package mcpauth

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// cimdServer serves a metadata document and counts how many times it was
// fetched (so cache behaviour is observable).
type cimdServer struct {
	*httptest.Server
	hits int
	body string
	code int
	hdrs map[string]string
}

func newCIMDServer(t *testing.T) *cimdServer {
	t.Helper()
	cs := &cimdServer{code: http.StatusOK, hdrs: map[string]string{}}
	cs.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.hits++
		for k, v := range cs.hdrs {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(cs.code)
		_, _ = w.Write([]byte(cs.body))
	}))
	t.Cleanup(cs.Close)
	return cs
}

func (cs *cimdServer) clientID() string { return cs.URL + "/client.json" }

// newCIMDAS builds an AS whose CIMD resolver talks to the test TLS server.
func newCIMDAS(t *testing.T, cs *cimdServer, allowedHosts ...string) *AS {
	t.Helper()
	as, err := New(Options{
		Issuer:          testIssuer,
		Resource:        testResource,
		ScopesSupported: []string{"mcp", "mcp:write"},
		SigningKeyPEM:   testKeyPEM(t),
		CIMD: CIMDOptions{
			Enabled:      true,
			AllowedHosts: allowedHosts,
			HTTPClient:   cs.Client(),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return as
}

func validDoc(clientID string) string {
	return `{"client_id":"` + clientID + `","client_name":"Example MCP Client",` +
		`"redirect_uris":["http://127.0.0.1:3000/callback"],"token_endpoint_auth_method":"none"}`
}

func TestCIMDResolveSuccess(t *testing.T) {
	cs := newCIMDServer(t)
	cs.body = validDoc(cs.clientID())
	as := newCIMDAS(t, cs)

	meta, err := as.ResolveClient(context.Background(), cs.clientID())
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if !meta.CIMD {
		t.Error("CIMD flag not set")
	}
	if meta.ClientName != "Example MCP Client" {
		t.Errorf("ClientName = %q", meta.ClientName)
	}
	if meta.ClientID != cs.clientID() {
		t.Errorf("ClientID = %q, want %q", meta.ClientID, cs.clientID())
	}
	if !meta.LocalhostOnly() {
		t.Error("LocalhostOnly = false, want true for a loopback-only client")
	}
}

func TestCIMDCachesDocument(t *testing.T) {
	cs := newCIMDServer(t)
	cs.body = validDoc(cs.clientID())
	as := newCIMDAS(t, cs)

	for range 3 {
		if _, err := as.ResolveClient(context.Background(), cs.clientID()); err != nil {
			t.Fatalf("ResolveClient: %v", err)
		}
	}
	if cs.hits != 1 {
		t.Errorf("fetched %d times, want 1 (cached)", cs.hits)
	}
}

func TestCIMDCachesFailures(t *testing.T) {
	cs := newCIMDServer(t)
	cs.code = http.StatusNotFound
	as := newCIMDAS(t, cs)

	for range 3 {
		if _, err := as.ResolveClient(context.Background(), cs.clientID()); err == nil {
			t.Fatal("ResolveClient succeeded on a 404 document")
		}
	}
	if cs.hits != 1 {
		t.Errorf("fetched %d times, want 1 (negative cache)", cs.hits)
	}
}

func TestCIMDCacheTTLFromHeaders(t *testing.T) {
	cs := newCIMDServer(t)
	r := newCIMDResolver(CIMDOptions{Enabled: true, CacheTTL: 15 * time.Minute, HTTPClient: cs.Client()})

	tests := []struct {
		cacheControl string
		want         time.Duration
	}{
		{"", 15 * time.Minute},
		{"max-age=3600", time.Hour},
		{"public, max-age=30", cimdMinTTL},     // clamped up
		{"max-age=999999999", cimdMaxTTL},      // clamped down
		{"no-store", cimdMinTTL},               // still cached, at the floor
		{"max-age=nonsense", 15 * time.Minute}, // unparseable → default
	}
	for _, tc := range tests {
		if got := r.cacheTTL(tc.cacheControl); got != tc.want {
			t.Errorf("cacheTTL(%q) = %v, want %v", tc.cacheControl, got, tc.want)
		}
	}
}

func TestCIMDRejectsInvalidDocuments(t *testing.T) {
	tests := []struct {
		name string
		body func(clientID string) string
	}{
		{"client_id mismatch", func(string) string {
			return `{"client_id":"https://evil.example/c.json","client_name":"X","redirect_uris":["https://a.example/cb"]}`
		}},
		{"missing client_name", func(id string) string {
			return `{"client_id":"` + id + `","redirect_uris":["https://a.example/cb"]}`
		}},
		{"missing redirect_uris", func(id string) string {
			return `{"client_id":"` + id + `","client_name":"X"}`
		}},
		{"non-loopback http redirect", func(id string) string {
			return `{"client_id":"` + id + `","client_name":"X","redirect_uris":["http://evil.example/cb"]}`
		}},
		{"redirect with fragment", func(id string) string {
			return `{"client_id":"` + id + `","client_name":"X","redirect_uris":["https://a.example/cb#x"]}`
		}},
		{"client authentication requested", func(id string) string {
			return `{"client_id":"` + id + `","client_name":"X","redirect_uris":["https://a.example/cb"],` +
				`"token_endpoint_auth_method":"client_secret_basic"}`
		}},
		{"not JSON", func(string) string { return `<html>nope</html>` }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := newCIMDServer(t)
			cs.body = tc.body(cs.clientID())
			as := newCIMDAS(t, cs)
			if _, err := as.ResolveClient(context.Background(), cs.clientID()); err == nil {
				t.Fatal("ResolveClient accepted an invalid document")
			}
		})
	}
}

func TestCIMDRejectsOversizedDocument(t *testing.T) {
	cs := newCIMDServer(t)
	cs.body = `{"client_id":"` + cs.clientID() + `","client_name":"` + strings.Repeat("A", cimdMaxBody) + `"}`
	as := newCIMDAS(t, cs)

	if _, err := as.ResolveClient(context.Background(), cs.clientID()); err == nil {
		t.Fatal("ResolveClient accepted an oversized document")
	}
}

func TestCIMDRefusesRedirects(t *testing.T) {
	target := newCIMDServer(t)
	target.body = validDoc(target.clientID())

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.clientID(), http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	as := newCIMDAS(t, target)
	if _, err := as.ResolveClient(context.Background(), redirector.URL+"/client.json"); err == nil {
		t.Fatal("ResolveClient followed a redirect")
	}
}

func TestCIMDURLValidation(t *testing.T) {
	bad := []string{
		"http://app.example.com/client.json", // not https
		"https://app.example.com",            // no path component
		"https://app.example.com/",           // no path component
		"https://app.example.com/c.json#f",   // fragment
		"https://user:pw@app.example.com/c",  // userinfo
		"https:///client.json",               // no host
	}
	for _, raw := range bad {
		if _, err := validateCIMDURL(raw); err == nil {
			t.Errorf("validateCIMDURL(%q) accepted an invalid client_id URL", raw)
		}
	}
	if _, err := validateCIMDURL("https://app.example.com/oauth/client.json"); err != nil {
		t.Errorf("validateCIMDURL rejected a valid client_id URL: %v", err)
	}
}

func TestCIMDTrustPolicy(t *testing.T) {
	r := newCIMDResolver(CIMDOptions{Enabled: true, AllowedHosts: []string{"app.example.com", "*.trusted.dev"}})

	allowed := []string{"app.example.com", "APP.example.com", "a.trusted.dev", "deep.a.trusted.dev", "trusted.dev"}
	for _, h := range allowed {
		if !r.hostAllowed(h) {
			t.Errorf("hostAllowed(%q) = false, want true", h)
		}
	}
	denied := []string{"evil.example.com", "app.example.com.evil.dev", "nottrusted.dev"}
	for _, h := range denied {
		if r.hostAllowed(h) {
			t.Errorf("hostAllowed(%q) = true, want false", h)
		}
	}

	open := newCIMDResolver(CIMDOptions{Enabled: true})
	if !open.hostAllowed("anything.example") {
		t.Error("an empty trust policy must allow any host")
	}
}

func TestCIMDTrustPolicyBlocksResolve(t *testing.T) {
	cs := newCIMDServer(t)
	cs.body = validDoc(cs.clientID())
	as := newCIMDAS(t, cs, "app.example.com")

	if _, err := as.ResolveClient(context.Background(), cs.clientID()); err == nil {
		t.Fatal("ResolveClient ignored the trust policy")
	}
	if cs.hits != 0 {
		t.Errorf("fetched %d times, want 0 (policy checked before fetch)", cs.hits)
	}
}

func TestCIMDDisabledRejectsURLClientID(t *testing.T) {
	as := newTestAS(t)
	if as.CIMDEnabled() {
		t.Fatal("CIMD should be off by default in Options")
	}
	if _, err := as.ResolveClient(context.Background(), "https://app.example.com/client.json"); err == nil {
		t.Fatal("ResolveClient accepted a URL client_id with CIMD disabled")
	}
}

func TestCIMDSSRFGuard(t *testing.T) {
	guard := dialGuard(false)
	blocked := []string{"127.0.0.1:443", "10.1.2.3:443", "192.168.1.1:443", "169.254.169.254:80",
		"[::1]:443", "[fd00::1]:443", "100.64.0.1:443", "0.0.0.0:443"}
	for _, addr := range blocked {
		if err := guard("tcp", addr, nil); err == nil {
			t.Errorf("dialGuard allowed %s", addr)
		}
	}
	if err := guard("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("dialGuard blocked a public address: %v", err)
	}
	if dialGuard(true) != nil {
		t.Error("AllowPrivateHosts must disable the guard entirely")
	}
}

func TestIsPublicIP(t *testing.T) {
	if isPublicIP(net.ParseIP("::ffff:10.0.0.1")) {
		t.Error("IPv4-mapped private address treated as public")
	}
	if !isPublicIP(net.ParseIP("2606:4700:4700::1111")) {
		t.Error("public IPv6 address treated as private")
	}
}

// ---- client resolution across mechanisms ------------------------------------

func TestResolveClientDCRPath(t *testing.T) {
	as := newTestAS(t)
	cid, err := as.MintClientID(ClientRegistration{
		RedirectURIs: []string{"https://c.example/cb"},
		ClientName:   "DCR App",
	})
	if err != nil {
		t.Fatalf("MintClientID: %v", err)
	}
	meta, err := as.ResolveClient(context.Background(), cid)
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if meta.CIMD {
		t.Error("a DCR client_id must not be flagged as CIMD")
	}
	if meta.ClientName != "DCR App" || meta.RedirectURIs[0] != "https://c.example/cb" {
		t.Errorf("unexpected metadata %+v", meta)
	}
	if meta.LocalhostOnly() {
		t.Error("LocalhostOnly = true for an https redirect URI")
	}
}

func TestResolveClientRejectsEmpty(t *testing.T) {
	as := newTestAS(t)
	if _, err := as.ResolveClient(context.Background(), ""); err == nil {
		t.Fatal("ResolveClient accepted an empty client_id")
	}
}

// RFC 8252 §7.3: a native client binds an ephemeral port at launch, so it
// publishes a portless loopback URI and arrives on whatever port it got.
func TestMatchRedirectURILoopbackPort(t *testing.T) {
	registered := []string{"http://localhost/callback", "http://127.0.0.1/callback"}

	match := []string{
		"http://localhost:57351/callback",
		"http://127.0.0.1:1/callback",
		"http://localhost/callback", // portless, byte-exact
	}
	for _, uri := range match {
		if !MatchRedirectURI(registered, uri) {
			t.Errorf("MatchRedirectURI rejected %q", uri)
		}
	}

	noMatch := []string{
		"http://localhost:57351/other",        // path must still match
		"https://localhost:57351/callback",    // scheme must still match
		"http://evil.example:57351/callback",  // not loopback
		"http://localhost:57351/callback?x=1", // query must still match
		"http://a@localhost:57351/callback",   // userinfo must not ride in
		"http://localhost:57351/callback#f",   // fragment must not ride in
		"",
	}
	for _, uri := range noMatch {
		if MatchRedirectURI(registered, uri) {
			t.Errorf("MatchRedirectURI accepted %q", uri)
		}
	}
}

// The port relaxation is loopback-only: a public https client still matches
// byte-for-byte, so a stolen code cannot be steered to another port.
func TestMatchRedirectURIHTTPSStaysExact(t *testing.T) {
	registered := []string{"https://client.example.com/callback"}

	if !MatchRedirectURI(registered, "https://client.example.com/callback") {
		t.Error("exact https redirect_uri rejected")
	}
	for _, uri := range []string{
		"https://client.example.com:8443/callback",
		"https://client.example.com/callback/",
		"https://Client.Example.com/callback",
	} {
		if MatchRedirectURI(registered, uri) {
			t.Errorf("MatchRedirectURI accepted non-exact https URI %q", uri)
		}
	}
}

func TestIsURLClientID(t *testing.T) {
	if !IsURLClientID("https://app.example.com/client.json") {
		t.Error("https client_id not detected as a URL")
	}
	if IsURLClientID("eyJhbGciOiJFUzI1NiJ9.abc.def") {
		t.Error("JWS client_id misdetected as a URL")
	}
}
