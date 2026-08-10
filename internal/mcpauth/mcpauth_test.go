package mcpauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	testIssuer   = "https://docs.hierarchy40.com"
	testResource = "https://docs.hierarchy40.com/mcp"
)

// testKeyPEM generates a fresh P-256 key as PKCS#8 PEM (matches what
// `openssl ... -genkey` piped through PKCS#8 would produce).
func testKeyPEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func newTestAS(t *testing.T) *AS {
	t.Helper()
	as, err := New(Options{
		Issuer:          testIssuer,
		Resource:        testResource,
		ScopesSupported: []string{"mcp"},
		SigningKeyPEM:   testKeyPEM(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return as
}

func TestRoundtripAllArtifacts(t *testing.T) {
	as := newTestAS(t)

	// client_id
	cid, err := as.MintClientID(ClientRegistration{RedirectURIs: []string{"https://c.example/cb"}, ClientName: "Test"})
	if err != nil {
		t.Fatalf("MintClientID: %v", err)
	}
	client, err := as.VerifyClientID(cid)
	if err != nil {
		t.Fatalf("VerifyClientID: %v", err)
	}
	if client.ClientName != "Test" || client.RedirectURIs[0] != "https://c.example/cb" {
		t.Fatalf("client roundtrip mismatch: %+v", client)
	}

	// authreq
	blob, csrf, err := as.MintAuthReq(AuthReqInput{
		ClientID: cid, RedirectURI: "https://c.example/cb", CodeChallenge: "chal",
		Resource: testResource, Scope: "mcp", State: "st", Sub: "user-1", Email: "u@x.io",
	})
	if err != nil {
		t.Fatalf("MintAuthReq: %v", err)
	}
	authReq, err := as.VerifyAuthReq(blob)
	if err != nil {
		t.Fatalf("VerifyAuthReq: %v", err)
	}
	if authReq.CSRF != csrf || authReq.Subject != "user-1" || authReq.State != "st" {
		t.Fatalf("authreq roundtrip mismatch: %+v", authReq)
	}

	// code
	codeStr, err := as.MintCode(authReq)
	if err != nil {
		t.Fatalf("MintCode: %v", err)
	}
	code, err := as.VerifyCode(codeStr)
	if err != nil {
		t.Fatalf("VerifyCode: %v", err)
	}
	if code.Subject != "user-1" || code.CodeChallenge != "chal" {
		t.Fatalf("code roundtrip mismatch: %+v", code)
	}

	// grant → access + refresh
	grant, err := as.IssueGrant(GrantInput{Sub: "user-1", Email: "u@x.io", ClientID: cid, Resource: testResource, Scope: "mcp"})
	if err != nil {
		t.Fatalf("IssueGrant: %v", err)
	}
	access, err := as.VerifyAccessToken(grant.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if access.Issuer != testIssuer || !access.Audience.Contains(testResource) || access.Email != "u@x.io" || access.TokenUse != useAccess {
		t.Fatalf("access claims mismatch: %+v", access)
	}
	refresh, err := as.VerifyRefreshToken(grant.RefreshToken)
	if err != nil {
		t.Fatalf("VerifyRefreshToken: %v", err)
	}
	if refresh.ClientID != cid || refresh.Family == "" {
		t.Fatalf("refresh claims mismatch: %+v", refresh)
	}
}

// TestCrossArtifactRejection is the load-bearing token_use test: an artifact of
// one kind must never verify as another, though all share the signing/enc key.
func TestCrossArtifactRejection(t *testing.T) {
	as := newTestAS(t)
	cid, _ := as.MintClientID(ClientRegistration{RedirectURIs: []string{"https://c/cb"}})
	blob, _, _ := as.MintAuthReq(AuthReqInput{ClientID: cid, RedirectURI: "https://c/cb", Resource: testResource, Sub: "u"})
	authReq, _ := as.VerifyAuthReq(blob)
	code, _ := as.MintCode(authReq)
	grant, _ := as.IssueGrant(GrantInput{Sub: "u", ClientID: cid, Resource: testResource, Scope: "mcp"})

	// None of these should verify as an access token.
	for name, tok := range map[string]string{"client_id": cid, "authreq": blob, "code": code, "refresh": grant.RefreshToken} {
		if _, err := as.VerifyAccessToken(tok); err == nil {
			t.Errorf("%s verified as access token, want rejection", name)
		}
	}
	// Access token must not verify as a code or refresh.
	if _, err := as.VerifyCode(grant.AccessToken); err == nil {
		t.Error("access token verified as code")
	}
	if _, err := as.VerifyRefreshToken(grant.AccessToken); err == nil {
		t.Error("access token verified as refresh")
	}
	// client_id must not verify as refresh (both JWS, differ only by token_use).
	if _, err := as.VerifyRefreshToken(cid); err == nil {
		t.Error("client_id verified as refresh")
	}
}

func TestAlgConfusionRejected(t *testing.T) {
	as := newTestAS(t)
	claims := map[string]any{
		"iss": testIssuer, "aud": testResource, "token_use": useAccess,
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	// alg=HS256 using an attacker-chosen symmetric key (the "public key becomes
	// an HMAC secret" attack) — pinning to ES256 rejects it.
	hsKey := make([]byte, 32)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hsKey}, nil)
	if err != nil {
		t.Fatalf("HS256 signer: %v", err)
	}
	hsTok, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("HS256 sign: %v", err)
	}
	if _, err := as.VerifyAccessToken(hsTok); err == nil {
		t.Error("HS256 token accepted, want rejection")
	}

	// alg=none, hand-assembled.
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + testIssuer + `","aud":"` + testResource + `","token_use":"access"}`))
	noneTok := hdr + "." + payload + "."
	if _, err := as.VerifyAccessToken(noneTok); err == nil {
		t.Error("alg=none token accepted, want rejection")
	}
}

func TestAccessTokenAudienceAndIssuerPinned(t *testing.T) {
	as := newTestAS(t)
	// A token minted for a different resource must not verify.
	other, err := as.IssueGrant(GrantInput{Sub: "u", ClientID: "c", Resource: "https://evil.example/mcp", Scope: "mcp"})
	if err != nil {
		t.Fatalf("IssueGrant: %v", err)
	}
	if _, err := as.VerifyAccessToken(other.AccessToken); err == nil {
		t.Error("access token with wrong aud accepted")
	}
}

func TestExpiredCodeAndAuthReqRejected(t *testing.T) {
	as := newTestAS(t)
	as.CodeTTL = -time.Second
	as.AuthReqTTL = -time.Second

	blob, _, _ := as.MintAuthReq(AuthReqInput{ClientID: "c", RedirectURI: "https://c/cb", Resource: testResource, Sub: "u"})
	if _, err := as.VerifyAuthReq(blob); err == nil {
		t.Error("expired authreq accepted")
	}
	// Mint a code from a non-expired authreq shape but expired code TTL.
	code, _ := as.MintCode(&AuthReqClaims{ClientID: "c", RedirectURI: "https://c/cb", Resource: testResource})
	if _, err := as.VerifyCode(code); err == nil {
		t.Error("expired code accepted")
	}
}

func TestPRMURLDerivation(t *testing.T) {
	cases := []struct{ resource, want string }{
		{"https://docs.hierarchy40.com/mcp", "https://docs.hierarchy40.com/.well-known/oauth-protected-resource/mcp"},
		{"https://docs.hierarchy40.com/", "https://docs.hierarchy40.com/.well-known/oauth-protected-resource"},
		{"https://docs.hierarchy40.com", "https://docs.hierarchy40.com/.well-known/oauth-protected-resource"},
		{"https://h.example/deep/path", "https://h.example/.well-known/oauth-protected-resource/deep/path"},
	}
	for _, c := range cases {
		as, err := New(Options{Issuer: testIssuer, Resource: c.resource, SigningKeyPEM: testKeyPEM(t)})
		if err != nil {
			t.Fatalf("New(%s): %v", c.resource, err)
		}
		if got := as.PRMURL(); got != c.want {
			t.Errorf("PRMURL(%s) = %q, want %q", c.resource, got, c.want)
		}
	}
}

func TestMatchesResource(t *testing.T) {
	as := newTestAS(t)
	good := []string{
		"https://docs.hierarchy40.com/mcp",
		"https://DOCS.hierarchy40.com/mcp", // host case-insensitive
		"HTTPS://docs.hierarchy40.com/mcp", // scheme case-insensitive
	}
	for _, r := range good {
		if !as.MatchesResource(r) {
			t.Errorf("MatchesResource(%q) = false, want true", r)
		}
	}
	bad := []string{
		"", "https://docs.hierarchy40.com/mcp#frag", "https://docs.hierarchy40.com/other",
		"https://evil.example/mcp", "https://docs.hierarchy40.com/mcp/extra",
	}
	for _, r := range bad {
		if as.MatchesResource(r) {
			t.Errorf("MatchesResource(%q) = true, want false", r)
		}
	}
}

func TestPublicJWKSHasNoPrivateMaterial(t *testing.T) {
	as := newTestAS(t)
	b, err := json.Marshal(as.PublicJWKS())
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	s := string(b)
	for _, want := range []string{`"kid"`, `"use":"sig"`, `"alg":"ES256"`, `"crv":"P-256"`} {
		if !strings.Contains(s, want) {
			t.Errorf("JWKS missing %s: %s", want, s)
		}
	}
	if strings.Contains(s, `"d":`) {
		t.Errorf("JWKS leaks private scalar: %s", s)
	}
}

func TestParseSEC1AndPKCS8Keys(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	sec1, _ := x509.MarshalECPrivateKey(priv)
	sec1PEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))
	if _, err := parseES256PrivateKey(sec1PEM); err != nil {
		t.Errorf("SEC1 parse failed: %v", err)
	}

	pkcs8, _ := x509.MarshalPKCS8PrivateKey(priv)
	pkcs8PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	if _, err := parseES256PrivateKey(pkcs8PEM); err != nil {
		t.Errorf("PKCS#8 parse failed: %v", err)
	}

	if _, err := parseES256PrivateKey("not pem"); err == nil {
		t.Error("expected error for non-PEM input")
	}
}

func TestRejectsNonHTTPSIssuerResource(t *testing.T) {
	if _, err := New(Options{Issuer: "http://insecure", Resource: testResource, SigningKeyPEM: testKeyPEM(t)}); err == nil {
		t.Error("expected error for non-https issuer")
	}
	if _, err := New(Options{Issuer: testIssuer, Resource: "http://insecure/mcp", SigningKeyPEM: testKeyPEM(t)}); err == nil {
		t.Error("expected error for non-https resource")
	}
}

func TestEncKeyDeterministicFromSigningKey(t *testing.T) {
	pemStr := testKeyPEM(t)
	k1, err := loadKeys(pemStr, "", "")
	if err != nil {
		t.Fatalf("loadKeys: %v", err)
	}
	k2, err := loadKeys(pemStr, "", "")
	if err != nil {
		t.Fatalf("loadKeys: %v", err)
	}
	// Same signing key ⇒ same HKDF-derived enc key across "replicas".
	if string(k1.encKey) != string(k2.encKey) {
		t.Error("HKDF enc key not stable across loads of the same signing key")
	}
	if len(k1.encKey) != 32 {
		t.Errorf("enc key length = %d, want 32", len(k1.encKey))
	}
	if k1.kid != k2.kid || k1.kid == "" {
		t.Errorf("kid not stable/non-empty: %q vs %q", k1.kid, k2.kid)
	}
}

func TestReplayGuard(t *testing.T) {
	g := NewMemoryReplayGuard(16)
	if g.SeenBefore("a", time.Minute) {
		t.Error("first SeenBefore(a) = true, want false")
	}
	if !g.SeenBefore("a", time.Minute) {
		t.Error("second SeenBefore(a) = false, want true")
	}
	if g.SeenBefore("b", time.Minute) {
		t.Error("SeenBefore(b) = true, want false")
	}
}

// An expired refresh token must be distinguishable from a forged one: the
// token endpoint logs that classification, and it is what tells an operator
// whether MCP_REFRESH_TOKEN_TTL is too short.
func TestVerifyRefreshTokenClassifiesExpiry(t *testing.T) {
	as := newTestAS(t)
	as.RefreshTTL = time.Hour
	grant, err := as.IssueGrant(GrantInput{Sub: "user-1", ClientID: "cid", Resource: testResource})
	if err != nil {
		t.Fatalf("IssueGrant: %v", err)
	}

	if _, err := as.VerifyRefreshToken(grant.RefreshToken); err != nil {
		t.Fatalf("fresh refresh token rejected: %v", err)
	}

	as.nowFn = func() time.Time { return time.Now().Add(2 * time.Hour) }
	_, err = as.VerifyRefreshToken(grant.RefreshToken)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expired refresh token gave %v, want ErrExpired", err)
	}

	if _, err := as.VerifyRefreshToken("not-a-token"); errors.Is(err, ErrExpired) {
		t.Fatal("a malformed token must not be classified as expired")
	}
}
