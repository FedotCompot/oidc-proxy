package mcpauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// Client ID Metadata Documents (MCP rev 2026-07-28, draft-ietf-oauth-client-id-
// metadata-document-00) let a client identify itself by an https URL it hosts
// instead of registering. That keeps registration stateless — nothing is stored
// on either side — which is why the 2026-07-28 spec deprecates DCR in its
// favour. The document is attacker-controlled input fetched by *us*, so every
// fetch is SSRF-guarded, size-capped, redirect-free, and cached.
const (
	cimdMaxBody     = 32 << 10
	cimdMinTTL      = time.Minute
	cimdMaxTTL      = 24 * time.Hour
	cimdNegativeTTL = time.Minute

	defaultCIMDTimeout   = 5 * time.Second
	defaultCIMDCacheTTL  = 15 * time.Minute
	defaultCIMDCacheSize = 512
)

// ClientMetadata is the resolved client identity behind a client_id, whatever
// registration mechanism produced it. RedirectURIs is the authoritative list
// the authorization request's redirect_uri is matched against.
type ClientMetadata struct {
	ClientID     string
	ClientName   string
	ClientURI    string
	RedirectURIs []string

	// CIMD is true when this came from a Client ID Metadata Document, i.e. the
	// client_id is an https URL whose host asserted these values.
	CIMD bool
}

// LocalhostOnly reports whether every redirect URI is a loopback address. Such
// clients cannot be told apart from any other process on the user's machine, so
// the consent page warns about them (spec: Localhost Redirect URI Risks).
func (c *ClientMetadata) LocalhostOnly() bool {
	for _, uri := range c.RedirectURIs {
		if u, err := url.Parse(uri); err != nil || !isLoopbackHost(u.Hostname()) {
			return false
		}
	}
	return len(c.RedirectURIs) > 0
}

// CIMDOptions configures Client ID Metadata Document resolution.
type CIMDOptions struct {
	Enabled bool

	// AllowedHosts is an optional domain trust policy: exact hosts, or
	// "*.example.com" to match any subdomain. Empty means any public host.
	AllowedHosts []string

	// AllowPrivateHosts disables the SSRF guard that rejects loopback/private
	// destinations. Only for tests and split-horizon deployments.
	AllowPrivateHosts bool

	CacheTTL  time.Duration
	CacheSize int
	Timeout   time.Duration

	// HTTPClient overrides the SSRF-guarded client (tests).
	HTTPClient *http.Client
}

type cimdResolver struct {
	http       *http.Client
	cache      *ttlcache.Cache[string, cimdEntry]
	allowed    []string
	defaultTTL time.Duration
}

// cimdEntry caches a resolution outcome. Failures are cached too (briefly) so a
// bad client_id cannot be used to make us hammer a third-party host.
type cimdEntry struct {
	meta *ClientMetadata
	err  string
}

func newCIMDResolver(opts CIMDOptions) *cimdResolver {
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout:       orDefault(opts.Timeout, defaultCIMDTimeout),
			CheckRedirect: refuseRedirect,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: 5 * time.Second,
					Control: dialGuard(opts.AllowPrivateHosts),
				}).DialContext,
				TLSHandshakeTimeout: 5 * time.Second,
				DisableKeepAlives:   true,
			},
		}
	}
	size := opts.CacheSize
	if size <= 0 {
		size = defaultCIMDCacheSize
	}
	return &cimdResolver{
		http: client,
		cache: ttlcache.New(
			ttlcache.WithCapacity[string, cimdEntry](uint64(size)),
			ttlcache.WithDisableTouchOnHit[string, cimdEntry](),
		),
		allowed:    normalizeHosts(opts.AllowedHosts),
		defaultTTL: orDefault(opts.CacheTTL, defaultCIMDCacheTTL),
	}
}

// resolve returns the metadata for an https client_id, fetching and validating
// the document on a cache miss.
func (r *cimdResolver) resolve(ctx context.Context, clientID string) (*ClientMetadata, error) {
	u, err := validateCIMDURL(clientID)
	if err != nil {
		return nil, err
	}
	if !r.hostAllowed(u.Hostname()) {
		return nil, fmt.Errorf("client_id host %q is not in the CIMD trust policy", u.Hostname())
	}

	if item := r.cache.Get(clientID); item != nil && !item.IsExpired() {
		e := item.Value()
		if e.err != "" {
			return nil, fmt.Errorf("%s", e.err)
		}
		return e.meta, nil
	}

	meta, ttl, err := r.fetch(ctx, clientID, u)
	if err != nil {
		r.cache.Set(clientID, cimdEntry{err: err.Error()}, cimdNegativeTTL)
		return nil, err
	}
	r.cache.Set(clientID, cimdEntry{meta: meta}, ttl)
	return meta, nil
}

func (r *cimdResolver) fetch(ctx context.Context, clientID string, u *url.URL) (*ClientMetadata, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build CIMD request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch client metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("client metadata returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBody+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read client metadata: %w", err)
	}
	if len(body) > cimdMaxBody {
		return nil, 0, fmt.Errorf("client metadata exceeds %d bytes", cimdMaxBody)
	}

	var doc cimdDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, fmt.Errorf("client metadata is not valid JSON: %w", err)
	}
	meta, err := doc.validate(clientID)
	if err != nil {
		return nil, 0, err
	}
	return meta, r.cacheTTL(resp.Header.Get("Cache-Control")), nil
}

// cacheTTL honours the document's Cache-Control, clamped to a sane band. A
// no-store/no-cache document still gets the floor so a hot client_id cannot
// turn every authorize into an outbound fetch.
func (r *cimdResolver) cacheTTL(cacheControl string) time.Duration {
	for part := range strings.SplitSeq(cacheControl, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		switch {
		case part == "no-store", part == "no-cache":
			return cimdMinTTL
		case strings.HasPrefix(part, "max-age="):
			secs, err := strconv.Atoi(strings.TrimPrefix(part, "max-age="))
			if err != nil {
				continue
			}
			return clampDuration(time.Duration(secs)*time.Second, cimdMinTTL, cimdMaxTTL)
		}
	}
	return clampDuration(r.defaultTTL, cimdMinTTL, cimdMaxTTL)
}

func (r *cimdResolver) hostAllowed(host string) bool {
	if len(r.allowed) == 0 {
		return true
	}
	host = strings.ToLower(host)
	for _, a := range r.allowed {
		if suffix, ok := strings.CutPrefix(a, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) || host == suffix {
				return true
			}
			continue
		}
		if host == a {
			return true
		}
	}
	return false
}

// cimdDocument is the client-hosted metadata document.
type cimdDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// validate enforces the normative checks: client_id matches the document URL
// exactly, the required fields are present, and every redirect URI is one this
// AS would have accepted at registration.
func (d *cimdDocument) validate(clientID string) (*ClientMetadata, error) {
	if d.ClientID != clientID {
		return nil, fmt.Errorf("client_id in metadata does not match the document URL")
	}
	if strings.TrimSpace(d.ClientName) == "" {
		return nil, fmt.Errorf("client metadata is missing client_name")
	}
	if len(d.RedirectURIs) == 0 {
		return nil, fmt.Errorf("client metadata is missing redirect_uris")
	}
	for _, uri := range d.RedirectURIs {
		if err := ValidateRedirectURI(uri); err != nil {
			return nil, fmt.Errorf("client metadata redirect_uri %q: %w", uri, err)
		}
	}
	// This AS issues no client secrets and supports no client authentication.
	if m := d.TokenEndpointAuthMethod; m != "" && m != "none" {
		return nil, fmt.Errorf("unsupported token_endpoint_auth_method %q", m)
	}
	return &ClientMetadata{
		ClientID:     clientID,
		ClientName:   d.ClientName,
		ClientURI:    d.ClientURI,
		RedirectURIs: d.RedirectURIs,
		CIMD:         true,
	}, nil
}

// ---- URL / network helpers --------------------------------------------------

// IsURLClientID reports whether a client_id is a Client ID Metadata Document
// URL rather than an AS-issued (JWS) client_id.
func IsURLClientID(clientID string) bool {
	return strings.Contains(clientID, "://")
}

// validateCIMDURL enforces the client_id URL shape: https, a real path
// component, no fragment, no userinfo.
func validateCIMDURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("client_id is not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("client_id URL must use the https scheme")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("client_id URL must include a host")
	}
	if u.User != nil {
		return nil, fmt.Errorf("client_id URL must not include userinfo")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("client_id URL must not contain a fragment")
	}
	if strings.Trim(u.Path, "/") == "" {
		return nil, fmt.Errorf("client_id URL must contain a path component")
	}
	return u, nil
}

// ValidateRedirectURI enforces the OAuth 2.1 / MCP constraints: absolute URI,
// https or loopback http, no fragment.
func ValidateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a valid URI")
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("must be an absolute URI")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("must not contain a fragment")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("http is only allowed for loopback (127.0.0.1 / localhost)")
	default:
		return fmt.Errorf("scheme must be https or loopback http")
	}
}

// MatchRedirectURI reports whether candidate is one of the registered URIs.
//
// Non-loopback URIs must match byte-for-byte. Loopback URIs match on
// everything except the port, which RFC 8252 §7.3 requires an authorization
// server to allow: a native client takes an ephemeral port from the OS when it
// starts its callback listener, so it cannot publish one ahead of time (Claude
// Code registers "http://localhost/callback" and arrives on :57351). The
// relaxation is confined to loopback, where the redirect can only ever reach
// the user's own machine.
func MatchRedirectURI(registered []string, candidate string) bool {
	if candidate == "" {
		return false
	}
	if slices.Contains(registered, candidate) {
		return true
	}
	got, err := url.Parse(candidate)
	// userinfo would let "http://trusted.example@localhost/cb" ride in on a
	// portless match, so a loopback candidate carrying any is refused.
	if err != nil || got.User != nil || got.Fragment != "" || !isLoopbackHost(got.Hostname()) {
		return false
	}
	for _, raw := range registered {
		want, err := url.Parse(raw)
		if err != nil || !isLoopbackHost(want.Hostname()) {
			continue
		}
		if want.Scheme == got.Scheme && want.Hostname() == got.Hostname() &&
			want.Path == got.Path && want.RawQuery == got.RawQuery {
			return true
		}
	}
	return false
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

func refuseRedirect(_ *http.Request, _ []*http.Request) error {
	return fmt.Errorf("client metadata URL must not redirect")
}

// dialGuard rejects connections to non-public addresses after DNS resolution,
// which is where an SSRF payload would land (a public hostname resolving to
// 169.254.169.254 or 10.0.0.0/8).
func dialGuard(allowPrivate bool) func(string, string, syscall.RawConn) error {
	if allowPrivate {
		return nil
	}
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("cannot parse dial address %q", address)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("cannot parse dial address %q", address)
		}
		if !isPublicIP(ip) {
			return fmt.Errorf("refusing to fetch client metadata from non-public address %s", ip)
		}
		return nil
	}
}

// cgnat is RFC 6598 shared address space, which net.IP has no predicate for.
var cgnat = net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	return !cgnat.Contains(ip)
}

func normalizeHosts(in []string) []string {
	out := make([]string, 0, len(in))
	for _, h := range in {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			out = append(out, h)
		}
	}
	return out
}

func clampDuration(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}
