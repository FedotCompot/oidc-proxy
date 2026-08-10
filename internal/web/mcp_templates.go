package web

import (
	"html/template"
	"log"
	"net/http"
	"strings"
)

// consentData drives the MCP authorization consent screen. Everything on it is
// either server-validated (RedirectHost, RedirectOrigin, Resource, Scopes) or
// explicitly labelled self-asserted (ClientName). AuthReq/CSRF are opaque
// hidden fields.
type consentData struct {
	RedirectHost string
	// RedirectOrigin is the scheme://host[:port] the Approve/Deny POST will be
	// 302'd to. It is added to the page's form-action CSP so the browser follows
	// that redirect (see renderConsent). Derived from the validated, exact-match
	// redirect_uri via utils.OriginOf, so it carries no path and no userinfo.
	RedirectOrigin string
	ClientName     string
	// ClientHost is the host of a Client ID Metadata Document client_id — the
	// domain that served the metadata, and the only part of a CIMD client's
	// identity this AS verified. Empty for DCR clients.
	ClientHost string
	// LoopbackOnly marks a client whose redirect URIs are all loopback, which
	// no authorization server can tell apart from any other local process.
	LoopbackOnly bool
	Resource     string
	Scopes       []string
	AuthReq      string
	CSRF         string
	BrandColor   string
}

// authzErrorData drives the HTML error pages returned before a validated
// redirect_uri exists (bad client_id / redirect_uri / not-allowed).
type authzErrorData struct {
	Title      string
	Message    string
	BrandColor string
}

// renderConsent renders the approval page. Its CSP allows the inline styles and
// a form POST to 'self' plus the one validated redirect origin, but no scripts
// and no other destinations — the page is a pure HTML form.
//
// form-action is scoped to 'self' AND data.RedirectOrigin, not 'self' alone.
// Browsers (Chromium/WebKit) enforce form-action against every hop of a form
// submission's redirect chain: the POST to /oauth2/authorize matches 'self',
// but the server then 302s to the client's redirect_uri (e.g. a loopback
// http://127.0.0.1:<port>/callback), and 'self' alone would block that hop, so
// the code never reaches the client. Listing the exact, already-validated
// redirect origin permits precisely that one destination and nothing else; it
// works in every browser and keeps the "no other destinations" intent (dropping
// form-action would leave submissions unrestricted, since it does NOT fall back
// to default-src). The origin is dropped if it contains any character that could
// break out of the CSP source list — url.Parse already rejects spaces and
// CR/LF, but a hostname may still carry ';' ',' or a quote and DCR is open, so
// we refuse to emit those rather than risk a malformed header.
//
// Referrer-Policy is "same-origin", NOT "no-referrer". This is load-bearing: the
// Approve button is a plain top-level <form> POST (not fetch/CORS), and per the
// Fetch spec a non-CORS POST under a "no-referrer" policy has its Origin header
// set to the literal "null". handleAuthorizePOST's sameOrigin check would then
// see Origin: null != the forwarded origin and reject every approval with "bad
// origin". "same-origin" still strips the Referer on the cross-origin redirect
// back to the client while keeping the real Origin on this same-origin POST.
func (s *Server) renderConsent(w http.ResponseWriter, data *consentData) {
	if data.BrandColor == "" {
		data.BrandColor = s.cfg.BrandColor
	}
	formAction := "'self'"
	if data.RedirectOrigin != "" && !strings.ContainsAny(data.RedirectOrigin, " \t\r\n;,'\"") {
		formAction += " " + data.RedirectOrigin
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+"; base-uri 'none'")
	if err := consentTemplate.Execute(w, data); err != nil {
		log.Printf("mcp: consent render: %v", err)
	}
}

// renderAuthzError renders an HTML error page (never a redirect) for the
// pre-validation authorize failures.
func (s *Server) renderAuthzError(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(status)
	if err := authzErrorTemplate.Execute(w, &authzErrorData{
		Title:      title,
		Message:    message,
		BrandColor: s.cfg.BrandColor,
	}); err != nil {
		log.Printf("mcp: authz error render: %v", err)
	}
}

// consentStyles adds a couple of consent-specific rules on top of sharedStyles.
const consentStyles = `<style>
  .card { text-align: left; width: min(440px, 100%); }
  .consent-anchor {
    font-size: 15px; margin: 0 0 20px; padding: 14px 16px;
    background: color-mix(in srgb, var(--accent) 8%, transparent);
    border: 1px solid color-mix(in srgb, var(--accent) 24%, transparent);
    border-radius: 10px;
  }
  .consent-anchor strong { word-break: break-all; }
  .consent-list { list-style: none; padding: 0; margin: 0 0 24px; }
  .consent-list li { display: flex; justify-content: space-between; gap: 16px; padding: 8px 0; border-bottom: 1px solid #e3e5ea; font-size: 14px; }
  .consent-list .k { color: #6b7280; }
  .consent-list .v { text-align: right; word-break: break-all; font-weight: 500; }
  .unverified { color: #9a6b00; font-size: 12px; }
  .consent-warning {
    font-size: 13px; margin: 0 0 20px; padding: 12px 14px; border-radius: 10px;
    color: #7a5500; background: #fff8e6; border: 1px solid #f0dca8;
  }
  .scopes { display: flex; flex-wrap: wrap; gap: 6px; justify-content: flex-end; }
  .scope { background: color-mix(in srgb, var(--accent) 12%, transparent); color: var(--accent); border-radius: 999px; padding: 2px 10px; font-size: 12px; font-weight: 500; }
  .actions { display: flex; gap: 12px; margin-top: 8px; }
  .actions .btn { width: auto; flex: 1; }
  .btn.secondary { background: transparent; color: var(--accent); border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent); }
  .btn.secondary:hover { filter: none; background: color-mix(in srgb, var(--accent) 8%, transparent); }
  @media (prefers-color-scheme: dark) {
    .consent-list li { border-color: #2c2f37; }
    .unverified { color: #d9a441; }
    .consent-warning { color: #e6c169; background: #2a2416; border-color: #4a3f22; }
  }
</style>`

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Authorize access</title>
` + sharedStyles + consentStyles + `
</head>
<body>
<main class="card">
  <span class="card-icon" aria-hidden="true">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M9 12l2 2 4-4"></path>
      <path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"></path>
    </svg>
  </span>
  <h1>Authorize access</h1>
  <p class="consent-anchor">You'll be returned to <strong>{{.RedirectHost}}</strong>. Only approve if you started this sign-in from an app you trust — this host is where your authorization will be delivered.</p>
  <ul class="consent-list">
    {{if .ClientName}}<li><span class="k">App name <span class="unverified">(unverified)</span></span><span class="v">{{.ClientName}}</span></li>{{end}}
    {{if .ClientHost}}<li><span class="k">Published by</span><span class="v">{{.ClientHost}}</span></li>{{end}}
    <li><span class="k">Resource</span><span class="v">{{.Resource}}</span></li>
    <li><span class="k">Scopes</span><span class="v"><span class="scopes">{{range .Scopes}}<span class="scope">{{.}}</span>{{end}}</span></span></li>
  </ul>
  {{if .LoopbackOnly}}<p class="consent-warning">This app receives your authorization on <strong>this device</strong>. Anything running locally could be listening — only approve if you just started this sign-in yourself.</p>{{end}}
  <form method="post" action="/oauth2/authorize">
    <input type="hidden" name="authreq" value="{{.AuthReq}}">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <div class="actions">
      <button class="btn secondary" type="submit" name="action" value="deny">Deny</button>
      <button class="btn" type="submit" name="action" value="approve">Approve</button>
    </div>
  </form>
</main>
</body>
</html>
`))

var authzErrorTemplate = template.Must(template.New("authzerr").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.Title}}</title>
` + sharedStyles + `
</head>
<body>
<main class="card">
  <span class="card-icon" aria-hidden="true">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"></circle>
      <path d="M12 8v4"></path>
      <path d="M12 16h.01"></path>
    </svg>
  </span>
  <h1>{{.Title}}</h1>
  <p class="subtitle">{{.Message}}</p>
</main>
</body>
</html>
`))
