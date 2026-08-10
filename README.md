# oidc-proxy

A tiny Go service that adds OIDC authentication to static sites behind
[Traefik](https://traefik.io/) via the
[`forwardAuth`](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)
middleware.

It runs a true **SPA / public-client** flow: all OAuth token requests
happen in the browser. The Go backend never exchanges codes or refresh
tokens itself — it only **verifies** ID tokens (JWKS signature + claims)
and writes the tokens as individual JS-readable cookies. That keeps the
design compatible with strict providers like Microsoft Entra ID, which
refuses server-side token redemption when a redirect URI is registered
as SPA, and minimizes client–backend roundtrips: the refresh page reads
its refresh token straight from `document.cookie`, and the static site
can call APIs with the access token cookie without asking the backend.

- Public-client / PKCE flow — no client secret needed
- Browser does the token exchange; backend only verifies the ID token
- Tokens are written as three separate plaintext cookies (`<prefix>_id_token`,
  `<prefix>_access_token`, `<prefix>_refresh_token`). JS-readable; not
  HttpOnly
- Self-contained HTML sign-in screen + tiny JS pages (no external assets)
- Zero config files — everything is env vars
- Two required env vars: `OIDC_ISSUER`, `OIDC_CLIENT_ID`

## How it fits in

```
                 ┌────────────────────────────────────────────┐
   browser ─────►│ Traefik                                    │
                 │  app.example.com/*  ── forwardAuth ──► oidc-proxy:/verify
                 │  app.example.com/oauth2/*  ───────────► oidc-proxy
                 │                                            │
                 │  static site (nginx, etc.)                 │
                 └────────────────────────────────────────────┘
```

`oidc-proxy` plays two roles:

1. **Verifier** — `/verify` is the Traefik `forwardAuth` target. It
   reads the session cookie, re-verifies the ID token's signature and
   claims via JWKS, and returns `200` (or `302` to refresh / sign in).
2. **Browser flow host** — `/oauth2/*` serves the sign-in screen and
   tiny JS pages that drive the OIDC redirect dance from inside the
   browser.

## Sign-in flow

```
  ┌─ user clicks "Sign in" on /oauth2/sign_in
  │
  ▼
  /oauth2/start  ──► JS generates PKCE verifier + state + nonce,
                     stores them in sessionStorage,
                     window.location = <issuer>/authorize?...
  │
  ▼
  issuer authenticates the user, redirects to
  /oauth2/callback?code=...&state=...
  │
  ▼
  /oauth2/callback  ──► JS fetch(POST <issuer>/token, ...)        ← browser sets Origin
                        JS fetch(POST /oauth2/session, tokens)    ← backend verifies + writes cookies
                        window.location = <original URL>
```

## Token refresh

When `/verify` finds the ID-token cookie no longer verifies, it
redirects to `/oauth2/refresh`. That page reads the refresh token
straight from `document.cookie` (no backend roundtrip), POSTs it to the
issuer's token endpoint from the browser, then POSTs the new tokens
back to `/oauth2/session`.

## Quick start

### 1. Register an OIDC client at your provider

- Application type: **SPA / public client** (no client secret)
- Redirect URI: `https://<your-domain>/oauth2/callback`

### 2. Run with Traefik

A complete example is in [`docker-compose.example.yml`](./docker-compose.example.yml).
The two routes you need on the same host:

```yaml
# Public router for the OIDC endpoints
- traefik.http.routers.oidc-proxy.rule=Host(`app.example.com`) && PathPrefix(`/oauth2/`)

# forwardAuth middleware that gates your site
- traefik.http.middlewares.oidc-auth.forwardauth.address=http://oidc-proxy:8080/verify
- traefik.http.middlewares.oidc-auth.forwardauth.authResponseHeaders=X-Auth-Request-Email,X-Auth-Request-User

# Apply the middleware to the static-site router
- traefik.http.routers.site.middlewares=oidc-auth@docker
```

### 3. Configure via env vars

```bash
OIDC_ISSUER=https://accounts.google.com
OIDC_CLIENT_ID=xxxx.apps.googleusercontent.com
```

## Endpoints

| Path | Method | Purpose |
| --- | --- | --- |
| `/verify` | GET | forwardAuth target — 200 / 302 / 403 |
| `/oauth2/sign_in` | GET | HTML login screen with a single button |
| `/oauth2/start` | GET | JS page: generates PKCE & redirects to issuer |
| `/oauth2/callback` | GET | JS page: exchanges code in-browser, posts tokens to backend |
| `/oauth2/session` | POST | Backend: verifies ID token, writes cookies (same-origin only) |
| `/oauth2/refresh` | GET | JS page: refreshes tokens in-browser (reads `document.cookie`) |
| `/oauth2/sign_out` | GET | Clears the token cookies |
| `/healthz` | GET | `204 No Content` |

`sign_in`, `start`, and `refresh` accept an `rd` query param to preserve
the destination URL across the redirects.

## Environment variables

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `OIDC_ISSUER` | yes | — | Discovery base URL (e.g. `https://accounts.google.com`) |
| `OIDC_CLIENT_ID` | yes | — | Public client ID |
| `OIDC_SCOPES` | no | `openid profile email` | Space-separated string passed as-is to the provider; `openid` is auto-added if missing |
| `COOKIE_NAME_PREFIX` | no | `_oidc_proxy` | Prefix for `_id_token` / `_access_token` / `_refresh_token` |
| `COOKIE_DOMAIN` | no | request host | Set to share across subdomains |
| `COOKIE_SECURE` | no | `true` | Set to `false` only for local HTTP testing |
| `VERIFY_CACHE_SIZE` | no | `1024` | Max ID-token verification results to cache. Entries live until the JWT's own `exp` |
| `ALLOWED_EMAILS` | no | — | Comma-separated allowlist of emails |
| `ALLOWED_DOMAINS` | no | — | Comma-separated allowlist of email domains |
| `SIGN_IN_TITLE` | no | `Sign in` | Sign-in page heading |
| `SIGN_IN_SUBTITLE` | no | — | Optional smaller text under the heading (e.g. `Use your work account`) |
| `SIGN_IN_BUTTON` | no | `Sign in with SSO` | Button label |
| `BRAND_COLOR` | no | `#2563eb` | Accent color for the button, focus ring, icon tint, and spinner. CSS hex only (`#rgb`, `#rrggbb`, or with alpha); invalid values fall back to the default |
| `LISTEN_ADDR` | no | `:8080` | HTTP listen address |

If both `ALLOWED_EMAILS` and `ALLOWED_DOMAINS` are unset, any user the
provider authenticates is allowed.

## Headers passed upstream

When a request is authenticated, `/verify` sets:

- `X-Auth-Request-Email`
- `X-Auth-Request-User` (the ID token `sub` claim)

For Traefik to forward these to your static site, list them in the
middleware's `authResponseHeaders` (shown in the example above).

## Provider notes

### Microsoft Entra ID

1. **Register the redirect URI under the *Single-Page Application*
   platform.** Because the token exchange happens in the browser via
   `fetch()`, the browser automatically sets the `Origin` header — the
   cross-origin signal Entra requires for SPA-registered apps (avoids
   `AADSTS9002327`).

2. **Override `OIDC_SCOPES`:**

   ```
   OIDC_SCOPES="openid profile email offline_access User.Read"
   ```

   With only `openid profile email`, Entra has no resource to issue an
   access token against, would issue one with audience = the app itself,
   and refuses with `AADSTS90009` ("Application is requesting a token
   for itself"). `User.Read` gives the access token a real audience
   (Microsoft Graph). `offline_access` enables refresh tokens.

3. Grant admin consent for `User.Read` (or have the user consent on
   first sign-in).

### Google / Auth0 / Okta / Keycloak

Standard SPA / public-client registration with PKCE. No special setup.

## MCP authorization

`oidc-proxy` can additionally act as an **MCP-compliant OAuth 2.1
Authorization Server** (MCP spec rev 2026-07-28) in front of a remote HTTP
MCP server, so AI-agent clients (Claude Code, Cursor, VS Code, `mcp-remote`,
…) authenticate with the **same Microsoft Entra ID SSO** your human users
already use — per-user identity, no shared secrets, zero client config.

It is **off by default** (`MCP_ENABLED=false`) and leaves the human `/verify`
cookie flow completely untouched. When enabled, the proxy:

- issues **its own** short-lived, audience-bound JWT access tokens signed with
  a stable ES256 key — it never redeems codes with Entra and never forwards
  Entra tokens upstream (**no token passthrough**);
- authenticates the browser at `/oauth2/authorize` purely by checking for a
  valid Entra session cookie (reusing the existing sign-in / refresh pages);
- accepts **Client ID Metadata Documents** — a client identifies itself with
  an `https` URL it hosts, so there is no registration step and no client
  record on either side;
- is **stateless end to end** — every artifact (client_id, consent blob, code,
  access & refresh token) is a self-contained JWS/JWE, so it scales to
  multiple replicas with no shared store.

### What rev 2026-07-28 changes

| Change | How it lands here |
| --- | --- |
| **Client ID Metadata Documents** (CIMD) replace registration | `client_id` may be an `https` URL; the AS fetches, validates and caches the document. Advertised as `client_id_metadata_document_supported` |
| **DCR deprecated** | `/oauth2/register` still works, unchanged, for older clients. `application_type` is accepted and echoed |
| **RFC 9207 issuer identification** | Every authorization response — success *and* error — carries `iss`, advertised as `authorization_response_iss_parameter_supported` |
| **Scope challenges / step-up** | 401 and 403 challenges carry a `scope` hint; a token missing `MCP_REQUIRED_SCOPES` gets `403` + `error="insufficient_scope"` |

The stateless *protocol* changes in this revision (no `initialize` handshake,
no `Mcp-Session-Id`, `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name`
headers) are the MCP server's business, not the proxy's — `/mcp-verify`
already treats every request independently, so nothing there needs to change.

### Client ID Metadata Documents

A client publishes a JSON document at an `https` URL with a path
(`https://app.example.com/oauth/client.json`) and passes that URL as its
`client_id`. The AS resolves it on `GET /oauth2/authorize` and requires
`client_id` (matching the URL exactly), `client_name`, and `redirect_uris`.
The authorization request's `redirect_uri` must match one of them exactly, as
with a registered client.

Because the AS fetches an attacker-chosen URL, the fetch is fenced in:
non-public destinations are refused after DNS resolution (SSRF), redirects are
not followed, the body is capped at 32 KiB, the request is timed out, results
(including failures) are cached, and the endpoint is rate limited per IP. Set
`MCP_CIMD_ALLOWED_HOSTS` to narrow it further to hosts you trust.

The consent page names the document's host under **Published by** — that
domain is the only part of a CIMD client's identity the AS actually verified;
`client_name` stays labelled unverified. Clients whose redirect URIs are all
loopback get an extra warning, since no authorization server can tell them
apart from anything else running on the user's machine.

### Flow

```
  MCP client                     oidc-proxy (AS + RS)                 Entra ID
      │  GET /mcp (no token)             │                                │
      │─────────────────────────────────►│ /mcp-verify → 401              │
      │  401 WWW-Authenticate:            │  resource_metadata=…           │
      │◄─────────────────────────────────│                                │
      │  GET /.well-known/oauth-protected-resource/<path>  (PRM, RFC 9728) │
      │  GET /.well-known/oauth-authorization-server       (AS md, 8414)   │
      │  client_id = https URL of its own metadata document (CIMD)         │
      │      (or POST /oauth2/register — deprecated DCR, RFC 7591)         │
      │  GET /oauth2/authorize (browser, PKCE S256 + resource)             │
      │─────────────────────────────────►│  fetch + validate the CIMD doc │
      │                                   │  no Entra cookie? ──► SSO ────►│
      │                                   │  consent page (Approve)        │
      │  POST /oauth2/authorize (same-origin, CSRF-guarded) → code + iss   │
      │  POST /oauth2/token (code + PKCE verifier) → access + refresh      │
      │◄─────────────────────────────────│                                │
      │  GET /mcp  Authorization: Bearer <access token>                    │
      │─────────────────────────────────►│ /mcp-verify → 200 + headers     │
```

`/mcp-verify` is a second `forwardAuth` target (analogous to `/verify`, but
for bearer tokens instead of cookies): it validates the token signature
(ES256, alg-pinned), `token_use=access`, `iss`, audience (`aud == MCP_RESOURCE`),
and expiry, then emits `X-Auth-Request-Email` / `X-Auth-Request-User`. It never
redirects — only `200` / `401` / `403`.

### MCP endpoints (only registered when `MCP_ENABLED=true`)

| Path | Method | Purpose |
| --- | --- | --- |
| `/.well-known/oauth-authorization-server[/<issuer path>]` | GET | AS metadata (RFC 8414) |
| `/.well-known/openid-configuration[/<issuer path>]` | GET | Same, plus OIDC-probe fields |
| `/.well-known/oauth-protected-resource[/<path>]` | GET | Protected-resource metadata (RFC 9728) |
| `/oauth2/jwks.json` | GET | Public ES256 signing key(s) |
| `/oauth2/register` | POST | Dynamic Client Registration (RFC 7591) — deprecated |
| `/oauth2/authorize` | GET | Validate + authenticate + render consent |
| `/oauth2/authorize` | POST | Same-origin, CSRF-guarded — mints the code |
| `/oauth2/token` | POST | authorization_code + refresh_token grants |
| `/mcp-verify` | GET/POST | Resource-server `forwardAuth` target |

### MCP environment variables

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `MCP_ENABLED` | no | `false` | Master switch for all of the above |
| `MCP_ISSUER` | if enabled | — | Canonical AS issuer, absolute `https://` URL. **Static** — never derived from `X-Forwarded-*` |
| `MCP_RESOURCE` | if enabled | — | Canonical MCP resource URI, e.g. `https://docs.example.com/mcp` |
| `MCP_RESOURCE_DOCS` | no | — | Optional human docs URL advertised in PRM |
| `MCP_SIGNING_KEY` / `MCP_SIGNING_KEY_FILE` | if enabled | — | ES256 private key (PEM) or a path to it. **Must be stable across replicas/restarts** |
| `MCP_SIGNING_KID` | no | JWK thumbprint | `kid` for the signing key |
| `MCP_ENC_KEY` | no | HKDF from signing key | 32-byte base64 key for the code/consent JWEs (A256GCM) |
| `MCP_ACCESS_TOKEN_TTL` | no | `15m` | Access-token lifetime |
| `MCP_REFRESH_TOKEN_TTL` | no | `720h` | Refresh lifetime, as a sliding window — an idle gap longer than this forces a full re-auth (see below) |
| `MCP_CODE_TTL` | no | `60s` | Authorization-code lifetime |
| `MCP_AUTHREQ_TTL` | no | `5m` | Consent-request blob lifetime |
| `MCP_SCOPES_SUPPORTED` | no | `mcp` | Advertised scopes (drives metadata + PRM). A request for anything outside this set is `invalid_scope`; a request with no `scope` grants all of them |
| `MCP_REQUIRED_SCOPES` | no | — | Scopes `/mcp-verify` demands. Must be a subset of the above. Empty = no scope enforcement |
| `MCP_CIMD_ENABLED` | no | `true` | Accept Client ID Metadata Document `client_id`s |
| `MCP_CIMD_ALLOWED_HOSTS` | no | — | Trust policy for CIMD hosts: exact hosts or `*.example.com`. Empty = any public host |
| `MCP_CIMD_ALLOW_PRIVATE_HOSTS` | no | `false` | Drop the SSRF guard so CIMD documents may be fetched from private/loopback addresses. Testing only |
| `MCP_CIMD_CACHE_TTL` | no | `15m` | Fallback cache lifetime when the document sends no `Cache-Control` (header `max-age` wins, clamped to 1m–24h) |
| `MCP_CIMD_CACHE_SIZE` | no | `512` | Max cached client metadata documents |
| `MCP_CIMD_TIMEOUT` | no | `5s` | Timeout for a client metadata fetch |

`ALLOWED_EMAILS` / `ALLOWED_DOMAINS` gate MCP access too — enforced at both
`/oauth2/authorize` and `/mcp-verify`.

> **Setting `MCP_REQUIRED_SCOPES` invalidates tokens in flight.** Access tokens
> issued before it was set carry whatever scope was requested then, so any that
> fall short start getting `403 insufficient_scope` until they expire
> (`MCP_ACCESS_TOKEN_TTL`, 15m by default). Clients recover on their own by
> re-authorizing with the challenged scope.

Generate a signing key with:

```bash
openssl ecparam -name prime256v1 -genkey -noout   # -> MCP_SIGNING_KEY (PEM)
```

### Traefik wiring

The existing `PathPrefix(/oauth2)` route already covers `authorize` / `token`
/ `register` / `jwks.json`. Two additions are needed (handled in your Traefik
config, not this repo):

1. A **public** route (no auth middleware) for the discovery paths:
   `PathPrefix(/.well-known/oauth-protected-resource)`,
   `PathPrefix(/.well-known/oauth-authorization-server)`,
   `PathPrefix(/.well-known/openid-configuration)` → oidc-proxy.
2. The `/mcp` route → your MCP server, gated by a **new** `forwardAuth`
   middleware pointing at `http://oidc-proxy:8080/mcp-verify` with
   `authResponseHeaders: X-Auth-Request-Email,X-Auth-Request-User`.

Do not log `/oauth2` query strings (codes are opaque JWEs, but avoid it
anyway). The MCP server itself stays vanilla — all enforcement is `/mcp-verify`.

### Connecting a client

```
claude mcp add --transport http docs https://docs.example.com/mcp
# → browser opens Microsoft SSO → consent → done (no manual token)
```

> **Refresh-token lifetime is a sliding window.** Every refresh mints a fresh
> token expiring `MCP_REFRESH_TOKEN_TTL` from *that moment*, so an actively
> used session never expires; the TTL only bites after an idle gap longer
> than it. At the former 8h default that meant a full browser re-auth every
> morning, which is why the default is now 30d.
>
> The cost is that per-replica reuse detection is best-effort (there is no
> shared store), so a leaked refresh token is undetectable for its whole
> life — a longer TTL widens that window. Lower `MCP_REFRESH_TOKEN_TTL` if
> that trade doesn't suit you, or keep it long once a shared `ReplayGuard`
> (e.g. Redis) backs reuse detection.
>
> A rejected refresh forces a full re-auth and logs a classification you can
> grep for: `refresh rejected (expired)` means the TTL is too short for your
> usage pattern, while `refresh rejected (already used)` means the same token
> was presented twice — a retried or concurrent refresh racing rotation,
> which no TTL change will fix.

## Security model

- The ID, access, and refresh tokens are written to three separate
  plaintext cookies on `<prefix>_id_token`, `<prefix>_access_token`,
  `<prefix>_refresh_token` — all `Secure`, `SameSite=Lax`, **not**
  `HttpOnly` so the static site's JS can read them. This is an
  intentional trade-off: the SPA flow already exposes the tokens to JS
  during sign-in, and JS-readable cookies remove backend roundtrips
  (the refresh page reads the refresh token directly; the static site
  can call APIs with the access token without asking the backend).
  Treat the cookies as you would any client-side token storage.
- `POST /oauth2/session` enforces `Origin == X-Forwarded-Host`,
  blocking session-fixation attacks where a third-party site tries to
  install tokens into the user's browser.
- On every protected request, the backend verifies the ID token via
  JWKS (cached by `go-oidc`) — never trusts the cookie blindly. The
  verification result is memoized in an in-process cache keyed by the
  token's SHA-256, expiring at the JWT's own `exp`, so a busy session
  pays the verification cost roughly once per token lifetime instead
  of once per request.
- Open-redirects are blocked: `rd` only accepts same-origin absolute paths.

## Build & run locally

```bash
go test ./...
go build -o oidc-proxy .

OIDC_ISSUER=https://accounts.google.com \
OIDC_CLIENT_ID=xxxx.apps.googleusercontent.com \
COOKIE_SECURE=false \
./oidc-proxy
```

A Docker image is built by the workflows in `.github/workflows/` and
published to `ghcr.io/<owner>/<repo>` on push to `dev` / `master` and on
`v*` tags.
