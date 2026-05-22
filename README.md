# oidc-proxy

A tiny Go service that adds OIDC authentication to static sites behind
[Traefik](https://traefik.io/) via the
[`forwardAuth`](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)
middleware.

It runs a true **SPA / public-client** flow: all OAuth token requests
happen in the browser. The Go backend never exchanges codes or refresh
tokens itself — it only **verifies** ID tokens (JWKS signature + claims)
and seals them into an encrypted HttpOnly cookie. That keeps the design
compatible with strict providers like Microsoft Entra ID, which refuses
server-side token redemption when a redirect URI is registered as SPA.

- Public-client / PKCE flow — no client secret needed
- Browser does the token exchange; backend only verifies & seals cookies
- AES-GCM encrypted HttpOnly session cookie holding access / ID / refresh tokens
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
                        JS fetch(POST /oauth2/session, tokens)    ← backend verifies + seals cookie
                        window.location = <original URL>
```

## Token refresh

When `/verify` finds the cookie's ID token has expired, it redirects to
`/oauth2/refresh`. That page asks the backend for the refresh token
(same-origin only), POSTs it to the issuer's token endpoint from the
browser, then POSTs the new tokens back to `/oauth2/session`. Same
"browser does the request" pattern as sign-in.

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
COOKIE_SECRET=$(openssl rand -base64 32)   # recommended
```

## Endpoints

| Path | Method | Purpose |
| --- | --- | --- |
| `/verify` | GET | forwardAuth target — 200 / 302 / 403 |
| `/oauth2/sign_in` | GET | HTML login screen with a single button |
| `/oauth2/start` | GET | JS page: generates PKCE & redirects to issuer |
| `/oauth2/callback` | GET | JS page: exchanges code in-browser, posts tokens to backend |
| `/oauth2/session` | POST | Backend: verifies ID token, seals encrypted cookie (same-origin only) |
| `/oauth2/refresh` | GET | JS page: refreshes tokens in-browser |
| `/oauth2/refresh_token` | GET | Backend: returns refresh token to the refresh page (same-origin only) |
| `/oauth2/sign_out` | GET | Clears the session cookie |
| `/healthz` | GET | `204 No Content` |

`sign_in`, `start`, and `refresh` accept an `rd` query param to preserve
the destination URL across the redirects.

## Environment variables

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `OIDC_ISSUER` | yes | — | Discovery base URL (e.g. `https://accounts.google.com`) |
| `OIDC_CLIENT_ID` | yes | — | Public client ID |
| `OIDC_SCOPES` | no | `openid profile email` | Space-separated; `openid` is auto-added if missing |
| `COOKIE_SECRET` | no | random per start | 16/24/32-byte base64. If unset, sessions die on restart |
| `COOKIE_NAME_PREFIX` | no | `_oidc_proxy` | Cookie name prefix |
| `COOKIE_DOMAIN` | no | request host | Set to share across subdomains |
| `COOKIE_SECURE` | no | `true` | Set to `false` only for local HTTP testing |
| `ALLOWED_EMAILS` | no | — | Comma-separated allowlist of emails |
| `ALLOWED_DOMAINS` | no | — | Comma-separated allowlist of email domains |
| `SIGN_IN_TITLE` | no | `Sign in` | Sign-in page heading |
| `SIGN_IN_BUTTON` | no | `Sign in with SSO` | Button label |
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

Register the redirect URI under the **Single-Page Application** platform.
Because the token exchange happens in the browser via `fetch()`, the
browser automatically sets the `Origin` header — the cross-origin signal
Entra requires for SPA-registered apps (avoids `AADSTS9002327`).

Make sure refresh-token issuance is enabled for SPAs in your app
registration if you want token refresh.

### Google / Auth0 / Okta / Keycloak

Standard SPA / public-client registration with PKCE. No special setup.

## Security model

- Tokens are stored only in an **HttpOnly, AES-GCM-encrypted cookie**.
  JS in the static site has no access to them.
- The refresh token is briefly readable by the JS on
  `/oauth2/refresh` (and only there). CORS and `SameSite=Lax` prevent
  cross-origin reads.
- `POST /oauth2/session` and `GET /oauth2/refresh_token` enforce
  `Origin == X-Forwarded-Host`, blocking CSRF-style session injection.
- On every protected request, the backend re-verifies the ID token via
  JWKS (cached by `go-oidc`) — not just the expiry hint in the cookie.
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
