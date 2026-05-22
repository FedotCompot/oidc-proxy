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
