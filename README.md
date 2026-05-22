# oidc-proxy

A tiny Go service that adds OIDC authentication to static sites behind
[Traefik](https://traefik.io/) via the
[`forwardAuth`](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)
middleware. It **only verifies tokens** — it never proxies your site's
traffic.

- Public-client / PKCE flow — no client secret needed
- AES-GCM encrypted session cookie holding access / ID / refresh tokens
- Self-contained HTML sign-in screen (light & dark)
- Zero config files — everything is env vars
- Two required env vars: `OIDC_ISSUER`, `OIDC_CLIENT_ID`

## How it fits in

```
                 ┌────────────────────────────────┐
   browser ─────►│ Traefik                        │
                 │  app.example.com/*  ── forwardAuth ──► oidc-proxy:/verify
                 │  app.example.com/oauth2/*  ───────────► oidc-proxy
                 │                                 │
                 │  static site (nginx, etc.)      │
                 └────────────────────────────────┘
```

`oidc-proxy` answers two kinds of requests:

1. **`/verify`** — called by Traefik's `forwardAuth`. Returns `200` if the
   request carries a valid session cookie; otherwise `302` to the sign-in
   page (or to `/oauth2/refresh` if only the access token is expired).
2. **`/oauth2/*`** — direct browser requests for the sign-in screen and
   OIDC redirect dance.

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

| Path | Purpose |
| --- | --- |
| `GET /verify` | forwardAuth target — 200 / 302 / 403 |
| `GET /oauth2/sign_in` | HTML login screen with a single button |
| `GET /oauth2/start` | Generates PKCE + state + nonce, redirects to issuer |
| `GET /oauth2/callback` | Receives the code, sets the session cookie |
| `GET /oauth2/refresh` | Refreshes tokens using the refresh token cookie |
| `GET /oauth2/sign_out` | Clears the session cookie |
| `GET /healthz` | `204 No Content` |

Each handler accepts an `rd` query param to preserve the destination URL
across the redirects.

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

## Token refresh

When the access token has expired but a refresh token is present,
`/verify` redirects to `/oauth2/refresh`. That endpoint is a normal route
(not behind forwardAuth), so its `Set-Cookie` reaches the browser without
needing extra Traefik configuration. It refreshes the tokens, rewrites the
session cookie, and bounces the user back to where they were.

## Cookie format

A single cookie (`<prefix>_session`) holds an AES-GCM-encrypted JSON blob:

```json
{ "a": "<access>", "i": "<id>", "r": "<refresh>", "e": "<expiry>", "m": "<email>", "s": "<sub>" }
```

A short-lived `<prefix>_flow` cookie holds the PKCE verifier, state, and
nonce during the redirect dance, scoped to `/oauth2`.

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
