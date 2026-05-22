package web

import "html/template"

// htmlPage is the contract every page-data struct satisfies so renderHTML
// can stamp a freshly-generated CSP nonce onto it. Each struct embeds it
// via a Nonce field and a setNonce method.
type htmlPage interface {
	setNonce(string)
}

type signInData struct {
	Title    string
	Button   string
	StartURL string
	Nonce    string
}

func (d *signInData) setNonce(n string) { d.Nonce = n }

// flowData is passed to the JS pages (start / callback / refresh). The fields
// are interpolated into the page's inline <script> via html/template, which
// applies JS-context-aware escaping automatically.
type flowData struct {
	ClientID          string
	Scopes            string
	AuthorizeEndpoint string
	TokenEndpoint     string
	CookiePrefix      string
	Redirect          string // not used by callback (it reads sessionStorage)
	Nonce             string
}

func (d *flowData) setNonce(n string) { d.Nonce = n }

var signInTemplate = template.Must(template.New("signin").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.Title}}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center;
    font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #f6f7f9; color: #1a1a1a;
  }
  @media (prefers-color-scheme: dark) {
    body { background: #15161a; color: #e6e6e6; }
    .card { background: #1f2127; border-color: #2c2f37; }
    .btn { background: #4f8cff; }
    .btn:hover { background: #3b78ee; }
  }
  .card {
    background: #fff; border: 1px solid #e3e5ea; border-radius: 12px;
    padding: 32px 36px; width: min(360px, 92vw);
    box-shadow: 0 1px 2px rgba(0,0,0,.04), 0 8px 24px rgba(0,0,0,.06);
    text-align: center;
  }
  h1 { font-size: 20px; margin: 0 0 24px; font-weight: 600; }
  .btn {
    display: block; width: 100%; padding: 12px 16px;
    background: #2563eb; color: #fff; border: 0; border-radius: 8px;
    font: inherit; font-weight: 500; text-decoration: none; cursor: pointer;
  }
  .btn:hover { background: #1d4ed8; }
</style>
</head>
<body>
<main class="card">
  <h1>{{.Title}}</h1>
  <a class="btn" href="{{.StartURL}}">{{.Button}}</a>
</main>
</body>
</html>
`))

// pkceJS is the shared helper code embedded in start / callback / refresh.
const pkceJS = `
function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function randURLSafe(n) {
  const arr = new Uint8Array(n);
  crypto.getRandomValues(arr);
  return b64url(arr);
}
async function sha256b64(s) {
  const bytes = new TextEncoder().encode(s);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return b64url(new Uint8Array(hash));
}
function fail(msg, detail) {
  if (detail) console.error('oidc-proxy:', detail);
  const main = document.createElement('main');
  main.className = 'card';
  const h1 = document.createElement('h1');
  h1.textContent = 'Authentication error';
  const p = document.createElement('p');
  p.textContent = msg || 'Sign-in failed.';
  const hint = document.createElement('p');
  hint.style.color = '#999';
  hint.style.fontSize = '12px';
  hint.textContent = 'See the browser console for details.';
  const retryWrap = document.createElement('p');
  const retry = document.createElement('a');
  retry.href = '/oauth2/sign_in';
  retry.textContent = 'Try again';
  retryWrap.appendChild(retry);
  main.replaceChildren(h1, p, hint, retryWrap);
  document.body.replaceChildren(main);
}
async function postSession(tokens) {
  const r = await fetch('/oauth2/session', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(tokens),
  });
  if (!r.ok) throw new Error('session: ' + r.status + ' ' + await r.text());
}
async function tokenRequest(endpoint, params) {
  const r = await fetch(endpoint, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams(params),
  });
  if (!r.ok) throw new Error('token endpoint: ' + r.status + ' ' + await r.text());
  return r.json();
}
`

const flowPageHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Signing in…</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center;
         font: 15px/1.5 system-ui, -apple-system, sans-serif;
         background: #f6f7f9; color: #1a1a1a; }
  @media (prefers-color-scheme: dark) { body { background: #15161a; color: #e6e6e6; } .card { background: #1f2127; } }
  .card { background: #fff; border-radius: 12px; padding: 32px 36px;
          width: min(420px, 92vw); text-align: center; }
  h1 { font-size: 18px; margin: 0 0 8px; font-weight: 600; }
  p { color: #666; margin: 4px 0; }
</style>
</head>
<body>
<main class="card"><h1>Signing in…</h1><p>One moment.</p></main>
`

var startTemplate = template.Must(template.New("start").Parse(flowPageHead + `<script nonce="{{.Nonce}}">
` + pkceJS + `
(async () => {
  try {
    const clientId = {{.ClientID}};
    const scopes = {{.Scopes}};
    const authorizeEndpoint = {{.AuthorizeEndpoint}};
    const rd = {{.Redirect}};
    const redirectUri = window.location.origin + '/oauth2/callback';
    const verifier = randURLSafe(32);
    const state = randURLSafe(24);
    const nonce = randURLSafe(24);
    const challenge = await sha256b64(verifier);
    sessionStorage.setItem('oidc.verifier', verifier);
    sessionStorage.setItem('oidc.state', state);
    sessionStorage.setItem('oidc.nonce', nonce);
    sessionStorage.setItem('oidc.rd', rd);
    sessionStorage.setItem('oidc.redirect_uri', redirectUri);
    const u = new URL(authorizeEndpoint);
    u.searchParams.set('client_id', clientId);
    u.searchParams.set('response_type', 'code');
    u.searchParams.set('redirect_uri', redirectUri);
    u.searchParams.set('scope', scopes);
    u.searchParams.set('state', state);
    u.searchParams.set('nonce', nonce);
    u.searchParams.set('code_challenge', challenge);
    u.searchParams.set('code_challenge_method', 'S256');
    window.location = u.toString();
  } catch (e) {
    fail('Could not start the OIDC flow.', e.message);
  }
})();
</script>
</body></html>
`))

var callbackTemplate = template.Must(template.New("callback").Parse(flowPageHead + `<script nonce="{{.Nonce}}">
` + pkceJS + `
(async () => {
  try {
    const clientId = {{.ClientID}};
    const tokenEndpoint = {{.TokenEndpoint}};
    const params = new URLSearchParams(window.location.search);
    const err = params.get('error');
    if (err) {
      console.error('oidc-proxy authorization error:', err, params.get('error_description'));
      throw new Error('authorization error');
    }
    const code = params.get('code');
    const state = params.get('state');
    if (!code) throw new Error('missing authorization code');
    if (state !== sessionStorage.getItem('oidc.state')) throw new Error('state mismatch');
    const verifier = sessionStorage.getItem('oidc.verifier');
    const nonce = sessionStorage.getItem('oidc.nonce');
    const rd = sessionStorage.getItem('oidc.rd') || '/';
    const redirectUri = sessionStorage.getItem('oidc.redirect_uri') || (window.location.origin + '/oauth2/callback');
    if (!verifier) throw new Error('missing PKCE verifier (sessionStorage cleared?)');

    const tok = await tokenRequest(tokenEndpoint, {
      grant_type: 'authorization_code',
      client_id: clientId,
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    });
    await postSession({ ...tok, nonce });

    sessionStorage.removeItem('oidc.verifier');
    sessionStorage.removeItem('oidc.state');
    sessionStorage.removeItem('oidc.nonce');
    sessionStorage.removeItem('oidc.rd');
    sessionStorage.removeItem('oidc.redirect_uri');
    window.location = rd;
  } catch (e) {
    fail('Sign-in failed.', e.message);
  }
})();
</script>
</body></html>
`))

var refreshTemplate = template.Must(template.New("refresh").Parse(flowPageHead + `<script nonce="{{.Nonce}}">
` + pkceJS + `
function readCookie(name) {
  for (const part of document.cookie.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) {
      return decodeURIComponent(part.slice(eq + 1));
    }
  }
  return '';
}
(async () => {
  const rd = {{.Redirect}};
  const clientId = {{.ClientID}};
  const tokenEndpoint = {{.TokenEndpoint}};
  const cookiePrefix = {{.CookiePrefix}};
  function bailToSignIn() {
    window.location = '/oauth2/sign_in?rd=' + encodeURIComponent(rd);
  }
  try {
    const refresh_token = readCookie(cookiePrefix + '_refresh_token');
    if (!refresh_token) return bailToSignIn();
    const tok = await tokenRequest(tokenEndpoint, {
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token,
    });
    await postSession(tok);
    window.location = rd;
  } catch (e) {
    bailToSignIn();
  }
})();
</script>
</body></html>
`))
