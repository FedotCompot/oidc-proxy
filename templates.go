package main

import "html/template"

type signInData struct {
	Title    string
	Button   string
	StartURL template.URL
}

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
