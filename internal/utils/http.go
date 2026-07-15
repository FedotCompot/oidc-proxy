// Package utils holds small request/URL helpers shared across the proxy.
package utils

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ForwardedProto / ForwardedHost prefer Traefik-set headers, falling back to
// the request itself so direct hits during local testing still work.
func ForwardedProto(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		return FirstField(v)
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func ForwardedHost(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		return FirstField(v)
	}
	return r.Host
}

// OriginalURL reconstructs the URL the user was originally trying to reach
// using Traefik's X-Forwarded-* headers (Uri carries path+query).
func OriginalURL(r *http.Request) string {
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" {
		uri = "/"
	}
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	return ForwardedProto(r) + "://" + ForwardedHost(r) + uri
}

// SanitizeRedirect blocks open-redirects: only same-origin paths are allowed.
func SanitizeRedirect(raw string) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw
	}
	return ""
}

func FirstField(s string) string {
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func OriginOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// ClientIP returns a best-effort client identifier for rate limiting. Behind
// Traefik the first X-Forwarded-For hop is the real client; otherwise fall
// back to the connection's remote address (port stripped). This is used only
// for coarse abuse limiting, never for authorization decisions.
func ClientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return FirstField(v)
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
