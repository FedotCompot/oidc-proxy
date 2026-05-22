package utils

import "testing"

func TestSanitizeRedirect(t *testing.T) {
	cases := map[string]string{
		"/foo":                "/foo",
		"/":                   "/",
		"":                    "",
		"//evil.com/x":        "",
		"https://evil.com/x":  "",
		"javascript:alert(1)": "",
		"/foo?x=1&y=2":        "/foo?x=1&y=2",
	}
	for in, want := range cases {
		if got := SanitizeRedirect(in); got != want {
			t.Errorf("SanitizeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}
