package token

import (
	"context"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Verified carries the claims extracted from a verified ID token. The struct
// is small on purpose: it isolates handlers from go-oidc and lets tests build
// a stub verifier without going through real JWT parsing.
type Verified struct {
	Subject string
	Email   string
	Nonce   string
	Expiry  time.Time
}

// VerifyFunc is the verification contract used throughout the codebase: take
// a raw JWT, return the verified claims (or an error). Caching and the real
// go-oidc verifier both implement this shape.
type VerifyFunc func(ctx context.Context, token string) (*Verified, error)

func Wrap(v *oidc.IDTokenVerifier) VerifyFunc {
	return func(ctx context.Context, token string) (*Verified, error) {
		idTok, err := v.Verify(ctx, token)
		if err != nil {
			return nil, err
		}
		var claims struct {
			Email string `json:"email"`
		}
		_ = idTok.Claims(&claims)
		return &Verified{
			Subject: idTok.Subject,
			Email:   claims.Email,
			Nonce:   idTok.Nonce,
			Expiry:  idTok.Expiry,
		}, nil
	}
}
