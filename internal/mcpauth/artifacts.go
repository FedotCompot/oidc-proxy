package mcpauth

import (
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// ErrExpired marks an artifact that verified but is past its expiry. Callers
// classify on it to tell a routine timeout apart from a malformed or forged
// artifact without logging any token-derived bytes.
var ErrExpired = errors.New("expired")

// token_use discriminates the five artifact kinds. Every artifact carries one
// and every verification site asserts an exact match, so an artifact of one
// kind can never be replayed as another even though they share a signing/enc
// key (see the threat model in the brief, §2.1).
const (
	useClient  = "client"
	useAuthReq = "authreq"
	useCode    = "code"
	useAccess  = "access"
	useRefresh = "refresh"
)

// jtiBytes is the entropy (in bytes) of jti/csrf/family identifiers.
const jtiBytes = 16

// clockSkewLeeway tolerates modest clock drift between replicas when checking
// exp/nbf on the longer-lived signed artifacts (access, refresh). Codes and
// authreq blobs are validated with zero leeway — they are short-lived and
// same-replica-minted, so strictness costs nothing.
const clockSkewLeeway = 60 * time.Second

// Allowed algorithms, pinned at every parse. The published signing key is
// public, so accepting anything but ES256 (e.g. HS256, none) would let an
// attacker forge tokens; the JWE key algorithm is pinned to dir/A256GCM.
var (
	sigAlgs = []jose.SignatureAlgorithm{jose.ES256}
	keyAlgs = []jose.KeyAlgorithm{jose.DIRECT}
	encAlgs = []jose.ContentEncryption{jose.A256GCM}
)

// ---- claim shapes -----------------------------------------------------------

// ClientClaims is the decoded, verified content of a registered client_id
// (JWS, token_use=client). No secret; long-lived.
type ClientClaims struct {
	jwt.Claims
	TokenUse     string   `json:"token_use"`
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name"`
}

// AuthReqClaims is the encrypted (JWE) consent-request blob bound to a single
// GET /authorize render. Subject is the Entra sub the blob was minted for.
type AuthReqClaims struct {
	jwt.Claims
	TokenUse      string `json:"token_use"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	CodeChallenge string `json:"code_challenge"`
	Resource      string `json:"resource"`
	Scope         string `json:"scope"`
	State         string `json:"state"`
	Email         string `json:"email"`
	CSRF          string `json:"csrf"`
}

// CodeClaims is the encrypted (JWE) authorization code. It is opaque to the
// browser it travels through; the AS is the only reader.
type CodeClaims struct {
	jwt.Claims
	TokenUse      string `json:"token_use"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	CodeChallenge string `json:"code_challenge"`
	Resource      string `json:"resource"`
	Scope         string `json:"scope"`
	Email         string `json:"email"`
}

// AccessClaims is the audience-bound bearer token (JWS) presented at
// /mcp-verify. It is the ONLY artifact that carries iss/aud.
type AccessClaims struct {
	jwt.Claims
	TokenUse string `json:"token_use"`
	Scope    string `json:"scope"`
	Email    string `json:"email"`
	ClientID string `json:"client_id"`
}

// RefreshClaims is the rotating refresh token (JWS). family ties a rotation
// lineage together for future (shared-store) reuse detection.
type RefreshClaims struct {
	jwt.Claims
	TokenUse string `json:"token_use"`
	ClientID string `json:"client_id"`
	Resource string `json:"resource"`
	Scope    string `json:"scope"`
	Email    string `json:"email"`
	Family   string `json:"family"`
}

// ---- low-level JOSE helpers -------------------------------------------------

func (k *keyMaterial) signClaims(claims any) (string, error) {
	return jwt.Signed(k.signer).Claims(claims).Serialize()
}

func (k *keyMaterial) encryptClaims(claims any) (string, error) {
	return jwt.Encrypted(k.enc).Claims(claims).Serialize()
}

// parseSigned verifies a JWS with the alg pinned to ES256 and the signing key
// selected by the token's kid header, decoding claims into dest.
func (k *keyMaterial) parseSigned(token string, dest any) error {
	tok, err := jwt.ParseSigned(token, sigAlgs)
	if err != nil {
		return fmt.Errorf("parse signed: %w", err)
	}
	if len(tok.Headers) == 0 {
		return fmt.Errorf("signed token has no header")
	}
	jwk, err := k.verificationKey(tok.Headers[0].KeyID)
	if err != nil {
		return err
	}
	if err := tok.Claims(jwk.Public().Key, dest); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}
	return nil
}

// parseEncrypted decrypts a JWE (dir + A256GCM pinned) into dest.
func (k *keyMaterial) parseEncrypted(token string, dest any) error {
	tok, err := jwt.ParseEncrypted(token, keyAlgs, encAlgs)
	if err != nil {
		return fmt.Errorf("parse encrypted: %w", err)
	}
	if err := tok.Claims(k.encKey, dest); err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	return nil
}

// ---- mint -------------------------------------------------------------------

// ClientRegistration is the validated subset of a DCR request that becomes a
// client_id.
type ClientRegistration struct {
	RedirectURIs []string
	ClientName   string
}

// MintClientID returns a stateless, signed client_id (no secret).
func (as *AS) MintClientID(reg ClientRegistration) (string, error) {
	return as.keys.signClaims(ClientClaims{
		Claims: jwt.Claims{
			IssuedAt: jwt.NewNumericDate(as.now()),
			ID:       randToken(jtiBytes),
		},
		TokenUse:     useClient,
		RedirectURIs: reg.RedirectURIs,
		ClientName:   reg.ClientName,
	})
}

// AuthReqInput carries the validated authorization-request parameters plus the
// authenticated identity, ready to be sealed into a consent blob.
type AuthReqInput struct {
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Resource      string
	Scope         string
	State         string
	Sub           string
	Email         string
}

// MintAuthReq seals the consent-request blob and returns it plus the CSRF
// nonce embedded in it (the caller renders both as hidden form fields).
func (as *AS) MintAuthReq(in AuthReqInput) (blob, csrf string, err error) {
	csrf = randToken(jtiBytes)
	now := as.now()
	blob, err = as.keys.encryptClaims(AuthReqClaims{
		Claims: jwt.Claims{
			Subject:  in.Sub,
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(as.AuthReqTTL)),
			ID:       randToken(jtiBytes),
		},
		TokenUse:      useAuthReq,
		ClientID:      in.ClientID,
		RedirectURI:   in.RedirectURI,
		CodeChallenge: in.CodeChallenge,
		Resource:      in.Resource,
		Scope:         in.Scope,
		State:         in.State,
		Email:         in.Email,
		CSRF:          csrf,
	})
	return blob, csrf, err
}

// MintCode seals an authorization code from an approved consent blob.
func (as *AS) MintCode(req *AuthReqClaims) (string, error) {
	now := as.now()
	return as.keys.encryptClaims(CodeClaims{
		Claims: jwt.Claims{
			Subject:  req.Subject,
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(as.CodeTTL)),
			ID:       randToken(jtiBytes),
		},
		TokenUse:      useCode,
		ClientID:      req.ClientID,
		RedirectURI:   req.RedirectURI,
		CodeChallenge: req.CodeChallenge,
		Resource:      req.Resource,
		Scope:         req.Scope,
		Email:         req.Email,
	})
}

// TokenGrant is what /oauth2/token returns to the client.
type TokenGrant struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	Scope        string
}

// GrantInput is the per-user, per-client context an access/refresh pair is
// bound to. family carries an existing rotation lineage forward (empty → new).
type GrantInput struct {
	Sub      string
	Email    string
	ClientID string
	Resource string
	Scope    string
	Family   string
}

// IssueGrant mints an audience-bound access token and a rotating refresh token
// bound to the same client/resource/scope.
func (as *AS) IssueGrant(in GrantInput) (TokenGrant, error) {
	now := as.now()
	access, err := as.keys.signClaims(AccessClaims{
		Claims: jwt.Claims{
			Issuer:    as.Issuer,
			Subject:   in.Sub,
			Audience:  jwt.Audience{in.Resource},
			Expiry:    jwt.NewNumericDate(now.Add(as.AccessTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        randToken(jtiBytes),
		},
		TokenUse: useAccess,
		Scope:    in.Scope,
		Email:    in.Email,
		ClientID: in.ClientID,
	})
	if err != nil {
		return TokenGrant{}, err
	}

	family := in.Family
	if family == "" {
		family = randToken(jtiBytes)
	}
	refresh, err := as.keys.signClaims(RefreshClaims{
		Claims: jwt.Claims{
			Subject:  in.Sub,
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(as.RefreshTTL)),
			ID:       randToken(jtiBytes),
		},
		TokenUse: useRefresh,
		ClientID: in.ClientID,
		Resource: in.Resource,
		Scope:    in.Scope,
		Email:    in.Email,
		Family:   family,
	})
	if err != nil {
		return TokenGrant{}, err
	}

	return TokenGrant{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    int(as.AccessTTL / time.Second),
		Scope:        in.Scope,
	}, nil
}

// ---- verify -----------------------------------------------------------------

// VerifyClientID decodes a registered client_id. token_use must be "client".
func (as *AS) VerifyClientID(token string) (*ClientClaims, error) {
	var c ClientClaims
	if err := as.keys.parseSigned(token, &c); err != nil {
		return nil, err
	}
	if c.TokenUse != useClient {
		return nil, fmt.Errorf("wrong token_use %q, want %q", c.TokenUse, useClient)
	}
	if len(c.RedirectURIs) == 0 {
		return nil, fmt.Errorf("client_id has no redirect_uris")
	}
	return &c, nil
}

// VerifyAuthReq decrypts and validates a consent blob. token_use must be
// "authreq" and it must not be expired.
func (as *AS) VerifyAuthReq(token string) (*AuthReqClaims, error) {
	var c AuthReqClaims
	if err := as.keys.parseEncrypted(token, &c); err != nil {
		return nil, err
	}
	if c.TokenUse != useAuthReq {
		return nil, fmt.Errorf("wrong token_use %q, want %q", c.TokenUse, useAuthReq)
	}
	// Zero leeway: these are short-lived and same-replica-minted.
	if err := c.ValidateWithLeeway(jwt.Expected{Time: as.now()}, 0); err != nil {
		return nil, err
	}
	return &c, nil
}

// VerifyCode decrypts and validates an authorization code. token_use must be
// "code" and it must not be expired.
func (as *AS) VerifyCode(token string) (*CodeClaims, error) {
	var c CodeClaims
	if err := as.keys.parseEncrypted(token, &c); err != nil {
		return nil, err
	}
	if c.TokenUse != useCode {
		return nil, fmt.Errorf("wrong token_use %q, want %q", c.TokenUse, useCode)
	}
	// Zero leeway: 60s codes are same-replica-minted; PKCE + replay guard are
	// the real defenses, so we do not extend the window with clock-skew slack.
	if err := c.ValidateWithLeeway(jwt.Expected{Time: as.now()}, 0); err != nil {
		return nil, err
	}
	return &c, nil
}

// VerifyAccessToken validates a bearer token for the RS hot path: signature
// (ES256), token_use=access, iss==configured issuer, aud contains the
// configured resource, and exp/nbf. iss and aud come from static config, never
// from request headers.
func (as *AS) VerifyAccessToken(token string) (*AccessClaims, error) {
	var c AccessClaims
	if err := as.keys.parseSigned(token, &c); err != nil {
		return nil, err
	}
	if c.TokenUse != useAccess {
		return nil, fmt.Errorf("wrong token_use %q, want %q", c.TokenUse, useAccess)
	}
	err := c.ValidateWithLeeway(jwt.Expected{
		Time:        as.now(),
		Issuer:      as.Issuer,
		AnyAudience: jwt.Audience{as.Resource},
	}, clockSkewLeeway)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// VerifyRefreshToken validates a refresh token: signature (ES256),
// token_use=refresh, and exp/nbf. Client binding is checked by the caller.
func (as *AS) VerifyRefreshToken(token string) (*RefreshClaims, error) {
	var c RefreshClaims
	if err := as.keys.parseSigned(token, &c); err != nil {
		return nil, err
	}
	if c.TokenUse != useRefresh {
		return nil, fmt.Errorf("wrong token_use %q, want %q", c.TokenUse, useRefresh)
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Time: as.now()}, clockSkewLeeway); err != nil {
		if errors.Is(err, jwt.ErrExpired) {
			return nil, ErrExpired
		}
		return nil, err
	}
	return &c, nil
}
