package mcpauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
)

// hkdfEncKeyInfo domain-separates the HKDF used to derive the JWE content key
// from the signing key when MCP_ENC_KEY is not supplied. Bump the version
// suffix only alongside an intentional key-schedule change.
const hkdfEncKeyInfo = "oidc-proxy/mcp-enc-key/v1"

// keyMaterial holds everything the AS needs to sign, encrypt, verify, and
// publish keys. It is derived once at startup from stable, secret config and
// shared read-only across requests and replicas.
type keyMaterial struct {
	signer jose.Signer        // JWS ES256, kid in protected header
	enc    jose.Encrypter     // JWE dir + A256GCM (encrypt-to-self)
	encKey []byte             // 32-byte A256GCM key (also the decrypt key)
	kid    string             // current signing kid
	verify jose.JSONWebKeySet // public keys accepted for verification (by kid)
	public jose.JSONWebKeySet // public keys published at jwks_uri
}

// loadKeys parses the ES256 signing key, derives the kid and JWE key, and
// builds the signer/encrypter plus the public JWK set.
func loadKeys(signingPEM, kid, encKeyB64 string) (*keyMaterial, error) {
	priv, err := parseES256PrivateKey(signingPEM)
	if err != nil {
		return nil, err
	}

	pubJWK := jose.JSONWebKey{
		Key:       &priv.PublicKey,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	if kid == "" {
		tp, err := pubJWK.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("derive kid: %w", err)
		}
		kid = base64.RawURLEncoding.EncodeToString(tp)
	}
	pubJWK.KeyID = kid

	signerOpts := (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, signerOpts)
	if err != nil {
		return nil, fmt.Errorf("build signer: %w", err)
	}

	encKey, err := deriveEncKey(priv, encKeyB64)
	if err != nil {
		return nil, err
	}
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: encKey}, nil)
	if err != nil {
		return nil, fmt.Errorf("build encrypter: %w", err)
	}

	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
	return &keyMaterial{
		signer: signer,
		enc:    enc,
		encKey: encKey,
		kid:    kid,
		verify: set,
		public: set,
	}, nil
}

// verificationKey returns the public key registered under kid, but only if it
// is an ES256 signing key. An empty kid selects the current signing key. This
// is where algorithm confusion is stopped at the key-selection layer: a key is
// never returned unless it is explicitly ES256 (the published key can never be
// re-used as an HMAC secret because we hand back the ECDSA public key, and the
// alg is pinned again at parse time).
func (k *keyMaterial) verificationKey(kid string) (*jose.JSONWebKey, error) {
	if kid == "" {
		kid = k.kid
	}
	for i := range k.verify.Keys {
		jwk := &k.verify.Keys[i]
		if jwk.KeyID == kid && jwk.Algorithm == string(jose.ES256) {
			return jwk, nil
		}
	}
	return nil, fmt.Errorf("no ES256 verification key for kid %q", kid)
}

// parseES256PrivateKey accepts a PEM-encoded P-256 ECDSA private key in either
// SEC1 ("EC PRIVATE KEY", what `openssl ecparam -genkey` emits) or PKCS#8
// ("PRIVATE KEY") form.
func parseES256PrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	pemStr = strings.TrimSpace(pemStr)
	if pemStr == "" {
		return nil, fmt.Errorf("empty signing key")
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("signing key is not valid PEM")
	}

	var priv *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse SEC1 EC private key: %w", err)
		}
		priv = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		ecKey, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing key is %T, want *ecdsa.PrivateKey", k)
		}
		priv = ecKey
	default:
		return nil, fmt.Errorf("unsupported PEM block %q; want EC PRIVATE KEY or PRIVATE KEY", block.Type)
	}

	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("signing key curve is %s, want P-256 (ES256)", priv.Curve.Params().Name)
	}
	return priv, nil
}

// deriveEncKey returns the 32-byte A256GCM content key. An explicit MCP_ENC_KEY
// (base64, 32 bytes) wins; otherwise the key is HKDF-derived from the signing
// key so it is stable across replicas and restarts without extra config.
func deriveEncKey(priv *ecdsa.PrivateKey, encKeyB64 string) ([]byte, error) {
	if s := strings.TrimSpace(encKeyB64); s != "" {
		raw, err := decodeBase64(s)
		if err != nil {
			return nil, fmt.Errorf("MCP_ENC_KEY: %w", err)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("MCP_ENC_KEY must decode to 32 bytes, got %d", len(raw))
		}
		return raw, nil
	}
	// Deterministic, stable secret from the private key material (PKCS#8 DER).
	secret, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal signing key for HKDF: %w", err)
	}
	key, err := hkdf.Key(sha256.New, secret, nil, hkdfEncKeyInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive enc key: %w", err)
	}
	return key, nil
}

// decodeBase64 accepts standard or URL alphabets, padded or unpadded.
func decodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not valid base64")
}
