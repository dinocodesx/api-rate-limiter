package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rishi/api-rate-limiter/packages/api-key/internal/types"
)

type Verifier struct {
	secret []byte
}

func NewVerifier(secret string) *Verifier {
	return &Verifier{secret: []byte(secret)}
}

func (v *Verifier) Verify(token string) (*types.APIKeyClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token must have 3 segments")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("unmarshal header: %w", err)
	}
	if header.Algorithm != "HS256" {
		return nil, fmt.Errorf("unsupported alg %q", header.Algorithm)
	}

	signingInput := parts[0] + "." + parts[1]
	expectedSig := signHS256(signingInput, v.secret)
	providedSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if !hmac.Equal(expectedSig, providedSig) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Claims are validated after signature verification so expiry and required
	// fields cannot be spoofed by unsigned payload changes.
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims types.APIKeyClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	if err := ValidateClaims(claims, time.Now().UTC()); err != nil {
		return nil, err
	}

	return &claims, nil
}

func signature(secret []byte, input string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(input))
	return mac.Sum(nil)
}
