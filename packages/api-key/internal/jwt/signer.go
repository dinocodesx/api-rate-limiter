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

type Signer struct {
	secret []byte
	issuer string
}

func NewSigner(secret, issuer string) *Signer {
	return &Signer{secret: []byte(secret), issuer: issuer}
}

func (s *Signer) Sign(claims types.APIKeyClaims) (string, error) {
	if claims.Issuer == "" {
		claims.Issuer = s.issuer
	}
	if err := ValidateClaims(claims, time.Unix(claims.IssuedAt, 0).UTC()); err != nil {
		return "", err
	}

	// The service builds compact HS256 JWTs directly to avoid pulling in a
	// heavier abstraction for a very small claim set.
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal jwt header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal jwt claims: %w", err)
	}

	encodedHeader := encodeSegment(headerJSON)
	encodedClaims := encodeSegment(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims

	sig := signHS256(signingInput, s.secret)
	return strings.Join([]string{encodedHeader, encodedClaims, encodeSegment(sig)}, "."), nil
}

func signHS256(signingInput string, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}

func encodeSegment(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
