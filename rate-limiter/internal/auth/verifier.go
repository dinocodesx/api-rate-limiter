package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	redisstore "github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/store/redis"
)

type Verifier struct {
	secret         []byte
	expectedIssuer string
	revocations    *redisstore.RevocationStore
}

func NewVerifier(secret string, expectedIssuer string, revocations *redisstore.RevocationStore) *Verifier {
	return &Verifier{secret: []byte(secret), expectedIssuer: expectedIssuer, revocations: revocations}
}

func (v *Verifier) VerifyRequest(ctx context.Context, token string, apiID string) (*APIKeyClaims, error) {
	claims, err := v.VerifyToken(token)
	if err != nil {
		return nil, err
	}
	// The header must agree with the token claim so callers cannot reuse one
	// valid key against a different registered API.
	if claims.APIID != apiID {
		return nil, fmt.Errorf("api_id mismatch")
	}
	revoked, err := v.revocations.IsRevoked(ctx, claims.JWTID)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, fmt.Errorf("api key has been revoked")
	}
	return claims, nil
}

func (v *Verifier) VerifyToken(token string) (*APIKeyClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token must have 3 segments")
	}
	var header struct {
		Algorithm string `json:"alg"`
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
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
		return nil, fmt.Errorf("JWT verification failed")
	}

	// Only after the signature matches do we trust and validate claim values.
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims APIKeyClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	if err := validateClaims(claims, v.expectedIssuer, time.Now().UTC()); err != nil {
		return nil, err
	}
	return &claims, nil
}

func validateClaims(claims APIKeyClaims, expectedIssuer string, now time.Time) error {
	if claims.Issuer == "" || claims.Subject == "" || claims.APIID == "" || claims.OwnerID == "" || claims.JWTID == "" {
		return fmt.Errorf("JWT verification failed")
	}
	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		return fmt.Errorf("JWT verification failed")
	}
	if claims.ExpiresAt == 0 || now.Unix() >= claims.ExpiresAt {
		return fmt.Errorf("JWT verification failed")
	}
	return nil
}

func signHS256(signingInput string, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}
