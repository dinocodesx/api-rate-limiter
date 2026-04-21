package jwt

import (
	"testing"
	"time"

	"github.com/rishi/api-rate-limiter/packages/api-key/internal/types"
)

func TestSignerAndVerifier(t *testing.T) {
	signer := NewSigner("secret", "issuer")
	verifier := NewVerifier("secret")
	now := time.Now().UTC()

	token, err := signer.Sign(types.APIKeyClaims{
		Subject:   "key_123",
		APIID:     "payments-prod",
		OwnerID:   "user_123",
		Scopes:    []string{"proxy:access"},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JWTID:     "jti_123",
	})
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	claims, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.Subject != "key_123" {
		t.Fatalf("expected subject key_123, got %s", claims.Subject)
	}
}

func TestVerifierRejectsExpiredToken(t *testing.T) {
	signer := NewSigner("secret", "issuer")
	verifier := NewVerifier("secret")
	now := time.Now().UTC().Add(-2 * time.Hour)

	token, err := signer.Sign(types.APIKeyClaims{
		Subject:   "key_123",
		APIID:     "payments-prod",
		OwnerID:   "user_123",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JWTID:     "jti_123",
	})
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	if _, err := verifier.Verify(token); err == nil {
		t.Fatal("expected expired token to fail verification")
	}
}
