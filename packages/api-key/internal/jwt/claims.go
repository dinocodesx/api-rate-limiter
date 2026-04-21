package jwt

import (
	"fmt"
	"time"

	"github.com/rishi/api-rate-limiter/packages/api-key/internal/types"
)

func ValidateClaims(claims types.APIKeyClaims, now time.Time) error {
	if claims.Issuer == "" {
		return fmt.Errorf("missing iss")
	}
	if claims.Subject == "" {
		return fmt.Errorf("missing sub")
	}
	if claims.APIID == "" {
		return fmt.Errorf("missing api_id")
	}
	if claims.OwnerID == "" {
		return fmt.Errorf("missing owner_id")
	}
	if claims.JWTID == "" {
		return fmt.Errorf("missing jti")
	}
	if claims.ExpiresAt == 0 {
		return fmt.Errorf("missing exp")
	}
	if now.Unix() >= claims.ExpiresAt {
		return fmt.Errorf("token expired")
	}
	if claims.IssuedAt == 0 {
		return fmt.Errorf("missing iat")
	}
	return nil
}
