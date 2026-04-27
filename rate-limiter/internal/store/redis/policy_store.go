package redisstore

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	redis "github.com/redis/go-redis/v9"
	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/types"
)

type PolicyStore struct {
	client *redis.Client
}

func NewPolicyStore(client *redis.Client) *PolicyStore {
	return &PolicyStore{client: client}
}

func (s *PolicyStore) GetAPI(ctx context.Context, apiID string) (*types.APIRegistration, error) {
	payload, err := s.client.Get(ctx, "api:config:"+apiID).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("api %q not found", apiID)
		}
		return nil, fmt.Errorf("get api config: %w", err)
	}
	var registration types.APIRegistration
	if err := json.Unmarshal(payload, &registration); err != nil {
		return nil, fmt.Errorf("unmarshal api config: %w", err)
	}
	return &registration, nil
}

func MatchPolicy(registration *types.APIRegistration, method, requestPath string) (*types.RoutePolicy, error) {
	normalizedMethod := strings.ToUpper(strings.TrimSpace(method))
	normalizedPath := normalizeRoute(requestPath)
	for _, policy := range registration.RoutePolicies {
		if strings.ToUpper(policy.Method) == normalizedMethod && normalizeRoute(policy.PathPattern) == normalizedPath {
			matched := policy
			matched.PathPattern = normalizeRoute(matched.PathPattern)
			return &matched, nil
		}
	}
	return nil, fmt.Errorf("no route policy for %s %s", normalizedMethod, normalizedPath)
}

type RevocationStore struct {
	client *redis.Client
}

func NewRevocationStore(client *redis.Client) *RevocationStore {
	return &RevocationStore{client: client}
}

func (s *RevocationStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	count, err := s.client.Exists(ctx, "revoked:jti:"+jti).Result()
	if err != nil {
		return false, fmt.Errorf("check revoked token: %w", err)
	}
	return count == 1, nil
}

func normalizeRoute(raw string) string {
	cleaned := path.Clean("/" + strings.TrimSpace(raw))
	if cleaned == "." {
		return "/"
	}
	return cleaned
}
