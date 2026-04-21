package redisstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	redis "github.com/redis/go-redis/v9"
	"github.com/rishi/api-rate-limiter/packages/api-key/internal/types"
)

type Store struct {
	client *redis.Client
}

func NewStore(client *redis.Client) *Store {
	return &Store{client: client}
}

func APIConfigKey(apiID string) string {
	return "api:config:" + apiID
}

func APIKeyKey(apiKeyID string) string {
	return "api:key:" + apiKeyID
}

func RevokedTokenKey(jti string) string {
	return "revoked:jti:" + jti
}

func (s *Store) UpsertAPI(ctx context.Context, registration types.APIRegistration) error {
	payload, err := json.Marshal(registration)
	if err != nil {
		return fmt.Errorf("marshal api registration: %w", err)
	}
	// API config is long-lived state, so it is stored without a TTL.
	return s.client.Set(ctx, APIConfigKey(registration.APIID), payload, 0).Err()
}

func (s *Store) GetAPI(ctx context.Context, apiID string) (*types.APIRegistration, error) {
	payload, err := s.client.Get(ctx, APIConfigKey(apiID)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("api %q not found", apiID)
		}
		return nil, fmt.Errorf("get api registration: %w", err)
	}
	var registration types.APIRegistration
	if err := json.Unmarshal(payload, &registration); err != nil {
		return nil, fmt.Errorf("unmarshal api registration: %w", err)
	}
	return &registration, nil
}

func (s *Store) SaveAPIKey(ctx context.Context, record types.APIKeyRecord) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal api key record: %w", err)
	}
	// Key metadata expires with the JWT so Redis naturally sheds stale records.
	ttl := time.Until(time.Unix(record.ExpiresAt, 0))
	if ttl <= 0 {
		ttl = time.Second
	}
	return s.client.Set(ctx, APIKeyKey(record.APIKeyID), payload, ttl).Err()
}

func (s *Store) GetAPIKey(ctx context.Context, apiKeyID string) (*types.APIKeyRecord, error) {
	payload, err := s.client.Get(ctx, APIKeyKey(apiKeyID)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("api key %q not found", apiKeyID)
		}
		return nil, fmt.Errorf("get api key: %w", err)
	}
	var record types.APIKeyRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, fmt.Errorf("unmarshal api key: %w", err)
	}
	return &record, nil
}

func (s *Store) IsRevoked(ctx context.Context, jti string) (bool, error) {
	count, err := s.client.Exists(ctx, RevokedTokenKey(jti)).Result()
	if err != nil {
		return false, fmt.Errorf("check revoked token: %w", err)
	}
	return count == 1, nil
}

func (s *Store) RevokeAPIKey(ctx context.Context, record *types.APIKeyRecord) error {
	ttl := time.Until(time.Unix(record.ExpiresAt, 0))
	if ttl <= 0 {
		ttl = time.Second
	}

	record.Revoked = true
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal revoked api key: %w", err)
	}

	// Update both the key record and the revoked-token index in a single Redis
	// pipeline so verification sees a consistent revocation state.
	pipe := s.client.TxPipeline()
	pipe.Set(ctx, RevokedTokenKey(record.JWTID), "1", ttl)
	pipe.Set(ctx, APIKeyKey(record.APIKeyID), payload, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	return nil
}
