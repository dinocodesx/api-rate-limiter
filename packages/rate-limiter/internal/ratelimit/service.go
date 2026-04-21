package ratelimit

import (
	"context"
	"fmt"
	"time"

	redisstore "github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/store/redis"
	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/types"
)

type Decision struct {
	Registration *types.APIRegistration
	Policy       *types.RoutePolicy
	Bucket       types.BucketState
}

type Service struct {
	policies *redisstore.PolicyStore
	buckets  *redisstore.BucketStore
	now      func() time.Time
}

func NewService(policies *redisstore.PolicyStore, buckets *redisstore.BucketStore) *Service {
	return &Service{policies: policies, buckets: buckets, now: time.Now}
}

func (s *Service) Evaluate(ctx context.Context, apiID string, apiKeyID string, method string, requestPath string) (*Decision, error) {
	registration, err := s.policies.GetAPI(ctx, apiID)
	if err != nil {
		return nil, err
	}
	if !registration.Active {
		return nil, fmt.Errorf("api is inactive")
	}

	policy, err := redisstore.MatchPolicy(registration, method, requestPath)
	if err != nil {
		return nil, err
	}

	now := s.now().UTC()
	// Buckets are isolated per API key and normalized route so different keys or
	// endpoints do not consume each other's quota.
	bucket, err := s.buckets.Consume(ctx, BucketKey(apiKeyID, method, policy.PathPattern), policy.Capacity, policy.RefillPerSec, time.Duration(policy.BucketTTLSec)*time.Second, now)
	if err != nil {
		return nil, err
	}

	return &Decision{Registration: registration, Policy: policy, Bucket: bucket}, nil
}
