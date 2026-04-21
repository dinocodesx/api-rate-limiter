package redisstore

import (
	"context"
	"fmt"
	"math"
	"time"

	redis "github.com/redis/go-redis/v9"
	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/types"
)

var bucketScript = redis.NewScript(`
local capacity = tonumber(ARGV[1])
local refill_per_sec = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local ttl_ms = tonumber(ARGV[4])

local tokens = tonumber(redis.call('HGET', KEYS[1], 'tokens'))
local last_refill_ms = tonumber(redis.call('HGET', KEYS[1], 'last_refill_ms'))

if tokens == nil then
  tokens = capacity
  last_refill_ms = now_ms
end

local elapsed_ms = now_ms - last_refill_ms
if elapsed_ms < 0 then
  elapsed_ms = 0
end

tokens = math.min(capacity, tokens + (elapsed_ms / 1000.0) * refill_per_sec)
local allowed = 0
if tokens >= 1 then
  allowed = 1
  tokens = tokens - 1
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'last_refill_ms', now_ms)
redis.call('PEXPIRE', KEYS[1], ttl_ms)
return {allowed, tokens, now_ms}
`)

type BucketStore struct {
	client *redis.Client
}

func NewBucketStore(client *redis.Client) *BucketStore {
	return &BucketStore{client: client}
}

func (s *BucketStore) Consume(ctx context.Context, bucketKey string, capacity int64, refillPerSec float64, ttl time.Duration, now time.Time) (types.BucketState, error) {
	// The Lua script keeps refill + consume atomic so concurrent requests
	// cannot overspend a shared bucket.
	result, err := bucketScript.Run(ctx, s.client, []string{bucketKey}, capacity, refillPerSec, now.UnixMilli(), ttl.Milliseconds()).Result()
	if err != nil {
		return types.BucketState{}, fmt.Errorf("run bucket script: %w", err)
	}
	values, ok := result.([]any)
	if !ok || len(values) != 3 {
		return types.BucketState{}, fmt.Errorf("unexpected bucket script response")
	}

	allowed := toInt64(values[0]) == 1
	tokens := toFloat64(values[1])
	remaining := int64(math.Floor(tokens))
	state := types.BucketState{
		Allowed:      allowed,
		Tokens:       tokens,
		LastRefillMS: toInt64(values[2]),
		Remaining:    remaining,
	}
	// Reset timing is computed in Go so the HTTP layer can expose consistent
	// headers without duplicating math elsewhere.
	if tokens >= 1 || refillPerSec <= 0 {
		state.ResetAfterMS = 0
		state.ResetAtUnixSec = now.Unix()
		return state, nil
	}
	missing := 1 - tokens
	state.ResetAfterMS = int64(math.Ceil((missing / refillPerSec) * 1000))
	state.ResetAtUnixSec = now.Add(time.Duration(state.ResetAfterMS) * time.Millisecond).Unix()
	return state, nil
}

func toInt64(value any) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	case string:
		var out int64
		fmt.Sscan(v, &out)
		return out
	default:
		return 0
	}
}

func toFloat64(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case int64:
		return float64(v)
	case string:
		var out float64
		fmt.Sscan(v, &out)
		return out
	default:
		return 0
	}
}
