package ratelimit

import (
	"math"
	"time"

	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/types"
)

func RefillAndConsume(tokens float64, lastRefill time.Time, now time.Time, capacity int64, refillPerSec float64) types.BucketState {
	elapsed := now.Sub(lastRefill).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	tokens = math.Min(float64(capacity), tokens+(elapsed*refillPerSec))
	state := types.BucketState{Tokens: tokens, LastRefillMS: now.UnixMilli()}
	if tokens >= 1 {
		state.Allowed = true
		state.Tokens = tokens - 1
	}
	state.Remaining = int64(math.Floor(state.Tokens))
	if state.Tokens >= 1 || refillPerSec <= 0 {
		state.ResetAfterMS = 0
		state.ResetAtUnixSec = now.Unix()
		return state
	}
	missing := 1 - state.Tokens
	state.ResetAfterMS = int64(math.Ceil((missing / refillPerSec) * 1000))
	state.ResetAtUnixSec = now.Add(time.Duration(state.ResetAfterMS) * time.Millisecond).Unix()
	return state
}
