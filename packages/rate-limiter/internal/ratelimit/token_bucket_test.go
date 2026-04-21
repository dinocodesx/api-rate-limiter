package ratelimit

import (
	"testing"
	"time"
)

func TestRefillAndConsume(t *testing.T) {
	start := time.Unix(100, 0)
	state := RefillAndConsume(0, start, start.Add(1500*time.Millisecond), 5, 1)
	if !state.Allowed {
		t.Fatal("expected request to be allowed after refill")
	}
	if state.Remaining != 0 {
		t.Fatalf("expected remaining to be 0, got %d", state.Remaining)
	}
}

func TestRefillAndConsumeBlocked(t *testing.T) {
	start := time.Unix(100, 0)
	state := RefillAndConsume(0.2, start, start, 5, 1)
	if state.Allowed {
		t.Fatal("expected request to be blocked")
	}
	if state.ResetAfterMS <= 0 {
		t.Fatal("expected reset_after_ms to be positive")
	}
}
