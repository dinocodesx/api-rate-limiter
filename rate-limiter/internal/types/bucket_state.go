package types

type BucketState struct {
	Tokens         float64 `json:"tokens"`
	LastRefillMS   int64   `json:"last_refill_ms"`
	Allowed        bool    `json:"allowed"`
	Remaining      int64   `json:"remaining"`
	ResetAfterMS   int64   `json:"reset_after_ms"`
	ResetAtUnixSec int64   `json:"reset_at_unix_sec"`
}
