package httpapi

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/types"
)

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write json response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: code, Message: message})
}

func writeRateLimitHeaders(w http.ResponseWriter, limit int64, bucket types.BucketState) {
	w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(limit, 10))
	w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(bucket.Remaining, 10))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(bucket.ResetAtUnixSec, 10))
	if !bucket.Allowed {
		retryAfter := bucket.ResetAfterMS / 1000
		if bucket.ResetAfterMS%1000 != 0 {
			retryAfter++
		}
		if retryAfter < 1 {
			retryAfter = 1
		}
		w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
	}
}
