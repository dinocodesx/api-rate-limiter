package httpapi

import (
	"net/http"

	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/auth"
	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/proxy"
	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/ratelimit"
)

type Handler struct {
	verifier *auth.Verifier
	limiter  *ratelimit.Service
	proxy    *proxy.ReverseProxy
}

func NewHandler(verifier *auth.Verifier, limiter *ratelimit.Service, reverseProxy *proxy.ReverseProxy) *Handler {
	return &Handler{verifier: verifier, limiter: limiter, proxy: reverseProxy}
}

func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, apiID, err := auth.ParseHeaders(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_api_key", err.Error())
		return
	}

	claims, err := h.verifier.VerifyRequest(r.Context(), token, apiID)
	if err != nil {
		status := http.StatusUnauthorized
		code := "invalid_api_key"
		if err.Error() == "api_id mismatch" {
			status = http.StatusForbidden
			code = "api_id_mismatch"
		}
		writeError(w, status, code, err.Error())
		return
	}

	// Policy resolution stays server-side; the request only carries identity.
	decision, err := h.limiter.Evaluate(r.Context(), apiID, claims.Subject, r.Method, r.URL.Path)
	if err != nil {
		writeError(w, http.StatusForbidden, "route_not_allowed", err.Error())
		return
	}

	// Rate-limit headers are written for both allowed and blocked responses so
	// clients can adapt without inspecting JSON error payloads.
	writeRateLimitHeaders(w, decision.Policy.Capacity, decision.Bucket)
	if !decision.Bucket.Allowed {
		writeError(w, http.StatusTooManyRequests, "rate_limit_exceeded", "Rate limit exceeded for api_id "+apiID+" on "+r.Method+" "+r.URL.Path)
		return
	}

	if err := h.proxy.ServeHTTP(w, r, decision.Registration.UpstreamURL); err != nil {
		writeError(w, http.StatusBadGateway, "upstream_error", err.Error())
		return
	}
}
