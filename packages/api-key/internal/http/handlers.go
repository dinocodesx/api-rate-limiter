package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwtlib "github.com/rishi/api-rate-limiter/packages/api-key/internal/jwt"
	redisstore "github.com/rishi/api-rate-limiter/packages/api-key/internal/store/redis"
	"github.com/rishi/api-rate-limiter/packages/api-key/internal/types"
)

type Handlers struct {
	store    *redisstore.Store
	signer   *jwtlib.Signer
	verifier *jwtlib.Verifier
	health   func(context.Context) error
}

func NewHandlers(store *redisstore.Store, signer *jwtlib.Signer, verifier *jwtlib.Verifier, health func(context.Context) error) *Handlers {
	return &Handlers{store: store, signer: signer, verifier: verifier, health: health}
}

type createAPIRequest struct {
	APIID         string              `json:"api_id"`
	OwnerID       string              `json:"owner_id"`
	UpstreamURL   string              `json:"upstream_url"`
	RoutePolicies []types.RoutePolicy `json:"route_policies"`
	Active        *bool               `json:"active,omitempty"`
}

type issueAPIKeyRequest struct {
	APIID          string   `json:"api_id"`
	OwnerID        string   `json:"owner_id"`
	ExpiresInHours int64    `json:"expires_in_hours"`
	Scopes         []string `json:"scopes"`
}

type tokenRequest struct {
	Token string `json:"token"`
}

type revokeRequest struct {
	APIKeyID string `json:"api_key_id"`
}

func (h *Handlers) Live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"service": "api-key",
		"status":  "ok",
	})
}

func (h *Handlers) Ready(w http.ResponseWriter, r *http.Request) {
	h.writeDependencyHealth(w, r)
}

func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	h.writeDependencyHealth(w, r)
}

func (h *Handlers) CreateAPI(w http.ResponseWriter, r *http.Request) {
	var req createAPIRequest
	if err := decodeJSON(r.Context(), r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := validateCreateAPIRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}

	// Route policies are normalized once on write so the limiter can perform
	// cheap exact matches when requests arrive.
	registration := types.APIRegistration{
		APIID:         req.APIID,
		OwnerID:       req.OwnerID,
		UpstreamURL:   req.UpstreamURL,
		Active:        active,
		RoutePolicies: normalizePolicies(req.RoutePolicies),
	}
	if err := h.store.UpsertAPI(r.Context(), registration); err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"api_id": registration.APIID,
		"status": "registered",
	})
}

func (h *Handlers) GetAPI(w http.ResponseWriter, r *http.Request) {
	apiID := strings.TrimPrefix(r.URL.Path, "/v1/apis/")
	if apiID == "" || apiID == "/v1/apis" {
		writeError(w, http.StatusBadRequest, "invalid_api_id", "api_id is required")
		return
	}
	registration, err := h.store.GetAPI(r.Context(), apiID)
	if err != nil {
		writeError(w, http.StatusNotFound, "api_not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, registration)
}

func (h *Handlers) IssueAPIKey(w http.ResponseWriter, r *http.Request) {
	var req issueAPIKeyRequest
	if err := decodeJSON(r.Context(), r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.APIID == "" || req.OwnerID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "api_id and owner_id are required")
		return
	}
	if req.ExpiresInHours <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "expires_in_hours must be greater than 0")
		return
	}

	registration, err := h.store.GetAPI(r.Context(), req.APIID)
	if err != nil {
		writeError(w, http.StatusNotFound, "api_not_found", err.Error())
		return
	}
	if !registration.Active {
		writeError(w, http.StatusForbidden, "api_inactive", "api is inactive")
		return
	}

	now := time.Now().UTC()
	apiKeyID := randomID("key")
	jti := randomID("jti")
	// JWT claims intentionally carry identity and scope only; live rate-limit
	// policy stays in Redis so config changes take effect immediately.
	claims := types.APIKeyClaims{
		Subject:   apiKeyID,
		APIID:     req.APIID,
		OwnerID:   req.OwnerID,
		Scopes:    req.Scopes,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Duration(req.ExpiresInHours) * time.Hour).Unix(),
		JWTID:     jti,
	}
	token, err := h.signer.Sign(claims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_sign_error", err.Error())
		return
	}

	record := types.APIKeyRecord{
		APIKeyID:  apiKeyID,
		APIID:     req.APIID,
		OwnerID:   req.OwnerID,
		Scopes:    req.Scopes,
		JWTID:     jti,
		IssuedAt:  claims.IssuedAt,
		ExpiresAt: claims.ExpiresAt,
		Revoked:   false,
	}
	if err := h.store.SaveAPIKey(r.Context(), record); err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"api_key_id": apiKeyID,
		"api_id":     req.APIID,
		"token_type": "Bearer",
		"token":      token,
	})
}

func (h *Handlers) ValidateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if err := decodeJSON(r.Context(), r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Validation checks both JWT integrity and revocation state so callers can
	// use this endpoint as an operational health check for issued keys.
	claims, err := h.verifier.Verify(req.Token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_api_key", err.Error())
		return
	}
	revoked, err := h.store.IsRevoked(r.Context(), claims.JWTID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	if revoked {
		writeError(w, http.StatusUnauthorized, "revoked_api_key", "api key has been revoked")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid":  true,
		"claims": claims,
	})
}

func (h *Handlers) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := decodeJSON(r.Context(), r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.APIKeyID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "api_key_id is required")
		return
	}

	record, err := h.store.GetAPIKey(r.Context(), req.APIKeyID)
	if err != nil {
		writeError(w, http.StatusNotFound, "api_key_not_found", err.Error())
		return
	}
	if err := h.store.RevokeAPIKey(r.Context(), record); err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}

	// Revocation is soft in Redis: we preserve metadata for inspection while
	// also writing a dedicated revoked JTI marker that expires with the token.
	writeJSON(w, http.StatusOK, map[string]string{
		"api_key_id": req.APIKeyID,
		"status":     "revoked",
	})
}

func decodeJSON(_ context.Context, r *http.Request, out any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode json body: %w", err)
	}
	return nil
}

func validateCreateAPIRequest(req createAPIRequest) error {
	if req.APIID == "" || req.OwnerID == "" || req.UpstreamURL == "" {
		return fmt.Errorf("api_id, owner_id, and upstream_url are required")
	}
	if _, err := url.ParseRequestURI(req.UpstreamURL); err != nil {
		return fmt.Errorf("invalid upstream_url: %w", err)
	}
	if len(req.RoutePolicies) == 0 {
		return fmt.Errorf("at least one route policy is required")
	}
	for _, policy := range req.RoutePolicies {
		if policy.Method == "" || policy.PathPattern == "" {
			return fmt.Errorf("each route policy must include method and path_pattern")
		}
		if policy.Capacity <= 0 || policy.RefillPerSec <= 0 || policy.BucketTTLSec <= 0 {
			return fmt.Errorf("route policy values must be greater than 0")
		}
	}
	return nil
}

func normalizePolicies(policies []types.RoutePolicy) []types.RoutePolicy {
	out := make([]types.RoutePolicy, 0, len(policies))
	for _, policy := range policies {
		policy.Method = strings.ToUpper(strings.TrimSpace(policy.Method))
		if !strings.HasPrefix(policy.PathPattern, "/") {
			policy.PathPattern = "/" + policy.PathPattern
		}
		out = append(out, policy)
	}
	return out
}

func randomID(prefix string) string {
	buffer := make([]byte, 8)
	_, _ = rand.Read(buffer)
	return prefix + "_" + hex.EncodeToString(buffer)
}

func (h *Handlers) writeDependencyHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	statusCode := http.StatusOK
	status := "ok"
	redisStatus := map[string]string{"status": "ok"}

	if err := h.health(ctx); err != nil {
		statusCode = http.StatusServiceUnavailable
		status = "degraded"
		redisStatus = map[string]string{
			"status": "error",
			"error":  err.Error(),
		}
	}

	writeJSON(w, statusCode, map[string]any{
		"service": "api-key",
		"status":  status,
		"checks": map[string]any{
			"redis": redisStatus,
		},
	})
}
