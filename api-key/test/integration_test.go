package test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	redis "github.com/redis/go-redis/v9"
	httpapi "github.com/rishi/api-rate-limiter/packages/api-key/internal/http"
	jwtlib "github.com/rishi/api-rate-limiter/packages/api-key/internal/jwt"
	redisstore "github.com/rishi/api-rate-limiter/packages/api-key/internal/store/redis"
)

func TestAPIKeyLifecycle(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := redisstore.NewStore(client)
	handlers := httpapi.NewHandlers(store, jwtlib.NewSigner("secret", "issuer"), jwtlib.NewVerifier("secret"), func(ctx context.Context) error {
		return client.Ping(ctx).Err()
	})
	server := httptest.NewServer(httpapi.NewRouter(handlers))
	defer server.Close()

	resp := doNoBody(t, server.Client(), http.MethodGet, server.URL+"/livez")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected livez 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = doNoBody(t, server.Client(), http.MethodGet, server.URL+"/readyz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected readyz 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	createBody := map[string]any{
		"api_id":       "payments-prod",
		"owner_id":     "user_123",
		"upstream_url": "https://example.com",
		"route_policies": []map[string]any{{
			"method":         "GET",
			"path_pattern":   "/v1/charges",
			"capacity":       100,
			"refill_per_sec": 10,
			"bucket_ttl_sec": 120,
		}},
	}
	resp = doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/apis", createBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected create api 201, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	issueBody := map[string]any{
		"api_id":           "payments-prod",
		"owner_id":         "user_123",
		"expires_in_hours": 24,
		"scopes":           []string{"proxy:access"},
	}
	resp = doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/api-keys", issueBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected issue api key 201, got %d", resp.StatusCode)
	}
	var issueResp map[string]any
	decodeResponse(t, resp, &issueResp)
	token := issueResp["token"].(string)
	apiKeyID := issueResp["api_key_id"].(string)

	resp = doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/api-keys/validate", map[string]any{"token": token})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected validate 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/api-keys/revoke", map[string]any{"api_key_id": apiKeyID})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected revoke 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/api-keys/validate", map[string]any{"token": token})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected validate revoked token 401, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func doJSON(t *testing.T, client *http.Client, method, url string, payload any) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return response
}

func doNoBody(t *testing.T, client *http.Client, method, url string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return response
}

func decodeResponse(t *testing.T, resp *http.Response, out any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}
