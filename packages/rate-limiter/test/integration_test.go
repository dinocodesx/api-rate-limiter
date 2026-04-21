package test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	redis "github.com/redis/go-redis/v9"
	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/auth"
	httpapi "github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/http"
	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/proxy"
	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/ratelimit"
	redisstore "github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/store/redis"
	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/types"
)

func TestRateLimiterAllowsThenBlocks(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	policyStore := redisstore.NewPolicyStore(client)
	bucketStore := redisstore.NewBucketStore(client)
	revocationStore := redisstore.NewRevocationStore(client)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	registration := types.APIRegistration{
		APIID:       "payments-prod",
		OwnerID:     "user_123",
		UpstreamURL: upstream.URL,
		Active:      true,
		RoutePolicies: []types.RoutePolicy{{
			Method:       "GET",
			PathPattern:  "/v1/charges",
			Capacity:     1,
			RefillPerSec: 0.1,
			BucketTTLSec: 120,
		}},
	}
	payload, _ := json.Marshal(registration)
	if err := client.Set(context.Background(), "api:config:payments-prod", payload, 0).Err(); err != nil {
		t.Fatalf("seed api config: %v", err)
	}

	verifier := auth.NewVerifier("secret", "api-key-service", revocationStore)
	limiter := ratelimit.NewService(policyStore, bucketStore)
	handler := httpapi.NewHandler(verifier, limiter, proxy.New())
	server := httptest.NewServer(httpapi.NewRouter(handler))
	defer server.Close()

	token := signToken(t, auth.APIKeyClaims{
		Issuer:    "api-key-service",
		Subject:   "key_123",
		APIID:     "payments-prod",
		OwnerID:   "user_123",
		IssuedAt:  time.Now().UTC().Unix(),
		ExpiresAt: time.Now().UTC().Add(time.Hour).Unix(),
		JWTID:     "jti_123",
	})

	resp := sendRequest(t, server.URL+"/v1/charges", token, "payments-prod")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = sendRequest(t, server.URL+"/v1/charges", token, "payments-prod")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected second request 429, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestRateLimiterRejectsRevokedToken(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	verifier := auth.NewVerifier("secret", "api-key-service", redisstore.NewRevocationStore(client))
	limiter := ratelimit.NewService(redisstore.NewPolicyStore(client), redisstore.NewBucketStore(client))
	handler := httpapi.NewHandler(verifier, limiter, proxy.New())
	server := httptest.NewServer(httpapi.NewRouter(handler))
	defer server.Close()

	if err := client.Set(context.Background(), "revoked:jti:jti_123", "1", time.Hour).Err(); err != nil {
		t.Fatalf("seed revoked token: %v", err)
	}
	token := signToken(t, auth.APIKeyClaims{
		Issuer:    "api-key-service",
		Subject:   "key_123",
		APIID:     "payments-prod",
		OwnerID:   "user_123",
		IssuedAt:  time.Now().UTC().Unix(),
		ExpiresAt: time.Now().UTC().Add(time.Hour).Unix(),
		JWTID:     "jti_123",
	})

	resp := sendRequest(t, server.URL+"/v1/charges", token, "payments-prod")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected revoked token 401, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func sendRequest(t *testing.T, url string, token string, apiID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-API-ID", apiID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func signToken(t *testing.T, claims auth.APIKeyClaims) string {
	t.Helper()
	headerBytes, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	claimsBytes, _ := json.Marshal(claims)
	head := base64.RawURLEncoding.EncodeToString(headerBytes)
	body := base64.RawURLEncoding.EncodeToString(claimsBytes)
	input := head + "." + body
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write([]byte(input))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s.%s", input, sig)
}
