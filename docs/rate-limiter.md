# Rate Limiter Service

`packages/rate-limiter` is the data-plane service for the platform. It receives client traffic, validates JWT API keys, loads the active API policy from Redis, applies token bucket enforcement, and reverse proxies allowed requests to the customer's upstream API.

## Responsibilities

- Parse `Authorization: Bearer <token>` and `X-API-ID`.
- Verify HS256 JWT signature and required claims.
- Reject revoked tokens by checking Redis.
- Load active API registration and route policy from Redis.
- Enforce token bucket rate limits per API key and route.
- Return `429 Too Many Requests` when a bucket is empty.
- Forward allowed traffic to the configured upstream URL.

## Runtime Layout

```text
packages/rate-limiter/
  cmd/server/main.go
  internal/auth
  internal/config
  internal/http
  internal/proxy
  internal/ratelimit
  internal/store/redis
  internal/types
  test
```

## Startup Flow

1. Load `PORT`, `REDIS_ADDR`, `JWT_SECRET`, and `EXPECTED_ISSUER`.
2. Connect to Redis and fail fast if unavailable.
3. Build:
   - policy store
   - bucket store
   - revocation store
   - JWT verifier
   - rate-limit service
   - reverse proxy
4. Start the HTTP server.

Key entrypoint:

- `packages/rate-limiter/cmd/server/main.go`

## Incoming Request Contract

Clients must send:

```http
Authorization: Bearer <jwt-token>
X-API-ID: payments-prod
```

Example:

```http
GET /v1/charges?limit=10
Host: limiter.local
Authorization: Bearer <jwt-token>
X-API-ID: payments-prod
X-Request-ID: req_abc123
```

## Request Pipeline

### 1. Header Parsing

`internal/auth/header_parser.go` ensures:

- `Authorization` exists
- the auth scheme is `Bearer`
- `X-API-ID` exists

If any are missing or malformed, the service returns `401`.

### 2. JWT Verification

`internal/auth/verifier.go` performs:

- JWT segment parsing
- HS256 signature verification
- claim presence checks
- issuer check against `EXPECTED_ISSUER`
- expiry check
- `api_id` claim vs `X-API-ID` header comparison
- revocation lookup in Redis via `revoked:jti:{jti}`

Responses:

- invalid signature or expired token -> `401`
- revoked token -> `401`
- mismatched `api_id` header vs token claim -> `403`

### 3. Policy Lookup

`internal/store/redis/policy_store.go` loads the API registration from:

- `api:config:{api_id}`

The service then matches the route policy by:

- HTTP method
- normalized request path

In v1, route matching is exact after normalization. Example:

- `/v1/charges` matches `/v1/charges`
- `/v1/charges/` normalizes to `/v1/charges`
- `/v1/charges/123` does not match `/v1/charges`

If there is no matching policy, the service returns `403`.

### 4. Bucket Selection

Bucket keys are built as:

```text
bucket:{api_key_id}:{method}:{normalized_route}
```

Example:

```text
bucket:key_01HXYZ:GET:/v1/charges
```

This isolates quota by:

- API key
- HTTP method
- route

That means:

- `GET /v1/charges` and `POST /v1/charges` use different buckets.
- Two different API keys do not share quota.

### 5. Atomic Token Bucket Enforcement

`internal/store/redis/bucket_store.go` uses a Lua script to make refill and consume a single atomic Redis operation.

The script:

1. Reads current `tokens` and `last_refill_ms`.
2. Creates a full bucket if one does not yet exist.
3. Refills tokens according to elapsed time and `refill_per_sec`.
4. Consumes one token if available.
5. Writes the updated state back to Redis.
6. Refreshes the bucket TTL.

This avoids race conditions when many requests hit the same bucket concurrently.

## Token Bucket Model

Each route policy defines:

- `capacity`: maximum number of tokens the bucket can hold
- `refill_per_sec`: token refill rate
- `bucket_ttl_sec`: how long idle bucket state should live in Redis

Example policy:

```json
{
  "method": "GET",
  "path_pattern": "/v1/charges",
  "capacity": 100,
  "refill_per_sec": 10,
  "bucket_ttl_sec": 120
}
```

Interpretation:

- The bucket can hold up to 100 requests.
- It refills at 10 requests per second.
- Idle bucket state expires after 120 seconds.

## Response Behavior

### Allowed Request

When a request is allowed:

- rate-limit headers are written
- the request is forwarded to the upstream service
- the upstream response body/status are passed back to the client

Example:

```http
200 OK
Content-Type: application/json
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 99
X-RateLimit-Reset: 1713691210

{ ...upstream response body... }
```

### Rate-Limited Request

When no token is available:

- the service returns `429`
- it does not contact the upstream service
- it includes `Retry-After` and standard limit headers

Example:

```http
429 Too Many Requests
Content-Type: application/json
Retry-After: 1
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1713691210

{
  "error": "rate_limit_exceeded",
  "message": "Rate limit exceeded for api_id payments-prod on GET /v1/charges"
}
```

### Unauthorized Request

Example:

```http
401 Unauthorized
Content-Type: application/json

{
  "error": "invalid_api_key",
  "message": "JWT verification failed"
}
```

### API Header Mismatch

Example:

```http
403 Forbidden
Content-Type: application/json

{
  "error": "api_id_mismatch",
  "message": "api_id mismatch"
}
```

## Health Check APIs

The service exposes three health endpoints:

- `GET /livez`: confirms the process is running
- `GET /readyz`: checks Redis availability for policy and bucket operations
- `GET /healthz`: combined dependency health response

Example `GET /livez` response:

```json
{
  "service": "rate-limiter",
  "status": "ok"
}
```

Example `GET /readyz` response:

```json
{
  "service": "rate-limiter",
  "status": "ok",
  "checks": {
    "redis": {
      "status": "ok"
    }
  }
}
```

If Redis is unavailable, `readyz` and `healthz` return `503 Service Unavailable` and include the Redis error in the payload.

## Proxying Rules

`internal/proxy/reverse_proxy.go` forwards allowed requests to the upstream URL from Redis.

Important proxy behavior:

- preserves method, body, query string, and most headers
- rewrites host/path toward the configured upstream
- removes internal headers before forwarding:
  - `Authorization`
  - `X-API-ID`

This prevents limiter-only authentication data from leaking to the customer upstream.

## Redis Keys

The limiter reads:

- `api:config:{api_id}`
- `revoked:jti:{jti}`

The limiter reads/writes:

- `bucket:{api_key_id}:{method}:{route}`

## Failure Modes

- Missing or malformed auth headers -> `401`
- Invalid JWT signature or expired token -> `401`
- Revoked token -> `401`
- `X-API-ID` mismatch -> `403`
- Unknown or inactive API -> `403`
- Route not configured -> `403`
- Upstream connection failure -> `502`

## Docker and Local Development

In local development, `docker-compose.yml` runs:

- `redis`
- `api-key`
- `rate-limiter`

The limiter expects Redis at `redis:6379` inside the compose network.

## Operational Notes

- Because route policy is loaded on every request from Redis, policy updates apply without rotating tokens.
- Exact route matching keeps v1 simple and predictable, but wildcard and parameterized matching can be added later.
- The Redis Lua script is the core concurrency control point for shared buckets.
