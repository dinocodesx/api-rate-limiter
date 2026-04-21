# API Key Service

`packages/api-key` is the admin-facing control-plane service for the platform. It stores API registrations in Redis, issues JWT-based API keys, validates issued tokens, and revokes keys by JTI.

## Responsibilities

- Register or update a customer's upstream API configuration.
- Persist route-level rate-limit policy for each API.
- Issue HS256 JWT API keys for that API.
- Validate tokens for operational/debugging use.
- Revoke keys before natural expiry.

## Runtime Layout

```text
packages/api-key/
  cmd/server/main.go
  internal/config
  internal/http
  internal/jwt
  internal/store/redis
  internal/types
  test
```

## Startup Flow

1. Load `PORT`, `REDIS_ADDR`, `JWT_SECRET`, and `TOKEN_ISSUER`.
2. Connect to Redis and fail fast if it is unavailable.
3. Build the Redis store, JWT signer, and JWT verifier.
4. Register HTTP routes and start the server.

Key entrypoint:

- `packages/api-key/cmd/server/main.go`

## Data Model

### API Registration

Stored at `api:config:{api_id}` as JSON.

```json
{
  "api_id": "payments-prod",
  "owner_id": "user_123",
  "upstream_url": "https://customer-payments.internal",
  "active": true,
  "route_policies": [
    {
      "method": "GET",
      "path_pattern": "/v1/charges",
      "capacity": 100,
      "refill_per_sec": 10,
      "bucket_ttl_sec": 120
    }
  ]
}
```

### API Key Record

Stored at `api:key:{api_key_id}` as JSON with a TTL equal to the JWT expiry.

```json
{
  "api_key_id": "key_a1b2c3",
  "api_id": "payments-prod",
  "owner_id": "user_123",
  "scopes": ["proxy:access"],
  "jti": "jti_d4e5f6",
  "issued_at": 1713690000,
  "expires_at": 1716282000,
  "revoked": false
}
```

### Revocation Marker

Stored at `revoked:jti:{jti}` with TTL until the original token expiry.

The rate limiter checks this key on every request, so revocation propagates immediately without waiting for token expiry.

## JWT Model

The service signs compact HS256 JWTs with these claims:

- `iss`: issuer, usually `api-key-service`
- `sub`: API key ID
- `api_id`: registered API identifier
- `owner_id`: customer/user identifier
- `scopes`: optional capabilities such as `proxy:access`
- `iat`: issued-at timestamp
- `exp`: expiry timestamp
- `jti`: unique token identifier used for revocation

Important design choice:

- JWTs carry identity and authorization context.
- Rate-limit policy is not embedded in the JWT.
- Current policy stays in Redis so config changes apply immediately.

## HTTP Endpoints

### `POST /v1/apis`

Creates or updates an API registration.

Request:

```http
POST /v1/apis
Content-Type: application/json

{
  "api_id": "payments-prod",
  "owner_id": "user_123",
  "upstream_url": "https://customer-payments.internal",
  "route_policies": [
    {
      "method": "GET",
      "path_pattern": "/v1/charges",
      "capacity": 100,
      "refill_per_sec": 10,
      "bucket_ttl_sec": 120
    },
    {
      "method": "POST",
      "path_pattern": "/v1/charges",
      "capacity": 20,
      "refill_per_sec": 2,
      "bucket_ttl_sec": 120
    }
  ]
}
```

Behavior:

- Validates required fields.
- Normalizes methods to uppercase.
- Normalizes paths to start with `/`.
- Stores the full registration in Redis.

Response:

```json
{
  "api_id": "payments-prod",
  "status": "registered"
}
```

### `GET /v1/apis/{api_id}`

Fetches a stored API registration.

### `POST /v1/api-keys`

Issues a JWT-backed API key.

Request:

```http
POST /v1/api-keys
Content-Type: application/json

{
  "api_id": "payments-prod",
  "owner_id": "user_123",
  "expires_in_hours": 720,
  "scopes": ["proxy:access"]
}
```

Behavior:

- Verifies the target API exists and is active.
- Generates `api_key_id` and `jti`.
- Signs the JWT.
- Stores key metadata in Redis with matching TTL.

Response:

```json
{
  "api_key_id": "key_01HXYZ",
  "api_id": "payments-prod",
  "token_type": "Bearer",
  "token": "<jwt-token>"
}
```

### `POST /v1/api-keys/validate`

Validates JWT integrity and checks revocation state.

Request:

```json
{
  "token": "<jwt-token>"
}
```

Success response:

```json
{
  "valid": true,
  "claims": {
    "iss": "api-key-service",
    "sub": "key_01HXYZ",
    "api_id": "payments-prod",
    "owner_id": "user_123",
    "scopes": ["proxy:access"],
    "iat": 1713690000,
    "exp": 1716282000,
    "jti": "jti_abc123"
  }
}
```

### `POST /v1/api-keys/revoke`

Marks an API key as revoked by key ID.

Request:

```json
{
  "api_key_id": "key_01HXYZ"
}
```

Behavior:

- Loads the stored key metadata.
- Marks the record as revoked.
- Writes `revoked:jti:{jti}` so verifiers can reject the token immediately.

## Request Lifecycle

### Registering an API

1. Admin sends `POST /v1/apis`.
2. Service validates payload and route policies.
3. Service writes `api:config:{api_id}`.
4. Future rate-limiter requests read this configuration from Redis.

### Issuing a Key

1. Admin sends `POST /v1/api-keys`.
2. Service confirms the API exists and is active.
3. Service creates JWT claims and signs them with HS256.
4. Service stores `api:key:{api_key_id}` with TTL.
5. Caller receives the bearer token.

### Revoking a Key

1. Admin sends `POST /v1/api-keys/revoke`.
2. Service looks up the stored key record.
3. Service sets the record to revoked.
4. Service writes `revoked:jti:{jti}` with TTL to token expiry.
5. The rate limiter begins rejecting the token immediately.

## Health Check APIs

The service exposes three health endpoints:

- `GET /livez`: process liveness only
- `GET /readyz`: readiness check including Redis connectivity
- `GET /healthz`: combined dependency health response

Example `GET /livez` response:

```json
{
  "service": "api-key",
  "status": "ok"
}
```

Example `GET /readyz` response:

```json
{
  "service": "api-key",
  "status": "ok",
  "checks": {
    "redis": {
      "status": "ok"
    }
  }
}
```

If Redis is unavailable, `readyz` and `healthz` return `503 Service Unavailable` and include the Redis error in the response body.

## Redis Keys

- `api:config:{api_id}`
- `api:key:{api_key_id}`
- `revoked:jti:{jti}`

## Failure Modes

- Missing `JWT_SECRET` or Redis connectivity prevents startup.
- Invalid `upstream_url`, missing route policies, or invalid limits return `400`.
- Unknown API returns `404` during key issuance or fetch.
- Inactive API returns `403` during key issuance.
- Invalid, expired, or revoked token returns `401` during validation.

## Operational Notes

- This service currently has no admin authentication layer, so it should sit behind trusted network boundaries in development and be secured before production.
- Redis is both config storage and the source of truth for revocation.
- Because policy stays in Redis, you can change route limits without reissuing JWTs.
