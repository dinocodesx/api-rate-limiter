package types

type APIKeyClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	APIID     string   `json:"api_id"`
	OwnerID   string   `json:"owner_id"`
	Scopes    []string `json:"scopes"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	JWTID     string   `json:"jti"`
}

type APIKeyRecord struct {
	APIKeyID  string   `json:"api_key_id"`
	APIID     string   `json:"api_id"`
	OwnerID   string   `json:"owner_id"`
	Scopes    []string `json:"scopes"`
	JWTID     string   `json:"jti"`
	IssuedAt  int64    `json:"issued_at"`
	ExpiresAt int64    `json:"expires_at"`
	Revoked   bool     `json:"revoked"`
}
