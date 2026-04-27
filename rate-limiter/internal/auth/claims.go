package auth

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
