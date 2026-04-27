package httpapi

import "net/http"

func NewRouter(handlers *Handlers) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", handlers.Live)
	mux.HandleFunc("GET /readyz", handlers.Ready)
	mux.HandleFunc("GET /healthz", handlers.Health)
	mux.HandleFunc("POST /v1/apis", handlers.CreateAPI)
	mux.HandleFunc("GET /v1/apis/", handlers.GetAPI)
	mux.HandleFunc("POST /v1/api-keys", handlers.IssueAPIKey)
	mux.HandleFunc("POST /v1/api-keys/validate", handlers.ValidateAPIKey)
	mux.HandleFunc("POST /v1/api-keys/revoke", handlers.RevokeAPIKey)
	return mux
}
