package httpapi

import "net/http"

func NewRouter(handler *Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", handler.Live)
	mux.HandleFunc("GET /readyz", handler.Ready)
	mux.HandleFunc("GET /healthz", handler.Health)
	mux.Handle("/", Recover(handler))
	return mux
}
