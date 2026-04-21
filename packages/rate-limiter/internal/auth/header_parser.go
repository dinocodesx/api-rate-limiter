package auth

import (
	"fmt"
	"net/http"
	"strings"
)

func ParseHeaders(r *http.Request) (token string, apiID string, err error) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if authorization == "" {
		return "", "", fmt.Errorf("missing Authorization header")
	}
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", "", fmt.Errorf("invalid Authorization header")
	}
	apiID = strings.TrimSpace(r.Header.Get("X-API-ID"))
	if apiID == "" {
		return "", "", fmt.Errorf("missing X-API-ID header")
	}
	return parts[1], apiID, nil
}
