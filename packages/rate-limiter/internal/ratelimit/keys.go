package ratelimit

import (
	"path"
	"strings"
)

func NormalizeRoute(raw string) string {
	cleaned := path.Clean("/" + strings.TrimSpace(raw))
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

func BucketKey(apiKeyID, method, route string) string {
	return "bucket:" + apiKeyID + ":" + strings.ToUpper(strings.TrimSpace(method)) + ":" + NormalizeRoute(route)
}
