package types

type RoutePolicy struct {
	Method       string  `json:"method"`
	PathPattern  string  `json:"path_pattern"`
	Capacity     int64   `json:"capacity"`
	RefillPerSec float64 `json:"refill_per_sec"`
	BucketTTLSec int64   `json:"bucket_ttl_sec"`
}

type APIRegistration struct {
	APIID         string        `json:"api_id"`
	OwnerID       string        `json:"owner_id"`
	UpstreamURL   string        `json:"upstream_url"`
	Active        bool          `json:"active"`
	RoutePolicies []RoutePolicy `json:"route_policies"`
}
