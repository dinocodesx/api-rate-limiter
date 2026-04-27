package ratelimit

import "testing"

func TestBucketKey(t *testing.T) {
	key := BucketKey("key_123", "get", "v1/charges")
	if key != "bucket:key_123:GET:/v1/charges" {
		t.Fatalf("unexpected bucket key %q", key)
	}
}
