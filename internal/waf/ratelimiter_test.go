package waf

import (
	"fmt"
	"testing"
)

func TestRateLimiterCapsVisitorState(t *testing.T) {
	r := NewRateLimiter(100, 0, 60, 60)
	for i := 0; i < maxVisitors+1000; i++ { r.Allow(fmt.Sprintf("198.51.100.%d", i%256)) }
	if len(r.visitors) > maxVisitors { t.Fatalf("visitor map grew beyond cap: %d", len(r.visitors)) }
}

func TestRateLimiterBlocksAfterLimit(t *testing.T) {
	r := NewRateLimiter(2, 0, 60, 60)
	if ok, _ := r.Allow("client"); !ok { t.Fatal("first request should be allowed") }
	if ok, _ := r.Allow("client"); !ok { t.Fatal("second request should be allowed") }
	if ok, _ := r.Allow("client"); ok { t.Fatal("third request should be blocked") }
}
