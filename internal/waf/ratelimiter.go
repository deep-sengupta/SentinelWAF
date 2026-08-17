package waf

import (
	"sync"
	"time"
)

const maxVisitors = 10000

type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	limit    int
	burst    int
	window   time.Duration
	blockFor time.Duration
}

type visitor struct {
	windowStart  time.Time
	lastSeen     time.Time
	count        int
	blockedUntil time.Time
}

func NewRateLimiter(limit int, burst int, windowSeconds int, blockSeconds int) *RateLimiter {
	if limit < 1 { limit = 1 }
	if burst < 0 { burst = 0 }
	if windowSeconds < 1 { windowSeconds = 1 }
	if blockSeconds < 1 { blockSeconds = 1 }
	return &RateLimiter{
		visitors: map[string]*visitor{},
		limit:    limit,
		burst:    burst,
		window:   time.Duration(windowSeconds) * time.Second,
		blockFor: time.Duration(blockSeconds) * time.Second,
	}
}

func (r *RateLimiter) Allow(key string) (bool, time.Duration) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	item := r.visitors[key]
	if item == nil {
		if len(r.visitors) >= maxVisitors { r.evict(now) }
		item = &visitor{windowStart: now, lastSeen: now}
		r.visitors[key] = item
	}
	item.lastSeen = now

	if !item.blockedUntil.IsZero() && now.Before(item.blockedUntil) {
		return false, time.Until(item.blockedUntil)
	}
	if now.Sub(item.windowStart) >= r.window {
		item.windowStart = now
		item.count = 0
		item.blockedUntil = time.Time{}
	}
	item.count++
	if item.count > r.limit+r.burst {
		item.blockedUntil = now.Add(r.blockFor)
		return false, r.blockFor
	}
	if item.count > r.limit {
		return false, time.Until(item.windowStart.Add(r.window))
	}
	return true, 0
}

func (r *RateLimiter) evict(now time.Time) {
	cutoff := now.Add(-2 * r.window)
	for key, item := range r.visitors {
		if len(r.visitors) < maxVisitors { break }
		if item.lastSeen.Before(cutoff) && (item.blockedUntil.IsZero() || !now.Before(item.blockedUntil)) { delete(r.visitors, key) }
	}
	for len(r.visitors) >= maxVisitors {
		var oldestKey string
		var oldest time.Time
		for key, item := range r.visitors {
			if oldestKey == "" || item.lastSeen.Before(oldest) { oldestKey, oldest = key, item.lastSeen }
		}
		if oldestKey == "" { break }
		delete(r.visitors, oldestKey)
	}
}
