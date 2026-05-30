package httpapi

import (
	"sync"
	"time"
)

type rateLimiter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	items  map[string]rateItem
}

type rateItem struct {
	count     int
	resetTime time.Time
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		window: window,
		max:    max,
		items:  make(map[string]rateItem),
	}
}

func (r *rateLimiter) Allow(key string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	item := r.items[key]
	if item.resetTime.IsZero() || now.After(item.resetTime) {
		r.items[key] = rateItem{count: 1, resetTime: now.Add(r.window)}
		return true
	}
	if item.count >= r.max {
		return false
	}
	item.count++
	r.items[key] = item
	return true
}
