package main

import (
	"sync"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// clientRateLimiter is a per-client token-bucket rate limiter. It allows a
// burst of up to burst requests and refills at requestsPerSecond.
type clientRateLimiter struct {
	mu      sync.Mutex
	clients map[turbotunnel.ClientID]*rateBucket
	rate    float64 // tokens added per nanosecond
	burst   float64
}

type rateBucket struct {
	tokens   float64
	lastSeen time.Time
}

func newClientRateLimiter(requestsPerSecond float64, burst int) *clientRateLimiter {
	return &clientRateLimiter{
		clients: make(map[turbotunnel.ClientID]*rateBucket),
		rate:    requestsPerSecond / 1e9,
		burst:   float64(burst),
	}
}

// Allow reports whether a request from clientID should be allowed.
func (l *clientRateLimiter) Allow(id turbotunnel.ClientID) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.clients[id]
	if !ok {
		b = &rateBucket{tokens: l.burst, lastSeen: now}
		l.clients[id] = b
	}
	elapsed := float64(now.Sub(b.lastSeen).Nanoseconds())
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastSeen = now
	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}
	return false
}

// Purge removes entries for clients not seen for longer than maxAge, freeing
// memory for clients that have disconnected.
func (l *clientRateLimiter) Purge(maxAge time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	threshold := time.Now().Add(-maxAge)
	for id, b := range l.clients {
		if b.lastSeen.Before(threshold) {
			delete(l.clients, id)
		}
	}
}
