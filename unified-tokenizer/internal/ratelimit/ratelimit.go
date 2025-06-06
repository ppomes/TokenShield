package ratelimit

import (
	"sync"
	"time"
)

// ClientRate represents rate limiting data for a single client
type ClientRate struct {
	Attempts    int
	LastAttempt time.Time
	BlockedUntil time.Time
}

// RateLimiter manages rate limiting for multiple clients
type RateLimiter struct {
	clients       map[string]*ClientRate
	maxAttempts   int
	windowSize    time.Duration
	blockDuration time.Duration
	mu            sync.RWMutex
}

// NewRateLimiter creates a new rate limiter with specified parameters
func NewRateLimiter(maxAttempts int, windowSize time.Duration, blockDuration time.Duration) *RateLimiter {
	return &RateLimiter{
		clients:       make(map[string]*ClientRate),
		maxAttempts:   maxAttempts,
		windowSize:    windowSize,
		blockDuration: blockDuration,
	}
}

// IsAllowed checks if a client is allowed to make a request
func (rl *RateLimiter) IsAllowed(clientIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	
	client, exists := rl.clients[clientIP]
	if !exists {
		// First request from this client
		rl.clients[clientIP] = &ClientRate{
			Attempts:    1,
			LastAttempt: now,
			BlockedUntil: time.Time{},
		}
		return true
	}
	
	// Check if client is currently blocked
	if !client.BlockedUntil.IsZero() && now.Before(client.BlockedUntil) {
		return false
	}
	
	// Reset if window has expired
	if now.Sub(client.LastAttempt) >= rl.windowSize {
		client.Attempts = 1
		client.LastAttempt = now
		client.BlockedUntil = time.Time{}
		return true
	}
	
	// Increment attempts
	client.Attempts++
	client.LastAttempt = now
	
	// Check if exceeded limit
	if client.Attempts > rl.maxAttempts {
		client.BlockedUntil = now.Add(rl.blockDuration)
		return false
	}
	
	return true
}

// GetClientInfo returns current rate limiting info for a client
func (rl *RateLimiter) GetClientInfo(clientIP string) (attempts int, lastAttempt time.Time, blockedUntil time.Time) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	
	client, exists := rl.clients[clientIP]
	if !exists {
		return 0, time.Time{}, time.Time{}
	}
	
	return client.Attempts, client.LastAttempt, client.BlockedUntil
}

// Cleanup removes expired entries from the rate limiter
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	
	// Remove entries that are both unblocked and outside the window
	for clientIP, client := range rl.clients {
		// Remove if unblocked and window expired
		windowExpired := now.Sub(client.LastAttempt) >= rl.windowSize
		blockExpired := client.BlockedUntil.IsZero() || now.After(client.BlockedUntil)
		
		if windowExpired && blockExpired {
			delete(rl.clients, clientIP)
		}
	}
}

// Reset clears all rate limiting data for a specific client
func (rl *RateLimiter) Reset(clientIP string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	delete(rl.clients, clientIP)
}

// GetStats returns overall rate limiter statistics
func (rl *RateLimiter) GetStats() (totalClients int, blockedClients int, activeClients int) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	
	now := time.Now()
	totalClients = len(rl.clients)
	
	for _, client := range rl.clients {
		// Count blocked clients
		if !client.BlockedUntil.IsZero() && now.Before(client.BlockedUntil) {
			blockedClients++
		}
		
		// Count active clients (made request within window)
		if now.Sub(client.LastAttempt) < rl.windowSize {
			activeClients++
		}
	}
	
	return totalClients, blockedClients, activeClients
}