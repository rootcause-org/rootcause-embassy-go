package embassy

import (
	"sync"
	"time"
)

// NonceStore records which nonces have been seen inside the freshness window.
//
// The default is in-process and therefore correct for exactly one process: a
// multi-worker deployment MUST inject a shared store (Redis, Postgres, memcached
// with an atomic add) or a replay slips through on a second worker.
type NonceStore interface {
	// Add records nonce for ttl and reports true iff it was previously unseen.
	// It must be atomic across concurrent callers.
	Add(nonce string, ttl time.Duration) bool
	// Delete forgets nonce so it can be accepted again. The result route calls
	// this to release a nonce whose handler dispatch failed (hub decision 1) —
	// without it one transient handler error permanently drops a result.
	Delete(nonce string)
}

// memoryNonceStore is the default store: a mutex-guarded map pruned on write,
// deadlines on Go's monotonic clock (immune to NTP jumps and suspend).
type memoryNonceStore struct {
	mu       sync.Mutex
	expiries map[string]time.Time
}

// NewMemoryNonceStore builds the default single-process nonce store.
func NewMemoryNonceStore() NonceStore {
	return &memoryNonceStore{expiries: map[string]time.Time{}}
}

func (s *memoryNonceStore) Add(nonce string, ttl time.Duration) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, deadline := range s.expiries {
		if !deadline.After(now) {
			delete(s.expiries, k)
		}
	}
	if _, seen := s.expiries[nonce]; seen {
		return false
	}
	s.expiries[nonce] = now.Add(ttl)
	return true
}

func (s *memoryNonceStore) Delete(nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.expiries, nonce)
}

// checkFreshness enforces the symmetric ±skew window on issued_at. A clock ahead
// is exactly as stale as a clock behind.
func checkFreshness(issuedAt string, skew time.Duration, now time.Time) error {
	issued, err := time.Parse(time.RFC3339, issuedAt)
	if err != nil {
		return replayRefusal("issued_at is not a valid RFC3339 timestamp")
	}
	drift := now.Sub(issued)
	if drift < 0 {
		drift = -drift
	}
	if drift > skew {
		return replayRefusal("issued_at outside ±%ds window (skew=%ds)", int(skew.Seconds()), int(drift.Seconds()))
	}
	return nil
}

// recordNonce consumes the nonce, reporting whether it was unseen. The TTL covers
// the FULL window (2×skew): past that the freshness check alone refuses, so the
// store never has to remember more.
func recordNonce(nonce string, store NonceStore, skew time.Duration) (bool, error) {
	if nonce == "" {
		return false, replayRefusal("nonce missing")
	}
	return store.Add(nonce, 2*skew+time.Second), nil
}
