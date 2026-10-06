// Package uuid generates the random identifiers the Embassy needs (action nonces
// and chat token jti values). Both the root package and chat/ mint them, and the
// import direction only runs one way, so the generator lives here.
package uuid

import (
	"crypto/rand"
	"fmt"
)

// New returns a random v4 UUID. crypto/rand.Read never returns an error (it panics
// if the OS source fails), so a nonce or jti is never silently predictable.
func New() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// IsCanonical reports whether s is the lowercase hyphenated 8-4-4-4-12 form the
// host emits for ledger ids such as action_run_id.
func IsCanonical(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}
