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
