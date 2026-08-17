package embassy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// SignatureHeader carries every HMAC on both directions of every signed plane.
const SignatureHeader = "X-Webhook-Signature"

const signaturePrefix = "sha256="

// Sign returns the wire header value for payload under secret: HMAC-SHA256 over
// the EXACT bytes, lowercase hex, `sha256=` prefixed.
//
// A blank secret fails closed: HMAC with a zero-length key is trivially forgeable,
// so we refuse to produce a signature at all. Boot validation rejects a blank
// secret, so this is a second floor, not a normal path.
func Sign(payload []byte, secret string) string {
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return signaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature constant-time compares header against HMAC(payload, secret).
// A missing, blank or malformed header is false, never a panic — "no signature"
// and "bad signature" refuse identically.
func VerifySignature(header string, payload []byte, secret string) bool {
	if header == "" || secret == "" {
		return false
	}
	expected := Sign(payload, secret)
	return hmac.Equal([]byte(expected), []byte(header))
}
