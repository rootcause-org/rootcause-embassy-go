package embassy

import "fmt"

// Error is a contract refusal: an HTTP status plus the snake_case `class` code the
// host reads off the signed body. The vocabulary is closed (see the hub's
// CONTRACT.md error table) — no implementation invents another code.
type Error struct {
	Status  int
	Class   string
	Message string
}

func (e *Error) Error() string { return e.Class + ": " + e.Message }

// Error classes. This is the whole vocabulary.
const (
	ClassInvalidRequest  = "invalid_request"
	ClassBadSignature    = "bad_signature"
	ClassReplay          = "replay"
	ClassSchemaViolation = "schema_violation"
	ClassResolveFailed   = "resolve_failed"
	ClassHandlerError    = "handler_error"
	ClassInternalError   = "internal_error"

	// classMethodNotAllowed is deliberately OUTSIDE the signed vocabulary: the 405
	// is a transport-level refusal answered before any contract processing, and it
	// is the liveness probe's target (hub decision 6d).
	classMethodNotAllowed = "method_not_allowed"
)

func invalidRequest(format string, a ...any) *Error {
	return &Error{Status: 400, Class: ClassInvalidRequest, Message: fmt.Sprintf(format, a...)}
}

func badSignature(msg string) *Error {
	return &Error{Status: 401, Class: ClassBadSignature, Message: msg}
}

func replayRefusal(format string, a ...any) *Error {
	return &Error{Status: 409, Class: ClassReplay, Message: fmt.Sprintf(format, a...)}
}

func schemaViolation(format string, a ...any) *Error {
	return &Error{Status: 422, Class: ClassSchemaViolation, Message: fmt.Sprintf(format, a...)}
}

func resolveFailed(format string, a ...any) *Error {
	return &Error{Status: 502, Class: ClassResolveFailed, Message: fmt.Sprintf(format, a...)}
}

func handlerError(format string, a ...any) *Error {
	return &Error{Status: 500, Class: ClassHandlerError, Message: fmt.Sprintf(format, a...)}
}
