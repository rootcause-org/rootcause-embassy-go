package embassy

import "fmt"

const docsBaseURL = "https://github.com/rootcause-org/rootcause-embassy/blob/main/docs/integrator/errors.md#"

// Error is a stable, customer-facing failure. ErrorCode is exposed through
// Code() so callers can branch with errors.As without parsing prose.
type Error struct {
	Status    int
	Class     string
	Message   string
	ErrorCode string
	Hint      string
	Docs      string
	Cause     error
}

func (e *Error) Error() string {
	return e.Code() + ": " + e.Hint + " — " + e.Docs
}

// Code returns the stable SCREAMING_SNAKE identifier.
func (e *Error) Code() string { return e.ErrorCode }

// Unwrap preserves sentinel and transport matching without exposing cause text.
func (e *Error) Unwrap() error { return e.Cause }

func publicError(code, hint string) *Error {
	return &Error{ErrorCode: code, Hint: hint, Docs: docsURL(code)}
}

func causedError(code, hint string, cause error) *Error {
	err := publicError(code, hint)
	err.Cause = cause
	return err
}

func docsURL(code string) string {
	return docsBaseURL + asciiLower(code)
}

func asciiLower(value string) string {
	bytes := []byte(value)
	for i, b := range bytes {
		if b >= 'A' && b <= 'Z' {
			bytes[i] = b + ('a' - 'A')
		}
	}
	return string(bytes)
}

// Error classes are the closed signed action-refusal vocabulary.
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
	classMethodNotAllowed    = "method_not_allowed"
	classActionPlaneDisabled = "action_plane_disabled"
)

var actionCodes = map[string]string{
	ClassInvalidRequest:  "INVALID_REQUEST",
	ClassBadSignature:    "BAD_SIGNATURE",
	ClassReplay:          "REPLAY",
	ClassSchemaViolation: "SCHEMA_VIOLATION",
	ClassResolveFailed:   "RESOLVE_FAILED",
	ClassHandlerError:    "HANDLER_ERROR",
	ClassInternalError:   "INTERNAL_ERROR",
}

func actionError(status int, class, message string) *Error {
	code := actionCodes[class]
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	return &Error{
		Status:    status,
		Class:     class,
		Message:   message,
		ErrorCode: code,
		Hint:      actionHint(class, message),
		Docs:      docsURL(code),
	}
}

func actionHint(class, detail string) string {
	switch class {
	case ClassInvalidRequest:
		return "Compare the signed action request with CONTRACT.md and fix the invalid field: " + detail + "."
	case ClassBadSignature:
		return "Verify ROOTCAUSE_ACTION_SECRET and sign the exact transmitted bytes."
	case ClassReplay:
		return "Use a fresh nonce and a current issued_at; never blindly retry an action with an uncertain outcome."
	case ClassSchemaViolation:
		return "Match action param names and types to the approved schema and keep tenant identity out of params."
	case ClassResolveFailed:
		return "Check ROOTCAUSE_FETCH_URL and run a dry run; never bypass signature or digest verification."
	case ClassHandlerError:
		return "Configure an idempotent ResultHandler and verify it with the analysis result fixture."
	default:
		return "Upgrade the Embassy and rerun the conformance suite, then escalate with a redacted doctor bundle."
	}
}

func invalidRequest(format string, a ...any) *Error {
	return actionError(400, ClassInvalidRequest, fmt.Sprintf(format, a...))
}

func badSignature(msg string) *Error {
	return actionError(401, ClassBadSignature, msg)
}

func replayRefusal(format string, a ...any) *Error {
	return actionError(409, ClassReplay, fmt.Sprintf(format, a...))
}

func schemaViolation(format string, a ...any) *Error {
	return actionError(422, ClassSchemaViolation, fmt.Sprintf(format, a...))
}

func resolveFailed(format string, a ...any) *Error {
	return actionError(502, ClassResolveFailed, fmt.Sprintf(format, a...))
}

func handlerError(format string, a ...any) *Error {
	return actionError(500, ClassHandlerError, fmt.Sprintf(format, a...))
}
