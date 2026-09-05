package embassy

import (
	"fmt"

	"github.com/rootcause-org/rootcause-embassy-go/internal/rcerr"
)

// Error is a stable, customer-facing failure. ErrorCode is exposed through Code()
// so callers can branch with errors.As without parsing prose. The definition is
// shared with the chat package; the customer-facing name is this one.
type Error = rcerr.Error

// publicError builds the canonical error for a code. The hint comes from the one
// code → hint table — a call site that needs to say more attaches a detail with
// WithDetail, it does not invent a second sentence for the same code.
func publicError(code string) *Error { return rcerr.New(code) }

func causedError(code string, cause error) *Error { return rcerr.Caused(code, cause) }

func docsURL(code string) string { return rcerr.DocsURL(code) }

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

// The variable detail rides the wire `message`, so the hint stays a stable,
// greppable string an integrator can search the catalogue for.
func actionError(status int, class, message string) *Error {
	code := actionCodes[class]
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	err := publicError(code).WithDetail(message)
	err.Status = status
	err.Class = class
	return err
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
