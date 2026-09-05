// Package rcerr is the single definition of a customer-facing Embassy failure.
//
// It lives in internal/ because both the root package and chat/ need it and the
// import direction only runs one way (root imports chat). The customer-visible
// names stay `embassy.Error` and `chat.Error`, which alias this type, so the two
// packages describe the same failure with one implementation.
package rcerr

import "strings"

// DocsBaseURL is the public error catalogue; a code's anchor is its lowercase form.
const DocsBaseURL = "https://github.com/rootcause-org/rootcause-embassy/blob/main/docs/integrator/errors.md#"

// Error is a stable, customer-facing failure. ErrorCode is exposed through Code()
// so callers can branch with errors.As without parsing prose.
//
// Status and Class are set only by the signed action/result planes, where the
// refusal also travels on the wire.
type Error struct {
	Status    int
	Class     string
	Message   string
	ErrorCode string
	Hint      string
	Docs      string
	Cause     error
}

// The stable prefix is the CODE; the variable detail rides Message and is appended
// when it adds something the canned hint does not, so a log line still names the
// field or value that was refused.
func (e *Error) Error() string {
	text := e.Code() + ": " + e.Hint
	if e.Message != "" && e.Message != e.Hint {
		text += " (" + e.Message + ")"
	}
	return text + " — " + e.Docs
}

// Code returns the stable SCREAMING_SNAKE identifier.
func (e *Error) Code() string { return e.ErrorCode }

// Unwrap preserves sentinel and transport matching without exposing cause text.
func (e *Error) Unwrap() error { return e.Cause }

// WithDetail attaches the variable half of a failure. The hint stays the stable,
// greppable sentence; the detail says which field, endpoint or value was refused.
func (e *Error) WithDetail(detail string) *Error {
	e.Message = detail
	return e
}

// New builds the canonical error for a code: one code, one hint, one docs anchor.
func New(code string) *Error {
	return &Error{ErrorCode: code, Hint: Hint(code), Docs: DocsURL(code)}
}

// Caused is New plus the underlying error, kept for errors.Is/As without ever
// putting the cause's text on the wire.
func Caused(code string, cause error) *Error {
	err := New(code)
	err.Cause = cause
	return err
}

// DocsURL is the catalogue anchor for a code.
func DocsURL(code string) string { return DocsBaseURL + strings.ToLower(code) }
