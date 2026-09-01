package chat

const docsBaseURL = "https://github.com/rootcause-org/rootcause-embassy/blob/main/docs/integrator/errors.md#"

// Error is a stable chat integration failure. Use errors.As and Code() instead
// of matching Error() text.
type Error struct {
	ErrorCode string
	Hint      string
	Docs      string
	Cause     error
}

func (e *Error) Error() string { return e.Code() + ": " + e.Hint + " — " + e.Docs }

// Code returns the stable SCREAMING_SNAKE identifier.
func (e *Error) Code() string { return e.ErrorCode }

func (e *Error) Unwrap() error { return e.Cause }

func refusal(code, hint string) *Error {
	return &Error{ErrorCode: code, Hint: hint, Docs: docsBaseURL + asciiLower(code)}
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
