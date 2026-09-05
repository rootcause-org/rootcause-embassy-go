package chat

import "github.com/rootcause-org/rootcause-embassy-go/internal/rcerr"

// Error is a stable chat integration failure. Use errors.As and Code() instead of
// matching Error() text. It is the same type the root package exposes as
// embassy.Error, so a lifted chat failure keeps its code, hint and docs link.
type Error = rcerr.Error

// refusal builds the canonical error for a code; the hint comes from the one
// code → hint table.
func refusal(code string) *Error { return rcerr.New(code) }
