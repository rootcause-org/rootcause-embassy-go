package embassy

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
)

// decodeJSONObject decodes into a generic map with UseNumber, so an integer param
// keeps its exact wire spelling instead of round-tripping through float64.
func decodeJSONObject(body []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("not a JSON object")
	}
	return object, nil
}

func stringField(raw map[string]any, key string) string {
	s, _ := raw[key].(string)
	return s
}

// typeName is what an unexpected error is allowed to reveal: the TYPE, never the
// message text, which may carry untrusted input.
func typeName(err error) string {
	if err == nil {
		return ""
	}
	t := reflect.TypeOf(err)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Name() != "" {
		return t.String()
	}
	return "error"
}

// panicError carries a recovered panic without letting its value reach the wire.
type panicError struct{ value any }

func (p *panicError) Error() string { return fmt.Sprintf("panic: %v", p.value) }

// crypto/rand.Read never returns an error (it panics if the OS source fails), so
// a nonce/jti is never silently predictable.
func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (c *Config) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	// A discarding logger keeps every call site unconditional.
	return slog.New(slog.DiscardHandler)
}

func (e *Embassy) logger() *slog.Logger { return e.cfg.logger() }

// logInvocation records identifiers and shape only: action_id, digest, param KEYS,
// ok, duration. Never values, never the body, never the secret.
func (e *Embassy) logInvocation(inv *invocation, envelope resultEnvelope) {
	e.logger().Info("rootcause action executed",
		"action_id", inv.ActionID,
		"digest", inv.ScriptDigest,
		"param_keys", paramKeys(inv.raw),
		"dry_run", inv.DryRun,
		"ok", envelope.OK,
		"duration_ms", envelope.DurationMs,
	)
}

// logRefusal takes best-effort context from an UNAUTHENTICATED body: param keys
// only, and only if it parsed.
func (e *Embassy) logRefusal(refusal *Error, raw []byte) {
	attrs := []any{"class", refusal.Class, "message", refusal.Message}
	if len(raw) > 0 {
		if parsed, err := decodeJSONObject(raw); err == nil {
			attrs = append(attrs, "param_keys", paramKeys(parsed))
		}
	}
	e.logger().Warn("rootcause refused", attrs...)
}

func paramKeys(raw map[string]any) []string {
	params, ok := raw["params"].(map[string]any)
	if !ok {
		return []string{}
	}
	return sortedKeys(params)
}
