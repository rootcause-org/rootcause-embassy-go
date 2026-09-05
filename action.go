package embassy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// maxInvocationBytes bounds what we will read off an unauthenticated connection.
const maxInvocationBytes = 8 << 20

type wireError struct {
	Class   string `json:"class"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
	Hint    string `json:"hint,omitempty"`
	Docs    string `json:"docs,omitempty"`
}

// resultEnvelope is the action plane's success/failure shape. Field order matches
// the hub goldens so a conformance suite has exact bytes to assert against; key
// order is not itself contract (each side signs the bytes it writes).
type resultEnvelope struct {
	OK          bool       `json:"ok"`
	ReturnValue any        `json:"return_value"`
	Stdout      string     `json:"stdout"`
	Error       *wireError `json:"error"`
	DurationMs  int64      `json:"duration_ms"`
}

// refusalEnvelope is the documented refusal minimum: non-2xx + a signed body.
type refusalEnvelope struct {
	OK    bool      `json:"ok"`
	Error wireError `json:"error"`
}

type healthEnvelope struct {
	OK           bool     `json:"ok"`
	Embassy      string   `json:"embassy"`
	Version      string   `json:"version"`
	Protocol     int      `json:"protocol"`
	Capabilities []string `json:"capabilities"`
}

// ActionHandler serves the action plane. Mount it twice — the invocation route and
// its health child — because Go's ServeMux matches an exact pattern:
//
//	mux.Handle("/rootcause/action", emb.ActionHandler())
//	mux.Handle("/rootcause/action/health", emb.ActionHandler())
func (e *Embassy) ActionHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.cfg.actionEnabled() {
			writeActionPlaneDisabled(w)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/health") {
			e.serveHealth(w, r)
			return
		}
		if r.Method != http.MethodPost {
			// Transport-level refusal, deliberately UNSIGNED and outside the error
			// vocabulary: it is the liveness floor an operator probes with no side
			// effects (hub decision 6d).
			writeMethodNotAllowed(w)
			return
		}
		e.serveInvocation(w, r)
	})
}

func (e *Embassy) serveHealth(w http.ResponseWriter, r *http.Request) {
	secret, selected := e.healthSecret(r.URL.RawQuery)
	// An unsigned prober learns nothing: no existence leak, no vocabulary. Map
	// selector failures also cannot be signed because no project key was found.
	if r.Method != http.MethodGet || !selected || !VerifySignature(r.Header.Get(SignatureHeader), []byte(r.URL.RawQuery), secret) {
		http.NotFound(w, r)
		return
	}
	e.writeSigned(w, http.StatusOK, healthEnvelope{
		OK:           true,
		Embassy:      RuntimeToken,
		Version:      Version,
		Protocol:     Protocol,
		Capabilities: []string{"actions", "dry_run", "analysis_result", "health"},
	}, secret)
}

func (e *Embassy) healthSecret(rawQuery string) (string, bool) {
	if len(e.cfg.Secrets) == 0 {
		return e.cfg.secretForProject("")
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil || len(values["project_id"]) != 1 {
		return "", false
	}
	return e.cfg.secretForProject(values.Get("project_id"))
}

func (e *Embassy) serveInvocation(w http.ResponseWriter, r *http.Request) {
	// ONE deadline over signature + replay + schema + fetch + execute: the host
	// gives an invocation a single 25s shot with no retry, so a hung script fetch
	// must still leave us time to answer with a SIGNED result.
	ctx, cancel := context.WithTimeout(r.Context(), e.cfg.TotalDeadline)
	defer cancel()

	started := time.Now()
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxInvocationBytes))
	if err != nil {
		refusal := invalidRequest("request body could not be read")
		secret, selected := e.inboundSecret(nil)
		if selected {
			e.writeSigned(w, 400, refusalEnvelope{Error: wireRefusal(refusal)}, secret)
		} else {
			e.writeUnsigned(w, http.StatusUnauthorized, refusalEnvelope{Error: wireRefusal(badSignature("signature missing or invalid"))})
		}
		return
	}

	secret, selected := e.inboundSecret(raw)
	if !selected {
		e.writeUnsigned(w, http.StatusUnauthorized, refusalEnvelope{Error: wireRefusal(badSignature("signature missing or invalid"))})
		return
	}
	envelope, refusal := e.invoke(ctx, raw, r.Header.Get(SignatureHeader), started, secret)
	if refusal != nil {
		e.logRefusal(refusal, raw)
		e.writeSigned(w, refusal.Status, refusalEnvelope{Error: wireRefusal(refusal)}, secret)
		return
	}
	e.writeSigned(w, http.StatusOK, envelope, secret)
}

func (e *Embassy) inboundSecret(raw []byte) (string, bool) {
	if len(e.cfg.Secrets) == 0 {
		return e.cfg.secretForProject("")
	}
	parsed, err := decodeJSONObject(raw)
	if err != nil {
		return "", false
	}
	projectID, ok := parsed["project_id"].(string)
	if !ok {
		return "", false
	}
	return e.cfg.secretForProject(projectID)
}

func (e *Embassy) invoke(ctx context.Context, raw []byte, signature string, started time.Time, secret string) (resultEnvelope, *Error) {
	// Verify FIRST, parse second: never spend work on an unauthenticated body.
	if !VerifySignature(signature, raw, secret) {
		return resultEnvelope{}, badSignature("signature missing or invalid")
	}

	invocation, err := parseInvocation(raw)
	if err != nil {
		return resultEnvelope{}, asError(err)
	}
	tenant, err := validateTenantContext(invocation.raw, e.cfg.RequireTenantContext, invocation.ActionID, e.cfg.TenantlessActions)
	if err != nil {
		return resultEnvelope{}, asError(err)
	}
	principal, err := validatePrincipal(invocation.raw)
	if err != nil {
		return resultEnvelope{}, asError(err)
	}

	if err := checkFreshness(invocation.IssuedAt, e.cfg.ClockSkew, e.cfg.Now()); err != nil {
		return resultEnvelope{}, asError(err)
	}
	unseen, err := recordNonce(invocation.Nonce, e.cfg.NonceStore, e.cfg.ClockSkew)
	if err != nil {
		return resultEnvelope{}, asError(err)
	}
	if !unseen {
		// A replayed INVOCATION is an attack or a double-write. Full replay
		// semantics here; only the result route relaxes this.
		return resultEnvelope{}, replayRefusal("nonce has already been seen")
	}

	params, err := validateParams(invocation.raw["params"], invocation.raw["schema"])
	if err != nil {
		return resultEnvelope{}, asError(err)
	}

	// Resolve runs in a dry run too: it exercises the signed, digest-verified fetch,
	// so a dry run surfaces fetch/digest contract problems. Only execution is skipped.
	script, err := e.resolver.resolve(ctx, invocation.ActionID, invocation.ScriptDigest, invocation.ProjectID)
	if err != nil {
		return resultEnvelope{}, asError(err)
	}

	if invocation.DryRun {
		envelope := resultEnvelope{
			OK:          true,
			ReturnValue: map[string]any{"dry_run": true, "would_execute": true},
			DurationMs:  millisSince(started),
		}
		e.logInvocation(invocation, envelope)
		return envelope, nil
	}

	hexDigest, err := digestHex(invocation.ScriptDigest)
	if err != nil {
		return resultEnvelope{}, asError(err)
	}

	execCtx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()
	outcome := e.executor.run(execCtx, script, hexDigest, invocation.ActionID, tenant, principal, params)

	envelope := resultEnvelope{
		OK:          outcome.ok,
		ReturnValue: outcome.returnValue,
		Stdout:      outcome.stdout,
		DurationMs:  millisSince(started),
	}
	if !outcome.ok {
		// The whole invocation ran out of budget, not just the body: report it with
		// the same vocabulary so the host sees one failure story.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			envelope.Error = executionWireError("timeout", "invocation exceeded its total deadline")
		} else {
			envelope.Error = executionWireError(outcome.errClass, outcome.errMessage)
		}
	}
	e.logInvocation(invocation, envelope)
	return envelope, nil
}

type invocation struct {
	ActionID     string
	ScriptDigest string
	ProjectID    string
	Nonce        string
	IssuedAt     string
	Runtime      string
	DryRun       bool
	raw          map[string]any
}

func parseInvocation(body []byte) (*invocation, error) {
	raw, err := decodeJSONObject(body)
	if err != nil {
		return nil, invalidRequest("body is not valid JSON")
	}

	inv := &invocation{
		ActionID:     stringField(raw, "action_id"),
		ScriptDigest: stringField(raw, "script_digest"),
		ProjectID:    stringField(raw, "project_id"),
		Nonce:        stringField(raw, "nonce"),
		IssuedAt:     stringField(raw, "issued_at"),
		Runtime:      stringField(raw, "runtime"),
		raw:          raw,
	}
	// dry_run fails CLOSED: a present-but-non-boolean value is a refusal, never
	// "not a dry run" — that would execute for real the one flag whose whole point
	// is zero side effects.
	if value, present := raw["dry_run"]; present {
		b, ok := value.(bool)
		if !ok {
			return nil, invalidRequest("dry_run must be a boolean")
		}
		inv.DryRun = b
	}

	var missing []string
	for field, value := range map[string]string{
		"action_id": inv.ActionID, "script_digest": inv.ScriptDigest,
		"nonce": inv.Nonce, "issued_at": inv.IssuedAt,
	} {
		if value == "" {
			missing = append(missing, field)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, invalidRequest("missing field(s): %s", strings.Join(missing, ", "))
	}
	// Hard-refuse a runtime we do not implement — never a best-effort interpretation.
	if inv.Runtime != "" && inv.Runtime != RuntimeToken {
		return nil, invalidRequest("unsupported runtime: %s", inv.Runtime)
	}
	return inv, nil
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Allow", "POST")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = w.Write([]byte(`{"ok":false,"error":{"class":"` + classMethodNotAllowed + `","message":"POST required","code":"METHOD_NOT_ALLOWED","hint":"Send a POST request to the action mount, or a GET request to its health child.","docs":"` + docsURL("METHOD_NOT_ALLOWED") + `"}}`))
}

// The SECOND unsigned refusal, alongside the 405 liveness floor: with no action
// secret configured there is no key to sign with, so a chat-only deployment that
// mounts the action routes answers 503 in the clear. Nothing here is a security
// decision — the host never trusts an unverified body.
func writeActionPlaneDisabled(w http.ResponseWriter) {
	err := publicError("ACTION_PLANE_DISABLED", "Configure ROOTCAUSE_ACTION_SECRET and ROOTCAUSE_FETCH_URL before mounting action routes.")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(refusalEnvelope{Error: wireError{
		Class: classActionPlaneDisabled, Message: err.Hint, Code: err.Code(), Hint: err.Hint, Docs: err.Docs,
	}})
}

func wireRefusal(err *Error) wireError {
	return wireError{Class: err.Class, Message: err.Message, Code: err.Code(), Hint: err.Hint, Docs: err.Docs}
}

func executionWireError(class, message string) *wireError {
	err := publicError("ACTION_EXECUTION_FAILED", "Inspect the action outcome and application logs before deciding whether a retry is safe.")
	return &wireError{Class: class, Message: message, Code: err.Code(), Hint: err.Hint, Docs: err.Docs}
}

// writeSigned marshals once, signs those exact bytes, and writes those exact
// bytes — including for a refusal. Selector failures use writeUnsigned because
// no project key exists with which to sign their opaque refusal.
func (e *Embassy) writeSigned(w http.ResponseWriter, status int, payload any, secret string) {
	body, err := json.Marshal(payload)
	if err != nil {
		body, _ = json.Marshal(refusalEnvelope{Error: wireRefusal(actionError(500, ClassInternalError, typeName(err)))})
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(SignatureHeader, Sign(body, secret))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (e *Embassy) writeUnsigned(w http.ResponseWriter, status int, payload any) {
	body, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// asError funnels anything unexpected into a signed internal_error whose message
// is the TYPE only — an unforeseen error's text may carry untrusted input.
func asError(err error) *Error {
	var refusal *Error
	if errors.As(err, &refusal) {
		return refusal
	}
	return actionError(500, ClassInternalError, typeName(err))
}

func millisSince(started time.Time) int64 {
	return time.Since(started).Round(time.Millisecond).Milliseconds()
}
