package embassy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
)

// ActionAPI is what a script receives: host-stamped tenant and principal context,
// the writer whose bytes become the wire `stdout`, and the run deadline.
//
// Tenant() is the ONLY trustworthy source of tenant identity — never read a
// tenant from params.
type ActionAPI interface {
	// Tenant returns the trusted tuple, or nil on a flat (non-tenant) project.
	Tenant() *TenantContext
	// Principal returns the host-stamped identity assertion, or nil when the
	// invocation has no requester-bound scope.
	Principal() *PrincipalContext
	// Out is captured into the result's `stdout`, truncated at MaxStdoutBytes.
	Out() io.Writer
	// Context carries the invocation deadline. A script doing its own I/O should
	// pass it down so a cancelled run stops promptly.
	Context() context.Context
	// ActionID is the registry id of the action being executed.
	ActionID() string
	// DryRun is always false inside Run — a dry run never executes — and exists so
	// a script can be written defensively.
	DryRun() bool
}

type actionAPI struct {
	tenant    *TenantContext
	principal *PrincipalContext
	out       io.Writer
	ctx       context.Context
	actionID  string
}

func (a *actionAPI) Tenant() *TenantContext       { return a.tenant }
func (a *actionAPI) Principal() *PrincipalContext { return a.principal }
func (a *actionAPI) Out() io.Writer               { return a.out }
func (a *actionAPI) Context() context.Context     { return a.ctx }
func (a *actionAPI) ActionID() string             { return a.actionID }
func (a *actionAPI) DryRun() bool                 { return false }

// execResult is the executor's half of the wire envelope.
type execResult struct {
	ok          bool
	returnValue any
	stdout      string
	errClass    string
	errMessage  string
}

// The trampoline is generated, not customer code: it is the only place that knows
// how to hand our Go values to interpreted code, and it lets the whole call ride
// inside one EvalWithContext — which is what lets the deadline abort the script's
// MAIN frame. A goroutine a script spawns is beyond that reach, which is why the
// script contract says: don't spawn one, and pass a.Context() into your own I/O.
const trampolineSource = `package rcrun

import (
	"action"
	"rcbridge"
	"os"
)

func Invoke() {
	a, p, env := rcbridge.Args()
	os.Clearenv()
	defer os.Clearenv()
	for name, value := range env {
		_ = os.Setenv(name, value)
	}
	rcbridge.Capture(action.Run(a, p))
}
`

const (
	embassyPkgKey  = "github.com/rootcause-org/rootcause-embassy-go/embassy"
	bridgePkgKey   = "rcbridge/rcbridge"
	symbolsPkgKey  = "rcsymbols/rcsymbols"
	invokeExprText = "rcrun.Invoke()"
)

// program is one interpreter that has already parsed a specific script body, plus
// the per-run slots the bridge reads. It is checked out of a pool for exactly one
// execution at a time, so no locking is needed on the slots themselves.
type program struct {
	interp *interp.Interpreter

	api          ActionAPI
	params       map[string]any
	principalEnv map[string]string
	returned     any
	returnErr    error
}

// executor memoizes parsed programs per digest. Different digests always run
// concurrently; the same digest runs concurrently too, by growing that digest's
// pool — nothing process-global (no env, no stdout swap, no execution mutex) is
// touched, unlike a subprocess or in-process-eval runtime.
type executor struct {
	cfg *Config

	mu    sync.Mutex
	pools map[string]*programPool
}

type programPool struct {
	mu   sync.Mutex
	free []*program
}

func newExecutor(cfg *Config) *executor {
	return &executor{cfg: cfg, pools: map[string]*programPool{}}
}

// poolKey binds a pooled interpreter to its complete trusted scope. Scripts may
// retain package state, so a principal-less run must never inherit a prior
// principal assertion through an interpreter reused for a different scope.
func poolKey(hexDigest string, tenant *TenantContext, principal *PrincipalContext) string {
	if tenant == nil && principal == nil {
		return hexDigest
	}
	scope := ""
	if tenant != nil {
		scope += tenant.ID + "\x00" + tenant.Slug + "\x00" + tenant.ScopeValue
	}
	if principal != nil {
		encoded, _ := json.Marshal(struct {
			Kind       string         `json:"kind"`
			ExternalID string         `json:"external_id"`
			Claims     map[string]any `json:"claims"`
		}{principal.kind, principal.externalID, principal.claims})
		scope += "\x00" + sha256Hex(string(encoded))
	}
	return hexDigest + "\x00" + scope
}

// maxPools bounds how many (digest, tenant) pairs keep warm interpreters. Each
// pooled interpreter is real memory in the customer's process, and script digests
// rotate, so an unbounded map would be a slow leak. Past the cap we drop the whole
// set and warm up again — losing memoization briefly beats leaking forever.
const maxPools = 64

func (e *executor) poolFor(key string) *programPool {
	e.mu.Lock()
	defer e.mu.Unlock()
	pool, ok := e.pools[key]
	if !ok {
		if len(e.pools) >= maxPools {
			e.pools = map[string]*programPool{}
		}
		pool = &programPool{}
		e.pools[key] = pool
	}
	return pool
}

func (p *programPool) get() *program {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := len(p.free); n > 0 {
		prog := p.free[n-1]
		p.free = p.free[:n-1]
		return prog
	}
	return nil
}

// maxPooledPrograms bounds idle interpreters per key: a burst grows the pool, a
// quiet period lets the extras go.
const maxPooledPrograms = 8

func (p *programPool) put(prog *program) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.free) < maxPooledPrograms {
		p.free = append(p.free, prog)
	}
}

// run executes a digest-verified script body. It never panics and never returns
// an error: every outcome — script error, panic, deadline, non-serializable
// return — becomes a structured failure envelope.
func (e *executor) run(ctx context.Context, script, hexDigest, actionID string, tenant *TenantContext, principal *PrincipalContext, params map[string]any) (result execResult) {
	out := newCappedWriter(e.cfg.MaxStdoutBytes)
	var err error

	defer func() {
		// Backstop: a panic escaping yaegi's own recover must still be a signed
		// failure result, never a crashed process. The program is deliberately NOT
		// pooled here — its interpreter state is unknown.
		if r := recover(); r != nil {
			result = execResult{stdout: out.String(), errClass: "panic", errMessage: fmt.Sprint(r)}
		}
	}()

	pool := e.poolFor(poolKey(hexDigest, tenant, principal))
	prog := pool.get()
	if prog == nil {
		prog, err = e.compile(script)
		if err != nil {
			return execResult{stdout: out.String(), errClass: "compile_error", errMessage: err.Error()}
		}
	}

	prog.api = &actionAPI{tenant: tenant, principal: principal, out: out, ctx: ctx, actionID: actionID}
	prog.params = params
	prog.principalEnv = principalEnvironment(principal)
	prog.returned, prog.returnErr = nil, nil

	_, err = prog.interp.EvalWithContext(ctx, invokeExprText)
	if err == nil {
		// Reuse ONLY a cleanly finished program. Cancellation returns while yaegi's
		// eval goroutine is still unwinding (its stop is cooperative, not a join), so
		// a pooled-back program could still have that goroutine write this run's
		// result slots underneath the NEXT run.
		defer pool.put(prog)
	}

	switch {
	case err != nil && errors.Is(err, context.DeadlineExceeded):
		return execResult{stdout: out.String(), errClass: "timeout", errMessage: "action exceeded its execution deadline"}
	case err != nil && errors.Is(err, context.Canceled):
		return execResult{stdout: out.String(), errClass: "canceled", errMessage: "action was canceled"}
	case err != nil:
		// yaegi surfaces an interpreted panic here as interp.Panic.
		var panicErr interp.Panic
		if errors.As(err, &panicErr) {
			return execResult{stdout: out.String(), errClass: "panic", errMessage: fmt.Sprint(panicErr.Value)}
		}
		return execResult{stdout: out.String(), errClass: "script_error", errMessage: err.Error()}
	}

	if prog.returnErr != nil {
		return execResult{stdout: out.String(), errClass: "error", errMessage: prog.returnErr.Error()}
	}
	// A return value the host cannot decode is a failed run, not a crash.
	if _, err := json.Marshal(prog.returned); err != nil {
		return execResult{stdout: out.String(), errClass: "non_serializable_result", errMessage: "return value is not JSON-serializable"}
	}
	return execResult{ok: true, returnValue: prog.returned, stdout: out.String()}
}

// compile builds a fresh interpreter around one script body. The bridge closures
// capture the pooled program, never a per-run value, so the per-run writer reaches
// the script through the ActionAPI the bridge hands it.
func (e *executor) compile(script string) (*program, error) {
	prog := &program{}
	prog.interp = interp.New(interp.Options{
		// yaegi prints an interpreted panic's trace to Stderr; we surface it in the
		// signed envelope instead and keep the customer's logs clean.
		Stderr: io.Discard,
	})
	if err := prog.interp.Use(stdlib.Symbols); err != nil {
		return nil, err
	}
	if err := prog.interp.Use(interp.Exports{
		embassyPkgKey: {
			"ActionAPI":        reflect.ValueOf((*ActionAPI)(nil)),
			"TenantContext":    reflect.ValueOf((*TenantContext)(nil)),
			"PrincipalContext": reflect.ValueOf((*PrincipalContext)(nil)),
		},
		bridgePkgKey: {
			// Read through a function, not a variable: yaegi binds an exported var
			// by value at Use time, so a per-run var would hand the script stale
			// arguments.
			"Args": reflect.ValueOf(func() (ActionAPI, map[string]any, map[string]string) {
				return prog.api, prog.params, prog.principalEnv
			}),
			"Capture": reflect.ValueOf(func(v any, err error) { prog.returned, prog.returnErr = v, err }),
		},
		symbolsPkgKey: e.symbolExports(),
	}); err != nil {
		return nil, err
	}
	if _, err := prog.interp.Eval(script); err != nil {
		return nil, err
	}
	if _, err := prog.interp.Eval(trampolineSource); err != nil {
		return nil, err
	}
	return prog, nil
}

func (e *executor) symbolExports() map[string]reflect.Value {
	exports := make(map[string]reflect.Value, len(e.cfg.Symbols))
	for name, value := range e.cfg.Symbols {
		exports[name] = reflect.ValueOf(value)
	}
	return exports
}

// cappedWriter is the wire `stdout` sink: it accepts every write so a chatty
// script never fails, but keeps only the first MaxStdoutBytes bytes.
type cappedWriter struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func newCappedWriter(limit int) *cappedWriter {
	return &cappedWriter{limit: limit}
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := w.limit - len(w.buf); room > 0 {
		if len(p) <= room {
			w.buf = append(w.buf, p...)
		} else {
			w.buf = append(w.buf, p[:room]...)
		}
	}
	return len(p), nil
}

func (w *cappedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.buf)
}
