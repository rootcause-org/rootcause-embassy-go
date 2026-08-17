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

// ActionAPI is what a script receives: the host-stamped tenant tuple, the writer
// whose bytes become the wire `stdout`, and the run's deadline-bearing context.
//
// Tenant() is the ONLY trustworthy source of tenant identity — never read a
// tenant from params.
type ActionAPI interface {
	// Tenant returns the trusted tuple, or nil on a flat (non-tenant) project.
	Tenant() *TenantContext
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
	tenant   *TenantContext
	out      io.Writer
	ctx      context.Context
	actionID string
}

func (a *actionAPI) Tenant() *TenantContext   { return a.tenant }
func (a *actionAPI) Out() io.Writer           { return a.out }
func (a *actionAPI) Context() context.Context { return a.ctx }
func (a *actionAPI) ActionID() string         { return a.actionID }
func (a *actionAPI) DryRun() bool             { return false }

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
)

func Invoke() {
	a, p := rcbridge.Args()
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

	api       ActionAPI
	params    map[string]any
	returned  any
	returnErr error
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

// poolKey binds a pooled interpreter to ONE tenant as well as one script body.
// A pooled interpreter keeps the script's package-level state between runs, so
// sharing one across tenants would be a cross-tenant bleed if a script ever held
// state in a package var. The trusted tuple itself is always passed per run.
func poolKey(hexDigest string, tenant *TenantContext) string {
	if tenant == nil {
		return hexDigest
	}
	return hexDigest + "\x00" + tenant.ID
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
func (e *executor) run(ctx context.Context, script, hexDigest, actionID string, tenant *TenantContext, params map[string]any) (result execResult) {
	out := newCappedWriter(e.cfg.MaxStdoutBytes)

	defer func() {
		// Backstop: a panic escaping yaegi's own recover must still be a signed
		// failure result, never a crashed process. The program is deliberately NOT
		// pooled here — its interpreter state is unknown.
		if r := recover(); r != nil {
			result = execResult{stdout: out.String(), errClass: "panic", errMessage: fmt.Sprint(r)}
		}
	}()

	pool := e.poolFor(poolKey(hexDigest, tenant))
	prog := pool.get()
	if prog == nil {
		var err error
		prog, err = e.compile(script)
		if err != nil {
			return execResult{stdout: out.String(), errClass: "compile_error", errMessage: err.Error()}
		}
	}

	prog.api = &actionAPI{tenant: tenant, out: out, ctx: ctx, actionID: actionID}
	prog.params = params
	prog.returned, prog.returnErr = nil, nil

	_, err := prog.interp.EvalWithContext(ctx, invokeExprText)
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
			"ActionAPI":     reflect.ValueOf((*ActionAPI)(nil)),
			"TenantContext": reflect.ValueOf((*TenantContext)(nil)),
		},
		bridgePkgKey: {
			// Read through a function, not a variable: yaegi binds an exported var
			// by value at Use time, so a per-run var would hand the script stale
			// arguments.
			"Args":    reflect.ValueOf(func() (ActionAPI, map[string]any) { return prog.api, prog.params }),
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
