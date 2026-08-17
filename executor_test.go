package embassy

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func runScript(t *testing.T, exec *executor, script string, params map[string]any) execResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.run(ctx, script, sha256Hex(script), "demo_action", nil, params)
}

func newTestExecutor(t *testing.T, symbols map[string]any) *executor {
	t.Helper()
	cfg := &Config{Secret: testSecret, FetchURL: "https://app.replypen.com/x", Symbols: symbols}
	cfg.applyDefaults()
	return newExecutor(cfg)
}

const echoScript = `package action

import emb "github.com/rootcause-org/rootcause-embassy-go"

func Run(a emb.ActionAPI, params map[string]any) (any, error) {
	a.Out().Write([]byte("hello"))
	return params["email"], nil
}
`

func TestExecutorRunsAndCaptures(t *testing.T) {
	result := runScript(t, newTestExecutor(t, nil), echoScript, map[string]any{"email": "x@acme.com"})
	if !result.ok || result.returnValue != "x@acme.com" || result.stdout != "hello" {
		t.Fatalf("result = %+v", result)
	}
}

func TestExecutorCapsStdout(t *testing.T) {
	const chatty = `package action

import emb "github.com/rootcause-org/rootcause-embassy-go"

func Run(a emb.ActionAPI, params map[string]any) (any, error) {
	for i := 0; i < 100; i++ {
		a.Out().Write([]byte("0123456789"))
	}
	return nil, nil
}
`
	exec := newTestExecutor(t, nil)
	exec.cfg.MaxStdoutBytes = 32
	result := runScript(t, exec, chatty, nil)
	if !result.ok || len(result.stdout) != 32 {
		t.Fatalf("stdout len = %d", len(result.stdout))
	}
}

func TestExecutorFailureModes(t *testing.T) {
	tests := []struct {
		name      string
		script    string
		wantClass string
	}{
		{
			name: "a returned error is a structured failure",
			script: `package action
import ("errors"; emb "github.com/rootcause-org/rootcause-embassy-go")
func Run(a emb.ActionAPI, params map[string]any) (any, error) { return nil, errors.New("nope") }
`,
			wantClass: "error",
		},
		{
			name: "a panic never crashes the process",
			script: `package action
import emb "github.com/rootcause-org/rootcause-embassy-go"
func Run(a emb.ActionAPI, params map[string]any) (any, error) { panic("boom") }
`,
			wantClass: "panic",
		},
		{
			name: "a non-serializable return value is a failed run",
			script: `package action
import emb "github.com/rootcause-org/rootcause-embassy-go"
func Run(a emb.ActionAPI, params map[string]any) (any, error) { return func() {}, nil }
`,
			wantClass: "non_serializable_result",
		},
		{
			name: "a script that does not compile is a failure, not a crash",
			script: `package action
func Run( { }
`,
			wantClass: "compile_error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runScript(t, newTestExecutor(t, nil), test.script, nil)
			if result.ok || result.errClass != test.wantClass {
				t.Fatalf("result = %+v, want class %s", result, test.wantClass)
			}
		})
	}
}

// The deadline must actually interrupt a running script, not just report late.
func TestExecutorDeadlineInterrupts(t *testing.T) {
	const spin = `package action
import emb "github.com/rootcause-org/rootcause-embassy-go"
func Run(a emb.ActionAPI, params map[string]any) (any, error) {
	for {
	}
}
`
	exec := newTestExecutor(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	result := exec.run(ctx, spin, sha256Hex(spin), "spin", nil, nil)
	if result.ok || result.errClass != "timeout" {
		t.Fatalf("result = %+v", result)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("deadline took %s to fire", elapsed)
	}
}

// A timed-out program must not go back in the pool: yaegi's cancellation is
// cooperative, so its eval goroutine can still be unwinding and would clobber the
// NEXT run's result slots.
func TestExecutorDoesNotReuseATimedOutProgram(t *testing.T) {
	const slow = `package action
import ("time"; emb "github.com/rootcause-org/rootcause-embassy-go")
func Run(a emb.ActionAPI, params map[string]any) (any, error) {
	if params["slow"] == true {
		time.Sleep(2 * time.Second)
	}
	return "done", nil
}
`
	exec := newTestExecutor(t, nil)
	digest := sha256Hex(slow)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if result := exec.run(ctx, slow, digest, "a", nil, map[string]any{"slow": true}); result.ok {
		t.Fatal("the slow run should have timed out")
	}

	pool := exec.poolFor(poolKey(digest, nil))
	if len(pool.free) != 0 {
		t.Fatal("a timed-out program was returned to the pool")
	}
	// The next run gets a clean program and its own result.
	if result := runScript(t, exec, slow, nil); !result.ok || result.returnValue != "done" {
		t.Fatalf("next run = %+v", result)
	}
}

// Params are DATA: a value that looks like code is an inert string.
func TestExecutorParamsAreData(t *testing.T) {
	const echo = `package action
import emb "github.com/rootcause-org/rootcause-embassy-go"
func Run(a emb.ActionAPI, params map[string]any) (any, error) { return params["name"], nil }
`
	payload := `"; os.Exit(1); "`
	result := runScript(t, newTestExecutor(t, nil), echo, map[string]any{"name": payload})
	if !result.ok || result.returnValue != payload {
		t.Fatalf("result = %+v", result)
	}
}

func TestExecutorExposesSymbols(t *testing.T) {
	const usesSymbols = `package action

import (
	emb "github.com/rootcause-org/rootcause-embassy-go"
	"rcsymbols"
)

func Run(a emb.ActionAPI, params map[string]any) (any, error) {
	return rcsymbols.Greet("world"), nil
}
`
	exec := newTestExecutor(t, map[string]any{
		"Greet": func(name string) string { return "hi " + name },
	})
	result := runScript(t, exec, usesSymbols, nil)
	if !result.ok || result.returnValue != "hi world" {
		t.Fatalf("result = %+v", result)
	}
}

// The trusted tuple reaches the script as a typed argument — no process env is
// mutated, so concurrent runs of DIFFERENT tenants cannot bleed into each other.
func TestExecutorConcurrentTenantIsolation(t *testing.T) {
	const tenantScript = `package action

import emb "github.com/rootcause-org/rootcause-embassy-go"

func Run(a emb.ActionAPI, params map[string]any) (any, error) {
	t := a.Tenant()
	if t == nil {
		return "", nil
	}
	return t.Slug, nil
}
`
	exec := newTestExecutor(t, nil)
	digest := sha256Hex(tenantScript)

	var wg sync.WaitGroup
	errs := make(chan string, 32)
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slug := "tenant-" + string(rune('a'+i%26))
			result := exec.run(context.Background(), tenantScript, digest, "a", &TenantContext{ID: "id", Slug: slug}, nil)
			if !result.ok || result.returnValue != slug {
				errs <- "got " + strings.TrimSpace(result.errMessage) + " want " + slug
			}
		}()
	}
	wg.Wait()
	close(errs)
	for message := range errs {
		t.Fatalf("tenant bled across concurrent runs: %s", message)
	}
}
