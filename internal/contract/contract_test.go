// Package contract replays the hub's canonical fixtures. Signed refusal
// fixtures are the required minimum; ports add code/hint/docs diagnostics.
//
// The fixtures in testdata/ are VENDORED from
// https://github.com/rootcause-org/rootcause-embassy — never edited here. When the
// hub changes, re-copy the directory and update testdata/HUB_SHA.
package contract_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	embassy "github.com/rootcause-org/rootcause-embassy-go"
	"github.com/rootcause-org/rootcause-embassy-go/chat"
)

const (
	reverseSecret = "contract-reverse-secret"
	chatSecretKey = "contract-chat-secret"
	projectID     = "11111111-1111-1111-1111-111111111111"
	sessionID     = "44444444-4444-4444-4444-444444444444"
)

// The reference clock every fixture's issued_at carries. A conformance suite
// INJECTS it; it never runs these against wall time.
var referenceClock = time.Unix(1781913600, 0).UTC()

// The Go script the executable round-trips use. The hub's fixture script is Ruby
// (`{ found: true, email: params[:email] }`), which this runtime cannot execute —
// the wire shapes are what conformance pins, not the script language.
const goScript = `package action

import emb "github.com/rootcause-org/rootcause-embassy-go"

func Run(a emb.ActionAPI, params map[string]any) (any, error) {
	slug := ""
	if t := a.Tenant(); t != nil {
		slug = t.Slug
	}
	if params["email"] == "boom@acme.com" {
		panic("boom")
	}
	a.Out().Write([]byte("looked up " + a.ActionID()))
	return map[string]any{"found": true, "email": params["email"], "tenant": slug}, nil
}
`

const principalScript = `package action

import (
	"os"
	emb "github.com/rootcause-org/rootcause-embassy-go"
)

func Run(a emb.ActionAPI, params map[string]any) (any, error) {
	p := a.Principal()
	if p == nil {
		return map[string]any{"present": false, "env_kind": os.Getenv("RC_PRINCIPAL_KIND")}, nil
	}
	if params["email"] == "clear@acme.com" {
		os.Clearenv()
	}
	userID, _ := p.Claim("user_id")
	backupIDs, _ := p.Claim("backup_ids")
	return map[string]any{
		"present": true, "kind": p.Kind(), "external_id": p.ExternalID(),
		"user_id": userID, "backup_ids": backupIDs,
		"env_kind": os.Getenv("RC_PRINCIPAL_KIND"),
		"env_user_id": os.Getenv("RC_PRINCIPAL_CLAIM_USER_ID"),
	}, nil
}
`

func TestMain(m *testing.M) {
	sha, err := os.ReadFile(filepath.Join("testdata", "HUB_SHA"))
	if err != nil {
		fmt.Println("SYNC: testdata/HUB_SHA missing — fixtures are unsynced")
		os.Exit(1)
	}
	fmt.Printf("SYNC: fixtures vendored from rootcause-embassy commit %s\n", strings.TrimSpace(string(sha)))
	os.Exit(m.Run())
}

type signingVectors struct {
	Secrets map[string]string `json:"secrets"`
	Header  string            `json:"header"`
	Bodies  []struct {
		Name       string `json:"name"`
		File       string `json:"file"`
		Secret     string `json:"secret"`
		BodyBytes  int    `json:"body_bytes"`
		BodySHA256 string `json:"body_sha256"`
		Signature  string `json:"signature"`
	} `json:"bodies"`
	QueryStrings []struct {
		Name      string `json:"name"`
		File      string `json:"file"`
		Secret    string `json:"secret"`
		RawQuery  string `json:"raw_query"`
		Signature string `json:"signature"`
	} `json:"query_strings"`
	ScriptDigest struct {
		Script string `json:"script"`
		Digest string `json:"digest"`
	} `json:"script_digest"`
}

func loadVectors(t *testing.T) signingVectors {
	t.Helper()
	var vectors signingVectors
	if err := json.Unmarshal(fixture(t, "signing_vectors.json"), &vectors); err != nil {
		t.Fatalf("signing_vectors.json: %v", err)
	}
	return vectors
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return raw
}

// 1. Verify — the exact bytes, their hash, their length and their signature.
func TestSigningVectors(t *testing.T) {
	vectors := loadVectors(t)
	if vectors.Header != embassy.SignatureHeader {
		t.Fatalf("header = %q, want %q", vectors.Header, embassy.SignatureHeader)
	}

	for _, vector := range vectors.Bodies {
		t.Run(vector.Name, func(t *testing.T) {
			body := fixture(t, vector.File)
			if len(body) != vector.BodyBytes {
				t.Fatalf("body_bytes = %d, want %d (a trailing newline snuck in?)", len(body), vector.BodyBytes)
			}
			sum := sha256.Sum256(body)
			if got := hex.EncodeToString(sum[:]); got != vector.BodySHA256 {
				t.Fatalf("body_sha256 = %s, want %s", got, vector.BodySHA256)
			}
			if got := embassy.Sign(body, vector.Secret); got != vector.Signature {
				t.Fatalf("signature = %s, want %s", got, vector.Signature)
			}
			if !embassy.VerifySignature(vector.Signature, body, vector.Secret) {
				t.Fatal("our own verifier rejected the vector signature")
			}
			if embassy.VerifySignature(vector.Signature, append(body, ' '), vector.Secret) {
				t.Fatal("a mutated body verified")
			}
		})
	}

	for _, vector := range vectors.QueryStrings {
		t.Run(vector.Name, func(t *testing.T) {
			raw := strings.TrimRight(string(fixture(t, vector.File)), "\n")
			if raw != vector.RawQuery {
				t.Fatalf("raw query file and vector disagree")
			}
			if got := embassy.Sign([]byte(raw), vector.Secret); got != vector.Signature {
				t.Fatalf("query signature = %s, want %s", got, vector.Signature)
			}
		})
	}
}

func TestBlankSecretFailsClosed(t *testing.T) {
	if embassy.Sign([]byte("x"), "") != "" {
		t.Fatal("signed with a blank key")
	}
	if embassy.VerifySignature("sha256=deadbeef", []byte("x"), "") {
		t.Fatal("verified with a blank key")
	}
	if embassy.VerifySignature("", []byte("x"), reverseSecret) {
		t.Fatal("a missing signature verified")
	}
}

// fakeHost serves the signed script-by-digest endpoint plus the analysis trigger
// and sent-message routes, and records what it received.
type fakeHost struct {
	server *httptest.Server

	script    string
	digest    string
	runtime   string
	unsigned  bool
	fetchCode int

	lastBody      []byte
	lastSignature string
	lastPath      string
	response      string
}

func newFakeHost(t *testing.T, script string) *fakeHost {
	t.Helper()
	sum := sha256.Sum256([]byte(script))
	host := &fakeHost{script: script, digest: "sha256:" + hex.EncodeToString(sum[:]), runtime: "go"}
	host.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host.lastPath = r.URL.Path
		if r.Method == http.MethodGet {
			host.lastSignature = r.Header.Get(embassy.SignatureHeader)
			host.lastBody = []byte(r.URL.RawQuery)
			if host.fetchCode != 0 {
				w.WriteHeader(host.fetchCode)
				return
			}
			body, _ := json.Marshal(map[string]any{
				"action_id": r.URL.Query().Get("action_id"),
				"digest":    r.URL.Query().Get("digest"),
				"script":    host.script,
				"runtime":   host.runtime,
			})
			if !host.unsigned {
				w.Header().Set(embassy.SignatureHeader, embassy.Sign(body, reverseSecret))
			}
			_, _ = w.Write(body)
			return
		}
		body, _ := readAll(r)
		host.lastBody = body
		host.lastSignature = r.Header.Get(embassy.SignatureHeader)
		w.WriteHeader(http.StatusAccepted)
		if host.response != "" {
			_, _ = w.Write([]byte(host.response))
		}
	}))
	t.Cleanup(host.server.Close)
	return host
}

func readAll(r *http.Request) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r.Body)
	return buf.Bytes(), err
}

func newEmbassy(t *testing.T, host *fakeHost, mutate func(*embassy.Config)) *embassy.Embassy {
	t.Helper()
	cfg := embassy.Config{
		Secret:         reverseSecret,
		FetchURL:       host.server.URL + "/actions/script",
		TriggerURL:     host.server.URL + "/analyses/demo",
		SentMessageURL: host.server.URL + "/analyses/demo/sent-message",
		Now:            func() time.Time { return referenceClock },
		Nonce:          func() string { return "contract-nonce" },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	emb, err := embassy.New(cfg)
	if err != nil {
		t.Fatalf("embassy.New: %v", err)
	}
	return emb
}

func postSigned(t *testing.T, handler http.Handler, body []byte, signature string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/rootcause/action", bytes.NewReader(body))
	request.Header.Set(embassy.SignatureHeader, signature)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// Every answer we produce — including a refusal — must carry a valid signature.
func assertSigned(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if !embassy.VerifySignature(recorder.Header().Get(embassy.SignatureHeader), recorder.Body.Bytes(), reverseSecret) {
		t.Fatalf("response was not validly signed: %s", recorder.Body.String())
	}
}

func invocationBody(t *testing.T, host *fakeHost, overrides map[string]any) []byte {
	t.Helper()
	body := map[string]any{
		"action_id":     "devise_send_password_reset",
		"script_digest": host.digest,
		"params":        map[string]any{"email": "x@acme.com"},
		"runtime":       "go",
		"project_id":    projectID,
		"nonce":         "nonce-" + t.Name(),
		"issued_at":     referenceClock.Format(time.RFC3339),
		"schema":        map[string]any{"email": map[string]any{"type": "string", "required": true}},
	}
	for key, value := range overrides {
		if value == nil {
			delete(body, key)
			continue
		}
		body[key] = value
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestActionRoundTrip(t *testing.T) {
	host := newFakeHost(t, goScript)
	emb := newEmbassy(t, host, nil)
	body := invocationBody(t, host, nil)

	recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
	assertSigned(t, recorder)
	if recorder.Code != 200 {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body)
	}

	var envelope struct {
		OK          bool           `json:"ok"`
		ReturnValue map[string]any `json:"return_value"`
		Stdout      string         `json:"stdout"`
		Error       any            `json:"error"`
		DurationMs  int            `json:"duration_ms"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK || envelope.Error != nil {
		t.Fatalf("envelope = %s", recorder.Body)
	}
	if envelope.ReturnValue["found"] != true || envelope.ReturnValue["email"] != "x@acme.com" {
		t.Fatalf("return_value = %v", envelope.ReturnValue)
	}
	if envelope.Stdout != "looked up devise_send_password_reset" {
		t.Fatalf("stdout = %q", envelope.Stdout)
	}

	// The script fetch signs the raw query, params in the contract order.
	if got := string(host.lastBody); !strings.HasPrefix(got, "action_id=devise_send_password_reset&digest=sha256%3A") ||
		!strings.HasSuffix(got, "&project_id="+projectID) {
		t.Fatalf("script fetch query = %q", got)
	}
	if host.lastSignature != embassy.Sign(host.lastBody, reverseSecret) {
		t.Fatal("script fetch was not signed over the raw query string")
	}

	// Same envelope key order as the golden; return_value contents differ because
	// the golden's script is Ruby.
	assertKeyOrder(t, recorder.Body.Bytes(), fixture(t, "actions/result_ok.json"))
}

// An omitted `runtime` is accepted — only a runtime we do not implement refuses.
func TestOmittedRuntimeIsAccepted(t *testing.T) {
	host := newFakeHost(t, goScript)
	emb := newEmbassy(t, host, nil)
	body := invocationBody(t, host, map[string]any{"runtime": nil})

	recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
	assertSigned(t, recorder)
	if recorder.Code != 200 {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body)
	}
}

// Strict tenant context may exempt named actions, never a whole project.
func TestTenantContextPolicy(t *testing.T) {
	const flatAction = "staff_flat_action"
	strict := func(cfg *embassy.Config) {
		cfg.RequireTenantContext = true
		cfg.TenantlessActions = []string{flatAction}
	}
	tuple := map[string]any{
		"tenant_id":   "22222222-2222-2222-2222-222222222222",
		"tenant_slug": "acme",
	}

	tests := []struct {
		name       string
		overrides  map[string]any
		wantStatus int
	}{
		{
			name:       "an absent tuple is accepted for an allowlisted action",
			overrides:  map[string]any{"action_id": flatAction},
			wantStatus: 200,
		},
		{
			name:       "a non-allowlisted flat invocation still refuses",
			overrides:  map[string]any{"action_id": "devise_send_password_reset"},
			wantStatus: 400,
		},
		{
			name:       "a partial tuple refuses even for an allowlisted action",
			overrides:  map[string]any{"action_id": flatAction, "tenant_id": tuple["tenant_id"]},
			wantStatus: 400,
		},
		{
			name:       "a complete tuple on an allowlisted action follows the normal path",
			overrides:  map[string]any{"action_id": flatAction, "tenant_id": tuple["tenant_id"], "tenant_slug": tuple["tenant_slug"]},
			wantStatus: 200,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host := newFakeHost(t, goScript)
			emb := newEmbassy(t, host, strict)
			body := invocationBody(t, host, test.overrides)

			recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
			assertSigned(t, recorder)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", recorder.Code, test.wantStatus, recorder.Body)
			}
			if test.wantStatus == 400 {
				assertClass(t, recorder, 400, embassy.ClassInvalidRequest)
				if host.lastPath != "" {
					t.Fatal("a tenant refusal must land before script resolution")
				}
			}
		})
	}
}

func TestTenantTupleReachesTheScript(t *testing.T) {
	host := newFakeHost(t, goScript)
	emb := newEmbassy(t, host, nil)
	body := invocationBody(t, host, map[string]any{
		"tenant_id":          "22222222-2222-2222-2222-222222222222",
		"tenant_slug":        "acme",
		"tenant_scope_value": "account-42",
	})

	recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
	assertSigned(t, recorder)
	var envelope struct {
		ReturnValue map[string]any `json:"return_value"`
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &envelope)
	if envelope.ReturnValue["tenant"] != "acme" {
		t.Fatalf("tenant did not reach the script: %s", recorder.Body)
	}
}

func TestPrincipalFixtureReachesOnlyItsInvocation(t *testing.T) {
	host := newFakeHost(t, principalScript)
	emb := newEmbassy(t, host, nil)

	var principalInvocation map[string]any
	if err := json.Unmarshal(fixture(t, "actions/invocation_principal.json"), &principalInvocation); err != nil {
		t.Fatal(err)
	}
	principalInvocation["runtime"] = "go"
	principalInvocation["script_digest"] = host.digest
	principalInvocation["nonce"] = "principal-env-clear"
	principalInvocation["params"] = map[string]any{"email": "clear@acme.com"}
	principalBody, err := json.Marshal(principalInvocation)
	if err != nil {
		t.Fatal(err)
	}
	recorder := postSigned(t, emb.ActionHandler(), principalBody, embassy.Sign(principalBody, reverseSecret))
	if recorder.Code != http.StatusOK {
		t.Fatalf("principal environment-clear status = %d: %s", recorder.Code, recorder.Body)
	}

	if err := json.Unmarshal(fixture(t, "actions/invocation_principal.json"), &principalInvocation); err != nil {
		t.Fatal(err)
	}
	principalInvocation["runtime"] = "go"
	principalInvocation["script_digest"] = host.digest
	principalInvocation["nonce"] = "principal-fixture"
	principalBody, err = json.Marshal(principalInvocation)
	if err != nil {
		t.Fatal(err)
	}
	recorder = postSigned(t, emb.ActionHandler(), principalBody, embassy.Sign(principalBody, reverseSecret))
	assertSigned(t, recorder)
	if recorder.Code != http.StatusOK {
		t.Fatalf("principal status = %d: %s", recorder.Code, recorder.Body)
	}
	var principalEnvelope struct {
		ReturnValue map[string]any `json:"return_value"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &principalEnvelope); err != nil {
		t.Fatal(err)
	}
	if principalEnvelope.ReturnValue["kind"] != "acme_user" || principalEnvelope.ReturnValue["external_id"] != "user-8f3" || principalEnvelope.ReturnValue["user_id"] != "user-8f3" || principalEnvelope.ReturnValue["env_kind"] != "acme_user" || principalEnvelope.ReturnValue["env_user_id"] != "user-8f3" {
		t.Fatalf("principal return value = %s", recorder.Body)
	}

	flatBody := invocationBody(t, host, nil)
	recorder = postSigned(t, emb.ActionHandler(), flatBody, embassy.Sign(flatBody, reverseSecret))
	assertSigned(t, recorder)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"present":false`) || !strings.Contains(recorder.Body.String(), `"env_kind":""`) {
		t.Fatalf("principal-less invocation inherited context: %d %s", recorder.Code, recorder.Body)
	}
}

func TestDryRunMatchesGolden(t *testing.T) {
	host := newFakeHost(t, goScript)
	emb := newEmbassy(t, host, nil)
	body := invocationBody(t, host, map[string]any{"dry_run": true})

	recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
	assertSigned(t, recorder)
	if recorder.Code != 200 {
		t.Fatalf("status = %d", recorder.Code)
	}
	assertEnvelopeShape(t, recorder.Body.Bytes(), fixture(t, "actions/result_dry_run.json"))
	if host.lastPath != "/actions/script" {
		t.Fatal("dry run skipped the signed script fetch — it must exercise it")
	}
}

// assertEnvelopeShape compares bytes with the volatile duration_ms normalized.
func assertEnvelopeShape(t *testing.T, got, want []byte) {
	t.Helper()
	if normalizeDuration(got) != normalizeDuration(want) {
		t.Fatalf("envelope bytes differ\n got: %s\nwant: %s", got, want)
	}
}

func normalizeDuration(body []byte) string {
	text := string(body)
	if i := strings.Index(text, `"duration_ms":`); i >= 0 {
		return text[:i] + `"duration_ms":0}`
	}
	return text
}

func assertKeyOrder(t *testing.T, got, want []byte) {
	t.Helper()
	if gotKeys, wantKeys := topLevelKeys(got), topLevelKeys(want); gotKeys != wantKeys {
		t.Fatalf("envelope key order = %s, want %s", gotKeys, wantKeys)
	}
}

// topLevelKeys lists an object's keys in serialization order, skipping over any
// nested value wholesale.
func topLevelKeys(body []byte) string {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ""
	}
	var keys []string
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			break
		}
		keys = append(keys, fmt.Sprint(key))
		var skipped json.RawMessage
		if err := decoder.Decode(&skipped); err != nil {
			break
		}
	}
	return strings.Join(keys, ",")
}

func TestRefusalEnvelopes(t *testing.T) {
	t.Run("bad_signature", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, nil)
		body := invocationBody(t, host, nil)
		recorder := postSigned(t, emb.ActionHandler(), body, "sha256=deadbeef")
		assertRefusal(t, recorder, 401, fixture(t, "actions/result_refusal_bad_signature.json"))
	})

	t.Run("replay", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, nil)
		body := invocationBody(t, host, nil)
		signature := embassy.Sign(body, reverseSecret)
		if first := postSigned(t, emb.ActionHandler(), body, signature); first.Code != 200 {
			t.Fatalf("first delivery = %d %s", first.Code, first.Body)
		}
		recorder := postSigned(t, emb.ActionHandler(), body, signature)
		assertRefusal(t, recorder, 409, fixture(t, "actions/result_refusal_replay.json"))
	})

	t.Run("schema_violation", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, nil)
		body := invocationBody(t, host, map[string]any{"schema": []any{map[string]any{"name": "email"}}})
		recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
		assertRefusal(t, recorder, 422, fixture(t, "actions/result_refusal_schema_violation.json"))
	})

	t.Run("resolve_failed", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, nil)
		// A digest that does not hash the body the host serves: the body never runs.
		body := invocationBody(t, host, map[string]any{
			"script_digest": "sha256:" + strings.Repeat("ab", 32),
		})
		recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
		assertRefusal(t, recorder, 502, fixture(t, "actions/result_refusal_resolve_failed.json"))
	})

	t.Run("unsigned_fetch_response", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		host.unsigned = true
		emb := newEmbassy(t, host, nil)
		body := invocationBody(t, host, nil)
		recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
		assertClass(t, recorder, 502, embassy.ClassResolveFailed)
	})

	t.Run("unimplemented_runtime", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, nil)
		// The hub's invocation fixtures declare runtime "ruby": a Go Embassy MUST
		// hard-refuse a runtime it does not implement (hub decision 8).
		body := fixture(t, "actions/invocation_flat.json")
		recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
		assertClass(t, recorder, 400, embassy.ClassInvalidRequest)
	})

	t.Run("a non-boolean dry_run fails closed", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, nil)
		// Never silently "not a dry run": that would execute for real.
		body := invocationBody(t, host, map[string]any{"dry_run": "true"})
		recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
		assertClass(t, recorder, 400, embassy.ClassInvalidRequest)
		if host.lastPath != "" {
			t.Fatal("a refused invocation must not reach the script fetch")
		}
	})

	t.Run("stale_issued_at", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, nil)
		body := invocationBody(t, host, map[string]any{
			"issued_at": referenceClock.Add(-10 * time.Minute).Format(time.RFC3339),
		})
		recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
		assertClass(t, recorder, 409, embassy.ClassReplay)
	})

	t.Run("reserved_tenant_param", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, nil)
		body := invocationBody(t, host, map[string]any{
			"params": map[string]any{"email": "x@acme.com", "RC_Tenant_ID": "sneaky"},
			"schema": map[string]any{
				"email":        map[string]any{"type": "string", "required": true},
				"RC_Tenant_ID": map[string]any{"type": "string"},
			},
		})
		recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
		assertClass(t, recorder, 422, embassy.ClassSchemaViolation)
	})

	t.Run("reserved_principal_param", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, nil)
		body := invocationBody(t, host, map[string]any{
			"params": map[string]any{"email": "x@acme.com", "RC_Principal_User_ID": "sneaky"},
			"schema": map[string]any{
				"email":                map[string]any{"type": "string", "required": true},
				"RC_Principal_User_ID": map[string]any{"type": "string"},
			},
		})
		recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
		assertClass(t, recorder, 422, embassy.ClassSchemaViolation)
	})

	t.Run("malformed_principal", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, nil)
		body := invocationBody(t, host, map[string]any{"principal": map[string]any{"kind": "acme_user"}})
		recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
		assertClass(t, recorder, 400, embassy.ClassInvalidRequest)
	})

	t.Run("partial_tenant_tuple", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, nil)
		body := invocationBody(t, host, map[string]any{"tenant_id": "22222222-2222-2222-2222-222222222222"})
		recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
		assertClass(t, recorder, 400, embassy.ClassInvalidRequest)
	})

	t.Run("script_panic_is_a_structured_failure", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, nil)
		body := invocationBody(t, host, map[string]any{"params": map[string]any{"email": "boom@acme.com"}})
		recorder := postSigned(t, emb.ActionHandler(), body, embassy.Sign(body, reverseSecret))
		assertSigned(t, recorder)
		if recorder.Code != 200 {
			t.Fatalf("status = %d", recorder.Code)
		}
		var envelope struct {
			OK    bool `json:"ok"`
			Error *struct {
				Class string `json:"class"`
			} `json:"error"`
		}
		_ = json.Unmarshal(recorder.Body.Bytes(), &envelope)
		if envelope.OK || envelope.Error == nil || envelope.Error.Class != "panic" {
			t.Fatalf("panic envelope = %s", recorder.Body)
		}
	})
}

func assertRefusal(t *testing.T, recorder *httptest.ResponseRecorder, status int, golden []byte) {
	t.Helper()
	assertSigned(t, recorder)
	if recorder.Code != status {
		t.Fatalf("status = %d, want %d (body %s)", recorder.Code, status, recorder.Body)
	}
	var got, want struct {
		OK    bool `json:"ok"`
		Error struct {
			Class   string `json:"class"`
			Message string `json:"message"`
			Code    string `json:"code"`
			Hint    string `json:"hint"`
			Docs    string `json:"docs"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(golden, &want); err != nil {
		t.Fatal(err)
	}
	if got.OK || got.Error.Class != want.Error.Class || got.Error.Message != want.Error.Message {
		t.Fatalf("refusal minimum differs\n got: %s\nwant: %s", recorder.Body, golden)
	}
	if got.Error.Code == "" || got.Error.Hint == "" || !strings.HasSuffix(got.Error.Docs, "#"+strings.ToLower(got.Error.Code)) {
		t.Fatalf("refusal diagnostics incomplete: %s", recorder.Body)
	}
}

func assertClass(t *testing.T, recorder *httptest.ResponseRecorder, status int, class string) {
	t.Helper()
	assertSigned(t, recorder)
	if recorder.Code != status {
		t.Fatalf("status = %d, want %d (body %s)", recorder.Code, status, recorder.Body)
	}
	var refusal struct {
		OK    bool `json:"ok"`
		Error struct {
			Class string `json:"class"`
			Code  string `json:"code"`
			Hint  string `json:"hint"`
			Docs  string `json:"docs"`
		} `json:"error"`
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &refusal)
	if refusal.OK || refusal.Error.Class != class {
		t.Fatalf("refusal = %s, want class %s", recorder.Body, class)
	}
	if refusal.Error.Code == "" || refusal.Error.Hint == "" || refusal.Error.Docs == "" {
		t.Fatalf("refusal diagnostics incomplete: %s", recorder.Body)
	}
}

func TestMethodNotAllowedProbe(t *testing.T) {
	host := newFakeHost(t, goScript)
	emb := newEmbassy(t, host, nil)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		request := httptest.NewRequest(method, "/rootcause/action", nil)
		recorder := httptest.NewRecorder()
		emb.ActionHandler().ServeHTTP(recorder, request)
		if recorder.Code != 405 {
			t.Fatalf("%s: status = %d, want 405", method, recorder.Code)
		}
		if recorder.Header().Get("Allow") != "POST" {
			t.Fatalf("%s: Allow = %q", method, recorder.Header().Get("Allow"))
		}
		if recorder.Header().Get(embassy.SignatureHeader) != "" {
			t.Fatalf("%s: the 405 probe must be UNSIGNED", method)
		}
		if !strings.Contains(recorder.Body.String(), `"method_not_allowed"`) {
			t.Fatalf("%s: body = %s", method, recorder.Body)
		}
	}
}

func TestHealthEndpoint(t *testing.T) {
	host := newFakeHost(t, goScript)
	emb := newEmbassy(t, host, nil)

	t.Run("unsigned is a 404 with no existence leak", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/rootcause/action/health", nil)
		recorder := httptest.NewRecorder()
		emb.ActionHandler().ServeHTTP(recorder, request)
		if recorder.Code != 404 {
			t.Fatalf("status = %d, want 404", recorder.Code)
		}
	})

	t.Run("signed", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/rootcause/action/health", nil)
		// A GET has no body: the signature covers the raw query string, empty here.
		request.Header.Set(embassy.SignatureHeader, embassy.Sign([]byte(""), reverseSecret))
		recorder := httptest.NewRecorder()
		emb.ActionHandler().ServeHTTP(recorder, request)
		assertSigned(t, recorder)
		if recorder.Code != 200 {
			t.Fatalf("status = %d", recorder.Code)
		}
		golden := string(fixture(t, "actions/health_response.json"))
		want := strings.NewReplacer(`"embassy":"ruby"`, `"embassy":"go"`, `"version":"0.5.0"`, `"version":"`+embassy.Version+`"`).Replace(golden)
		if recorder.Body.String() != want {
			t.Fatalf("health body\n got: %s\nwant: %s", recorder.Body, want)
		}
	})
}

// 3. Decode — the full result surface maps into our types.
func TestResultCallbackDecode(t *testing.T) {
	host := newFakeHost(t, goScript)
	var got embassy.Result
	emb := newEmbassy(t, host, func(cfg *embassy.Config) {
		cfg.ResultHandler = func(result embassy.Result) error {
			got = result
			return nil
		}
	})

	body := fixture(t, "analysis/result_callback.json")
	recorder := postResult(t, emb, body, embassy.Sign(body, reverseSecret))
	assertSigned(t, recorder)
	if recorder.Code != 200 {
		t.Fatalf("status = %d body %s", recorder.Code, recorder.Body)
	}
	if !bytes.Equal(recorder.Body.Bytes(), fixture(t, "analysis/result_ack.json")) {
		t.Fatalf("ack bytes = %s", recorder.Body)
	}

	if got.AnalysisID != "33333333-3333-3333-3333-333333333333" || got.SessionID != sessionID || got.ProjectID != projectID {
		t.Fatalf("ids = %q %q %q", got.AnalysisID, got.SessionID, got.ProjectID)
	}
	if !strings.HasPrefix(got.Draft, "Your reset link expired") {
		t.Fatalf("draft = %q", got.Draft)
	}
	if got.DraftSubject != "Re: Login fails after password reset" {
		t.Fatalf("draft subject = %q", got.DraftSubject)
	}
	if !strings.HasPrefix(got.Note, "Expired reset token") {
		t.Fatalf("summary note = %q", got.Note)
	}
	if len(got.Actions) != 1 || got.Actions[0].Slug != "devise_send_password_reset" || got.Actions[0].URL == "" {
		t.Fatalf("actions = %+v", got.Actions)
	}
	// A proposal may carry a render-only resource_url; an OUTCOME never does.
	if got.Actions[0].ResourceURL != "https://admin.acme.com/users/9f21c4/password" {
		t.Fatalf("resource_url = %q", got.Actions[0].ResourceURL)
	}
	if len(got.ExecutedActions) != 1 || !got.ExecutedActions[0].OK || got.ExecutedActions[0].Slug != "recompute_record_formulas" {
		t.Fatalf("executed_actions = %+v", got.ExecutedActions)
	}
	if len(got.Questions) != 1 || got.Questions[0].ID != "country" || len(got.Questions[0].Options) != 2 {
		t.Fatalf("questions = %+v", got.Questions)
	}
	if len(got.DeleteIDs) != 1 || got.DeleteIDs[0] != "77777777-7777-7777-7777-777777777777" {
		t.Fatalf("delete = %+v", got.DeleteIDs)
	}
	if got.Metadata["resource_id"] != "42" || !got.OK() {
		t.Fatalf("metadata = %+v ok = %v", got.Metadata, got.OK())
	}
}

// A resource_url that is not http(s) is dropped silently: the analysis result is
// the valuable payload and a bad decoration must not cost the reviewer the draft.
func TestNonHTTPResourceURLIsDropped(t *testing.T) {
	host := newFakeHost(t, goScript)
	var got embassy.Result
	emb := newEmbassy(t, host, func(cfg *embassy.Config) {
		cfg.ResultHandler = func(result embassy.Result) error {
			got = result
			return nil
		}
	})

	body := []byte(`{"analysis_id":"33333333-3333-3333-3333-333333333333","project_id":"` + projectID +
		`","actions":[{"id":"55555555-5555-5555-5555-555555555555","slug":"devise_send_password_reset",` +
		`"url":"https://app.replypen.com/a/confirm/eyJ0","resource_url":"javascript:alert(1)"}],` +
		`"nonce":"contract-nonce-resource-url","issued_at":"` + referenceClock.Format(time.RFC3339) + `"}`)

	recorder := postResult(t, emb, body, embassy.Sign(body, reverseSecret))
	assertSigned(t, recorder)
	if recorder.Code != 200 {
		t.Fatalf("status = %d body %s", recorder.Code, recorder.Body)
	}
	if len(got.Actions) != 1 || got.Actions[0].ResourceURL != "" {
		t.Fatalf("actions = %+v, want the resource_url dropped", got.Actions)
	}
	if got.Actions[0].URL == "" {
		t.Fatal("dropping the decoration must not drop the confirm URL")
	}
}

func postResult(t *testing.T, emb *embassy.Embassy, body []byte, signature string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/rootcause/result", bytes.NewReader(body))
	request.Header.Set(embassy.SignatureHeader, signature)
	recorder := httptest.NewRecorder()
	emb.ResultHandler().ServeHTTP(recorder, request)
	return recorder
}

// 7. Replay — the result route's asymmetry with the action route.
func TestResultRedeliverySemantics(t *testing.T) {
	body := fixture(t, "analysis/result_callback.json")
	signature := embassy.Sign(body, reverseSecret)

	t.Run("duplicate after a successful dispatch is an idempotent ack", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		dispatches := 0
		emb := newEmbassy(t, host, func(cfg *embassy.Config) {
			cfg.ResultHandler = func(embassy.Result) error { dispatches++; return nil }
		})

		for i := 0; i < 3; i++ {
			recorder := postResult(t, emb, body, signature)
			assertSigned(t, recorder)
			if recorder.Code != 200 || !bytes.Equal(recorder.Body.Bytes(), fixture(t, "analysis/result_ack.json")) {
				t.Fatalf("delivery %d = %d %s", i, recorder.Code, recorder.Body)
			}
		}
		if dispatches != 1 {
			t.Fatalf("dispatches = %d, want 1", dispatches)
		}
	})

	t.Run("a failed dispatch releases the nonce", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		dispatches := 0
		emb := newEmbassy(t, host, func(cfg *embassy.Config) {
			cfg.ResultHandler = func(embassy.Result) error {
				dispatches++
				if dispatches == 1 {
					return fmt.Errorf("database is down")
				}
				return nil
			}
		})

		first := postResult(t, emb, body, signature)
		assertSigned(t, first)
		if first.Code != 500 {
			t.Fatalf("failed dispatch = %d %s", first.Code, first.Body)
		}
		second := postResult(t, emb, body, signature)
		assertSigned(t, second)
		if second.Code != 200 || dispatches != 2 {
			t.Fatalf("redelivery = %d, dispatches = %d — the nonce was not released", second.Code, dispatches)
		}
	})

	t.Run("a panicking handler is a signed 500 that names only the type", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		dispatches := 0
		emb := newEmbassy(t, host, func(cfg *embassy.Config) {
			cfg.ResultHandler = func(embassy.Result) error {
				dispatches++
				if dispatches == 1 {
					panic("connection string sk-live-secret is bad")
				}
				return nil
			}
		})

		first := postResult(t, emb, body, signature)
		assertSigned(t, first)
		assertClass(t, first, 500, embassy.ClassInternalError)
		var refusal struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(first.Body.Bytes(), &refusal); err != nil {
			t.Fatal(err)
		}
		if refusal.Error.Message != "embassy.panicError" {
			t.Fatalf("internal_error must carry the type name only, got %q", refusal.Error.Message)
		}
		// A panic is a failed dispatch like any other: the nonce is released so the
		// host's redelivery is really processed.
		second := postResult(t, emb, body, signature)
		assertSigned(t, second)
		if second.Code != 200 || dispatches != 2 {
			t.Fatalf("redelivery = %d, dispatches = %d — the nonce was not released", second.Code, dispatches)
		}
	})

	t.Run("stale issued_at is still a 409", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, func(cfg *embassy.Config) {
			cfg.ResultHandler = func(embassy.Result) error { return nil }
			cfg.Now = func() time.Time { return referenceClock.Add(time.Hour) }
		})
		recorder := postResult(t, emb, body, signature)
		assertSigned(t, recorder)
		if recorder.Code != 409 {
			t.Fatalf("stale result = %d %s", recorder.Code, recorder.Body)
		}
	})

	t.Run("an unconfigured handler fails closed", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, nil)
		recorder := postResult(t, emb, body, signature)
		assertClass(t, recorder, 500, embassy.ClassHandlerError)
	})

	t.Run("a bad signature refuses", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, func(cfg *embassy.Config) {
			cfg.ResultHandler = func(embassy.Result) error { return nil }
		})
		recorder := postResult(t, emb, body, "sha256=deadbeef")
		assertRefusal(t, recorder, 401, fixture(t, "actions/result_refusal_bad_signature.json"))
	})
}

// 2. Sign — our own serialization of each outbound message, byte-for-byte.
func TestOutboundSerializationMatchesGoldens(t *testing.T) {
	t.Run("trigger", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		host.response = string(fixture(t, "analysis/trigger_response.json"))
		emb := newEmbassy(t, host, func(cfg *embassy.Config) {
			cfg.Nonce = func() string { return "contract-nonce-trigger" }
		})

		analysis, err := emb.StartAnalysis(t.Context(), embassy.AnalysisRequest{
			Subject:  "Login fails after password reset",
			Body:     "The reset mail arrives but the new password is refused.",
			Metadata: map[string]any{"resource_type": "SupportTicket", "resource_id": "42"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if analysis.AnalysisID == "" || analysis.SessionID != sessionID || analysis.Status != "queued" {
			t.Fatalf("analysis = %+v", analysis)
		}
		assertOutbound(t, host, fixture(t, "analysis/trigger.json"))
	})

	t.Run("trigger_with_principal", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		host.response = string(fixture(t, "analysis/trigger_response.json"))
		emb := newEmbassy(t, host, func(cfg *embassy.Config) {
			cfg.Nonce = func() string { return "contract-nonce-trigger-principal" }
		})

		_, err := emb.StartAnalysis(t.Context(), embassy.AnalysisRequest{
			Subject:     "Still failing after the reset",
			Body:        "Same error on the second attempt.",
			Attachments: []embassy.Attachment{{Filename: "error.log", MimeType: "text/plain", ContentBase64: "Ym9vbQo="}},
			Metadata:    map[string]any{"resource_type": "SupportTicket", "resource_id": "42"},
			SessionID:   sessionID,
			Tenant:      "acme",
			Principal: &embassy.Principal{
				Kind:       "acme_user",
				ExternalID: "user-8f3",
				AssertedBy: "acme",
				Assurance:  "customer_backend_jwt",
				TenantHint: "acme",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertOutbound(t, host, fixture(t, "analysis/trigger_with_principal.json"))
	})

	t.Run("sent_message", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, func(cfg *embassy.Config) {
			cfg.Nonce = func() string { return "contract-nonce-sent-message" }
		})

		if _, err := emb.CaptureSentMessage(t.Context(), embassy.SentMessageRequest{
			SessionID:    sessionID,
			SentBody:     "Sent you a fresh reset link — it expires in an hour.",
			Sender:       "Jane",
			ProposedBody: "Your reset link expired before you used it. I sent a fresh one.",
			Metadata:     embassy.SentMessageMetadata{ResourceType: "SupportTicket", ResourceID: "42"},
		}); err != nil {
			t.Fatal(err)
		}
		assertOutbound(t, host, fixture(t, "analysis/sent_message.json"))
	})

	t.Run("answers", func(t *testing.T) {
		host := newFakeHost(t, goScript)
		emb := newEmbassy(t, host, func(cfg *embassy.Config) {
			cfg.Nonce = func() string { return "contract-nonce-answers" }
		})

		if _, err := emb.CaptureSentMessage(t.Context(), embassy.SentMessageRequest{
			SessionID: sessionID,
			Metadata:  embassy.SentMessageMetadata{ResourceType: "SupportTicket", ResourceID: "42"},
			Answers:   []embassy.Answer{{ID: "country", Values: []string{"BE"}}},
		}); err != nil {
			t.Fatal(err)
		}
		assertOutbound(t, host, fixture(t, "analysis/answers.json"))
	})
}

// assertOutbound checks the logical message against the golden and the signature
// against OUR OWN bytes. Key order inside a body is deliberately not contract: the
// sender signs the bytes it writes and the receiver verifies the bytes it got. Go
// serializes a free-form metadata map in sorted key order, which differs from the
// golden's hand-written order — that is allowed, so we compare structurally and
// pin the field ORDER of the fields we control separately.
func assertOutbound(t *testing.T, host *fakeHost, golden []byte) {
	t.Helper()
	var got, want any
	if err := json.Unmarshal(host.lastBody, &got); err != nil {
		t.Fatalf("outbound body is not JSON: %s", host.lastBody)
	}
	if err := json.Unmarshal(golden, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outbound message differs\n got: %s\nwant: %s", host.lastBody, golden)
	}
	if gotKeys, wantKeys := topLevelKeys(host.lastBody), topLevelKeys(golden); gotKeys != wantKeys {
		t.Fatalf("outbound key order = %s, want %s", gotKeys, wantKeys)
	}
	if host.lastSignature != embassy.Sign(host.lastBody, reverseSecret) {
		t.Fatalf("outbound signature does not cover the transmitted bytes")
	}
}

// 6. Chat — replay the JWT vector to the EXACT token string.
func TestChatJWTVector(t *testing.T) {
	var vector struct {
		Secret       string `json:"secret"`
		NowUnix      int64  `json:"now_unix"`
		TTLSeconds   int64  `json:"ttl_seconds"`
		SigningInput string `json:"signing_input"`
		Token        string `json:"token"`
		ClaimsJSON   string `json:"claims_json"`
	}
	if err := json.Unmarshal(fixture(t, "chat/jwt_vector.json"), &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Secret != chatSecretKey {
		t.Fatalf("vector secret = %q", vector.Secret)
	}

	token, err := chat.MintEmbedToken(vector.Secret, chat.Claims{
		Project:     "acme",
		ExternalID:  "user-8f3",
		Kind:        "acme_user",
		Origin:      "https://app.acme.example",
		Tenant:      "acme",
		Locale:      "nl",
		ColorScheme: "light",
		JTI:         "88888888-8888-8888-8888-888888888888",
		TTL:         time.Duration(vector.TTLSeconds) * time.Second,
		IssuedAt:    time.Unix(vector.NowUnix, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if token != vector.Token {
		t.Fatalf("token\n got: %s\nwant: %s", token, vector.Token)
	}
	if !strings.HasPrefix(token, vector.SigningInput+".") {
		t.Fatal("signing input differs from the vector")
	}

	tag, err := chat.WidgetTagHTML(chat.Widget{
		BaseURL:     "https://app.replypen.com",
		Project:     "acme",
		Token:       token,
		Mode:        "page",
		Target:      "#rc-chat",
		Locale:      "nl",
		ColorScheme: "light",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimRight(string(fixture(t, "chat/widget_tag.html")), "\n")
	if tag != want {
		t.Fatalf("widget tag\n got: %s\nwant: %s", tag, want)
	}
}
