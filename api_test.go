package embassy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
)

func apiEmbassy(t *testing.T, baseURL, apiKey string) *Embassy {
	t.Helper()
	emb, err := New(Config{
		Secret:     testSecret,
		FetchURL:   "https://app.replypen.com/actions/script",
		APIBaseURL: baseURL,
		APIKey:     apiKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return emb
}

func TestAPIRefreshTokenExchange(t *testing.T) {
	var exchanges, calls int32
	var bearerMu sync.Mutex
	var lastBearer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			atomic.AddInt32(&exchanges, 1)
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "refresh_token" ||
				r.Form.Get("client_id") != oauthClientID ||
				r.Form.Get("refresh_token") != "rcor_secret" {
				t.Errorf("exchange form = %v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "rcoa_live", "expires_in": 3600, "token_type": "Bearer"})
			return
		}
		atomic.AddInt32(&calls, 1)
		bearerMu.Lock()
		lastBearer = r.Header.Get("Authorization")
		bearerMu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()

	emb := apiEmbassy(t, server.URL, "rcor_secret")
	response := emb.API().Get(context.Background(), "/api/v1/projects", url.Values{"limit": {"10"}})
	if !response.OK || response.Status != 200 {
		t.Fatalf("response = %+v", response)
	}
	bearerMu.Lock()
	seen := lastBearer
	bearerMu.Unlock()
	if seen != "Bearer rcoa_live" {
		t.Fatalf("bearer = %q", seen)
	}

	// Single-flight: concurrent callers exchange once and share the cached token.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emb.API().Get(context.Background(), "/api/v1/projects", nil)
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&exchanges); got != 1 {
		t.Fatalf("exchanges = %d, want 1", got)
	}
}

func TestAPIRetriesOnceOn401(t *testing.T) {
	var exchanges, unauthorized int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			atomic.AddInt32(&exchanges, 1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "rcoa_live", "expires_in": 3600})
			return
		}
		// Refuse the first call as if the token had been revoked.
		if atomic.AddInt32(&unauthorized, 1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()

	emb := apiEmbassy(t, server.URL, "rcor_secret")
	if response := emb.API().Get(context.Background(), "/api/v1/me", nil); !response.OK {
		t.Fatalf("response = %+v", response)
	}
	if got := atomic.LoadInt32(&exchanges); got != 2 {
		t.Fatalf("exchanges = %d, want 2 (burn + re-exchange exactly once)", got)
	}
}

func TestAPIStaticBearerIsUsedVerbatim(t *testing.T) {
	var bearer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			t.Error("a non-rcor_ key must never be exchanged")
		}
		bearer = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	emb := apiEmbassy(t, server.URL, "rcoa_static")
	emb.API().Get(context.Background(), "/api/v1/me", nil)
	if bearer != "Bearer rcoa_static" {
		t.Fatalf("bearer = %q", bearer)
	}
}

func TestAPIOutcomesAreValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rate":
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"slow down"}`))
		case "/invalid":
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":"validation_failed","field_errors":{"name":"blank"}}`))
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer server.Close()
	emb := apiEmbassy(t, server.URL, "rcoa_static")

	if response := emb.API().Get(context.Background(), "/rate", nil); response.OK || !response.Retryable {
		t.Fatalf("429 must be retryable backpressure: %+v", response)
	}
	response := emb.API().Post(context.Background(), "/invalid", map[string]any{"name": ""}, nil)
	if response.Retryable || response.FieldErrors["name"] != "blank" || response.Error != "validation_failed" {
		t.Fatalf("422 = %+v", response)
	}
	if response := emb.API().Get(context.Background(), "/boom", nil); !response.Retryable || response.Status != 502 {
		t.Fatalf("5xx = %+v", response)
	}
}

func TestAPIMisconfigurationDoesNotHide(t *testing.T) {
	emb := apiEmbassy(t, "https://app.replypen.com", "rcoa_static")

	// A bad argument raises instead of hiding in an outcome, and never carries the
	// bearer somewhere it was not meant to go.
	for _, test := range []struct {
		name string
		path string
		code string
	}{
		{name: "another origin", path: "https://evil.example.com/steal", code: "API_ORIGIN_MISMATCH"},
		{name: "malformed absolute port", path: "https://app.replypen.com:notaport/api/v1/me", code: "API_PATH_INVALID"},
		{name: "blank path", path: "", code: "API_PATH_REQUIRED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := emb.API().Get(context.Background(), test.path, nil)
			var typed *Error
			if response.OK || !errors.As(response.Err, &typed) || typed.Code() != test.code {
				t.Fatalf("response = %+v err = %#v", response, typed)
			}
			if !errors.Is(response.Err, ErrMisconfigured) {
				t.Fatalf("a caller bug must be distinguishable from a call outcome: %#v", response.Err)
			}
		})
	}
}

// A base URL may carry a path prefix (the host mounted behind a gateway), so the
// prefix has to survive the join with both spellings of the path.
func TestAPIBaseURLPathPrefixJoins(t *testing.T) {
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.RequestURI()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	api := apiEmbassy(t, server.URL+"/rootcause", "rcoa_static").API()
	for _, path := range []string{"api/v1/projects", "/api/v1/projects"} {
		seen = ""
		if response := api.Get(context.Background(), path, url.Values{"limit": {"10"}}); !response.OK {
			t.Fatalf("%s: response = %+v", path, response)
		}
		if seen != "/rootcause/api/v1/projects?limit=10" {
			t.Fatalf("%s: request = %q", path, seen)
		}
	}
}

// The host's own code, hint and docs are what a caller branches on, whether the
// refusal arrives from an API call (nested under "error") or from the token
// exchange (top level).
func TestHostRefusalPreservesHostDiagnostics(t *testing.T) {
	for _, test := range []struct {
		name      string
		apiKey    string
		status    int
		body      string
		code      string
		hint      string
		docs      string
		retryable bool
	}{
		{
			name:   "api call, nested error object",
			apiKey: "rcoa_static",
			status: http.StatusForbidden,
			body:   `{"error":{"code":"CHAT_DISABLED","hint":"Enable chat for this project.","docs":"https://example.test/chat-disabled"}}`,
			code:   "CHAT_DISABLED",
			hint:   "Enable chat for this project.",
			docs:   "https://example.test/chat-disabled",
		},
		{
			// An auth failure is retryable: the credential is usually fine and the
			// exchange endpoint was merely unhappy.
			name:      "token exchange, top-level object",
			apiKey:    "rcor_refused",
			status:    http.StatusUnauthorized,
			body:      `{"code":"BAD_TOKEN","hint":"Rotate the API credential.","docs":"https://example.test/bad-token"}`,
			code:      "BAD_TOKEN",
			hint:      "Rotate the API credential.",
			docs:      "https://example.test/bad-token",
			retryable: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			response := apiEmbassy(t, server.URL, test.apiKey).API().Get(context.Background(), "/api/v1/chat", nil)
			var typed *Error
			if !errors.As(response.Err, &typed) || response.Error != test.code || typed.Code() != test.code ||
				typed.Hint != test.hint || typed.Docs != test.docs || response.Retryable != test.retryable {
				t.Fatalf("response = %+v err = %#v", response, typed)
			}
		})
	}
}
