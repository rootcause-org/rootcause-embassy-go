package embassy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const (
	mapProjectA = "11111111-1111-1111-1111-111111111111"
	mapProjectB = "22222222-2222-2222-2222-222222222222"
	mapSecretA  = "project-a-reverse-secret"
	mapSecretB  = "project-b-reverse-secret"
)

var mapReferenceClock = time.Unix(1781913600, 0).UTC()

func mapConfig(fetchURL string) Config {
	return Config{
		Secrets:  map[string]string{mapProjectA: mapSecretA, mapProjectB: mapSecretB},
		FetchURL: fetchURL,
		Now:      func() time.Time { return mapReferenceClock },
	}
}

func mapFetchHost(t *testing.T, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	script := "package action\n"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		projectID := r.URL.Query().Get("project_id")
		secret := map[string]string{mapProjectA: mapSecretA, mapProjectB: mapSecretB}[projectID]
		body, _ := json.Marshal(map[string]any{
			"action_id": r.URL.Query().Get("action_id"),
			"digest":    r.URL.Query().Get("digest"),
			"script":    script,
			"runtime":   "go",
		})
		w.Header().Set(SignatureHeader, Sign(body, secret))
		_, _ = w.Write(body)
	}))
}

func mapDryRunInvocation(t *testing.T, projectID, digest string) []byte {
	t.Helper()
	raw := map[string]any{
		"action_id":     "map_action",
		"script_digest": digest,
		"params":        map[string]any{},
		"runtime":       "go",
		"project_id":    projectID,
		"nonce":         "map-nonce-" + projectID,
		"issued_at":     mapReferenceClock.Format(time.RFC3339),
		"dry_run":       true,
		"schema":        map[string]any{},
	}
	body, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestSecretMapConfigValidation(t *testing.T) {
	valid := Config{Secrets: map[string]string{mapProjectA: mapSecretA}, FetchURL: "https://app.replypen.com/actions/script"}
	if _, err := New(valid); err != nil {
		t.Fatalf("valid map config: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"both modes": func(c *Config) { c.Secret = "single" },
		"empty map":  func(c *Config) { c.Secrets = map[string]string{} },
		"bad uuid":   func(c *Config) { c.Secrets = map[string]string{"project": mapSecretA} },
		"blank value": func(c *Config) {
			c.Secrets = map[string]string{mapProjectA: " "}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("map config unexpectedly accepted")
			}
		})
	}
}

func TestActionSecretMapSelection(t *testing.T) {
	script := "package action\n"
	digest := "sha256:" + sha256Hex(script)
	var calls atomic.Int32
	host := mapFetchHost(t, &calls)
	defer host.Close()
	cfg := mapConfig(host.URL)
	emb, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("map hit uses selected key", func(t *testing.T) {
		body := mapDryRunInvocation(t, mapProjectA, digest)
		req := httptest.NewRequest(http.MethodPost, "/action", bytes.NewReader(body))
		req.Header.Set(SignatureHeader, Sign(body, mapSecretA))
		rec := httptest.NewRecorder()
		emb.ActionHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !VerifySignature(rec.Header().Get(SignatureHeader), rec.Body.Bytes(), mapSecretA) {
			t.Fatalf("response = %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("sibling key is rejected with selected-key signature", func(t *testing.T) {
		body := mapDryRunInvocation(t, mapProjectA, digest)
		req := httptest.NewRequest(http.MethodPost, "/action", bytes.NewReader(body))
		req.Header.Set(SignatureHeader, Sign(body, mapSecretB))
		rec := httptest.NewRecorder()
		emb.ActionHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || !VerifySignature(rec.Header().Get(SignatureHeader), rec.Body.Bytes(), mapSecretA) {
			t.Fatalf("response = %d %s", rec.Code, rec.Body)
		}
	})

	for _, projectID := range []string{"", "33333333-3333-3333-3333-333333333333"} {
		t.Run("selector miss "+projectID, func(t *testing.T) {
			before := calls.Load()
			body := mapDryRunInvocation(t, projectID, digest)
			req := httptest.NewRequest(http.MethodPost, "/action", bytes.NewReader(body))
			req.Header.Set(SignatureHeader, Sign(body, mapSecretA))
			rec := httptest.NewRecorder()
			emb.ActionHandler().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized || rec.Header().Get(SignatureHeader) != "" {
				t.Fatalf("response = %d signature=%q body=%s", rec.Code, rec.Header().Get(SignatureHeader), rec.Body)
			}
			if calls.Load() != before {
				t.Fatal("selector miss reached script resolver")
			}
		})
	}
}

func TestResultSecretMapSelection(t *testing.T) {
	var dispatches atomic.Int32
	emb, err := New(Config{
		Secrets:       map[string]string{mapProjectA: mapSecretA, mapProjectB: mapSecretB},
		FetchURL:      "https://app.replypen.com/actions/script",
		Now:           func() time.Time { return mapReferenceClock },
		ResultHandler: func(Result) error { dispatches.Add(1); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"analysis_id":"map-result","project_id":"` + mapProjectA + `","nonce":"map-result","issued_at":"2026-06-20T00:00:00Z"}`)

	t.Run("map hit dispatches and signs ack", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/result", bytes.NewReader(body))
		req.Header.Set(SignatureHeader, Sign(body, mapSecretA))
		rec := httptest.NewRecorder()
		emb.ResultHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !VerifySignature(rec.Header().Get(SignatureHeader), rec.Body.Bytes(), mapSecretA) {
			t.Fatalf("response = %d %s", rec.Code, rec.Body)
		}
		if dispatches.Load() != 1 {
			t.Fatalf("dispatches = %d", dispatches.Load())
		}
	})

	t.Run("sibling key refuses with selected-key signature", func(t *testing.T) {
		second := bytes.Replace(body, []byte("map-result"), []byte("map-result-2"), 1)
		req := httptest.NewRequest(http.MethodPost, "/result", bytes.NewReader(second))
		req.Header.Set(SignatureHeader, Sign(second, mapSecretB))
		rec := httptest.NewRecorder()
		emb.ResultHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || !VerifySignature(rec.Header().Get(SignatureHeader), rec.Body.Bytes(), mapSecretA) {
			t.Fatalf("response = %d %s", rec.Code, rec.Body)
		}
		if dispatches.Load() != 1 {
			t.Fatalf("sibling signature dispatched: %d", dispatches.Load())
		}
	})

	t.Run("unknown selector is unsigned and not recorded", func(t *testing.T) {
		unknown := bytes.Replace(body, []byte(mapProjectA), []byte(mapProjectB[:len(mapProjectB)-1]+"3"), 1)
		req := httptest.NewRequest(http.MethodPost, "/result", bytes.NewReader(unknown))
		req.Header.Set(SignatureHeader, Sign(unknown, mapSecretB))
		rec := httptest.NewRecorder()
		emb.ResultHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get(SignatureHeader) != "" {
			t.Fatalf("response = %d signature=%q", rec.Code, rec.Header().Get(SignatureHeader))
		}
		if dispatches.Load() != 1 {
			t.Fatalf("unknown selector dispatched: %d", dispatches.Load())
		}
	})
}

func TestSingleSecretAcceptsLegacyResultWithoutProjectID(t *testing.T) {
	called := false
	emb, err := New(Config{
		Secret:        mapSecretA,
		FetchURL:      "https://app.replypen.com/actions/script",
		Now:           func() time.Time { return mapReferenceClock },
		ResultHandler: func(Result) error { called = true; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"analysis_id":"legacy-result","nonce":"legacy-result","issued_at":"2026-06-20T00:00:00Z"}`)
	req := httptest.NewRequest(http.MethodPost, "/result", bytes.NewReader(body))
	req.Header.Set(SignatureHeader, Sign(body, mapSecretA))
	rec := httptest.NewRecorder()
	emb.ResultHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !VerifySignature(rec.Header().Get(SignatureHeader), rec.Body.Bytes(), mapSecretA) || !called {
		t.Fatalf("legacy result = %d signed=%t called=%t", rec.Code, VerifySignature(rec.Header().Get(SignatureHeader), rec.Body.Bytes(), mapSecretA), called)
	}
}

func TestHealthSecretMapSelection(t *testing.T) {
	emb, err := New(Config{Secrets: map[string]string{mapProjectA: mapSecretA}, FetchURL: "https://app.replypen.com/actions/script"})
	if err != nil {
		t.Fatal(err)
	}
	query := "project_id=" + mapProjectA
	req := httptest.NewRequest(http.MethodGet, "/action/health?"+query, nil)
	req.Header.Set(SignatureHeader, Sign([]byte(query), mapSecretA))
	rec := httptest.NewRecorder()
	emb.ActionHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !VerifySignature(rec.Header().Get(SignatureHeader), rec.Body.Bytes(), mapSecretA) {
		t.Fatalf("health response = %d %s", rec.Code, rec.Body)
	}

	req = httptest.NewRequest(http.MethodGet, "/action/health?project_id="+mapProjectB, nil)
	req.Header.Set(SignatureHeader, Sign([]byte(req.URL.RawQuery), mapSecretB))
	rec = httptest.NewRecorder()
	emb.ActionHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || rec.Header().Get(SignatureHeader) != "" {
		t.Fatalf("unknown health response = %d signature=%q", rec.Code, rec.Header().Get(SignatureHeader))
	}
}
