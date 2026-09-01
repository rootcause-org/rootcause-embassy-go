package embassy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const testSecret = "test-reverse-secret"

func testConfig(t *testing.T, fetchURL string) *Config {
	t.Helper()
	cfg := &Config{Secret: testSecret, FetchURL: fetchURL}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func TestDigestHexRejectsTraversal(t *testing.T) {
	for _, bad := range []string{
		"sha256:../../etc/passwd",
		"sha256:" + strings.Repeat("z", 64),
		"sha256:abc",
		"",
		strings.Repeat("a", 63),
	} {
		if _, err := digestHex(bad); err == nil {
			t.Fatalf("digestHex(%q) was accepted", bad)
		} else if err.(*Error).Class != ClassResolveFailed {
			t.Fatalf("digestHex(%q) class = %s", bad, err.(*Error).Class)
		}
	}
	// Case is normalized; the `sha256:` label is optional on the wire value.
	got, err := digestHex("sha256:" + strings.ToUpper(strings.Repeat("ab", 32)))
	if err != nil || got != strings.Repeat("ab", 32) {
		t.Fatalf("digestHex = %q, %v", got, err)
	}
}

func scriptHost(t *testing.T, script string, sign bool) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(map[string]string{
			"action_id": r.URL.Query().Get("action_id"),
			"digest":    r.URL.Query().Get("digest"),
			"script":    script,
		})
		if sign {
			w.Header().Set(SignatureHeader, Sign(body, testSecret))
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestResolverVerifiesDigestAndSignature(t *testing.T) {
	const script = "package action\n"
	digest := "sha256:" + sha256Hex(script)

	t.Run("happy path caches on disk and re-verifies on read", func(t *testing.T) {
		server := scriptHost(t, script, true)
		cfg := testConfig(t, server.URL)
		cfg.CacheDir = t.TempDir()
		r := newResolver(cfg)

		body, err := r.resolve(context.Background(), "a", digest, "p")
		if err != nil || body != script {
			t.Fatalf("resolve = %q, %v", body, err)
		}
		path := filepath.Join(cfg.CacheDir, sha256Hex(script)+".go")
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("disk cache: %v", err)
		}

		// A tampered disk entry simply fails its hash and is re-fetched, never run.
		if err := os.WriteFile(path, []byte("package evil\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		fresh := newResolver(cfg)
		body, err = fresh.resolve(context.Background(), "a", digest, "p")
		if err != nil || body != script {
			t.Fatalf("tampered cache resolve = %q, %v", body, err)
		}
	})

	t.Run("digest mismatch never runs", func(t *testing.T) {
		server := scriptHost(t, script, true)
		r := newResolver(testConfig(t, server.URL))
		_, err := r.resolve(context.Background(), "a", "sha256:"+strings.Repeat("ab", 32), "p")
		if err == nil || err.(*Error).Class != ClassResolveFailed {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an unsigned fetch response is a hard refuse", func(t *testing.T) {
		server := scriptHost(t, script, false)
		r := newResolver(testConfig(t, server.URL))
		if _, err := r.resolve(context.Background(), "a", digest, "p"); err == nil ||
			!strings.Contains(err.(*Error).Message, "signature invalid") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a non-2xx fetch is a resolve failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer server.Close()
		r := newResolver(testConfig(t, server.URL))
		if _, err := r.resolve(context.Background(), "a", digest, "p"); err == nil ||
			err.(*Error).Status != 502 {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestResolverMapCacheIsPartitionedByProject(t *testing.T) {
	const script = "package action\n"
	digest := "sha256:" + sha256Hex(script)
	var fetches atomic.Int32
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		secrets := map[string]string{mapProjectA: mapSecretA, mapProjectB: mapSecretB}
		secret := secrets[r.URL.Query().Get("project_id")]
		body, _ := json.Marshal(map[string]string{
			"action_id": r.URL.Query().Get("action_id"),
			"digest":    r.URL.Query().Get("digest"),
			"script":    script,
			"runtime":   "go",
		})
		w.Header().Set(SignatureHeader, Sign(body, secret))
		_, _ = w.Write(body)
	}))
	defer host.Close()

	cfg := &Config{
		Secrets:  map[string]string{mapProjectA: mapSecretA, mapProjectB: mapSecretB},
		FetchURL: host.URL,
		CacheDir: t.TempDir(),
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	r := newResolver(cfg)
	for _, projectID := range []string{mapProjectA, mapProjectB} {
		if got, err := r.resolve(context.Background(), "same-action", digest, projectID); err != nil || got != script {
			t.Fatalf("resolve(%s) = %q, %v", projectID, got, err)
		}
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("fetches = %d, want one authorized fetch per project", got)
	}
	if _, err := os.Stat(filepath.Join(cfg.CacheDir, mapProjectA, sha256Hex(script)+".go")); err != nil {
		t.Fatalf("project A cache path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.CacheDir, mapProjectB, sha256Hex(script)+".go")); err != nil {
		t.Fatalf("project B cache path: %v", err)
	}
}
