package embassy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// resolver produces a digest-verified script body. The digest IS the
// authorization unit: a body runs iff sha256(body) equals the digest inside the
// signed invocation, so every body — memory hit, disk hit or fresh fetch — is
// re-hashed here before it leaves. The cache is therefore immutable and
// self-verifying; a tampered entry simply fails the hash and is re-fetched.
//
// Lookup order: memory → disk (optional) → signed HTTP GET.
type resolver struct {
	cfg *Config

	mu     sync.RWMutex
	memory map[string]string // cache key (project + digest in map mode) → verified body
}

func newResolver(cfg *Config) *resolver {
	return &resolver{cfg: cfg, memory: map[string]string{}}
}

var hexDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// digestHex strips the `sha256:` label and validates the shape, so a malformed
// digest can never become a cache filename and therefore never a path traversal.
func digestHex(digest string) (string, error) {
	raw := strings.ToLower(strings.TrimPrefix(digest, "sha256:"))
	if !hexDigestPattern.MatchString(raw) {
		return "", resolveFailed("malformed script_digest")
	}
	return raw, nil
}

func (r *resolver) resolve(ctx context.Context, actionID, digest, projectID string) (string, error) {
	if _, ok := r.cfg.secretForProject(projectID); !ok {
		return "", resolveFailed("project secret unavailable")
	}
	hexDigest, err := digestHex(digest)
	if err != nil {
		return "", err
	}

	if body, ok := r.fromCacheForProject(hexDigest, projectID); ok {
		return body, nil
	}

	body, err := r.fetch(ctx, actionID, digest, projectID)
	if err != nil {
		return "", err
	}
	if sha256Hex(body) != hexDigest {
		return "", resolveFailed("digest mismatch: fetched body does not hash to script_digest")
	}
	r.storeForProject(hexDigest, projectID, body)
	return body, nil
}

func (r *resolver) fromCacheForProject(hexDigest, projectID string) (string, bool) {
	key := r.cacheKey(hexDigest, projectID)
	r.mu.RLock()
	body, ok := r.memory[key]
	r.mu.RUnlock()
	if ok {
		return body, true
	}

	path := r.diskPathForProject(hexDigest, projectID)
	if path == "" {
		return "", false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	// Disk is shared, mutable state — re-verify before trusting or promoting.
	if sha256Hex(string(raw)) != hexDigest {
		return "", false
	}
	body = string(raw)
	r.mu.Lock()
	r.memory[key] = body
	r.mu.Unlock()
	return body, true
}

func (r *resolver) storeForProject(hexDigest, projectID, body string) {
	key := r.cacheKey(hexDigest, projectID)
	r.mu.Lock()
	r.memory[key] = body
	r.mu.Unlock()

	path := r.diskPathForProject(hexDigest, projectID)
	if path == "" {
		return
	}
	// Disk caching is best-effort — memory already holds the body — but the write
	// is atomic (temp + rename) so a concurrent reader never sees a half body.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+hexDigest+".*")
	if err != nil {
		return
	}
	name := tmp.Name()
	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
	}
}

func (r *resolver) diskPathForProject(hexDigest, projectID string) string {
	if r.cfg.CacheDir == "" || !hexDigestPattern.MatchString(hexDigest) {
		return ""
	}
	if len(r.cfg.Secrets) > 0 {
		if !validProjectID(projectID) {
			return ""
		}
		return filepath.Join(r.cfg.CacheDir, strings.ToLower(projectID), hexDigest+".go")
	}
	return filepath.Join(r.cfg.CacheDir, hexDigest+".go")
}

func (r *resolver) cacheKey(hexDigest, projectID string) string {
	if len(r.cfg.Secrets) == 0 {
		return hexDigest
	}
	return strings.ToLower(projectID) + ":" + hexDigest
}

type fetchResponse struct {
	ActionID string `json:"action_id"`
	Digest   string `json:"digest"`
	Script   string `json:"script"`
	Runtime  string `json:"runtime"`
}

// fetch signs the RAW query string (a GET has no body) with the params in the
// exact contract order: action_id, digest, project_id.
func (r *resolver) fetch(ctx context.Context, actionID, digest, projectID string) (string, error) {
	secret, ok := r.cfg.secretForProject(projectID)
	if !ok {
		return "", resolveFailed("project secret unavailable")
	}
	query := "action_id=" + url.QueryEscape(actionID) +
		"&digest=" + url.QueryEscape(digest) +
		"&project_id=" + url.QueryEscape(projectID)

	target, err := url.Parse(r.cfg.FetchURL)
	if err != nil {
		return "", resolveFailed("fetch_url is not a valid URL")
	}
	target.RawQuery = query

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return "", resolveFailed("script fetch request could not be built")
	}
	request.Header.Set(SignatureHeader, Sign([]byte(query), secret))

	response, err := r.cfg.HTTPClient.Do(request)
	if err != nil {
		// Transport / TLS / timeout all collapse to a fail-closed refusal: the run
		// never proceeds without a verified body.
		return "", resolveFailed("script fetch failed")
	}
	defer func() { _ = response.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return "", resolveFailed("script fetch response could not be read")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", resolveFailed("script fetch returned %d", response.StatusCode)
	}
	// The script's integrity rests on the digest, but the channel is signed both
	// ways: an unsigned or mis-signed response is a hard refuse, so a misconfigured
	// host fails closed instead of feeding us an attacker's body.
	if !VerifySignature(response.Header.Get(SignatureHeader), raw, secret) {
		return "", resolveFailed("script fetch response signature invalid")
	}

	var payload fetchResponse
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", resolveFailed("script fetch response was not valid JSON")
	}
	if payload.Script == "" {
		return "", resolveFailed("script fetch response missing script")
	}
	if payload.Digest != "" && payload.Digest != digest {
		return "", resolveFailed("script fetch returned a different digest")
	}
	// A body written for another runtime must never be interpreted as Go.
	if payload.Runtime != "" && payload.Runtime != RuntimeToken {
		return "", resolveFailed("script fetch returned runtime %q", payload.Runtime)
	}
	return payload.Script, nil
}

func sha256Hex(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}
