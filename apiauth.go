package embassy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// oauthClientID is the OAuth client a machine credential is issued for — the
	// same one the rc CLI uses.
	oauthClientID = "rcocl_cli"
	// refreshPrefix marks the only key shape we exchange. Anything else is used
	// verbatim as the bearer, so a static-bearer deployment needs no code change.
	refreshPrefix = "rcor_"
	// expirySkew refreshes early so a call starting just before the boundary never
	// lands with a dead token.
	expirySkew = 60 * time.Second
	// defaultExpiresIn is the fallback lifetime when the host omits expires_in.
	defaultExpiresIn = 3600 * time.Second
)

type tokenCacheKey struct {
	baseURL string
	apiKey  string
}

type cachedToken struct {
	// mu serializes the exchange so concurrent callers do it once (single-flight),
	// and keeps the per-credential caches independent of one another.
	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

var (
	tokenCacheMu sync.Mutex
	tokenCache   = map[tokenCacheKey]*cachedToken{}
)

func isExchangeableKey(apiKey string) bool { return strings.HasPrefix(apiKey, refreshPrefix) }

func tokenEntry(key tokenCacheKey) *cachedToken {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	entry, ok := tokenCache[key]
	if !ok {
		entry = &cachedToken{}
		tokenCache[key] = entry
	}
	return entry
}

func invalidateToken(baseURL, apiKey string) {
	entry := tokenEntry(tokenCacheKey{baseURL, apiKey})
	entry.mu.Lock()
	entry.token, entry.expiresAt = "", time.Time{}
	entry.mu.Unlock()
}

// bearerFor resolves the Authorization value: an `rcor_` refresh token is exchanged
// for a short-lived access token and cached in-process per (base URL, key);
// anything else is the bearer itself.
//
// The deadline rides Go's monotonic clock, so an NTP jump or a suspend cannot make
// a dead token look live.
func bearerFor(ctx context.Context, cfg *Config, baseURL, apiKey string) (string, error) {
	if !isExchangeableKey(apiKey) {
		return apiKey, nil
	}
	entry := tokenEntry(tokenCacheKey{baseURL, apiKey})

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.token != "" && time.Now().Before(entry.expiresAt.Add(-expirySkew)) {
		return entry.token, nil
	}

	token, expiresIn, err := exchangeRefreshToken(ctx, cfg, baseURL, apiKey)
	if err != nil {
		return "", err
	}
	entry.token, entry.expiresAt = token, time.Now().Add(expiresIn)
	return token, nil
}

type tokenResponse struct {
	AccessToken string  `json:"access_token"`
	ExpiresIn   float64 `json:"expires_in"`
	TokenType   string  `json:"token_type"`
}

func exchangeRefreshToken(ctx context.Context, cfg *Config, baseURL, refreshToken string) (string, time.Duration, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {oauthClientID},
	}
	endpoint := strings.TrimSuffix(baseURL, "/") + "/oauth/token"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("token exchange request could not be built")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := cfg.HTTPClient.Do(request)
	if err != nil {
		return "", 0, fmt.Errorf("token exchange transport error")
	}
	defer func() { _ = response.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", 0, fmt.Errorf("token exchange response could not be read")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", 0, fmt.Errorf("token exchange failed: http_%d", response.StatusCode)
	}
	var payload tokenResponse
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", 0, fmt.Errorf("token exchange response was not valid JSON")
	}
	if payload.AccessToken == "" {
		return "", 0, fmt.Errorf("token exchange response missing access_token")
	}
	expiresIn := defaultExpiresIn
	if payload.ExpiresIn > 0 {
		expiresIn = time.Duration(payload.ExpiresIn) * time.Second
	}
	return payload.AccessToken, expiresIn, nil
}
