package embassy

import (
	"context"
	"encoding/json"
	"errors"
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

func isExchangeableKey(apiKey string) bool { return strings.HasPrefix(apiKey, refreshPrefix) }

// apiAuth is ONE caller's access-token cache. The cache key is the API value it
// belongs to — an API is pinned to a single (base URL, api key) pair — so two
// callers for two projects can never hand each other a token, and a caller that
// is garbage-collected takes its token with it.
type apiAuth struct {
	// mu serializes the exchange so concurrent callers do it once (single-flight).
	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// invalidate burns the cached token after the host refused it.
func (a *apiAuth) invalidate() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token, a.expiresAt = "", time.Time{}
}

// bearer resolves the Authorization value: an `rcor_` refresh token is exchanged
// for a short-lived access token and cached on this caller; anything else is the
// bearer itself.
//
// The deadline rides Go's monotonic clock, so an NTP jump or a suspend cannot make
// a dead token look live.
func (a *API) bearer(ctx context.Context) (string, error) {
	if !isExchangeableKey(a.apiKey) {
		return a.apiKey, nil
	}
	a.auth.mu.Lock()
	defer a.auth.mu.Unlock()
	if a.auth.token != "" && time.Now().Before(a.auth.expiresAt.Add(-expirySkew)) {
		return a.auth.token, nil
	}

	token, expiresIn, err := exchangeRefreshToken(ctx, a.cfg, a.baseURL, a.apiKey)
	if err != nil {
		return "", err
	}
	a.auth.token, a.auth.expiresAt = token, time.Now().Add(expiresIn)
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
		return "", 0, causedError("TOKEN_EXCHANGE_FAILED", err).WithDetail("the token request could not be built")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	answer, err := doHTTP(cfg.HTTPClient, request, tokenReadLimit)
	if err != nil {
		if errors.Is(err, errHTTPRead) {
			return "", 0, causedError("TOKEN_EXCHANGE_FAILED", err).WithDetail("the token response could not be read")
		}
		return "", 0, causedError("API_TRANSPORT_ERROR", err).WithDetail("oauth token exchange")
	}
	raw := answer.Body
	if answer.Status < 200 || answer.Status > 299 {
		return "", 0, hostRefusal(parseAPIBody(raw), answer.Status)
	}
	var payload tokenResponse
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", 0, causedError("TOKEN_EXCHANGE_FAILED", err).WithDetail("the token response was not valid JSON")
	}
	if payload.AccessToken == "" {
		return "", 0, publicError("TOKEN_EXCHANGE_FAILED").WithDetail("the token response omitted access_token")
	}
	expiresIn := defaultExpiresIn
	if payload.ExpiresIn > 0 {
		expiresIn = time.Duration(payload.ExpiresIn) * time.Second
	}
	return payload.AccessToken, expiresIn, nil
}
