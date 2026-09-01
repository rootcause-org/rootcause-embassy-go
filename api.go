package embassy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrMisconfigured marks a deploy or caller bug (unset base URL or key, blank
// path, off-origin URL, unsupported verb) rather than a call outcome. It is the
// one thing the API plane refuses to bury in a response.
var ErrMisconfigured = errors.New("embassy: api misconfigured")

// APIResponse is the outcome of one API call. Every outcome is a value — transport
// failure, auth failure, 4xx, 5xx, 2xx — so a background job decides retry from
// Retryable instead of catching anything.
type APIResponse struct {
	OK     bool
	Status int
	// Body is parsed JSON when it parses, else the raw string, else nil.
	Body any
	// FieldErrors carries the host's per-field rejections from a 4xx
	// validation_failed body.
	FieldErrors map[string]any
	// Error is the host's error/message, or http_<status>, or the transport/auth reason.
	Error string
	// Retryable is true for transport failures, auth failures, 5xx, 429 and 408.
	// 429/408 are backpressure, not a contract break; every other 4xx is a genuine
	// caller error where a retry only burns quota.
	Retryable bool
	// Err is set for a misconfiguration (wrapping ErrMisconfigured) or the
	// underlying transport error.
	Err error
}

// API is a generic authenticated caller for ANY rootcause endpoint — transport and
// auth only, never per-endpoint wrappers, so a new host endpoint is usable the day
// it ships with no Embassy release. What endpoints exist is the host's contract.
type API struct {
	cfg     *Config
	baseURL string
	apiKey  string
}

func newAPI(cfg *Config, baseURL, apiKey string) *API {
	return &API{cfg: cfg, baseURL: baseURL, apiKey: apiKey}
}

func (a *API) Get(ctx context.Context, path string, params url.Values) APIResponse {
	return a.Do(ctx, http.MethodGet, path, nil, params)
}

func (a *API) Post(ctx context.Context, path string, body any, params url.Values) APIResponse {
	return a.Do(ctx, http.MethodPost, path, body, params)
}

func (a *API) Patch(ctx context.Context, path string, body any, params url.Values) APIResponse {
	return a.Do(ctx, http.MethodPatch, path, body, params)
}

func (a *API) Put(ctx context.Context, path string, body any, params url.Values) APIResponse {
	return a.Do(ctx, http.MethodPut, path, body, params)
}

func (a *API) Delete(ctx context.Context, path string, body any, params url.Values) APIResponse {
	return a.Do(ctx, http.MethodDelete, path, body, params)
}

// Do performs one call. body is JSON-encoded (a string or []byte rides verbatim);
// params become the query string.
func (a *API) Do(ctx context.Context, method, path string, body any, params url.Values) APIResponse {
	target, err := a.buildURL(path, params)
	if err != nil {
		return misconfigured(err)
	}
	payload, err := encodeAPIBody(body)
	if err != nil {
		return misconfigured(causedError("API_REQUEST_INVALID", "Pass a JSON-encodable request body.", ErrMisconfigured))
	}

	bearer, err := bearerFor(ctx, a.cfg, a.baseURL, a.apiKey)
	if err != nil {
		// Auth failure is retryable: the credential is usually fine and the exchange
		// endpoint was merely unreachable or unhappy.
		return APIResponse{Error: errorCode(err), Retryable: true, Err: typedAPIError(err)}
	}

	response, raw, err := a.perform(ctx, method, target, bearer, payload)
	if err != nil {
		if errors.Is(err, ErrMisconfigured) {
			return misconfigured(err)
		}
		return APIResponse{Error: "API_TRANSPORT_ERROR", Retryable: true, Err: causedError("API_TRANSPORT_ERROR", "The ReplyPen API could not be reached; retry after checking network connectivity.", err)}
	}

	// A token we believed live can still be refused (host restart, revocation).
	// Burn it, re-exchange exactly ONCE, and accept the second answer as final.
	if response.StatusCode == http.StatusUnauthorized && isExchangeableKey(a.apiKey) {
		invalidateToken(a.baseURL, a.apiKey)
		bearer, err = bearerFor(ctx, a.cfg, a.baseURL, a.apiKey)
		if err != nil {
			return APIResponse{Error: errorCode(err), Retryable: true, Err: typedAPIError(err)}
		}
		response, raw, err = a.perform(ctx, method, target, bearer, payload)
		if err != nil {
			return APIResponse{Error: "API_TRANSPORT_ERROR", Retryable: true, Err: causedError("API_TRANSPORT_ERROR", "The ReplyPen API could not be reached; retry after checking network connectivity.", err)}
		}
	}

	// Verb, PATH and status only — never the bearer, never the body, never the
	// query string (it can carry identifiers).
	a.cfg.logger().Info("rootcause api call", "method", method, "path", target.Path, "status", response.StatusCode)

	parsed := parseAPIBody(raw)
	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		return APIResponse{OK: true, Status: response.StatusCode, Body: parsed}
	}

	result := APIResponse{
		Status:    response.StatusCode,
		Body:      parsed,
		Error:     fmt.Sprintf("http_%d", response.StatusCode),
		Retryable: retryableStatus(response.StatusCode),
	}
	refusal := hostRefusal(parsed, response.StatusCode)
	result.Err = refusal
	if object, ok := parsed.(map[string]any); ok {
		if fieldErrors, ok := object["field_errors"].(map[string]any); ok {
			result.FieldErrors = fieldErrors
		}
		for _, key := range []string{"error", "message"} {
			if message, ok := object[key].(string); ok && message != "" {
				result.Error = message
				break
			}
		}
		if code, ok := object["code"].(string); ok && code != "" {
			result.Error = code
		}
	}
	if refusal.Code() != "HOST_REFUSED" {
		result.Error = refusal.Code()
	}
	return result
}

func (a *API) perform(ctx context.Context, method string, target *url.URL, bearer string, payload []byte) (*http.Response, []byte, error) {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:
	default:
		return nil, nil, causedError("API_METHOD_INVALID", "Use GET, POST, PATCH, PUT, or DELETE for API calls.", ErrMisconfigured)
	}

	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return nil, nil, causedError("API_REQUEST_INVALID", "Use a valid API path and request payload.", ErrMisconfigured)
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := a.cfg.HTTPClient.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return nil, nil, err
	}
	return response, raw, nil
}

// buildURL joins path onto the configured origin. An absolute URL is accepted ONLY
// on that same origin — a typo must not leak the bearer to another host.
func (a *API) buildURL(path string, params url.Values) (*url.URL, error) {
	if a.baseURL == "" {
		return nil, causedError("API_BASE_URL_REQUIRED", "Set ROOTCAUSE_API_BASE_URL before calling the API plane.", ErrMisconfigured)
	}
	if a.apiKey == "" {
		return nil, causedError("API_KEY_REQUIRED", "Set ROOTCAUSE_API_KEY before calling the API plane.", ErrMisconfigured)
	}
	if path == "" {
		return nil, causedError("API_PATH_REQUIRED", "Pass a non-blank API path such as /api/v1/projects.", ErrMisconfigured)
	}
	base, err := url.Parse(strings.TrimSuffix(a.baseURL, "/"))
	if err != nil || !isAbsoluteHTTPURL(a.baseURL) {
		return nil, causedError("API_BASE_URL_INVALID", "Set ROOTCAUSE_API_BASE_URL to an absolute http or https URL.", ErrMisconfigured)
	}

	target, err := url.Parse(path)
	if err != nil {
		return nil, causedError("API_PATH_INVALID", "Pass a valid relative path or a URL on ROOTCAUSE_API_BASE_URL.", ErrMisconfigured)
	}
	if target.IsAbs() {
		if target.Scheme != base.Scheme || target.Host != base.Host {
			return nil, causedError("API_ORIGIN_MISMATCH", "Keep absolute API paths on the configured ROOTCAUSE_API_BASE_URL origin.", ErrMisconfigured)
		}
	} else {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		target, err = url.Parse(base.String() + path)
		if err != nil {
			return nil, causedError("API_PATH_INVALID", "Pass a valid relative API path.", ErrMisconfigured)
		}
	}

	if len(params) > 0 {
		query := target.Query()
		for key, values := range params {
			for _, value := range values {
				query.Add(key, value)
			}
		}
		target.RawQuery = query.Encode()
	}
	return target, nil
}

func encodeAPIBody(body any) ([]byte, error) {
	switch v := body.(type) {
	case nil:
		return nil, nil
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		return json.Marshal(v)
	}
}

func parseAPIBody(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return string(raw)
	}
	return value
}

func retryableStatus(status int) bool {
	return status >= 500 || status == http.StatusTooManyRequests || status == http.StatusRequestTimeout
}

func misconfigured(err error) APIResponse {
	return APIResponse{Error: errorCode(err), Err: typedAPIError(err)}
}

func typedAPIError(err error) error {
	var typed *Error
	if errors.As(err, &typed) {
		return typed
	}
	return causedError("API_TRANSPORT_ERROR", "The ReplyPen API request failed; retry after checking connectivity.", err)
}

func errorCode(err error) string {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code()
	}
	return "API_TRANSPORT_ERROR"
}

func hostRefusal(parsed any, status int) *Error {
	code := "HOST_REFUSED"
	hint := fmt.Sprintf("ReplyPen refused the API request with HTTP %d; check the request and the project configuration.", status)
	docs := ""
	object, _ := parsed.(map[string]any)
	if nested, ok := object["error"].(map[string]any); ok {
		object = nested
	}
	if value, ok := object["code"].(string); ok && value != "" {
		code = value
	}
	if value, ok := object["hint"].(string); ok && value != "" {
		hint = value
	} else if value, ok := object["message"].(string); ok && value != "" {
		hint = value
	}
	if value, ok := object["docs"].(string); ok && value != "" {
		docs = value
	}
	err := publicError(code, hint)
	if docs != "" {
		err.Docs = docs
	}
	err.Status = status
	return err
}
