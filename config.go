package embassy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Version is this Embassy's release, surfaced by the health endpoint.
const Version = "0.1.0"

// Protocol is the wire protocol generation. Bumped ONLY on a breaking change:
// additive fields stay non-breaking because the action/result direction decodes
// tolerantly.
const Protocol = 1

// RuntimeToken is the `runtime` value this Embassy implements. Anything else is a
// hard 400 invalid_request — never a best-effort interpretation.
const RuntimeToken = "go"

// placeholderFetchURL is the inert default: reaching a script fetch with it means
// ROOTCAUSE_FETCH_URL was never set. Caught at boot, not on the first invocation.
const placeholderFetchURL = "https://rootcause.invalid/actions/script"

// Config is set once at boot and treated as immutable afterwards. Every string
// field falls back to its ROOTCAUSE_* environment variable when left empty.
type Config struct {
	// Secret is the per-project action_reverse_secret: the HMAC key for BOTH the
	// action and analysis planes. Never the chat webhook_secret, never the API key,
	// and no fallback in any direction. Env: ROOTCAUSE_ACTION_SECRET.
	Secret string

	// FetchURL is the host's script-by-digest endpoint, hit on a cache miss.
	// Env: ROOTCAUSE_FETCH_URL.
	FetchURL string

	// TriggerURL is where StartAnalysis POSTs, e.g.
	// "https://app.replypen.com/analyses/<project>". Env: ROOTCAUSE_TRIGGER_URL.
	TriggerURL string

	// SentMessageURL is where CaptureSentMessage POSTs (sent replies AND answers to
	// a run's questions). Env: ROOTCAUSE_SENT_MESSAGE_URL.
	SentMessageURL string

	// APIBaseURL / APIKey wire the generic API plane — a THIRD privilege boundary,
	// bearer-authed, never the HMAC secret. An `rcor_` key is exchanged for a
	// short-lived access token; anything else is used verbatim as the bearer.
	// Env: ROOTCAUSE_API_BASE_URL, ROOTCAUSE_API_KEY.
	APIBaseURL string
	APIKey     string

	// ChatSecret is the project's webhook_secret, used ONLY to mint embed-chat
	// tokens. A leaked chat key must not buy action execution, so it must differ
	// from Secret. Env: ROOTCAUSE_CHAT_SECRET.
	ChatSecret string
	// ChatProject is the rootcause project the token is issued for (public — it
	// ships in the widget tag). Env: ROOTCAUSE_CHAT_PROJECT.
	ChatProject string
	// ChatBaseURL is the origin serving the hosted widget loader.
	// Env: ROOTCAUSE_CHAT_BASE_URL.
	ChatBaseURL string

	// ResultHandler receives each analysis result callback. It MUST be idempotent:
	// an unexpected error is deliberately not an ack, so the host redelivers.
	// Unset → the result route fails closed with handler_error.
	ResultHandler func(Result) error

	// Timeout bounds ONE script execution. Must stay under TotalDeadline so it is
	// the one that fires on a slow body. Default 20s.
	Timeout time.Duration

	// TotalDeadline bounds script fetch AND execution together. The host waits 25s
	// one-shot with no retry, so our signed refusal must beat its cutoff.
	// Default 22s.
	TotalDeadline time.Duration

	// ClockSkew is the symmetric freshness half-window. Default 300s.
	ClockSkew time.Duration

	// RequireTenantContext refuses a validly signed invocation that carries no
	// tenant tuple, before script resolution. Tenant-enabled deployments set it.
	RequireTenantContext bool

	// CacheDir persists digest-keyed script bodies across restarts. Empty (the
	// default) keeps the cache in memory only. The cache is self-verifying: every
	// disk read is re-hashed before it is trusted.
	CacheDir string

	// MaxStdoutBytes caps what a script writes to ActionAPI.Out() before it is
	// truncated into the wire `stdout`. Default 64 KiB.
	MaxStdoutBytes int

	// MaxAttachmentBytes caps a single StartAnalysis attachment in DECODED bytes;
	// over-cap raises before anything is sent. Default 256 KiB.
	MaxAttachmentBytes int

	// Symbols are exported into every script interpreter as package `rcsymbols`
	// (e.g. Symbols["DB"] reaches the script as rcsymbols.DB). Names must be
	// exported (capitalized) to be visible, exactly like real Go.
	Symbols map[string]any

	// NonceStore defaults to an in-process store — correct for ONE process only.
	// Inject a shared store in a multi-worker deployment.
	NonceStore NonceStore

	// Logger is optional. Identifiers, shapes and byte counts only ever reach it:
	// never values, bodies, secrets, bearers or query strings.
	Logger *slog.Logger

	// HTTPClient is used for every outbound call (script fetch, trigger,
	// sent-message, API plane). Defaults to a client with a 20s timeout.
	HTTPClient *http.Client

	// Now and Nonce are determinism seams for tests and conformance replay.
	Now   func() time.Time
	Nonce func() string
}

func (c *Config) applyDefaults() {
	c.Secret = orEnv(c.Secret, "ROOTCAUSE_ACTION_SECRET")
	c.FetchURL = orEnv(c.FetchURL, "ROOTCAUSE_FETCH_URL")
	c.TriggerURL = orEnv(c.TriggerURL, "ROOTCAUSE_TRIGGER_URL")
	c.SentMessageURL = orEnv(c.SentMessageURL, "ROOTCAUSE_SENT_MESSAGE_URL")
	c.APIBaseURL = orEnv(c.APIBaseURL, "ROOTCAUSE_API_BASE_URL")
	c.APIKey = orEnv(c.APIKey, "ROOTCAUSE_API_KEY")
	c.ChatSecret = orEnv(c.ChatSecret, "ROOTCAUSE_CHAT_SECRET")
	c.ChatProject = orEnv(c.ChatProject, "ROOTCAUSE_CHAT_PROJECT")
	c.ChatBaseURL = orEnv(c.ChatBaseURL, "ROOTCAUSE_CHAT_BASE_URL")

	if c.FetchURL == "" {
		c.FetchURL = placeholderFetchURL
	}
	if c.Timeout == 0 {
		c.Timeout = 20 * time.Second
	}
	if c.TotalDeadline == 0 {
		c.TotalDeadline = 22 * time.Second
	}
	if c.ClockSkew == 0 {
		c.ClockSkew = 300 * time.Second
	}
	if c.MaxStdoutBytes == 0 {
		c.MaxStdoutBytes = 64 * 1024
	}
	if c.MaxAttachmentBytes == 0 {
		c.MaxAttachmentBytes = 256 * 1024
	}
	if c.NonceStore == nil {
		c.NonceStore = NewMemoryNonceStore()
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Nonce == nil {
		c.Nonce = newUUID
	}
}

// validate fails closed at BOOT rather than on the first invocation: every check
// here catches a deployment mistake, not a runtime condition.
func (c *Config) validate() error {
	if c.Secret == "" {
		return fmt.Errorf("embassy: Secret is required (ROOTCAUSE_ACTION_SECRET) — HMAC with a blank key is trivially forgeable")
	}
	if isPlaceholderFetchURL(c.FetchURL) {
		return fmt.Errorf("embassy: FetchURL is the placeholder (%s) — set ROOTCAUSE_FETCH_URL to the host's script endpoint", c.FetchURL)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("embassy: Timeout must be positive")
	}
	if c.TotalDeadline <= c.Timeout {
		return fmt.Errorf("embassy: TotalDeadline (%s) must exceed Timeout (%s) — the execute backstop has to fire inside the invocation budget, not after it", c.TotalDeadline, c.Timeout)
	}
	if c.ClockSkew <= 0 {
		return fmt.Errorf("embassy: ClockSkew must be positive")
	}
	if err := c.validateAPI(); err != nil {
		return err
	}
	return c.validateChat()
}

// The API plane is opt-in, but a HALF-wired one is a boot mistake rather than a
// first-call surprise in a background job.
func (c *Config) validateAPI() error {
	if c.APIBaseURL == "" && c.APIKey == "" {
		return nil
	}
	if c.APIBaseURL == "" {
		return fmt.Errorf("embassy: APIBaseURL is required when APIKey is set")
	}
	if c.APIKey == "" {
		return fmt.Errorf("embassy: APIKey is required when APIBaseURL is set")
	}
	if !isAbsoluteHTTPURL(c.APIBaseURL) {
		return fmt.Errorf("embassy: APIBaseURL must be an absolute http(s) URL")
	}
	return nil
}

func (c *Config) validateChat() error {
	if c.ChatSecret == "" && c.ChatProject == "" && c.ChatBaseURL == "" {
		return nil
	}
	if c.ChatSecret == "" {
		return fmt.Errorf("embassy: ChatSecret is required when chat is configured")
	}
	if c.ChatProject == "" {
		return fmt.Errorf("embassy: ChatProject is required when chat is configured")
	}
	// Two different privilege boundaries. The same value in both means one of the
	// two env vars points at the wrong secret.
	if c.ChatSecret == c.Secret {
		return fmt.Errorf("embassy: ChatSecret must differ from Secret — ROOTCAUSE_CHAT_SECRET is the project's webhook_secret, not the action reverse-channel secret")
	}
	if c.ChatBaseURL != "" && !isAbsoluteHTTPURL(c.ChatBaseURL) {
		return fmt.Errorf("embassy: ChatBaseURL must be an absolute http(s) URL")
	}
	return nil
}

// The placeholder by exact match OR any host under the reserved .invalid TLD; an
// unparseable or host-less URL counts too, so a malformed FetchURL cannot slip
// past the boot guard and fail opaquely at the first resolve.
func isPlaceholderFetchURL(raw string) bool {
	if raw == "" || raw == placeholderFetchURL {
		return true
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return true
	}
	return strings.HasSuffix(strings.ToLower(parsed.Hostname()), ".invalid")
}

func isAbsoluteHTTPURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func orEnv(value, key string) string {
	if value != "" {
		return value
	}
	return os.Getenv(key)
}
