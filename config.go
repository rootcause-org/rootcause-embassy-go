package embassy

import (
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Version is this Embassy's release, surfaced by the health endpoint.
const Version = "0.3.1"

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

// DefaultChatBaseURL is the public ReplyPen application origin.
const DefaultChatBaseURL = "https://app.replypen.com"

// Config is set once at boot and treated as immutable afterwards. Every string
// field falls back to its ROOTCAUSE_* environment variable when left empty.
type Config struct {
	// Secret is the per-project action_reverse_secret: the HMAC key for BOTH the
	// action and analysis planes. Never the chat webhook_secret, never the API key,
	// and no fallback in any direction. Env: ROOTCAUSE_ACTION_SECRET.
	Secret string

	// Secrets selects the action_reverse_secret by project UUID for a shared
	// Embassy deployment. Configure Secrets OR Secret, never both. Map values
	// must be non-blank; map-mode inbound bodies and health queries must carry a
	// project selector, while outbound analysis calls use their request's
	// ProjectID.
	Secrets map[string]string

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

	// TenantlessActions narrows strict tenant enforcement per SIGNED action id, for
	// a deployment that also serves a genuinely flat project through the same
	// Embassy. A listed action is accepted with no tenant tuple at all; a partial
	// tuple still refuses, and every unlisted action stays strict. Ids used this way
	// must be globally unique across the projects sharing the reverse secret.
	// Env: ROOTCAUSE_TENANTLESS_ACTIONS (comma-separated).
	TenantlessActions []string

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
	if len(c.TenantlessActions) == 0 {
		c.TenantlessActions = splitEnvList("ROOTCAUSE_TENANTLESS_ACTIONS")
	}

	if c.FetchURL == "" {
		c.FetchURL = placeholderFetchURL
	}
	if c.ChatBaseURL == "" {
		c.ChatBaseURL = DefaultChatBaseURL
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
	if c.actionPlaneRequested() {
		if err := c.validateAction(); err != nil {
			return err
		}
	}
	if err := c.validateAPI(); err != nil {
		return err
	}
	return c.validateChat()
}

func (c *Config) validateAction() error {
	if err := c.validateSecrets(); err != nil {
		return err
	}
	if isPlaceholderFetchURL(c.FetchURL) {
		return publicError("ACTION_FETCH_URL_REQUIRED")
	}
	if c.Timeout <= 0 {
		return publicError("ACTION_TIMEOUT_INVALID")
	}
	if c.TotalDeadline <= c.Timeout {
		return publicError("ACTION_DEADLINE_INVALID")
	}
	if c.ClockSkew <= 0 {
		return publicError("ACTION_CLOCK_SKEW_INVALID")
	}
	return c.validateTenantlessActions()
}

// The allowlist is an exception to strict enforcement, so it is meaningless —
// and misleading to read — without it. Blank or duplicated ids are a deployment
// typo: refuse at boot rather than silently widen or narrow the exception.
func (c *Config) validateTenantlessActions() error {
	if len(c.TenantlessActions) == 0 {
		return nil
	}
	if !c.RequireTenantContext {
		return publicError("ACTION_TENANTLESS_ACTIONS_INVALID", "Set RequireTenantContext when configuring TenantlessActions, or leave the allowlist empty.")
	}
	seen := make(map[string]struct{}, len(c.TenantlessActions))
	for _, actionID := range c.TenantlessActions {
		if strings.TrimSpace(actionID) == "" {
			return publicError("ACTION_TENANTLESS_ACTIONS_INVALID", "Set TenantlessActions to unique, non-blank action ids, or leave it empty.")
		}
		if _, exists := seen[actionID]; exists {
			return publicError("ACTION_TENANTLESS_ACTIONS_INVALID", "Remove the duplicate action id from TenantlessActions.")
		}
		seen[actionID] = struct{}{}
	}
	return nil
}

func (c *Config) actionPlaneRequested() bool {
	return c.actionEnabled() || c.FetchURL != placeholderFetchURL || c.TriggerURL != "" ||
		c.SentMessageURL != "" || c.ResultHandler != nil || c.RequireTenantContext || len(c.TenantlessActions) > 0 ||
		c.CacheDir != "" || len(c.Symbols) > 0
}

func (c *Config) actionEnabled() bool {
	return strings.TrimSpace(c.Secret) != "" || len(c.Secrets) > 0
}

func (c *Config) validateSecrets() error {
	hasSecret := strings.TrimSpace(c.Secret) != ""
	hasMap := len(c.Secrets) > 0
	if hasSecret == hasMap {
		if hasSecret {
			return publicError("ACTION_SECRETS_INVALID")
		}
		return publicError("ACTION_SECRET_REQUIRED")
	}
	if hasMap {
		seen := make(map[string]struct{}, len(c.Secrets))
		for projectID, secret := range c.Secrets {
			if !validProjectID(projectID) {
				return publicError("ACTION_SECRETS_INVALID")
			}
			canonical := strings.ToLower(projectID)
			if _, exists := seen[canonical]; exists {
				return publicError("ACTION_SECRETS_INVALID")
			}
			seen[canonical] = struct{}{}
			if strings.TrimSpace(secret) == "" {
				return publicError("ACTION_SECRETS_INVALID")
			}
		}
	}
	return nil
}

// The API plane is opt-in, but a HALF-wired one is a boot mistake rather than a
// first-call surprise in a background job.
func (c *Config) validateAPI() error {
	if c.APIBaseURL == "" && c.APIKey == "" {
		return nil
	}
	if c.APIBaseURL == "" {
		return publicError("API_BASE_URL_REQUIRED")
	}
	if c.APIKey == "" {
		return publicError("API_KEY_REQUIRED")
	}
	if !isAbsoluteHTTPURL(c.APIBaseURL) {
		return publicError("API_BASE_URL_INVALID")
	}
	return nil
}

func (c *Config) validateChat() error {
	if !isAbsoluteHTTPURL(c.ChatBaseURL) {
		return publicError("CHAT_BASE_URL_INVALID")
	}
	if c.ChatSecret == "" && c.ChatProject == "" {
		return nil
	}
	if c.ChatSecret == "" {
		return publicError("CHAT_SECRET_REQUIRED")
	}
	if c.ChatProject == "" {
		return publicError("CHAT_PROJECT_REQUIRED")
	}
	// Two different privilege boundaries. The same value in both means one of the
	// two env vars points at the wrong secret.
	if c.ChatSecret == c.Secret {
		return publicError("CHAT_SECRET_REUSED")
	}
	for _, secret := range c.Secrets {
		if c.ChatSecret == secret {
			return publicError("CHAT_SECRET_REUSED")
		}
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

// splitEnvList reads a comma-separated env list, trimming each entry. A blank
// entry is kept so validation refuses the typo instead of quietly dropping it.
func splitEnvList(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func orEnv(value, key string) string {
	if value != "" {
		return value
	}
	return os.Getenv(key)
}
