package embassy

import (
	"errors"
	"testing"
	"time"
)

func TestConfigValidationFailsClosedAtBoot(t *testing.T) {
	valid := func() Config {
		return Config{Secret: "s3cret", FetchURL: "https://app.replypen.com/actions/script"}
	}

	tests := []struct {
		name     string
		mutate   func(*Config)
		wantCode string
	}{
		{name: "valid"},
		{
			name:     "a blank secret is forgeable",
			mutate:   func(c *Config) { c.Secret = "" },
			wantCode: "ACTION_SECRET_REQUIRED",
		},
		{
			name:     "the placeholder fetch url",
			mutate:   func(c *Config) { c.FetchURL = placeholderFetchURL },
			wantCode: "ACTION_FETCH_URL_REQUIRED",
		},
		{
			name:     "any .invalid host is the placeholder",
			mutate:   func(c *Config) { c.FetchURL = "https://whatever.invalid/x" },
			wantCode: "ACTION_FETCH_URL_REQUIRED",
		},
		{
			name:     "an unparseable fetch url cannot slip past",
			mutate:   func(c *Config) { c.FetchURL = "not a url" },
			wantCode: "ACTION_FETCH_URL_REQUIRED",
		},
		{
			name:     "the execute backstop must fire inside the invocation budget",
			mutate:   func(c *Config) { c.Timeout = 30 * time.Second },
			wantCode: "ACTION_DEADLINE_INVALID",
		},
		{
			name:     "half-wired api plane",
			mutate:   func(c *Config) { c.APIKey = "rcor_x" },
			wantCode: "API_BASE_URL_REQUIRED",
		},
		{
			name:     "api base url must be absolute",
			mutate:   func(c *Config) { c.APIKey, c.APIBaseURL = "rcor_x", "app.replypen.com" },
			wantCode: "API_BASE_URL_INVALID",
		},
		{
			name:     "half-wired chat",
			mutate:   func(c *Config) { c.ChatSecret = "chat" },
			wantCode: "CHAT_PROJECT_REQUIRED",
		},
		{
			name:     "the chat key must not be the action key",
			mutate:   func(c *Config) { c.ChatSecret, c.ChatProject = "s3cret", "demo" },
			wantCode: "CHAT_SECRET_REUSED",
		},
		{
			name: "fully wired",
			mutate: func(c *Config) {
				c.ChatSecret, c.ChatProject, c.APIKey, c.APIBaseURL = "chat", "demo", "rcor_x", "https://app.replypen.com"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid()
			if test.mutate != nil {
				test.mutate(&cfg)
			}
			_, err := New(cfg)
			switch {
			case test.wantCode == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case test.wantCode != "":
				var typed *Error
				if !errors.As(err, &typed) || typed.Code() != test.wantCode {
					t.Fatalf("error = %v, want code %q", err, test.wantCode)
				}
			}
		})
	}
}

func TestChatOnlyConfigDefaultsAndDisablesActionPlane(t *testing.T) {
	emb, err := New(Config{ChatSecret: "chat-secret", ChatProject: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if emb.Config().ChatBaseURL != DefaultChatBaseURL {
		t.Fatalf("ChatBaseURL = %q", emb.Config().ChatBaseURL)
	}
	if emb.ActionPlaneEnabled() {
		t.Fatal("chat-only config enabled the action plane")
	}
}

func TestPartialPlaneConfigStillFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		code string
	}{
		{name: "fetch without action secret", cfg: Config{FetchURL: "https://app.replypen.com/actions/script"}, code: "ACTION_SECRET_REQUIRED"},
		{name: "invalid chat base without other chat fields", cfg: Config{ChatBaseURL: "app.replypen.com"}, code: "CHAT_BASE_URL_INVALID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.cfg)
			var typed *Error
			if !errors.As(err, &typed) || typed.Code() != test.code {
				t.Fatalf("error = %v, want code %s", err, test.code)
			}
		})
	}
}

func TestConfigEnvFallback(t *testing.T) {
	t.Setenv("ROOTCAUSE_ACTION_SECRET", "from-env")
	t.Setenv("ROOTCAUSE_FETCH_URL", "https://app.replypen.com/actions/script")
	t.Setenv("ROOTCAUSE_TRIGGER_URL", "https://app.replypen.com/analyses/demo")

	emb, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := emb.Config()
	if cfg.Secret != "from-env" || cfg.TriggerURL == "" {
		t.Fatalf("env fallback did not apply: %+v", cfg.Secret)
	}
	// An explicit value always wins over the environment.
	emb, err = New(Config{Secret: "explicit"})
	if err != nil || emb.Config().Secret != "explicit" {
		t.Fatalf("explicit config lost to the environment: %v", err)
	}
}

func TestTenantlessActionsKnob(t *testing.T) {
	valid := func() Config {
		return Config{
			Secret:               "s3cret",
			FetchURL:             "https://app.replypen.com/actions/script",
			RequireTenantContext: true,
			TenantlessActions:    []string{"staff_flat_action"},
		}
	}

	tests := []struct {
		name     string
		mutate   func(*Config)
		wantCode string
	}{
		{name: "an allowlist under strict tenant context"},
		{
			name:     "an allowlist without strict tenant context exempts nothing",
			mutate:   func(c *Config) { c.RequireTenantContext = false },
			wantCode: "ACTION_TENANTLESS_ACTIONS_INVALID",
		},
		{
			name:     "a blank action id",
			mutate:   func(c *Config) { c.TenantlessActions = []string{"staff_flat_action", "  "} },
			wantCode: "ACTION_TENANTLESS_ACTIONS_INVALID",
		},
		{
			name:     "a duplicated action id",
			mutate:   func(c *Config) { c.TenantlessActions = []string{"staff_flat_action", "staff_flat_action"} },
			wantCode: "ACTION_TENANTLESS_ACTIONS_INVALID",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid()
			if test.mutate != nil {
				test.mutate(&cfg)
			}
			_, err := New(cfg)
			if test.wantCode == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var typed *Error
			if !errors.As(err, &typed) || typed.Code() != test.wantCode {
				t.Fatalf("error = %v, want code %s", err, test.wantCode)
			}
		})
	}
}

func TestTenantlessActionsEnvFallback(t *testing.T) {
	t.Setenv("ROOTCAUSE_ACTION_SECRET", "s3cret")
	t.Setenv("ROOTCAUSE_FETCH_URL", "https://app.replypen.com/actions/script")
	t.Setenv("ROOTCAUSE_TENANTLESS_ACTIONS", "staff_flat_action, staff_other_action")

	emb, err := New(Config{RequireTenantContext: true})
	if err != nil {
		t.Fatal(err)
	}
	got := emb.Config().TenantlessActions
	if len(got) != 2 || got[0] != "staff_flat_action" || got[1] != "staff_other_action" {
		t.Fatalf("tenantless actions = %#v", got)
	}
}
