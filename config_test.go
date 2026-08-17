package embassy

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidationFailsClosedAtBoot(t *testing.T) {
	valid := func() Config {
		return Config{Secret: "s3cret", FetchURL: "https://app.replypen.com/actions/script"}
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "valid"},
		{
			name:    "a blank secret is forgeable",
			mutate:  func(c *Config) { c.Secret = "" },
			wantErr: "Secret is required",
		},
		{
			name:    "the placeholder fetch url",
			mutate:  func(c *Config) { c.FetchURL = placeholderFetchURL },
			wantErr: "placeholder",
		},
		{
			name:    "any .invalid host is the placeholder",
			mutate:  func(c *Config) { c.FetchURL = "https://whatever.invalid/x" },
			wantErr: "placeholder",
		},
		{
			name:    "an unparseable fetch url cannot slip past",
			mutate:  func(c *Config) { c.FetchURL = "not a url" },
			wantErr: "placeholder",
		},
		{
			name:    "the execute backstop must fire inside the invocation budget",
			mutate:  func(c *Config) { c.Timeout = 30 * time.Second },
			wantErr: "must exceed Timeout",
		},
		{
			name:    "half-wired api plane",
			mutate:  func(c *Config) { c.APIKey = "rcor_x" },
			wantErr: "APIBaseURL is required",
		},
		{
			name:    "api base url must be absolute",
			mutate:  func(c *Config) { c.APIKey, c.APIBaseURL = "rcor_x", "app.replypen.com" },
			wantErr: "absolute http(s) URL",
		},
		{
			name:    "half-wired chat",
			mutate:  func(c *Config) { c.ChatSecret = "chat" },
			wantErr: "ChatProject is required",
		},
		{
			name:    "the chat key must not be the action key",
			mutate:  func(c *Config) { c.ChatSecret, c.ChatProject = "s3cret", "demo" },
			wantErr: "must differ from Secret",
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
			case test.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)):
				t.Fatalf("error = %v, want %q", err, test.wantErr)
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
