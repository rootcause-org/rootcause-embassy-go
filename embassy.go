// Package embassy is rootcause's trusted in-app presence in a customer's own Go
// runtime: it executes digest-pinned actions against the app's own production,
// triggers async analyses, receives their results, and mints embedded-chat tokens.
//
// Four planes, three keys, one contract — see
// https://github.com/rootcause-org/rootcause-embassy (CONTRACT.md) for the
// authoritative wire spec that this package conforms to.
//
//	emb, err := embassy.New(embassy.Config{ResultHandler: handleResult})
//	mux.Handle("/rootcause/action", emb.ActionHandler())
//	mux.Handle("/rootcause/action/health", emb.ActionHandler())
//	mux.Handle("/rootcause/result", emb.ResultHandler())
package embassy

// Embassy is the configured facade over every plane. Build one at boot and share
// it: it is safe for concurrent use.
type Embassy struct {
	cfg      *Config
	resolver *resolver
	executor *executor
	api      *API
}

// New validates the configuration fail-closed and builds the Embassy. Every check
// it makes catches a deployment mistake, so a bad deploy dies at boot rather than
// on the first invocation.
func New(cfg Config) (*Embassy, error) {
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	e := &Embassy{cfg: &cfg}
	if cfg.actionEnabled() {
		e.resolver = newResolver(e.cfg)
		e.executor = newExecutor(e.cfg)
	}
	e.api = newAPI(e.cfg, e.cfg.APIBaseURL, e.cfg.APIKey)
	return e, nil
}

// Config returns a copy of the effective configuration (secrets included — never
// log it).
func (e *Embassy) Config() Config { return *e.cfg }

// ActionPlaneEnabled reports whether action/analysis secrets were configured.
func (e *Embassy) ActionPlaneEnabled() bool { return e.cfg.actionEnabled() }

// API is the generic authenticated caller for any rootcause backend endpoint.
// Bearer auth on a THIRD key, never the HMAC secret.
func (e *Embassy) API() *API { return e.api }

// APIFor builds a caller for ANOTHER project: rootcause refresh tokens are
// project-pinned, so an app spanning several projects holds one credential each
// and their token caches never mix.
//
// Hold on to the returned caller. Its access-token cache lives on the value, so
// building a fresh one per call re-exchanges the refresh token every time.
func (e *Embassy) APIFor(apiBaseURL, apiKey string) *API {
	return newAPI(e.cfg, apiBaseURL, apiKey)
}
