# rootcause-embassy-go

The Go **Embassy**: rootcause's trusted in-app presence inside your own Go service.

It does four things, all on your side of the wire:

1. **Actions** — rootcause sends a signed, **digest-pinned** invocation; you run the approved script
   against your own production and answer with a signed structured result.
2. **Analysis** — your code asks rootcause *"analyze this"* and gets the drafted answer back later on
   a route you mount. No polling, no callback rig of your own.
3. **Chat** — mint the short-lived token that lets a logged-in user chat with rootcause in your UI.
4. **API** — call any rootcause API endpoint, bearer auth handled for you.

Dependencies: the Go standard library and [yaegi](https://github.com/traefik/yaegi) (the script
interpreter). Nothing else.

The wire contract is owned by [`rootcause-embassy`](https://github.com/rootcause-org/rootcause-embassy);
this package conforms to it and replays its fixtures in CI.

## Install

```sh
go get github.com/rootcause-org/rootcause-embassy-go
```

## Configure

One `embassy.New` at boot. It validates **fail-closed** — a missing secret, a placeholder fetch URL or
a chat key equal to the action key is a boot error, not a first-invocation surprise.

```go
package main

import (
	"log/slog"
	"net/http"

	"github.com/rootcause-org/rootcause-embassy-go"
)

func main() {
	emb, err := embassy.New(embassy.Config{
		// Every string field falls back to its ROOTCAUSE_* env var when left empty:
		//   Secret          ROOTCAUSE_ACTION_SECRET      (per-project reverse-channel HMAC key)
		//   FetchURL        ROOTCAUSE_FETCH_URL          (the host's script-by-digest endpoint)
		//   TriggerURL      ROOTCAUSE_TRIGGER_URL
		//   SentMessageURL  ROOTCAUSE_SENT_MESSAGE_URL
		//   APIBaseURL      ROOTCAUSE_API_BASE_URL
		//   APIKey          ROOTCAUSE_API_KEY
		//   ChatSecret      ROOTCAUSE_CHAT_SECRET        (the project's webhook_secret — NOT Secret)
		//   ChatProject     ROOTCAUSE_CHAT_PROJECT
		//   ChatBaseURL     ROOTCAUSE_CHAT_BASE_URL
		Logger:        slog.Default(),
		ResultHandler: handleAnalysisResult,
		Symbols: map[string]any{
			"DB":    db,          // whatever your action scripts need
			"Mailer": mailer,
		},
	})
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/rootcause/action", emb.ActionHandler())
	mux.Handle("/rootcause/action/health", emb.ActionHandler())
	mux.Handle("/rootcause/result", emb.ResultHandler())
	http.ListenAndServe(":8080", mux)
}
```

Both action lines are needed: Go's `ServeMux` matches an exact pattern, and the health child lives one
segment below the mount.

## Writing an action script

An action script is ordinary Go source that rootcause stores in your project's brain and pins by
digest. Convention:

- package `action`
- one exported `func Run(a embassy.ActionAPI, params map[string]any) (any, error)`
- the return value must be JSON-serializable — it becomes `return_value` on the wire

```go
package action

import (
	"fmt"

	"github.com/rootcause-org/rootcause-embassy-go"
	"rcsymbols" // whatever you registered in Config.Symbols
)

func Run(a embassy.ActionAPI, params map[string]any) (any, error) {
	email := params["email"].(string)

	// The tenant tuple is the ONLY trustworthy tenant identity: the host stamped it
	// outside any model-authored params and signed the exact bytes. Never read a
	// tenant out of params — reserved param names are refused for that reason.
	scope := ""
	if t := a.Tenant(); t != nil {
		scope = t.ScopeValue
	}

	user, err := rcsymbols.DB.FindUser(a.Context(), email, scope)
	if err != nil {
		return nil, err
	}
	if err := rcsymbols.Mailer.SendPasswordReset(a.Context(), user); err != nil {
		return nil, err
	}

	// Anything written to a.Out() becomes the wire `stdout` (capped at 64 KiB).
	fmt.Fprintf(a.Out(), "reset sent to user %d", user.ID)

	return map[string]any{"sent": true, "user_id": user.ID}, nil
}
```

Notes:

- **Params are data, never source.** They arrive as a validated `map[string]any` (`string`, `int64`,
  `float64`, `bool`, `[]string`); a value like `"; os.Exit(1); "` is an inert string.
- **`a.Context()` carries the deadline.** Pass it into your own I/O so a cancelled run stops promptly.
  **Do not spawn goroutines** — the deadline aborts the script's main frame, not work it spawned.
- **`fmt.Println` is NOT captured** — the interpreter shares the process's real stdout. Write to
  `a.Out()` for anything you want in the result.
- **A panic is recovered** into a structured failure result. It never crashes your server.
- **Do not keep per-run state in a package-level var.** Interpreters are memoized per script digest
  (and per tenant), so a package var survives between runs of the same action. Keep everything a run
  needs in `Run`.
- Types your script touches must come from the standard library or from `Config.Symbols`.

## What it does, in order (fail-closed at every step)

| Step | Refusal |
|---|---|
| verify HMAC over the raw bytes | `401 bad_signature` |
| parse + required fields + `runtime` | `400 invalid_request` |
| tenant tuple (all-or-nothing) | `400 invalid_request` |
| freshness `issued_at` ±300s, unseen `nonce` | `409 replay` |
| re-validate params against the invocation's schema | `422 schema_violation` |
| fetch the script by digest, signed, and re-hash it | `502 resolve_failed` |
| execute (skipped on `dry_run`) | `200` with `ok:false` |

Every answer — including every refusal — is signed. The one exception is the `405 + Allow: POST` a
non-POST gets at the mount: that is the deliberately unsigned liveness floor an operator probes.

The whole pipeline (script fetch **and** execution) runs under one 22s deadline, so a slow fetch still
leaves time for a signed answer inside the host's 25s one-shot wait.

## Security posture (honest caveats)

- **This is not a sandbox.** A script runs as your app, with your privileges, over yaegi's standard
  library. The boundary is: digest-pinned approved scripts only, signature + replay, params as data,
  and an audit trail on both sides.
- **Restrict the mount at the edge.** Both routes only ever talk to rootcause — allowlist its egress
  IP in your load balancer / firewall and keep the HMAC as defense in depth.
- **The timeout is a backstop, not a transaction boundary.** It can fire mid-transaction. Actions must
  be idempotent and safe to re-run.
- **Three keys, no fallback.** `Secret` (actions + analysis), `ChatSecret` (chat tokens only), `APIKey`
  (API bearer). None ever substitutes for another; boot validation refuses a chat key equal to the
  action key.
- **Never log a secret.** The package logs identifiers, param KEYS, byte counts and statuses only.

## Async analysis

```go
analysis, err := emb.StartAnalysis(ctx, embassy.AnalysisRequest{
	Subject:  ticket.Subject,
	Body:     ticket.Body,
	Metadata: map[string]any{"resource_type": "SupportTicket", "resource_id": ticket.ID},
	// Optional: continue a conversation. Send ONLY the new message — the host keeps
	// the prior turns.
	SessionID: ticket.RootcauseSessionID,
	// Optional: assert WHO this is on behalf of, from your OWN authenticated session.
	// Never from model output, never from user input.
	Principal: &embassy.Principal{Kind: "acme_admin", ExternalID: user.ID, Assurance: "session"},
})
// persist analysis.AnalysisID + analysis.SessionID on your record
```

The answer arrives later on your result route:

```go
func handleAnalysisResult(result embassy.Result) error {
	// MUST be idempotent — upsert by AnalysisID or Metadata, never blind-insert. An
	// error here is deliberately not an ack, so rootcause redelivers.
	ticket := findTicket(result.Metadata["resource_id"])
	ticket.Draft = result.Draft        // markdown
	ticket.Summary = result.Note       // the summary note, markdown
	ticket.Questions = result.Questions

	// Proposals: render each as a button pointing at Action.URL (single-use,
	// expiring, digest-pinned). NEVER auto-execute one.
	ticket.Proposals = result.Actions
	// Already ran host-side mid-loop: render as an outcome, never a confirm button.
	ticket.Outcomes = result.ExecutedActions
	// Retract previously delivered artifacts.
	ticket.Retract(result.DeleteIDs)

	return ticket.Save()
}
```

When a human sends the reply — and/or answers the run's questions — hand it back:

```go
emb.CaptureSentMessage(ctx, embassy.SentMessageRequest{
	SessionID:    ticket.RootcauseSessionID,
	SentBody:     reply.Body,       // what actually left the building
	ProposedBody: ticket.Draft,     // what rootcause proposed; omit for pure signal
	Sender:       agent.Name,
	Metadata:     embassy.SentMessageMetadata{ResourceType: "SupportTicket", ResourceID: ticket.ID},
	Answers:      []embassy.Answer{{ID: "country", Values: []string{"BE"}}},
})
```

`Metadata` here is **not** free-form: exactly `ResourceType` + `ResourceID` (the host strict-decodes).

## Call any rootcause endpoint (the API plane)

Generic by design — transport and auth only, so a new host endpoint works the day it ships.

```go
response := emb.API().Patch(ctx, "/api/v1/tenants/acme/profile",
	map[string]any{"settings": settings, "source": "embassy"}, nil)

if !response.OK && response.Retryable {
	return retryLater() // transport, auth, 5xx, 429, 408
}
```

Nothing about an HTTP outcome panics or errors — inspect `OK` / `Status` / `FieldErrors` / `Error` /
`Retryable`. Only a misconfiguration (blank path, off-origin URL) sets `Err`.

An `rcor_` key is exchanged for a short-lived access token and cached in-process; anything else is
used verbatim as the bearer. Credentials are project-pinned — use `emb.APIFor(baseURL, key)` per
project and the caches never mix.

## Embedded chat

```go
tag, err := emb.ChatWidgetTagHTML(chat.Claims{
	ExternalID:  user.ID,                       // opaque, stable — never a name or email
	Kind:        "acme_admin",
	Origin:      "https://admin.acme.com",      // the browser Origin the token is pinned to
	Tenant:      currentTenant.Slug,            // from your server-side authorized context
	Locale:      "nl",
	ColorScheme: "light",
}, chat.Widget{Mode: "page", Target: "#rc-chat"})
```

Render `tag` in your layout. **Mint a fresh token per render** — tokens are short-lived and the `jti`
is single-use host-side. `chat.MintEmbedToken(secret, claims)` is the standalone form.

## Multi-worker deployments

The default nonce store is in-process, which is correct for exactly one process. Behind several
workers a replay could slip through on a second worker — inject a shared store:

```go
type redisNonces struct{ client *redis.Client }

func (r redisNonces) Add(nonce string, ttl time.Duration) bool {
	ok, _ := r.client.SetNX(context.Background(), "rc:nonce:"+nonce, 1, ttl).Result()
	return ok // true iff previously unseen — must be atomic
}

func (r redisNonces) Delete(nonce string) {
	r.client.Del(context.Background(), "rc:nonce:"+nonce)
}
```

`Delete` matters: the result route releases a nonce whose handler dispatch failed, so rootcause's
redelivery is really processed instead of silently acked.

Script bodies are cached per digest in memory (and on disk when `CacheDir` is set) and re-hashed on
every read, so each worker warms its own cache safely.

## Development

```sh
make check   # build + vet + golangci-lint + test
```

The conformance suite in `internal/contract/` replays the hub's canonical fixtures byte-for-byte and
prints the hub commit its `testdata/` was vendored from.
