# rootcause-embassy-go

The Go **Embassy**: rootcause's trusted in-app presence inside your own Go service.

It does four things, all on your side of the wire:

1. **Chat** — mint the short-lived token that lets a logged-in user chat with rootcause in your UI.
2. **Actions** — rootcause sends a signed, **digest-pinned** invocation; you run the approved script
   against your own production and answer with a signed structured result.
3. **Analysis** — your code asks rootcause *"analyze this"* and gets the drafted answer back later on
   a route you mount. No polling, no callback rig of your own.
4. **API** — call any rootcause API endpoint, bearer auth handled for you.

Dependencies: the Go standard library and [yaegi](https://github.com/traefik/yaegi) (the script
interpreter). Nothing else.

The wire contract is owned by [`rootcause-embassy`](https://github.com/rootcause-org/rootcause-embassy);
this package conforms to it and replays its fixtures in CI.

## Install

```sh
go get github.com/rootcause-org/rootcause-embassy-go
```

## Chat quickstart

Start with chat only. `ChatBaseURL` defaults to `https://app.replypen.com`; the long-lived chat secret
stays in your backend and never reaches the browser.

```go
package main

import (
	"os"
	"time"

	"github.com/rootcause-org/rootcause-embassy-go"
	"github.com/rootcause-org/rootcause-embassy-go/chat"
)

func newEmbassy() (*embassy.Embassy, error) {
	emb, err := embassy.New(embassy.Config{
		ChatSecret:  os.Getenv("ROOTCAUSE_CHAT_SECRET"),
		ChatProject: os.Getenv("ROOTCAUSE_CHAT_PROJECT"),
	})
	if err != nil {
		return nil, err
	}
	return emb, nil
}

func replypenChatToken(emb *embassy.Embassy, userID, authorizedTenant string) (string, error) {
	// Inside an authenticated server handler: identity comes from the server
	// session, never from browser input.
	return emb.MintChatToken(chat.Claims{
		ExternalID: userID,
		Kind:       "your_configured_principal_kind",
		Origin:     "https://app.example.com",
		Tenant:     authorizedTenant,
		TTL:        2 * time.Hour,
	})
}
```

Mint a fresh token per page render. Re-mint at half-life and when the widget reports `auth-expired`.
The complete runnable backend + page is [`examples/graphql-chat`](examples/graphql-chat), including
the GraphQL-shaped `replypenChatToken { token project baseUrl }` response and required CSP.

Errors are typed and safe to branch on:

```go
var embassyErr *embassy.Error
if errors.As(err, &embassyErr) {
	log.Printf("ReplyPen setup failed: %s", embassyErr.Code())
}
```

Meaning, self-fix steps, verification, and escalation live in the public
[integrator guides](https://github.com/rootcause-org/rootcause-embassy/tree/main/docs/integrator).

## Add actions and analysis later

Add `ROOTCAUSE_ACTION_SECRET` plus `ROOTCAUSE_FETCH_URL`; `New` then validates the action plane
fail-closed. The chat and action secrets are different privilege boundaries and must differ.

```go
emb, err := embassy.New(embassy.Config{
	ChatSecret:  os.Getenv("ROOTCAUSE_CHAT_SECRET"),
	ChatProject: os.Getenv("ROOTCAUSE_CHAT_PROJECT"),
	Secret:      os.Getenv("ROOTCAUSE_ACTION_SECRET"),
	FetchURL:    os.Getenv("ROOTCAUSE_FETCH_URL"),
	ResultHandler: handleAnalysisResult,
	Symbols: map[string]any{"DB": db, "Mailer": mailer},
})

mux.Handle("/rootcause/action", emb.ActionHandler())
mux.Handle("/rootcause/action/health", emb.ActionHandler())
mux.Handle("/rootcause/result", emb.ResultHandler())
```

Mounting these routes in a chat-only deployment is safe: they return `ACTION_PLANE_DISABLED` with a
fix hint and docs link. Both action lines are needed because Go's `ServeMux` matches exact patterns.
In map mode, use `Secrets` instead of `Secret`; action/result requests select a configured project
UUID and health signs its raw `?project_id=<uuid>` query.

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

Every answer — including every refusal — is signed. Two deliberate exceptions carry no signature
because there is no key to sign with or nothing to protect: the `405 + Allow: POST` a non-POST gets
at the mount (the liveness floor an operator probes) and the `503 ACTION_PLANE_DISABLED` a chat-only
deployment returns from mounted action routes.

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
- **Three keys, no fallback.** `Secret`/`Secrets` (actions + analysis), `ChatSecret` (chat tokens only),
  `APIKey` (API bearer). None ever substitutes for another; boot validation refuses a chat key equal to
  an action key.
- **Never log a secret.** The package logs identifiers, param KEYS, byte counts and statuses only.

## Async analysis

```go
analysis, err := emb.StartAnalysis(ctx, embassy.AnalysisRequest{
	ProjectID: ticket.ProjectID, // required when Config.Secrets is used; selects the local HMAC key
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
	ProjectID:    ticket.ProjectID, // required when Config.Secrets is used
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

Nothing about an HTTP outcome panics. Inspect `OK` / `Status` / `FieldErrors` / `Error` /
`Retryable`; failures also set `Err` to a typed `*embassy.Error`. A host `code`, `hint`, and `docs`
survive token exchange and ordinary API refusals.

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
}, chat.Widget{Mode: "page", Target: "#rc-chat"}) // Mode "page" requires Target; omit both for the floating bubble
```

Render `tag` in your layout. `ChatWidgetTagHTML` uses the configured `ChatBaseURL`; the standalone
`chat.WidgetTagHTML` also defaults its base URL to `https://app.replypen.com`. **Mint a fresh token per
render** — tokens are short-lived and the `jti` is single-use when opening a session.
If the Chat Studio brief has an empty `principal_kinds` list, omit both `Kind` and `ExternalID`; otherwise
derive both from the authenticated server session and use one kind declared by the brief.

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

The conformance suite in `internal/contract/` replays the hub's canonical fixtures — status, `class`
and `message` must match the golden exactly, and every refusal additionally carries `code`, `hint` and
`docs` — and prints the hub commit its `testdata/` was vendored from.
