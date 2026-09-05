# rootcause-embassy-go — agent map

The Go Embassy. Customer-facing usage is in [README.md](README.md); this file is the repo map and the
rules an agent changing it must follow.

## The contract lives elsewhere

**`~/code/rootcause-org/rootcause-embassy` is the authority** for every wire question: `CONTRACT.md`,
`planes/{actions,analysis,chat,api}.md`, `decisions.md`, `fixtures/`.

- A behavior/wire change starts THERE — edit the contract and the fixtures first, then conform here.
- Never "fix" a fixture in this repo. `internal/contract/testdata/` is a VENDORED copy; re-copy the
  hub's `fixtures/` wholesale and update `testdata/HUB_SHA` (the suite prints it, so drift is visible).
- The two invariants no port may drop: **no Embassy auto-executes an action**, and **no principal ever
  originates from model output**.

## Repo map

| File | What it owns |
|---|---|
| `embassy.go` | `New`, the facade, `API()` / `APIFor()` |
| `config.go` | every knob, `ROOTCAUSE_*` env fallbacks, fail-closed boot validation |
| `secrets.go` | the decision-14 selector: signed `project_id` → reverse secret, for every HMAC direction |
| `errors.go` | the customer-facing `Error`, the signed refusal classes, the code→hint lookup |
| `httpx.go` | the one outbound HTTP call, and the four response read caps in one table |
| `signature.go` | HMAC-SHA256, `X-Webhook-Signature`, constant-time verify, blank-key floor |
| `replay.go` | freshness window, `NonceStore` + the default in-memory store |
| `schema.go` | map-form param re-validation, reserved tenant/principal names, type normalization |
| `tenant.go` / `principal.go` | trusted host scope: tenant tuple (incl. the `TenantlessActions` exemption) and optional typed principal validation |
| `resolver.go` | script by digest: memory → disk → signed GET, re-hash everywhere |
| `executor.go` | yaegi: typed `ActionAPI` scope, bridge/trampoline, scope-isolated program pool, stdout cap |
| `action.go` | the invocation route: verify → parse → tenant → replay → schema → resolve → run |
| `result.go` | the `Result` value type and the tolerant result decode |
| `resultroute.go` | the result route, incl. the idempotent-ack + nonce-release rule |
| `client.go` | `StartAnalysis`, `CaptureSentMessage` (sent replies AND answers) |
| `api.go` / `apiauth.go` | the generic API plane, the `rcor_` token exchange, and the per-caller token cache |
| `chat/` | embed-token minting + the widget tag (a DIFFERENT key: `ChatSecret`) |
| `internal/rcerr/` | the ONE `Error` definition and the ONE code→hint table, shared with `chat/` |
| `internal/uuid/` | nonce and `jti` generation, shared with `chat/` |
| `internal/contract/` | the conformance suite + vendored hub fixtures |

## Rules

- **stdlib + yaegi only.** Adding a dependency needs a very good reason.
- **Sign every response**, including refusals. The only unsigned answer is the `405` liveness probe.
- **Log identifiers, shapes and byte counts** — never values, bodies, secrets, bearers, query strings,
  or the message text of an unexpected error (`internal_error` carries the type name only).
- `make check` before you call anything done.

## Known deviations from the Ruby reference

- **stdout** is captured through `ActionAPI.Out()`, not by swapping a process-global stream, so
  `fmt.Println` in a script is NOT captured. This is what lets executions run concurrently.
- **The tenant tuple** reaches a script as a typed argument, never through `RC_TENANT_*` env — the
  contract makes the mechanism explicitly language-local (hub decision 9).
- **The principal** reaches scripts as a frozen `ActionAPI.Principal()` value and the contract's
  `RC_PRINCIPAL_*` virtual environment. Each scope-keyed Yaegi program starts with only this invocation's
  values, so a principal-less or concurrent invocation cannot observe a prior one.
- **`runtime`** must be `go`; the hub's invocation fixtures declare `ruby` and are therefore refused
  with `400 invalid_request` here, which is the contract's own rule (hub decision 8).
- **Execution-failure `error.class` values** inside a `200` result envelope (`timeout`, `panic`,
  `script_error`, `error`, `compile_error`, `non_serializable_result`) are Go-local, the way Ruby's are
  Ruby class names. The closed vocabulary in `CONTRACT.md` governs REFUSALS — hub decision 6e now says
  so explicitly, so this is sanctioned, not a deviation to reconcile.

## Open questions for the hub

- A script's spawned goroutine outlives the deadline (yaegi cannot be killed). The contract's
  "timeout is a backstop, not a transaction boundary" covers the spirit; the script-authoring rule
  ("don't spawn goroutines") is currently only in our README.
