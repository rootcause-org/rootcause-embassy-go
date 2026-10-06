# Changelog

## 0.6.0

Conforms to hub `2be70da` (decision 23): loader contract `?v=4` in the generated widget tag (hosted
loader gained the persistent Turbo mode; generated tags behave as before).

## 0.5.0

Conforms to hub `6d2c818` (decision 22: action-run id as chat-context locator).

- `ActionAPI.ActionRunID()` and virtual env `RC_ACTION_RUN_ID` expose the invocation's host-stamped
  `action_run_id`, invocation-scoped; empty/unset when absent, never inherited from process env.
  A malformed value refuses as signed `400 invalid_request` before resolution (dry run included).
  Breaking only for code that implements `ActionAPI` itself.
- `AnalysisRequest.ContextRefs` (`[]ContextRef{Kind, ID}`) sends `context_refs` after `session_id`.
  Client-side: at most one, `kind` `action_run`, canonical lowercase UUID id; otherwise
  `ANALYSIS_REQUEST_INVALID` before sending.
