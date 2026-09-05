package rcerr

// hints is the ONE code → hint table (hub decision 15: a code carries one
// customer-safe sentence). A call site passes a code and, when the failure has a
// variable half, a detail — it never writes a second sentence for a code that
// already has one, because a drifting hint is a hint an integrator cannot grep
// the catalogue for.
//
// Every key here is a heading in the public error catalogue
// (docs/integrator/errors.md). Adding a code starts THERE, not here.
var hints = map[string]string{
	// Signed action/result refusal classes — one hint per class, the detail rides
	// the wire `message`.
	"INVALID_REQUEST":  "Compare the signed action request with CONTRACT.md and fix the invalid field.",
	"BAD_SIGNATURE":    "Verify ROOTCAUSE_ACTION_SECRET and sign the exact transmitted bytes.",
	"REPLAY":           "Use a fresh nonce and a current issued_at; never blindly retry an action with an uncertain outcome.",
	"SCHEMA_VIOLATION": "Match action param names and types to the approved schema and keep tenant identity out of params.",
	"RESOLVE_FAILED":   "Check ROOTCAUSE_FETCH_URL and run a dry run; never bypass signature or digest verification.",
	"HANDLER_ERROR":    "Configure an idempotent ResultHandler and verify it with the analysis result fixture.",
	"INTERNAL_ERROR":   "Upgrade the Embassy and rerun the conformance suite, then escalate with a redacted doctor bundle.",

	// Action plane configuration.
	"ACTION_FETCH_URL_REQUIRED":         "Set ROOTCAUSE_FETCH_URL to the absolute ReplyPen script endpoint before enabling actions.",
	"ACTION_TIMEOUT_INVALID":            "Set Timeout to a positive duration shorter than TotalDeadline.",
	"ACTION_DEADLINE_INVALID":           "Set TotalDeadline greater than Timeout so the Embassy can refuse before the host cutoff.",
	"ACTION_CLOCK_SKEW_INVALID":         "Set ClockSkew to a positive duration.",
	"ACTION_SECRET_REQUIRED":            "Set ROOTCAUSE_ACTION_SECRET, or Config.Secrets, before enabling the action or analysis plane.",
	"ACTION_SECRETS_INVALID":            "Configure exactly one of Secret or Secrets, and map every non-nil project UUID once to a non-blank action reverse secret.",
	"ACTION_PLANE_DISABLED":             "Configure ROOTCAUSE_ACTION_SECRET and ROOTCAUSE_FETCH_URL before mounting or calling the action and analysis planes.",
	"ACTION_TENANTLESS_ACTIONS_INVALID": "Set TenantlessActions to unique, non-blank action ids alongside RequireTenantContext, or leave the allowlist empty.",
	"ACTION_PROJECT_UNKNOWN":            "Set ProjectID to a project UUID present in Config.Secrets.",
	"ACTION_EXECUTION_FAILED":           "Inspect the action outcome and application logs before deciding whether a retry is safe.",

	// Analysis and sent-message calls.
	"ANALYSIS_TRIGGER_URL_REQUIRED": "Set ROOTCAUSE_TRIGGER_URL before starting an analysis.",
	"ANALYSIS_BODY_REQUIRED":        "Set AnalysisRequest.Body to the text ReplyPen should analyze.",
	"ANALYSIS_REQUEST_INVALID":      "Use JSON-compatible values in the analysis request.",
	"ANALYSIS_RESPONSE_INVALID":     "The analysis response was unusable; capture the status and escalate.",
	"SENT_MESSAGE_URL_REQUIRED":     "Set ROOTCAUSE_SENT_MESSAGE_URL before capturing a sent message.",
	"SENT_MESSAGE_CONTENT_REQUIRED": "Set SentBody, Answers, or both before capturing a sent message.",
	"SENT_MESSAGE_INVALID":          "Use JSON-compatible values in the sent-message request.",
	"SENT_MESSAGE_RESPONSE_INVALID": "The sent-message response was invalid JSON; capture the status and escalate.",
	"SESSION_ID_REQUIRED":           "Set SentMessageRequest.SessionID to the ReplyPen session being continued.",
	"PRINCIPAL_REQUIRED":            "Set both the principal kind and its external id from the signed-in server session.",
	"ATTACHMENT_INVALID":            "Encode every attachment's ContentBase64 with standard base64 before sending.",
	"ATTACHMENT_TOO_LARGE":          "Reduce each decoded attachment below Config.MaxAttachmentBytes.",
	"ATTACHMENTS_TOO_LARGE":         "Reduce the combined decoded attachments below the ReplyPen request limit.",

	// API plane.
	"API_BASE_URL_REQUIRED": "Set ROOTCAUSE_API_BASE_URL before configuring ROOTCAUSE_API_KEY or calling the API plane.",
	"API_BASE_URL_INVALID":  "Set ROOTCAUSE_API_BASE_URL to an absolute http or https URL.",
	"API_KEY_REQUIRED":      "Set ROOTCAUSE_API_KEY before configuring ROOTCAUSE_API_BASE_URL or calling the API plane.",
	"API_PATH_REQUIRED":     "Pass a non-blank API path such as /api/v1/projects.",
	"API_PATH_INVALID":      "Pass a valid relative API path, or an absolute URL on ROOTCAUSE_API_BASE_URL.",
	"API_ORIGIN_MISMATCH":   "Keep absolute API paths on the configured ROOTCAUSE_API_BASE_URL origin.",
	"API_METHOD_INVALID":    "Use GET, POST, PATCH, PUT, or DELETE for API calls.",
	"API_REQUEST_INVALID":   "Use a valid endpoint URL, API path, and JSON-encodable request body.",
	"API_RESPONSE_INVALID":  "The ReplyPen response could not be read; retry and escalate if it persists.",
	"API_TRANSPORT_ERROR":   "The ReplyPen endpoint could not be reached; check connectivity and retry.",
	"TOKEN_EXCHANGE_FAILED": "Check ROOTCAUSE_API_BASE_URL and the API credential, then retry the token exchange.",
	"HOST_REFUSED":          "ReplyPen refused the API request; check the request and the project configuration.",

	// Chat plane.
	"CHAT_BASE_URL_INVALID":     "Set the chat base URL to an absolute http or https origin with no path.",
	"CHAT_SECRET_REQUIRED":      "Set ROOTCAUSE_CHAT_SECRET to the project's chat signing secret.",
	"CHAT_SECRET_REUSED":        "Use a chat signing secret that differs from ROOTCAUSE_ACTION_SECRET and from every Config.Secrets value.",
	"CHAT_PROJECT_REQUIRED":     "Set the public ReplyPen project slug on ROOTCAUSE_CHAT_PROJECT, Claims.Project, or Widget.Project.",
	"CHAT_EXTERNAL_ID_REQUIRED": "Set Claims.ExternalID from the signed-in server session's stable user identifier.",
	"TOKEN_TTL_INVALID":         "Set Claims.TTL between 1 second and 24 hours; 2 hours is the recommended default.",
	"TOKEN_MINT_FAILED":         "Use JSON-compatible UTF-8 claim values and retry minting.",
	"NO_TOKEN":                  "Mint a fresh embed token for this page render and pass it as Widget.Token.",
	"ORIGIN_INVALID":            "Set the browser origin to scheme://host[:port] with no path, query, fragment, or user information.",
	"WIDGET_MODE_INVALID":       "Set Widget.Mode to page or bubble, or leave it empty for the floating widget.",
	"WIDGET_TARGET_INVALID":     "Set a non-empty Widget.Target only when Widget.Mode is page.",
}

// Hint is the customer-safe sentence for a code. An unknown code is either a
// host-supplied one (which carries its own hint) or a code that never reached the
// catalogue, so it falls back to the escalation sentence rather than to silence.
func Hint(code string) string {
	if hint, ok := hints[code]; ok {
		return hint
	}
	return hints["INTERNAL_ERROR"]
}
