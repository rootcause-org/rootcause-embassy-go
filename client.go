package embassy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// maxTotalAttachmentBytes is the host's aggregate decoded cap for one trigger.
// Not configurable: it is the host's limit, not ours.
const maxTotalAttachmentBytes = 6 << 20

// Principal is a trusted identity assertion about WHO a trigger is on behalf of.
// Your app asserts it from its OWN authenticated session — it must never be
// derived from model output or from anything an end user can set.
//
// Kind and ExternalID are the identity core: both or neither (a partial assertion
// silently under-scopes, so the host rejects it at ingress). AssertedBy and
// Assurance carry the signed channel's own trust semantics and are not defaulted
// host-side.
type Principal struct {
	Kind           string         `json:"kind"`
	ExternalID     string         `json:"external_id"`
	AssertedBy     string         `json:"asserted_by,omitempty"`
	Assurance      string         `json:"assurance,omitempty"`
	TenantHint     string         `json:"tenant_hint,omitempty"`
	SourceMetadata map[string]any `json:"source_metadata,omitempty"`
}

// AnalysisRequest asks rootcause to analyze something and answer later over the
// result route.
type AnalysisRequest struct {
	// ProjectID selects the reverse secret in Config.Secrets. It is not duplicated
	// in the trigger body because the host route already identifies the project.
	ProjectID string
	Subject   string
	// Body is required, plain text only (v1).
	Body        string
	Attachments []Attachment
	// Metadata is FREE-FORM here (unlike the sent-message route): scalars, small,
	// no secrets or PII — it transits rootcause and comes back verbatim.
	Metadata map[string]any
	// SessionID continues a conversation. Omit on turn 1 and the host mints one;
	// on a follow-up send ONLY the new message — the host holds the prior turns.
	SessionID string
	// Tenant binds the run by slug on a tenant-enabled project.
	Tenant    string
	Principal *Principal
}

// Analysis is the host's 202: the run id to persist alongside your resource, the
// session handle to carry forward, and the queue status.
type Analysis struct {
	AnalysisID string `json:"analysis_id"`
	SessionID  string `json:"session_id"`
	Status     string `json:"status"`
}

// SentMessageMetadata is FIXED on the sent-message route — the host strict-decodes
// exactly these two keys and 400s on anything else. ResourceID becomes the join
// handle (falling back to SessionID when absent).
type SentMessageMetadata struct {
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
}

// Answer is a reviewer's answer to one of a prior run's Questions.
type Answer struct {
	ID     string   `json:"id"`
	Values []string `json:"values"`
}

// SentMessageRequest hands rootcause what a human actually sent, and/or the
// answers to a run's clarifying questions. Both ride the same route and may
// arrive together or alone.
type SentMessageRequest struct {
	// ProjectID selects the reverse secret in Config.Secrets. It is not duplicated
	// in the sent-message body because the host route already identifies the project.
	ProjectID string
	// SessionID is required — the same handle passed to StartAnalysis.
	SessionID string
	// SentBody is the reply that actually left the building. Required unless this
	// is an answers-only capture.
	SentBody string
	Sender   string
	// ProposedBody is what rootcause proposed; omit to treat the reply as pure
	// signal (the host computes the proposed-vs-sent delta).
	ProposedBody string
	Metadata     SentMessageMetadata
	Answers      []Answer
}

// SentMessage is the host's capture ack. AnalysisID is set only when answers
// spawned a rerun ({"status":"accepted"}).
type SentMessage struct {
	Status     string `json:"status"`
	AnalysisID string `json:"analysis_id"`
	ID         string `json:"sent_message_id"`
}

// Wire shapes. Field order matches the hub goldens; omitempty keeps optional
// claims OMITTED rather than nulled.
type triggerPayload struct {
	Subject     string         `json:"subject"`
	Body        string         `json:"body"`
	Attachments []Attachment   `json:"attachments"`
	Metadata    map[string]any `json:"metadata"`
	SessionID   string         `json:"session_id,omitempty"`
	Principal   *Principal     `json:"principal,omitempty"`
	Nonce       string         `json:"nonce"`
	IssuedAt    string         `json:"issued_at"`
	Tenant      string         `json:"tenant,omitempty"`
}

type sentMessagePayload struct {
	Type      string              `json:"type"`
	SessionID string              `json:"session_id"`
	Sent      *sentBody           `json:"sent,omitempty"`
	Proposed  *proposedBody       `json:"proposed,omitempty"`
	Metadata  SentMessageMetadata `json:"metadata"`
	Answers   []Answer            `json:"answers,omitempty"`
	Nonce     string              `json:"nonce"`
	IssuedAt  string              `json:"issued_at"`
}

type sentBody struct {
	Body   string `json:"body"`
	Sender string `json:"sender,omitempty"`
}

type proposedBody struct {
	Body string `json:"body"`
}

// StartAnalysis signs and POSTs the trigger, returning the run id to persist.
//
// Failures are the caller's to handle and are never swallowed: a non-2xx,
// malformed response or transport failure comes back as an error, and the caller
// decides whether to retry. An over-cap or malformed attachment fails BEFORE
// anything is sent.
func (e *Embassy) StartAnalysis(ctx context.Context, request AnalysisRequest) (Analysis, error) {
	if e.cfg.TriggerURL == "" {
		return Analysis{}, publicError("ANALYSIS_TRIGGER_URL_REQUIRED")
	}
	if request.Body == "" {
		return Analysis{}, publicError("ANALYSIS_BODY_REQUIRED")
	}
	secret, err := e.cfg.outboundSecret(request.ProjectID)
	if err != nil {
		return Analysis{}, err
	}
	if err := e.checkAttachments(request.Attachments); err != nil {
		return Analysis{}, err
	}
	if request.Principal != nil {
		if request.Principal.Kind == "" || request.Principal.ExternalID == "" {
			return Analysis{}, publicError("PRINCIPAL_REQUIRED")
		}
	}

	attachments := request.Attachments
	if attachments == nil {
		attachments = []Attachment{}
	}
	metadata := request.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}

	raw, err := json.Marshal(triggerPayload{
		Subject:     request.Subject,
		Body:        request.Body,
		Attachments: attachments,
		Metadata:    metadata,
		SessionID:   request.SessionID,
		Principal:   request.Principal,
		Nonce:       e.cfg.Nonce(),
		IssuedAt:    e.issuedAt(),
		Tenant:      request.Tenant,
	})
	if err != nil {
		return Analysis{}, causedError("ANALYSIS_REQUEST_INVALID", err)
	}

	body, err := e.postSigned(ctx, e.cfg.TriggerURL, raw, "analysis trigger", secret)
	if err != nil {
		return Analysis{}, err
	}
	var analysis Analysis
	if err := json.Unmarshal(body, &analysis); err != nil || analysis.AnalysisID == "" {
		return Analysis{}, causedError("ANALYSIS_RESPONSE_INVALID", err).WithDetail("the response omitted analysis_id")
	}
	e.logger().Info("rootcause analysis triggered",
		"analysis_id", analysis.AnalysisID,
		"metadata_keys", sortedKeys(metadata),
		"attachments", len(attachments),
	)
	return analysis, nil
}

// CaptureSentMessage hands rootcause the reply a human actually sent and/or the
// answers to a prior run's questions. Answers alone are valid — the host re-runs
// the most recent question-raising run in the session grounded on them and pushes
// the updated result back over the result route.
func (e *Embassy) CaptureSentMessage(ctx context.Context, request SentMessageRequest) (SentMessage, error) {
	if e.cfg.SentMessageURL == "" {
		return SentMessage{}, publicError("SENT_MESSAGE_URL_REQUIRED")
	}
	if request.SessionID == "" {
		return SentMessage{}, publicError("SESSION_ID_REQUIRED")
	}
	secret, err := e.cfg.outboundSecret(request.ProjectID)
	if err != nil {
		return SentMessage{}, err
	}
	if request.SentBody == "" && len(request.Answers) == 0 {
		return SentMessage{}, publicError("SENT_MESSAGE_CONTENT_REQUIRED")
	}

	payload := sentMessagePayload{
		Type:      "sent_message",
		SessionID: request.SessionID,
		Metadata:  request.Metadata,
		Answers:   request.Answers,
		Nonce:     e.cfg.Nonce(),
		IssuedAt:  e.issuedAt(),
	}
	if request.SentBody != "" {
		payload.Sent = &sentBody{Body: request.SentBody, Sender: request.Sender}
	}
	if request.ProposedBody != "" {
		payload.Proposed = &proposedBody{Body: request.ProposedBody}
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return SentMessage{}, causedError("SENT_MESSAGE_INVALID", err)
	}

	body, err := e.postSigned(ctx, e.cfg.SentMessageURL, raw, "sent-message capture", secret)
	if err != nil {
		return SentMessage{}, err
	}
	var result SentMessage
	if len(body) > 0 {
		if err := json.Unmarshal(body, &result); err != nil {
			return SentMessage{}, causedError("SENT_MESSAGE_RESPONSE_INVALID", err)
		}
	}
	// Byte counts, never bodies; metadata KEYS, never values.
	e.logger().Info("rootcause sent-message captured",
		"session_id", request.SessionID,
		"sent_bytes", len(request.SentBody),
		"proposed_bytes", len(request.ProposedBody),
		"answers", len(request.Answers),
	)
	return result, nil
}

// postSigned signs the RAW bytes and posts them — the receiver verifies exactly
// what was transmitted, so key order here is irrelevant.
func (e *Embassy) postSigned(ctx context.Context, url string, raw []byte, label, secret string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, causedError("API_REQUEST_INVALID", err).WithDetail(label)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(SignatureHeader, Sign(raw, secret))

	response, err := e.cfg.HTTPClient.Do(request)
	if err != nil {
		return nil, causedError("API_TRANSPORT_ERROR", err).WithDetail(label)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, causedError("API_RESPONSE_INVALID", err).WithDetail(label)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, hostRefusal(parseAPIBody(body), response.StatusCode)
	}
	return body, nil
}

// Enforce the per-attachment cap client-side and fail BEFORE the round-trip: a
// strict decode also proves the base64 is well-formed.
func (e *Embassy) checkAttachments(attachments []Attachment) error {
	total := 0
	for _, attachment := range attachments {
		decoded, err := base64.StdEncoding.DecodeString(attachment.ContentBase64)
		if err != nil {
			return publicError("ATTACHMENT_INVALID")
		}
		if len(decoded) > e.cfg.MaxAttachmentBytes {
			return publicError("ATTACHMENT_TOO_LARGE")
		}
		total += len(decoded)
		// The host's aggregate ceiling: without this a set of individually legal
		// attachments uploads in full and is rejected on arrival.
		if total > maxTotalAttachmentBytes {
			return publicError("ATTACHMENTS_TOO_LARGE")
		}
	}
	return nil
}

func (e *Embassy) issuedAt() string {
	return e.cfg.Now().UTC().Format(time.RFC3339)
}
