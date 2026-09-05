package embassy

// Result is one analysis outcome, decoded from the host's result callback and
// handed to Config.ResultHandler.
//
// The human-in-the-loop invariant lives in the field split:
//   - Draft / Note / Notes / Attachments / Questions are informational.
//   - Actions are PROPOSALS. Render each as a button pointing at its single-use
//     confirm URL. An Embassy NEVER auto-executes one. Action.ResourceURL, when
//     present, is a render-only link beside that button — never a confirm target.
//   - ExecutedActions already ran host-side mid-loop. Render them as OUTCOMES,
//     never as confirm buttons.
type Result struct {
	AnalysisID string
	// ProjectID identifies the host project that emitted this callback. It is
	// present on newly emitted callbacks and optional for single-secret legacy
	// callbacks.
	ProjectID string
	// SessionID is the host-managed continuity handle — opaque here. Persist it and
	// pass it back on the next turn; the host holds the prior messages.
	SessionID string
	Metadata  map[string]any

	// Draft is the drafted answer flattened to markdown (body_html is the fallback
	// while the host migrates), and DraftSubject its subject line.
	Draft        string
	DraftSubject string

	// Note is the SUMMARY note's markdown — the one human-facing note. Notes keeps
	// the full list for apps that render widget notes too.
	Note  string
	Notes []Note

	Actions         []Action
	ExecutedActions []ExecutedAction
	Questions       []Question
	// DeleteIDs (wire key `delete`) retracts previously delivered artifacts.
	DeleteIDs   []string
	Attachments []Attachment
	Decline     *Decline
}

// OK reports an analysis that produced output rather than declining.
func (r Result) OK() bool { return r.Decline == nil }

type Note struct {
	Key          string `json:"key"`
	BodyMarkdown string `json:"body_markdown"`
	BodyHTML     string `json:"body_html"`
	BodyText     string `json:"body_text"`
}

type Action struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Label       string `json:"label"`
	Description string `json:"description"`
	URL         string `json:"url"`
	// ResourceURL is an optional absolute http(s) link into the integrator's own
	// admin UI for the record this action would modify. It exists so a reviewer can
	// SEE the record before confirming; it is host-resolved, render-only, and must
	// never be wired to a confirm, a POST or an auto-execute. A value that is not
	// http(s) is dropped rather than refused — a bad decoration must not cost the
	// reviewer the draft.
	ResourceURL string `json:"resource_url"`
	Color       string `json:"color"`
}

type ExecutedAction struct {
	ID      string `json:"id"`
	Slug    string `json:"slug"`
	Label   string `json:"label"`
	OK      bool   `json:"ok"`
	Summary string `json:"summary"`
}

type Question struct {
	ID         string           `json:"id"`
	Type       string           `json:"type"`
	Prompt     string           `json:"prompt"`
	Why        string           `json:"why"`
	Options    []QuestionOption `json:"options"`
	AllowOther bool             `json:"allow_other"`
}

type QuestionOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type Attachment struct {
	Filename      string `json:"filename"`
	MimeType      string `json:"mime_type"`
	ContentBase64 string `json:"content_base64"`
}

type Decline struct {
	Reason string `json:"reason"`
}

// noteKeySummary discriminates the human-facing note. The host emits `key`; a
// legacy `kind` is accepted as a fallback.
const noteKeySummary = "summary"

// resultPayload is the tolerant-inbound wire shape: unknown fields are ignored,
// which is what makes additive host changes non-breaking.
type resultPayload struct {
	AnalysisID string           `json:"analysis_id"`
	SessionID  string           `json:"session_id"`
	ProjectID  string           `json:"project_id"`
	Draft      *draftPayload    `json:"draft"`
	Notes      []notePayload    `json:"notes"`
	Actions    []Action         `json:"actions"`
	Executed   []ExecutedAction `json:"executed_actions"`
	Delete     []string         `json:"delete"`
	Questions  []Question       `json:"questions"`
	Attachs    []Attachment     `json:"attachments"`
	Decline    *Decline         `json:"decline"`
	Metadata   map[string]any   `json:"metadata"`
	Nonce      string           `json:"nonce"`
	IssuedAt   string           `json:"issued_at"`
}

type draftPayload struct {
	Subject      string `json:"subject"`
	BodyMarkdown string `json:"body_markdown"`
	BodyHTML     string `json:"body_html"`
	BodyText     string `json:"body_text"`
}

type notePayload struct {
	Key          string `json:"key"`
	Kind         string `json:"kind"`
	BodyMarkdown string `json:"body_markdown"`
	BodyHTML     string `json:"body_html"`
	BodyText     string `json:"body_text"`
}

func (p resultPayload) toResult() Result {
	result := Result{
		AnalysisID:      p.AnalysisID,
		ProjectID:       p.ProjectID,
		SessionID:       p.SessionID,
		Metadata:        p.Metadata,
		Actions:         sanitizeActions(p.Actions),
		ExecutedActions: p.Executed,
		Questions:       p.Questions,
		DeleteIDs:       p.Delete,
		Attachments:     p.Attachs,
		Decline:         p.Decline,
	}
	if result.Metadata == nil {
		result.Metadata = map[string]any{}
	}
	if p.Draft != nil {
		result.DraftSubject = p.Draft.Subject
		result.Draft = flattenBody(p.Draft.BodyMarkdown, p.Draft.BodyHTML, p.Draft.BodyText)
	}
	for _, note := range p.Notes {
		result.Notes = append(result.Notes, Note{
			Key:          firstNonEmpty(note.Key, note.Kind),
			BodyMarkdown: note.BodyMarkdown,
			BodyHTML:     note.BodyHTML,
			BodyText:     note.BodyText,
		})
	}
	if summary := summaryNote(result.Notes); summary != nil {
		result.Note = flattenBody(summary.BodyMarkdown, summary.BodyHTML, summary.BodyText)
	}
	return result
}

// sanitizeActions drops a resource_url that is not an absolute http(s) URL,
// silently: the analysis result is the valuable payload and a bad decoration must
// not cost the reviewer the draft.
func sanitizeActions(actions []Action) []Action {
	for i := range actions {
		if actions[i].ResourceURL != "" && !isAbsoluteHTTPURL(actions[i].ResourceURL) {
			actions[i].ResourceURL = ""
		}
	}
	return actions
}

// summaryNote picks the ONE human-facing note. An explicit `summary` key always
// wins over array order, so a later trace note can never clobber it; with no keyed
// summary at all, a single unkeyed note still surfaces.
func summaryNote(notes []Note) *Note {
	if len(notes) == 0 {
		return nil
	}
	for i := range notes {
		if notes[i].Key == noteKeySummary {
			return &notes[i]
		}
	}
	return &notes[0]
}

// Markdown-first, HTML then text as fallbacks while the host migrates.
func flattenBody(markdown, html, text string) string {
	return firstNonEmpty(markdown, html, text)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
