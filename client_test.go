package embassy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAnalysisClientsSelectProjectSecretInMapMode(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		secret := map[string]string{mapProjectA: mapSecretA, mapProjectB: mapSecretB}[mapProjectA]
		if !VerifySignature(r.Header.Get(SignatureHeader), body, secret) {
			t.Errorf("request signature did not use project key")
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("body: %v", err)
		}
		if _, present := payload["project_id"]; present {
			t.Error("project_id should be selected locally, not duplicated in the wire body")
		}
		if r.URL.Path == "/analyses/demo" {
			_, _ = w.Write([]byte(`{"analysis_id":"a","session_id":"s","status":"queued"}`))
		}
	}))
	defer server.Close()

	emb, err := New(Config{
		Secrets:        map[string]string{mapProjectA: mapSecretA, mapProjectB: mapSecretB},
		FetchURL:       "https://app.replypen.com/actions/script",
		TriggerURL:     server.URL + "/analyses/demo",
		SentMessageURL: server.URL + "/analyses/demo/sent-message",
		Now:            func() time.Time { return mapReferenceClock },
		Nonce:          func() string { return "map-client-nonce" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := emb.StartAnalysis(context.Background(), AnalysisRequest{ProjectID: mapProjectA, Body: "hello"}); err != nil {
		t.Fatal(err)
	}
	if _, err := emb.CaptureSentMessage(context.Background(), SentMessageRequest{ProjectID: mapProjectA, SessionID: "s", SentBody: "sent"}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if _, err := emb.StartAnalysis(context.Background(), AnalysisRequest{ProjectID: "33333333-3333-3333-3333-333333333333", Body: "unknown"}); err == nil {
		t.Fatal("unknown project was accepted")
	}
}

// Everything below must fail BEFORE a byte leaves the process — the server here
// exists only to prove nothing was sent.
func TestStartAnalysisValidatesBeforeSending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a refused request must never reach the host")
	}))
	defer server.Close()

	emb, err := New(Config{
		Secret:             testSecret,
		FetchURL:           "https://app.replypen.com/actions/script",
		TriggerURL:         server.URL + "/analyses/demo",
		MaxAttachmentBytes: 2 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}

	oversized := base64.StdEncoding.EncodeToString(make([]byte, emb.cfg.MaxAttachmentBytes+1))
	oneMiB := base64.StdEncoding.EncodeToString(make([]byte, 1<<20))
	many := make([]Attachment, 8) // individually legal, 8 MiB together
	for i := range many {
		many[i] = Attachment{Filename: "a.bin", ContentBase64: oneMiB}
	}

	tests := []struct {
		name    string
		request AnalysisRequest
		wantErr string
	}{
		{
			name:    "body is required",
			request: AnalysisRequest{Subject: "hi"},
			wantErr: "body is required",
		},
		{
			name:    "a partial principal under-scopes",
			request: AnalysisRequest{Body: "x", Principal: &Principal{Kind: "admin"}},
			wantErr: "Kind and ExternalID",
		},
		{
			name:    "malformed base64",
			request: AnalysisRequest{Body: "x", Attachments: []Attachment{{ContentBase64: "!!!"}}},
			wantErr: "not valid base64",
		},
		{
			name:    "per-attachment cap",
			request: AnalysisRequest{Body: "x", Attachments: []Attachment{{ContentBase64: oversized}}},
			wantErr: "MaxAttachmentBytes",
		},
		{
			name:    "aggregate cap",
			request: AnalysisRequest{Body: "x", Attachments: many},
			wantErr: "exceeds the host's",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := emb.StartAnalysis(context.Background(), test.request)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestCaptureSentMessageRequiresContent(t *testing.T) {
	emb, err := New(Config{
		Secret:         testSecret,
		FetchURL:       "https://app.replypen.com/actions/script",
		SentMessageURL: "https://app.replypen.com/analyses/demo/sent-message",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := emb.CaptureSentMessage(context.Background(), SentMessageRequest{SentBody: "hi"}); err == nil {
		t.Fatal("session_id is required")
	}
	// A sent body alone is valid, and answers alone are valid. Neither is not.
	if _, err := emb.CaptureSentMessage(context.Background(), SentMessageRequest{SessionID: "s"}); err == nil {
		t.Fatal("an empty capture must be refused")
	}
}
