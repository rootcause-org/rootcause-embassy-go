package embassy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rootcause-org/rootcause-embassy-go/chat"
)

func TestDisabledActionRoutesExplainHowToEnableThem(t *testing.T) {
	emb, err := New(Config{ChatSecret: "chat-secret", ChatProject: "acme"})
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/rootcause/action", "/rootcause/action/health", "/rootcause/result"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, nil)
		if path == "/rootcause/action/health" {
			request.Method = http.MethodGet
		}
		if path == "/rootcause/result" {
			emb.ResultHandler().ServeHTTP(recorder, request)
		} else {
			emb.ActionHandler().ServeHTTP(recorder, request)
		}
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s status = %d", path, recorder.Code)
		}
		var body struct {
			Error wireError `json:"error"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Error.Code != "ACTION_PLANE_DISABLED" || body.Error.Hint == "" || body.Error.Docs == "" {
			t.Fatalf("%s body = %s", path, recorder.Body)
		}
	}
}

func TestEmbassyChatFacadeReturnsEmbassyError(t *testing.T) {
	emb, err := New(Config{ChatSecret: "chat-secret", ChatProject: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = emb.MintChatToken(chat.Claims{ExternalID: "user-1", Origin: "https://app.acme.example"})
	var typed *Error
	if !errors.As(err, &typed) || typed.Code() != "PRINCIPAL_REQUIRED" || typed.Hint == "" || typed.Docs == "" {
		t.Fatalf("error = %#v", err)
	}
}

func TestChatOnlyOutboundPlanesRefuseFailClosed(t *testing.T) {
	if _, err := New(Config{ChatSecret: "chat-secret", ChatProject: "acme", TriggerURL: "https://app.replypen.com/trigger"}); err == nil {
		t.Fatal("a trigger url without an action secret must not boot")
	}

	emb, err := New(Config{ChatSecret: "chat-secret", ChatProject: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = emb.StartAnalysis(context.Background(), AnalysisRequest{Body: "why?"})
	var typed *Error
	if !errors.As(err, &typed) || typed.Code() != "ANALYSIS_TRIGGER_URL_REQUIRED" {
		t.Fatalf("error = %#v", err)
	}
	_, err = emb.CaptureSentMessage(context.Background(), SentMessageRequest{SessionID: "s"})
	if !errors.As(err, &typed) || typed.Code() != "SENT_MESSAGE_URL_REQUIRED" {
		t.Fatalf("error = %#v", err)
	}
}
