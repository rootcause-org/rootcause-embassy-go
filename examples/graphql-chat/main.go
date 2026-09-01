package main

import (
	"embed"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	embassy "github.com/rootcause-org/rootcause-embassy-go"
	"github.com/rootcause-org/rootcause-embassy-go/chat"
)

//go:embed index.html app.js style.css
var assets embed.FS

type app struct {
	emb           *embassy.Embassy
	principalKind string
	appOrigin     string
	widgetOrigin  string
}

type graphQLRequest struct {
	Query         string          `json:"query"`
	OperationName string          `json:"operationName,omitempty"`
	Variables     json.RawMessage `json:"variables,omitempty"`
}

type chatToken struct {
	Token   string `json:"token"`
	Project string `json:"project"`
	BaseURL string `json:"baseUrl"`
}

func main() {
	cfg := embassy.Config{
		ChatSecret:  os.Getenv("ROOTCAUSE_CHAT_SECRET"),
		ChatProject: os.Getenv("ROOTCAUSE_CHAT_PROJECT"),
		ChatBaseURL: os.Getenv("ROOTCAUSE_CHAT_BASE_URL"),
		Secret:      os.Getenv("ROOTCAUSE_ACTION_SECRET"),
		FetchURL:    os.Getenv("ROOTCAUSE_FETCH_URL"),
	}
	emb, err := embassy.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	principalKind := strings.TrimSpace(os.Getenv("ROOTCAUSE_CHAT_PRINCIPAL_KIND"))
	if principalKind == "" {
		log.Fatal("PRINCIPAL_REQUIRED: Set ROOTCAUSE_CHAT_PRINCIPAL_KIND to the kind configured for this project — https://github.com/rootcause-org/rootcause-embassy/blob/main/docs/integrator/errors.md#principal_required")
	}
	appOrigin := envOr("APP_ORIGIN", "http://localhost:8080")
	if _, err := chat.CanonicalOrigin(appOrigin); err != nil {
		log.Fatal(err)
	}
	widgetURL, err := url.Parse(emb.Config().ChatBaseURL)
	if err != nil {
		log.Fatal(err)
	}

	a := &app{emb: emb, principalKind: principalKind, appOrigin: appOrigin, widgetOrigin: widgetURL.Scheme + "://" + widgetURL.Host}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.page)
	mux.HandleFunc("GET /app.js", static("app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /style.css", static("style.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("POST /graphql", a.graphQL)
	mux.Handle("/rootcause/action", emb.ActionHandler())
	mux.Handle("/rootcause/action/health", emb.ActionHandler())
	mux.Handle("/rootcause/result", emb.ResultHandler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "actions": emb.ActionPlaneEnabled()})
	})

	address := ":" + envOr("PORT", "8080")
	log.Printf("GraphQL chat example: %s (actions=%t)", appOrigin, emb.ActionPlaneEnabled())
	log.Fatal(http.ListenAndServe(address, mux))
}

func (a *app) page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'self'",
		"script-src 'self' " + a.widgetOrigin,
		"frame-src " + a.widgetOrigin,
		"connect-src 'self' " + a.widgetOrigin,
		"style-src 'self'",
		"img-src 'self' data: " + a.widgetOrigin,
		"object-src 'none'",
		"base-uri 'none'",
		"frame-ancestors 'none'",
	}, "; "))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := r.Cookie("demo_session_user"); errors.Is(err, http.ErrNoCookie) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}
	raw, _ := assets.ReadFile("index.html")
	_, _ = w.Write(raw)
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: "demo_session_user", Value: "user-123", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: strings.HasPrefix(a.appOrigin, "https://"),
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) graphQL(w http.ResponseWriter, r *http.Request) {
	session, err := r.Cookie("demo_session_user")
	if err != nil || strings.TrimSpace(session.Value) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"errors": []map[string]string{{"message": "Sign in before requesting a chat token."}}})
		return
	}
	var request graphQLRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	if err := decoder.Decode(&request); err != nil || !strings.Contains(request.Query, "replypenChatToken") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []map[string]string{{"message": "Query replypenChatToken { token project baseUrl }."}}})
		return
	}

	token, err := a.emb.MintChatToken(chat.Claims{
		ExternalID: session.Value,
		Kind:       a.principalKind,
		Origin:     a.appOrigin,
		TTL:        2 * time.Hour,
	})
	if err != nil {
		writeTypedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"replypenChatToken": chatToken{
		Token: token, Project: a.emb.Config().ChatProject, BaseURL: a.emb.Config().ChatBaseURL,
	}}})
}

func static(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		raw, err := assets.ReadFile(name)
		if err != nil {
			http.Error(w, "asset not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(raw)
	}
}

func writeTypedError(w http.ResponseWriter, err error) {
	type coded interface{ Code() string }
	var typed coded
	if errors.As(err, &typed) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []map[string]string{{"message": err.Error(), "code": typed.Code()}}})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]any{"errors": []map[string]string{{"message": "TOKEN_MINT_FAILED: Chat token minting failed."}}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func init() { log.SetFlags(0) }
