package chat_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rootcause-org/rootcause-embassy-go/chat"
)

const secret = "contract-chat-secret"

// verify is the host's side, reimplemented minimally: alg is checked BEFORE the
// signature, and the signature covers the exact transmitted segments.
func verify(t *testing.T, token, secret string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var head struct{ Alg, Typ string }
	if err := json.Unmarshal(header, &head); err != nil {
		t.Fatal(err)
	}
	if head.Alg != "HS256" {
		t.Fatalf("alg = %q — never let alg pick the verifier", head.Alg)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[2])) {
		t.Fatal("signature did not verify")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestMintDefaultsAndVerification(t *testing.T) {
	token, err := chat.MintEmbedToken(secret, chat.Claims{
		Project:    "kampadmin",
		ExternalID: "user-8f3",
		Kind:       "kampadmin_admin",
		Origin:     "https://admin.kampadmin.be",
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := verify(t, token, secret)

	if claims["aud"] != "rootcause:chat:kampadmin" || claims["iss"] != "kampadmin" {
		t.Fatalf("aud/iss = %v %v", claims["aud"], claims["iss"])
	}
	if claims["jti"] == "" || claims["exp"] == nil {
		t.Fatal("jti and exp are required — a missing exp is a refusal, not an infinite token")
	}
	principal := claims["principal"].(map[string]any)
	if principal["asserted_by"] != "kampadmin" || principal["assurance"] != chat.DefaultAssurance {
		t.Fatalf("principal = %v", principal)
	}
	// Optional claims are OMITTED, never nulled.
	for _, key := range []string{"tenant", "locale", "color_scheme"} {
		if _, present := claims[key]; present {
			t.Fatalf("%s should be omitted when unset", key)
		}
	}
	if exp, iat := claims["exp"].(float64), claims["iat"].(float64); exp-iat != chat.DefaultTTL.Seconds() {
		t.Fatalf("ttl = %v", exp-iat)
	}
	// A different key must not verify: the chat key is its own privilege boundary.
	parts := strings.Split(token, ".")
	mac := hmac.New(sha256.New, []byte("contract-reverse-secret"))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) == parts[2] {
		t.Fatal("the action secret produced the same signature")
	}
}

func TestMintRefusals(t *testing.T) {
	base := chat.Claims{Project: "p", ExternalID: "u", Kind: "k", Origin: "https://app.example.com"}
	tests := []struct {
		name   string
		secret string
		mutate func(*chat.Claims)
	}{
		{name: "blank secret fails closed", secret: ""},
		{name: "missing project", secret: secret, mutate: func(c *chat.Claims) { c.Project = "" }},
		{name: "missing external id", secret: secret, mutate: func(c *chat.Claims) { c.ExternalID = "" }},
		{name: "missing kind", secret: secret, mutate: func(c *chat.Claims) { c.Kind = "" }},
		{name: "missing origin", secret: secret, mutate: func(c *chat.Claims) { c.Origin = "" }},
		{name: "origin with a path", secret: secret, mutate: func(c *chat.Claims) { c.Origin = "https://app.example.com/chat" }},
		{name: "origin with a query", secret: secret, mutate: func(c *chat.Claims) { c.Origin = "https://app.example.com?a=1" }},
		{name: "non-http origin", secret: secret, mutate: func(c *chat.Claims) { c.Origin = "ftp://app.example.com" }},
		{name: "negative ttl", secret: secret, mutate: func(c *chat.Claims) { c.TTL = -time.Second }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := base
			if test.mutate != nil {
				test.mutate(&claims)
			}
			if _, err := chat.MintEmbedToken(test.secret, claims); err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
}

func TestCanonicalOrigin(t *testing.T) {
	cases := map[string]string{
		"https://Admin.Example.com":      "https://admin.example.com",
		"https://admin.example.com/":     "https://admin.example.com",
		"https://admin.example.com:443":  "https://admin.example.com",
		"http://admin.example.com:80":    "http://admin.example.com",
		"https://admin.example.com:8443": "https://admin.example.com:8443",
	}
	for input, want := range cases {
		got, err := chat.CanonicalOrigin(input)
		if err != nil || got != want {
			t.Fatalf("CanonicalOrigin(%q) = %q, %v — want %q", input, got, err, want)
		}
	}
}

func TestWidgetTagOmitsUnsetAttributes(t *testing.T) {
	tag, err := chat.WidgetTagHTML(chat.Widget{
		BaseURL: "https://app.replypen.com/",
		Project: "kampadmin",
		Token:   "tok",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `<script src="https://app.replypen.com/chat/widget/v1/loader.js?v=2" data-rc-project="kampadmin" data-rc-token="tok"></script>`
	if tag != want {
		t.Fatalf("tag = %s", tag)
	}
	if _, err := chat.WidgetTagHTML(chat.Widget{Project: "p", Token: "t"}); err == nil {
		t.Fatal("a missing base url must be refused")
	}
}
