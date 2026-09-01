// Package chat is the MINT side of rootcause's embedded-chat trust boundary.
//
// Your backend mints a short-lived HS256 token asserting who is chatting (and, on
// a tenant-enabled project, inside which tenant); rootcause only ever VERIFIES it.
// The browser never sees the key, so it cannot mint a token for another user,
// tenant, origin or a later expiry.
//
// The signing key is the project's webhook_secret — a DIFFERENT privilege boundary
// from the action-plane reverse-channel secret, with no fallback in either
// direction: a leaked chat key must not buy action execution.
package chat

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/url"
	"strings"
	"time"

	"crypto/sha256"
)

// DefaultTTL is the token lifetime the host is tuned for. The jti is single-use
// anyway, so this only bounds the UNOPENED window.
const DefaultTTL = 7200 * time.Second

// MaxTTL prevents a leaked, unopened token from remaining useful indefinitely.
const MaxTTL = 24 * time.Hour

// DefaultBaseURL is the hosted ReplyPen widget origin.
const DefaultBaseURL = "https://app.replypen.com"

// DefaultAssurance means "asserted by the customer's own authenticated server
// session".
const DefaultAssurance = "customer_backend_jwt"

const (
	loaderPath = "/chat/widget/v1/loader.js"
	// loaderRevision is the loader CONTRACT revision. The host immutable-caches that
	// asset, so bump it whenever a generated attribute starts requiring new loader
	// behavior — otherwise an already-open browser pairs a new tag with stale JS.
	loaderRevision = "2"
)

// Claims is what the token asserts. Every field is inside the signature, so a
// swapped tenant or origin is a broken token.
type Claims struct {
	// Project is the rootcause project name: it fixes both `iss` and
	// `aud` (rootcause:chat:<project>).
	Project string
	// ExternalID is the opaque, stable user id rootcause anchors a conversation to
	// — never a name or an email.
	ExternalID string
	// Kind names the identity namespace ExternalID lives in, e.g. "acme_user".
	Kind string
	// Origin is the browser Origin the token is pinned to. The host compares it
	// byte-for-byte with the request's Origin header.
	Origin string
	// Tenant is the rootcause tenant SLUG. It must come from your server-side
	// authorized tenant context, never from client input.
	Tenant string
	// Locale and ColorScheme are presentation hints only — they grant nothing.
	Locale      string
	ColorScheme string
	// AssertedBy defaults to Project, Assurance to DefaultAssurance.
	AssertedBy string
	Assurance  string
	// JTI is single-use host-side (burned when a session opens). Generated when empty.
	JTI string
	// TTL defaults to DefaultTTL; IssuedAt defaults to now.
	TTL      time.Duration
	IssuedAt time.Time
}

// Claim order is pinned so a conformance suite has exact bytes to assert against;
// the wire itself does not care about key order.
type tokenClaims struct {
	Sub         string         `json:"sub"`
	Aud         string         `json:"aud"`
	Iss         string         `json:"iss"`
	Jti         string         `json:"jti"`
	Origin      string         `json:"origin"`
	Iat         int64          `json:"iat"`
	Nbf         int64          `json:"nbf"`
	Exp         int64          `json:"exp"`
	Principal   tokenPrincipal `json:"principal"`
	Tenant      string         `json:"tenant,omitempty"`
	Locale      string         `json:"locale,omitempty"`
	ColorScheme string         `json:"color_scheme,omitempty"`
}

type tokenPrincipal struct {
	Kind       string `json:"kind"`
	ExternalID string `json:"external_id"`
	AssertedBy string `json:"asserted_by"`
	Assurance  string `json:"assurance"`
}

// MintEmbedToken produces the compact HS256 token for one user (+ tenant).
//
// Optional claims are OMITTED, never nulled: a present-but-empty tenant reads as
// "no tenant" and an explicit null would be indistinguishable.
func MintEmbedToken(secret string, claims Claims) (string, error) {
	// A blank key fails closed: HMAC with a zero-length key is trivially forgeable.
	if strings.TrimSpace(secret) == "" {
		return "", refusal("CHAT_SECRET_REQUIRED", "Set ROOTCAUSE_CHAT_SECRET to the project's chat signing secret.")
	}
	if strings.TrimSpace(claims.Project) == "" {
		return "", refusal("CHAT_PROJECT_REQUIRED", "Set Claims.Project, or Config.ChatProject, to the public ReplyPen project slug.")
	}
	if strings.TrimSpace(claims.ExternalID) == "" {
		return "", refusal("CHAT_EXTERNAL_ID_REQUIRED", "Set Claims.ExternalID from the signed-in server session's stable user identifier.")
	}
	if strings.TrimSpace(claims.Kind) == "" {
		return "", refusal("PRINCIPAL_REQUIRED", "Set Claims.Kind to the principal kind configured for this ReplyPen project.")
	}
	origin, err := CanonicalOrigin(claims.Origin)
	if err != nil {
		return "", err
	}
	ttl := claims.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < time.Second || ttl > MaxTTL {
		return "", refusal("TOKEN_TTL_INVALID", "Set Claims.TTL between 1 second and 24 hours; 2 hours is the recommended default.")
	}
	issuedAt := claims.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}
	jti := claims.JTI
	if jti == "" {
		jti = newUUID()
	}
	assertedBy := claims.AssertedBy
	if assertedBy == "" {
		assertedBy = claims.Project
	}
	assurance := claims.Assurance
	if assurance == "" {
		assurance = DefaultAssurance
	}

	issued := issuedAt.Unix()
	payload := tokenClaims{
		Sub:    claims.ExternalID,
		Aud:    Audience(claims.Project),
		Iss:    claims.Project,
		Jti:    jti,
		Origin: origin,
		Iat:    issued,
		Nbf:    issued,
		Exp:    issued + int64(ttl.Seconds()),
		Principal: tokenPrincipal{
			Kind:       claims.Kind,
			ExternalID: claims.ExternalID,
			AssertedBy: assertedBy,
			Assurance:  assurance,
		},
		Tenant:      claims.Tenant,
		Locale:      claims.Locale,
		ColorScheme: claims.ColorScheme,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", &Error{ErrorCode: "TOKEN_MINT_FAILED", Hint: "Use JSON-compatible UTF-8 claim values and retry minting.", Docs: docsBaseURL + "token_mint_failed", Cause: err}
	}

	// The header is exactly this, always. `alg` is checked BEFORE the signature
	// host-side — never let alg pick the verifier.
	header := []byte(`{"alg":"HS256","typ":"JWT"}`)
	signingInput := b64(header) + "." + b64(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64(mac.Sum(nil)), nil
}

// Audience is the host's required `aud` for a project's embed token.
func Audience(project string) string { return "rootcause:chat:" + project }

// Widget describes the loader <script> tag.
type Widget struct {
	// BaseURL is the origin serving the hosted widget, e.g. "https://app.replypen.com".
	BaseURL string
	Project string
	Token   string
	// Mode "page" selects the full-page surface; empty means the floating widget.
	Mode string
	// Target is the CSS selector the page-mode surface mounts into.
	Target string
	// Locale and ColorScheme ride BOTH the claim and the attribute, so the loader
	// can localize and paint server-rendered chrome without decoding the token.
	Locale      string
	ColorScheme string
}

// WidgetTagHTML renders the loader tag with every attribute HTML-escaped.
//
// Mint a FRESH token per render — tokens are short-lived and single-use, so one is
// never cached across renders.
func WidgetTagHTML(w Widget) (string, error) {
	if w.BaseURL == "" {
		w.BaseURL = DefaultBaseURL
	}
	baseURL, err := CanonicalOrigin(w.BaseURL)
	if err != nil {
		return "", refusal("CHAT_BASE_URL_INVALID", "Set Widget.BaseURL to an absolute http or https origin with no path.")
	}
	if strings.TrimSpace(w.Project) == "" {
		return "", refusal("CHAT_PROJECT_REQUIRED", "Set Widget.Project to the public ReplyPen project slug.")
	}
	if strings.TrimSpace(w.Token) == "" {
		return "", refusal("NO_TOKEN", "Mint a fresh embed token for this page render and pass it as Widget.Token.")
	}
	// The loader's vocabulary is exactly page|bubble; an empty Mode is the bubble.
	if w.Mode != "" && w.Mode != "page" && w.Mode != "bubble" {
		return "", refusal("WIDGET_MODE_INVALID", "Set Widget.Mode to page or bubble, or leave it empty for the floating widget.")
	}
	if (w.Mode == "page") != (strings.TrimSpace(w.Target) != "") {
		return "", refusal("WIDGET_TARGET_INVALID", "Set a non-empty Widget.Target only when Widget.Mode is page.")
	}

	attributes := [][2]string{
		{"src", baseURL + loaderPath + "?v=" + loaderRevision},
		{"data-rc-project", w.Project},
		{"data-rc-token", w.Token},
	}
	for _, optional := range [][2]string{
		{"data-rc-mode", w.Mode},
		{"data-rc-target", w.Target},
		{"data-rc-locale", w.Locale},
		{"data-rc-color-scheme", w.ColorScheme},
	} {
		if optional[1] != "" {
			attributes = append(attributes, optional)
		}
	}

	var builder strings.Builder
	builder.WriteString("<script")
	for _, attribute := range attributes {
		builder.WriteString(" " + attribute[0] + `="` + html.EscapeString(attribute[1]) + `"`)
	}
	builder.WriteString("></script>")
	return builder.String(), nil
}

// CanonicalOrigin normalizes a browser Origin to scheme://host[:port]: lowercase
// host, default port dropped, a bare trailing slash dropped. Anything carrying a
// path, query or fragment is refused AT MINT TIME — the host compares byte for
// byte, so a near-miss would read as a forged token far from its cause.
func CanonicalOrigin(raw string) (string, error) {
	if raw == "" {
		return "", refusal("ORIGIN_INVALID", "Set Claims.Origin to the browser origin as scheme://host[:port].")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", refusal("ORIGIN_INVALID", "Set Claims.Origin to a valid http or https origin as scheme://host[:port].")
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return "", refusal("ORIGIN_INVALID", "Set Claims.Origin to scheme://host[:port] with no path, query, fragment, or user information.")
	}

	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return parsed.Scheme + "://" + host, nil
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

// crypto/rand.Read never returns an error (it panics if the OS source fails), so
// a jti is never silently predictable.
func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
