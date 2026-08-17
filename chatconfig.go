package embassy

import (
	"github.com/rootcause-org/rootcause-embassy-go/chat"
)

// MintChatToken mints an embed-chat token from the configured chat credentials.
// Project defaults to Config.ChatProject; the key is Config.ChatSecret — never the
// action-plane Secret.
func (e *Embassy) MintChatToken(claims chat.Claims) (string, error) {
	if claims.Project == "" {
		claims.Project = e.cfg.ChatProject
	}
	return chat.MintEmbedToken(e.cfg.ChatSecret, claims)
}

// ChatWidgetTagHTML mints a FRESH token and renders the loader tag for it.
func (e *Embassy) ChatWidgetTagHTML(claims chat.Claims, widget chat.Widget) (string, error) {
	token, err := e.MintChatToken(claims)
	if err != nil {
		return "", err
	}
	if widget.BaseURL == "" {
		widget.BaseURL = e.cfg.ChatBaseURL
	}
	if widget.Project == "" {
		widget.Project = firstNonEmpty(claims.Project, e.cfg.ChatProject)
	}
	widget.Token = token
	if widget.Locale == "" {
		widget.Locale = claims.Locale
	}
	if widget.ColorScheme == "" {
		widget.ColorScheme = claims.ColorScheme
	}
	return chat.WidgetTagHTML(widget)
}
