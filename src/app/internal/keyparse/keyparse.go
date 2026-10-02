// Package keyparse validates the pasted access key and turns it into a sing-box profile.
//
// Accepted shape is exactly the product scenario: vless:// + Reality + flow
// xtls-rprx-vision over plain TCP. Error messages never contain any part of the key.
package keyparse

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"runetaccess/internal/config"
)

// Error carries a stable code (for tests/UI logic) and a message safe to show to the user.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func fail(code, msg string) *Error { return &Error{Code: code, Message: msg} }

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	pbkRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`) // x25519 public key, base64url, no padding
	sidRe  = regexp.MustCompile(`^[0-9a-fA-F]{0,16}$`)
)

// ProfileName is fixed so the server address never reaches logs through the name.
const ProfileName = "Runet Access"

// Parse validates raw and returns the profile for the core.
func Parse(raw string) (*config.Profile, *Error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil, fail("empty", "Вставьте ключ из Telegram.")
	}
	// The part after '#' is only a display name given by the provider ("Server 1", in any
	// language). It may contain spaces and plays no role in the connection, so drop it first.
	if i := strings.Index(text, "#"); i >= 0 {
		text = text[:i]
	}
	if strings.IndexFunc(text, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }) >= 0 {
		return nil, fail("multi", "Вставьте один ключ целиком, без пробелов и переносов строк.")
	}
	if !strings.HasPrefix(strings.ToLower(text), "vless://") {
		return nil, fail("scheme", "Нужен ключ, который начинается с vless://")
	}
	u, err := url.Parse(text)
	if err != nil || u.Host == "" {
		return nil, fail("broken", "Ключ повреждён или скопирован не целиком. Скопируйте его из Telegram ещё раз.")
	}
	q := u.Query()
	id := ""
	if u.User != nil {
		id = u.User.Username()
	}
	if !uuidRe.MatchString(id) {
		return nil, fail("uuid", "В ключе нет корректного идентификатора пользователя.")
	}
	port := 443
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return nil, fail("server", "В ключе нет адреса сервера или порта.")
		}
		port = n
	}
	if u.Hostname() == "" {
		return nil, fail("server", "В ключе нет адреса сервера или порта.")
	}
	if !strings.EqualFold(q.Get("security"), "reality") {
		return nil, fail("not-reality", "Ключ не использует Reality (security=reality). Такой ключ не подходит.")
	}
	pbk := q.Get("pbk")
	if !pbkRe.MatchString(pbk) {
		return nil, fail("pbk", "В ключе нет корректного публичного ключа Reality (pbk).")
	}
	sid := q.Get("sid")
	if !sidRe.MatchString(sid) {
		return nil, fail("sid", "В ключе некорректный параметр sid.")
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	if sni == "" {
		// Reality needs an explicit mask host; falling back to the server address would
		// import "successfully" and never connect.
		return nil, fail("sni", "В ключе нет имени сайта-маски (sni).")
	}
	if q.Get("flow") != "xtls-rprx-vision" {
		return nil, fail("flow", "В ключе нет flow=xtls-rprx-vision. Такой ключ не подходит.")
	}
	switch strings.ToLower(q.Get("type")) {
	case "", "tcp", "raw", "none":
	default:
		return nil, fail("transport", "Ключ использует нестандартный транспорт. Нужен обычный TCP.")
	}
	if enc := q.Get("encryption"); enc != "" && enc != "none" {
		return nil, fail("encryption", "Ключ использует неподдерживаемое шифрование VLESS.")
	}
	fp := q.Get("fp")
	if fp == "" {
		fp = "chrome"
	}
	return &config.Profile{
		ID:     "runet-access-key",
		Name:   ProfileName,
		Type:   "vless",
		Server: u.Hostname(),
		Port:   port,
		UUID:   id,
		Flow:   "xtls-rprx-vision",
		TLS: &config.TLS{
			Enabled:    true,
			ServerName: sni,
			UTLS:       &config.UTLS{Enabled: true, Fingerprint: fp},
			Reality:    &config.Reality{Enabled: true, PublicKey: pbk, ShortID: sid},
		},
	}, nil
}
