// Package keyparse validates the pasted access key and turns it into a sing-box profile.
//
// Two key shapes are accepted, both VLESS:
//   - Reality over plain TCP with flow xtls-rprx-vision (the original scenario);
//   - TLS over WebSocket (what the HLVPN support actually issued for "Рунет"; verified to work
//     in an independent Xray client).
//
// TLS certificate verification is never switched off: keys that ask for allowInsecure are
// refused. Error messages never contain any part of the key.
package keyparse

import (
	"net"
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

const unsupportedMsg = "Этот вид ключа не поддерживается. Нужен VLESS с Reality (TCP) или VLESS с TLS и WebSocket."

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

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
	if enc := q.Get("encryption"); enc != "" && enc != "none" {
		return nil, fail("encryption", "Ключ использует неподдерживаемое шифрование VLESS.")
	}
	// Certificate verification is a safety property of this product: never relaxed by a key.
	if truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure")) {
		return nil, fail("insecure", "Ключ просит отключить проверку сертификата сервера. Это не допускается.")
	}

	base := &config.Profile{
		ID:     "runet-access-key",
		Name:   ProfileName,
		Type:   "vless",
		Server: u.Hostname(),
		Port:   port,
		UUID:   id,
	}
	switch strings.ToLower(q.Get("security")) {
	case "reality":
		return parseReality(base, q)
	case "tls":
		return parseTLSWebSocket(base, q)
	default:
		return nil, fail("unsupported", unsupportedMsg)
	}
}

func parseReality(p *config.Profile, q url.Values) (*config.Profile, *Error) {
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
	fp := q.Get("fp")
	if fp == "" {
		fp = "chrome"
	}
	p.Flow = "xtls-rprx-vision"
	p.TLS = &config.TLS{
		Enabled:    true,
		ServerName: sni,
		UTLS:       &config.UTLS{Enabled: true, Fingerprint: fp},
		Reality:    &config.Reality{Enabled: true, PublicKey: pbk, ShortID: sid},
	}
	return p, nil
}

// parseTLSWebSocket accepts VLESS over TLS over WebSocket. Only what the key states is used;
// the usual protocol defaults apply to the rest (SNI = server name when the address is a name).
func parseTLSWebSocket(p *config.Profile, q url.Values) (*config.Profile, *Error) {
	if strings.ToLower(q.Get("type")) != "ws" {
		return nil, fail("transport", "Для ключа с TLS нужен транспорт WebSocket (type=ws).")
	}
	switch strings.ToLower(q.Get("packetEncoding")) {
	case "", "xudp": // the generator always uses xudp for VLESS
	default:
		return nil, fail("packet", "Ключ использует неподдерживаемую упаковку пакетов.")
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	if sni == "" {
		if net.ParseIP(p.Server) != nil {
			return nil, fail("sni", "В ключе нет имени сервера для TLS (sni), а адрес — IP.")
		}
		sni = p.Server // standard TLS behaviour: the certificate is checked against the address name
	}
	tls := &config.TLS{Enabled: true, ServerName: sni} // Insecure stays false: the certificate IS verified
	if a := strings.TrimSpace(q.Get("alpn")); a != "" {
		for _, x := range strings.Split(a, ",") {
			if x = strings.TrimSpace(x); x != "" {
				tls.ALPN = append(tls.ALPN, x)
			}
		}
	}
	if fp := q.Get("fp"); fp != "" {
		tls.UTLS = &config.UTLS{Enabled: true, Fingerprint: fp}
	}
	p.TLS = tls
	p.Transport = &config.Transport{Type: "ws", Path: q.Get("path"), Host: q.Get("host")}
	// A flow (xtls-rprx-vision) cannot run over WebSocket; the generator drops it, as providers
	// often attach it to ws links by mistake.
	return p, nil
}
