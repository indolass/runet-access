// Package keyparse validates the pasted access key and turns it into a sing-box profile.
//
// Accepted static keys:
//   - vless:// Reality over plain TCP with flow xtls-rprx-vision (the original scenario);
//   - vless:// TLS over WebSocket (what the HLVPN support actually issued for "Рунет"; verified to work
//     in an independent Xray client);
//   - ss:// Shadowsocks (SIP002, the legacy base64 form and Outline static keys, with the Outline prefix), see ss.go.
//
// ssconf:// (Outline dynamic keys) is recognised here (IsDynamic) but fetched and interpreted by package
// dynkey: this package never touches the network.
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

// Error classes (what the interface tells the user apart):
//   - ClassFormat       the text is not a key we know (unknown scheme);
//   - ClassKey          a known format with a damaged or incomplete key;
//   - ClassUnsupported  a known format that asks for something we do not support (and will not silently drop);
//   - ClassFetch        the dynamic key's settings could not be loaded.
const (
	ClassFormat      = "format"
	ClassKey         = "key"
	ClassUnsupported = "unsupported"
	ClassFetch       = "fetch"
)

// Error carries a stable code (for tests/UI logic), its class and a message safe to show to the user.
type Error struct {
	Code    string
	Class   string
	Message string
}

func (e *Error) Error() string { return e.Message }

// Codes that mean "understood, but not supported".
var unsupportedCodes = map[string]bool{
	"unsupported": true, "transport": true, "encryption": true, "insecure": true, "packet": true,
	"ss-cipher": true, "ss-legacy-cipher": true, "ss-plugin": true, "ss-prefix-cipher": true, "ss-prefix-long": true, "ss-param": true,
	"dyn-yaml": true, "dyn-format": true, "dyn-param": true, "dyn-transport": true,
}

func fail(code, msg string) *Error {
	class := ClassKey
	switch {
	case code == "scheme":
		class = ClassFormat
	case unsupportedCodes[code]:
		class = ClassUnsupported
	case strings.HasPrefix(code, "fetch"):
		class = ClassFetch
	}
	return &Error{Code: code, Class: class, Message: msg}
}

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

// UnknownFormatMsg is shown for a text whose scheme we do not know. It names exactly what is supported.
const UnknownFormatMsg = "Неизвестный формат ключа. Поддерживаются ключи vless://, ss:// (Shadowsocks и Outline) и ssconf:// (динамические ключи Outline)."

// schemeLen returns the length of "scheme://" at the start of text, or 0.
func schemeLen(text string) int {
	i := strings.Index(text, "://")
	if i < 1 || i > 12 {
		return 0
	}
	return i + 3
}

// IsDynamic reports whether the text is an Outline dynamic key (ssconf://). Such a key must be resolved
// with package dynkey before it can be turned into a profile.
func IsDynamic(raw string) bool {
	t := strings.TrimSpace(raw)
	return len(t) >= 9 && strings.EqualFold(t[:9], "ssconf://")
}

// Clean applies the same pre-processing as Parse (display name after '#' dropped, a single line required)
// and returns the key text without the fragment.
func Clean(raw string) (string, *Error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return "", fail("empty", "Вставьте ключ подключения из бота.")
	}
	if i := strings.Index(text, "#"); i >= 0 {
		text = text[:i]
	}
	if strings.IndexFunc(text, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }) >= 0 {
		return "", fail("multi", "Вставьте один ключ целиком, без пробелов и переносов строк.")
	}
	return text, nil
}

// Parse validates raw and returns the profile for the core.
func Parse(raw string) (*config.Profile, *Error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil, fail("empty", "Вставьте ключ подключения из бота.")
	}
	// The part after '#' is only a display name given by the provider ("Server 1", in any
	// language). It may contain spaces and plays no role in the connection, so drop it first.
	if i := strings.Index(text, "#"); i >= 0 {
		text = text[:i]
	}
	if strings.IndexFunc(text, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }) >= 0 {
		return nil, fail("multi", "Вставьте один ключ целиком, без пробелов и переносов строк.")
	}
	switch strings.ToLower(text[:schemeLen(text)]) {
	case "vless://":
		// handled below
	case "ss://":
		return parseShadowsocks(text)
	case "ssconf://":
		return nil, fail("dynamic", "Это динамический ключ (ssconf://): его настройки загружаются при подключении.")
	default:
		return nil, fail("scheme", UnknownFormatMsg)
	}
	u, err := url.Parse(text)
	if err != nil || u.Host == "" {
		return nil, fail("broken", "Ключ повреждён или скопирован не целиком. Скопируйте его из бота ещё раз.")
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
