package keyparse

import (
	"encoding/base64"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"runetaccess/internal/config"
	"runetaccess/internal/ssbridge"
)

// Shadowsocks keys (ss://).
//
// Accepted shapes (SIP002 https://shadowsocks.org/doc/sip002.html, and what Outline issues):
//
//	ss://BASE64URL(method:password)@host:port[/][?outline=1][#name]     stream/AEAD ciphers, Outline static keys
//	ss://method:password@host:port[/]...        AEAD-2022: userinfo is NOT base64 (percent-encoded instead)
//	ss://BASE64(method:password@host:port)[#name]                        the legacy form
//
// The set of ciphers is exactly what the pinned sing-box core can use securely: AEAD and AEAD-2022.
// The legacy stream ciphers and "none" are refused with their own message. A key that carries a plugin is
// refused with an exact message: nothing is silently dropped (the plugins are not enabled in this product).
//
// The Outline "prefix" (https://developer.getoutline.org/vpn/advanced/prefixing/) is the first bytes of the
// Shadowsocks salt. The pinned sing-box 1.13.16 cannot set them, so a key with a prefix is carried out by
// package ssbridge (the Outline SDK) and the profile gets Prefix; it is possible only with the ciphers the
// SDK has (chacha20-ietf-poly1305, aes-128/192/256-gcm). The query value is decoded exactly as the Outline
// client decodes it: percent-decoding, then each character (code 0..255) is one byte.
// Messages never contain the server, the password, the prefix or any other part of the key; the cipher name
// and the NAME of an unexpected parameter are not secrets.

// ssCiphers: what the product accepts. Value = key length in bytes for the 2022 family, 0 otherwise.
var ssCiphers = map[string]int{
	"aes-128-gcm":                   0,
	"aes-192-gcm":                   0,
	"aes-256-gcm":                   0,
	"chacha20-ietf-poly1305":        0,
	"xchacha20-ietf-poly1305":       0,
	"2022-blake3-aes-128-gcm":       16,
	"2022-blake3-aes-256-gcm":       32,
	"2022-blake3-chacha20-poly1305": 32,
}

// Ciphers sing-box still knows but that are obsolete or unencrypted.
var ssLegacy = map[string]bool{
	"none": true, "aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true, "aes-128-cfb": true,
	"aes-192-cfb": true, "aes-256-cfb": true, "rc4-md5": true, "chacha20-ietf": true, "xchacha20": true,
	"rc4": true, "chacha20": true, "salsa20": true, "bf-cfb": true, "table": true,
}

// DecodePrefix turns the text of a prefix (already percent-decoded by the URL, JSON or YAML reader) into the
// bytes Outline uses: each character is one byte, so only the code points 0..255 are allowed. A text that is
// not valid UTF-8 (a lone %A8, say) yields U+FFFD and is refused, as the Outline client refuses it.
func DecodePrefix(s string) ([]byte, *Error) {
	if s == "" {
		return nil, nil
	}
	rs := []rune(s)
	out := make([]byte, len(rs))
	for i, r := range rs {
		if r < 0 || r > 0xFF {
			return nil, fail("ss-prefix-bad", "Префикс в ключе записан неверно: допустимы только символы с кодами от 0 до 255, как требует Outline.")
		}
		out[i] = byte(r)
	}
	return out, nil
}

// SafeName shortens a parameter or cipher name for a message: only plain characters survive.
func SafeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if len(b.String()) >= 32 {
			b.WriteString("…")
			break
		}
		if r == '-' || r == '_' || r == '.' || r == '$' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		} else {
			b.WriteRune('?')
		}
	}
	return b.String()
}

func decodeB64(s string) (string, bool) {
	s = strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), true
		}
	}
	return "", false
}

// ParseShadowsocks parses a static ss:// key (already stripped of its #name).
func ParseShadowsocks(text string) (*config.Profile, *Error) { return parseShadowsocks(text) }

func parseShadowsocks(text string) (*config.Profile, *Error) {
	broken := fail("broken", "Ключ повреждён или скопирован не целиком. Скопируйте его из бота ещё раз.")
	rest := text[len("ss://"):]
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query, rest = rest[i+1:], rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" {
		return nil, broken
	}

	var methodPass, hostPort string
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		userinfo := rest[:at]
		hostPort = rest[at+1:]
		plain, err := url.PathUnescape(userinfo)
		if err != nil {
			return nil, broken
		}
		if strings.Contains(plain, ":") { // AEAD-2022 and any key written without base64
			methodPass = plain
		} else if dec, ok := decodeB64(userinfo); ok && strings.Contains(dec, ":") {
			methodPass = dec
		} else {
			return nil, broken
		}
	} else { // the legacy form: everything is inside one base64 blob
		dec, ok := decodeB64(rest)
		at := strings.LastIndex(dec, "@")
		if !ok || at < 0 {
			return nil, broken
		}
		methodPass, hostPort = dec[:at], dec[at+1:]
	}

	i := strings.Index(methodPass, ":")
	method, password := strings.ToLower(methodPass[:i]), methodPass[i+1:]
	if password == "" {
		return nil, fail("key", "В ключе нет пароля.")
	}

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, fail("server", "В ключе нет адреса сервера или порта.")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fail("server", "В ключе нет адреса сервера или порта.")
	}

	prefix, qerr := checkSSQuery(query)
	if qerr != nil {
		return nil, qerr
	}
	return ShadowsocksProfile(host, port, method, password, prefix)
}

// Fail builds an Error of the right class for other packages (dynkey).
func Fail(code, msg string) *Error { return fail(code, msg) }

// ShadowsocksProfile validates the parts of a Shadowsocks key, wherever they came from (an ss:// link,
// the JSON or the YAML of a dynamic key), and returns the profile. prefix is the Outline prefix (nil = none).
func ShadowsocksProfile(host string, port int, method, password string, prefix []byte) (*config.Profile, *Error) {
	method = strings.ToLower(strings.TrimSpace(method))
	if host == "" || strings.ContainsAny(host, " /\\@\t\r\n") || port < 1 || port > 65535 {
		return nil, fail("server", "В ключе нет адреса сервера или порта.")
	}
	if password == "" {
		return nil, fail("key", "В ключе нет пароля.")
	}
	if e := checkSSCipher(method, password); e != nil {
		return nil, e
	}
	if len(prefix) > 0 {
		switch ssbridge.CheckPrefix(method, prefix) {
		case "cipher":
			return nil, fail("ss-prefix-cipher", "Префикс Outline работает только с шифрами chacha20-ietf-poly1305 и aes-128/192/256-gcm. Шифр «"+SafeName(method)+"» с префиксом не поддерживается.")
		case "long":
			return nil, fail("ss-prefix-long", "Префикс в ключе слишком длинный: допускается не больше "+strconv.Itoa(maxPrefixFor(method))+" байт, чтобы в соединении оставалась случайная часть.")
		}
	}
	return &config.Profile{
		ID: "runet-access-key", Name: ProfileName, Type: "shadowsocks",
		Server: host, Port: port, Method: method, Password: password, Prefix: append([]byte(nil), prefix...),
	}, nil
}

// maxPrefixFor is the longest prefix allowed with the cipher (for the message only).
func maxPrefixFor(method string) int {
	n := ssbridge.MaxPrefix
	if salt, ok := ssbridge.CipherInfo(method); ok && salt-8 < n {
		n = salt - 8
	}
	return n
}

// checkSSQuery accepts Outline's own marker and its prefix; everything else is named and refused.
func checkSSQuery(query string) ([]byte, *Error) {
	if query == "" {
		return nil, nil
	}
	vals, err := url.ParseQuery(query)
	if err != nil {
		return nil, fail("broken", "Ключ повреждён или скопирован не целиком. Скопируйте его из бота ещё раз.")
	}
	var prefix []byte
	names := make([]string, 0, len(vals))
	for k := range vals {
		names = append(names, k)
	}
	sort.Strings(names) // when several things are wrong, the same one is always named
	for _, k := range names {
		v := vals[k]
		switch strings.ToLower(k) {
		case "outline":
			// Outline marks its own keys with outline=1; it changes nothing for the connection
		case "prefix":
			if len(v) > 0 {
				p, perr := DecodePrefix(v[0])
				if perr != nil {
					return nil, perr
				}
				prefix = p
			}
		case "plugin":
			name := ""
			if len(v) > 0 {
				name = v[0]
				if j := strings.Index(name, ";"); j >= 0 {
					name = name[:j]
				}
			}
			return nil, fail("ss-plugin", "Ключ требует плагин Shadowsocks «"+SafeName(name)+"»: плагины не поддерживаются.")
		default:
			return nil, fail("ss-param", "Ключ содержит параметр «"+SafeName(k)+"», который не поддерживается.")
		}
	}
	return prefix, nil
}

func checkSSCipher(method, password string) *Error {
	if ssLegacy[method] {
		return fail("ss-legacy-cipher", "Шифр «"+SafeName(method)+"» устарел или не шифрует трафик и не поддерживается. Нужен современный шифр (AEAD).")
	}
	keyLen, ok := ssCiphers[method]
	if !ok {
		return fail("ss-cipher", "Шифр «"+SafeName(method)+"» не поддерживается.")
	}
	if keyLen > 0 { // AEAD-2022: the password is a base64 key of an exact length (several, joined by ':', for a relay)
		for _, part := range strings.Split(password, ":") {
			b, err := base64.StdEncoding.DecodeString(part)
			if err != nil || len(b) != keyLen {
				return fail("key", "Пароль ключа не подходит к шифру: для него нужен ключ в Base64 длиной "+strconv.Itoa(keyLen)+" байт.")
			}
		}
	}
	return nil
}
