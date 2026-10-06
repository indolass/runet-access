package dynkey

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"runetaccess/internal/config"
	"runetaccess/internal/keyparse"
)

// Interpret reads the settings page of a dynamic key. Three answers are understood (Outline's own):
//   - a single ss:// link;
//   - the JSON object {"server", "server_port", "password", "method"};
//   - a YAML transport description, ONLY in its documented simple shape (see parseYAML / fromTransport).
//
// Anything else, and any parameter beyond the ones we use, is refused by name.
func Interpret(body []byte) (*config.Profile, *keyparse.Error) {
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\uFEFF"))
	if text == "" {
		return nil, keyparse.Fail("fetch-empty", "Не удалось загрузить настройки ключа: сервер настроек вернул пустой ответ.")
	}
	switch {
	case strings.HasPrefix(strings.ToLower(text), "ss://"):
		return fromLink(text)
	case strings.HasPrefix(text, "{"):
		return fromJSON([]byte(text))
	case looksLikeYAML(text):
		return fromYAML(text)
	}
	return nil, keyparse.Fail("dyn-format", "Настройки ключа содержат неподдерживаемые параметры: ответ сервера настроек не похож ни на ss://, ни на JSON, ни на YAML Outline.")
}

func fromLink(text string) (*config.Profile, *keyparse.Error) {
	clean, kerr := keyparse.Clean(text)
	if kerr != nil {
		return nil, keyparse.Fail("dyn-format", "Настройки ключа содержат неподдерживаемые параметры: ответ сервера настроек должен быть одной строкой ss://.")
	}
	return keyparse.ParseShadowsocks(clean)
}

// JSON fields that mean nothing for the connection (a label) and may be ignored.
var jsonIgnored = map[string]bool{"name": true, "remarks": true, "tag": true, "comment": true, "description": true}

func fromJSON(b []byte) (*config.Profile, *keyparse.Error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, keyparse.Fail("dyn-format", "Настройки ключа содержат неподдерживаемые параметры: ответ сервера настроек не является корректным JSON.")
	}
	str := func(k string) string {
		switch v := m[k].(type) {
		case string:
			return v
		}
		return ""
	}
	var prefix []byte
	for _, k := range sortedKeys(m) {
		v := m[k]
		switch strings.ToLower(k) {
		case "server", "server_port", "password", "method":
		case "prefix":
			if v == nil {
				continue
			}
			s, isStr := v.(string)
			if !isStr {
				return nil, keyparse.Fail("dyn-param", "Настройки ключа содержат неподдерживаемые параметры: «prefix» должен быть строкой.")
			}
			p, perr := keyparse.DecodePrefix(s)
			if perr != nil {
				return nil, perr
			}
			prefix = p
		case "plugin", "plugin_opts":
			if s, _ := v.(string); s != "" {
				return nil, keyparse.Fail("ss-plugin", "Настройки ключа требуют плагин Shadowsocks «"+keyparse.SafeName(strings.SplitN(s, ";", 2)[0])+"»: плагины не поддерживаются.")
			}
		default:
			if jsonIgnored[strings.ToLower(k)] {
				continue
			}
			return nil, keyparse.Fail("dyn-param", "Настройки ключа содержат неподдерживаемые параметры: «"+keyparse.SafeName(k)+"».")
		}
	}
	port := 0
	switch v := m["server_port"].(type) {
	case json.Number:
		port, _ = strconv.Atoi(v.String())
	case string:
		port, _ = strconv.Atoi(strings.TrimSpace(v))
	}
	return keyparse.ShadowsocksProfile(str("server"), port, str("method"), str("password"), prefix)
}

func looksLikeYAML(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(line, "transport:") || strings.Contains(l, "$type") {
			return true
		}
	}
	return false
}

func fromYAML(text string) (*config.Profile, *keyparse.Error) {
	root, err := parseYAML(text)
	if err != "" {
		return nil, keyparse.Fail("dyn-yaml", "Настройки ключа содержат неподдерживаемые параметры: "+err+".")
	}
	if _, ok := root["transport"]; !ok {
		return nil, keyparse.Fail("dyn-yaml", "Настройки ключа содержат неподдерживаемые параметры: в YAML нет раздела transport.")
	}
	for _, k := range sortedKeys(root) {
		if k != "transport" {
			return nil, keyparse.Fail("dyn-param", "Настройки ключа содержат неподдерживаемые параметры: «"+keyparse.SafeName(k)+"».")
		}
	}
	switch t := root["transport"].(type) {
	case string: // a transport given as a link
		if strings.HasPrefix(strings.ToLower(t), "ss://") {
			return fromLink(t)
		}
		return nil, keyparse.Fail("dyn-transport", "Настройки ключа содержат неподдерживаемые параметры: транспорт задан строкой, которую мы не понимаем.")
	case map[string]any:
		return fromTransport(t)
	}
	return nil, keyparse.Fail("dyn-yaml", "Настройки ключа содержат неподдерживаемые параметры: в YAML нет раздела transport.")
}

func typeOf(m map[string]any) string {
	s, _ := m["$type"].(string)
	return s
}

// fromTransport understands exactly the documented Outline shapes for Shadowsocks:
//
//	transport: {$type: tcpudp, tcp: <shadowsocks>, udp: <shadowsocks>}   (udp optional)
//	transport: <shadowsocks>
//
// where <shadowsocks> is {$type: shadowsocks, endpoint, cipher, secret, prefix?}. Every other transport
// type (websocket, tls, socks5, split, disorder, override, ...) is named and refused.
//
// The prefix of the tcp part is the one used (everything the browser sends is TCP). The udp part may carry a
// different prefix (Outline lets the two differ); it is not used, but its server, cipher and secret must be
// the same as the tcp part's, as before.
func fromTransport(t map[string]any) (*config.Profile, *keyparse.Error) {
	var tcp, udp map[string]any
	switch ty := typeOf(t); ty {
	case "tcpudp":
		for _, k := range sortedKeys(t) {
			if k != "$type" && k != "tcp" && k != "udp" {
				return nil, keyparse.Fail("dyn-param", "Настройки ключа содержат неподдерживаемые параметры: «"+keyparse.SafeName(k)+"».")
			}
		}
		tcp, _ = t["tcp"].(map[string]any)
		udp, _ = t["udp"].(map[string]any)
		if tcp == nil {
			return nil, keyparse.Fail("dyn-yaml", "Настройки ключа содержат неподдерживаемые параметры: в transport нет раздела tcp.")
		}
	case "shadowsocks":
		tcp = t
	default:
		return nil, keyparse.Fail("dyn-transport", "Настройки ключа содержат неподдерживаемые параметры: транспорт «"+keyparse.SafeName(ty)+"» не поддерживается.")
	}
	host, port, method, secret, prefix, kerr := shadowsocksPart(tcp)
	if kerr != nil {
		return nil, kerr
	}
	if udp != nil {
		h2, p2, m2, s2, _, kerr := shadowsocksPart(udp)
		if kerr != nil {
			return nil, kerr
		}
		if h2 != host || p2 != port || m2 != method || s2 != secret {
			return nil, keyparse.Fail("dyn-param", "Настройки ключа содержат неподдерживаемые параметры: для TCP и UDP заданы разные серверы или пароли.")
		}
	}
	return keyparse.ShadowsocksProfile(host, port, method, secret, prefix)
}

func shadowsocksPart(m map[string]any) (host string, port int, method, secret string, prefix []byte, kerr *keyparse.Error) {
	if ty := typeOf(m); ty != "shadowsocks" {
		return "", 0, "", "", nil, keyparse.Fail("dyn-transport", "Настройки ключа содержат неподдерживаемые параметры: транспорт «"+keyparse.SafeName(ty)+"» не поддерживается.")
	}
	for _, k := range sortedKeys(m) {
		v := m[k]
		switch k {
		case "$type", "endpoint", "cipher", "secret":
		case "prefix":
			s, isStr := v.(string)
			if !isStr {
				return "", 0, "", "", nil, keyparse.Fail("dyn-param", "Настройки ключа содержат неподдерживаемые параметры: «prefix» должен быть строкой.")
			}
			p, perr := keyparse.DecodePrefix(s)
			if perr != nil {
				return "", 0, "", "", nil, perr
			}
			prefix = p
		default:
			return "", 0, "", "", nil, keyparse.Fail("dyn-param", "Настройки ключа содержат неподдерживаемые параметры: «"+keyparse.SafeName(k)+"».")
		}
	}
	endpoint := ""
	switch e := m["endpoint"].(type) {
	case string:
		endpoint = e
	case map[string]any:
		if ty := typeOf(e); ty != "dial" {
			return "", 0, "", "", nil, keyparse.Fail("dyn-transport", "Настройки ключа содержат неподдерживаемые параметры: адрес сервера задан способом «"+keyparse.SafeName(ty)+"».")
		}
		for _, k := range sortedKeys(e) {
			if k != "$type" && k != "address" {
				return "", 0, "", "", nil, keyparse.Fail("dyn-param", "Настройки ключа содержат неподдерживаемые параметры: «"+keyparse.SafeName(k)+"».")
			}
		}
		endpoint, _ = e["address"].(string)
	}
	h, p, ok := splitHostPort(endpoint)
	if !ok {
		return "", 0, "", "", nil, keyparse.Fail("server", "В ключе нет адреса сервера или порта.")
	}
	method, _ = m["cipher"].(string)
	secret, _ = m["secret"].(string)
	return h, p, method, secret, prefix, nil
}

// sortedKeys makes the refusal deterministic: when several things are wrong, the same one is always named.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
