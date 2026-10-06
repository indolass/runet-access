package keyparse

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"runetaccess/internal/config"
)

const (
	ssHost = "203.0.113.9"
	ssPass = "Pa$$w0rd/with+odd:chars"
)

func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func mustSS(t *testing.T, key string) *config.Profile {
	t.Helper()
	p, err := Parse(key)
	if err != nil {
		t.Fatalf("%q: %s (%s)", key, err.Message, err.Code)
	}
	return p
}

func TestShadowsocksFormats(t *testing.T) {
	key2022 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")) // 16 bytes
	key2022b := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	cases := []struct {
		name, key, method, pass, host string
		port                          int
	}{
		{"SIP002 base64url, no padding", "ss://" + b64url("chacha20-ietf-poly1305:"+ssPass) + "@" + ssHost + ":8388", "chacha20-ietf-poly1305", ssPass, ssHost, 8388},
		{"SIP002 with padding and slash", "ss://" + base64.URLEncoding.EncodeToString([]byte("aes-256-gcm:"+ssPass)) + "@" + ssHost + ":443/", "aes-256-gcm", ssPass, ssHost, 443},
		{"SIP002 standard alphabet", "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:"+ssPass)) + "@" + ssHost + ":1", "aes-128-gcm", ssPass, ssHost, 1},
		{"Outline static key with the outline marker and a Russian name with spaces",
			"ss://" + b64url("chacha20-ietf-poly1305:secret") + "@" + ssHost + ":8388/?outline=1#Назад в СССР / Сервер 1", "chacha20-ietf-poly1305", "secret", ssHost, 8388},
		{"AEAD-2022 percent-encoded, not base64", "ss://2022-blake3-aes-128-gcm:" + url.PathEscape(key2022) + "@" + ssHost + ":8388", "2022-blake3-aes-128-gcm", key2022, ssHost, 8388},
		{"AEAD-2022 256 bit", "ss://2022-blake3-chacha20-poly1305:" + url.PathEscape(key2022b) + "@host.example.org:9000/", "2022-blake3-chacha20-poly1305", key2022b, "host.example.org", 9000},
		{"legacy: everything in one base64", "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret@"+ssHost+":8443")), "aes-256-gcm", "secret", ssHost, 8443},
		{"IPv6 host", "ss://" + b64url("aes-256-gcm:secret") + "@[2001:db8::1]:8388", "aes-256-gcm", "secret", "2001:db8::1", 8388},
		{"upper-case scheme and cipher", "SS://" + b64url("AES-256-GCM:secret") + "@" + ssHost + ":8388", "aes-256-gcm", "secret", ssHost, 8388},
	}
	for _, c := range cases {
		p := mustSS(t, c.key)
		if p.Type != "shadowsocks" || p.Method != c.method || p.Password != c.pass || p.Server != c.host || p.Port != c.port {
			t.Errorf("%s: got type=%s method=%s host=%s port=%d pass-ok=%v", c.name, p.Type, p.Method, p.Server, p.Port, p.Password == c.pass)
		}
	}
}

func TestShadowsocksReachesTheCoreConfig(t *testing.T) {
	p := mustSS(t, "ss://"+b64url("chacha20-ietf-poly1305:secret")+"@"+ssHost+":8388/?outline=1")
	cfg, err := config.Build(p, config.Inbound{Listen: "127.0.0.1", Port: 1080}, config.Routing{Final: "proxy"}, "warn")
	if err != nil {
		t.Fatal(err)
	}
	s := string(cfg)
	for _, want := range []string{`"type": "shadowsocks"`, `"method": "chacha20-ietf-poly1305"`, `"password": "secret"`, `"server_port": 8388`, `"tag": "proxy"`, `"final": "proxy"`} {
		if !strings.Contains(s, want) {
			t.Errorf("config lacks %s", want)
		}
	}
	for _, bad := range []string{`"tls"`, `"transport"`, `"plugin"`, `"insecure"`} {
		if strings.Contains(s, bad) {
			t.Errorf("config must not contain %s for plain Shadowsocks", bad)
		}
	}
}

func TestShadowsocksRefusals(t *testing.T) {
	good := b64url("chacha20-ietf-poly1305:" + ssPass)
	key2022 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	cases := []struct {
		name, key, code, class string
	}{
		{"unknown scheme", "vmess://abcdef", "scheme", ClassFormat},
		{"hysteria link", "hysteria2://pw@host:443", "scheme", ClassFormat},
		{"plain text", "hello", "scheme", ClassFormat},
		{"empty", "   ", "empty", ClassKey},
		{"two keys on one line", "ss://" + good + "@" + ssHost + ":1 ss://x", "multi", ClassKey},
		{"nothing after the scheme", "ss://", "broken", ClassKey},
		{"not base64, no @", "ss://!!!notbase64!!!", "broken", ClassKey},
		{"base64 without a colon", "ss://" + b64url("justwords") + "@" + ssHost + ":1", "broken", ClassKey},
		{"empty password", "ss://" + b64url("aes-256-gcm:") + "@" + ssHost + ":1", "key", ClassKey},
		{"no port", "ss://" + good + "@" + ssHost, "server", ClassKey},
		{"port out of range", "ss://" + good + "@" + ssHost + ":70000", "server", ClassKey},
		{"unknown cipher", "ss://" + b64url("magic-cipher:secret") + "@" + ssHost + ":1", "ss-cipher", ClassUnsupported},
		{"obsolete cipher rc4-md5", "ss://" + b64url("rc4-md5:secret") + "@" + ssHost + ":1", "ss-legacy-cipher", ClassUnsupported},
		{"cfb cipher", "ss://" + b64url("aes-256-cfb:secret") + "@" + ssHost + ":1", "ss-legacy-cipher", ClassUnsupported},
		{"no encryption at all", "ss://" + b64url("none:secret") + "@" + ssHost + ":1", "ss-legacy-cipher", ClassUnsupported},
		{"2022 key of the wrong length", "ss://2022-blake3-aes-256-gcm:" + url.PathEscape(key2022) + "@" + ssHost + ":1", "key", ClassKey},
		{"2022 key that is not base64", "ss://2022-blake3-aes-128-gcm:not-a-key@" + ssHost + ":1", "key", ClassKey},
		{"plugin", "ss://" + good + "@" + ssHost + ":1/?plugin=" + url.QueryEscape("obfs-local;obfs=http;obfs-host=SECRETHOST"), "ss-plugin", ClassUnsupported},
		{"Outline prefix", "ss://" + good + "@" + ssHost + ":1/?prefix=" + url.QueryEscape("\x16\x03\x01\x00"), "ss-prefix", ClassUnsupported},
		{"unknown parameter", "ss://" + good + "@" + ssHost + ":1/?udp-over-tcp=1", "ss-param", ClassUnsupported},
		{"dynamic key is not a static one", "ssconf://keys.public-test.org/path?x=1", "dynamic", ClassKey},
	}
	secrets := []string{ssHost, "Pa$$w0rd", "SECRETHOST", good, "keys.public-test.org", "path?x=1", "/path"}
	for _, c := range cases {
		_, err := Parse(c.key)
		if err == nil {
			t.Errorf("%s: must be refused", c.name)
			continue
		}
		if err.Code != c.code || err.Class != c.class {
			t.Errorf("%s: got code=%s class=%s, want %s/%s (%s)", c.name, err.Code, err.Class, c.code, c.class, err.Message)
		}
		for _, s := range secrets {
			if strings.Contains(err.Message, s) {
				t.Errorf("%s: the message leaks %q: %s", c.name, s, err.Message)
			}
		}
	}
}

func TestUnknownFormatNamesWhatIsSupported(t *testing.T) {
	_, err := Parse("trojan://x@y:1")
	if err == nil || !strings.Contains(err.Message, "vless://") || !strings.Contains(err.Message, "ss://") || !strings.Contains(err.Message, "ssconf://") {
		t.Fatalf("the message must list the supported formats: %v", err)
	}
	if strings.Contains(err.Message, "Нужен ключ, который начинается") {
		t.Fatal("the old 'vless:// only' wording is back")
	}
}

func TestVlessStillWorksAndIsClassified(t *testing.T) {
	// the VLESS rules are unchanged: Reality, WebSocket+TLS and the certificate rule
	if _, err := Parse("vless://11111111-2222-3333-4444-555555555555@203.0.113.9:443?security=tls&type=ws&sni=host.example.org&path=%2Fws"); err != nil {
		t.Fatalf("WebSocket+TLS: %v", err)
	}
	if _, err := Parse("vless://11111111-2222-3333-4444-555555555555@203.0.113.9:443?security=tls&type=ws&sni=host.example.org&allowInsecure=1"); err == nil || err.Class != ClassUnsupported {
		t.Fatalf("allowInsecure must stay refused as unsupported: %v", err)
	}
	if _, err := Parse("vless://x"); err == nil || err.Class != ClassKey {
		t.Fatalf("a broken vless key is a key problem: %v", err)
	}
}

func TestIsDynamicAndClean(t *testing.T) {
	if !IsDynamic("  SSCONF://a.b/c ") || IsDynamic("ss://x") || IsDynamic("ssconfx://") {
		t.Fatal("IsDynamic")
	}
	got, err := Clean("ssconf://a.b/c?d=e#Имя с пробелами")
	if err != nil || got != "ssconf://a.b/c?d=e" {
		t.Fatalf("%q %v", got, err)
	}
}
