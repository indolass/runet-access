package keyparse

import (
	"strings"
	"testing"
)

// Obviously synthetic: documentation-range host, fixed test UUID, made-up public key.
const (
	testUUID = "11111111-2222-3333-4444-555555555555"
	testPBK  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func key(params string) string {
	return "vless://" + testUUID + "@192.0.2.10:443?" + params + "#synthetic"
}

const good = "encryption=none&flow=xtls-rprx-vision&security=reality&sni=masque.example&fp=chrome&pbk=" + testPBK + "&sid=abcd1234&type=tcp"

func TestAcceptsGoodKey(t *testing.T) {
	p, err := Parse(key(good))
	if err != nil {
		t.Fatalf("rejected: %v", err)
	}
	if p.Type != "vless" || p.Server != "192.0.2.10" || p.Port != 443 || p.Flow != "xtls-rprx-vision" ||
		p.TLS.Reality.PublicKey != testPBK || p.TLS.ServerName != "masque.example" || p.Name != "Runet Access" {
		t.Fatalf("unexpected profile: %+v", p)
	}
}

func TestFragmentNameMaySpaceAndBeCyrillic(t *testing.T) {
	in := "vless://" + testUUID + "@192.0.2.10:443?" + good + "#Имя сервера с пробелами 1"
	if _, err := Parse(in); err != nil {
		t.Fatalf("rejected a key whose only spaces are in the #name: %v", err)
	}
	if _, err := Parse(strings.Replace(in, "&sid=abcd1234", "&sid=abcd 1234", 1)); err == nil || err.Code != "multi" {
		t.Fatalf("space inside the real part must still be rejected, got %v", err)
	}
}

func TestRejects(t *testing.T) {
	cases := []struct{ name, in, code string }{
		{"empty", "", "empty"},
		{"whitespace before #", strings.Replace(key(good), "#synthetic", " extra#synthetic", 1), "multi"},
		{"second key after a space, no #", "vless://" + testUUID + "@192.0.2.10:443?" + good + " vless://x", "multi"},
		{"other scheme", "vmess://abcdef", "scheme"},
		{"tls over plain tcp is not a supported shape", key(strings.Replace(good, "security=reality", "security=tls", 1)), "transport"},
		{"no security at all", key(strings.Replace(good, "security=reality", "security=none", 1)), "unsupported"},
		{"certificate check switched off", key(good + "&allowInsecure=1"), "insecure"},
		{"no flow", key(strings.Replace(good, "flow=xtls-rprx-vision&", "", 1)), "flow"},
		{"wrong flow", key(strings.Replace(good, "xtls-rprx-vision", "xtls-rprx-direct", 1)), "flow"},
		{"bad pbk", key(strings.Replace(good, testPBK, "short", 1)), "pbk"},
		{"bad sid", key(strings.Replace(good, "abcd1234", "zzzz", 1)), "sid"},
		{"no sni", key(strings.Replace(good, "sni=masque.example&", "", 1)), "sni"},
		{"ws transport", key(strings.Replace(good, "type=tcp", "type=ws&path=%2Fx", 1)), "transport"},
		{"bad uuid", strings.Replace(key(good), testUUID, "not-a-uuid", 1), "uuid"},
		{"bad encryption", key(strings.Replace(good, "encryption=none", "encryption=aes", 1)), "encryption"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.in)
			if err == nil {
				t.Fatal("accepted")
			}
			if err.Code != c.code {
				t.Fatalf("code %q, want %q", err.Code, c.code)
			}
			for _, secret := range []string{testUUID, testPBK, "192.0.2.10", "abcd1234"} {
				if strings.Contains(err.Message, secret) {
					t.Fatalf("message leaks %q", secret)
				}
			}
		})
	}
}
