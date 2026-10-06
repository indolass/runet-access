package keyparse

import (
	"encoding/json"
	"strings"
	"testing"

	"runetaccess/internal/config"
)

// Regression: the key HLVPN support actually issued ("Рунет") is VLESS over TLS over WebSocket, not
// Reality. An independent Xray client carried traffic with it, while the parser rejected it up front
// ("not Reality"). The values below are synthetic; the SHAPE (parameter names and kinds) is the real one.
const tlsWS = "encryption=none&security=tls&type=ws&sni=cdn.example&host=front.example&path=%2Fapi%2Fws%3Fed%3D2048&alpn=h2%2Chttp%2F1.1&fp=edge&packetEncoding=xudp"

func tlsKey(params string) string {
	return "vless://" + testUUID + "@edge.example:443?" + params + "#Имя сервера 1"
}

// buildFor runs the key through the same path the launcher uses and returns the proxy outbound.
func buildFor(t *testing.T, in string) map[string]any {
	t.Helper()
	p, err := Parse(in)
	if err != nil {
		t.Fatalf("rejected: %v", err)
	}
	raw, e := config.Build(p, config.Inbound{Listen: "127.0.0.1", Port: 17000}, config.Routing{Final: "proxy"}, "warn")
	if e != nil {
		t.Fatalf("generator refused the profile: %v", e)
	}
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if e := json.Unmarshal(raw, &cfg); e != nil {
		t.Fatal(e)
	}
	for _, o := range cfg.Outbounds {
		if o["tag"] == "proxy" {
			return o
		}
	}
	t.Fatal("no proxy outbound in the generated config")
	return nil
}

func TestTLSWebSocketKeyBecomesAWorkingOutbound(t *testing.T) {
	o := buildFor(t, tlsKey(tlsWS))
	tls, _ := o["tls"].(map[string]any)
	tr, _ := o["transport"].(map[string]any)
	if o["type"] != "vless" || o["uuid"] != testUUID {
		t.Fatalf("wrong outbound: %v", o["type"])
	}
	if tls == nil || tls["enabled"] != true || tls["server_name"] != "cdn.example" {
		t.Fatalf("TLS not enabled with the key's server name: %v", tls)
	}
	if v, present := tls["insecure"]; present && v == true {
		t.Fatal("certificate verification was switched off")
	}
	if _, has := tls["reality"]; has {
		t.Fatal("a TLS key must not produce a Reality block")
	}
	if alpn, _ := tls["alpn"].([]any); len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Fatalf("alpn lost: %v", tls["alpn"])
	}
	if utls, _ := tls["utls"].(map[string]any); utls == nil || utls["fingerprint"] != "edge" {
		t.Fatalf("fingerprint of the key lost: %v", tls["utls"])
	}
	hdr, _ := tr["headers"].(map[string]any)
	if tr["type"] != "ws" || tr["path"] != "/api/ws?ed=2048" || hdr["Host"] != "front.example" {
		t.Fatalf("WebSocket transport wrong: %v", tr)
	}
	if o["packet_encoding"] != "xudp" {
		t.Fatalf("packet encoding: %v", o["packet_encoding"])
	}
	if _, has := o["flow"]; has {
		t.Fatal("a flow must not be sent over WebSocket")
	}
}

func TestTLSWebSocketDropsAFlowAttachedByMistake(t *testing.T) {
	o := buildFor(t, tlsKey(tlsWS+"&flow=xtls-rprx-vision"))
	if _, has := o["flow"]; has {
		t.Fatal("flow=xtls-rprx-vision over WebSocket black-holes connections; it must be dropped")
	}
}

func TestTLSServerNameDefaultsToAddressNameOnly(t *testing.T) {
	o := buildFor(t, tlsKey(strings.Replace(tlsWS, "sni=cdn.example&", "", 1)))
	if tls, _ := o["tls"].(map[string]any); tls["server_name"] != "edge.example" {
		t.Fatalf("server name should default to the address name, got %v", tls["server_name"])
	}
	ipKey := strings.Replace(tlsKey(strings.Replace(tlsWS, "sni=cdn.example&", "", 1)), "edge.example", "192.0.2.10", 1)
	if _, err := Parse(ipKey); err == nil || err.Code != "sni" {
		t.Fatalf("an IP address without sni must be refused (the certificate name is unknown), got %v", err)
	}
}

func TestCertificateVerificationCanNotBeSwitchedOffByAKey(t *testing.T) {
	for _, extra := range []string{"&allowInsecure=1", "&allowInsecure=true", "&insecure=1", "&insecure=TRUE"} {
		if _, err := Parse(tlsKey(tlsWS + extra)); err == nil || err.Code != "insecure" {
			t.Fatalf("%s accepted: %v", extra, err)
		}
		if _, err := Parse(key(good + extra)); err == nil || err.Code != "insecure" {
			t.Fatalf("%s accepted for a Reality key: %v", extra, err)
		}
	}
	if _, err := Parse(tlsKey(tlsWS + "&allowInsecure=0")); err != nil {
		t.Fatalf("an explicit 'off' must be harmless: %v", err)
	}
}

func TestTLSKeysThatAreNotWebSocketAreRefusedPlainly(t *testing.T) {
	cases := []struct{ name, in, code string }{
		{"tls over tcp", tlsKey(strings.Replace(tlsWS, "type=ws", "type=tcp", 1)), "transport"},
		{"tls over grpc", tlsKey(strings.Replace(tlsWS, "type=ws", "type=grpc", 1)), "transport"},
		{"tls without a type", tlsKey(strings.Replace(tlsWS, "type=ws&", "", 1)), "transport"},
		{"unsupported packet packing", tlsKey(strings.Replace(tlsWS, "packetEncoding=xudp", "packetEncoding=packetaddr", 1)), "packet"},
		{"no security", tlsKey(strings.Replace(tlsWS, "security=tls", "security=none", 1)), "unsupported"},
		{"xtls security", tlsKey(strings.Replace(tlsWS, "security=tls", "security=xtls", 1)), "unsupported"},
		{"unknown encryption", tlsKey(strings.Replace(tlsWS, "encryption=none", "encryption=aes", 1)), "encryption"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.in)
			if err == nil || err.Code != c.code {
				t.Fatalf("got %v, want code %q", err, c.code)
			}
			for _, secret := range []string{testUUID, "edge.example", "cdn.example", "front.example", "/api/ws"} {
				if strings.Contains(err.Message, secret) {
					t.Fatalf("message leaks %q", secret)
				}
			}
		})
	}
}
