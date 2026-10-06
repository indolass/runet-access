package dynkey

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"runetaccess/internal/config"
	"runetaccess/internal/keyparse"
)

const (
	secretPass  = "PASSWORD-SECRET-123"
	secretPath  = "/s3cr3t-Path-ABC"
	secretQuery = "token=XYZ789"
)

func goodJSON(host string) string {
	return `{"server":"` + host + `","server_port":8388,"password":"` + secretPass + `","method":"chacha20-ietf-poly1305"}`
}

// stand is an HTTPS server standing in for a key provider; options trust its certificate and allow loopback.
func stand(t *testing.T, h http.HandlerFunc) (*httptest.Server, Options, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, Options{AllowLoopback: true, RootCAs: pool}, "ssconf://" + srv.Listener.Addr().String() + secretPath + "?" + secretQuery + "#Имя"
}

// noLeak checks every secret-bearing string against a message.
func noLeak(t *testing.T, what, msg string, extra ...string) {
	t.Helper()
	for _, s := range append([]string{secretPass, secretPath, secretQuery, "XYZ789", "s3cr3t", "127.0.0.1"}, extra...) {
		if strings.Contains(msg, s) {
			t.Errorf("%s: the message leaks %q: %s", what, s, msg)
		}
	}
}

func TestResolveJSON(t *testing.T) {
	var gotPath, gotQuery, gotUA string
	_, opts, key := stand(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotUA = r.URL.Path, r.URL.RawQuery, r.UserAgent()
		_, _ = w.Write([]byte(goodJSON("203.0.113.9")))
	})
	p, err := Resolve(context.Background(), key, opts)
	if err != nil {
		t.Fatal(err.Message)
	}
	if p.Type != "shadowsocks" || p.Server != "203.0.113.9" || p.Port != 8388 || p.Method != "chacha20-ietf-poly1305" || p.Password != secretPass {
		t.Fatalf("profile: %+v", p)
	}
	if gotPath != secretPath || gotQuery != secretQuery {
		t.Fatalf("the provider must receive the path and query of the key: %q %q", gotPath, gotQuery)
	}
	if gotUA != "RunetAccess" {
		t.Fatalf("user agent %q", gotUA)
	}
	if _, e := config.Build(p, config.Inbound{Listen: "127.0.0.1", Port: 1}, config.Routing{Final: "proxy"}, "warn"); e != nil {
		t.Fatal(e)
	}
}

func TestResolveSSLink(t *testing.T) {
	link := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:"+secretPass)) + "@203.0.113.9:443/?outline=1#x"
	_, opts, key := stand(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("\n" + link + "\n")) })
	p, err := Resolve(context.Background(), key, opts)
	if err != nil || p.Method != "aes-256-gcm" || p.Password != secretPass || p.Port != 443 {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestFetchFailuresAreExactAndLeakNothing(t *testing.T) {
	var big = strings.Repeat("A", 70<<10)
	type tc struct {
		name, code string
		h          http.HandlerFunc
		opts       func(*Options)
	}
	cases := []tc{
		{"404", "fetch-http", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }, nil},
		{"500", "fetch-http", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }, nil},
		{"too big", "fetch-size", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(big)) }, nil},
		{"too slow", "fetch-timeout", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(3 * time.Second):
			case <-r.Context().Done():
			}
		}, func(o *Options) { o.Timeout = 300 * time.Millisecond }},
		{"empty answer", "fetch-empty", func(w http.ResponseWriter, r *http.Request) {}, nil},
		{"redirect to plain http", "fetch-downgrade", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://keys.public-test.org/"+secretPath, http.StatusFound)
		}, nil},
		{"redirect to a private address", "fetch-blocked", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://10.0.0.5/"+secretPath, http.StatusFound)
		}, nil},
		{"redirect to the metadata address", "fetch-blocked", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://169.254.169.254/latest", http.StatusFound)
		}, nil},
		{"redirect to a service name", "fetch-blocked", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://router.local/", http.StatusFound)
		}, nil},
		{"redirect with credentials", "fetch-blocked", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://user:pw@keys.public-test.org/", http.StatusFound)
		}, nil},
		{"redirect loop", "fetch-redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
		}, nil},
	}
	for _, c := range cases {
		_, opts, key := stand(t, c.h)
		if c.opts != nil {
			c.opts(&opts)
		}
		_, err := Resolve(context.Background(), key, opts)
		if err == nil {
			t.Errorf("%s: must fail", c.name)
			continue
		}
		if err.Code != c.code || err.Class != keyparse.ClassFetch {
			t.Errorf("%s: got %s/%s: %s", c.name, err.Code, err.Class, err.Message)
		}
		if !strings.HasPrefix(err.Message, "Не удалось загрузить настройки ключа") {
			t.Errorf("%s: wording: %s", c.name, err.Message)
		}
		noLeak(t, c.name, err.Message, "10.0.0.5", "169.254", "router.local", "user:pw", "keys.public-test.org")
	}
}

func TestRedirectOnTheSameServerIsFollowed(t *testing.T) {
	_, opts, key := stand(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == secretPath {
			http.Redirect(w, r, "/moved", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(goodJSON("203.0.113.9")))
	})
	if _, err := Resolve(context.Background(), key, opts); err != nil {
		t.Fatal(err.Message)
	}
}

func TestCertificateIsAlwaysVerified(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(goodJSON("203.0.113.9"))) }))
	defer srv.Close()
	// the server's certificate is not in the trust store: no way through
	_, err := Resolve(context.Background(), "ssconf://"+srv.Listener.Addr().String()+secretPath, Options{AllowLoopback: true})
	if err == nil || err.Code != "fetch-tls" {
		t.Fatalf("got %v", err)
	}
	noLeak(t, "tls", err.Message)
}

func TestPlainHTTPServerIsNeverContacted(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { atomic.AddInt32(&hits, 1) }))
	defer srv.Close()
	// ssconf:// always means https://: a plain-HTTP listener just fails the TLS handshake
	_, err := Resolve(context.Background(), "ssconf://"+srv.Listener.Addr().String()+"/x", Options{AllowLoopback: true})
	if err == nil {
		t.Fatal("must fail")
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("an HTTP handler was reached")
	}
}

func TestInternalDestinationsAreRefusedBeforeAnyConnection(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "[::1]", "localhost", "10.1.2.3", "192.168.0.1", "172.16.5.5", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "[fd00::1]", "[fe80::1]", "intranet", "printer.local", "db.internal", "x.localhost", "224.0.0.1", "255.255.255.255", "198.18.0.1"} {
		key := "ssconf://" + host + ":8443" + secretPath + "?" + secretQuery
		_, err := Resolve(context.Background(), key, Options{Timeout: time.Second})
		if err == nil || err.Code != "fetch-blocked" {
			t.Errorf("%s: got %v", host, err)
			continue
		}
		noLeak(t, host, err.Message, host)
	}
	if _, err := Resolve(context.Background(), "ssconf://user:pw@keys.public-test.org/x", Options{}); err == nil || err.Code != "fetch-blocked" {
		t.Errorf("credentials: %v", err)
	}
}

func TestNameThatResolvesToAnInternalAddressIsRefused(t *testing.T) {
	look := func(addrs ...string) func(context.Context, string) ([]net.IP, error) {
		return func(context.Context, string) ([]net.IP, error) {
			var r []net.IP
			for _, a := range addrs {
				r = append(r, net.ParseIP(a))
			}
			return r, nil
		}
	}
	for name, addrs := range map[string][]string{
		"rebinding to loopback": {"127.0.0.1"}, "private": {"10.0.0.7"}, "public and private mixed": {"93.184.216.34", "10.0.0.7"}, "metadata": {"169.254.169.254"},
	} {
		_, err := Resolve(context.Background(), "ssconf://keys.public-test.org"+secretPath, Options{Lookup: look(addrs...), Timeout: time.Second})
		if err == nil || err.Code != "fetch-blocked" {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestCancelledFetchStops(t *testing.T) {
	_, opts, key := stand(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(150 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err := Resolve(ctx, key, opts)
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("got %v after %v", err, time.Since(start))
	}
}

func TestInterpretJSON(t *testing.T) {
	ok := []string{
		goodJSON("203.0.113.9"),
		`{"server":"203.0.113.9","server_port":"8388","password":"p","method":"aes-256-gcm","name":"label"}`,
		`{"server":"203.0.113.9","server_port":8388,"password":"p","method":"aes-256-gcm","prefix":""}`,
	}
	for _, j := range ok {
		if _, err := Interpret([]byte(j)); err != nil {
			t.Errorf("%s: %s", j, err.Message)
		}
	}
	bad := []struct{ j, code, class, mention string }{
		{`{"server":"203.0.113.9","server_port":8388,"password":"p","method":"aes-256-gcm","prefix":"€"}`, "ss-prefix-bad", keyparse.ClassKey, "Префикс"},
		{`{"server":"203.0.113.9","server_port":8388,"password":"p","method":"aes-256-gcm","prefix":5}`, "dyn-param", keyparse.ClassUnsupported, "prefix"},
		{`{"server":"203.0.113.9","server_port":8388,"password":"p","method":"aes-256-gcm","prefix":"AAAAAAAAAAAAAAAAA"}`, "ss-prefix-long", keyparse.ClassUnsupported, "слишком длинный"},
		{`{"server":"203.0.113.9","server_port":8388,"password":"p","method":"aes-256-gcm","plugin":"v2ray-plugin"}`, "ss-plugin", keyparse.ClassUnsupported, "v2ray-plugin"},
		{`{"server":"203.0.113.9","server_port":8388,"password":"p","method":"aes-256-gcm","routing":{"x":1}}`, "dyn-param", keyparse.ClassUnsupported, "routing"},
		{`{"server":"203.0.113.9","server_port":8388,"password":"p","method":"rc4-md5"}`, "ss-legacy-cipher", keyparse.ClassUnsupported, "rc4-md5"},
		{`{"server":"203.0.113.9","password":"p","method":"aes-256-gcm"}`, "server", keyparse.ClassKey, ""},
		{`{"server":"203.0.113.9","server_port":8388,"method":"aes-256-gcm"}`, "key", keyparse.ClassKey, "пароля"},
		{`{"server": 5`, "dyn-format", keyparse.ClassUnsupported, "JSON"},
		{`<html>sign in</html>`, "dyn-format", keyparse.ClassUnsupported, "не похож"},
		{`vless://11111111-2222-3333-4444-555555555555@h:443`, "dyn-format", keyparse.ClassUnsupported, ""},
		{``, "fetch-empty", keyparse.ClassFetch, "пустой"},
	}
	for _, c := range bad {
		_, err := Interpret([]byte(c.j))
		if err == nil {
			t.Errorf("%s: must fail", c.j)
			continue
		}
		if err.Code != c.code || err.Class != c.class || !strings.Contains(err.Message, c.mention) {
			t.Errorf("%s: got %s/%s: %s", c.j, err.Code, err.Class, err.Message)
		}
		noLeak(t, c.j, err.Message, "203.0.113.9")
	}
}

const yamlGood = `# Outline transport
transport:
  $type: tcpudp
  tcp:
    $type: shadowsocks
    endpoint: 203.0.113.9:4321
    cipher: chacha20-ietf-poly1305   # comment
    secret: "PASSWORD-SECRET-123"
  udp:
    $type: shadowsocks
    endpoint:
      $type: dial
      address: 203.0.113.9:4321
    cipher: chacha20-ietf-poly1305
    secret: PASSWORD-SECRET-123
`

func TestInterpretYAML(t *testing.T) {
	p, err := Interpret([]byte(yamlGood))
	if err != nil || p.Server != "203.0.113.9" || p.Port != 4321 || p.Password != secretPass || p.Method != "chacha20-ietf-poly1305" {
		t.Fatalf("%+v %v", p, err)
	}
	// only a TCP part is fine too; a bare shadowsocks transport as well
	p, err = Interpret([]byte("transport:\n  $type: shadowsocks\n  endpoint: h.example.org:443\n  cipher: aes-256-gcm\n  secret: x\n"))
	if err != nil || p.Server != "h.example.org" {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = Interpret([]byte("transport: ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:x")) + "@203.0.113.9:443\n"))
	if err != nil || p.Method != "aes-256-gcm" {
		t.Fatalf("link as transport: %+v %v", p, err)
	}
}

func TestInterpretPrefix(t *testing.T) {
	// JSON: the string is read by the JSON decoder (\u0016 -> U+0016), each character is one byte
	bs := string(rune(92)) // a backslash: written out here so that no tool turns "backslash-u" sequences into characters
	p, err := Interpret([]byte(strings.ReplaceAll(`{"server":"203.0.113.9","server_port":8388,"password":"p","method":"chacha20-ietf-poly1305","prefix":"@u0016@u0003@u0001@u0000@u00a8@u0001@u0001"}`, "@", bs)))
	if err != nil || string(p.Prefix) != "\x16\x03\x01\x00\xa8\x01\x01" {
		t.Fatalf("json: %v %v", p, err)
	}
	// YAML, the example of the Outline guide; the udp part has ANOTHER prefix, which is allowed and not used
	y := "transport:\n  $type: tcpudp\n  tcp:\n    $type: shadowsocks\n    endpoint: 203.0.113.9:4321\n    cipher: chacha20-ietf-poly1305\n    secret: s\n" +
		"    prefix: \"\\u0013\\u0003\\u0003\\u003F\"\n" +
		"  udp:\n    $type: shadowsocks\n    endpoint: 203.0.113.9:4321\n    cipher: chacha20-ietf-poly1305\n    secret: s\n    prefix: \"\\u006b\\u007b\\u0001\\u0020\"\n"
	p, err = Interpret([]byte(y))
	if err != nil || string(p.Prefix) != "\x13\x03\x03\x3f" {
		t.Fatalf("yaml: % x %v", p.Prefix, err)
	}
	// a bare shadowsocks transport; escapes are YAML's (\xHH is the CODE POINT, so \xA8 is one byte A8)
	for text, want := range map[string]string{
		`"@xA8@u00ff@x00"`: "\xa8\xff\x00",
		`"A@" # c"`:        "A\" # c",
		`'it''s'`:          "it's",
		`"@t@r@n@0@e@@"`:   "\t\r\n\x00\x1b\\",
		`"@u00A8"`:         "\xa8",
		`"@U000000A8"`:     "\xa8",
		`"A@ B"`:           "A B",
	} {
		text = strings.ReplaceAll(text, "@", bs)
		p, err := Interpret([]byte("transport:\n  $type: shadowsocks\n  endpoint: h.example.org:443\n  cipher: aes-256-gcm\n  secret: x\n  prefix: " + text + "\n"))
		if err != nil {
			t.Errorf("%s: %s", text, err.Message)
		} else if string(p.Prefix) != want {
			t.Errorf("%s: % x", text, p.Prefix)
		}
	}
	// the tcp part wins; no prefix in tcp means none, even when udp has one
	y2 := "transport:\n  $type: tcpudp\n  tcp:\n    $type: shadowsocks\n    endpoint: 203.0.113.9:4321\n    cipher: aes-256-gcm\n    secret: s\n  udp:\n    $type: shadowsocks\n    endpoint: 203.0.113.9:4321\n    cipher: aes-256-gcm\n    secret: s\n    prefix: \"POST \"\n"
	if p, err := Interpret([]byte(y2)); err != nil || len(p.Prefix) != 0 {
		t.Fatalf("tcp without a prefix: % x %v", p.Prefix, err)
	}
	// a link as the answer carries its own prefix
	if p, err := Interpret([]byte("ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:x")) + "@203.0.113.9:443/?prefix=POST%20")); err != nil || string(p.Prefix) != "POST " {
		t.Fatalf("link: %v", err)
	}
}

func TestInterpretYAMLRefusals(t *testing.T) {
	ss := "    $type: shadowsocks\n    endpoint: 203.0.113.9:4321\n    cipher: aes-256-gcm\n    secret: PASSWORD-SECRET-123\n"
	cases := []struct{ name, y, code, mention string }{
		{"prefix above 255", "transport:\n  $type: tcpudp\n  tcp:\n" + ss + "    prefix: \"\\u20AC\"\n", "ss-prefix-bad", "Префикс"},
		{"prefix with a bad escape", "transport:\n  $type: tcpudp\n  tcp:\n" + ss + "    prefix: \"\\q\"\n", "dyn-yaml", "экранирования"},
		{"prefix with a half of a surrogate pair", "transport:\n  $type: tcpudp\n  tcp:\n" + ss + "    prefix: \"\\uD800\"\n", "dyn-yaml", "экранирования"},
		{"prefix too long for the cipher", "transport:\n  $type: tcpudp\n  tcp:\n" + ss + "    prefix: \"AAAAAAAAAAAAAAAAA\"\n", "ss-prefix-long", "слишком длинный"},
		{"websocket transport", "transport:\n  $type: tcpudp\n  tcp:\n    $type: websocket\n    url: wss://x.example.org/s\n", "dyn-transport", "websocket"},
		{"tls wrapper", "transport:\n  $type: tls\n  inner: x\n", "dyn-transport", "tls"},
		{"socks5", "transport:\n  $type: socks5\n  address: 1.2.3.4:1\n", "dyn-transport", "socks5"},
		{"endpoint of another kind", "transport:\n  $type: tcpudp\n  tcp:\n    $type: shadowsocks\n    endpoint:\n      $type: websocket\n      url: x\n    cipher: aes-256-gcm\n    secret: s\n", "dyn-transport", "websocket"},
		{"unknown key in tcp", "transport:\n  $type: tcpudp\n  tcp:\n" + ss + "    padding: 5\n", "dyn-param", "padding"},
		{"unknown key at the top", "version: 2\ntransport:\n  $type: shadowsocks\n  endpoint: h.example.org:1\n  cipher: aes-256-gcm\n  secret: s\n", "dyn-param", "version"},
		{"tcp and udp differ", "transport:\n  $type: tcpudp\n  tcp:\n" + ss + "  udp:\n    $type: shadowsocks\n    endpoint: 203.0.113.10:4321\n    cipher: aes-256-gcm\n    secret: PASSWORD-SECRET-123\n", "dyn-param", "разные"},
		{"no tcp", "transport:\n  $type: tcpudp\n  udp:\n" + ss, "dyn-yaml", "tcp"},
		{"list", "transport:\n  - a\n", "dyn-yaml", "списки"},
		{"flow map", "transport: {$type: shadowsocks}\n", "dyn-yaml", "{…}"},
		{"anchor", "transport: &x\n  $type: shadowsocks\n", "dyn-yaml", "якоря"},
		{"block scalar", "transport:\n  $type: shadowsocks\n  secret: |\n    abc\n", "dyn-yaml", "многострочные"},
		{"tab indent", "transport:\n\t$type: shadowsocks\n", "dyn-yaml", "табуляцией"},
		{"two documents", "transport:\n  $type: shadowsocks\n---\nx: 1\n", "dyn-yaml", "нескольких"},
		{"duplicate key", "transport:\n  $type: shadowsocks\n  $type: tcpudp\n", "dyn-yaml", "повторяющийся"},
		{"no transport", "$type: shadowsocks\n", "dyn-yaml", "transport"},
		{"obsolete cipher", "transport:\n  $type: shadowsocks\n  endpoint: h.example.org:1\n  cipher: rc4-md5\n  secret: s\n", "ss-legacy-cipher", "rc4-md5"},
		{"bad endpoint", "transport:\n  $type: shadowsocks\n  endpoint: no-port\n  cipher: aes-256-gcm\n  secret: s\n", "server", ""},
	}
	for _, c := range cases {
		_, err := Interpret([]byte(c.y))
		if err == nil {
			t.Errorf("%s: must be refused", c.name)
			continue
		}
		if err.Code != c.code || !strings.Contains(err.Message, c.mention) {
			t.Errorf("%s: got %s: %s", c.name, err.Code, err.Message)
		}
		noLeak(t, c.name, err.Message, "203.0.113.9", "x.example.org")
	}
}

func TestOnlyHTTPSIsUsedForTheAddress(t *testing.T) {
	u, err := URL("ssconf://keys.public-test.org:8443/a/b?c=d#Имя с пробелом")
	if err != nil || u.String() != "https://keys.public-test.org:8443/a/b?c=d" {
		t.Fatalf("%v %v", u, err)
	}
	if _, err := URL("ss://x@h:1"); err == nil {
		t.Fatal("only ssconf:// is dynamic")
	}
}
