package ssbridge

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// ssServer is an INDEPENDENT Shadowsocks server (go-shadowsocks2, not the Outline SDK that the bridge uses)
// standing behind a middlebox that lets a connection through only when its first bytes are the expected prefix:
// exactly what an Outline prefix is for. It records the first bytes of every connection it sees.
type ssServer struct {
	ln       net.Listener
	prefix   []byte
	password string

	mu       sync.Mutex
	salts    [][]byte // the first 32 bytes of each connection
	rejected int
	served   int
}

func startSS(t *testing.T, password string, prefix []byte) *ssServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &ssServer{ln: ln, prefix: prefix, password: password}
	ciph, err := core.PickCipher("CHACHA20-IETF-POLY1305", nil, password)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReaderSize(c, 4096)
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				head, err := br.Peek(32)
				if err != nil {
					return
				}
				s.mu.Lock()
				s.salts = append(s.salts, append([]byte(nil), head...))
				ok := bytes.HasPrefix(head, s.prefix)
				if ok {
					s.served++
				} else {
					s.rejected++
				}
				s.mu.Unlock()
				if !ok {
					return // the middlebox drops what does not look like the allowed protocol
				}
				_ = c.SetReadDeadline(time.Time{})
				sc := ciph.StreamConn(&peeked{Conn: c, r: br})
				target, err := socks.ReadAddr(sc)
				if err != nil {
					return
				}
				up, err := net.DialTimeout("tcp", target.String(), 3*time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(up, sc) }()
				_, _ = io.Copy(sc, up)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

type peeked struct {
	net.Conn
	r io.Reader
}

func (p *peeked) Read(b []byte) (int, error) { return p.r.Read(b) }

func (s *ssServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }
func (s *ssServer) counts() (served, rejected int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.served, s.rejected
}

// echoTarget answers every line with "echo:" + line.
func echoTarget(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					_, _ = c.Write([]byte("echo:" + sc.Text() + "\n"))
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// socksDial talks to the bridge as the sing-box core does: SOCKS5 with a username and a password, CONNECT.
func socksDial(t *testing.T, bridgePort int, user, pass, host string, port int) (net.Conn, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(bridgePort), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	_, _ = c.Write([]byte{5, 1, 2})
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m[1] != 2 {
		c.Close()
		return nil, 0xFF
	}
	req := append([]byte{1, byte(len(user))}, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	_, _ = c.Write(req)
	var a [2]byte
	if _, err := io.ReadFull(c, a[:]); err != nil || a[1] != 0 {
		c.Close()
		return nil, 0xFE
	}
	r := []byte{5, 1, 0, 3, byte(len(host))}
	r = append(r, host...)
	r = append(r, byte(port>>8), byte(port))
	_, _ = c.Write(r)
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		c.Close()
		return nil, 0xFD
	}
	return c, rep[1]
}

func roundTrip(c net.Conn, line string) (string, error) {
	_, _ = c.Write([]byte(line + "\n"))
	return bufio.NewReader(c).ReadString('\n')
}

func startBridge(t *testing.T, ss *ssServer, password string, prefix []byte) *Bridge {
	t.Helper()
	b, err := Start(Config{Server: "127.0.0.1", Port: ss.port(), Method: "chacha20-ietf-poly1305", Password: password, Prefix: prefix}, "u-test", "p-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestPrefixReachesTheWireAndTheTrafficFlows(t *testing.T) {
	echo := echoTarget(t)
	eport := echo.Addr().(*net.TCPAddr).Port
	// bytes that matter: a zero, a high byte (0xA8 as in Outline's own example), 0xFF, a TLS-like start
	for _, prefix := range [][]byte{
		[]byte("POST "),
		{0x16, 0x03, 0x01, 0x00, 0xA8, 0x01, 0x01},
		{0x00, 0xFF, 0x80, 0x7F, 0x0D, 0x0A},
		bytes.Repeat([]byte{0xAB}, 16),
	} {
		ss := startSS(t, "pa55", prefix)
		br := startBridge(t, ss, "pa55", prefix)
		c, code := socksDial(t, br.Port(), "u-test", "p-test", "127.0.0.1", eport)
		if c == nil || code != 0 {
			t.Fatalf("prefix % x: SOCKS failed (%d)", prefix, code)
		}
		got, err := roundTrip(c, "hello")
		c.Close()
		if err != nil || got != "echo:hello\n" {
			t.Fatalf("prefix % x: %q %v", prefix, got, err)
		}
		served, rejected := ss.counts()
		if served != 1 || rejected != 0 {
			t.Fatalf("prefix % x: served=%d rejected=%d", prefix, served, rejected)
		}
		// the salt on the wire starts with the prefix and the rest is random: two connections differ after it
		c2, _ := socksDial(t, br.Port(), "u-test", "p-test", "127.0.0.1", eport)
		_, _ = roundTrip(c2, "again")
		c2.Close()
		ss.mu.Lock()
		a, b := ss.salts[0], ss.salts[1]
		ss.mu.Unlock()
		if !bytes.Equal(a[:len(prefix)], prefix) || !bytes.Equal(b[:len(prefix)], prefix) {
			t.Fatalf("prefix % x: the wire starts with % x / % x", prefix, a[:len(prefix)], b[:len(prefix)])
		}
		if bytes.Equal(a[len(prefix):], b[len(prefix):]) {
			t.Fatalf("prefix % x: the rest of the salt is not random", prefix)
		}
	}
}

func TestTheStandNeedsTheRightPrefix(t *testing.T) {
	echo := echoTarget(t)
	eport := echo.Addr().(*net.TCPAddr).Port
	want := []byte("POST ")
	ss := startSS(t, "pa55", want)
	for name, prefix := range map[string][]byte{"no prefix": nil, "a wrong prefix": []byte("GET /"), "a one-byte difference": []byte("POST!"), "only the beginning": []byte("POS")} {
		br := startBridge(t, ss, "pa55", prefix)
		c, code := socksDial(t, br.Port(), "u-test", "p-test", "127.0.0.1", eport)
		if c == nil {
			t.Fatalf("%s: SOCKS failed (%d)", name, code)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		got, err := roundTrip(c, "hello")
		c.Close()
		if err == nil && got == "echo:hello\n" {
			t.Fatalf("%s: the stand let the connection through", name)
		}
	}
	served, rejected := ss.counts()
	if served != 0 || rejected != 4 {
		t.Fatalf("served=%d rejected=%d", served, rejected)
	}
	// and the right one passes on the same stand
	br := startBridge(t, ss, "pa55", want)
	c, _ := socksDial(t, br.Port(), "u-test", "p-test", "127.0.0.1", eport)
	if got, err := roundTrip(c, "ok"); err != nil || got != "echo:ok\n" {
		t.Fatalf("right prefix: %q %v", got, err)
	}
	c.Close()
}

func TestWrongPasswordFailsEvenWithTheRightPrefix(t *testing.T) {
	echo := echoTarget(t)
	prefix := []byte("POST ")
	ss := startSS(t, "pa55", prefix)
	br := startBridge(t, ss, "other-password", prefix)
	c, _ := socksDial(t, br.Port(), "u-test", "p-test", "127.0.0.1", echo.Addr().(*net.TCPAddr).Port)
	if c == nil {
		t.Fatal("SOCKS failed")
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if got, err := roundTrip(c, "x"); err == nil && got == "echo:x\n" {
		t.Fatal("a wrong password was accepted")
	}
	c.Close()
}

func TestBridgeIsNotAnOpenProxy(t *testing.T) {
	echo := echoTarget(t)
	ss := startSS(t, "pa55", []byte("POST "))
	br := startBridge(t, ss, "pa55", []byte("POST "))
	eport := echo.Addr().(*net.TCPAddr).Port
	if c, code := socksDial(t, br.Port(), "u-test", "wrong", "127.0.0.1", eport); c != nil || code != 0xFE {
		t.Fatalf("a wrong password was accepted (%d)", code)
	}
	if c, code := socksDial(t, br.Port(), "wrong", "p-test", "127.0.0.1", eport); c != nil || code != 0xFE {
		t.Fatalf("a wrong user was accepted (%d)", code)
	}
	// a client that offers only "no authentication" is refused
	c, _ := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(br.Port()))
	_, _ = c.Write([]byte{5, 1, 0})
	var m [2]byte
	_, _ = io.ReadFull(c, m[:])
	c.Close()
	if m[1] != 0xFF {
		t.Fatalf("no-auth was offered a method: %v", m)
	}
	if served, rejected := ss.counts(); served+rejected != 0 {
		t.Fatalf("the Shadowsocks server was reached without a login: %d/%d", served, rejected)
	}
	// BIND and UDP ASSOCIATE are not offered
	for _, cmd := range []byte{2, 3} {
		c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(br.Port()))
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write([]byte{5, 1, 2})
		_, _ = io.ReadFull(c, m[:])
		_, _ = c.Write(append(append([]byte{1, 6}, "u-test"...), append([]byte{6}, "p-test"...)...))
		var a [2]byte
		_, _ = io.ReadFull(c, a[:])
		_, _ = c.Write([]byte{5, cmd, 0, 1, 127, 0, 0, 1, 0, 80})
		var rep [10]byte
		_, _ = io.ReadFull(c, rep[:])
		c.Close()
		if rep[1] != 7 {
			t.Fatalf("command %d got reply %d", cmd, rep[1])
		}
	}
}

func TestCloseDropsEverythingAndIsSilent(t *testing.T) {
	echo := echoTarget(t)
	ss := startSS(t, "pa55", []byte("POST "))
	exits := make(chan error, 2)
	b, err := Start(Config{Server: "127.0.0.1", Port: ss.port(), Method: "chacha20-ietf-poly1305", Password: "pa55", Prefix: []byte("POST ")}, "u", "p", func(e error) { exits <- e })
	if err != nil {
		t.Fatal(err)
	}
	c, code := socksDial(t, b.Port(), "u", "p", "127.0.0.1", echo.Addr().(*net.TCPAddr).Port)
	if c == nil || code != 0 {
		t.Fatal("no connection")
	}
	if got, err := roundTrip(c, "hi"); err != nil || got != "echo:hi\n" {
		t.Fatalf("%q %v", got, err)
	}
	port := b.Port()
	done := make(chan struct{})
	go func() { b.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hangs with an open connection")
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the open connection survived Close")
	}
	if cc, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second); err == nil {
		cc.Close()
		t.Fatal("the port is still open after Close")
	}
	select {
	case e := <-exits:
		t.Fatalf("a deliberate Close reported an exit: %v", e)
	case <-time.After(300 * time.Millisecond):
	}
	b.Close() // twice is fine
}

func TestUnexpectedListenerFailureIsReported(t *testing.T) {
	ss := startSS(t, "pa55", nil)
	exits := make(chan error, 1)
	b, err := Start(Config{Server: "127.0.0.1", Port: ss.port(), Method: "chacha20-ietf-poly1305", Password: "pa55"}, "u", "p", func(e error) { exits <- e })
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	_ = b.ln.Close() // the listener dies by itself
	select {
	case e := <-exits:
		if e == nil {
			t.Fatal("nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the failure was not reported")
	}
}

func TestUnreachableServerGivesAFailureReplyWithoutLeakingIt(t *testing.T) {
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	port := dead.Addr().(*net.TCPAddr).Port
	dead.Close()
	b, err := Start(Config{Server: "127.0.0.1", Port: port, Method: "chacha20-ietf-poly1305", Password: "pa55", Prefix: []byte("POST ")}, "u", "p", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	c, code := socksDial(t, b.Port(), "u", "p", "127.0.0.1", 9)
	if c != nil {
		c.Close()
	}
	if code == 0 {
		t.Fatal("success reported for an unreachable server")
	}
	if s := b.String(); bytes.Contains([]byte(s), []byte(strconv.Itoa(port))) {
		t.Fatalf("String() shows the server port: %s", s)
	}
}

func TestPrefixRules(t *testing.T) {
	long17, long9 := bytes.Repeat([]byte("A"), 17), bytes.Repeat([]byte("A"), 9)
	cases := []struct {
		method string
		prefix []byte
		want   string
	}{
		{"chacha20-ietf-poly1305", nil, ""},
		{"chacha20-ietf-poly1305", bytes.Repeat([]byte("A"), 16), ""},
		{"chacha20-ietf-poly1305", long17, "long"},
		{"aes-256-gcm", bytes.Repeat([]byte("A"), 16), ""},
		{"aes-192-gcm", bytes.Repeat([]byte("A"), 16), ""},
		{"aes-192-gcm", bytes.Repeat([]byte("A"), 17), "long"},
		{"aes-128-gcm", bytes.Repeat([]byte("A"), 8), ""},
		{"aes-128-gcm", long9, "long"},
		{"xchacha20-ietf-poly1305", []byte("A"), "cipher"},
		{"2022-blake3-aes-128-gcm", []byte("A"), "cipher"},
		{"rc4-md5", []byte("A"), "cipher"},
	}
	for _, c := range cases {
		if got := CheckPrefix(c.method, c.prefix); got != c.want {
			t.Errorf("%s/%d bytes: %q, want %q", c.method, len(c.prefix), got, c.want)
		}
	}
	if _, err := Start(Config{Server: "127.0.0.1", Port: 1, Method: "chacha20-ietf-poly1305", Password: "x", Prefix: long17}, "u", "p", nil); err == nil {
		t.Error("Start accepted a too long prefix")
	}
	if _, err := Start(Config{Server: "127.0.0.1", Port: 1, Method: "chacha20-ietf-poly1305", Password: "x"}, "", "", nil); !errors.Is(err, err) || err == nil {
		t.Error("Start accepted an empty login")
	}
}
