// Package ssbridge is a small local SOCKS5 server whose upstream is a Shadowsocks server reached with the
// Outline SDK (golang.getoutline.org/sdk, Apache-2.0). It exists for ONE reason: the Outline "prefix" (the
// first bytes of the Shadowsocks salt) cannot be set in the pinned sing-box core, while the SDK's
// shadowsocks.StreamDialer has it built in (SaltGenerator). Keys without a prefix never come here.
//
// The bridge lives inside the launcher process (no extra process to start, watch or leave behind) and is
// closed with the connection. It is only ever reached by the pinned core: it listens on loopback and demands
// a username and password that are random for each run and known only to the generated core config, so no
// other program on the machine can use the key's tunnel through it.
//
// What it does: SOCKS5 CONNECT only (no BIND, no UDP ASSOCIATE; the prefix is a TCP-only feature in the
// Outline key format). It does no cryptography of its own: all of it is the SDK's.
package ssbridge

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
)

// MaxPrefix is the longest prefix accepted (Outline: "should be no longer than 16 bytes"; a longer one steals
// entropy from the salt and risks salt reuse, which breaks the encryption).
const MaxPrefix = 16

// minRandomSalt is the number of salt bytes that must stay random after the prefix.
const minRandomSalt = 8

// CipherInfo reports whether the SDK can use the cipher (the names are the usual Shadowsocks ones) and the
// size of its salt. AEAD-2022 and xchacha20 are not in the SDK.
func CipherInfo(method string) (saltSize int, ok bool) {
	k, err := shadowsocks.NewEncryptionKey(method, "x")
	if err != nil {
		return 0, false
	}
	return k.SaltSize(), true
}

// CheckPrefix says whether the prefix is acceptable for the cipher; the returned text (empty = fine) names the
// reason without any secret.
func CheckPrefix(method string, prefix []byte) string {
	salt, ok := CipherInfo(method)
	if !ok {
		return "cipher"
	}
	if len(prefix) > MaxPrefix || len(prefix) > salt-minRandomSalt {
		return "long"
	}
	return ""
}

// Config is the upstream Shadowsocks server.
type Config struct {
	Server   string
	Port     int
	Method   string
	Password string
	Prefix   []byte
}

// Bridge is a running local SOCKS5 -> Shadowsocks bridge.
type Bridge struct {
	ln     net.Listener
	dialer *shadowsocks.StreamDialer
	user   string
	pass   string

	ctx    context.Context
	stop   context.CancelFunc
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// Start listens on 127.0.0.1 (a free port) and serves until Close. onExit is called, once, only when the
// listener fails for a reason other than Close.
func Start(cfg Config, user, pass string, onExit func(error)) (*Bridge, error) {
	if user == "" || pass == "" {
		return nil, errors.New("ssbridge: credentials are required")
	}
	if r := CheckPrefix(cfg.Method, cfg.Prefix); r != "" {
		return nil, errors.New("ssbridge: unsuitable prefix or cipher (" + r + ")")
	}
	key, err := shadowsocks.NewEncryptionKey(cfg.Method, cfg.Password)
	if err != nil {
		return nil, errors.New("ssbridge: unsupported cipher")
	}
	ep := &transport.TCPEndpoint{Address: net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port))}
	d, err := shadowsocks.NewStreamDialer(ep, key)
	if err != nil {
		return nil, errors.New("ssbridge: cannot create the dialer")
	}
	if len(cfg.Prefix) > 0 {
		d.SaltGenerator = shadowsocks.NewPrefixSaltGenerator(append([]byte(nil), cfg.Prefix...))
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, stop := context.WithCancel(context.Background())
	b := &Bridge{ln: ln, dialer: d, user: user, pass: pass, ctx: ctx, stop: stop, conns: map[net.Conn]struct{}{}}
	go b.serve(onExit)
	return b, nil
}

// Port is the loopback port the bridge listens on.
func (b *Bridge) Port() int { return b.ln.Addr().(*net.TCPAddr).Port }

// Close stops the listener, drops every connection and waits for the handlers to finish.
func (b *Bridge) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	b.stop()
	_ = b.ln.Close()
	for c := range b.conns {
		_ = c.Close()
	}
	b.mu.Unlock()
	b.wg.Wait()
}

func (b *Bridge) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

func (b *Bridge) track(c net.Conn) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.conns[c] = struct{}{}
	b.wg.Add(1)
	return true
}

func (b *Bridge) untrack(c net.Conn) {
	b.mu.Lock()
	delete(b.conns, c)
	b.mu.Unlock()
	b.wg.Done()
}

func (b *Bridge) serve(onExit func(error)) {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			if !b.isClosed() && onExit != nil {
				onExit(err)
			}
			return
		}
		if !b.track(c) {
			_ = c.Close()
			return
		}
		go func() {
			defer b.untrack(c)
			defer c.Close()
			b.handle(c)
		}()
	}
}

const (
	socksVer   = 5
	authVer    = 1
	cmdCONNECT = 1
)

func (b *Bridge) handle(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != socksVer {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	hasAuth := false
	for _, m := range methods {
		if m == 2 {
			hasAuth = true
		}
	}
	if !hasAuth {
		_, _ = c.Write([]byte{socksVer, 0xFF})
		return
	}
	if _, err := c.Write([]byte{socksVer, 2}); err != nil {
		return
	}
	// RFC 1929 username/password
	var ah [2]byte
	if _, err := io.ReadFull(c, ah[:1]); err != nil || ah[0] != authVer {
		return
	}
	user, err := readLV(c)
	if err != nil {
		return
	}
	pass, err := readLV(c)
	if err != nil {
		return
	}
	okU := subtle.ConstantTimeCompare(user, []byte(b.user))
	okP := subtle.ConstantTimeCompare(pass, []byte(b.pass))
	if okU&okP != 1 {
		_, _ = c.Write([]byte{authVer, 1})
		return
	}
	if _, err := c.Write([]byte{authVer, 0}); err != nil {
		return
	}

	var rh [4]byte
	if _, err := io.ReadFull(c, rh[:]); err != nil || rh[0] != socksVer {
		return
	}
	if rh[1] != cmdCONNECT {
		reply(c, 7) // command not supported
		return
	}
	var host string
	switch rh[3] {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return
		}
		host = net.IP(a[:]).String()
	case 4:
		var a [16]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return
		}
		host = net.IP(a[:]).String()
	case 3:
		n, err := readLV(c)
		if err != nil || len(n) == 0 {
			return
		}
		host = string(n)
	default:
		reply(c, 8) // address type not supported
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(pb[0])<<8|int(pb[1])))

	ctx, cancel := context.WithTimeout(b.ctx, 15*time.Second)
	up, err := b.dialer.DialStream(ctx, target)
	cancel()
	if err != nil {
		reply(c, 1) // general failure; the text of the error may carry the server address, so it is dropped
		return
	}
	defer up.Close()
	if !b.trackUp(up) {
		return
	}
	defer b.untrack(up)
	if err := reply(c, 0); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	relay(c, up)
}

// trackUp registers the upstream connection so that Close also drops it.
func (b *Bridge) trackUp(c net.Conn) bool { return b.track(c) }

// halfClosedGrace is how long the other direction may go on after one side has finished: a connection whose peer
// vanished without closing must not live (and hold a goroutine) forever.
const halfClosedGrace = 2 * time.Minute

func relay(c net.Conn, up transport.StreamConn) {
	done := make(chan struct{}, 2)
	grace := func() {
		d := time.Now().Add(halfClosedGrace)
		_ = c.SetDeadline(d)
		_ = up.SetDeadline(d)
	}
	go func() {
		_, _ = io.Copy(up, c)
		_ = up.CloseWrite()
		grace()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, up)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		grace()
		done <- struct{}{}
	}()
	<-done
	<-done
}

func readLV(r io.Reader) ([]byte, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	b := make([]byte, n[0])
	_, err := io.ReadFull(r, b)
	return b, err
}

func reply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{socksVer, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

// String never shows the server or the secret.
func (b *Bridge) String() string { return fmt.Sprintf("ssbridge(127.0.0.1:%d)", b.Port()) }
