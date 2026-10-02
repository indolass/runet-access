// Command launcher is Runet Access: a dedicated browser window whose ENTIRE traffic goes
// through the user's key, and nothing else on the machine does.
//
// It starts the pinned sing-box core on a loopback port, then starts Google Chrome with
// its own profile directory and --proxy-server pointing at that port. There is no browser
// extension, no registry change, no system proxy and no TUN. When the proxy is down the
// port is held by a "guard" listener that drops connections, so the window fails closed
// (an error page) instead of silently using the direct connection.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"runetaccess/internal/config"
	"runetaccess/internal/core"
	"runetaccess/internal/keyparse"
)

var version = "0.2.0-dev"

const (
	phaseIdle       = "idle"
	phaseConnecting = "connecting"
	phaseConnected  = "connected"
	phaseError      = "error"
)

type app struct {
	home      string
	mgr       *core.Manager
	store     keyStore
	token     string
	proxyPort int

	mu       sync.Mutex
	phase    string
	errMsg   string
	cfg      []byte // generated core config, kept in memory only, for automatic restarts
	guard    net.Listener
	restarts int
	closing  bool

	probeOverride string // test-only: RUNET_PROBE_URL
	quit          sync.Once
	releaseLock   func()
}

func main() {
	home := os.Getenv("RUNET_ACCESS_HOME")
	if home == "" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			fatal("Не найден каталог LOCALAPPDATA.")
		}
		home = filepath.Join(base, "RunetAccess")
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		fatal("Не удалось создать рабочую папку: " + err.Error())
	}
	release, err := acquireLock(filepath.Join(home, "run.lock"))
	if err != nil {
		fatal("Runet Access уже запущен.")
	}

	chrome := findChrome()
	if chrome == "" {
		release()
		fatal("Не найден Google Chrome. Установите Chrome и запустите Runet Access снова.")
	}

	// Anything the core spawns dies with us, however we die.
	_ = core.ConfineChildren()
	mgr, err := core.NewManager()
	if err != nil {
		release()
		fatal("Не найден компонент подключения (sing-box). Переустановите Runet Access.")
	}

	a := &app{home: home, mgr: mgr, store: keyStore{path: filepath.Join(home, "key.dpapi")},
		phase: phaseIdle, probeOverride: os.Getenv("RUNET_PROBE_URL"), releaseLock: release}
	tok := make([]byte, 16)
	_, _ = rand.Read(tok)
	a.token = hex.EncodeToString(tok)

	port, err := core.FreePort()
	if err != nil {
		a.shutdown()
		fatal("Не удалось выбрать порт.")
	}
	a.proxyPort = port
	if err := a.openGuard(); err != nil {
		a.shutdown()
		fatal("Не удалось занять локальный порт: " + err.Error())
	}
	mgr.OnExit = a.onCoreExit

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		a.shutdown()
		fatal("Не удалось запустить локальный интерфейс.")
	}
	srvPort := ln.Addr().(*net.TCPAddr).Port
	srv := &http.Server{Handler: a.routes(srvPort), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	profile := filepath.Join(home, "profile")
	_ = os.MkdirAll(profile, 0o700)
	args := chromeArgs(profile, port, fmt.Sprintf("http://127.0.0.1:%d/?t=%s", srvPort, a.token))
	cmd := exec.Command(chrome, args...)
	if err := cmd.Start(); err != nil {
		a.shutdown()
		fatal("Не удалось запустить Chrome: " + err.Error())
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done: // last Chrome window closed
	case <-sig:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(ctx)
	cancel()
	a.shutdown()
}

// chromeArgs builds the dedicated-browser command line. Everything except loopback
// (the control page) goes to the local proxy port; local DNS resolution is disabled so
// no hostname lookup can leave through the direct connection.
func chromeArgs(profileDir string, proxyPort int, startURL string) []string {
	args := []string{
		"--user-data-dir=" + profileDir,
		fmt.Sprintf("--proxy-server=socks5://127.0.0.1:%d", proxyPort),
		"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--disable-background-mode", // closing the last window must really end the browser
		"--no-first-run", "--no-default-browser-check",
	}
	if extra := strings.Fields(os.Getenv("RUNET_CHROME_EXTRA_ARGS")); len(extra) > 0 { // test only
		args = append(args, extra...)
	}
	return append(args, startURL)
}

func findChrome() string {
	if p := os.Getenv("RUNET_CHROME_PATH"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
		if base := os.Getenv(env); base != "" {
			p := filepath.Join(base, "Google", "Chrome", "Application", "chrome.exe")
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// openGuard holds the proxy port while the core is not running. Connections are accepted
// and dropped, so the browser gets an error instead of any other process answering.
func (a *app) openGuard() error {
	var ln net.Listener
	var err error
	for i := 0; i < 20; i++ {
		ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", a.proxyPort))
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	a.guard = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return nil
}

func (a *app) closeGuard() {
	if a.guard != nil {
		_ = a.guard.Close()
		a.guard = nil
	}
}

// connect parses the key, starts the core and returns once its port accepts connections.
func (a *app) connect(rawKey string, remember bool) (code, msg string) {
	a.mu.Lock()
	if a.phase == phaseConnecting || a.phase == phaseConnected {
		a.mu.Unlock()
		return "busy", "Уже подключено."
	}
	a.phase, a.errMsg = phaseConnecting, ""
	a.mu.Unlock()

	fail := func(code, msg string) (string, string) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.phase, a.errMsg = phaseError, msg
		if code == "key" {
			a.phase, a.errMsg = phaseIdle, ""
		}
		return code, msg
	}

	typed := strings.TrimSpace(rawKey)
	if typed == "" {
		saved, err := a.store.load()
		if err != nil || saved == "" {
			return fail("key", "Вставьте ключ из Telegram.")
		}
		typed = saved
		remember = false
	}
	cfg, perr := buildConfig(typed, a.proxyPort)
	if perr != nil {
		return fail("key", perr.Message)
	}

	a.mu.Lock()
	a.closeGuard()
	a.mu.Unlock()
	if err := a.mgr.Start(cfg, a.proxyPort); err != nil {
		a.reguard()
		return fail("core", "Компонент подключения не запустился. Перезапустите Runet Access.")
	}
	if err := a.mgr.WaitReady(a.proxyPort, 15*time.Second); err != nil {
		_ = a.mgr.Stop()
		a.reguard()
		return fail("core", "Компонент подключения не запустился. Перезапустите Runet Access.")
	}
	if remember {
		_ = a.store.save(typed)
	}
	a.mu.Lock()
	a.cfg, a.phase, a.errMsg, a.restarts = cfg, phaseConnected, "", 0
	a.mu.Unlock()
	return "", ""
}

func (a *app) reguard() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.guard == nil && !a.closing {
		_ = a.openGuard()
	}
}

// disconnect stops the core and puts the guard back: the window stays fail-closed.
func (a *app) disconnect() {
	a.mu.Lock()
	a.phase, a.errMsg, a.cfg = phaseIdle, "", nil
	a.mu.Unlock()
	_ = a.mgr.Stop()
	a.reguard()
}

// onCoreExit runs only for UNEXPECTED core exits (deliberate stops are silent).
func (a *app) onCoreExit(err error) {
	a.mu.Lock()
	if a.phase != phaseConnected || a.closing {
		a.mu.Unlock()
		return
	}
	cfg := a.cfg
	a.restarts++
	attempt := a.restarts
	a.mu.Unlock()

	if attempt <= 3 && cfg != nil {
		time.Sleep(time.Duration(attempt) * 700 * time.Millisecond)
		if e := a.mgr.Start(cfg, a.proxyPort); e == nil && a.mgr.WaitReady(a.proxyPort, 10*time.Second) == nil {
			return
		}
	}
	a.mu.Lock()
	a.phase, a.errMsg = phaseError, "Соединение прервано. Окно не выходит в интернет напрямую. Нажмите «Подключить» ещё раз."
	a.mu.Unlock()
	_ = a.mgr.Stop()
	a.reguard()
}

func (a *app) shutdown() {
	a.quit.Do(func() {
		a.mu.Lock()
		a.closing = true
		a.closeGuard()
		a.mu.Unlock()
		_ = a.mgr.Stop()
		a.mgr.Cleanup()
		if a.releaseLock != nil {
			a.releaseLock()
		}
	})
}

// buildConfig validates the key and returns the core config for the given local port.
func buildConfig(key string, port int) ([]byte, *keyparse.Error) {
	p, kerr := keyparse.Parse(key)
	if kerr != nil {
		return nil, kerr
	}
	cfg, err := config.Build(p, config.Inbound{Listen: "127.0.0.1", Port: port}, config.Routing{Final: "proxy"}, "warn")
	if err != nil {
		return nil, &keyparse.Error{Code: "config", Message: "Ключ не удалось применить. Проверьте, что он скопирован целиком."}
	}
	return cfg, nil
}
