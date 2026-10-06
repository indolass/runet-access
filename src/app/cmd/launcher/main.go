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
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"runetaccess/internal/config"
	"runetaccess/internal/core"
	"runetaccess/internal/keyparse"
)

var version = "0.3.0-dev"

const (
	phaseIdle       = "idle"
	phaseConnecting = "connecting"
	phaseConnected  = "connected"
	phaseError      = "error"
)

type app struct {
	home      string
	profile   string // the special browser's own profile directory
	chrome    string
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

	gen        int    // bumped by every disconnect: an operation started earlier notices and stops
	epoch      int    // bumped each time the core becomes ready: a verdict about an older one is void
	confirmed  bool   // the exit country was verified for the current epoch (reported by the page)
	restarting bool   // the core died and is being restarted: nothing can be verified right now
	serverAddr string // host:port of the key's server, used only for the reachability test
	curKey     string // key of the running attempt (memory only)
	pendingKey string // a typed key waits for its verification: it is saved only after that
	pendingRem bool
	goodKey    string // last key that passed verification in this run (memory only)

	browserDone  <-chan struct{} // closed when the special browser has exited
	openExternal func(url string) error

	probeOverride string // test-only: RUNET_PROBE_URL
	recheckMs     int    // test-only: RUNET_RECHECK_MS
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

	holdAppMutex() // lets the installer see that the program is running
	opener := openerFromEnv()
	chrome := waitForChrome(opener)
	if chrome == "" { // the user closed the "Chrome is needed" window: a normal way out
		release()
		os.Exit(0)
	}

	// Anything the core spawns dies with us, however we die.
	_ = core.ConfineChildren()
	mgr, err := core.NewManager()
	if err != nil {
		release()
		fatal("Не найден компонент подключения (sing-box). Переустановите Runet Access.")
	}

	a := &app{home: home, chrome: chrome, profile: filepath.Join(home, "profile"), mgr: mgr,
		store: keyStore{path: filepath.Join(home, "key.dpapi")}, phase: phaseIdle,
		probeOverride: os.Getenv("RUNET_PROBE_URL"), releaseLock: release, openExternal: opener}
	if v, err := strconv.Atoi(os.Getenv("RUNET_RECHECK_MS")); err == nil && v >= 500 { // test only
		a.recheckMs = v
	}
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

	_ = os.MkdirAll(a.profile, 0o700)
	args := append(chromeArgs(a.profile, port), fmt.Sprintf("http://127.0.0.1:%d/?t=%s", srvPort, a.token))
	cmd := exec.Command(chrome, args...)
	if err := cmd.Start(); err != nil {
		a.shutdown()
		fatal("Не удалось запустить Chrome: " + err.Error())
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	a.browserDone = done
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

// chromeArgs builds the dedicated-browser command line (without a start address). Everything
// except loopback (the control page) goes to the local proxy port; local DNS resolution is
// disabled so no hostname lookup can leave through the direct connection.
func chromeArgs(profileDir string, proxyPort int) []string {
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
	return args
}

// chromeInstallURL is Google's own page for getting Chrome. We open it only on the user's click.
const chromeInstallURL = "https://www.google.com/chrome/"

// openerFromEnv returns the function that hands an address to Windows. Test only: with
// RUNET_OPEN_LOG set, addresses are appended to that file instead of being opened.
func openerFromEnv() func(string) error {
	lf := os.Getenv("RUNET_OPEN_LOG")
	if lf == "" {
		return shellOpen
	}
	return func(u string) error {
		f, err := os.OpenFile(lf, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = fmt.Fprintln(f, u)
		return err
	}
}

// waitForChrome returns the path of an installed Chrome. When there is none it shows a small
// window (see chrome_prompt_windows.go) and keeps asking until Chrome appears or the user
// closes the window, in which case it returns "".
func waitForChrome(open func(string) error) string {
	for {
		if p := findChrome(); p != "" {
			return p
		}
		switch showChromeMissing() {
		case dlgOpen:
			_ = open(chromeInstallURL)
		case dlgRecheck:
		default:
			return ""
		}
	}
}

// findChrome looks for an installed Google Chrome: the standard per-machine and per-user
// folders first, then the path Chrome registers for itself.
func findChrome() string {
	if p := os.Getenv("RUNET_CHROME_PATH"); p != "" { // test only
		if isFile(p) {
			return p
		}
		return ""
	}
	var cands []string
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
		if base := os.Getenv(env); base != "" {
			cands = append(cands, filepath.Join(base, "Google", "Chrome", "Application", "chrome.exe"))
		}
	}
	cands = append(cands, chromeFromRegistry()...)
	return firstChrome(cands)
}

// firstChrome returns the first candidate that is a real file named chrome.exe.
func firstChrome(cands []string) string {
	for _, p := range cands {
		p = strings.Trim(p, `"`)
		if strings.EqualFold(filepath.Base(p), "chrome.exe") && isFile(p) {
			return p
		}
	}
	return ""
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
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

// connect validates the key, starts the core and returns once its port accepts connections.
// A key that merely looks wrong is refused before anything changes. Otherwise the previous
// connection (if any) is stopped first, so an old connection can never pass for the new key.
// A typed key is saved only later, by verdict(), after its exit has been verified.
func (a *app) connect(rawKey string, remember bool) (epoch int, code, msg string) {
	typed := strings.TrimSpace(rawKey)
	key := typed
	if key == "" {
		if saved, err := a.store.load(); err == nil {
			key = saved
		}
		if key == "" {
			a.mu.Lock()
			key = a.goodKey
			a.mu.Unlock()
		}
		if key == "" {
			return 0, "key", "Вставьте ключ подключения."
		}
	}
	cfg, addr, perr := buildConfig(key, a.proxyPort)
	if perr != nil {
		return 0, "key", perr.Message
	}

	a.mu.Lock()
	if a.phase == phaseConnecting {
		a.mu.Unlock()
		return 0, "busy", "Подключение уже выполняется."
	}
	wasUp := a.phase == phaseConnected
	a.gen++
	gen := a.gen
	a.phase, a.errMsg, a.confirmed, a.cfg = phaseConnecting, "", false, nil
	a.serverAddr, a.curKey = addr, key
	a.pendingKey, a.pendingRem = "", false
	if typed != "" {
		a.pendingKey, a.pendingRem = typed, remember
	}
	a.mu.Unlock()
	if wasUp {
		_ = a.mgr.Stop()
		a.reguard()
	}

	stale := func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.gen != gen || a.closing
	}
	fail := func(code, msg string) (int, string, string) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.gen == gen {
			a.phase, a.errMsg, a.pendingKey = phaseError, msg, ""
		}
		return 0, code, msg
	}

	// Cheap and honest: when the server's port does not even answer, the core cannot work either.
	c, err := net.DialTimeout("tcp", addr, 6*time.Second)
	if err != nil {
		if stale() {
			return 0, "cancelled", ""
		}
		return fail("server", "Сервер недоступен. Проверьте интернет и повторите попытку.")
	}
	_ = c.Close()
	if stale() {
		return 0, "cancelled", ""
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
		if stale() {
			return 0, "cancelled", ""
		}
		return fail("core", "Компонент подключения не запустился. Перезапустите Runet Access.")
	}
	a.mu.Lock()
	if a.gen != gen || a.closing {
		a.mu.Unlock()
		_ = a.mgr.Stop()
		a.reguard()
		return 0, "cancelled", ""
	}
	a.cfg, a.phase, a.errMsg, a.restarts = cfg, phaseConnected, "", 0
	a.epoch++
	epoch = a.epoch
	a.mu.Unlock()
	return epoch, "", ""
}

// verdict is the page's report on the exit check for a given epoch. A report about an older
// epoch (the core was restarted since) or a closed connection is ignored. Only a positive
// verdict lets a typed key be saved and makes sites openable.
func (a *app) verdict(ok bool, epoch int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.phase != phaseConnected || epoch != a.epoch {
		return
	}
	if !ok {
		a.confirmed = false
		return
	}
	a.confirmed = true
	a.goodKey = a.curKey
	if a.pendingKey != "" {
		if a.pendingRem {
			_ = a.store.save(a.pendingKey)
		}
		a.pendingKey = ""
	}
}

// reachable reports whether the key's server accepts a TCP connection (diagnostics only).
func (a *app) reachable() bool {
	a.mu.Lock()
	addr := a.serverAddr
	a.mu.Unlock()
	if addr == "" {
		return false
	}
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (a *app) reguard() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.guard == nil && !a.closing {
		_ = a.openGuard()
	}
}

// disconnect stops the core and puts the guard back: the window stays fail-closed.
// It also cancels any connection attempt in progress.
func (a *app) disconnect() {
	a.mu.Lock()
	a.gen++
	a.phase, a.errMsg, a.cfg, a.confirmed, a.pendingKey, a.restarting = phaseIdle, "", nil, false, "", false
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
	cfg, gen := a.cfg, a.gen
	// What was confirmed belonged to the process that has just died. A new epoch also voids any
	// verdict still on its way from a check that began before the death.
	a.confirmed = false
	a.restarting = true
	a.epoch++
	a.restarts++
	attempt := a.restarts
	a.mu.Unlock()
	a.reguard() // no gap in which the port is free for somebody else

	if attempt <= 3 && cfg != nil {
		time.Sleep(time.Duration(attempt) * 700 * time.Millisecond)
		a.mu.Lock()
		stale := a.gen != gen || a.closing
		if !stale {
			a.closeGuard()
		}
		a.mu.Unlock()
		if stale {
			return
		}
		if e := a.mgr.Start(cfg, a.proxyPort); e == nil && a.mgr.WaitReady(a.proxyPort, 10*time.Second) == nil {
			a.mu.Lock()
			if a.gen == gen && !a.closing {
				a.restarting = false
				a.epoch++ // the page verifies the exit of the NEW core
				a.mu.Unlock()
				return
			}
			a.mu.Unlock()
			_ = a.mgr.Stop()
			a.reguard()
			return
		}
		_ = a.mgr.Stop()
	}
	a.mu.Lock()
	if a.gen == gen {
		a.phase, a.errMsg, a.restarting = phaseError, "Соединение прервано. Окно не выходит в интернет напрямую.", false
	}
	a.mu.Unlock()
	a.reguard()
}

// openSite opens a page in a NEW TAB of the special browser by handing the address to the
// browser that already runs on our profile. The window.open() route is not usable here: the
// connection and the exit check take longer than the few seconds a click stays "fresh", and
// Chrome then blocks the tab as a pop-up. The proxy flags travel along, so even if the browser
// had just died the new one would still be fail-closed. Only after a verified exit.
func (a *app) openSite(raw string) (code, msg string) {
	a.mu.Lock()
	ok := a.phase == phaseConnected && a.confirmed && !a.closing
	a.mu.Unlock()
	if !ok {
		return "not-confirmed", "Подключение через Россию ещё не подтверждено."
	}
	u, bad := validSiteURL(raw)
	if bad != "" {
		return "url", bad
	}
	select {
	case <-a.browserDone:
		return "gone", "Окно браузера уже закрыто."
	default:
	}
	cmd := exec.Command(a.chrome, append(chromeArgs(a.profile, a.proxyPort), u)...)
	if err := cmd.Start(); err != nil {
		return "launch", "Не удалось открыть вкладку."
	}
	go func() { _ = cmd.Wait() }() // the hand-over process exits at once
	return "", ""
}

// validSiteURL accepts only a plain http(s) address of an outside host.
func validSiteURL(raw string) (string, string) {
	const msg = "Введите адрес сайта, например nalog.gov.ru."
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 2048 {
		return "", msg
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Opaque != "" {
		return "", msg
	}
	h := strings.ToLower(u.Hostname())
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".localhost") || !strings.Contains(h, ".") {
		return "", msg
	}
	if ip := net.ParseIP(h); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return "", msg
	}
	return u.String(), ""
}

// externalLinks is the whole list of addresses the page may ask us to open outside the special
// browser (the window cannot reach them before it is connected). The page sends an id, never an
// address, so this is not a way to open anything else.
var externalLinks = map[string]string{
	"bot-ussr":  "https://t.me/BackInTheUSSR_bot",
	"bot-hlvpn": "https://t.me/hlvpnbot",
	"thanks":    "https://t.me/W3_accelerators_GK",
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

// buildConfig validates the key and returns the core config for the given local port and the
// server's host:port (for the reachability test only; it is never shown or logged).
func buildConfig(key string, port int) ([]byte, string, *keyparse.Error) {
	p, kerr := keyparse.Parse(key)
	if kerr != nil {
		return nil, "", kerr
	}
	cfg, err := config.Build(p, config.Inbound{Listen: "127.0.0.1", Port: port}, config.Routing{Final: "proxy"}, "warn")
	if err != nil {
		return nil, "", &keyparse.Error{Code: "config", Message: "Ключ не удалось применить. Проверьте, что он скопирован целиком."}
	}
	return cfg, net.JoinHostPort(p.Server, strconv.Itoa(p.Port)), nil
}
