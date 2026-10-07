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
	"crypto/x509"
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
	"runetaccess/internal/dynkey"
	"runetaccess/internal/keyparse"
	"runetaccess/internal/ssbridge"
)

var version = "0.3.0-dev"

// portableHold keeps the unpacked core of the portable build open (no write/delete sharing) for the whole run.
var portableHold *os.File

// maxKeyChars is the longest text accepted as a key. Real keys (vless://, ss://, ssconf://) are well
// under 2 000 characters; the limit only separates "a key" from "a pasted message" for a plain error.
const maxKeyChars = 8192

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
	cfg      []byte           // generated core config, kept in memory only, for automatic restarts
	bridge   *ssbridge.Bridge // only for keys with an Outline prefix: the core's single upstream
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
	if portableCommand(home, os.Args, openerFromEnv()) { // "--licenses" of the portable build; needs no lock
		return
	}
	release, err := acquireLock(filepath.Join(home, "run.lock"))
	if err != nil {
		fatal("Runet Access уже запущен.")
	}

	savedChromeFile = filepath.Join(home, "chrome-path.txt")
	holdAppMutex() // lets the installer see that the program is running
	opener := openerFromEnv()
	chrome := waitForChrome(opener)
	if chrome == "" { // the user closed the "Chrome is needed" window: a normal way out
		release()
		os.Exit(0)
	}

	// Anything the core spawns dies with us, however we die.
	_ = core.ConfineChildren()
	var mgr *core.Manager
	if portableBuild {
		// One-file build: unpack/verify the core into the program's data folder and keep it locked against changes
		// until the program ends (portableHold is never closed on purpose; Windows releases it with the process).
		hold, corePath, perr := preparePortable(home)
		if perr != nil {
			release()
			fatal("Не удалось подготовить компоненты программы: " + perr.Error())
		}
		portableHold = hold
		mgr, err = core.NewManagerAt(corePath)
	} else {
		mgr, err = core.NewManager()
	}
	if err != nil {
		release()
		fatal("Не найден компонент подключения (sing-box). Переустановите Runet Access.")
	}

	a := &app{home: home, chrome: chrome, profile: filepath.Join(home, "profile"), mgr: mgr,
		store: keyStore{path: filepath.Join(home, "key.dpapi")}, phase: phaseIdle,
		probeOverride: testEnv("RUNET_PROBE_URL"), releaseLock: release, openExternal: opener}
	if v, err := strconv.Atoi(testEnv("RUNET_RECHECK_MS")); err == nil && v >= 500 { // test only
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
	if extra := strings.Fields(testEnv("RUNET_CHROME_EXTRA_ARGS")); len(extra) > 0 { // test only
		args = append(args, extra...)
	}
	return args
}

// testMode is true only when RUNET_TEST_MODE=1. Every test override below is honoured ONLY then, so a
// stray variable left in somebody's environment (RUNET_CHROME_PATH pointing nowhere, a fake country, ...)
// can never change how the real program behaves.
func testMode() bool { return os.Getenv("RUNET_TEST_MODE") == "1" }

func testEnv(name string) string {
	if !testMode() {
		return ""
	}
	return os.Getenv(name)
}

// openerFromEnv returns the function that hands an address to Windows. Test only: with
// RUNET_OPEN_LOG set, addresses are appended to that file instead of being opened.
func openerFromEnv() func(string) error {
	lf := testEnv("RUNET_OPEN_LOG")
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
// closes the window, in which case it returns "". The window can download and start Google's
// own installer (chrome_install.go) or let the user point at an existing chrome.exe; the result
// of the last attempt is shown on top.
func waitForChrome(open func(string) error) string {
	note, details := "", ""
	for {
		if p := findChrome(); p != "" {
			return p
		}
		switch showChromeMissing(note, details) {
		case dlgInstall:
			note, details = installChromeInteractive()
		case dlgPick:
			note, details = pickExistingChrome()
		case dlgOpen:
			note, details = "", ""
			_ = open(chromeManualURL)
		case dlgRecheck:
			note, details = "", ""
		default:
			return ""
		}
	}
}

// findChrome looks for an installed Google Chrome: the standard per-machine and per-user
// folders first, then the path Chrome registers for itself.
func findChrome() string {
	if p := testEnv("RUNET_CHROME_PATH"); p != "" { // test only
		if isFile(p) {
			return p
		}
		return ""
	}
	var cands []string
	if testEnv("RUNET_TEST_NO_AUTODETECT") == "1" { // test only: pretend the automatic search found nothing
		return savedChrome()
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
		if base := os.Getenv(env); base != "" {
			cands = append(cands, filepath.Join(base, "Google", "Chrome", "Application", "chrome.exe"))
		}
	}
	cands = append(cands, chromeFromRegistry()...)
	if p := firstChrome(cands); p != "" {
		return p
	}
	return savedChrome()
}

// savedChromeFile is where a chrome.exe chosen by the user ("Указать chrome.exe") is remembered:
// one line in the program's own data folder (set in main).
var savedChromeFile string

// chromeFileOK checks that a remembered file is still a genuine Chrome (Windows build: Google's signature).
var chromeFileOK = func(path string) error { return nil }

func savedChrome() string {
	if savedChromeFile == "" {
		return ""
	}
	b, err := os.ReadFile(savedChromeFile)
	if err != nil {
		return ""
	}
	p := strings.TrimSpace(string(b))
	if !strings.EqualFold(filepath.Base(p), "chrome.exe") || !isFile(p) || chromeFileOK(p) != nil {
		return ""
	}
	return p
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
	// Keys are a few hundred characters; many thousands means the whole message (or more) was pasted.
	// Said plainly, before any parsing: the text stays in the field so the user can cut it down.
	if len(typed) > maxKeyChars {
		return 0, keyparse.ClassFormat, "Текст слишком длинный для ключа. Скопируйте из сообщения бота только сам ключ (ссылку или строку)."
	}
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
			return 0, keyparse.ClassKey, "Вставьте ключ подключения из бота."
		}
	}
	// Everything that can be refused is refused BEFORE anything changes: a wrong key, a dynamic key whose
	// settings cannot be loaded or contain something unsupported leave the previous connection and the saved
	// key exactly as they were.
	a.mu.Lock()
	startGen := a.gen
	a.mu.Unlock()
	fctx, fcancel := context.WithTimeout(context.Background(), 25*time.Second)
	pl, perr := buildPlan(fctx, key, a.proxyPort)
	fcancel()
	if perr != nil {
		return 0, perr.Class, perr.Message // "format", "key", "unsupported" or "fetch"
	}
	cfg, addr := pl.cfg, pl.addr
	a.mu.Lock()
	cancelledMeanwhile := a.gen != startGen || a.closing
	a.mu.Unlock()
	if cancelledMeanwhile { // the user pressed Cancel/Disconnect while the settings were being loaded
		return 0, "cancelled", ""
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
		a.stopCore()
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

	// A key with an Outline prefix is carried by the local bridge; the core's only upstream is that bridge.
	var br *ssbridge.Bridge
	if pl.p.Prefix != nil {
		var berr error
		br, cfg, berr = a.startBridge(pl.p)
		if berr != nil {
			return fail("core", "Компонент подключения не запустился. Перезапустите Runet Access.")
		}
	}
	a.mu.Lock()
	a.closeGuard()
	a.mu.Unlock()
	if err := a.mgr.Start(cfg, a.proxyPort); err != nil {
		a.stopCore()
		a.reguard()
		return fail("core", "Компонент подключения не запустился. Перезапустите Runet Access.")
	}
	if err := a.mgr.WaitReady(a.proxyPort, 15*time.Second); err != nil {
		a.stopCore()
		a.reguard()
		if stale() {
			return 0, "cancelled", ""
		}
		return fail("core", "Компонент подключения не запустился. Перезапустите Runet Access.")
	}
	a.mu.Lock()
	if a.gen != gen || a.closing {
		a.mu.Unlock()
		a.stopCore()
		a.reguard()
		return 0, "cancelled", ""
	}
	if br != nil && a.bridge != br { // the bridge died while the core was starting
		a.mu.Unlock()
		a.stopCore()
		a.reguard()
		return fail("core", "Компонент подключения не запустился. Перезапустите Runet Access.")
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
	a.stopCore()
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
			a.stopCore()
			a.reguard()
			return
		}
		a.stopCore()
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
		a.stopCore()
		a.mgr.Cleanup()
		if a.releaseLock != nil {
			a.releaseLock()
		}
	})
}

// dynOptions are the production settings of the dynamic-key fetch. In test mode (and only there) a local
// HTTPS stand-in can be trusted and loopback allowed.
func dynOptions() dynkey.Options {
	var o dynkey.Options
	if testMode() {
		o.AllowLoopback = testEnv("RUNET_TEST_SSCONF_LOOPBACK") == "1"
		if f := testEnv("RUNET_TEST_SSCONF_CA"); f != "" {
			if pem, err := os.ReadFile(f); err == nil {
				o.RootCAs = x509.NewCertPool()
				o.RootCAs.AppendCertsFromPEM(pem)
			}
		}
	}
	return o
}

// resolveProfile turns the key text into a profile: static keys are parsed, dynamic (ssconf://) keys are
// fetched first, over HTTPS, before any tunnel exists.
func resolveProfile(ctx context.Context, key string) (*config.Profile, *keyparse.Error) {
	if keyparse.IsDynamic(key) {
		return dynkey.Resolve(ctx, key, dynOptions())
	}
	return keyparse.Parse(key)
}

// plan is a validated key: its profile, the server's host:port (for the reachability test only; it is never
// shown or logged) and the core config. cfg is nil for a key with an Outline prefix: that config can only be
// written once the local bridge exists (see startBridge).
type plan struct {
	p    *config.Profile
	addr string
	cfg  []byte
}

// buildPlan validates the key and returns the plan for the given local port.
func buildPlan(ctx context.Context, key string, port int) (*plan, *keyparse.Error) {
	p, kerr := resolveProfile(ctx, key)
	if kerr != nil {
		return nil, kerr
	}
	pl := &plan{p: p, addr: net.JoinHostPort(p.Server, strconv.Itoa(p.Port))}
	if len(p.Prefix) > 0 {
		p.Prefix = append([]byte(nil), p.Prefix...)
		return pl, nil
	}
	p.Prefix = nil
	cfg, err := config.Build(p, config.Inbound{Listen: "127.0.0.1", Port: port}, config.Routing{Final: "proxy"}, "warn")
	if err != nil {
		return nil, keyparse.Fail("config", "Ключ не удалось применить. Проверьте, что он скопирован целиком.")
	}
	pl.cfg = cfg
	return pl, nil
}

// bridgeProfile is what the core sees for a prefix key: one authenticated SOCKS5 upstream on loopback.
func bridgeProfile(port int, user, pass string) *config.Profile {
	return &config.Profile{ID: "runet-access-bridge", Name: keyparse.ProfileName, Type: "socks", SocksVersion: "5",
		Server: "127.0.0.1", Port: port, Username: user, Password: pass}
}

// startBridge starts the local Shadowsocks bridge for a prefix key and returns it together with the core
// config that uses it. The bridge's login is random for this run and exists only in that config (memory).
func (a *app) startBridge(p *config.Profile) (*ssbridge.Bridge, []byte, error) {
	a.closeBridge()
	rnd := make([]byte, 24)
	if _, err := rand.Read(rnd); err != nil {
		return nil, nil, err
	}
	user, pass := hex.EncodeToString(rnd[:12]), hex.EncodeToString(rnd[12:])
	var br *ssbridge.Bridge
	br, err := ssbridge.Start(ssbridge.Config{Server: p.Server, Port: p.Port, Method: p.Method, Password: p.Password, Prefix: p.Prefix},
		user, pass, func(error) { a.onBridgeExit(br) })
	if err != nil {
		return nil, nil, err
	}
	cfg, err := config.Build(bridgeProfile(br.Port(), user, pass), config.Inbound{Listen: "127.0.0.1", Port: a.proxyPort}, config.Routing{Final: "proxy"}, "warn")
	if err != nil {
		br.Close()
		return nil, nil, err
	}
	a.mu.Lock()
	a.bridge = br
	a.mu.Unlock()
	return br, cfg, nil
}

// closeBridge stops the bridge, if one runs.
func (a *app) closeBridge() {
	a.mu.Lock()
	b := a.bridge
	a.bridge = nil
	a.mu.Unlock()
	if b != nil {
		b.Close()
	}
}

// stopCore stops everything that carries the traffic: the core and, for a prefix key, its bridge.
func (a *app) stopCore() {
	_ = a.mgr.Stop()
	a.closeBridge()
}

// onBridgeExit runs when the bridge's listener fails by itself (a deliberate Close is silent). The core's
// only upstream is gone, so nothing can pass; it is stopped, the guard is put back and the green state is
// withdrawn, exactly as for a core that died and cannot be restarted.
func (a *app) onBridgeExit(br *ssbridge.Bridge) {
	a.mu.Lock()
	if a.bridge != br || a.closing {
		a.mu.Unlock()
		return
	}
	a.bridge = nil
	a.confirmed = false
	a.epoch++ // a verdict still on its way described the bridge that has just died
	if a.phase == phaseConnected {
		a.phase, a.errMsg, a.cfg, a.restarting = phaseError, "Соединение прервано. Окно не выходит в интернет напрямую.", nil, false
	}
	a.mu.Unlock()
	_ = a.mgr.Stop()
	a.reguard()
}
