//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// The small window shown when Google Chrome is not installed. It appears BEFORE anything else
// starts (no core, no browser page), says in a few plain Russian words what is needed and offers:
//   - download and install Chrome from Google (see chrome_install.go for what is guaranteed),
//   - open Google's page to install it by hand (the fallback),
//   - check again, and plain "close" (the program ends without an error).
// Technical facts (source, final address, HTTP answer, size, hash, signer) live in an expandable
// "Подробности" section so the main text stays short. Chrome is never installed silently.
//
// Any window shown while a test override is active is marked "ТЕСТ", so nobody can mistake it for a real error.

const (
	dlgClose   = 0
	dlgOpen    = 101 // open the official Chrome page (manual installation)
	dlgRecheck = 102
	dlgInstall = 103 // download from Google and run the installer
)

const chromeManualURL = "https://www.google.com/chrome/"

const (
	chromeMissingTitle = "Runet Access"
	chromeMissingHead  = "Нужен Google Chrome"
	chromeMissingBody  = "Chrome на этом компьютере не найден. Без него Runet Access не работает."
	chromeDetailsText  = "Установщик скачивается только с dl.google.com по HTTPS и запускается лишь после проверки подписи Google LLC. " +
		"Окна установщика и вопросы Windows вы подтверждаете сами: тихой установки и скрытого принятия условий нет. " +
		"Обычный браузер и настройки Windows программа не меняет."
	testBanner = "Это тестовое окно разработчика, а не настоящая ошибка."
)

// isTestRun is true when any override that fakes the environment of this window is set.
func isTestRun() bool {
	for _, k := range []string{"RUNET_CHROME_PATH", "RUNET_TEST_CHROME_URL", "RUNET_TEST_CHROME_PROMPT", "RUNET_TEST_DIALOG_DUMP"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

func windowTitle() string {
	if isTestRun() {
		return "ТЕСТ — " + chromeMissingTitle
	}
	return chromeMissingTitle
}

func withTestMark(head, body string) (string, string) {
	if isTestRun() {
		return "ТЕСТ: " + head, testBanner + "\n\n" + body
	}
	return head, body
}

// showChromeMissing returns dlgInstall, dlgOpen, dlgRecheck or dlgClose. `note` (the result of the previous
// attempt) is shown above the explanation and `details` in the expandable section. RUNET_TEST_CHROME_PROMPT
// (test only) supplies a comma-separated list of answers ("install,open,recheck,close") instead of a window.
func showChromeMissing(note, details string) int {
	if script := os.Getenv("RUNET_TEST_CHROME_PROMPT"); script != "" {
		return scriptedAnswer(script)
	}
	body := chromeMissingBody
	if note != "" {
		body = note + "\n\n" + body
	}
	expanded := chromeDetailsText
	if details != "" {
		expanded = strings.TrimSpace(details) + "\n\n" + chromeDetailsText
	}
	if r, ok := taskDialogMain(body, expanded); ok {
		return r
	}
	return messageBoxFallback(body)
}

var scriptPos int

func scriptedAnswer(script string) int {
	parts := strings.Split(script, ",")
	if scriptPos >= len(parts) {
		return dlgClose
	}
	a := strings.TrimSpace(parts[scriptPos])
	scriptPos++
	switch a {
	case "install":
		return dlgInstall
	case "open":
		return dlgOpen
	case "recheck":
		return dlgRecheck
	}
	return dlgClose
}

// dumpDialog / dumpResult (test only): RUNET_TEST_DIALOG_DUMP names a file that receives the texts of every
// dialog shown, so tests can check wording without depending on UI Automation.
func dumpDialog(title, head, body, expanded string, buttons []tdButton) {
	lf := os.Getenv("RUNET_TEST_DIALOG_DUMP")
	if lf == "" {
		return
	}
	f, err := os.OpenFile(lf, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "=== DIALOG\ntitle: %s\nhead: %s\nbody: %s\nexpanded: %s\n", title, head, body, expanded)
	for _, b := range buttons {
		fmt.Fprintf(f, "button %d: %s\n", b.id, b.text)
	}
}

func dumpResult(hr uintptr, pressed int32) {
	if lf := os.Getenv("RUNET_TEST_DIALOG_DUMP"); lf != "" {
		if f, err := os.OpenFile(lf, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			fmt.Fprintf(f, "result: hr=0x%x pressed=%d\n", uint32(hr), pressed)
			f.Close()
		}
	}
}

func u16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

type tdButton struct {
	id   int32
	text string
}

const (
	tdfExpandFooter      = 0x0040
	tdfExpandedByDefault = 0x0080
	tdfAllowCancel       = 0x0008
	tdfCommandLinks      = 0x0010
	tdfMarquee           = 0x0400
	tdfCallbackTimer     = 0x0800
	tdcbfCancel          = 0x0008
	tdcbfClose           = 0x0020
	iconWarning          = 0xFFFF
	iconInformation      = 0xFFFD
	// the window width in DIALOG UNITS: it scales with the Windows display scale (100-200%), so lines
	// always wrap inside the window instead of running off the right edge
	dialogWidthDLU = 190
)

type tdOptions struct {
	flags, common uint32
	icon          uintptr
	head, body    string
	buttons       []tdButton
	def           int32
	callback      uintptr
	expanded      string
}

// taskDialog shows a Windows TaskDialog. The structure is #pragma pack(1) on 64-bit Windows (160 bytes).
// It needs the common-controls v6 manifest that the build embeds; without it the call fails.
func taskDialog(o tdOptions) (int32, bool) {
	proc := syscall.NewLazyDLL("comctl32.dll").NewProc("TaskDialogIndirect")
	if proc.Find() != nil {
		return 0, false
	}
	head, body := withTestMark(o.head, o.body)
	keep := []*uint16{u16(windowTitle()), u16(head), u16(body)}
	le := binary.LittleEndian
	btns := make([]byte, 12*len(o.buttons)+12)
	for i, b := range o.buttons {
		p := u16(b.text)
		keep = append(keep, p)
		le.PutUint32(btns[12*i:], uint32(b.id))
		le.PutUint64(btns[12*i+4:], uint64(uintptr(unsafe.Pointer(p))))
	}
	cfg := make([]byte, 160)
	flags := o.flags
	var exp, expCtl, colCtl *uint16
	if o.expanded != "" {
		flags |= tdfExpandFooter
		if os.Getenv("RUNET_TEST_DIALOG_DUMP") != "" { // tests photograph the details too
			flags |= tdfExpandedByDefault
		}
		exp, expCtl, colCtl = u16(o.expanded), u16("Скрыть подробности"), u16("Подробности")
	}
	le.PutUint32(cfg[0:], 160)
	le.PutUint32(cfg[20:], flags)
	le.PutUint32(cfg[24:], o.common)
	le.PutUint64(cfg[28:], uint64(uintptr(unsafe.Pointer(keep[0]))))
	le.PutUint64(cfg[36:], uint64(o.icon))
	le.PutUint64(cfg[44:], uint64(uintptr(unsafe.Pointer(keep[1]))))
	le.PutUint64(cfg[52:], uint64(uintptr(unsafe.Pointer(keep[2]))))
	le.PutUint32(cfg[60:], uint32(len(o.buttons)))
	if len(o.buttons) > 0 {
		le.PutUint64(cfg[64:], uint64(uintptr(unsafe.Pointer(&btns[0]))))
	}
	le.PutUint32(cfg[72:], uint32(o.def))
	if exp != nil {
		le.PutUint64(cfg[100:], uint64(uintptr(unsafe.Pointer(exp))))
		le.PutUint64(cfg[108:], uint64(uintptr(unsafe.Pointer(expCtl))))
		le.PutUint64(cfg[116:], uint64(uintptr(unsafe.Pointer(colCtl))))
	}
	le.PutUint64(cfg[140:], uint64(o.callback))
	le.PutUint32(cfg[156:], dialogWidthDLU)
	dumpDialog(windowTitle(), head, body, o.expanded, o.buttons)
	var pressed int32
	hr, _, _ := proc.Call(uintptr(unsafe.Pointer(&cfg[0])), uintptr(unsafe.Pointer(&pressed)), 0, 0)
	dumpResult(hr, pressed)
	runtime.KeepAlive(btns)
	runtime.KeepAlive(cfg)
	runtime.KeepAlive(keep)
	runtime.KeepAlive([]*uint16{exp, expCtl, colCtl})
	if hr != 0 {
		return 0, false
	}
	return pressed, true
}

func taskDialogMain(body, expanded string) (int, bool) {
	pressed, ok := taskDialog(tdOptions{
		flags: tdfAllowCancel | tdfCommandLinks, common: tdcbfClose, icon: iconWarning, head: chromeMissingHead, body: body,
		buttons: []tdButton{
			{dlgInstall, "Скачать и установить Chrome"},
			{dlgOpen, "Открыть страницу Chrome (вручную)"},
			{dlgRecheck, "Проверить снова"},
		}, def: dlgInstall, expanded: expanded,
	})
	if !ok {
		return 0, false
	}
	switch pressed {
	case dlgInstall, dlgOpen, dlgRecheck:
		return int(pressed), true
	}
	return dlgClose, true
}

// messageBoxFallback is used only if the modern dialog is unavailable: Yes = download and install,
// No = open the page, Cancel/close = quit.
func messageBoxFallback(body string) int {
	head, text := withTestMark(chromeMissingHead, body)
	text = head + "\n\n" + text + "\n\nДа — скачать и установить Chrome.\nНет — открыть страницу Chrome.\nОтмена — закрыть."
	const mbYesNoCancel, mbIconWarning = 0x3, 0x30
	r, _, _ := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0,
		uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16(windowTitle()))), mbYesNoCancel|mbIconWarning)
	switch r {
	case 6:
		return dlgInstall
	case 7:
		return dlgOpen
	}
	return dlgClose
}

// ---- the "working" window -----------------------------------------------------------------

type busyState struct {
	mu   sync.Mutex
	text string
	done bool
}

func (b *busyState) set(s string) { b.mu.Lock(); b.text = s; b.mu.Unlock() }
func (b *busyState) finish()      { b.mu.Lock(); b.done = true; b.mu.Unlock() }
func (b *busyState) get() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.text, b.done
}

// showBusy shows a progress window with a Cancel button until st is finished. It returns true when the user
// closed or cancelled it before the work ended.
func showBusy(head string, st *busyState) (userCancelled bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	sendMessage := syscall.NewLazyDLL("user32.dll").NewProc("SendMessageW")
	const (
		tdmClickButton   = 0x466
		tdmSetMarquee    = 0x46B
		tdmSetElementTxt = 0x46C
		tdnCreated       = 0
		tdnTimer         = 4
		idCancel         = 2
	)
	shown := ""
	var cur *uint16
	cb := syscall.NewCallback(func(hwnd, msg, wparam, lparam, data uintptr) uintptr {
		switch msg {
		case tdnCreated:
			sendMessage.Call(hwnd, tdmSetMarquee, 1, 30)
		case tdnTimer:
			text, done := st.get()
			if done {
				sendMessage.Call(hwnd, tdmClickButton, idCancel, 0)
			} else if text != shown {
				shown = text
				cur = u16(text)
				sendMessage.Call(hwnd, tdmSetElementTxt, 0, uintptr(unsafe.Pointer(cur)))
			}
		}
		return 0
	})
	text, _ := st.get()
	_, ok := taskDialog(tdOptions{flags: tdfAllowCancel | tdfMarquee | tdfCallbackTimer, common: tdcbfCancel,
		icon: iconInformation, head: head, body: text, callback: cb})
	runtime.KeepAlive(cur)
	_, done := st.get()
	if !ok { // the dialog could not be shown: just wait for the work
		for !done {
			time.Sleep(200 * time.Millisecond)
			_, done = st.get()
		}
		return false
	}
	return !done
}

// installChromeInteractive downloads and starts Google's installer, with a progress window, and returns
// "" when Chrome is installed, otherwise a short message for the user and technical details.
func installChromeInteractive() (note, details string) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	st := &busyState{text: "Подготовка…"}
	deps := realInstallDeps(st.set)
	var res *installError
	done := make(chan struct{})
	go func() {
		_, res = installChrome(ctx, deps)
		st.finish()
		close(done)
	}()
	cancelled := showBusy("Установка Google Chrome", st)
	if cancelled {
		cancel() // stops waiting/downloading; an installer that already runs is never killed
	}
	<-done
	switch {
	case res == nil:
		return "", ""
	case cancelled && res.Kind == failCancelled:
		return "Установка отменена. Её можно повторить.", res.Details
	}
	return res.Msg, res.Details
}

func realInstallDeps(stage func(string)) installDeps {
	d := installDeps{
		url:          chromeInstallerURL,
		allowedHosts: []string{chromeInstallerHost},
		tempBase:     filepath.Join(os.TempDir(), "runet-access"),
		verify:       verifyGoogleSigned,
		run:          func(ctx context.Context, p string) (uint32, error) { return shellRunAndWait(ctx, p, swShowNormal) },
		detect:       findChrome,
		stage:        stage,
	}
	// Test only: a loopback address stands in for Google's host. It is honoured for loopback only, so it
	// cannot redirect the download to a real site; the signature requirement is never relaxed.
	if raw := os.Getenv("RUNET_TEST_CHROME_URL"); raw != "" {
		if u, err := url.Parse(raw); err == nil && isLoopbackHost(u.Hostname()) {
			d.url, d.allowedHosts, d.allowLoopbackHTTP = raw, []string{u.Hostname()}, true
		}
	}
	return d
}
