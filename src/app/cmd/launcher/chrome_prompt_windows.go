//go:build windows

package main

import (
	"encoding/binary"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// The small window shown when Google Chrome is not installed. It appears BEFORE anything else
// starts (no core, no browser page), explains what is needed in plain Russian and offers two
// actions plus a plain "close". Chrome is never downloaded or installed by us.

const (
	dlgClose   = 0
	dlgOpen    = 101 // open the official Chrome page
	dlgRecheck = 102
)

const chromeMissingTitle = "Runet Access"
const chromeMissingHead = "Для работы нужен Google Chrome"
const chromeMissingBody = "Runet Access открывает российские сайты в отдельном окне Google Chrome, а Chrome на этом компьютере не найден.\n\n" +
	"Установите его с официального сайта Google и нажмите «Проверить снова». Ваш обычный браузер и настройки Windows программа не меняет."

// showChromeMissing returns dlgOpen, dlgRecheck or dlgClose. RUNET_TEST_CHROME_PROMPT (test only)
// supplies a comma-separated list of answers ("open,recheck,close") instead of showing the window.
func showChromeMissing() int {
	if script := os.Getenv("RUNET_TEST_CHROME_PROMPT"); script != "" {
		return scriptedAnswer(script)
	}
	if r, ok := taskDialog(); ok {
		return r
	}
	return messageBoxFallback()
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
	case "open":
		return dlgOpen
	case "recheck":
		return dlgRecheck
	}
	return dlgClose
}

func u16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

// taskDialog uses the modern Windows dialog with command links. It needs the common-controls v6
// manifest that the build embeds; without it the call fails and the caller falls back.
func taskDialog() (int, bool) {
	comctl := syscall.NewLazyDLL("comctl32.dll")
	proc := comctl.NewProc("TaskDialogIndirect")
	if proc.Find() != nil {
		return 0, false
	}
	title, head, body := u16(chromeMissingTitle), u16(chromeMissingHead), u16(chromeMissingBody)
	t1, t2 := u16("Открыть страницу установки Chrome"), u16("Проверить снова")

	// TASKDIALOG_BUTTON array, packed (4 + 8 bytes each)
	btns := make([]byte, 24)
	binary.LittleEndian.PutUint32(btns[0:], dlgOpen)
	binary.LittleEndian.PutUint64(btns[4:], uint64(uintptr(unsafe.Pointer(t1))))
	binary.LittleEndian.PutUint32(btns[12:], dlgRecheck)
	binary.LittleEndian.PutUint64(btns[16:], uint64(uintptr(unsafe.Pointer(t2))))

	// TASKDIALOGCONFIG, #pragma pack(1) layout on 64-bit Windows: 160 bytes
	cfg := make([]byte, 160)
	le := binary.LittleEndian
	le.PutUint32(cfg[0:], 160)
	le.PutUint32(cfg[20:], 0x0008|0x0010) // allow cancellation (X, Esc), command links
	le.PutUint32(cfg[24:], 0x0020)        // common button: Close
	le.PutUint64(cfg[28:], uint64(uintptr(unsafe.Pointer(title))))
	le.PutUint64(cfg[36:], 0xFFFF) // TD_WARNING_ICON
	le.PutUint64(cfg[44:], uint64(uintptr(unsafe.Pointer(head))))
	le.PutUint64(cfg[52:], uint64(uintptr(unsafe.Pointer(body))))
	le.PutUint32(cfg[60:], 2)
	le.PutUint64(cfg[64:], uint64(uintptr(unsafe.Pointer(&btns[0]))))
	le.PutUint32(cfg[72:], dlgOpen)

	var pressed int32
	hr, _, _ := proc.Call(uintptr(unsafe.Pointer(&cfg[0])), uintptr(unsafe.Pointer(&pressed)), 0, 0)
	runtime.KeepAlive(btns)
	runtime.KeepAlive(cfg)
	runtime.KeepAlive([]*uint16{title, head, body, t1, t2})
	if hr != 0 {
		return 0, false
	}
	switch pressed {
	case dlgOpen, dlgRecheck:
		return int(pressed), true
	}
	return dlgClose, true
}

// messageBoxFallback is used only if the modern dialog is unavailable: Yes = open the page,
// No = check again, Cancel/close = quit.
func messageBoxFallback() int {
	text := chromeMissingBody + "\n\nДа — открыть страницу установки Chrome.\nНет — проверить снова.\nОтмена — закрыть."
	const mbYesNoCancel, mbIconWarning = 0x3, 0x30
	r, _, _ := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0,
		uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16(chromeMissingTitle))), mbYesNoCancel|mbIconWarning)
	switch r {
	case 6:
		return dlgOpen
	case 7:
		return dlgRecheck
	}
	return dlgClose
}
