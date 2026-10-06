//go:build windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// chromeFromRegistry reads the path Chrome registers for itself ("App Paths"), which covers
// installs in non-standard folders, for the current user as well as for the whole machine.
// Read only: nothing is ever written to the registry.
func chromeFromRegistry() []string {
	const sub = `Microsoft\Windows\CurrentVersion\App Paths\chrome.exe`
	keys := []struct {
		root syscall.Handle
		path string
	}{
		{syscall.HKEY_CURRENT_USER, `Software\` + sub},
		{syscall.HKEY_LOCAL_MACHINE, `SOFTWARE\` + sub},
		{syscall.HKEY_LOCAL_MACHINE, `SOFTWARE\WOW6432Node\` + sub},
	}
	var out []string
	for _, k := range keys {
		if v := regDefaultString(k.root, k.path); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func regDefaultString(root syscall.Handle, path string) string {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	var h syscall.Handle
	if syscall.RegOpenKeyEx(root, p, 0, syscall.KEY_READ, &h) != nil {
		return ""
	}
	defer syscall.RegCloseKey(h)
	var typ, n uint32
	if syscall.RegQueryValueEx(h, nil, nil, &typ, nil, &n) != nil || n < 2 || n > 4096 || typ != syscall.REG_SZ {
		return ""
	}
	buf := make([]uint16, n/2+1)
	if syscall.RegQueryValueEx(h, nil, nil, &typ, (*byte)(unsafePtr(&buf[0])), &n) != nil {
		return ""
	}
	return string(utf16.Decode(trimNul(buf)))
}

func trimNul(b []uint16) []uint16 {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

type openFileName struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	Flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	FlagsEx           uint32
}

// pickChromeFile shows the standard Windows "open file" window (only chrome.exe is offered) and returns the
// chosen path, or "" when the user cancels.
func pickChromeFile() string {
	buf := make([]uint16, 1024)
	filter := utf16.Encode([]rune("chrome.exe\x00chrome.exe\x00\x00"))
	title, _ := syscall.UTF16PtrFromString("Укажите chrome.exe")
	var dir *uint16
	if d := os.Getenv("ProgramFiles"); d != "" {
		cand := filepath.Join(d, "Google", "Chrome", "Application")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			dir, _ = syscall.UTF16PtrFromString(cand)
		}
	}
	const (
		ofnHideReadOnly  = 0x4
		ofnNoChangeDir   = 0x8
		ofnPathMustExist = 0x800
		ofnFileMustExist = 0x1000
		ofnExplorer      = 0x80000
	)
	ofn := openFileName{lpstrFilter: &filter[0], lpstrFile: &buf[0], nMaxFile: uint32(len(buf)), lpstrTitle: title, lpstrInitialDir: dir,
		Flags: ofnHideReadOnly | ofnNoChangeDir | ofnPathMustExist | ofnFileMustExist | ofnExplorer}
	ofn.lStructSize = uint32(unsafe.Sizeof(ofn))
	r, _, _ := syscall.NewLazyDLL("comdlg32.dll").NewProc("GetOpenFileNameW").Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		return ""
	}
	return string(utf16.Decode(trimNul(buf)))
}
