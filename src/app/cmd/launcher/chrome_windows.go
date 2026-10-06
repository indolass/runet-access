//go:build windows

package main

import (
	"syscall"
	"unicode/utf16"
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
