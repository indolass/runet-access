//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// shellOpen hands an address to Windows, which opens it in the user's DEFAULT browser (or the
// Telegram app). The address is passed as a single parameter, never through a shell or a
// command line, and callers only pass entries of externalLinks.
func shellOpen(target string) error {
	verb, _ := syscall.UTF16PtrFromString("open")
	file, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	proc := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")
	const swShowNormal = 1
	r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), 0, 0, swShowNormal)
	if r <= 32 { // ShellExecute returns a value above 32 on success
		return fmt.Errorf("ShellExecute failed (%d)", r)
	}
	return nil
}
