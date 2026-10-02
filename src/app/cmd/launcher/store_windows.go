//go:build windows

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"runetaccess/internal/dpapi"
)

// keyStore keeps the key encrypted with Windows DPAPI (bound to this Windows user).
type keyStore struct{ path string }

func (s keyStore) exists() bool {
	st, err := os.Stat(s.path)
	return err == nil && !st.IsDir()
}

func (s keyStore) save(key string) error {
	enc, err := dpapi.Protect([]byte(key))
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, enc, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s keyStore) load() (string, error) {
	enc, err := os.ReadFile(s.path)
	if err != nil {
		return "", err
	}
	dec, err := dpapi.Unprotect(enc)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

func (s keyStore) remove() { _ = os.Remove(s.path) }

// ---- single instance --------------------------------------------------------------------

// acquireLock creates an exclusive lock file holding our PID. A stale file (its process is
// gone) is taken over. The returned func releases it.
func acquireLock(path string) (func(), error) {
	for i := 0; i < 2; i++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%d", os.Getpid())
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		b, rerr := os.ReadFile(path)
		if rerr == nil {
			if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil && pidAlive(pid) {
				return nil, fmt.Errorf("running")
			}
		}
		_ = os.Remove(path)
	}
	return nil, fmt.Errorf("lock")
}

func pidAlive(pid int) bool {
	const processQueryLimited = 0x1000
	h, err := syscall.OpenProcess(processQueryLimited, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

// ---- user-visible fatal errors (the launcher has no console) ------------------------------

func fatal(msg string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	box := user32.NewProc("MessageBoxW")
	title, _ := syscall.UTF16PtrFromString("Runet Access")
	text, _ := syscall.UTF16PtrFromString(msg)
	if os.Getenv("RUNET_NO_DIALOG") == "" {
		box.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10)
	}
	os.Exit(1)
}
