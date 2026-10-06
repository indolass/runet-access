//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// shellRunAndWait starts a program the way Explorer would (Windows shows its own consent/elevation
// prompt when the program needs it; nothing is bypassed or pre-answered) and waits for it to end.
// Cancelling the context stops WAITING; the program itself is never killed.

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     uintptr
}

var (
	modShell32               = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteExW      = modShell32.NewProc("ShellExecuteExW")
	procWaitForSingleObjectK = syscall.NewLazyDLL("kernel32.dll").NewProc("WaitForSingleObject")
	procGetExitCodeProcessK  = syscall.NewLazyDLL("kernel32.dll").NewProc("GetExitCodeProcess")
	procCloseHandleK         = syscall.NewLazyDLL("kernel32.dll").NewProc("CloseHandle")
)

const (
	seeMaskNoCloseProcess = 0x40
	errorCancelled        = 1223
	swShowNormal          = 1
	swHide                = 0
)

func shellRunAndWait(ctx context.Context, path string, show int32) (uint32, error) {
	if st, err := os.Stat(path); err != nil || st.IsDir() { // no Windows error box for a missing file
		return 0, fmt.Errorf("file not found")
	}
	file, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	info := shellExecuteInfo{fMask: seeMaskNoCloseProcess, lpFile: file, nShow: show}
	info.cbSize = uint32(unsafe.Sizeof(info))
	r, _, e := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		if en, ok := e.(syscall.Errno); ok && en == errorCancelled {
			return 0, errDenied
		}
		return 0, fmt.Errorf("ShellExecuteEx: %v", e)
	}
	if info.hProcess == 0 { // the handler gave no process to wait for: the caller polls for the result
		return 0, nil
	}
	defer procCloseHandleK.Call(info.hProcess)
	for {
		w, _, _ := procWaitForSingleObjectK.Call(info.hProcess, 500)
		if w == 0 { // WAIT_OBJECT_0
			var code uint32
			procGetExitCodeProcessK.Call(info.hProcess, uintptr(unsafe.Pointer(&code)))
			return code, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
