//go:build windows

package main

import "syscall"

// appMutexName is checked by the installer (AppMutex): while the program runs, Setup and the
// uninstaller ask the user to close it instead of replacing files under it.
const appMutexName = "RunetAccess.SingleInstance.6f0c7e1a"

var appMutex syscall.Handle // held for the life of the process

func holdAppMutex() {
	name, err := syscall.UTF16PtrFromString(appMutexName)
	if err != nil {
		return
	}
	h, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("CreateMutexW").Call(0, 0, uintptr(unsafePtr(name)))
	appMutex = syscall.Handle(h)
}
