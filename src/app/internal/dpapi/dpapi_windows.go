//go:build windows

// Package dpapi wraps Windows DPAPI (CryptProtectData): data is bound to the current
// Windows user, so a copied file is useless on another account or machine.
package dpapi

import (
	"errors"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32          = syscall.NewLazyDLL("crypt32.dll")
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procProtect      = crypt32.NewProc("CryptProtectData")
	procUnprotect    = crypt32.NewProc("CryptUnprotectData")
	procLocalFree    = kernel32.NewProc("LocalFree")
	cryptprotectNoUI = uintptr(0x1)
	errEmptyInput    = errors.New("dpapi: empty input")
	entropy          = []byte("runet-access/v1") // not a secret: scopes blobs to this app
	descriptionUTF16 = syscall.StringToUTF16Ptr("runet-access key")
)

func blobOf(b []byte) *dataBlob {
	if len(b) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

func takeOutput(out *dataBlob) []byte {
	if out.pbData == nil {
		return nil
	}
	res := make([]byte, out.cbData)
	copy(res, unsafe.Slice(out.pbData, out.cbData))
	procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return res
}

// Protect encrypts data for the current Windows user.
func Protect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errEmptyInput
	}
	var out dataBlob
	r, _, err := procProtect.Call(
		uintptr(unsafe.Pointer(blobOf(data))), uintptr(unsafe.Pointer(descriptionUTF16)),
		uintptr(unsafe.Pointer(blobOf(entropy))), 0, 0, cryptprotectNoUI, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, err
	}
	return takeOutput(&out), nil
}

// Unprotect decrypts data produced by Protect for the same Windows user.
func Unprotect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errEmptyInput
	}
	var out dataBlob
	r, _, err := procUnprotect.Call(
		uintptr(unsafe.Pointer(blobOf(data))), 0,
		uintptr(unsafe.Pointer(blobOf(entropy))), 0, 0, cryptprotectNoUI, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, err
	}
	return takeOutput(&out), nil
}
