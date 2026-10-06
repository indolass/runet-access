//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// Authenticode verification through Windows itself (WinVerifyTrust): the signature must be valid,
// the certificate chain must lead to a trusted root, revocation is checked, and the signer's
// organisation is read from the certificate. No third-party code, no PowerShell.

var (
	modWintrust  = syscall.NewLazyDLL("wintrust.dll")
	modCrypt32   = syscall.NewLazyDLL("crypt32.dll")
	modKernel32x = syscall.NewLazyDLL("kernel32.dll")

	procWinVerifyTrust                 = modWintrust.NewProc("WinVerifyTrust")
	procWTHelperProvDataFromStateData  = modWintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain = modWintrust.NewProc("WTHelperGetProvSignerFromChain")
	procCertGetNameStringW             = modCrypt32.NewProc("CertGetNameStringW")
	procRtlMoveMemory                  = modKernel32x.NewProc("RtlMoveMemory")
)

type winGUID struct {
	D1 uint32
	D2 uint16
	D3 uint16
	D4 [8]byte
}

// WINTRUST_ACTION_GENERIC_VERIFY_V2
var actionGenericVerifyV2 = winGUID{0x00AAC56B, 0xCD44, 0x11D0, [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}}

type winTrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          uintptr
	pgKnownSubject uintptr
}

type winTrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               *winTrustFileInfo
	dwStateAction       uint32
	hWVTStateData       uintptr
	pwszURLReference    uintptr
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

const (
	wtdUINone                = 2
	wtdRevokeWholeChain      = 1
	wtdChoiceFile            = 1
	wtdStateActionVerify     = 1
	wtdStateActionClose      = 2
	wtdRevocationExcludeRoot = 0x80
	certNameAttrType         = 3
)

func hrMessage(hr uintptr) string {
	switch uint32(hr) {
	case 0x800B0100:
		return "файл не подписан"
	case 0x80096010:
		return "подпись не совпадает с содержимым файла (файл изменён)"
	case 0x800B0109, 0x800B010A:
		return "сертификат подписи не удалось связать с доверенным корневым"
	case 0x800B0101:
		return "срок действия сертификата подписи истёк"
	case 0x80092013, 0x80092012:
		return "не удалось проверить отзыв сертификата"
	case 0x800B0111:
		return "подпись отклонена политикой"
	}
	return fmt.Sprintf("код проверки 0x%08X", uint32(hr))
}

func readMem(dst []byte, src uintptr) {
	if src != 0 && len(dst) > 0 {
		procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&dst[0])), src, uintptr(len(dst)))
	}
}

func readPtr(at uintptr) uintptr {
	var b [8]byte
	readMem(b[:], at)
	return uintptr(b[0]) | uintptr(b[1])<<8 | uintptr(b[2])<<16 | uintptr(b[3])<<24 |
		uintptr(b[4])<<32 | uintptr(b[5])<<40 | uintptr(b[6])<<48 | uintptr(b[7])<<56
}

// verifyAuthenticode returns the organisation of the signer when Windows accepts the signature
// (including a revocation check of the certificate chain).
func verifyAuthenticode(path string) (string, error) { return verifyAuthenticodeRev(path, true) }

// verifyAuthenticodeRev is verifyAuthenticode with the revocation lookup optional (it needs the network).
func verifyAuthenticodeRev(path string, revocation bool) (string, error) {
	p16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	fi := winTrustFileInfo{cbStruct: uint32(unsafe.Sizeof(winTrustFileInfo{})), pcwszFilePath: p16}
	wd := winTrustData{
		cbStruct: uint32(unsafe.Sizeof(winTrustData{})), dwUIChoice: wtdUINone,
		dwUnionChoice: wtdChoiceFile, pFile: &fi, dwStateAction: wtdStateActionVerify,
	}
	if revocation {
		wd.fdwRevocationChecks, wd.dwProvFlags = wtdRevokeWholeChain, wtdRevocationExcludeRoot
	}
	invalidHandle := ^uintptr(0)
	hr, _, _ := procWinVerifyTrust.Call(invalidHandle, uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&wd)))
	defer func() {
		wd.dwStateAction = wtdStateActionClose
		procWinVerifyTrust.Call(invalidHandle, uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&wd)))
	}()
	if hr != 0 {
		return "", fmt.Errorf("%s", hrMessage(hr))
	}
	prov, _, _ := procWTHelperProvDataFromStateData.Call(wd.hWVTStateData)
	if prov == 0 {
		return "", fmt.Errorf("не удалось прочитать данные подписи")
	}
	sgnr, _, _ := procWTHelperGetProvSignerFromChain.Call(prov, 0, 0, 0)
	if sgnr == 0 {
		return "", fmt.Errorf("в файле нет подписанта")
	}
	// CRYPT_PROVIDER_SGNR (x64): csCertChain DWORD at 12, pasCertChain pointer at 16;
	// CRYPT_PROVIDER_CERT: pCert pointer at 8.
	var cnt [4]byte
	readMem(cnt[:], sgnr+12)
	if cnt == [4]byte{} {
		return "", fmt.Errorf("пустая цепочка сертификатов")
	}
	chain := readPtr(sgnr + 16)
	cert := readPtr(chain + 8)
	if cert == 0 {
		return "", fmt.Errorf("не удалось прочитать сертификат подписанта")
	}
	oid := append([]byte("2.5.4.10"), 0) // organisation name
	buf := make([]uint16, 256)
	n, _, _ := procCertGetNameStringW.Call(cert, certNameAttrType, 0, uintptr(unsafe.Pointer(&oid[0])), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n <= 1 {
		return "", fmt.Errorf("в сертификате нет названия организации")
	}
	return strings.TrimSpace(string(utf16.Decode(buf[:n-1]))), nil
}

// verifyGoogleSigned accepts the file only when Windows trusts its signature AND the signer is Google LLC.
// The publisher is returned even on refusal when the signature itself is valid (for the details section).
func verifyGoogleSigned(path string) (string, error) {
	org, err := verifyAuthenticode(path)
	if err != nil {
		return "", err
	}
	if org != chromeSignerOrg {
		return org, fmt.Errorf("подписано не Google (издатель: %s)", org)
	}
	return org, nil
}

// validateChromePick checks a chrome.exe the user pointed at. The returned text lists what was found.
func validateChromePick(path string) (string, error) {
	info := "Файл: " + path + "\n"
	if !strings.EqualFold(filepath.Base(path), "chrome.exe") {
		return info, fmt.Errorf("файл называется не chrome.exe")
	}
	if st, err := os.Stat(path); err != nil || st.IsDir() || st.Size() < 1<<20 {
		return info, fmt.Errorf("файл не найден или слишком мал для браузера")
	}
	org, err := verifyAuthenticodeRev(path, false)
	if org != "" {
		info += "Издатель в подписи: " + org + "\n"
	}
	if err != nil {
		return info, fmt.Errorf("проверка подписи Windows: %v", err)
	}
	if org != chromeSignerOrg {
		return info, fmt.Errorf("подписано не Google (издатель: %s)", org)
	}
	return info + "Проверка подписи Windows: действительна\n", nil
}

func init() {
	chromeFileOK = func(path string) error {
		org, err := verifyAuthenticodeRev(path, false)
		if err != nil {
			return err
		}
		if org != chromeSignerOrg {
			return fmt.Errorf("подписано не Google")
		}
		return nil
	}
}
