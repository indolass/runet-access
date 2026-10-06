//go:build windows

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const installedChrome = `C:\Program Files\Google\Chrome\Application\chrome.exe`

// signedByOther is the pinned Inno Setup installer cached by scripts\make-installer.ps1: validly signed,
// but by "Pyrsys B.V.", not by Google.
func signedByOther(t *testing.T) string {
	t.Helper()
	p, _ := filepath.Abs(filepath.Join("..", "..", "..", "..", ".local", "cache", "downloads", "innosetup-6.7.3.exe"))
	if _, err := os.Stat(p); err != nil {
		t.Skip("the cached signed installer is not present: " + p)
	}
	return p
}

func TestGoogleSignatureIsAccepted(t *testing.T) {
	if _, err := os.Stat(installedChrome); err != nil {
		t.Skip("no installed Chrome to read a real Google signature from")
	}
	org, err := verifyAuthenticode(installedChrome) // read-only: the installed file is only inspected
	if err != nil || org != "Google LLC" {
		t.Fatalf("got %q %v", org, err)
	}
	if pub, err := verifyGoogleSigned(installedChrome); err != nil || pub != "Google LLC" {
		t.Fatalf("%q %v", pub, err)
	}
}

func TestAValidSignatureOfSomeoneElseIsRefused(t *testing.T) {
	p := signedByOther(t)
	org, err := verifyAuthenticode(p)
	if err != nil || org != "Pyrsys B.V." {
		t.Fatalf("expected a valid Pyrsys signature, got %q %v", org, err)
	}
	pub, err := verifyGoogleSigned(p)
	if err == nil || !strings.Contains(err.Error(), "не Google") || pub != "Pyrsys B.V." {
		t.Fatalf("must be refused as not Google, with the publisher reported: %q %v", pub, err)
	}
}

func TestTamperedFileIsRefused(t *testing.T) {
	p := signedByOther(t)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0xFF // change one byte in the middle of the file
	q := filepath.Join(t.TempDir(), "tampered.exe")
	if err := os.WriteFile(q, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAuthenticode(q); err == nil {
		t.Fatal("a modified file must not verify")
	}
}

func TestUnsignedFileIsRefused(t *testing.T) {
	self, _ := os.Executable() // the test binary: not signed
	if _, err := verifyAuthenticode(self); err == nil || !strings.Contains(err.Error(), "не подписан") {
		t.Fatalf("got %v", err)
	}
	if _, err := verifyGoogleSigned(self); err == nil {
		t.Fatal("unsigned must be refused")
	}
	if _, err := verifyAuthenticode(filepath.Join(t.TempDir(), "missing.exe")); err == nil {
		t.Fatal("a missing file must be refused")
	}
}

func buildFixture(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "fixture.exe")
	cmd := exec.Command("go", "build", "-o", out, "./testdata/exitcode")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build the fixture: %v\n%s", err, b)
	}
	return out
}

func TestShellRunWaitsAndReturnsTheExitCode(t *testing.T) {
	fx := buildFixture(t)
	t.Setenv("FIXTURE_CODE", "7")
	code, err := shellRunAndWait(context.Background(), fx, swHide)
	if err != nil || code != 7 {
		t.Fatalf("got %d %v", code, err)
	}
}

func TestShellRunCancelStopsWaitingOnly(t *testing.T) {
	fx := buildFixture(t)
	t.Setenv("FIXTURE_SLEEP_MS", "2500")
	t.Setenv("FIXTURE_CODE", "0")
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := shellRunAndWait(ctx, fx, swHide)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("expected a prompt cancellation, got %v after %v", err, time.Since(start))
	}
	time.Sleep(2500 * time.Millisecond) // the program was NOT killed; let it end by itself so the folder can be removed
}

func TestShellRunMissingFileIsAnErrorNotADenial(t *testing.T) {
	_, err := shellRunAndWait(context.Background(), filepath.Join(t.TempDir(), "nope.exe"), swHide)
	if err == nil || err == errDenied {
		t.Fatalf("got %v", err)
	}
}

func TestPickedChromeIsValidated(t *testing.T) {
	// the genuine installed Chrome (read only)
	if _, err := os.Stat(installedChrome); err == nil {
		info, err := validateChromePick(installedChrome)
		if err != nil || !strings.Contains(info, "Google LLC") {
			t.Fatalf("the real Chrome must be accepted: %v\n%s", err, info)
		}
	}
	dir := t.TempDir()
	// a validly signed program of someone else, renamed chrome.exe
	other := signedByOther(t)
	b, _ := os.ReadFile(other)
	fake := filepath.Join(dir, "chrome.exe")
	if err := os.WriteFile(fake, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if info, err := validateChromePick(fake); err == nil || !strings.Contains(info, "Pyrsys B.V.") {
		t.Fatalf("someone else's signed program must be refused with the publisher shown: %v\n%s", err, info)
	}
	// the same file, one byte changed
	b[len(b)/2] ^= 0xFF
	_ = os.WriteFile(fake, b, 0o600)
	if _, err := validateChromePick(fake); err == nil {
		t.Fatal("a modified file must be refused")
	}
	// wrong name, unsigned, tiny, folder, missing
	self, _ := os.Executable()
	sb, _ := os.ReadFile(self)
	wrong := filepath.Join(dir, "browser.exe")
	_ = os.WriteFile(wrong, sb, 0o600)
	if _, err := validateChromePick(wrong); err == nil {
		t.Fatal("only chrome.exe may be picked")
	}
	unsigned := filepath.Join(dir, "sub", "chrome.exe")
	_ = os.MkdirAll(filepath.Dir(unsigned), 0o700)
	_ = os.WriteFile(unsigned, sb, 0o600)
	if _, err := validateChromePick(unsigned); err == nil {
		t.Fatal("an unsigned chrome.exe must be refused")
	}
	tiny := filepath.Join(dir, "tiny", "chrome.exe")
	_ = os.MkdirAll(filepath.Dir(tiny), 0o700)
	_ = os.WriteFile(tiny, []byte("MZ"), 0o600)
	if _, err := validateChromePick(tiny); err == nil {
		t.Fatal("a tiny file must be refused")
	}
	if _, err := validateChromePick(filepath.Join(dir, "missing", "chrome.exe")); err == nil {
		t.Fatal("a missing file must be refused")
	}
}
