package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makePayload builds a payload zip the way scripts\make-portable.ps1 does: the core, licence files and a manifest.
func makePayload(t *testing.T, core string, extra map[string]string) payloadSpec {
	t.Helper()
	files := map[string]string{"sing-box.exe": core, "licenses/LICENSE.txt": "licence text", "licenses/sub/NOTICE.txt": "notice " + core}
	for k, v := range extra {
		files[k] = v
	}
	return payloadFrom(t, files, true)
}

func payloadFrom(t *testing.T, files map[string]string, withManifest bool) payloadSpec {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var manifest strings.Builder
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
		manifest.WriteString(sha256Hex([]byte(body)) + "  " + name + "\n")
	}
	if withManifest {
		w, _ := zw.Create(manifestName)
		_, _ = w.Write([]byte(manifest.String()))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	return payloadSpec{zip: b, wantPayload: sha256Hex(b), wantCore: sha256Hex([]byte(files["sing-box.exe"]))}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestFreshUnpackThenReuse(t *testing.T) {
	home := t.TempDir()
	p := makePayload(t, "CORE-A", nil)
	dir, err := ensureComponents(home, p)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(dir) != p.wantPayload[:16] || filepath.Dir(dir) != filepath.Join(home, "components") {
		t.Fatalf("unexpected folder %s", dir)
	}
	if read(t, filepath.Join(dir, "sing-box.exe")) != "CORE-A" || read(t, filepath.Join(dir, "licenses", "sub", "NOTICE.txt")) != "notice CORE-A" {
		t.Fatal("wrong content")
	}
	st1, _ := os.Stat(filepath.Join(dir, "sing-box.exe"))
	time.Sleep(20 * time.Millisecond)
	dir2, err := ensureComponents(home, p)
	st2, _ := os.Stat(filepath.Join(dir2, "sing-box.exe"))
	if err != nil || dir2 != dir || !st1.ModTime().Equal(st2.ModTime()) {
		t.Fatalf("a good copy must be reused untouched: %v", err)
	}
}

func TestDamagedCopyIsRepairedFromTheExe(t *testing.T) {
	home := t.TempDir()
	p := makePayload(t, "CORE-A", nil)
	dir, _ := ensureComponents(home, p)
	core := filepath.Join(dir, "sing-box.exe")
	// 1. the core is modified (one byte appended)
	if err := os.WriteFile(core, []byte("CORE-A!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureComponents(home, p); err != nil || read(t, core) != "CORE-A" {
		t.Fatalf("modified core not repaired: %v", err)
	}
	// 2. a licence file is replaced
	lic := filepath.Join(dir, "licenses", "LICENSE.txt")
	_ = os.WriteFile(lic, []byte("other"), 0o600)
	if _, err := ensureComponents(home, p); err != nil || read(t, lic) != "licence text" {
		t.Fatalf("modified licence not repaired: %v", err)
	}
	// 3. a file is deleted, then the whole folder
	_ = os.Remove(core)
	if _, err := ensureComponents(home, p); err != nil || read(t, core) != "CORE-A" {
		t.Fatalf("deleted core not restored: %v", err)
	}
	_ = os.RemoveAll(dir)
	if _, err := ensureComponents(home, p); err != nil || read(t, core) != "CORE-A" {
		t.Fatalf("deleted folder not restored: %v", err)
	}
	// nothing is left aside
	entries, _ := os.ReadDir(filepath.Join(home, "components"))
	if len(entries) != 1 {
		t.Fatalf("left-overs: %v", entries)
	}
}

func TestBuildsThatDoNotAddUpAreRefused(t *testing.T) {
	good := makePayload(t, "CORE-A", nil)
	bad := map[string]payloadSpec{}
	p := good
	p.wantPayload = strings.Repeat("0", 64)
	bad["payload hash"] = p
	p = good
	p.wantCore = strings.Repeat("1", 64)
	bad["core hash"] = p
	p = good
	p.wantPayload, p.wantCore = "", ""
	bad["no hashes baked in"] = p
	bad["empty payload"] = payloadSpec{wantPayload: good.wantPayload, wantCore: good.wantCore}
	flipped := append([]byte(nil), good.zip...)
	flipped[len(flipped)/2] ^= 0xFF
	bad["a changed byte in the exe's payload"] = payloadSpec{zip: flipped, wantPayload: good.wantPayload, wantCore: good.wantCore}
	// a zip that is well formed and whose hashes ARE baked in, but whose content is unsafe or inconsistent
	unsafe := map[string]map[string]string{
		"path escape":        {"sing-box.exe": "C", "licenses/../../evil.txt": "x"},
		"backslash":          {"sing-box.exe": "C", "licenses\\x.txt": "x"},
		"absolute":           {"sing-box.exe": "C", "/licenses/x.txt": "x"},
		"drive":              {"sing-box.exe": "C", "licenses/c:x.txt": "x"},
		"an unexpected root": {"sing-box.exe": "C", "other/x.txt": "x"},
		"trailing dot":       {"sing-box.exe": "C", "licenses/x.": "x"},
	}
	for name, files := range unsafe {
		bad[name] = payloadFrom(t, files, true)
	}
	bad["no manifest"] = payloadFrom(t, map[string]string{"sing-box.exe": "C"}, false)
	for name, spec := range bad {
		home := t.TempDir()
		if _, err := ensureComponents(home, spec); err == nil {
			t.Errorf("%s: must be refused", name)
		}
		if _, err := os.Stat(filepath.Join(home, "evil.txt")); err == nil {
			t.Errorf("%s: wrote outside the folder", name)
		}
	}
}

func TestManifestMustListExactlyTheFiles(t *testing.T) {
	// an extra file the manifest does not know, and a manifest line for a file that is not there
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("sing-box.exe")
	_, _ = w.Write([]byte("C"))
	w, _ = zw.Create("licenses/extra.txt")
	_, _ = w.Write([]byte("x"))
	w, _ = zw.Create(manifestName)
	_, _ = w.Write([]byte(sha256Hex([]byte("C")) + "  sing-box.exe\n"))
	_ = zw.Close()
	spec := payloadSpec{zip: buf.Bytes(), wantPayload: sha256Hex(buf.Bytes()), wantCore: sha256Hex([]byte("C"))}
	if _, err := ensureComponents(t.TempDir(), spec); err == nil {
		t.Fatal("a file outside the manifest must be refused")
	}
}

func TestTheCoreIsLockedAgainstChangeWhileHeld(t *testing.T) {
	home := t.TempDir()
	p := makePayload(t, "CORE-A", nil)
	core, hold, err := prepareCore(home, p)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	if f, err := os.OpenFile(core, os.O_WRONLY, 0); err == nil {
		f.Close()
		t.Fatal("the held core could be opened for writing")
	}
	if err := os.WriteFile(core, []byte("evil"), 0o600); err == nil {
		t.Fatal("the held core could be overwritten")
	}
	if err := os.Remove(core); err == nil {
		t.Fatal("the held core could be deleted")
	}
	if err := os.Rename(core, core+".x"); err == nil {
		t.Fatal("the held core could be renamed")
	}
	if read(t, core) != "CORE-A" { // and it can still be read and started
		t.Fatal("changed")
	}
	// a second copy of the program (the next build) must not disturb it: another folder, and the running one stays
	p2 := makePayload(t, "CORE-B", nil)
	core2, hold2, err := prepareCore(home, p2)
	if err != nil {
		t.Fatal(err)
	}
	defer hold2.Close()
	if filepath.Dir(core2) == filepath.Dir(core) {
		t.Fatal("two builds share a folder")
	}
	if read(t, core) != "CORE-A" || read(t, core2) != "CORE-B" {
		t.Fatal("a running instance's component was changed by the update")
	}
}

func TestDamagedAndInUseGivesAPlainError(t *testing.T) {
	home := t.TempDir()
	p := makePayload(t, "CORE-A", nil)
	dir, _ := ensureComponents(home, p)
	_, hold, err := prepareCore(home, p)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	// a licence file is damaged while the core is held: the folder cannot be moved aside, so it says so (no panic, no half state)
	_ = os.WriteFile(filepath.Join(dir, "licenses", "LICENSE.txt"), []byte("x"), 0o600)
	if _, err := ensureComponents(home, p); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("got %v", err)
	}
	if read(t, filepath.Join(dir, "sing-box.exe")) != "CORE-A" {
		t.Fatal("the held core was touched")
	}
}

func TestLeftOversAndOldBuildsAreCleanedButNothingElse(t *testing.T) {
	home := t.TempDir()
	base := filepath.Join(home, "components")
	for _, d := range []string{".tmp-abc", ".old-def", "0123456789abcdef", "my-own-folder"} {
		_ = os.MkdirAll(filepath.Join(base, d), 0o700)
		_ = os.WriteFile(filepath.Join(base, d, "f"), []byte("x"), 0o600)
	}
	if _, err := ensureComponents(home, makePayload(t, "CORE-A", nil)); err != nil {
		t.Fatal(err)
	}
	for d, want := range map[string]bool{".tmp-abc": false, ".old-def": false, "0123456789abcdef": false, "my-own-folder": true} {
		_, err := os.Stat(filepath.Join(base, d))
		if (err == nil) != want {
			t.Errorf("%s: exists=%v want %v", d, err == nil, want)
		}
	}
}
