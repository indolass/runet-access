package main

import (
	"bytes"
	"debug/pe"
	"os"
	"path/filepath"
	"testing"
)

// The object must be readable as COFF with one .rsrc section that holds the manifest, and the
// manifest must never ask for administrator rights.
func TestObjectIsValidCOFF(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.syso")
	if err := os.WriteFile(p, build([]byte(manifest)), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := pe.Open(p)
	if err != nil {
		t.Fatalf("not a valid COFF object: %v", err)
	}
	defer f.Close()
	if f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || len(f.Sections) != 1 || f.Sections[0].Name != ".rsrc" {
		t.Fatalf("unexpected layout: machine %x sections %d", f.Machine, len(f.Sections))
	}
	data, err := f.Sections[0].Data()
	if err != nil || !bytes.Contains(data, []byte(`level="asInvoker"`)) {
		t.Fatalf("manifest not in the section: %v", err)
	}
	if bytes.Contains([]byte(manifest), []byte("requireAdministrator")) || bytes.Contains([]byte(manifest), []byte("highestAvailable")) {
		t.Fatal("the manifest must not request elevation")
	}
}
