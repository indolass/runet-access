//go:build portable

package main

import (
	_ "embed"
	"os"
	"path/filepath"
)

// The portable build: the core and the licences travel inside the exe (payload/payload.zip is made by
// scripts\make-portable.ps1; the hashes below are baked in with -ldflags "-X main.payloadSHA256=... -X main.coreSHA256=...").
const portableBuild = true

//go:embed payload/payload.zip
var embeddedPayload []byte

var payloadSHA256, coreSHA256 string

func spec() payloadSpec {
	return payloadSpec{zip: embeddedPayload, wantPayload: payloadSHA256, wantCore: coreSHA256}
}

func preparePortable(home string) (*os.File, string, error) {
	core, hold, err := prepareCore(home, spec())
	return hold, core, err
}

// portableCommand handles "RunetAccess-Portable.exe --licenses": unpacks the licence texts (and the sing-box source
// archive) if needed and opens their folder. It works while the program runs, so it never takes the program's lock.
func portableCommand(home string, args []string, open func(string) error) bool {
	if len(args) < 2 || args[1] != "--licenses" {
		return false
	}
	dir, err := ensureComponents(home, spec())
	if err != nil {
		fatal("Не удалось подготовить лицензии: " + err.Error())
	}
	_ = open(filepath.Join(dir, "licenses"))
	return true
}
