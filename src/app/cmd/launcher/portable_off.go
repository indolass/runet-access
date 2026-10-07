//go:build !portable

package main

import "os"

// The ordinary build (the one the installer packs) keeps sing-box next to the exe; nothing to prepare.
const portableBuild = false

func preparePortable(home string) (*os.File, string, error) { return nil, "", nil }

func portableCommand(home string, args []string, open func(string) error) bool { return false }
