// A harmless test program: optionally sleeps, then exits with the code given in the environment.
// Used only by the launcher's tests (it is never packaged).
package main

import (
	"os"
	"strconv"
	"time"
)

func main() {
	if ms, err := strconv.Atoi(os.Getenv("FIXTURE_SLEEP_MS")); err == nil {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
	if m := os.Getenv("FIXTURE_MARKER"); m != "" { // proves that the program was started
		_ = os.WriteFile(m, []byte("started"), 0o600)
	}
	code, _ := strconv.Atoi(os.Getenv("FIXTURE_CODE"))
	os.Exit(code)
}
