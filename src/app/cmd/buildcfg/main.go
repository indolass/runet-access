// Command buildcfg is a developer/test tool: it runs a key through the SAME code the launcher uses
// (keyparse.Parse -> config.Build) and writes the resulting sing-box config. It lets the transport
// be tested against external servers without the launcher's country check and without a browser.
// The key is read from a file, never from the command line; failures print only the user-safe message.
//
//	buildcfg -in key.txt -port 17001 -out config.json
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"runetaccess/internal/config"
	"runetaccess/internal/keyparse"
)

func main() {
	in := flag.String("in", "", "file with the key (one line)")
	port := flag.Int("port", 0, "local mixed inbound port")
	out := flag.String("out", "", "config output path")
	flag.Parse()
	if *in == "" || *port == 0 || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: buildcfg -in key.txt -port N -out config.json")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read the key file")
		os.Exit(2)
	}
	p, kerr := keyparse.Parse(strings.TrimSpace(string(raw)))
	if kerr != nil {
		fmt.Printf("REJECTED %s: %s\n", kerr.Code, kerr.Message)
		os.Exit(3)
	}
	cfg, err := config.Build(p, config.Inbound{Listen: "127.0.0.1", Port: *port}, config.Routing{Final: "proxy"}, "warn")
	if err != nil {
		fmt.Println("REJECTED config: the generator refused the profile")
		os.Exit(3)
	}
	if err := os.WriteFile(*out, cfg, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "cannot write the config")
		os.Exit(2)
	}
	fmt.Println("OK")
}
