package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed ui/*
var uiFS embed.FS

type stateResp struct {
	Phase   string `json:"phase"`
	Error   string `json:"error,omitempty"`
	HasKey  bool   `json:"hasKey"`
	Version string `json:"version"`
}

type probeCfg struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type configResp struct {
	ExpectedCountry string     `json:"expectedCountry"`
	Proxied         []probeCfg `json:"proxied"`
	Direct          probeCfg   `json:"direct"`
	TimeoutMs       int        `json:"timeoutMs"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// routes serves the control page and its API on 127.0.0.1 only. Access needs the random
// token (cookie), and the Host header must be our own loopback address (anti DNS-rebinding).
func (a *app) routes(srvPort int) http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(uiFS, "ui")
	static := http.FileServer(http.FS(sub))
	mux.Handle("/", static)

	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		s := stateResp{Phase: a.phase, Error: a.errMsg, Version: version}
		a.mu.Unlock()
		s.HasKey = a.store.exists()
		writeJSON(w, 200, s)
	})
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		c := configResp{
			ExpectedCountry: "RU", TimeoutMs: 8000,
			Proxied: []probeCfg{{"country.is", "https://api.country.is/"}, {"ipwho.is", "https://ipwho.is/"}},
			Direct:  probeCfg{"ipify", "/api/direct-ip"},
		}
		// Test only: lets a foreign test server be checked end to end. The check itself stays real
		// (the exit country must equal this value, otherwise the connection is refused); the default is RU.
		if cc := strings.ToUpper(os.Getenv("RUNET_EXPECTED_COUNTRY")); len(cc) == 2 && cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' && cc[1] <= 'Z' {
			c.ExpectedCountry = cc
		}
		if a.probeOverride != "" { // test only
			c.Proxied = []probeCfg{{"country.is", a.probeOverride}}
		}
		writeJSON(w, 200, c)
	})
	mux.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Key      string `json:"key"`
			Remember bool   `json:"remember"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"code": "bad", "message": "Некорректный запрос."})
			return
		}
		code, msg := a.connect(body.Key, body.Remember)
		if code != "" {
			status := 400
			if code == "core" {
				status = 500
			}
			writeJSON(w, status, map[string]string{"code": code, "message": msg})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		a.disconnect()
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/forget", func(w http.ResponseWriter, r *http.Request) {
		a.store.remove()
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// The reference "ordinary connection" address, fetched by the launcher WITHOUT any proxy.
	// Inside the browser window everything is proxied, so only we can see it.
	mux.HandleFunc("/api/direct-ip", func(w http.ResponseWriter, r *http.Request) {
		ip, err := directIP()
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": "unavailable"})
			return
		}
		writeJSON(w, 200, map[string]string{"ip": ip})
	})

	wantHost := fmt.Sprintf("127.0.0.1:%d", srvPort)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != wantHost {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/" {
			if t := r.URL.Query().Get("t"); t != "" {
				if subtle.ConstantTimeCompare([]byte(t), []byte(a.token)) == 1 {
					http.SetCookie(w, &http.Cookie{Name: "rt", Value: a.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
					http.Redirect(w, r, "/", http.StatusFound) // drop the token from the address bar
					return
				}
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		c, err := r.Cookie("rt")
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(a.token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method == http.MethodPost && r.Header.Get("X-Runet") != "1" {
			http.Error(w, "forbidden", http.StatusForbidden) // custom header: cannot be sent cross-site without CORS
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' https: http:; img-src 'self' data:; frame-ancestors 'none'")
		mux.ServeHTTP(w, r)
	})
}

// directIP asks a public service for the address of the ordinary (non-proxied) connection.
func directIP() (string, error) {
	cl := &http.Client{
		Timeout:   8 * time.Second,
		Transport: &http.Transport{Proxy: nil}, // never the proxy, never the environment
	}
	resp, err := cl.Get("https://api.ipify.org/?format=json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var v struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&v); err != nil {
		return "", err
	}
	if net.ParseIP(v.IP) == nil {
		return "", fmt.Errorf("bad address")
	}
	return v.IP, nil
}
