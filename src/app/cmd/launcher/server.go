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
	Phase     string `json:"phase"`
	Error     string `json:"error,omitempty"`
	Saved     bool   `json:"saved"`      // a key is stored (encrypted) on this computer
	Memory    bool   `json:"memory"`     // a verified key is held in memory for this run only
	Epoch     int    `json:"epoch"`      // changes whenever the core (re)starts
	Confirmed bool   `json:"confirmed"`  // the exit was verified for this epoch
	Restart   bool   `json:"restarting"` // the core is being restarted after a crash
	Version   string `json:"version"`
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
	RecheckMs       int        `json:"recheckMs"`
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
		s := stateResp{Phase: a.phase, Error: a.errMsg, Version: version, Epoch: a.epoch, Confirmed: a.confirmed, Restart: a.restarting, Memory: a.goodKey != ""}
		a.mu.Unlock()
		s.Saved = a.store.exists()
		writeJSON(w, 200, s)
	})
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		c := configResp{
			ExpectedCountry: "RU", TimeoutMs: 8000, RecheckMs: 60000,
			Proxied: []probeCfg{{"country.is", "https://api.country.is/"}, {"ipwho.is", "https://ipwho.is/"}},
			Direct:  probeCfg{"ipify", "/api/direct-ip"},
		}
		// Test only: lets a foreign test server be checked end to end. The check itself stays real
		// (the exit country must equal this value, otherwise the connection is refused); the default is RU.
		if cc := strings.ToUpper(os.Getenv("RUNET_EXPECTED_COUNTRY")); len(cc) == 2 && cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' && cc[1] <= 'Z' {
			c.ExpectedCountry = cc
		}
		if a.recheckMs > 0 { // test only
			c.RecheckMs = a.recheckMs
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
		epoch, code, msg := a.connect(body.Key, body.Remember)
		if code != "" {
			status := 400
			switch code {
			case "core":
				status = 500
			case "server":
				status = 502
			case "cancelled":
				status = 409
			}
			writeJSON(w, status, map[string]string{"code": code, "message": msg})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "epoch": epoch})
	})
	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		a.disconnect()
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// The page reports whether the exit check for a given epoch passed (see app.verdict).
	mux.HandleFunc("/api/verdict", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			OK    bool `json:"ok"`
			Epoch int  `json:"epoch"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 512)).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"code": "bad", "message": "Некорректный запрос."})
			return
		}
		a.verdict(body.OK, body.Epoch)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/reach", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]bool{"reachable": a.reachable()})
	})
	mux.HandleFunc("/api/forget", func(w http.ResponseWriter, r *http.Request) {
		a.store.remove()
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// New tab of the special browser, only after a verified exit.
	mux.HandleFunc("/api/open-site", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"code": "bad", "message": "Некорректный запрос."})
			return
		}
		if code, msg := a.openSite(body.URL); code != "" {
			status := 400
			if code == "not-confirmed" {
				status = 409
			}
			writeJSON(w, status, map[string]string{"code": code, "message": msg})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// Help links that must work BEFORE connecting (the window itself has no internet then):
	// the page names an entry of the fixed list, Windows opens it in the user's default browser.
	mux.HandleFunc("/api/open-external", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 512)).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"code": "bad", "message": "Некорректный запрос."})
			return
		}
		target, ok := externalLinks[body.ID]
		if !ok {
			writeJSON(w, 404, map[string]string{"code": "unknown", "message": "Неизвестная ссылка."})
			return
		}
		if err := a.openExternal(target); err != nil {
			writeJSON(w, 500, map[string]string{"code": "launch", "message": "Не удалось открыть ссылку. Скопируйте её и откройте вручную."})
			return
		}
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
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// State-changing calls must be POSTs carrying a custom header: a foreign page cannot
			// send that without CORS. Reads are plain GETs.
			readOnly := r.Method == http.MethodGet && (r.URL.Path == "/api/state" || r.URL.Path == "/api/config" || r.URL.Path == "/api/reach" || r.URL.Path == "/api/direct-ip")
			if !readOnly && (r.Method != http.MethodPost || r.Header.Get("X-Runet") != "1") {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' https: http:; img-src 'self' data:; frame-ancestors 'none'")
		mux.ServeHTTP(w, r)
	})
}

// directIP asks a public service for the address of the ordinary (non-proxied) connection.
func directIP() (string, error) {
	// Test only: a fixed reference, so an external service cannot make a test flaky.
	if v := os.Getenv("RUNET_DIRECT_IP"); net.ParseIP(v) != nil {
		return v, nil
	}
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
