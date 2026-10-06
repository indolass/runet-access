package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A tiny fake "installer": starts with MZ, big enough to pass the sanity checks.
func fakeExe() []byte { return append([]byte("MZ"), bytes.Repeat([]byte{0x90}, 100<<10)...) }

type rig struct {
	srv     *httptest.Server
	hits    int32
	d       installDeps
	runs    int32
	verifs  int32
	tmp     string
	stages  []string
	detects int32
}

// newRig starts a TLS server standing in for Google's host; the allow-list is that host only.
func newRig(t *testing.T, h http.HandlerFunc) *rig {
	t.Helper()
	r := &rig{tmp: t.TempDir()}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&r.hits, 1)
		h(w, req)
	}))
	t.Cleanup(r.srv.Close)
	u, _ := url.Parse(r.srv.URL)
	r.d = installDeps{
		client: r.srv.Client(), url: r.srv.URL + "/ChromeSetup.exe", allowedHosts: []string{u.Hostname()}, tempBase: r.tmp,
		verify: func(string) (string, error) { atomic.AddInt32(&r.verifs, 1); return "Google LLC", nil },
		run:    func(context.Context, string) (uint32, error) { atomic.AddInt32(&r.runs, 1); return 0, nil },
		detect: func() string { atomic.AddInt32(&r.detects, 1); return "" },
		stage:  func(s string) { r.stages = append(r.stages, s) },
		wait:   300 * time.Millisecond, poll: 20 * time.Millisecond,
	}
	return r
}

func serveExe(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-msdos-program")
	_, _ = w.Write(fakeExe())
}

func leftovers(t *testing.T, dir string) int {
	t.Helper()
	es, _ := os.ReadDir(dir)
	return len(es)
}

func TestInstallHappyPath(t *testing.T) {
	r := newRig(t, serveExe)
	chromeAppears := int32(0)
	r.d.detect = func() string {
		if atomic.LoadInt32(&chromeAppears) == 1 {
			return `C:\Chrome\chrome.exe`
		}
		return ""
	}
	r.d.run = func(context.Context, string) (uint32, error) {
		atomic.AddInt32(&r.runs, 1)
		atomic.StoreInt32(&chromeAppears, 1)
		return 0, nil
	}
	p, err := installChrome(context.Background(), r.d)
	if err != nil || p != `C:\Chrome\chrome.exe` {
		t.Fatalf("got %q %v", p, err)
	}
	if r.runs != 1 || r.verifs != 1 {
		t.Fatalf("runs %d verifs %d", r.runs, r.verifs)
	}
	if n := leftovers(t, r.tmp); n != 0 {
		t.Fatalf("the downloaded installer was left behind (%d entries)", n)
	}
	if !strings.Contains(strings.Join(r.stages, "|"), "подпись") {
		t.Fatalf("no progress about the signature check: %v", r.stages)
	}
}

func TestInstalledChromeIsNeverReinstalled(t *testing.T) {
	r := newRig(t, serveExe)
	r.d.detect = func() string { return `C:\Chrome\chrome.exe` }
	if p, err := installChrome(context.Background(), r.d); err != nil || p == "" {
		t.Fatalf("%q %v", p, err)
	}
	if r.hits != 0 || r.runs != 0 {
		t.Fatalf("an installed Chrome triggered a download (%d) or a run (%d)", r.hits, r.runs)
	}
}

func TestChromeThatAppearsDuringDownloadIsNotInstalledOver(t *testing.T) {
	r := newRig(t, serveExe)
	n := int32(0)
	r.d.detect = func() string {
		if atomic.AddInt32(&n, 1) >= 2 {
			return `C:\Chrome\chrome.exe`
		}
		return ""
	}
	if p, err := installChrome(context.Background(), r.d); err != nil || p == "" {
		t.Fatalf("%q %v", p, err)
	}
	if r.runs != 0 {
		t.Fatal("the installer was started although Chrome had appeared")
	}
}

func TestBadSignatureIsNeverRun(t *testing.T) {
	r := newRig(t, serveExe)
	r.d.verify = func(string) (string, error) { return "Someone Else Ltd", errors.New("подписано не Google") }
	_, err := installChrome(context.Background(), r.d)
	if err == nil || err.Kind != failSignature {
		t.Fatalf("got %v", err)
	}
	if r.runs != 0 {
		t.Fatal("an unverified file was started")
	}
	if n := leftovers(t, r.tmp); n != 0 {
		t.Fatalf("the rejected file stays on disk (%d)", n)
	}
	if !strings.Contains(err.Msg, "удалён") {
		t.Fatalf("message must say the file was removed: %s", err.Msg)
	}
	for _, need := range []string{"Источник: 127.0.0.1", "Ответ сервера: 200", "application/x-msdos-program", "Скачано байт:", "SHA-256 файла:", "Someone Else Ltd"} {
		if !strings.Contains(err.Details, need) {
			t.Errorf("details lack %q: %s", need, err.Details)
		}
	}
	if len(err.Msg) > 120 {
		t.Errorf("the user-facing message must stay short, got %d characters", len(err.Msg))
	}
}

func TestDownloadProblemsAreDownloadErrors(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"404": func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) },
		"html instead of the program": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write(fakeExe())
		},
		"not a Windows program": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(bytes.Repeat([]byte("A"), 100<<10))
		},
		"too small": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("MZ tiny")) },
		"huge": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "400000000")
			w.WriteHeader(200)
		},
	}
	for name, h := range cases {
		r := newRig(t, h)
		_, err := installChrome(context.Background(), r.d)
		if err == nil || err.Kind != failDownload {
			t.Errorf("%s: got %v", name, err)
		}
		if r.runs != 0 || r.verifs != 0 {
			t.Errorf("%s: later steps ran", name)
		}
		if n := leftovers(t, r.tmp); n != 0 {
			t.Errorf("%s: leftovers %d", name, n)
		}
	}
}

func TestOnlyOfficialHostsAndHTTPS(t *testing.T) {
	r := newRig(t, serveExe)
	for _, bad := range []string{
		"https://evil.example/ChromeSetup.exe", "http://dl.google.com/ChromeSetup.exe", "https://dl.google.com.evil.example/x.exe",
		"https://user:pw@dl.google.com/x.exe", "ftp://dl.google.com/x.exe", "file:///C:/x.exe",
	} {
		d := r.d
		d.url, d.allowedHosts = bad, []string{"dl.google.com"}
		if _, _, _, err := downloadInstaller(context.Background(), &d); err == nil {
			t.Errorf("must refuse %s", bad)
		}
	}
	if r.hits != 0 {
		t.Fatal("a refused address was contacted")
	}
}

func TestRedirectToAForeignHostIsRefused(t *testing.T) {
	r := newRig(t, func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "https://evil.example/ChromeSetup.exe", http.StatusFound)
	})
	_, err := installChrome(context.Background(), r.d)
	if err == nil || err.Kind != failDownload {
		t.Fatalf("got %v", err)
	}
	if r.runs != 0 {
		t.Fatal("ran")
	}
}

func TestRedirectOnTheSameHostIsFollowed(t *testing.T) {
	r := newRig(t, nil)
	r.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/ChromeSetup.exe" {
			http.Redirect(w, req, "/real/ChromeSetup.exe", http.StatusFound)
			return
		}
		serveExe(w, req)
	})
	if _, _, _, err := downloadInstaller(context.Background(), &r.d); err != nil {
		t.Fatalf("%v", err)
	}
}

func TestPermissionDeniedIsExplained(t *testing.T) {
	r := newRig(t, serveExe)
	r.d.run = func(context.Context, string) (uint32, error) { return 0, errDenied }
	_, err := installChrome(context.Background(), r.d)
	if err == nil || err.Kind != failDenied || !strings.Contains(err.Msg, "администратор") || !strings.Contains(err.Msg, "Повторите") {
		t.Fatalf("got %v", err)
	}
	if n := leftovers(t, r.tmp); n != 0 {
		t.Fatalf("leftovers %d", n)
	}
}

func TestCancelDuringDownload(t *testing.T) {
	r := newRig(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/x-msdos-program")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-req.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err := installChrome(ctx, r.d)
	if err == nil || err.Kind != failCancelled {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("cancel was slow")
	}
	if n := leftovers(t, r.tmp); n != 0 {
		t.Fatalf("leftovers %d", n)
	}
}

func TestCancelWhileTheInstallerRunsDoesNotKillIt(t *testing.T) {
	r := newRig(t, serveExe)
	ctx, cancel := context.WithCancel(context.Background())
	r.d.run = func(c context.Context, _ string) (uint32, error) { cancel(); <-c.Done(); return 0, c.Err() }
	_, err := installChrome(ctx, r.d)
	if err == nil || err.Kind != failCancelled || !strings.Contains(err.Msg, "Проверить снова") {
		t.Fatalf("got %v", err)
	}
}

func TestInstallerEndsWithoutChrome(t *testing.T) {
	r := newRig(t, serveExe)
	r.d.run = func(context.Context, string) (uint32, error) { return 3, nil }
	_, err := installChrome(context.Background(), r.d)
	if err == nil || err.Kind != failInstaller || !strings.Contains(err.Msg, "3") {
		t.Fatalf("got %v", err)
	}
	r2 := newRig(t, serveExe)
	_, err = installChrome(context.Background(), r2.d)
	if err == nil || err.Kind != failNotFound {
		t.Fatalf("got %v", err)
	}
}

func TestChromeShowsUpAfterTheInstallerProcessEnded(t *testing.T) {
	r := newRig(t, serveExe)
	r.d.wait = 2 * time.Second
	var started atomic.Value
	r.d.run = func(context.Context, string) (uint32, error) { started.Store(time.Now()); return 0, nil }
	r.d.detect = func() string {
		if st, ok := started.Load().(time.Time); ok && time.Since(st) > 150*time.Millisecond {
			return `C:\Chrome\chrome.exe`
		}
		return ""
	}
	p, err := installChrome(context.Background(), r.d)
	if err != nil || p == "" {
		t.Fatalf("got %q %v", p, err)
	}
}
