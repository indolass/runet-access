package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidSiteURL(t *testing.T) {
	good := map[string]string{
		"https://www.gosuslugi.ru/":   "https://www.gosuslugi.ru/",
		"http://minjust.gov.ru/a?b=1": "http://minjust.gov.ru/a?b=1",
	}
	for in, want := range good {
		if got, bad := validSiteURL(in); bad != "" || got != want {
			t.Errorf("%q: got %q %q", in, got, bad)
		}
	}
	for _, in := range []string{"", "   ", "file:///c:/x", "javascript:alert(1)", "https://user:pw@nalog.gov.ru/",
		"https://localhost/", "https://127.0.0.1:8080/", "https://[::1]/", "https://intranet/", "ftp://a.ru/", "mailto:a@b.ru",
		"https://x.localhost/", "https://0.0.0.0/", "chrome://settings", "https://a.ru/" + strings.Repeat("x", 3000)} {
		if got, bad := validSiteURL(in); bad == "" {
			t.Errorf("%q must be refused, got %q", in, got)
		}
	}
}

func TestExternalLinksAreExactlyTheAgreedOnes(t *testing.T) {
	want := map[string]string{
		"bot-ussr":  "https://t.me/BackInTheUSSR_bot",
		"bot-hlvpn": "https://t.me/hlvpnbot",
		"thanks":    "https://t.me/W3_accelerators_GK",
	}
	if len(externalLinks) != len(want) {
		t.Fatalf("list size changed: %d", len(externalLinks))
	}
	for k, v := range want {
		if externalLinks[k] != v {
			t.Errorf("%s: %q", k, externalLinks[k])
		}
	}
}

func testApp(t *testing.T) *app {
	t.Helper()
	return &app{store: keyStore{path: filepath.Join(t.TempDir(), "key.dpapi")}, phase: phaseIdle}
}

// A typed key is saved only after a positive verdict for the CURRENT epoch of a live connection.
func TestVerdictCommitsTheKeyOnlyAfterVerification(t *testing.T) {
	a := testApp(t)
	a.phase, a.epoch, a.curKey, a.pendingKey, a.pendingRem = phaseConnected, 3, "vless://new", "vless://new", true

	a.verdict(true, 2) // stale epoch
	if a.store.exists() || a.confirmed {
		t.Fatal("a verdict about an older epoch must be ignored")
	}
	a.verdict(false, 3)
	if a.store.exists() || a.confirmed {
		t.Fatal("a negative verdict must not save or confirm")
	}
	a.verdict(true, 3)
	if !a.confirmed || !a.store.exists() || a.pendingKey != "" || a.goodKey != "vless://new" {
		t.Fatalf("positive verdict: confirmed=%v saved=%v pending=%q good=%q", a.confirmed, a.store.exists(), a.pendingKey, a.goodKey)
	}
	if got, _ := a.store.load(); got != "vless://new" {
		t.Fatal("stored key differs")
	}
	a.verdict(false, 3)
	if a.confirmed {
		t.Fatal("a later negative verdict must clear the confirmation")
	}
}

func TestVerdictIgnoredWhenNotConnected(t *testing.T) {
	a := testApp(t)
	a.phase, a.epoch, a.pendingKey, a.pendingRem = phaseIdle, 1, "vless://x", true
	a.verdict(true, 1)
	if a.confirmed || a.store.exists() {
		t.Fatal("verdict must not count without a live connection")
	}
}

func TestOpenSiteNeedsVerifiedExit(t *testing.T) {
	a := testApp(t)
	a.phase = phaseConnected
	if code, _ := a.openSite("https://nalog.gov.ru/"); code != "not-confirmed" {
		t.Fatalf("code %q", code)
	}
}

func apiCall(t *testing.T, a *app, method, path, body string, withHeader bool) *httptest.ResponseRecorder {
	t.Helper()
	h := a.routes(4321)
	r := httptest.NewRequest(method, "http://127.0.0.1:4321"+path, strings.NewReader(body))
	r.Host = "127.0.0.1:4321"
	r.AddCookie(&http.Cookie{Name: "rt", Value: a.token})
	if withHeader {
		r.Header.Set("X-Runet", "1")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestOpenExternalOnlyOpensFixedIDs(t *testing.T) {
	a := testApp(t)
	a.token = "tok"
	var opened []string
	a.openExternal = func(u string) error { opened = append(opened, u); return nil }

	if w := apiCall(t, a, "POST", "/api/open-external", `{"id":"bot-ussr"}`, true); w.Code != 200 || len(opened) != 1 || opened[0] != "https://t.me/BackInTheUSSR_bot" {
		t.Fatalf("known id: %d %v", w.Code, opened)
	}
	for _, body := range []string{`{"id":"https://evil.example/"}`, `{"id":"../x"}`, `{"id":""}`, `{"url":"https://evil.example/"}`, `{"id":"BOT-USSR"}`} {
		if w := apiCall(t, a, "POST", "/api/open-external", body, true); w.Code == 200 {
			t.Errorf("must refuse %s", body)
		}
	}
	if len(opened) != 1 {
		t.Fatalf("something else was opened: %v", opened)
	}
	if w := apiCall(t, a, "POST", "/api/open-external", `{"id":"bot-ussr"}`, false); w.Code != 403 {
		t.Errorf("a call without the custom header must be refused, got %d", w.Code)
	}
	if w := apiCall(t, a, "GET", "/api/open-external", ``, true); w.Code != 403 {
		t.Errorf("GET must be refused, got %d", w.Code)
	}
	if len(opened) != 1 {
		t.Fatalf("refused calls opened something: %v", opened)
	}
}

func TestStateChangingCallsNeedPostAndHeader(t *testing.T) {
	a := testApp(t)
	a.token = "tok"
	for _, p := range []string{"/api/disconnect", "/api/forget", "/api/verdict", "/api/connect", "/api/open-site"} {
		if w := apiCall(t, a, "GET", p, "", true); w.Code != 403 {
			t.Errorf("GET %s: %d", p, w.Code)
		}
		if w := apiCall(t, a, "POST", p, "{}", false); w.Code != 403 {
			t.Errorf("POST %s without header: %d", p, w.Code)
		}
	}
	if w := apiCall(t, a, "GET", "/api/state", "", false); w.Code != 200 {
		t.Errorf("state: %d", w.Code)
	}
}

func TestFirstChromeNeedsARealChromeExe(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "Application", "chrome.exe")
	if err := os.MkdirAll(filepath.Dir(good), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "notchrome.exe")
	_ = os.WriteFile(other, []byte("x"), 0o644)
	folder := filepath.Join(dir, "chrome.exe") // a folder named chrome.exe is not a browser
	_ = os.MkdirAll(folder, 0o755)

	if got := firstChrome([]string{filepath.Join(dir, "missing", "chrome.exe"), other, folder, `"` + good + `"`}); got != good {
		t.Fatalf("got %q", got)
	}
	if got := firstChrome([]string{other, folder}); got != "" {
		t.Fatalf("must find nothing, got %q", got)
	}
}

func TestChromeTestOverrideDoesNotFallBack(t *testing.T) {
	t.Setenv("RUNET_CHROME_PATH", filepath.Join(t.TempDir(), "nope", "chrome.exe"))
	if findChrome() != "" {
		t.Fatal("an override pointing nowhere must mean 'no Chrome', not the installed one")
	}
}

func TestWaitForChromeAsksThenLetsTheUserOut(t *testing.T) {
	t.Setenv("RUNET_CHROME_PATH", filepath.Join(t.TempDir(), "nope", "chrome.exe"))
	t.Setenv("RUNET_TEST_CHROME_PROMPT", "open,recheck,close")
	scriptPos = 0
	var opened []string
	if got := waitForChrome(func(u string) error { opened = append(opened, u); return nil }); got != "" {
		t.Fatalf("closing the window must return empty, got %q", got)
	}
	if len(opened) != 1 || opened[0] != "https://www.google.com/chrome/" {
		t.Fatalf("the official page must be opened exactly once: %v", opened)
	}
}
