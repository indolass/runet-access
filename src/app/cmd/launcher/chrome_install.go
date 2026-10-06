package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Installing Google Chrome for a user who has none. Everything here is deliberately plain:
//   - the installer comes only from Google's download host over HTTPS (every redirect is checked too);
//   - it is run only after Windows confirms a valid Authenticode signature whose signer is "Google LLC";
//   - it is run exactly as Google ships it, with NO arguments: no silent mode, no hidden acceptance of
//     Google's terms, Windows' own prompts (UAC) are answered by the user;
//   - an existing Chrome is never reinstalled (detection runs before the download and before the launch);
//   - afterwards Chrome is looked for again and the program simply continues.
// This file holds the logic with injectable parts (tests use fakes); the Windows parts are in
// authenticode_windows.go, shellrun_windows.go and the dialogs in chrome_prompt_windows.go.

const (
	// Google's own tagged installer link: 64-bit stable, Russian, statistics off by default.
	chromeInstallerURL  = "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26lang%3Dru%26browser%3D4%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_0%26installdataindex%3Dempty/update2/installers/ChromeSetup.exe"
	chromeInstallerHost = "dl.google.com"
	chromeSignerOrg     = "Google LLC"
	maxInstallerBytes   = 300 << 20
)

type installKind int

const (
	failDownload  installKind = iota + 1 // could not fetch the file
	failSignature                        // the file is not signed by Google: never run
	failDenied                           // Windows did not get permission (UAC refused / admin needed)
	failInstaller                        // the installer ended without a result
	failNotFound                         // it ended, Chrome still not found
	failCancelled                        // the user cancelled
)

type installError struct {
	Kind    installKind
	Msg     string // short, for the user
	Details string // technical facts for the expandable section (no key, no personal data)
}

func (e *installError) Error() string { return e.Msg }

// errDenied is returned by a runner when Windows refused to start the installer (user declined the
// elevation prompt or no rights).
var errDenied = errors.New("windows did not allow the installer to start")

type installDeps struct {
	client            *http.Client
	url               string
	allowedHosts      []string
	allowLoopbackHTTP bool // tests only
	tempBase          string
	verify            func(path string) (publisher string, err error)        // nil = skip (tests)
	run               func(ctx context.Context, path string) (uint32, error) // starts and waits
	detect            func() string
	stage             func(text string)
	wait              time.Duration // how long to wait for Chrome to appear after the installer ends
	poll              time.Duration
}

func (d *installDeps) say(s string) {
	if d.stage != nil {
		d.stage(s)
	}
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// checkInstallerURL allows only https on an allowed host (http on loopback in tests).
func (d *installDeps) checkInstallerURL(u *url.URL) error {
	host := strings.ToLower(u.Hostname())
	if u.User != nil {
		return fmt.Errorf("address with credentials")
	}
	ok := false
	for _, h := range d.allowedHosts {
		if host == strings.ToLower(h) {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("host %q is not an official Google download host", host)
	}
	if u.Scheme == "https" || (d.allowLoopbackHTTP && u.Scheme == "http" && isLoopbackHost(host)) {
		return nil
	}
	return fmt.Errorf("the address must be https")
}

// dlInfo records what the download actually was, for the details section.
type dlInfo struct {
	FinalURL    string
	Status      string
	ContentType string
	Bytes       int64
	SHA256      string
}

func (i dlInfo) lines() string {
	var b strings.Builder
	if u, err := url.Parse(i.FinalURL); err == nil && i.FinalURL != "" {
		name := u.Path
		if k := strings.LastIndex(name, "/"); k >= 0 {
			name = name[k+1:]
		}
		fmt.Fprintf(&b, "Источник: %s, %s\n", u.Hostname(), u.Scheme)
		fmt.Fprintf(&b, "Конечный адрес: %s/…/%s\n", u.Host, name)
	}
	if i.Status != "" {
		fmt.Fprintf(&b, "Ответ сервера: %s\n", i.Status)
	}
	if i.ContentType != "" {
		fmt.Fprintf(&b, "Тип содержимого: %s\n", i.ContentType)
	}
	if i.Bytes > 0 {
		fmt.Fprintf(&b, "Скачано байт: %d\n", i.Bytes)
	}
	if i.SHA256 != "" {
		if len(i.SHA256) == 64 {
			fmt.Fprintf(&b, "SHA-256 файла: %s\n%s\n", i.SHA256[:32], i.SHA256[32:])
		} else {
			fmt.Fprintf(&b, "SHA-256 файла: %s\n", i.SHA256)
		}
	}
	return b.String()
}

// downloadInstaller fetches the installer into a fresh private folder and returns the file and folder.
func downloadInstaller(ctx context.Context, d *installDeps) (file, dir string, info dlInfo, err error) {
	u, perr := url.Parse(d.url)
	if perr != nil {
		return "", "", info, perr
	}
	if err := d.checkInstallerURL(u); err != nil {
		return "", "", info, err
	}
	info.FinalURL = u.String()
	base := d.tempBaseOrDefault()
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", "", info, err
	}
	dir, err = os.MkdirTemp(base, "chrome-setup-")
	if err != nil {
		return "", "", info, err
	}
	fail := func(e error) (string, string, dlInfo, error) { _ = os.RemoveAll(dir); return "", "", info, e }

	client := d.client
	if client == nil {
		client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment,
			TLSHandshakeTimeout: 20 * time.Second, ResponseHeaderTimeout: 40 * time.Second}}
	}
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return d.checkInstallerURL(req.URL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fail(err)
	}
	req.Header.Set("User-Agent", "RunetAccess")
	resp, err := c.Do(req)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	info.FinalURL, info.Status, info.ContentType = resp.Request.URL.String(), resp.Status, resp.Header.Get("Content-Type")
	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("server answered %d", resp.StatusCode))
	}
	if strings.HasPrefix(strings.ToLower(info.ContentType), "text/") {
		return fail(fmt.Errorf("the server sent a web page instead of the installer"))
	}
	if resp.ContentLength > maxInstallerBytes {
		return fail(fmt.Errorf("the file is unexpectedly large"))
	}
	file = filepath.Join(dir, "ChromeSetup.exe")
	f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fail(err)
	}
	total, last := int64(0), time.Time{}
	h := sha256.New()
	buf := make([]byte, 64<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > maxInstallerBytes {
				f.Close()
				return fail(fmt.Errorf("the file is unexpectedly large"))
			}
			h.Write(buf[:n])
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				return fail(werr)
			}
			if time.Since(last) > 300*time.Millisecond {
				last = time.Now()
				if resp.ContentLength > 0 {
					d.say(fmt.Sprintf("Скачиваем установщик… %d%%", total*100/resp.ContentLength))
				} else {
					d.say(fmt.Sprintf("Скачиваем установщик… %d МБ", total>>20))
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return fail(rerr)
		}
	}
	if err := f.Close(); err != nil {
		return fail(err)
	}
	info.Bytes, info.SHA256 = total, hex.EncodeToString(h.Sum(nil))
	head := make([]byte, 2)
	if hf, err := os.Open(file); err == nil {
		_, _ = io.ReadFull(hf, head)
		hf.Close()
	}
	if total < 64<<10 || string(head) != "MZ" {
		return fail(fmt.Errorf("the downloaded file is not a Windows program"))
	}
	return file, dir, info, nil
}

// installChrome returns the path of Chrome once it is installed. It never touches a Chrome that
// is already there.
func installChrome(ctx context.Context, d installDeps) (string, *installError) {
	if p := d.detect(); p != "" {
		return p, nil
	}
	cancelled := &installError{failCancelled, "Установка отменена.", ""}
	if ctx.Err() != nil {
		return "", cancelled
	}
	d.say("Скачиваем установщик…")
	file, dir, info, err := downloadInstaller(ctx, &d)
	if err != nil {
		if ctx.Err() != nil {
			return "", cancelled
		}
		return "", &installError{failDownload, "Не удалось скачать установщик. Проверьте интернет и повторите.",
			info.lines() + "Причина: " + shortReason(err)}
	}
	defer func() {
		// our own private folder, created a moment ago: the downloaded file and nothing else
		if filepath.Dir(dir) == d.tempBaseOrDefault() && strings.HasPrefix(filepath.Base(dir), "chrome-setup-") {
			_ = os.RemoveAll(dir)
		}
	}()

	d.say("Проверяем подпись Google…")
	sigLine := "Подпись: не проверялась"
	if d.verify != nil {
		pub, verr := d.verify(file)
		if verr != nil {
			who := ""
			if pub != "" {
				who = "Издатель в подписи: " + pub + "\n"
			}
			return "", &installError{failSignature, "Скачанный файл не подписан Google. Он не запущен и удалён.",
				info.lines() + who + "Проверка подписи Windows: отказ (" + shortReason(verr) + ")\nФайл удалён, не запускался."}
		}
		sigLine = "Подпись: действительна, издатель " + pub
	}
	if p := d.detect(); p != "" { // appeared while we were downloading: do not install over it
		return p, nil
	}
	if ctx.Err() != nil {
		return "", cancelled
	}

	d.say("Запущен установщик Google. Следуйте его окнам; на вопросы Windows ответьте сами.")
	code, rerr := d.run(ctx, file)
	details := info.lines() + sigLine
	switch {
	case ctx.Err() != nil:
		return "", &installError{failCancelled, "Ожидание отменено. Если установщик Google ещё работает, дождитесь его и нажмите «Проверить снова».", details}
	case errors.Is(rerr, errDenied):
		return "", &installError{failDenied, "Windows не разрешила запуск (нужны права администратора или вы отказались). Повторите или установите вручную.", details}
	case rerr != nil:
		return "", &installError{failInstaller, "Не удалось запустить установщик. Повторите или установите вручную.", details + "\nПричина: " + shortReason(rerr)}
	}

	d.say("Ждём завершения установки…")
	wait, poll := d.wait, d.poll
	if wait == 0 {
		wait = 3 * time.Minute
	}
	if poll == 0 {
		poll = 2 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		if p := d.detect(); p != "" {
			return p, nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return "", &installError{failCancelled, "Ожидание отменено. Если установщик Google ещё работает, дождитесь его и нажмите «Проверить снова».", details}
		case <-time.After(poll):
		}
	}
	details += fmt.Sprintf("\nКод завершения установщика: %d", code)
	if code != 0 {
		return "", &installError{failInstaller, fmt.Sprintf("Установка не завершена (код %d). Повторите или установите вручную.", code), details}
	}
	return "", &installError{failNotFound, "Установщик закрылся, но Chrome пока не найден. Если установка идёт, дождитесь её и нажмите «Проверить снова».", details}
}

func (d *installDeps) tempBaseOrDefault() string {
	if d.tempBase != "" {
		return d.tempBase
	}
	return os.TempDir()
}

// shortReason keeps a technical reason short.
func shortReason(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
