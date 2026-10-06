// Package dynkey resolves Outline dynamic access keys (ssconf://) into a connection profile.
//
// Outline's rule: ssconf://host/path?query#name stands for the HTTPS address https://host/path?query; the
// page returns the real key (an ss:// link, the JSON {server, server_port, password, method} or, in newer
// clients, a YAML transport description). The page is DATA: nothing in it is executed and it cannot
// change our routing rules; only the few parameters we understand are read and everything else is refused
// by name, never silently dropped.
//
// The fetch is done here, by the launcher process, not by the browser page (no CORS), and BEFORE the tunnel
// exists. It is deliberately strict:
//   - HTTPS only, certificate verified (never relaxed), TLS 1.2 or newer;
//   - one overall time limit, a response size limit, a redirect limit;
//   - the destination and every redirect target must be a public address: loopback, private, link-local,
//     carrier-grade NAT, multicast, unspecified and "service" names (localhost, *.local, single labels, ...)
//     are refused, and the check is made on the address that is actually dialled (no DNS-rebinding gap);
//   - no proxy, no cookies, no credentials in the address.
//
// The address of a dynamic key, its path and query ARE the secret. They are never put into an error, a
// message or a command line: every failure is classified into a fixed Russian sentence.
package dynkey

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"runetaccess/internal/config"
	"runetaccess/internal/keyparse"
)

// Options tune the fetch. The zero value is the production configuration.
type Options struct {
	Timeout      time.Duration // whole request including redirects (default 15 s)
	MaxBytes     int64         // response size limit (default 64 KiB)
	MaxRedirects int           // default 3

	// Tests only (the launcher sets them in test mode and nowhere else):
	AllowLoopback bool                                                     // lets 127.0.0.0/8 and ::1 through
	RootCAs       *x509.CertPool                                           // extra trust anchors for a local HTTPS stand-in
	Lookup        func(ctx context.Context, host string) ([]net.IP, error) // resolver
}

func (o *Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return 15 * time.Second
}

func (o *Options) maxBytes() int64 {
	if o.MaxBytes > 0 {
		return o.MaxBytes
	}
	return 64 << 10
}

func (o *Options) maxRedirects() int {
	if o.MaxRedirects > 0 {
		return o.MaxRedirects
	}
	return 3
}

var (
	errBlocked   = errors.New("destination is not a public address")
	errDowngrade = errors.New("redirect to a non-https address")
	errTooMany   = errors.New("too many redirects")
	errNoAddr    = errors.New("no address")
)

func fetchFail(code, reason string) *keyparse.Error {
	return keyparse.Fail("fetch-"+code, "Не удалось загрузить настройки ключа: "+reason+".")
}

// blockedIP reports addresses a dynamic key must never be fetched from.
func blockedIP(ip net.IP, allowLoopback bool) bool {
	if allowLoopback && ip.IsLoopback() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		switch {
		case ip4[0] == 0, // 0.0.0.0/8
			ip4[0] == 100 && ip4[1]&0xC0 == 64,              // 100.64.0.0/10 carrier-grade NAT
			ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0,     // 192.0.0.0/24
			ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19), // 198.18.0.0/15
			ip4[0] >= 240: // reserved and broadcast
			return true
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

var serviceSuffixes = []string{".local", ".localhost", ".localdomain", ".lan", ".home", ".home.arpa", ".internal", ".intranet", ".corp", ".private", ".test", ".invalid", ".example"}

// checkURL applies the rules to an address (the starting one and every redirect target).
func (o *Options) checkURL(u *url.URL) error {
	if u.Scheme != "https" {
		return errDowngrade
	}
	if u.User != nil || u.Hostname() == "" {
		return errBlocked
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if ip := net.ParseIP(host); ip != nil {
		if blockedIP(ip, o.AllowLoopback) {
			return errBlocked
		}
		return nil
	}
	if o.AllowLoopback && host == "localhost" {
		return nil
	}
	if host == "localhost" || !strings.Contains(host, ".") {
		return errBlocked
	}
	for _, suf := range serviceSuffixes {
		if strings.HasSuffix(host, suf) {
			return errBlocked
		}
	}
	return nil
}

// URL turns an ssconf:// key into the HTTPS address it stands for and checks it.
func URL(raw string) (*url.URL, *keyparse.Error) {
	text, kerr := keyparse.Clean(raw)
	if kerr != nil {
		return nil, kerr
	}
	if len(text) < 9 || !strings.EqualFold(text[:9], "ssconf://") {
		return nil, keyparse.Fail("scheme", keyparse.UnknownFormatMsg)
	}
	u, err := url.Parse("https://" + text[9:])
	if err != nil || u.Hostname() == "" {
		return nil, keyparse.Fail("broken", "Ключ повреждён или скопирован не целиком. Скопируйте его из бота ещё раз.")
	}
	return u, nil
}

func (o *Options) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else if o.Lookup != nil {
		if ips, err = o.Lookup(ctx, host); err != nil {
			return nil, err
		}
	} else {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		return nil, errNoAddr
	}
	for _, ip := range ips { // one bad answer refuses the name: no mixing of public and internal addresses
		if blockedIP(ip, o.AllowLoopback) {
			return nil, errBlocked
		}
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	var last error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// Fetch downloads the settings of a dynamic key.
func Fetch(ctx context.Context, raw string, o Options) ([]byte, *keyparse.Error) {
	u, kerr := URL(raw)
	if kerr != nil {
		return nil, kerr
	}
	if err := o.checkURL(u); err != nil {
		return nil, classify(err)
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout())
	defer cancel()

	tr := &http.Transport{
		DialContext:            o.dial,
		Proxy:                  nil, // before the tunnel exists, and never through a proxy picked up from the environment
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.RootCAs},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  12 * time.Second,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: 16 << 10,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > o.maxRedirects() {
				return errTooMany
			}
			return o.checkURL(req.URL)
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fetchFail("net", "адрес настроек некорректен")
	}
	req.Header.Set("User-Agent", "RunetAccess")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, classify(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fetchFail("http", "сервер настроек ответил кодом "+strconv.Itoa(resp.StatusCode))
	}
	if resp.ContentLength > o.maxBytes() {
		return nil, fetchFail("size", "ответ сервера настроек слишком большой")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, o.maxBytes()+1))
	if err != nil {
		return nil, classify(err)
	}
	if int64(len(body)) > o.maxBytes() {
		return nil, fetchFail("size", "ответ сервера настроек слишком большой")
	}
	return body, nil
}

// classify maps a transport error to a fixed sentence. It never uses err.Error(): that text contains the
// address of the request, which is a secret.
func classify(err error) *keyparse.Error {
	var cert x509.UnknownAuthorityError
	var certInv x509.CertificateInvalidError
	var host x509.HostnameError
	var dnsErr *net.DNSError
	var verify *tls.CertificateVerificationError
	var netErr net.Error
	switch {
	case errors.Is(err, errBlocked):
		return fetchFail("blocked", "адрес настроек указывает на локальную или служебную сеть, это запрещено")
	case errors.Is(err, errDowngrade):
		return fetchFail("downgrade", "перенаправление на незащищённый адрес (HTTP) отклонено")
	case errors.Is(err, errTooMany):
		return fetchFail("redirect", "слишком много перенаправлений")
	case errors.Is(err, context.DeadlineExceeded):
		return fetchFail("timeout", "время ожидания истекло")
	case errors.As(err, &cert), errors.As(err, &certInv), errors.As(err, &host), errors.As(err, &verify):
		return fetchFail("tls", "сертификат HTTPS сервера настроек не принят (проверка сертификата не отключается)")
	case errors.As(err, &dnsErr):
		return fetchFail("dns", "не удалось найти сервер настроек")
	case errors.As(err, &netErr) && netErr.Timeout():
		return fetchFail("timeout", "время ожидания истекло")
	case errors.Is(err, context.Canceled):
		return fetchFail("cancelled", "загрузка отменена")
	}
	return fetchFail("net", "не удалось подключиться к серверу настроек")
}

// Resolve fetches and interprets a dynamic key.
func Resolve(ctx context.Context, raw string, o Options) (*config.Profile, *keyparse.Error) {
	body, kerr := Fetch(ctx, raw, o)
	if kerr != nil {
		return nil, kerr
	}
	return Interpret(body)
}
