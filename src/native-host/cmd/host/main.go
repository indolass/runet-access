// Command host is the MagicProxy Native Messaging host. Chrome/Brave launches it
// automatically when the extension connects; it manages a sing-box process and
// exposes a local SOCKS5+HTTP endpoint.
package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"magicproxy/internal/config"
	"magicproxy/internal/core"
	"magicproxy/internal/diag"
	"magicproxy/internal/messaging"
)

// Overridden at build time by CI: -ldflags "-X main.hostVersion=<tag>".
var hostVersion = "0.0.0-dev"

type startPayload struct {
	Profile  config.Profile `json:"profile"`
	Inbound  config.Inbound `json:"inbound"`
	Routing  config.Routing `json:"routing"`
	LogLevel string         `json:"logLevel"`
}

func main() {
	conn := messaging.NewConn(os.Stdin, os.Stdout)

	// Before anything is spawned: make the operating system responsible for
	// killing sing-box when this host dies. Stop() only covers the orderly exits.
	// Строки хоста — по-английски: это диагностика, она попадает в логи и в
	// отчёты об ошибках. Единственная строка ДЛЯ человека (подсказка про TUN)
	// имеет стабильный префикс, по которому расширение показывает её на языке
	// пользователя.
	if err := core.ConfineChildren(); err != nil {
		_ = conn.Emit("log", map[string]any{
			"level": "warn",
			"line": "MagicProxy: could not confine the core to the host process (" + err.Error() +
				"); if the host dies abnormally, sing-box may stay in memory",
		})
	}

	mgr, err := core.NewManager()
	if err != nil {
		// We can still speak the protocol; report the failure on first request.
		runWithoutCore(conn, err)
		return
	}

	// Forward sing-box logs and exit events to the extension.
	//
	// When a failure looks like another client's TUN mode capturing our own
	// outbound connection, append a plain-language explanation. The core's message
	// ("reality verification failed") is accurate but gives the user no way to
	// guess the real cause, and this is a common setup: our audience frequently
	// already runs Clash/Hiddify/v2rayN.
	hintedThisRun := false
	mgr.OnLog = func(level, line string) {
		_ = conn.Emit("log", map[string]any{"level": level, "line": line})
		if hintedThisRun || !diag.LooksLikeDoubleProxying(line) {
			return
		}
		if adapters := diag.ActiveTunnelAdapters(); len(adapters) > 0 {
			hintedThisRun = true
			// Формат зафиксирован: расширение узнаёт эту строку по префиксу
			// "MagicProxy: active TUN adapter detected (" и подменяет её
			// переводом (см. TUN_HINT_RE в service-worker.js). Менять текст —
			// только вместе с тем регулярным выражением.
			_ = conn.Emit("log", map[string]any{
				"level": "error",
				"line": "MagicProxy: active TUN adapter detected (" + strings.Join(adapters, ", ") +
					"). Another proxy client is capturing all system traffic, including our " +
					"connection to your server — double proxying breaks the handshake. Switch " +
					"that client to plain proxy mode or add your server's address to its bypass list.",
			})
		}
	}
	mgr.OnExit = func(err error) {
		payload := map[string]any{"running": false}
		if err != nil {
			payload["error"] = err.Error()
		}
		_ = conn.Emit("state", payload)
	}

	for {
		req, err := conn.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break // extension disconnected: Chrome will terminate us
			}
			break
		}
		handle(conn, mgr, req)
	}

	_ = mgr.Stop()
	// Конфиг с паролями не должен переживать процесс, который его написал.
	mgr.Cleanup()
}

func handle(conn *messaging.Conn, mgr *core.Manager, req *messaging.Request) {
	switch req.Type {
	case "ping":
		_ = conn.Respond(req.ID, map[string]any{"pong": true})

	case "version":
		_ = conn.Respond(req.ID, map[string]any{
			"host":    hostVersion,
			"singbox": mgr.Version(),
		})

	case "status":
		running, port, uptime := mgr.Status()
		_ = conn.Respond(req.ID, map[string]any{
			"running":   running,
			"port":      port,
			"uptimeSec": uptime,
		})

	case "test":
		var p struct {
			Profile config.Profile `json:"profile"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			_ = conn.RespondError(req.ID, err)
			return
		}
		cfg, err := config.Build(&p.Profile, config.Inbound{Listen: "127.0.0.1", Port: 1080}, config.Routing{}, "warn")
		if err != nil {
			_ = conn.RespondError(req.ID, err)
			return
		}
		if err := mgr.Check(cfg); err != nil {
			_ = conn.RespondError(req.ID, err)
			return
		}
		_ = conn.Respond(req.ID, map[string]any{"valid": true})

	case "start":
		var pl startPayload
		if err := json.Unmarshal(req.Payload, &pl); err != nil {
			_ = conn.RespondError(req.ID, err)
			return
		}
		// Stop any current instance first so it releases its port — otherwise
		// ResolvePort would see the requested port as taken and pick a new one.
		_ = mgr.Stop()
		// Reuse the requested port when free (stable across restarts), else pick a
		// fresh one and report it back so the extension can re-point chrome.proxy.
		port, err := core.ResolvePort(pl.Inbound.Port)
		if err != nil {
			_ = conn.RespondError(req.ID, err)
			return
		}
		listen := pl.Inbound.Listen
		if listen == "" {
			listen = "127.0.0.1"
		}
		// LogLevel was previously declared and then never used, so the level stayed
		// hardcoded at "info" — which logs every connection's hostname.
		cfg, err := config.Build(&pl.Profile, config.Inbound{Listen: listen, Port: port}, pl.Routing, pl.LogLevel)
		if err != nil {
			_ = conn.RespondError(req.ID, err)
			return
		}
		if err := mgr.Start(cfg, port); err != nil {
			_ = conn.RespondError(req.ID, err)
			return
		}
		// Answer only when the inbound really accepts connections (see WaitReady).
		if err := mgr.WaitReady(port, 15*time.Second); err != nil {
			_ = mgr.Stop()
			_ = conn.RespondError(req.ID, err)
			return
		}
		_ = conn.Respond(req.ID, map[string]any{
			"listen": listen,
			"port":   port,
			"socks":  true,
			"http":   true,
		})

	case "stop":
		if err := mgr.Stop(); err != nil {
			_ = conn.RespondError(req.ID, err)
			return
		}
		_ = conn.Respond(req.ID, map[string]any{"stopped": true})

	// runet-access: самообновление ядра отключено. Upstream качает sing-box "latest"
	// с GitHub без проверки хеша; у нас версия закреплена и проверена по SHA256
	// (scripts/tools.lock.json), обновление — только вместе с новой сборкой.
	case "checkUpdate", "updateCore":
		_ = conn.RespondError(req.ID, errors.New("core update is disabled in runet-access"))

	default:
		_ = conn.RespondError(req.ID, errors.New("unknown request type: "+req.Type))
	}
}

// runWithoutCore keeps the protocol alive but fails every actionable request
// with the initialization error (e.g. sing-box binary missing).
func runWithoutCore(conn *messaging.Conn, initErr error) {
	for {
		req, err := conn.Read()
		if err != nil {
			return
		}
		switch req.Type {
		case "ping":
			_ = conn.Respond(req.ID, map[string]any{"pong": true})
		case "version":
			_ = conn.Respond(req.ID, map[string]any{"host": hostVersion, "singbox": "unavailable"})
		default:
			_ = conn.RespondError(req.ID, initErr)
		}
	}
}
