// Shared test support: synthetic VLESS+Reality server, country-check mock, test-only extension copy.
// Everything is synthetic; no real keys. Files live under the repo-local TEMP.
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import http from "node:http";
import net from "node:net";
import { root } from "./cdp.mjs";

export const serverBox = join(root, ".local", "tools", "sing-box", "sing-box.exe");
export const MASK = "www.cloudflare.com";
export const MOCK_HOST = "mock-country.example";
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
export const portOpen = (p) => new Promise((res) => { const s = net.connect(p, "127.0.0.1"); s.once("connect", () => { s.destroy(); res(true); }); s.once("error", () => res(false)); });
export const until = async (fn, ms = 10000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await fn()) return true; await sleep(150); } return false; };

const sb = (...args) => spawnSync(serverBox, args, { encoding: "utf8" }).stdout.trim();

/** Country-check mock. state.country / state.ip are changed by the test at will. */
export async function startMock() {
  const state = { country: "RU", ip: "203.0.113.77", hits: 0, delayMs: 0, fail: false };
  const server = http.createServer((req, res) => {
    state.hits++;
    const answer = () => {
      if (state.fail) { res.writeHead(503, { "access-control-allow-origin": "*" }); res.end("down"); return; }
      res.writeHead(200, { "content-type": "application/json", "access-control-allow-origin": "*" });
      res.end(JSON.stringify({ ip: state.ip, country: state.country }));
    };
    if (state.delayMs > 0) setTimeout(answer, state.delayMs); else answer();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { state, port: server.address().port, close: () => server.close() };
}

/** Synthetic server. The host MOCK_HOST is redirected to the local mock (so the mock answers only through the tunnel). */
export async function startSyntheticServer(mockPort, reuse) {
  // `reuse` = a previous server's credentials: restarts the SAME server (same key, same port)
  const uuid = reuse ? reuse.uuid : sb("generate", "uuid");
  const kp = reuse ? reuse.kp : Object.fromEntries(sb("generate", "reality-keypair").split(/\r?\n/).map((l) => l.split(/:\s*/)));
  const sid = reuse ? reuse.sid : sb("generate", "rand", "--hex", "8");
  const port = reuse ? reuse.port : await freePort();
  const dir = mkdtempSync(join(process.env.TEMP, "synth-"));
  const cfg = join(dir, "server.json");
  writeFileSync(cfg, JSON.stringify({
    log: { level: "info", timestamp: true },
    inbounds: [{ type: "vless", listen: "127.0.0.1", listen_port: port, users: [{ uuid, flow: "xtls-rprx-vision" }],
      tls: { enabled: true, server_name: MASK, reality: { enabled: true, handshake: { server: MASK, server_port: 443 }, private_key: kp.PrivateKey, short_id: [sid] } } }],
    outbounds: [{ type: "direct", tag: "direct" }],
    route: {
      rules: [{ domain: [MOCK_HOST], action: "route", outbound: "direct", override_address: "127.0.0.1", override_port: mockPort }],
      final: "direct",
    },
  }));
  const chk = spawnSync(serverBox, ["check", "-c", cfg], { encoding: "utf8" });
  if (chk.status !== 0) throw new Error("synthetic server config invalid: " + (chk.stdout + chk.stderr).slice(0, 400));
  const proc = spawn(serverBox, ["run", "-c", cfg], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  const h = { log: "" };
  proc.stdout.on("data", (d) => (h.log += d)); proc.stderr.on("data", (d) => (h.log += d));
  if (!(await until(() => portOpen(port), 8000))) throw new Error("synthetic server did not start: " + h.log.slice(0, 400));
  const key = `vless://${uuid}@127.0.0.1:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${MASK}&fp=chrome&pbk=${kp.PublicKey}&sid=${sid}&type=tcp#synthetic`;
  return {
    key, uuid, port, h, proc, creds: { uuid, kp, sid, port },
    stop() { proc.kill(); },
    cleanup() { try { rmSync(dir, { recursive: true, force: true }); } catch {} },
  };
}
