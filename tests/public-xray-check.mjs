// Independent positive control: do the selected PUBLIC keys really carry traffic through Xray?
// - the Xray config is built HERE, from the key's URL parameters, independently of our Go parser/generator;
// - Xray runs directly through its CLI (.local\tools\xray\xray.exe) with a local SOCKS inbound on 127.0.0.1;
// - success = https://example.com/ is fetched THROUGH that proxy with TLS certificate verification ON
//   (curl, Schannel; ssl_verify_result must be 0), HTTP 200 and the expected page text. An open port or a
//   running process is NOT success;
// - the tunnel exit country is read through the same proxy (api.country.is) for information only;
// - only public test pages are requested; each request is time-limited; only our own processes are stopped;
// - keys are read from .local\data\selected.json; configs live in .local\tmp and are deleted right after;
//   console output and .local\data\xray-results.json carry NO keys, hosts or full IPs.
// Usage: node tests/public-xray-check.mjs
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import net from "node:net";
import { readFileSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { root, sleep } from "./cdp.mjs";

const run = promisify(execFile);
const xray = join(root, ".local", "tools", "xray", "xray.exe");
const cands = JSON.parse(readFileSync(join(root, ".local", "data", "selected.json"), "utf8"));
const tmp = join(root, ".local", "tmp"); mkdirSync(tmp, { recursive: true });

const maskIp = (s) => String(s).replace(/\b(\d{1,3})(\.\d{1,3}){3}\b/g, "$1.x.x.x");
const redactor = (c) => (s) => {
  let t = String(s).replace(/\x1b\[[0-9;]*m/g, "");
  for (const x of [c.host, c.uuid, c.pbk, c.sid]) if (x && x.length >= 4) t = t.split(x).join("<скрыто>");
  return maskIp(t);
};
const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const tcpProbe = (host, port) => new Promise((res) => { const t0 = Date.now(); const s = net.connect({ host, port, timeout: 8000 });
  s.once("connect", () => { s.destroy(); res({ ok: true, ms: Date.now() - t0 }); }); s.once("timeout", () => { s.destroy(); res({ ok: false, why: "таймаут" }); }); s.once("error", (e) => res({ ok: false, why: e.code || e.message })); });

// Independent Xray config: written from the Xray documentation, not from our generator.
function xrayConfig(c, port) {
  return {
    log: { loglevel: "warning" },
    inbounds: [{ listen: "127.0.0.1", port, protocol: "socks", settings: { auth: "noauth", udp: false } }],
    outbounds: [{
      protocol: "vless",
      settings: { vnext: [{ address: c.host, port: c.port, users: [{ id: c.uuid, encryption: "none", flow: c.flow }] }] },
      streamSettings: { network: "tcp", security: "reality", realitySettings: { serverName: c.sni, fingerprint: c.fp || "chrome", publicKey: c.pbk, shortId: c.sid, spiderX: "" } },
    }],
  };
}

async function curlVia(port, url, extra = []) {
  try {
    const r = await run("curl.exe", ["-sS", "--max-time", "20", "--connect-timeout", "15", "--socks5-hostname", `127.0.0.1:${port}`, "-w", "\n%{http_code} %{ssl_verify_result}", ...extra, url], { maxBuffer: 1 << 22 });
    const i = r.stdout.lastIndexOf("\n");
    const [code, verify] = r.stdout.slice(i + 1).trim().split(" ");
    return { ok: true, body: r.stdout.slice(0, i), code: Number(code), verify: Number(verify) };
  } catch (e) { return { ok: false, err: String(e.stderr || e.message).trim().split("\n")[0], exit: e.code }; }
}

const results = [];
for (const c of cands) {
  const R = redactor(c);
  const r = { id: c.id, section: c.label, port: c.port, fp: c.fp, sidLen: c.sid.length };
  const cfgPath = join(tmp, `xray-${c.id}.json`);
  let proc, log = "";
  try {
    r.tcp = await tcpProbe(c.host, c.port);
    const lp = await freePort();
    writeFileSync(cfgPath, JSON.stringify(xrayConfig(c, lp)));
    proc = spawn(xray, ["run", "-c", cfgPath], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    proc.stdout.on("data", (d) => (log += d)); proc.stderr.on("data", (d) => (log += d));
    for (let i = 0; i < 40 && !(await new Promise((res) => { const s = net.connect(lp, "127.0.0.1"); s.once("connect", () => { s.destroy(); res(true); }); s.once("error", () => res(false)); })); i++) await sleep(250);
    rmSync(cfgPath, { force: true }); // Xray has read it; do not leave the key on disk
    const t0 = Date.now();
    const page = await curlVia(lp, "https://example.com/");   // certificate verification stays ON (no -k)
    r.seconds = Math.round((Date.now() - t0) / 100) / 10;
    if (page.ok) {
      r.example = { http: page.code, tlsVerify: page.verify, textOk: /Example Domain/.test(page.body) };
      r.xrayOk = page.code === 200 && page.verify === 0 && r.example.textOk;
      if (r.xrayOk) { // informational: exit country through the same tunnel
        const c2 = await curlVia(lp, "https://api.country.is/");
        const m = c2.ok && /"country"\s*:\s*"([A-Z]{2})"/.exec(c2.body);
        r.exitCountry = m ? m[1] : "не определена";
      }
    } else { r.xrayOk = false; r.error = R(page.err); }
    r.xrayLog = [...new Set(R(log).split(/\r?\n/).filter((l) => /error|fail|refus|reset|timeout|EOF|reality|reject/i.test(l)).map((l) => l.replace(/^\S+ \S+ /, "").trim()))].slice(0, 4);
  } catch (e) { r.xrayOk = false; r.error = R(e.message); }
  finally {
    try { if (proc) proc.kill(); } catch {}
    rmSync(cfgPath, { force: true });
  }
  await sleep(500);
  results.push(r);
  console.log(`${c.id} [${c.label}] порт ${c.port}: TCP ${r.tcp.ok ? "открыт " + r.tcp.ms + " мс" : "НЕТ (" + r.tcp.why + ")"}; Xray example.com: ${r.xrayOk ? "ДА (HTTP 200, TLS проверен, текст страницы на месте, выход " + r.exitCountry + ")" : "НЕТ" + (r.example ? ` (HTTP ${r.example.http}, verify ${r.example.tlsVerify})` : "") + (r.error ? ": " + r.error : "")}${r.xrayLog && r.xrayLog.length ? "\n      журнал Xray: " + r.xrayLog.join(" | ") : ""}`);
}
writeFileSync(join(root, ".local", "data", "xray-results.json"), JSON.stringify(results, null, 2));
const left = (await run("powershell", ["-NoProfile", "-Command", "(Get-Process xray -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*runet-access*' } | Measure-Object).Count"])).stdout.trim();
console.log(`\nУспешных в Xray: ${results.filter((x) => x.xrayOk).length} из ${results.length}; оставшихся процессов xray из проекта: ${left}`);
