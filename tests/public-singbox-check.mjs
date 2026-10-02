// Same keys through OUR code: keyparse -> config.Build (via tools\buildcfg) -> the pinned sing-box.
// Same success criterion as the Xray check: https://example.com/ fetched through the local proxy with TLS
// verification ON (curl/Schannel, ssl_verify_result 0), HTTP 200 and the expected text. Transport only:
// this is NOT the launcher and NOT the browser, so the country check is not part of it.
// Keys are read from .local\data\selected.json; the temporary key file and config live in .local\tmp and are
// deleted right after use; output carries no keys, hosts or full IPs.
// Usage: node tests/public-singbox-check.mjs   (after: go build -o .local\tools\buildcfg.exe ./cmd/buildcfg)
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import net from "node:net";
import { readFileSync, writeFileSync, rmSync } from "node:fs";
import { root, sleep } from "./cdp.mjs";

const run = promisify(execFile);
const buildcfg = join(root, ".local", "tools", "buildcfg.exe");
const singbox = join(root, ".local", "tools", "sing-box", "sing-box.exe");
const cands = JSON.parse(readFileSync(join(root, ".local", "data", "selected.json"), "utf8"));
const xrayRes = (() => { try { return JSON.parse(readFileSync(join(root, ".local", "data", "xray-results.json"), "utf8")); } catch { return []; } })();
const tmp = join(root, ".local", "tmp");

const maskIp = (s) => String(s).replace(/\b(\d{1,3})(\.\d{1,3}){3}\b/g, "$1.x.x.x");
const redactor = (c) => (s) => { let t = String(s).replace(/\x1b\[[0-9;]*m/g, ""); for (const x of [c.host, c.uuid, c.pbk, c.sid]) if (x && x.length >= 4) t = t.split(x).join("<скрыто>"); return maskIp(t); };
const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const listening = (p) => new Promise((res) => { const s = net.connect(p, "127.0.0.1"); s.once("connect", () => { s.destroy(); res(true); }); s.once("error", () => res(false)); });
async function curlVia(port, url) {
  try {
    const r = await run("curl.exe", ["-sS", "--max-time", "20", "--connect-timeout", "15", "--socks5-hostname", `127.0.0.1:${port}`, "-w", "\n%{http_code} %{ssl_verify_result}", url], { maxBuffer: 1 << 22 });
    const i = r.stdout.lastIndexOf("\n"); const [code, verify] = r.stdout.slice(i + 1).trim().split(" ");
    return { ok: true, body: r.stdout.slice(0, i), code: Number(code), verify: Number(verify) };
  } catch (e) { return { ok: false, err: String(e.stderr || e.message).trim().split("\n")[0] }; }
}

const results = [];
for (const c of cands) {
  const R = redactor(c);
  const r = { id: c.id, section: c.label };
  const keyFile = join(tmp, `sb-${c.id}.key`), cfgFile = join(tmp, `sb-${c.id}.json`);
  let proc, log = "";
  try {
    const lp = await freePort();
    writeFileSync(keyFile, c.key);
    const b = await run(buildcfg, ["-in", keyFile, "-port", String(lp), "-out", cfgFile]).then((x) => ({ code: 0, out: x.stdout.trim() }), (e) => ({ code: e.code, out: String(e.stdout || e.stderr || "").trim() }));
    rmSync(keyFile, { force: true });
    r.parser = b.code === 0 ? "принят" : "ОТКЛОНЁН: " + b.out;
    if (b.code !== 0) { r.ok = false; results.push(r); console.log(`${c.id}: наш парсер/генератор — ${r.parser}`); continue; }
    const chk = await run(singbox, ["check", "-c", cfgFile]).then(() => "ok", (e) => "ОШИБКА: " + R(String(e.stdout || e.stderr).trim()).slice(0, 160));
    r.singboxCheck = chk;
    proc = spawn(singbox, ["run", "-c", cfgFile], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    proc.stdout.on("data", (d) => (log += d)); proc.stderr.on("data", (d) => (log += d));
    for (let i = 0; i < 40 && !(await listening(lp)); i++) await sleep(250);
    rmSync(cfgFile, { force: true });
    const t0 = Date.now();
    const page = await curlVia(lp, "https://example.com/");
    r.seconds = Math.round((Date.now() - t0) / 100) / 10;
    if (page.ok) {
      r.example = { http: page.code, tlsVerify: page.verify, textOk: /Example Domain/.test(page.body) };
      r.ok = page.code === 200 && page.verify === 0 && r.example.textOk;
      if (r.ok) { const c2 = await curlVia(lp, "https://api.country.is/"); const m = c2.ok && /"country"\s*:\s*"([A-Z]{2})"/.exec(c2.body); r.exitCountry = m ? m[1] : "не определена"; }
    } else { r.ok = false; r.error = R(page.err); }
    r.coreLog = [...new Set(R(log).split(/\r?\n/).filter((l) => /error|fail|refus|reset|timeout|EOF|reality|reject/i.test(l)).map((l) => l.replace(/\[\d+ \d+\w*\]/g, "").replace(/^\S+ /, "").trim()))].slice(0, 4);
  } catch (e) { r.ok = false; r.error = R(e.message); }
  finally { try { if (proc) proc.kill(); } catch {} rmSync(keyFile, { force: true }); rmSync(cfgFile, { force: true }); }
  await sleep(500);
  const x = xrayRes.find((q) => q.id === c.id);
  r.xray = x ? x.xrayOk : null;
  results.push(r);
  console.log(`${c.id} [${c.label}]: парсер ${r.parser}; sing-box check ${r.singboxCheck}; sing-box example.com: ${r.ok ? "ДА (HTTP 200, TLS проверен, текст на месте, выход " + r.exitCountry + ")" : "НЕТ" + (r.example ? ` (HTTP ${r.example.http}, verify ${r.example.tlsVerify})` : "") + (r.error ? ": " + r.error : "")}; Xray: ${r.xray === null ? "?" : r.xray ? "ДА" : "нет"}${r.coreLog && r.coreLog.length ? "\n      журнал sing-box: " + r.coreLog.join(" | ") : ""}`);
}
writeFileSync(join(root, ".local", "data", "singbox-results.json"), JSON.stringify(results, null, 2));
const left = (await run("powershell", ["-NoProfile", "-Command", "(Get-Process sing-box -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*runet-access*' } | Measure-Object).Count"])).stdout.trim();
console.log(`\nУспешных в sing-box: ${results.filter((x) => x.ok).length} из ${results.length}; оставшихся процессов sing-box из проекта: ${left}`);
