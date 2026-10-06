// Layered check of the key in .local\secrets\test-key.txt: independent Xray vs OUR path (keyparse ->
// config.Build -> sing-box). The key is read in-process; it never reaches output, command lines or Git;
// the file is never modified or deleted. Console output and .local\data\owner-results.json are masked
// (no host, UUID, keys, full IPs). Temporary configs (they must hold the key) live in .local\tmp and are
// removed right after the core has read them. Only processes started here are stopped; every request and
// process has a timeout; nothing is retried in a loop.
//   node tests/owner-key-check.mjs            wait for the file to CHANGE, then check
//   node tests/owner-key-check.mjs --now      check the file as it is
// Layers are reported separately and a layer is blamed only when the evidence names it.
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import net from "node:net";
import dns from "node:dns/promises";
import { createHmac } from "node:crypto";
import { readFileSync, writeFileSync, rmSync, statSync, existsSync, mkdirSync } from "node:fs";
import { root, sleep } from "./cdp.mjs";

const run = promisify(execFile);
const keyFile = join(root, ".local", "secrets", "test-key.txt");
const xrayExe = join(root, ".local", "tools", "xray", "xray.exe");
const sbExe = join(root, ".local", "tools", "sing-box", "sing-box.exe");
const buildcfg = join(root, ".local", "tools", "buildcfg.exe");
const tmp = join(root, ".local", "tmp"); mkdirSync(tmp, { recursive: true });
const NOW = process.argv.includes("--now");

let secrets = [];
const maskIp = (s) => String(s).replace(/\b(\d{1,3})(\.\d{1,3}){3}\b/g, "$1.x.x.x");
const redact = (s) => { let t = String(s).replace(/\x1b\[[0-9;]*m/g, ""); for (const x of secrets) if (x && x.length >= 4) t = t.split(x).join("<скрыто>"); return maskIp(t).replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<uuid>"); };
const log = (s) => console.log(redact(s));
process.on("unhandledRejection", (e) => { log("FATAL " + (e && e.message)); process.exit(1); });
const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const listening = (p) => new Promise((res) => { const s = net.connect(p, "127.0.0.1"); s.once("connect", () => { s.destroy(); res(true); }); s.once("error", () => res(false)); });
const out = { stages: {} };

// ---------------- 0. wait for the key file ----------------
const baseline = statSync(keyFile).mtimeMs;
log(NOW ? "Проверяю файл ключа как есть (--now)." : "Жду, когда файл .local\\secrets\\test-key.txt будет изменён (сохранён второй ключ)...");
let raw = "";
for (let last = -1, since = 0, warned = new Set(); ; await sleep(1500)) {
  const st = statSync(keyFile);
  if (!NOW && st.mtimeMs === baseline) continue;
  if (st.size === 0) continue;
  if (st.mtimeMs !== last) { last = st.mtimeMs; since = Date.now(); continue; }
  if (Date.now() - since < 3000 && !NOW) continue;
  const t = readFileSync(keyFile, "utf8").trim();
  if (/^vless:\/\/\S+$/i.test(t.split("#")[0])) { raw = t; break; }
  if (!warned.has(st.mtimeMs)) { warned.add(st.mtimeMs); log("В файле не одна строка vless://... (до #). Исправьте и сохраните; жду."); }
  if (NOW) { log("Формат ключа неверен."); process.exit(2); }
}
const u = new URL(raw.split("#")[0]); raw = "";
const q = u.searchParams;
const k = { host: u.hostname, port: Number(u.port) || 443, uuid: decodeURIComponent(u.username), q: Object.fromEntries(q.entries()) };
secrets = [k.host, k.uuid, k.q.pbk, k.q.sid, u.password];
const present = Object.keys(k.q).sort();
log(`\n[0] Ключ прочитан. Присутствуют параметры: ${present.join(", ")}.`);
log(`    security=${k.q.security || "—"}, type=${k.q.type || "— (по умолчанию tcp)"}, flow=${k.q.flow || "—"}, fp=${k.q.fp || "—"}, sni задан=${!!k.q.sni}, pbk длина=${(k.q.pbk || "").length}, sid длина=${(k.q.sid || "").length}, encryption=${k.q.encryption || "—"}, порт=${k.port}, адрес — ${net.isIP(k.host) ? "IP" : "имя"}`);
out.stages.key = { params: present, security: k.q.security, type: k.q.type, flow: k.q.flow, fp: k.q.fp, sidLen: (k.q.sid || "").length, pbkLen: (k.q.pbk || "").length };

// ---------------- 1. compare with the previous server (informational, not blocking) ----------------
try {
  const prev = JSON.parse(readFileSync(join(root, ".local", "secrets", "prev-server.json"), "utf8"));
  const fp = (s) => createHmac("sha256", Buffer.from(prev.salt, "hex")).update(s).digest("hex");
  let ips = net.isIP(k.host) ? [k.host] : await dns.lookup(k.host, { all: true, family: 4 }).then((r) => r.map((x) => x.address), () => []);
  const sameName = fp(`${k.host.toLowerCase()}:${k.port}`) === prev.name, sameIp = ips.some((ip) => prev.ips.includes(fp(`${ip}:${k.port}`)));
  out.stages.sameServerAsBefore = { name: sameName, ip: sameIp };
  log(`[1] Сервер относительно прежнего ключа: тот же адрес и порт — ${sameName ? "ДА" : "нет"}; тот же IP и порт — ${sameIp ? "ДА" : "нет"}. Совпадение не запрещает проверку: поддержка выдала новый ключ, параметры доступа или состояние сервера могли измениться.`);
} catch { log("[1] Отпечатка прежнего сервера нет: сравнение пропущено."); }

// ---------------- 2. DNS and TCP ----------------
let target = k.host, dnsOk = true;
if (!net.isIP(k.host)) {
  const r = {};
  r.system = await dns.lookup(k.host, { all: true, family: 4 }).then((x) => x.map((y) => y.address).sort(), (e) => "ошибка " + e.code);
  const res = new dns.Resolver(); res.setServers(["1.1.1.1"]);
  r.cloudflare = await Promise.race([res.resolve4(k.host), sleep(6000).then(() => { throw { code: "TIMEOUT" }; })]).then((x) => x.sort(), (e) => "ошибка " + (e.code || e.message));
  dnsOk = Array.isArray(r.system);
  log(`[2] DNS: системный резолвер ${dnsOk ? "разрешил (" + r.system.length + " адр.)" : r.system}; 1.1.1.1 ${Array.isArray(r.cloudflare) ? "разрешил" : r.cloudflare}; ответы совпадают: ${JSON.stringify(r.system) === JSON.stringify(r.cloudflare)}`);
  if (dnsOk) target = r.system[0];
  out.stages.dns = { ok: dnsOk, same: JSON.stringify(r.system) === JSON.stringify(r.cloudflare) };
}
const tcp = dnsOk ? await new Promise((res) => { const t0 = Date.now(); const s = net.connect({ host: target, port: k.port, timeout: 10000 });
  s.once("connect", () => { s.destroy(); res({ ok: true, ms: Date.now() - t0 }); }); s.once("timeout", () => { s.destroy(); res({ ok: false, why: "таймаут 10 с" }); }); s.once("error", (e) => res({ ok: false, why: e.code || e.message })); }) : { ok: false, why: "DNS не разрешил имя" };
out.stages.tcp = tcp;
log(`    TCP до сервера:порта: ${tcp.ok ? "открыт за " + tcp.ms + " мс" : "НЕТ (" + tcp.why + ")"}`);

// ---------------- helpers: curl through a local proxy ----------------
async function curlVia(port, url) {
  try {
    const r = await run("curl.exe", ["-sS", "--max-time", "20", "--connect-timeout", "15", "--socks5-hostname", `127.0.0.1:${port}`, "-w", "\n%{http_code} %{ssl_verify_result}", url], { maxBuffer: 1 << 22 });
    const i = r.stdout.lastIndexOf("\n"); const [code, verify] = r.stdout.slice(i + 1).trim().split(" ");
    return { ok: true, body: r.stdout.slice(0, i), code: Number(code), verify: Number(verify) };
  } catch (e) { return { ok: false, err: redact(String(e.stderr || e.message).trim().split("\n")[0]), exit: e.code }; }
}
const classify = (logText) => {
  const t = redact(logText);
  const lines = [...new Set(t.split(/\r?\n/).filter((l) => /error|fail|refus|reset|timeout|EOF|reality|reject|handshake|lookup|dial|no such host|certificate|invalid/i.test(l)).map((l) => l.replace(/^\S+ \S+ /, "").replace(/\[\d+ \d+\w*\]/g, "").replace(/\s+/g, " ").trim()))].slice(0, 6);
  const has = (re) => re.test(t);
  const layers = [];
  if (has(/no such host|lookup .* (failed|timeout)|dns.*(fail|timeout)/i)) layers.push("DNS (по журналу)");
  if (has(/connection refused|actively refused|i\/o timeout.*dial|dial tcp .*timeout|connectex/i)) layers.push("TCP до сервера (по журналу)");
  if (has(/REALITY|reality|tls: .*(handshake|bad|invalid)|handshake failure|certificate/i)) layers.push("Reality/TLS-рукопожатие (по журналу)");
  if (has(/EOF|reset by peer|forcibly closed|connection reset/i) && !layers.length) layers.push("соединение с сервером оборвано после установления TCP; журнал клиента не указывает слой точнее (возможны отзыв UUID, параметры Reality, фильтрация)");
  return { lines, layers };
};
const exitCountry = async (port) => { const c = await curlVia(port, "https://api.country.is/"); const m = c.ok && /"country"\s*:\s*"([A-Z]{2})"/.exec(c.body); return m ? m[1] : null; };

// ---------------- 3. independent Xray ----------------
{
  log("\n[3] Независимый Xray (CLI, свой конфиг, не наш парсер и не наш генератор)");
  const ver = await run(xrayExe, ["version"]).then((x) => x.stdout.split(/\r?\n/)[0], () => "неизвестна");
  log(`    версия: ${ver}`);
  const r = { version: ver };
  const net_ = (k.q.type || "tcp").toLowerCase();
  const sec_ = (k.q.security || "").toLowerCase();
  const supported = (sec_ === "reality" && ["tcp", "raw"].includes(net_)) || (sec_ === "tls" && ["tcp", "raw", "ws"].includes(net_));
  if (!supported) {
    r.skipped = `не собирается: security=${k.q.security}, type=${net_}`; log("    " + r.skipped);
  } else {
    // only what the key states; nothing is guessed (VLESS "encryption" is "none" per the protocol when absent;
    // TLS certificate verification stays ON: allowInsecure is never set)
    const user = { id: k.uuid, encryption: k.q.encryption || "none" }; if (k.q.flow) user.flow = k.q.flow;
    let stream;
    if (sec_ === "reality") {
      const rs = { publicKey: k.q.pbk }; if (k.q.sni) rs.serverName = k.q.sni; if (k.q.fp) rs.fingerprint = k.q.fp; if (k.q.sid !== undefined) rs.shortId = k.q.sid; if (k.q.spx) rs.spiderX = k.q.spx;
      stream = { network: "tcp", security: "reality", realitySettings: rs };
    } else {
      const ts = {}; if (k.q.sni) ts.serverName = k.q.sni; if (k.q.fp) ts.fingerprint = k.q.fp; if (k.q.alpn) ts.alpn = k.q.alpn.split(",").map((x) => x.trim()).filter(Boolean);
      stream = { network: net_ === "raw" ? "tcp" : net_, security: "tls", tlsSettings: ts };
      if (net_ === "ws") { const ws = {}; if (k.q.path) ws.path = k.q.path; if (k.q.host) ws.headers = { Host: k.q.host }; stream.wsSettings = ws; }
    }
    r.shape = `${sec_}/${net_}`;
    const lp = await freePort(), cfg = join(tmp, "owner-xray.json");
    writeFileSync(cfg, JSON.stringify({ log: { loglevel: "debug" }, inbounds: [{ listen: "127.0.0.1", port: lp, protocol: "socks", settings: { auth: "noauth", udp: false } }],
      outbounds: [{ protocol: "vless", settings: { vnext: [{ address: k.host, port: k.port, users: [user] }] }, streamSettings: stream }] }));
    const test = await run(xrayExe, ["run", "-test", "-c", cfg], { timeout: 20000 }).then(() => "конфиг принят этой версией Xray", (e) => "КОНФИГ ОТВЕРГНУТ: " + redact(String(e.stdout || e.stderr || e.message).trim()).slice(0, 200));
    r.configTest = test; log("    " + test);
    if (test.startsWith("конфиг принят")) {
      let lg = ""; const proc = spawn(xrayExe, ["run", "-c", cfg], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
      proc.stdout.on("data", (d) => (lg += d)); proc.stderr.on("data", (d) => (lg += d));
      try {
        for (let i = 0; i < 40 && !(await listening(lp)); i++) await sleep(250);
        rmSync(cfg, { force: true });
        const t0 = Date.now(); const page = await curlVia(lp, "https://example.com/");
        r.seconds = Math.round((Date.now() - t0) / 100) / 10;
        if (page.ok) {
          r.example = { http: page.code, tlsVerify: page.verify, textOk: /Example Domain/.test(page.body) };
          r.ok = page.code === 200 && page.verify === 0 && r.example.textOk;
          if (r.ok) r.exitCountry = await exitCountry(lp);
        } else { r.ok = false; r.requestError = page.err; }
        const c = classify(lg); r.logLines = c.lines; r.layers = c.layers;
      } finally { try { proc.kill(); } catch {} rmSync(cfg, { force: true }); }
      log(`    example.com через туннель (TLS проверен): ${r.ok ? "ДА (HTTP 200, текст на месте), выход: " + (r.exitCountry || "не определён") : "НЕТ" + (r.requestError ? " — " + r.requestError : "")}`);
      if (!r.ok) { log("    слой по журналу Xray: " + (r.layers.length ? r.layers.join("; ") : "журнал не указывает слой") ); if (r.logLines.length) log("    строки журнала Xray:\n      " + r.logLines.join("\n      ")); }
    }
  }
  out.stages.xray = r;
}
await sleep(700);

// ---------------- 4. our path: keyparse -> config.Build -> sing-box ----------------
{
  log("\n[4] Наш путь: keyparse → config.Build → sing-box");
  const r = {};
  const keyTmp = join(tmp, "owner-sb.key"), cfg = join(tmp, "owner-sb.json");
  const lp = await freePort();
  writeFileSync(keyTmp, readFileSync(keyFile, "utf8").trim());
  const b = await run(buildcfg, ["-in", keyTmp, "-port", String(lp), "-out", cfg, "-log", "debug"]).then((x) => ({ code: 0, out: x.stdout.trim() }), (e) => ({ code: e.code, out: String(e.stdout || e.stderr || "").trim() }));
  rmSync(keyTmp, { force: true });
  r.parser = b.code === 0 ? "принят" : "ОТКЛОНЁН: " + redact(b.out); log("    парсер и генератор: " + r.parser);
  if (b.code === 0) {
    r.check = await run(sbExe, ["check", "-c", cfg]).then(() => "ok", (e) => "ОШИБКА: " + redact(String(e.stdout || e.stderr).trim()).slice(0, 200)); log("    sing-box check: " + r.check);
    let lg = ""; const proc = spawn(sbExe, ["run", "-c", cfg], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    proc.stdout.on("data", (d) => (lg += d)); proc.stderr.on("data", (d) => (lg += d));
    try {
      for (let i = 0; i < 40 && !(await listening(lp)); i++) await sleep(250);
      rmSync(cfg, { force: true });
      const t0 = Date.now(); const page = await curlVia(lp, "https://example.com/");
      r.seconds = Math.round((Date.now() - t0) / 100) / 10;
      if (page.ok) {
        r.example = { http: page.code, tlsVerify: page.verify, textOk: /Example Domain/.test(page.body) };
        r.ok = page.code === 200 && page.verify === 0 && r.example.textOk;
        if (r.ok) r.exitCountry = await exitCountry(lp);
      } else { r.ok = false; r.requestError = page.err; }
      const c = classify(lg); r.logLines = c.lines; r.layers = c.layers;
    } finally { try { proc.kill(); } catch {} rmSync(cfg, { force: true }); }
    log(`    example.com через туннель (TLS проверен): ${r.ok ? "ДА (HTTP 200, текст на месте), выход: " + (r.exitCountry || "не определён") : "НЕТ" + (r.requestError ? " — " + r.requestError : "")}`);
    if (!r.ok) { log("    слой по журналу sing-box: " + (r.layers.length ? r.layers.join("; ") : "журнал не указывает слой")); if (r.logLines.length) log("    строки журнала sing-box:\n      " + r.logLines.join("\n      ")); }
  }
  out.stages.singbox = r;
}

// ---------------- summary ----------------
const x = out.stages.xray, s = out.stages.singbox;
log("\nИТОГ по слоям (без ключа и полного IP):");
log(`  DNS: ${out.stages.dns ? (out.stages.dns.ok ? "разрешает" : "НЕ разрешает") : "не нужен (в ключе IP)"}`);
log(`  TCP до сервера: ${tcp.ok ? "открыт" : "НЕТ (" + tcp.why + ")"}`);
log(`  Xray: ${x.ok ? "туннель работает, example.com загружен, выход " + (x.exitCountry || "?") : x.skipped ? "не проверялся (" + x.skipped + ")" : "НЕ работает" + (x.layers && x.layers.length ? " — " + x.layers.join("; ") : "")}`);
log(`  Наш sing-box путь: ${s.ok ? "туннель работает, example.com загружен, выход " + (s.exitCountry || "?") : s.parser && s.parser !== "принят" ? "парсер/генератор отклонили ключ" : "НЕ работает" + (s.layers && s.layers.length ? " — " + s.layers.join("; ") : "")}`);
out.verdict = x.ok && s.ok ? "оба работают" : !x.ok && !s.ok ? "оба не работают" : x.ok ? "Xray работает, наш путь нет" : "наш путь работает, Xray нет";
log(`  Вывод: ${out.verdict}. ` + (!x.ok && !s.ok ? "Два отказа не доказывают исправность нашего приложения; слой назван только там, где его указывает журнал." : ""));
const left = (await run("powershell", ["-NoProfile", "-Command", "(Get-Process xray,sing-box -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*runet-access*' } | Measure-Object).Count"])).stdout.trim();
log(`  Оставшихся процессов xray/sing-box из проекта: ${left}; файл ключа на месте: ${existsSync(keyFile)}`);
writeFileSync(join(root, ".local", "data", "owner-results.json"), JSON.stringify(out, null, 2));
process.exit(0);
