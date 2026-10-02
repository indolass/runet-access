// Layer-by-layer diagnosis of a real key WITHOUT the launcher: DNS -> TCP -> bare sing-box client
// (debug log) -> traffic through it. The key is read from .local\secrets\test-key.txt inside this
// process; every output line is passed through a redactor that replaces the server address, UUID,
// public key, short id and any IPv4 with placeholders. The temporary client config (it has to hold
// the key for sing-box) lives only in .local\tmp and is deleted at the end. The key FILE is kept.
// Run:  . .\scripts\env.ps1; node tests\real-diagnose.mjs
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import net from "node:net";
import dns from "node:dns/promises";
import { existsSync, readFileSync, rmSync, writeFileSync, statSync, mkdirSync } from "node:fs";
import { root, sleep } from "./cdp.mjs";

const run = promisify(execFile);
const keyFile = join(root, ".local", "secrets", "test-key.txt");
const box = join(root, ".local", "tools", "sing-box", "sing-box.exe");
const cfgPath = join(process.env.TEMP, "diag-client.json");
let secrets = [];
const redact = (s) => {
  let t = String(s).replace(/\x1b\[[0-9;]*m/g, "");
  for (const x of secrets) if (x) t = t.split(x).join("<скрыто>");
  return t.replace(/\b(\d{1,3})(\.\d{1,3}){3}\b/g, "$1.x.x.x").replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<uuid>");
};
const log = (s) => console.log(redact(s));
process.on("unhandledRejection", (e) => { log("FATAL " + (e && e.message)); cleanup(); process.exit(1); });
function cleanup() { try { rmSync(cfgPath, { force: true }); } catch {} }

mkdirSync(join(root, ".local", "secrets"), { recursive: true });
if (!existsSync(keyFile)) writeFileSync(keyFile, "");
log("Жду ключ в файле .local\\secrets\\test-key.txt ...");
let raw = "";
for (let last = -1, since = 0, warned = new Set(); Date.now() < Date.now() + 1; await sleep(1500)) {
  const sz = statSync(keyFile).size;
  if (sz > 0) {
    if (sz !== last) { last = sz; since = Date.now(); }
    else if (Date.now() - since > 3000 && !warned.has(sz)) {
      const t = readFileSync(keyFile, "utf8").trim();
      if (/^vless:\/\/\S+$/i.test(t.split("#")[0])) { raw = t; break; }
      warned.add(sz); log("В файле не одна строка vless://... (до #). Жду исправления.");
    }
  }
}
const u = new URL(raw.split("#")[0]); raw = "";
const q = u.searchParams;
const p = { host: u.hostname, port: Number(u.port) || 443, uuid: decodeURIComponent(u.username), flow: q.get("flow") || "", sni: q.get("sni") || "", pbk: q.get("pbk") || "", sid: q.get("sid") || "", fp: q.get("fp") || "chrome", sec: q.get("security") || "", type: q.get("type") || "tcp" };
secrets = [p.host, p.uuid, p.pbk, p.sid, u.password];
log(`Параметры ключа (без значений): security=${p.sec}, flow=${p.flow}, type=${p.type}, fp=${p.fp}, sni задан=${!!p.sni}, sid длина=${p.sid.length}, pbk длина=${p.pbk.length}, порт=${p.port}, адрес — ${net.isIP(p.host) ? "IP" : "доменное имя"}`);

// 1. DNS
let target = p.host;
if (!net.isIP(p.host)) {
  try { const r = await dns.lookup(p.host, { all: true }); log(`1. DNS: имя сервера разрешается (${r.length} адр.)`); target = r[0].address; }
  catch (e) { log("1. DNS: имя сервера НЕ разрешается (" + (e.code || e.message) + "). Слой: DNS/сеть пользователя или имя неверно."); cleanup(); process.exit(0); }
} else log("1. DNS: не нужен (в ключе IP)");

// 2. TCP
const tcp = await new Promise((res) => { const t0 = Date.now(); const s = net.connect({ host: target, port: p.port, timeout: 10000 });
  s.once("connect", () => { s.destroy(); res("открыт за " + (Date.now() - t0) + " мс"); }); s.once("timeout", () => { s.destroy(); res("ТАЙМАУТ 10 с (фильтрация/блокировка или сервер молчит)"); }); s.once("error", (e) => res("ОШИБКА " + (e.code || e.message))); });
log("2. TCP до сервера:порта: " + tcp);

// 3. bare sing-box client with debug log
const port = await new Promise((r) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const x = s.address().port; s.close(() => r(x)); }); });
writeFileSync(cfgPath, JSON.stringify({ log: { level: "debug", timestamp: false }, inbounds: [{ type: "mixed", listen: "127.0.0.1", listen_port: port }],
  outbounds: [{ type: "vless", tag: "proxy", server: p.host, server_port: p.port, uuid: p.uuid, flow: p.flow,
    tls: { enabled: true, server_name: p.sni, utls: { enabled: true, fingerprint: p.fp }, reality: { enabled: true, public_key: p.pbk, short_id: p.sid } } }],
  dns: { servers: [{ type: "local", tag: "l" }] }, route: { final: "proxy", default_domain_resolver: { server: "l" } } }));
let out = "";
const core = spawn(box, ["run", "-c", cfgPath], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
core.stdout.on("data", (d) => (out += d)); core.stderr.on("data", (d) => (out += d));
await sleep(2500);
rmSync(cfgPath, { force: true }); // sing-box has read it; do not leave the key on disk

const curl = async (url) => { try { const r = await run("curl.exe", ["-sS", "--max-time", "25", "-x", `socks5h://127.0.0.1:${port}`, url]); return { ok: true, body: r.stdout.trim() }; } catch (e) { return { ok: false, err: String(e.stderr || e.message).trim().split("\n")[0] }; } };
const c = await curl("https://api.country.is/");
const ex = await curl("https://example.com/");
core.kill(); await sleep(500);

log("3. Через «голый» sing-box с тем же ключом:");
log("   api.country.is (проверка страны): " + (c.ok ? "ответ получен: " + c.body.replace(/"ip":"[^"]*"/, '"ip":"скрыт"') : "НЕТ ответа: " + c.err));
log("   example.com: " + (ex.ok ? "ответ получен (" + ex.body.length + " байт)" : "НЕТ ответа: " + ex.err));
const lines = redact(out).split(/\r?\n/).filter((l) => /error|warn|fail|reality|handshake|refused|timeout|eof|reset|certificate|invalid|denied/i.test(l));
const uniq = [...new Set(lines.map((l) => l.replace(/\[\d+ \d+ms\]/g, "").replace(/\s+/g, " ").trim()))].slice(0, 12);
log("   Диагностические строки ядра (уникальные, адреса скрыты):\n     " + (uniq.length ? uniq.join("\n     ") : "(нет ошибок)"));

let verdict;
const all = out;
if (/connection refused/i.test(tcp) || /ECONNREFUSED/.test(tcp)) verdict = "сервер/порт: соединение отвергнуто (сервер выключен, порт закрыт или фильтрация)";
else if (/ТАЙМАУТ/.test(tcp)) verdict = "сервер/сеть: нет ответа на TCP (блокировка маршрута до сервера, неверный адрес/порт или сервер не работает)";
else if (c.ok || ex.ok) verdict = "ключ и транспорт РАБОТАЮТ; если лаунчер не подтвердил выход, причина в проверке страны или в самом лаунчере";
else if (/reality|handshake|verification|invalid connection|certificate/i.test(all)) verdict = "транспорт Reality: рукопожатие отвергнуто (неверный публичный ключ/sid/sni, ключ отозван или сервер настроен иначе)";
else if (/eof|reset|i\/o timeout|timeout/i.test(all)) verdict = "транспорт: соединение с сервером устанавливается, но обрывается (сервер не принимает этот ключ/UUID, DPI-фильтрация или перегрузка)";
else verdict = "не определено однозначно: см. строки ядра выше";
log("\nВЫВОД: " + verdict);
cleanup();
log("Временный конфиг удалён. Файл ключа сохранён для повторных проверок (удалю по вашей команде или после успешной проверки).");
process.exit(0);
