// Is the "connection refused" caused by wrong local DNS? Resolves the key's server name through the
// system resolver, 1.1.1.1, 8.8.8.8 and DNS-over-HTTPS, then tries TCP on every distinct address.
// The key is read from .local\secrets\test-key.txt in-process; addresses are masked in the output
// (first octet only) and the host name is never printed. The key file is not modified.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import net from "node:net";
import dns from "node:dns/promises";
import { root } from "./cdp.mjs";

const raw = readFileSync(join(root, ".local", "secrets", "test-key.txt"), "utf8").trim().split("#")[0];
const u = new URL(raw);
const host = u.hostname, port = Number(u.port) || 443;
const mask = (ip) => ip.replace(/^(\d+)\.\d+\.\d+\.\d+$/, "$1.x.x.x");
const results = {};

results["система"] = await dns.lookup(host, { all: true, family: 4 }).then((r) => r.map((x) => x.address), (e) => ["ошибка " + e.code]);
for (const srv of ["1.1.1.1", "8.8.8.8"]) {
  const r = new dns.Resolver(); r.setServers([srv]);
  results[srv] = await Promise.race([r.resolve4(host), new Promise((_, rej) => setTimeout(() => rej({ code: "TIMEOUT" }), 6000))]).catch((e) => ["ошибка " + (e.code || e.message)]);
}
results["DoH cloudflare"] = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(8000) })
  .then((r) => r.json()).then((j) => (j.Answer || []).filter((a) => a.type === 1).map((a) => a.data)).catch((e) => ["ошибка " + (e.name || e.message)]);

for (const [k, v] of Object.entries(results)) console.log(`DNS через ${k}: ${v.length ? v.map(mask).join(", ") : "(пусто)"}`);
const sets = Object.values(results).map((v) => [...v].sort().join(","));
console.log("Все резолверы дают одинаковый ответ: " + (new Set(sets).size === 1));

const ips = [...new Set(Object.values(results).flat().filter((x) => net.isIPv4(x)))];
for (const ip of ips) {
  const r = await new Promise((res) => { const t0 = Date.now(); const s = net.connect({ host: ip, port, timeout: 8000 });
    s.once("connect", () => { s.destroy(); res("порт открыт (" + (Date.now() - t0) + " мс)"); }); s.once("timeout", () => { s.destroy(); res("таймаут"); }); s.once("error", (e) => res(e.code || e.message)); });
  console.log(`TCP ${mask(ip)}:${port} -> ${r}`);
}
// control: the same machine reaches an ordinary HTTPS host, so a refusal is specific to this server
const ctl = await new Promise((res) => { const s = net.connect({ host: "api.ipify.org", port: 443, timeout: 8000 }); s.once("connect", () => { s.destroy(); res("открыт"); }); s.once("error", (e) => res(e.code)); s.once("timeout", () => { s.destroy(); res("таймаут"); }); });
console.log("Контроль (обычный HTTPS-сайт, порт 443) с этого компьютера: " + ctl);
