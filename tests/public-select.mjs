// Picks up to N public VLESS+Reality+TCP candidates with DIFFERENT servers from the published list
// (tiagorrg/vless-checker, docs/keys.json). Full keys are written ONLY to .local\data\selected.json
// (git-ignored); the console shows masked facts (section, port, flow, fp, short-id length, latency).
// Usage: node tests/public-select.mjs [N=5]
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { root } from "./cdp.mjs";

const N = Number(process.argv[2] || 5);
const src = JSON.parse(readFileSync(join(root, ".local", "data", "keys.json"), "utf8"));

// flatten: every key string with its section label
const found = [];
const visit = (label, v) => {
  if (!v) return;
  if (typeof v === "string") { if (v.startsWith("vless://")) found.push({ label, key: v }); return; }
  if (Array.isArray(v)) { for (const x of v) visit(label, x); return; }
  if (typeof v === "object") {
    if (typeof v.key === "string") found.push({ label, key: v.key, latency: v.latency_ms });
    for (const [k, x] of Object.entries(v)) if (k !== "key") visit(label, x);
  }
};
for (const [section, v] of Object.entries(src)) {
  if (section === "other_countries") { for (const [c, x] of Object.entries(v)) visit("other:" + c, x); }
  else if (typeof v === "object" && v) visit(section, v);
}

function facts(entry) {
  let u;
  try { u = new URL(entry.key.split("#")[0]); } catch { return null; }
  const q = u.searchParams;
  return {
    label: entry.label, key: entry.key, latency: entry.latency ?? null,
    host: u.hostname, port: Number(u.port) || 443, uuid: decodeURIComponent(u.username),
    security: (q.get("security") || "").toLowerCase(), type: (q.get("type") || "tcp").toLowerCase(), flow: q.get("flow") || "",
    sni: q.get("sni") || "", pbk: q.get("pbk") || "", sid: q.get("sid") || "", fp: q.get("fp") || "", enc: q.get("encryption") || "",
  };
}
const compatible = (f) => f && f.security === "reality" && ["tcp", "raw"].includes(f.type) && f.flow === "xtls-rprx-vision" && f.sni && /^[A-Za-z0-9_-]{43}$/.test(f.pbk)
  && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(f.uuid) && /^[0-9a-fA-F]{0,16}$/.test(f.sid) && (f.enc === "" || f.enc === "none");

const all = found.map(facts).filter(Boolean);
const compat = all.filter(compatible);
const bySection = {};
for (const f of compat) bySection[f.label] = (bySection[f.label] || 0) + 1;
console.log(`Ключей в списке: ${all.length}; совместимых (VLESS+Reality+TCP+vision): ${compat.length}; уникальных серверов (host:port): ${new Set(compat.map((f) => f.host + ":" + f.port)).size}`);
console.log("Совместимых по секциям: " + Object.entries(bySection).map(([k, v]) => `${k}=${v}`).join(", "));

// one per server, spread across sections, lowest latency first within a section
const seenServer = new Set(), perSection = {}, picked = [];
const sorted = [...compat].sort((a, b) => (a.latency ?? 1e9) - (b.latency ?? 1e9));
for (const round of [1, 2]) {
  for (const f of sorted) {
    if (picked.length >= N) break;
    const server = f.host + ":" + f.port;
    if (seenServer.has(server)) continue;
    if ((perSection[f.label] || 0) >= round) continue;
    seenServer.add(server); perSection[f.label] = (perSection[f.label] || 0) + 1; picked.push(f);
  }
}
writeFileSync(join(root, ".local", "data", "selected.json"), JSON.stringify(picked.map((f, i) => ({ id: "c" + (i + 1), ...f })), null, 2));
console.log(`\nОтобрано кандидатов: ${picked.length} (полные ключи только в .local\\data\\selected.json)`);
picked.forEach((f, i) => console.log(`c${i + 1}: секция=${f.label}, порт=${f.port}, fp=${f.fp || "-"}, sid длина=${f.sid.length}, flow=${f.flow}, задержка (с GitHub, США)=${f.latency ?? "-"} мс`));
