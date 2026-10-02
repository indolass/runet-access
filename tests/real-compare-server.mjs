// Compares the server (host:port and resolved IP:port) of the key in .local\secrets\test-key.txt with
// the one saved earlier, WITHOUT printing any address. Only salted HMAC fingerprints are stored, in
// .local\secrets\prev-server.json (git-ignored). The key file is only read, never modified.
//   node tests\real-compare-server.mjs save      remember the server of the current key
//   node tests\real-compare-server.mjs compare   compare the current key with the saved one
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createHmac, randomBytes } from "node:crypto";
import dns from "node:dns/promises";
import net from "node:net";
import { root } from "./cdp.mjs";

const keyFile = join(root, ".local", "secrets", "test-key.txt");
const store = join(root, ".local", "secrets", "prev-server.json");
mkdirSync(join(root, ".local", "secrets"), { recursive: true });
const mode = process.argv[2];
if (!["save", "compare"].includes(mode)) { console.log("usage: save | compare"); process.exit(2); }

const raw = readFileSync(keyFile, "utf8").trim().split("#")[0];
if (!/^vless:\/\/\S+$/i.test(raw)) { console.log("В файле ключа нет одной строки vless://... (до #)."); process.exit(2); }
const u = new URL(raw);
const host = u.hostname.toLowerCase(), port = String(Number(u.port) || 443);
let ips = [];
if (net.isIP(host)) ips = [host];
else ips = await dns.lookup(host, { all: true, family: 4 }).then((r) => r.map((x) => x.address).sort(), () => []);

const fp = (salt, s) => createHmac("sha256", Buffer.from(salt, "hex")).update(s).digest("hex");
const fingerprints = (salt) => ({ name: fp(salt, `${host}:${port}`), ips: ips.map((ip) => fp(salt, `${ip}:${port}`)) });

if (mode === "save") {
  const salt = randomBytes(16).toString("hex");
  writeFileSync(store, JSON.stringify({ salt, savedAt: new Date().toISOString(), ...fingerprints(salt) }, null, 2));
  console.log(`Отпечаток текущего сервера сохранён (имя/адрес и порт; найденных IPv4: ${ips.length}). Адреса не показаны.`);
} else {
  if (!existsSync(store)) { console.log("Сохранённого отпечатка нет: сравнивать не с чем."); process.exit(2); }
  const prev = JSON.parse(readFileSync(store, "utf8"));
  const cur = fingerprints(prev.salt);
  const sameName = cur.name === prev.name;
  const sameIp = cur.ips.some((x) => prev.ips.includes(x));
  console.log(`Тот же адрес и порт, что в прошлом ключе: ${sameName ? "ДА" : "нет"}`);
  console.log(`Тот же IP и порт после разрешения имени: ${sameIp ? "ДА" : cur.ips.length ? "нет" : "не определить (имя не разрешилось)"}`);
  if (sameName || sameIp) console.log("ВНИМАНИЕ: сервер тот же, что отвергал соединение. Новый ключ на том же адресе, скорее всего, не поможет; проверять его повторно не буду, пока вы не подтвердите.");
  else console.log("Сервер другой: можно проверять соединение, затем выход и три сайта.");
  process.exit(sameName || sameIp ? 3 : 0);
}
