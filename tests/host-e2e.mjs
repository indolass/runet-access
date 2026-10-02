// Host + sing-box integration test with a SYNTHETIC local VLESS+Reality server.
// No real keys. Needs internet only for the Reality "mask" host and api.ipify.org.
// Run (after scripts\build.ps1):  . .\scripts\env.ps1; node tests\host-e2e.mjs
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync, readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import assert from "node:assert/strict";
import { validateKey } from "../src/extension/src/gov/key.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const hostExe = join(root, "dist", "runet-access", "bin", "runet-access-host.exe");
const serverBox = join(root, ".local", "tools", "sing-box", "sing-box.exe");
const tmpRoot = process.env.TEMP;
assert.ok(tmpRoot && tmpRoot.startsWith(root), "run inside scripts\\env.ps1 so TEMP is under the repo root");
assert.ok(existsSync(hostExe), "build first: scripts\\build.ps1");

let passed = 0, failed = 0;
const step = async (name, fn) => {
  try { await fn(); passed++; console.log("PASS  " + name); }
  catch (e) { failed++; console.log("FAIL  " + name + "\n      " + (e && e.message)); }
};

const sb = (...args) => spawnSync(serverBox, args, { encoding: "utf8" }).stdout.trim();
const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const portOpen = (p) => new Promise((res) => { const s = net.connect(p, "127.0.0.1"); s.once("connect", () => { s.destroy(); res(true); }); s.once("error", () => res(false)); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 10000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await fn()) return true; await sleep(150); } return false; };

// PowerShell via -EncodedCommand: no quoting problems.
const ps = (script) => spawnSync("powershell", ["-NoProfile", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { encoding: "utf8" }).stdout;
const procs = () => {
  const out = ps("Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe'\" | Select-Object ProcessId,ParentProcessId,ExecutablePath | ConvertTo-Json -Compress");
  if (!out.trim()) return [];
  const j = JSON.parse(out); return Array.isArray(j) ? j : [j];
};
const curlVia = (port) => spawnSync("curl.exe", ["-sS", "--max-time", "30", "-x", `socks5h://127.0.0.1:${port}`, "https://api.ipify.org"], { encoding: "utf8" });

// ---- synthetic server ---------------------------------------------------
const uuid = sb("generate", "uuid");
const kp = Object.fromEntries(sb("generate", "reality-keypair").split(/\r?\n/).map((l) => l.split(/:\s*/)));
const sid = sb("generate", "rand", "--hex", "8");
const srvPort = await freePort();
const MASK = "www.cloudflare.com"; // www.microsoft.com is rejected by sing-box 1.13.16 REALITY in this setup
const work = mkdtempSync(join(tmpRoot, "e2e-"));
const srvCfg = join(work, "server.json");
writeFileSync(srvCfg, JSON.stringify({
  log: { level: "info", timestamp: true },
  inbounds: [{ type: "vless", listen: "127.0.0.1", listen_port: srvPort, users: [{ uuid, flow: "xtls-rprx-vision" }],
    tls: { enabled: true, server_name: MASK, reality: { enabled: true, handshake: { server: MASK, server_port: 443 }, private_key: kp.PrivateKey, short_id: [sid] } } }],
  outbounds: [{ type: "direct" }],
}));
let serverLog = "";
const server = spawn(serverBox, ["run", "-c", srvCfg], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
server.stdout.on("data", (d) => (serverLog += d)); server.stderr.on("data", (d) => (serverLog += d));
assert.ok(await until(() => portOpen(srvPort), 8000), "synthetic server did not start");

const key = `vless://${uuid}@127.0.0.1:${srvPort}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${MASK}&fp=chrome&pbk=${kp.PublicKey}&sid=${sid}&type=tcp#synthetic`;
const v = validateKey(key);
assert.ok(v.ok, "validateKey rejected the synthetic key: " + (v.message || ""));
const profile = v.profile;

// ---- native messaging client --------------------------------------------
function startHost() {
  const child = spawn(hostExe, [], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  const h = { child, buf: Buffer.alloc(0), pending: new Map(), events: [], seq: 0 };
  child.stdout.on("data", (d) => {
    h.buf = Buffer.concat([h.buf, d]);
    while (h.buf.length >= 4) {
      const n = h.buf.readUInt32LE(0);
      if (h.buf.length < 4 + n) break;
      const msg = JSON.parse(h.buf.subarray(4, 4 + n).toString("utf8")); h.buf = h.buf.subarray(4 + n);
      if (msg.event) h.events.push(msg); else if (h.pending.has(msg.id)) { h.pending.get(msg.id)(msg); h.pending.delete(msg.id); }
    }
  });
  h.req = (type, payload = {}, ms = 30000) => new Promise((res, rej) => {
    const id = "r" + ++h.seq; const body = Buffer.from(JSON.stringify({ id, type, payload }));
    const hdr = Buffer.alloc(4); hdr.writeUInt32LE(body.length);
    const t = setTimeout(() => rej(new Error("timeout " + type)), ms);
    h.pending.set(id, (m) => { clearTimeout(t); res(m); });
    child.stdin.write(Buffer.concat([hdr, body]));
  });
  h.exited = new Promise((res) => child.once("exit", res));
  return h;
}
const startPayload = { profile, inbound: { listen: "127.0.0.1", port: 0 }, routing: { final: "proxy", rules: [], remoteDns: "" }, logLevel: "warn" };

let host = startHost();
let port;
const hostWorkDir = () => join(tmpRoot, "runet-access", "host-" + host.child.pid);

await step("host answers ping/version; sing-box is the pinned 1.13.16", async () => {
  assert.equal((await host.req("ping")).ok, true);
  const r = await host.req("version");
  assert.match(r.result.singbox, /1\.13\.16/);
});

await step("start: local mixed inbound opens on 127.0.0.1", async () => {
  const r = await host.req("start", startPayload);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.result.listen, "127.0.0.1");
  port = r.result.port;
  assert.equal(await portOpen(port), true, "start answered before the inbound was listening");
  const t0 = Date.now();
  const up = await until(() => portOpen(port), 10000);
  console.log(`      (port ${port} became reachable after ${Date.now() - t0} ms: ${up})`);
  assert.ok(up);
});

await step("traffic through the local port reaches the VLESS+Reality server and out", async () => {
  const r = curlVia(port);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^\d+\.\d+\.\d+\.\d+$/);
  assert.ok(await until(() => /api\.ipify\.org/.test(serverLog), 5000), "server never saw the destination");
});

await step("the clear-text config is deleted once the core is up (nothing with the key stays in TEMP while running)", async () => {
  assert.ok(existsSync(hostWorkDir()), "work dir missing: " + hostWorkDir());
  assert.ok(await until(() => !readdirSync(hostWorkDir()).includes("config.json"), 5000), "config.json still on disk: " + readdirSync(hostWorkDir()));
});

await step("an unexpected core death is reported and the local port stays dead (no direct fallback)", async () => {
  const mine = procs().filter((p) => p.ExecutablePath && p.ExecutablePath.toLowerCase().includes("dist\\runet-access") && p.ParentProcessId === host.child.pid);
  assert.equal(mine.length, 1, "expected exactly one client core under the host");
  spawnSync("taskkill", ["/F", "/PID", String(mine[0].ProcessId)]);
  assert.ok(await until(() => host.events.some((e) => e.event === "state" && e.payload.running === false), 8000), "no state event");
  assert.equal(await portOpen(port), false, "local port still open");
  const r = curlVia(port);
  assert.notEqual(r.status, 0, "request succeeded without the core — would be a silent bypass");
});

await step("restart after the crash works (stable port reused when free)", async () => {
  const r = await host.req("start", { ...startPayload, inbound: { listen: "127.0.0.1", port } });
  assert.equal(r.ok, true);
  assert.equal(r.result.port, port);
  assert.equal(curlVia(port).status, 0);
});

await step("stop: port closed, no client core left", async () => {
  assert.equal((await host.req("stop")).ok, true);
  assert.equal(await portOpen(port), false, "port still open right after stop returned");
  assert.ok(await until(() => !procs().some((p) => p.ParentProcessId === host.child.pid), 5000));
});

await step("core self-update is disabled", async () => {
  const r = await host.req("updateCore");
  assert.equal(r.ok, false);
  assert.match(r.error, /disabled/);
});

await step("invalid profile: error text does not echo key material", async () => {
  const bad = { ...profile, tls: { ...profile.tls, reality: { ...profile.tls.reality, publicKey: "!!!notbase64!!!" } } };
  const r = await host.req("test", { profile: bad });
  assert.equal(r.ok, false);
  const text = JSON.stringify(r);
  for (const secret of [uuid, kp.PublicKey, sid]) assert.ok(!text.includes(secret), "error leaks a secret: " + text.slice(0, 200));
});

await step("graceful exit (stdin closed): host ends, work dir and config are removed", async () => {
  await host.req("start", startPayload);
  const dir = hostWorkDir(); assert.ok(existsSync(dir));
  host.child.stdin.end();
  await Promise.race([host.exited, sleep(8000)]);
  assert.ok(await until(() => !existsSync(dir), 5000), "work dir left behind: " + dir);
  assert.ok(!procs().some((p) => p.ExecutablePath && p.ExecutablePath.toLowerCase().includes("dist\\runet-access")), "client core left behind");
});

await step("hard kill of the host takes the core with it (Job Object)", async () => {
  host = startHost();
  const r = await host.req("start", startPayload); assert.equal(r.ok, true);
  const p = r.result.port; assert.ok(await until(() => portOpen(p), 10000), "core did not come up");
  spawnSync("taskkill", ["/F", "/PID", String(host.child.pid)]);
  assert.ok(await until(async () => !(await portOpen(p)), 6000), "core outlived the host");
  assert.ok(!procs().some((q) => q.ExecutablePath && q.ExecutablePath.toLowerCase().includes("dist\\runet-access")));
});

await step("wrong key is refused by the server (core starts, traffic does not pass)", async () => {
  host = startHost();
  const wrong = { ...profile, uuid: "99999999-9999-4999-8999-999999999999" };
  const r = await host.req("start", { ...startPayload, profile: wrong }); assert.equal(r.ok, true);
  const c = spawnSync("curl.exe", ["-sS", "--max-time", "12", "-x", `socks5h://127.0.0.1:${r.result.port}`, "https://api.ipify.org"], { encoding: "utf8" });
  assert.notEqual(c.status, 0, "traffic passed with a wrong UUID");
  await host.req("stop"); host.child.stdin.end(); await Promise.race([host.exited, sleep(5000)]);
});

server.kill();
await sleep(500);
// the synthetic server config holds the synthetic key; remove our own temp dir contents
for (const f of readdirSync(work)) { try { (await import("node:fs")).unlinkSync(join(work, f)); } catch {} }
try { (await import("node:fs")).rmdirSync(work); } catch {}
if (process.env.E2E_DEBUG) {
  console.log("--- host events:");
  for (const e of host.events) console.log(JSON.stringify(e).slice(0, 400));
  console.log("--- server log:\n" + serverLog.slice(-2500));
}
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
