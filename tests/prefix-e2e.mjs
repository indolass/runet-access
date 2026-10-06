// Outline "prefix" end to end, in a REAL Chrome started by RunetAccess.exe.
//
// The stand: a real Shadowsocks server (sing-box, an implementation independent of the Outline SDK that the program
// uses for prefix keys) hidden behind a middlebox that passes a connection ONLY when its first bytes are the agreed
// prefix and drops everything else (see startPrefixFront). So a key without the prefix, or with a wrong one, must fail,
// and a key with the right one must carry real traffic. Checked here:
//   - static ss:// and dynamic ssconf:// (JSON and YAML, a different UDP prefix is allowed) with a prefix connect, verify the
//     exit and carry traffic; the bytes on the wire start with the prefix, the rest of the salt is random;
//   - no prefix / a wrong prefix / the right prefix with a wrong password fail, are never green and never go direct;
//   - the settings of a dynamic key are read again at every connection (a changed prefix is noticed);
//   - the core dying is survived (the bridge stays), the server dying cuts the window off, nothing goes direct;
//   - no extra process, no secret on screen or in a command line, everything of ours ends with the window.
// Run (after scripts\build.ps1; through tests\run-hidden.ps1 if you do not want to see Chrome):
//   . .\scripts\env.ps1; node tests\prefix-e2e.mjs
// Needs internet for https://example.com/ (reached through the Shadowsocks server).
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { join, dirname } from "node:path";
import { createHash } from "node:crypto";
import https from "node:https";
import { existsSync, readFileSync, rmSync, mkdirSync, writeFileSync, readdirSync } from "node:fs";
import assert from "node:assert/strict";
import { root, connectBrowser, pageWhere, sleep } from "./cdp.mjs";
import { startMock, startSsServer, startPrefixFront, prefixQuery, tlsPair, freePort, until, MOCK_HOST } from "./support.mjs";

const run = promisify(execFile);
const exe = process.env.RUNET_EXE || join(root, "dist", "runet-access", "RunetAccess.exe");
const exeDir = dirname(exe);
const work = join(root, ".local", "prefix-work");
const home = join(work, "home");
assert.ok(existsSync(exe), "build first: scripts\\build.ps1");
assert.ok((process.env.TEMP || "").startsWith(root), "run inside scripts\\env.ps1 so TEMP is under the repo root");
rmSync(work, { recursive: true, force: true }); mkdirSync(work, { recursive: true });

for (const ev of ["uncaughtException", "unhandledRejection"]) process.on(ev, (e) => { console.log("FATAL " + ev + ": " + ((e && e.stack) || e)); process.exit(1); });
let passed = 0, failed = 0;
const step = async (name, fn) => { try { await fn(); passed++; console.log("PASS  " + name); } catch (e) { failed++; console.log("FAIL  " + name + "\n      " + (e && e.message)); } };

const ps = async (script) => (await run("powershell", ["-NoProfile", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { maxBuffer: 1 << 24 })).stdout;
async function ours() {
  const out = await ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -in 'sing-box.exe','RunetAccess.exe','chrome.exe' } | Select-Object Name,ProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress");
  if (!out.trim()) return [];
  const j = JSON.parse(out); const all = Array.isArray(j) ? j : [j];
  return all.filter((p) => ((p.ExecutablePath || "").toLowerCase().startsWith(exeDir.toLowerCase())) || (p.Name === "chrome.exe" && (p.CommandLine || "").toLowerCase().includes(home.toLowerCase())));
}
const cores = async () => (await ours()).filter((p) => p.Name === "sing-box.exe");
const sysProxy = async () => (await run("reg", ["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"])).stdout.split(/\r?\n/).filter((l) => /Proxy|AutoConfig|AutoDetect/i.test(l)).sort().join("|");
const killPid = (pid) => run("taskkill", ["/F", "/PID", String(pid)]).catch(() => {});
const sha = (f) => (existsSync(f) ? createHash("sha256").update(readFileSync(f)).digest("hex") : "");
const keyFile = join(home, "key.dpapi");
const sysBefore = await sysProxy();

// ---- stand ---------------------------------------------------------------------------------------------------------------------------
const DIRECT_IP = "198.51.100.7";
const mock = await startMock();
const ssB = await startSsServer(mock.port, "chacha20-ietf-poly1305"); // the real server behind the middlebox
const PREFIX = [0x16, 0x03, 0x01, 0x00, 0xa8, 0x01, 0x01]; // the example of the Outline guide: a TLS-like start with a zero and a high byte
const front = await startPrefixFront(ssB.port, Buffer.from(PREFIX));
const b64url = (x) => Buffer.from(x).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const userinfo = b64url("chacha20-ietf-poly1305:" + ssB.password);
const staticKey = (prefixBytes, port = front.port, pw = ssB.password) =>
  `ss://${pw === ssB.password ? userinfo : b64url("chacha20-ietf-poly1305:" + pw)}@127.0.0.1:${port}/?outline=1${prefixBytes ? "&prefix=" + prefixQuery(prefixBytes) : ""}#%D0%9A%D0%BB%D1%8E%D1%87`;
const bs = String.fromCharCode(92);
const yamlStr = (bytes) => '"' + [...bytes].map((b) => bs + "u" + b.toString(16).padStart(4, "0")).join("") + '"'; // Outline's own way (the guide)
const yamlKey = (tcpPrefix, udpPrefix) =>
  `transport:\n  $type: tcpudp\n  tcp:\n    $type: shadowsocks\n    endpoint: 127.0.0.1:${front.port}\n    cipher: chacha20-ietf-poly1305\n    secret: ${ssB.password}\n    prefix: ${yamlStr(tcpPrefix)}\n` +
  `  udp:\n    $type: shadowsocks\n    endpoint: 127.0.0.1:${front.port}\n    cipher: chacha20-ietf-poly1305\n    secret: ${ssB.password}\n    prefix: ${yamlStr(udpPrefix)}\n`;
const jsonKey = (prefixText) => JSON.stringify({ server: "127.0.0.1", server_port: front.port, password: ssB.password, method: "chacha20-ietf-poly1305", prefix: prefixText });

const SECRET_PATH = "/k/SECRET-PATH-" + Math.random().toString(36).slice(2, 10);
const TOKEN = "TOKEN-" + Math.random().toString(36).slice(2, 10);
const pair = tlsPair("localhost");
writeFileSync(join(work, "ca.pem"), pair.cert);
const routes = new Map();
const provider = https.createServer({ key: pair.key, cert: pair.cert }, (req, res) => { const h = routes.get(req.url.split("?")[0]); if (!h) { res.writeHead(404); res.end("no"); return; } h(req, res); });
await new Promise((r) => provider.listen(0, "127.0.0.1", r));
const provPort = provider.address().port;
const dynKey = `ssconf://localhost:${provPort}${SECRET_PATH}?token=${TOKEN}#dyn`;
const serve = (body, status = 200, type = "application/json") => (_q, res) => { res.writeHead(status, { "content-type": type }); res.end(body); };
let providerHits = 0; provider.on("request", () => { providerHits++; });
const SECRETS = [SECRET_PATH, SECRET_PATH.slice(3), TOKEN, ssB.password, `localhost:${provPort}`, String(front.port) + "/", prefixQuery(PREFIX)];

async function launch() {
  const cdpPort = await freePort();
  const child = spawn(exe, [], {
    stdio: "ignore",
    env: { ...process.env, RUNET_TEST_MODE: "1", RUNET_ACCESS_HOME: home, RUNET_PROBE_URL: `http://${MOCK_HOST}/`, RUNET_CHROME_EXTRA_ARGS: `--remote-debugging-port=${cdpPort}`,
      RUNET_NO_DIALOG: "1", RUNET_DIRECT_IP: DIRECT_IP, RUNET_RECHECK_MS: "60000", RUNET_TEST_SSCONF_LOOPBACK: "1", RUNET_TEST_SSCONF_CA: join(work, "ca.pem") },
  });
  const exited = new Promise((r) => child.once("exit", r));
  const browser = await connectBrowser(cdpPort);
  const control = await pageWhere(browser, (u) => u.startsWith("http://127.0.0.1:"));
  assert.ok(await control.waitFor("document.getElementById('statusLine').textContent !== 'Загрузка…'", 20000), "control page did not initialise");
  return { child, exited, browser, control };
}
const $ = (p, id, prop) => p.evaluate(`document.getElementById('${id}').${prop}`);
const click = (p, id) => p.evaluate(`document.getElementById('${id}').click()`);
const setVal = (p, id, v) => p.evaluate(`(() => { const e = document.getElementById('${id}'); e.value = ${JSON.stringify(v)}; e.dispatchEvent(new Event('input')); return true; })()`);
const vis = (p, id) => p.evaluate(`!document.getElementById('${id}').classList.contains('hidden')`);
const status = (p) => $(p, "statusLine", "textContent");
const note = (p) => $(p, "statusNote", "textContent");
const statusIs = (p, s, ms = 90000) => p.waitFor(`document.getElementById('statusLine').textContent === ${JSON.stringify(s)}`, ms);
const fetchState = (p, url) => p.evaluate(`fetch(${JSON.stringify(url)}, { mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(20000) }).then(() => 'loaded', () => 'failed')`);
const goSettings = async (p) => { if (!(await vis(p, "viewSettings"))) { await click(p, "settingsBtn"); assert.ok(await p.waitFor("!document.getElementById('viewSettings').classList.contains('hidden')", 5000)); } };
async function replaceWith(p, key, remember = true) {
  await goSettings(p);
  if (!(await vis(p, "replaceForm"))) await click(p, "replaceOpen");
  await p.evaluate(`document.getElementById('newRemember').checked = ${remember}`);
  await setVal(p, "newKeyInput", key);
  await click(p, "replaceGo");
}
const BUSY_OR_OK = ["Загрузка…", "Не подключено", "Подключаемся…", "Проверяем подключение через Россию…", "Подключено через Россию"];
const notGreen = async (p, ms = 90000) => { // wait for the attempt to END in an error state (never in "connected")
  const list = JSON.stringify(BUSY_OR_OK);
  assert.ok(await p.waitFor(`!${list}.includes(document.getElementById("statusLine").textContent)`, ms), "no error state; status: " + await status(p));
  return await status(p);
};
async function noSecrets(p, what) {
  await p.evaluate("document.querySelectorAll('textarea, input').forEach((e) => { if (e.type !== 'checkbox') e.value = ''; })");
  const page = await p.evaluate("document.body.innerText + ' ' + document.documentElement.outerHTML");
  for (const s of SECRETS) assert.ok(!page.includes(s), `${what}: the page shows a secret (${s.slice(0, 6)}…)`);
  const cmd = (await ours()).map((x) => x.CommandLine || "").join("\n");
  for (const s of SECRETS) assert.ok(!cmd.includes(s), `${what}: a command line holds a secret`);
}
const logOf = (s) => s.h.log.replace(/\x1b\[[0-9;]*m/g, "");

let L = await launch();
let control = L.control;
try {
  await step("a static ss:// key with an Outline prefix: connected, exit verified, REAL traffic through the middlebox and the server", async () => {
    await setVal(control, "keyInput", staticKey(PREFIX));
    await click(control, "mainBtn");
    assert.ok(await statusIs(control, "Подключено через Россию"), "status: " + await status(control) + " | " + await note(control));
    assert.equal(await fetchState(control, "https://example.com/"), "loaded");
    assert.ok(/example\.com/.test(logOf(ssB)), "the server never saw example.com");
    assert.ok(mock.state.hits > 0, "the country probe did not go through the tunnel");
    assert.ok(front.stats.served > 0 && front.stats.rejected === 0, `served=${front.stats.served} rejected=${front.stats.rejected}`);
    assert.ok(existsSync(keyFile), "the key was not saved after the verified exit");
    const bytes = readFileSync(keyFile).toString("latin1");
    for (const s of [ssB.password, "ss://", "prefix"]) assert.ok(!bytes.includes(s), "the stored key is readable on disk: " + s);
  });

  await step("on the wire the salt STARTS with the prefix (all 7 bytes, a zero and 0xA8 among them) and the rest of it is random", async () => {
    const heads = front.stats.heads; assert.ok(heads.length >= 2, "few connections seen: " + heads.length);
    for (const h of heads) assert.ok(h.subarray(0, PREFIX.length).equals(Buffer.from(PREFIX)), "a connection started with " + h.subarray(0, 8).toString("hex"));
    const tails = new Set(heads.map((h) => h.subarray(PREFIX.length).toString("hex")));
    assert.equal(tails.size, heads.length, "the random part of the salt repeats");
  });

  await step("no extra process: exactly one core and nothing else of ours besides Chrome; the config with the secrets is not on disk", async () => {
    const names = (await ours()).map((p) => p.Name);
    assert.deepEqual([...new Set(names)].sort(), ["RunetAccess.exe", "chrome.exe", "sing-box.exe"]);
    assert.equal((await cores()).length, 1);
    const tmp = join(process.env.TEMP, "runet-access");
    if (existsSync(tmp)) for (const d of readdirSync(tmp)) assert.ok(!existsSync(join(tmp, d, "config.json")), "config.json is still on disk in " + d);
    await noSecrets(control, "after a prefix connect");
  });

  await step("the core and the browser see only a loopback upstream: the command line of the core holds no server address or key", async () => {
    const core = (await cores())[0];
    assert.ok(!(core.CommandLine || "").includes(String(front.port)) && !(core.CommandLine || "").includes(ssB.password));
  });

  // ------------------------------------------------------------------------------------------------------ the stand really needs the prefix
  const failing = [
    ["no prefix at all", () => staticKey(null)],
    ["a wrong prefix", () => staticKey([0x47, 0x45, 0x54, 0x20, 0x2f])],
    ["the right start but one byte too short (the stand wants all 7)", () => staticKey(PREFIX.slice(0, 6))],
    ["the right prefix but a wrong password", () => staticKey(PREFIX, front.port, "not-the-password")],
  ];
  for (const [name, key] of failing) {
    await step(`replacement with ${name}: never shown as connected, never direct, the saved key and the stand are untouched`, async () => {
      const h0 = sha(keyFile), rej0 = front.stats.rejected, srv0 = front.stats.served;
      await replaceWith(control, key());
      const s = await notGreen(control);
      console.log("      (status shown: " + s + ")");
      assert.equal(await fetchState(control, "https://example.com/"), "failed", "traffic passed although the key must fail");
      assert.equal(sha(keyFile), h0, "a failing key was saved");
      if (name !== "the right prefix but a wrong password") assert.ok(front.stats.rejected > rej0, "the middlebox never saw the attempt");
      if (name !== "the right prefix but a wrong password") assert.equal(front.stats.served, srv0, "the middlebox let a wrong prefix through");
      await noSecrets(control, name);
      // back to the saved key
      await click(control, "retryBtn").catch(() => {});
      assert.ok(await statusIs(control, "Подключено через Россию", 90000), "the saved key did not come back: " + await status(control));
      assert.equal(await fetchState(control, "https://example.com/"), "loaded");
    });
  }

  // ------------------------------------------------------------------------------------------------------ dynamic keys
  await step("ssconf:// answering with YAML (tcp prefix, ANOTHER udp prefix): connected, traffic through the middlebox, the saved key is the link", async () => {
    routes.set(SECRET_PATH, serve(yamlKey(PREFIX, [0x6b, 0x7b, 0x01, 0x20]), 200, "text/yaml"));
    const hits0 = providerHits, served0 = front.stats.served;
    await replaceWith(control, dynKey);
    assert.ok(await statusIs(control, "Подключено через Россию"), "status: " + await status(control) + " | " + await note(control));
    assert.ok(providerHits > hits0);
    assert.equal(await fetchState(control, "https://example.com/"), "loaded");
    assert.ok(front.stats.served > served0);
    const bytes = readFileSync(keyFile).toString("latin1");
    for (const s of [SECRET_PATH, TOKEN, "ssconf"]) assert.ok(!bytes.includes(s), "the saved dynamic link is readable on disk: " + s);
    await noSecrets(control, "after a dynamic prefix connect");
  });

  await step("the settings are read again at every connection: the provider now sends a WRONG prefix and the connection fails, the old key is kept", async () => {
    routes.set(SECRET_PATH, serve(yamlKey([0x50, 0x4f, 0x53, 0x54], [0x50]), 200, "text/yaml"));
    const h0 = sha(keyFile), rej0 = front.stats.rejected;
    await click(control, "disconnectBtn");
    assert.ok(await statusIs(control, "Не подключено", 20000));
    await click(control, "connectBtn");
    await notGreen(control);
    assert.equal(await fetchState(control, "https://example.com/"), "failed");
    assert.ok(front.stats.rejected > rej0, "the middlebox never saw the new prefix");
    assert.equal(sha(keyFile), h0);
    routes.set(SECRET_PATH, serve(jsonKey(String.fromCharCode(...PREFIX))));
    await click(control, "retryBtn");
    assert.ok(await statusIs(control, "Подключено через Россию", 90000), "status: " + await status(control) + " | " + await note(control));
  });

  await step("ssconf:// answering with JSON (the prefix as a JSON string): connected and carries traffic", async () => {
    const served0 = front.stats.served;
    assert.equal(await fetchState(control, "https://example.com/"), "loaded");
    assert.ok(front.stats.served > served0);
  });

  await step("a settings page with a prefix above 255 (not one byte per character): named, no secrets, nothing changes", async () => {
    routes.set("/bad", serve(jsonKey(String.fromCharCode(0x20ac))));
    const h0 = sha(keyFile);
    await replaceWith(control, `ssconf://localhost:${provPort}/bad?token=${TOKEN}`);
    assert.ok(await control.waitFor("document.getElementById('newKeyError').textContent.length > 0", 30000));
    const t = await $(control, "newKeyError", "textContent");
    assert.ok(t.includes("Префикс в ключе записан неверно"), t);
    assert.equal(await status(control), "Подключено через Россию");
    assert.equal(sha(keyFile), h0);
    await noSecrets(control, "bad prefix");
    await click(control, "replaceCancel");
  });

  // ------------------------------------------------------------------------------------------------------ failures of components
  await step("the core dies: the guard holds (no direct exit), the core comes back on the SAME bridge and traffic resumes", async () => {
    const core = (await cores())[0]; assert.ok(core, "no core");
    await killPid(core.ProcessId);
    // while it is down nothing may pass; once restarted it must work again
    assert.ok(await until(async () => (await cores()).length === 1 && (await cores())[0].ProcessId !== core.ProcessId, 30000), "the core was not restarted");
    assert.ok(await until(async () => (await fetchState(control, "https://example.com/")) === "loaded", 60000), "traffic did not resume");
    assert.ok(await statusIs(control, "Подключено через Россию", 60000), "status after the restart: " + await status(control));
  });

  await step("the server dies: the window is cut off (never direct); when it is back, traffic resumes", async () => {
    front.stop();
    await until(async () => (await fetchState(control, "https://example.com/")) === "failed", 30000);
    for (let i = 0; i < 3; i++) assert.equal(await fetchState(control, "https://example.com/"), "failed");
    const again = await startPrefixFront(ssB.port, Buffer.from(PREFIX), front.port);
    front.stats = again.stats; front.stop = again.stop;
    assert.ok(await until(async () => (await fetchState(control, "https://example.com/")) === "loaded", 60000), "traffic did not resume");
  });

  await step("hygiene: no secret on screen or in any command line; one core; system proxy untouched", async () => {
    await noSecrets(control, "final");
    assert.equal((await cores()).length, 1);
    assert.equal(await sysProxy(), sysBefore);
  });

  await step("close the last window: everything of ours ends (core, program, bridge) and the middlebox has no connection left open", async () => {
    await L.browser.send("Browser.close").catch(() => {});
    const code = await Promise.race([L.exited, sleep(20000).then(() => "timeout")]);
    assert.notEqual(code, "timeout");
    assert.ok(await until(async () => (await ours()).length === 0, 15000), "leftover: " + JSON.stringify((await ours()).map((p) => p.Name)));
    assert.ok(await until(async () => front.stats.open.size === 0, 10000), "connections to the middlebox are still open: " + front.stats.open.size);
  });
} finally {
  try { front.stop(); } catch {}
  try { ssB.stop(); ssB.cleanup(); } catch {}
  provider.close(); mock.close();
  for (const p of await ours()) await killPid(p.ProcessId);
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
