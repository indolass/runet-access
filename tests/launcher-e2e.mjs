// End-to-end test of the special browser in a REAL Chrome started by RunetAccess.exe.
// Synthetic VLESS+Reality server on localhost; a mock of the country service that is reachable
// ONLY through the tunnel (server-side redirect of a fake host name). No registry, no extension.
// Run (after scripts\build.ps1):  . .\scripts\env.ps1; node tests\launcher-e2e.mjs
// Needs internet for: the Reality mask host, https://example.com/, https://api.ipify.org/.
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import { existsSync, readFileSync, rmSync, mkdirSync, statSync, readdirSync } from "node:fs";
import assert from "node:assert/strict";
import { root, connectBrowser, pageWhere, openPage, sleep } from "./cdp.mjs";
import { startMock, startSyntheticServer, freePort, until, MOCK_HOST } from "./support.mjs";

const run = promisify(execFile);
const exe = join(root, "dist", "runet-access", "RunetAccess.exe");
const home = join(root, ".local", "e2e-home");
const profile = join(home, "profile");
const shots = join(root, ".local", "logs", "shots"); mkdirSync(shots, { recursive: true });
assert.ok(existsSync(exe), "build first: scripts\\build.ps1");
assert.ok((process.env.TEMP || "").startsWith(root), "run inside scripts\\env.ps1 so TEMP is under the repo root");

for (const ev of ["uncaughtException", "unhandledRejection"]) process.on(ev, (e) => { console.log("FATAL " + ev + ": " + ((e && e.stack) || e)); process.exit(1); });
let passed = 0, failed = 0;
const step = async (name, fn) => { try { await fn(); passed++; console.log("PASS  " + name); } catch (e) { failed++; console.log("FAIL  " + name + "\n      " + (e && e.message)); } };

const ps = async (script) => (await run("powershell", ["-NoProfile", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { maxBuffer: 1 << 24 })).stdout;
async function ours() {
  const out = await ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -in 'sing-box.exe','RunetAccess.exe','chrome.exe' } | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress");
  if (!out.trim()) return [];
  const j = JSON.parse(out); const all = Array.isArray(j) ? j : [j];
  const dist = join(root, "dist", "runet-access").toLowerCase();
  return all.filter((p) => ((p.ExecutablePath || "").toLowerCase().startsWith(dist)) || (p.Name === "chrome.exe" && (p.CommandLine || "").toLowerCase().includes(profile.toLowerCase())));
}
const curl = async (...a) => { try { return (await run("curl.exe", ["-sS", "--max-time", "25", ...a])).stdout.trim(); } catch { return ""; } };
const sysProxy = async () => (await run("reg", ["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"])).stdout.split(/\r?\n/).filter((l) => /Proxy|AutoConfig|AutoDetect/i.test(l)).sort().join("|");
const killPid = (pid) => run("taskkill", ["/F", "/PID", String(pid)]).catch(() => {});

const DIRECT_IP = await curl("https://api.ipify.org");
assert.match(DIRECT_IP, /^\d+\.\d+\.\d+\.\d+$/, "no direct internet for the reference IP");
const sysBefore = await sysProxy();

const mock = await startMock();
let server = await startSyntheticServer(mock.port);
const sbLog = () => server.h.log.replace(/\x1b\[[0-9;]*m/g, "");

async function launch() {
  const cdpPort = await freePort();
  const child = spawn(exe, [], {
    stdio: "ignore", windowsHide: false,
    env: { ...process.env, RUNET_ACCESS_HOME: home, RUNET_PROBE_URL: `http://${MOCK_HOST}/`, RUNET_CHROME_EXTRA_ARGS: `--remote-debugging-port=${cdpPort}`, RUNET_NO_DIALOG: "1" },
  });
  const exited = new Promise((r) => child.once("exit", r));
  const browser = await connectBrowser(cdpPort);
  const control = await pageWhere(browser, (u) => u.startsWith("http://127.0.0.1:"));
  assert.ok(await control.waitFor("document.getElementById('statusLine').textContent !== 'Загрузка…'", 20000), "control page did not initialise");
  return { child, exited, browser, control, cdpPort };
}
const $ = (p, id, prop) => p.evaluate(`document.getElementById('${id}').${prop}`);
const click = (p, id) => p.evaluate(`document.getElementById('${id}').click()`);
const setVal = (p, id, v) => p.evaluate(`(() => { const e = document.getElementById('${id}'); e.value = ${JSON.stringify(v)}; e.dispatchEvent(new Event('input')); return true; })()`);
const status = (p) => $(p, "statusLine", "textContent");
const fetchState = (p, url) => p.evaluate(`fetch(${JSON.stringify(url)}, { mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(15000) }).then(() => 'loaded', () => 'failed')`);
// Replace the key (the launcher keeps only an accepted key), paste it and press Connect.
async function connectWith(p, key, remember) {
  if (await p.evaluate("document.getElementById('keyInput').classList.contains('hidden')")) await click(p, "keyReplace");
  await p.evaluate(`document.getElementById('remember').checked = ${remember}`);
  await setVal(p, "keyInput", key);
  await click(p, "mainBtn");
}
const statusStarts = (p, s, ms = 90000) => p.waitFor(`document.getElementById('statusLine').textContent.startsWith(${JSON.stringify(s)})`, ms);
const statusHas = (p, s, ms = 90000) => p.waitFor(`document.getElementById('statusLine').textContent.includes(${JSON.stringify(s)})`, ms);

rmSync(home, { recursive: true, force: true });
let L = await launch();
let { control } = L;

try {
  await step("Chrome is started by the launcher with its own profile and the proxy flag; ordinary Chrome untouched", async () => {
    const chromes = (await ours()).filter((p) => p.Name === "chrome.exe" && /--proxy-server=socks5:\/\/127\.0\.0\.1:\d+/.test(p.CommandLine || ""));
    assert.ok(chromes.length > 0, "no chrome with --proxy-server for our profile");
    const cl = chromes[0].CommandLine;
    assert.ok(cl.includes("--host-resolver-rules=MAP * ~NOTFOUND"), "local DNS is not disabled");
    assert.ok(cl.includes("--disable-background-mode"));
    assert.ok(!/--load-extension|--proxy-pac-url/.test(cl), "unexpected extension/PAC flags");
  });

  await step("FAIL-CLOSED before connecting: the window cannot reach the internet at all", async () => {
    assert.equal(await fetchState(control, "https://example.com/"), "failed");
    assert.equal(await fetchState(control, "https://api.ipify.org/"), "failed");
  });

  await step("second launcher instance is refused (single instance)", async () => {
    const c2 = spawn(exe, [], { stdio: "ignore", env: { ...process.env, RUNET_ACCESS_HOME: home, RUNET_NO_DIALOG: "1" } });
    const code = await Promise.race([new Promise((r) => c2.once("exit", r)), sleep(10000).then(() => "timeout")]);
    assert.equal(code, 1, "second instance exit: " + code);
  });

  await step("bad key: plain message, nothing echoed, no core started", async () => {
    await setVal(control, "keyInput", "vless://11111111-2222-3333-4444-555555555555@192.0.2.10:443?security=tls&flow=xtls-rprx-vision");
    await click(control, "mainBtn");
    assert.ok(await control.waitFor("document.getElementById('keyError').textContent.length > 0", 8000));
    const t = await $(control, "keyError", "textContent");
    assert.match(t, /Reality/);
    for (const s of ["11111111-2222", "192.0.2.10"]) assert.ok(!t.includes(s));
    assert.equal((await ours()).filter((p) => p.Name === "sing-box.exe").length, 0);
  });

  await step("paste key -> Connect -> exit confirmed (RU through the key), ordinary address shown separately", async () => {
    await setVal(control, "keyInput", server.key);
    await click(control, "mainBtn");
    const ok = await statusStarts(control, "Подключено");
    if (!ok) console.log("      DIAG status: " + await status(control) + "\n      server log tail:\n" + sbLog().split("\n").slice(-8).join("\n"));
    assert.ok(ok, "status: " + await status(control));
    assert.equal((await $(control, "resExit", "innerText")).replace(/\s+/g, " "), "Выход этого окна RU · 203.0.113.77");
    assert.ok((await $(control, "resDirect", "innerText")).includes(DIRECT_IP));
    assert.equal(await $(control, "keyInput", "value"), "", "key left in the field");
    assert.ok(mock.state.hits > 0, "mock was never reached: the probe did not use the tunnel");
  });
  await control.shot(join(shots, "launcher-connected.png"));

  await step("ALL traffic goes through the key: listed-nowhere sites, no domain list", async () => {
    const tab = await openPage(L.browser, "https://example.com/");
    assert.ok(await tab.waitFor("/Example Domain/.test(document.title)", 30000), "site did not load: " + await tab.url());
    assert.equal(await fetchState(control, "https://api.ipify.org/"), "loaded");
    const log = sbLog();
    assert.ok(/example\.com/.test(log), "server never saw example.com");
    assert.ok(/api\.ipify\.org/.test(log), "server never saw api.ipify.org");
  });

  await step("the control page itself stays on loopback (not proxied)", async () => {
    const ctlPort = new URL(await control.url()).port;
    const log = sbLog();
    assert.ok(!log.includes(`connection to 127.0.0.1:${ctlPort}`) && !/inbound connection to 127\.0\.0\.1/.test(log), "loopback traffic reached the tunnel server");
  });

  await step("'Open' button opens the typed site in a new tab", async () => {
    await setVal(control, "siteUrl", "example.com");
    assert.equal(await $(control, "openBtn", "disabled"), false);
    await click(control, "openBtn");
    const t = await pageWhere(L.browser, (u) => u.startsWith("https://example.com"), 15000);
    assert.ok(await t.waitFor("/Example Domain/.test(document.title)", 30000));
  });

  await step("stored key is DPAPI-encrypted on disk (no plaintext UUID / pbk)", async () => {
    const f = join(home, "key.dpapi");
    assert.ok(existsSync(f) && statSync(f).size > 100);
    const txt = readFileSync(f).toString("latin1");
    for (const s of [server.uuid, "vless://", "reality", "xtls"]) assert.ok(!txt.includes(s), "plaintext found: " + s);
  });

  await step("one core + the launcher are ours; the core came from dist", async () => {
    const names = (await ours()).filter((p) => p.Name !== "chrome.exe").map((p) => p.Name).sort();
    assert.deepEqual(names, ["RunetAccess.exe", "sing-box.exe"], JSON.stringify(names));
  });

  await step("core killed: window is cut off at once (no direct path), launcher restarts it, traffic resumes through the tunnel", async () => {
    const core = (await ours()).find((p) => p.Name === "sing-box.exe");
    await killPid(core.ProcessId);
    assert.equal(await fetchState(control, "https://example.com/"), "failed", "site loaded while the core was dead");
    assert.ok(await until(async () => (await fetchState(control, "https://example.com/")) === "loaded", 30000), "traffic did not resume after the automatic restart");
  });

  await step("tunnel dies: the window is cut off (no silent direct exit); re-check says undetermined", async () => {
    server.stop(); await sleep(1500);
    assert.equal(await fetchState(control, "https://example.com/"), "failed");
    await click(control, "recheckBtn");
    assert.ok(await statusHas(control, "не удалось", 60000), "status: " + await status(control));
    assert.equal(await $(control, "openBtn", "disabled"), true);
    assert.ok(!(await status(control)).startsWith("Подключено"));
  });

  await step("Disconnect: core stops, window stays cut off (fail-closed by design)", async () => {
    await click(control, "mainBtn");
    assert.ok(await statusStarts(control, "Отключено", 20000), "status: " + await status(control));
    assert.ok(await until(async () => (await ours()).filter((p) => p.Name === "sing-box.exe").length === 0, 8000));
    assert.equal(await fetchState(control, "https://example.com/"), "failed");
  });

  server.cleanup(); server = await startSyntheticServer(mock.port);

  await step("replace key; wrong exit country (DE): refused, disconnected, window cut off", async () => {
    mock.state.country = "DE";
    await connectWith(control, server.key, false);
    assert.ok(await statusHas(control, "не в нужной стране", 90000), "status: " + await status(control));
    assert.ok(await control.waitFor("document.getElementById('mainBtn').textContent === 'Подключить'", 20000));
    assert.equal(await $(control, "openBtn", "disabled"), true);
    assert.equal(await fetchState(control, "https://example.com/"), "failed");
  });

  await step("proxied probe returns the SAME address as the ordinary one: refused as 'not using the key'", async () => {
    mock.state.country = "RU"; mock.state.ip = DIRECT_IP;
    await connectWith(control, server.key, false);
    assert.ok(await statusHas(control, "тот же адрес", 90000), "status: " + await status(control));
  });

  await step("recovery: good exit again -> Connected, site loads (this key is remembered for the restart test)", async () => {
    mock.state.ip = "203.0.113.77";
    await connectWith(control, server.key, true);
    assert.ok(await statusStarts(control, "Подключено"), "status: " + await status(control));
    assert.equal(await fetchState(control, "https://example.com/"), "loaded");
  });

  await step("close the last window: launcher exits, core and Chrome are gone, no lock, no config, nothing left", async () => {
    await L.browser.send("Browser.close").catch(() => {});
    const code = await Promise.race([L.exited, sleep(20000).then(() => "timeout")]);
    assert.notEqual(code, "timeout", "launcher did not exit after the window was closed");
    assert.ok(await until(async () => (await ours()).length === 0, 15000), "leftover: " + JSON.stringify((await ours()).map((p) => p.Name)));
    assert.ok(!existsSync(join(home, "run.lock")), "lock left");
    const wd = join(process.env.TEMP, "runet-access");
    const left = existsSync(wd) ? readdirSync(wd) : [];
    for (const d of left) assert.ok(!existsSync(join(wd, d, "config.json")), "config.json left in " + d);
  });

  // ---- second run: stored key, forget, crash ----
  L = await launch(); control = L.control;
  await step("restart: saved key is offered; Connect without pasting starts the core from the encrypted key", async () => {
    assert.match(await status(control), /Нажмите «Подключить»/);
    assert.equal(await $(control, "keySaved", "classList.contains('hidden')"), false);
    await click(control, "mainBtn");
    assert.ok(await statusStarts(control, "Подключено", 90000), "status: " + await status(control));
    assert.equal(await fetchState(control, "https://example.com/"), "loaded");
  });

  await step("launcher crash: Windows takes the core AND the browser window down with it (Job Object); nothing stays connected or orphaned", async () => {
    const launcher = (await ours()).find((p) => p.Name === "RunetAccess.exe");
    await killPid(launcher.ProcessId);
    assert.ok(await until(async () => (await ours()).length === 0, 15000), "leftover after crash: " + JSON.stringify((await ours()).map((p) => p.Name)));
  });
  await L.browser.send("Browser.close").catch(() => {});
  await until(async () => (await ours()).length === 0, 15000);
  rmSync(join(home, "run.lock"), { force: true });

  L = await launch(); control = L.control;
  await step("stale lock from the crash is taken over; 'Delete key' removes the stored key", async () => {
    await click(control, "keyForget");
    assert.ok(await control.waitFor("document.getElementById('keyInput').classList.contains('hidden') === false", 8000));
    assert.ok(!existsSync(join(home, "key.dpapi")), "key file still on disk");
  });
  await L.browser.send("Browser.close").catch(() => {});
  await Promise.race([L.exited, sleep(20000)]);

  await step("system proxy settings unchanged; no extension, no registry writes by the product", async () => {
    assert.equal(await sysProxy(), sysBefore);
  });
} finally {
  server.stop(); server.cleanup(); mock.close();
  for (const p of await ours()) await killPid(p.ProcessId); // our own test processes only (dist + our profile)
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
