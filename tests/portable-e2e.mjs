// The ONE-FILE portable exe, as a friend would run it: a folder that holds nothing but the exe (path with spaces and
// Cyrillic), a working directory elsewhere, no development tools on PATH. Everything the program writes goes to a
// throw-away %LOCALAPPDATA% (the variable is redirected for the program only, so the real data of the owner is never
// touched). Real Chrome (CDP), a real Shadowsocks server (sing-box) on loopback and the country-check mock.
//   - unpack + verify of the components, the core is locked while running, a second start is refused;
//   - data survive close and a second start (saved key via DPAPI, no new unpacking);
//   - a modified / deleted component is repaired from the exe; a read-only exe folder is fine;
//   - an ORDINARY start (no test variables) finds Chrome and starts our window;
//   - no registration (uninstall entry, shortcuts), no system proxy change, nothing left running after closing;
//   - "--licenses" opens the unpacked licence folder, with the sing-box source archive.
// Run (after scripts\make-portable.ps1; through tests\run-hidden.ps1 to keep the windows off the screen):
//   . .\scripts\env.ps1; node tests\portable-e2e.mjs
import { spawn, execFile, spawnSync } from "node:child_process";
import { promisify } from "node:util";
import { join, dirname } from "node:path";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync, mkdirSync, copyFileSync, readdirSync, statSync, appendFileSync, openSync, closeSync, unlinkSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import { root, connectBrowser, pageWhere, sleep } from "./cdp.mjs";
import { startMock, startSsServer, freePort, until, MOCK_HOST } from "./support.mjs";

const run = promisify(execFile);
const version = readFileSync(join(root, "VERSION"), "utf8").trim();
const built = process.env.RUNET_EXE || join(root, "dist", "portable", `RunetAccess-Portable-${version}.exe`);
const work = join(root, ".local", "portable-work");
const cyr = (cps) => String.fromCharCode(...cps);
const folder = join(work, `${cyr([0x41f, 0x430, 0x43f, 0x43a, 0x430])} s probelami`, cyr([0x41e, 0x434, 0x438, 0x43d, 0x20, 0x444, 0x430, 0x439, 0x43b])); // "Papka s probelami\Odin fail"
const exe = join(folder, `RunetAccess-Portable-${version}.exe`);
const local = join(work, "local"); // the redirected %LOCALAPPDATA%
const data = join(local, "RunetAccess");
const elsewhere = join(work, "cwd-elsewhere");
assert.ok(existsSync(built), "build first: scripts\\make-portable.ps1");
assert.ok((process.env.TEMP || "").startsWith(root), "run inside scripts\\env.ps1 so TEMP is under the repo root");
assert.ok(work.startsWith(root));
rmSync(work, { recursive: true, force: true });
for (const d of [folder, local, elsewhere]) mkdirSync(d, { recursive: true });
copyFileSync(built, exe);
const pinnedCore = createHash("sha256").update(readFileSync(join(root, ".local", "tools", "sing-box", "sing-box.exe"))).digest("hex");
const lock = JSON.parse(readFileSync(join(root, "scripts", "tools.lock.json"), "utf8"));

for (const ev of ["uncaughtException", "unhandledRejection"]) process.on(ev, (e) => { console.log("FATAL " + ev + ": " + ((e && e.stack) || e)); process.exit(1); });
let passed = 0, failed = 0;
const step = async (name, fn) => { try { await fn(); passed++; console.log("PASS  " + name); } catch (e) { failed++; console.log("FAIL  " + name + "\n      " + (e && e.message)); } };

const ps = async (script) => (await run("powershell", ["-NoProfile", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { maxBuffer: 1 << 24 })).stdout;
async function ours() { // our program, its core and our Chrome windows (found by where they live, never by name alone)
  const out = await ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'RunetAccess*.exe' -or $_.Name -in 'sing-box.exe','chrome.exe' } | Select-Object Name,ProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress");
  if (!out.trim()) return [];
  const j = JSON.parse(out); const all = Array.isArray(j) ? j : [j];
  const under = (p, d) => (p || "").toLowerCase().startsWith(d.toLowerCase());
  return all.filter((p) => under(p.ExecutablePath, folder) || under(p.ExecutablePath, data) || (p.Name === "chrome.exe" && (p.CommandLine || "").toLowerCase().includes(data.toLowerCase())));
}
const cores = async () => (await ours()).filter((p) => p.Name === "sing-box.exe");
const killPid = (pid) => run("taskkill", ["/F", "/T", "/PID", String(pid)]).catch(() => {});
const sysProxy = async () => (await run("reg", ["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"])).stdout.split(/\r?\n/).filter((l) => /Proxy|AutoConfig|AutoDetect/i.test(l)).sort().join("|");
const uninstallKeys = async () => (await ps("(Get-ChildItem 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName } | Sort-Object) -join '|'")).trim();
const shortcuts = async () => (await ps("$d = [Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('CommonDesktopDirectory'), [Environment]::GetFolderPath('Programs'), [Environment]::GetFolderPath('CommonPrograms'); (Get-ChildItem -Path $d -Recurse -Filter '*.lnk' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*unet*' } | ForEach-Object { $_.FullName }) -join '|'")).trim();
const sha = (f) => createHash("sha256").update(readFileSync(f)).digest("hex");
const keyFile = join(data, "key.dpapi");
const compDir = () => { const b = join(data, "components"); const d = existsSync(b) ? readdirSync(b) : []; return d.length === 1 ? join(b, d[0]) : null; };
const coreFile = () => join(compDir() || join(data, "components", "none"), "sing-box.exe");

const before = { proxy: await sysProxy(), uninstall: await uninstallKeys(), lnk: await shortcuts() };

const mock = await startMock();
const ssA = await startSsServer(mock.port, "chacha20-ietf-poly1305");
const DIRECT_IP = "198.51.100.7";
const minimalPath = `${process.env.SystemRoot}\\System32;${process.env.SystemRoot}`; // no Go / Node / Python / Git on PATH
const baseEnv = (extra = {}) => {
  const env = { ...process.env, LOCALAPPDATA: local, PATH: minimalPath, Path: minimalPath, ...extra };
  delete env.RUNET_ACCESS_HOME; delete env.GOROOT; delete env.GOPATH;
  return env;
};
async function launch(extraEnv = {}) {
  const cdpPort = await freePort();
  const child = spawn(exe, [], {
    cwd: elsewhere, stdio: "ignore",
    env: baseEnv({ RUNET_TEST_MODE: "1", RUNET_PROBE_URL: `http://${MOCK_HOST}/`, RUNET_CHROME_EXTRA_ARGS: `--remote-debugging-port=${cdpPort}`, RUNET_NO_DIALOG: "1", RUNET_DIRECT_IP: DIRECT_IP, RUNET_RECHECK_MS: "60000", ...extraEnv }),
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
const status = (p) => $(p, "statusLine", "textContent");
const statusIs = (p, s, ms = 90000) => p.waitFor(`document.getElementById('statusLine').textContent === ${JSON.stringify(s)}`, ms);
const fetchState = (p, url) => p.evaluate(`fetch(${JSON.stringify(url)}, { mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(20000) }).then(() => 'loaded', () => 'failed')`);
async function closeApp(L) {
  await L.browser.send("Browser.close").catch(() => {});
  const code = await Promise.race([L.exited, sleep(20000).then(() => "timeout")]);
  assert.notEqual(code, "timeout", "the program did not exit after the window was closed");
  assert.ok(await until(async () => (await ours()).length === 0, 15000), "leftover: " + JSON.stringify((await ours()).map((p) => p.Name)));
}

let L = null;
try {
  await step("a folder with ONLY the exe (spaces and Cyrillic in the path), started from another working directory, no dev tools on PATH: the window comes up", async () => {
    assert.deepEqual(readdirSync(folder), [`RunetAccess-Portable-${version}.exe`]);
    assert.ok(/\s/.test(folder) && /[Ѐ-ӿ]/.test(folder), "the test path must contain spaces and Cyrillic");
    L = await launch();
    assert.equal(await status(L.control), "Не подключено");
  });

  await step("the components are unpacked into the program's own data folder and match the pinned release; nothing is written next to the exe", async () => {
    const cd = compDir(); assert.ok(cd, "no single components folder");
    assert.ok(/^[0-9a-f]{16}$/.test(cd.split("\\").pop()));
    assert.equal(sha(coreFile()), pinnedCore, "unpacked core is not the pinned sing-box");
    const lic = join(cd, "licenses");
    for (const f of ["LICENSE.txt", "THIRD_PARTY.txt", "BUILD-INFO.txt", "go-modules.txt", "OutlineSDK/LICENSE.txt", "go-shadowsocks2/LICENSE.txt", "golang-x/LICENSE.txt", "sing-box/GPL-3.0.txt", "sing-box/SOURCE-OFFER.txt", "sing-box/SOURCE-INFO.txt"]) assert.ok(existsSync(join(lic, f)), "missing licence file " + f);
    assert.equal(sha(join(lic, "sing-box", "sing-box-1.13.16-source.tar.gz")), lock["sing-box-source"].sha256, "the source archive is not the pinned one");
    assert.ok(/portable/.test(readFileSync(join(lic, "BUILD-INFO.txt"), "utf8")));
    assert.deepEqual(readdirSync(folder), [`RunetAccess-Portable-${version}.exe`], "something was written next to the exe");
  });

  await step("no registration: no uninstall entry, no shortcuts, system proxy untouched; the data folder holds only the program's own entries", async () => {
    assert.equal(await uninstallKeys(), before.uninstall);
    assert.equal(await shortcuts(), before.lnk);
    assert.equal(await sysProxy(), before.proxy);
    const names = readdirSync(data).sort();
    for (const n of names) assert.ok(["components", "profile", "run.lock", "key.dpapi", "chrome-path.txt"].includes(n), "unexpected entry in the data folder: " + n);
  });

  await step("connection through the new packaging: key typed, exit RU verified, REAL traffic crosses the server, the core runs from the unpacked copy", async () => {
    await setVal(L.control, "keyInput", ssA.key);
    await click(L.control, "mainBtn");
    assert.ok(await statusIs(L.control, "Подключено через Россию"), "status: " + await status(L.control));
    assert.equal(await fetchState(L.control, "https://example.com/"), "loaded");
    assert.ok(/example\.com/.test(ssA.h.log.replace(/\x1b\[[0-9;]*m/g, "")), "the server never saw example.com");
    const cs = await cores(); assert.equal(cs.length, 1);
    assert.ok(cs[0].ExecutablePath.toLowerCase() === coreFile().toLowerCase(), "the core runs from somewhere else: " + cs[0].ExecutablePath);
    assert.ok(!(cs[0].CommandLine || "").includes(ssA.password));
    assert.ok(existsSync(keyFile), "the key was not saved after the verified exit");
    assert.ok(!readFileSync(keyFile).toString("latin1").includes(ssA.password), "the saved key is readable on disk");
  });

  await step("while it runs the core file cannot be modified, deleted or renamed (it is locked); a second start is refused and starts nothing", async () => {
    const core = coreFile();
    assert.throws(() => closeSync(openSync(core, "r+")), "opened for writing");
    assert.throws(() => unlinkSync(core), "deleted");
    assert.throws(() => appendFileSync(core, "x"), "appended");
    const ownProcs = async () => (await ours()).filter((p) => p.Name !== "chrome.exe").length; // Chrome spawns and ends helper processes by itself
    const n0 = await ownProcs();
    const second = spawn(exe, [], { cwd: elsewhere, stdio: "ignore", env: baseEnv({ RUNET_NO_DIALOG: "1" }) });
    const code = await Promise.race([new Promise((r) => second.once("exit", r)), sleep(20000).then(() => "timeout")]);
    assert.equal(code, 1, "the second copy did not refuse to start (exit " + code + ")");
    assert.equal(await ownProcs(), n0, "the second start left processes behind");
    assert.equal(await status(L.control), "Подключено через Россию");
  });

  await step("close the last window: everything of ours ends, the data stay", async () => {
    await closeApp(L); L = null;
    assert.ok(existsSync(keyFile) && existsSync(join(data, "profile")) && compDir());
  });

  let birth;
  await step("second start: the saved key is there (nothing to re-enter), connects; the components are NOT unpacked again", async () => {
    birth = statSync(coreFile()).birthtimeMs;
    L = await launch();
    assert.ok(await $(L.control, "connectBtn", "offsetParent !== null"), "no Connect button for the saved key; status: " + await status(L.control));
    await click(L.control, "connectBtn");
    assert.ok(await statusIs(L.control, "Подключено через Россию"), "status: " + await status(L.control));
    assert.equal(await fetchState(L.control, "https://example.com/"), "loaded");
    assert.equal(statSync(coreFile()).birthtimeMs, birth, "the core was unpacked again although it was fine");
    await closeApp(L); L = null;
  });

  await step("a MODIFIED core is repaired from the exe at the next start (and works); nothing damaged is left aside", async () => {
    appendFileSync(coreFile(), "tampered");
    assert.notEqual(sha(coreFile()), pinnedCore);
    L = await launch();
    assert.equal(sha(coreFile()), pinnedCore, "the modified core was not replaced");
    await click(L.control, "connectBtn");
    assert.ok(await statusIs(L.control, "Подключено через Россию"), "status: " + await status(L.control));
    assert.equal(readdirSync(join(data, "components")).length, 1, "left-overs in components");
    await closeApp(L); L = null;
  });

  await step("a DELETED licence file and a DELETED components folder are both restored", async () => {
    const lic = join(compDir(), "licenses", "sing-box", "GPL-3.0.txt");
    rmSync(lic);
    L = await launch(); assert.ok(existsSync(lic), "licence file not restored"); await closeApp(L); L = null;
    rmSync(join(data, "components"), { recursive: true, force: true });
    L = await launch(); assert.equal(sha(coreFile()), pinnedCore, "components not restored"); await closeApp(L); L = null;
  });

  await step("the exe folder is READ-ONLY for the user: the program still starts and runs (it writes nothing there)", async () => {
    const user = (await ps("$env:USERNAME")).trim();
    await run("icacls", [folder, "/deny", `${user}:(OI)(CI)(WD,AD,DC)`]);
    try {
      assert.throws(() => writeFileSync(join(folder, "probe.txt"), "x"), "the folder is not read-only");
      L = await launch();
      await click(L.control, "connectBtn");
      assert.ok(await statusIs(L.control, "Подключено через Россию"), "status: " + await status(L.control));
      await closeApp(L); L = null;
    } finally { await run("icacls", [folder, "/remove:d", user]).catch(() => {}); }
    writeFileSync(join(folder, "probe.txt"), "x"); unlinkSync(join(folder, "probe.txt")); // writable again: the test restored what it changed
  });

  await step("--licenses opens the unpacked licence folder (works without starting the program)", async () => {
    const log = join(work, "open.log");
    const r = spawnSync(exe, ["--licenses"], { cwd: elsewhere, env: baseEnv({ RUNET_TEST_MODE: "1", RUNET_OPEN_LOG: log, RUNET_NO_DIALOG: "1" }), timeout: 30000 });
    assert.equal(r.status, 0);
    const opened = readFileSync(log, "utf8").trim();
    assert.equal(opened.toLowerCase(), join(compDir(), "licenses").toLowerCase());
    assert.ok(existsSync(join(opened, "sing-box", "SOURCE-OFFER.txt")));
    assert.equal((await ours()).length, 0);
  });

  await step("ORDINARY start (no test variables at all): Chrome is found, no window asks for it, our Chrome window and core start; closing ends them", async () => {
    const env = baseEnv(); for (const k of Object.keys(env)) if (k.startsWith("RUNET_")) delete env[k];
    const child = spawn(exe, [], { cwd: elsewhere, stdio: "ignore", env });
    const exited = new Promise((r) => child.once("exit", r));
    try {
      assert.ok(await until(async () => (await ours()).some((p) => p.Name === "chrome.exe"), 40000), "our Chrome did not start");
      const list = await ours();
      assert.ok(list.some((p) => p.Name.startsWith("RunetAccess")), "the program is not running");
      const chrome = list.find((p) => p.Name === "chrome.exe");
      console.log("      Chrome used: " + chrome.ExecutablePath);
      assert.ok(/--proxy-server=socks5:\/\/127\.0\.0\.1:\d+/.test(chrome.CommandLine) && chrome.CommandLine.includes("--user-data-dir="), "Chrome is not started with its own profile and proxy");
    } finally {
      for (const p of await ours()) if (p.Name.startsWith("RunetAccess")) await killPid(p.ProcessId); // the program's job object takes its children along
      await Promise.race([exited, sleep(10000)]);
      for (const p of await ours()) await killPid(p.ProcessId);
    }
  });

  await step("hygiene at the end: nothing of ours runs; no uninstall entry, no shortcuts, system proxy unchanged; the exe is unchanged", async () => {
    assert.ok(await until(async () => (await ours()).length === 0, 15000), "leftover: " + JSON.stringify((await ours()).map((p) => p.Name)));
    assert.equal(await uninstallKeys(), before.uninstall);
    assert.equal(await shortcuts(), before.lnk);
    assert.equal(await sysProxy(), before.proxy);
    assert.equal(sha(exe), sha(built));
    assert.deepEqual(readdirSync(folder), [`RunetAccess-Portable-${version}.exe`]);
  });
} finally {
  try { if (L) await closeApp(L); } catch {}
  try { ssA.stop(); ssA.cleanup(); } catch {}
  mock.close();
  for (const p of await ours()) await killPid(p.ProcessId);
  try { const user = (await ps("$env:USERNAME")).trim(); await run("icacls", [folder, "/remove:d", user]); } catch {}
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
