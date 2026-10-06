// End-to-end test of the special browser in a REAL Chrome started by RunetAccess.exe.
// Synthetic VLESS+Reality servers on localhost; a mock of the country service that is reachable
// ONLY through the tunnel (server-side redirect of a fake host name). No registry, no extension.
// Run (after scripts\build.ps1):  . .\scripts\env.ps1; node tests\launcher-e2e.mjs
// Needs internet for: the Reality mask host, https://example.com/, https://api.ipify.org/,
// and (one step) the public page https://www.nalog.gov.ru/ is requested through the synthetic tunnel.
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { join, dirname } from "node:path";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync, mkdirSync, statSync, readdirSync } from "node:fs";
import assert from "node:assert/strict";
import { root, connectBrowser, pageWhere, openPage, sleep } from "./cdp.mjs";
import { startMock, startSyntheticServer, freePort, portOpen, until, MOCK_HOST } from "./support.mjs";

const run = promisify(execFile);
// RUNET_EXE: run the same checks against an INSTALLED copy (tests/installer-check.ps1 does this)
const exe = process.env.RUNET_EXE || join(root, "dist", "runet-access", "RunetAccess.exe");
const exeDir = dirname(exe);
const home = join(root, ".local", "e2e-home");
const profile = join(home, "profile");
const openLog = join(root, ".local", "e2e-open.log");
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
  const dist = exeDir.toLowerCase();
  return all.filter((p) => ((p.ExecutablePath || "").toLowerCase().startsWith(dist)) || (p.Name === "chrome.exe" && (p.CommandLine || "").toLowerCase().includes(profile.toLowerCase())));
}
const cores = async () => (await ours()).filter((p) => p.Name === "sing-box.exe");
const curl = async (...a) => { try { return (await run("curl.exe", ["-sS", "--max-time", "25", ...a])).stdout.trim(); } catch { return ""; } };
const sysProxy = async () => (await run("reg", ["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"])).stdout.split(/\r?\n/).filter((l) => /Proxy|AutoConfig|AutoDetect/i.test(l)).sort().join("|");
const killPid = (pid) => run("taskkill", ["/F", "/PID", String(pid)]).catch(() => {});
const sha = (f) => (existsSync(f) ? createHash("sha256").update(readFileSync(f)).digest("hex") : "");
const keyFile = join(home, "key.dpapi");

const DIRECT_IP = await curl("https://api.ipify.org");
assert.match(DIRECT_IP, /^\d+\.\d+\.\d+\.\d+$/, "no direct internet for the reference IP");
const sysBefore = await sysProxy();

const mock = await startMock();
let serverA = await startSyntheticServer(mock.port);
let serverB = null;
const sbLog = (s) => s.h.log.replace(/\x1b\[[0-9;]*m/g, "");

async function launch() {
  const cdpPort = await freePort();
  const child = spawn(exe, [], {
    stdio: "ignore", windowsHide: false,
    env: { ...process.env, RUNET_TEST_MODE: "1", RUNET_ACCESS_HOME: home, RUNET_PROBE_URL: `http://${MOCK_HOST}/`, RUNET_CHROME_EXTRA_ARGS: `--remote-debugging-port=${cdpPort}`,
      RUNET_NO_DIALOG: "1", RUNET_OPEN_LOG: openLog, RUNET_DIRECT_IP: DIRECT_IP, RUNET_RECHECK_MS: "3000" },
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
const vis = (p, id) => p.evaluate(`!document.getElementById('${id}').classList.contains('hidden')`);
const status = (p) => $(p, "statusLine", "textContent");
const note = (p) => $(p, "statusNote", "textContent");
const fetchState = (p, url) => p.evaluate(`fetch(${JSON.stringify(url)}, { mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(15000) }).then(() => 'loaded', () => 'failed')`);
const statusIs = (p, s, ms = 90000) => p.waitFor(`document.getElementById('statusLine').textContent === ${JSON.stringify(s)}`, ms);
const apiPost = (p, path, body, header = true) => p.evaluate(`fetch(${JSON.stringify(path)}, { method: 'POST', headers: ${header ? `{ 'Content-Type': 'application/json', 'X-Runet': '1' }` : "{}"}, body: ${JSON.stringify(JSON.stringify(body))} }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))`);
const apiGet = (p, path) => p.evaluate(`fetch(${JSON.stringify(path)}, { cache: 'no-store' }).then((r) => r.json())`);
const tabs = async (browser, prefix) => (await browser.send("Target.getTargets")).targetInfos.filter((t) => t.type === "page" && t.url.startsWith(prefix));
const closeTabs = async (browser, prefix) => { for (const t of await tabs(browser, prefix)) await browser.send("Target.closeTarget", { targetId: t.targetId }).catch(() => {}); };
const openedLinks = () => (existsSync(openLog) ? readFileSync(openLog, "utf8").split(/\r?\n/).filter(Boolean) : []);

const goSettings = async (p) => { await click(p, "settingsBtn"); assert.ok(await p.waitFor("!document.getElementById('viewSettings').classList.contains('hidden')", 5000), "settings did not open"); };
const goMain = async (p) => { await click(p, "backBtn"); assert.ok(await p.waitFor("!document.getElementById('viewMain').classList.contains('hidden')", 5000)); };
async function replaceWith(p, key, remember = true) {
  if (!(await vis(p, "viewSettings"))) await goSettings(p);
  if (!(await vis(p, "replaceForm"))) await click(p, "replaceOpen");
  await p.evaluate(`document.getElementById('newRemember').checked = ${remember}`);
  await setVal(p, "newKeyInput", key);
  await click(p, "replaceGo");
}
const submitSite = async (p, v) => { await setVal(p, "siteUrl", v); await p.evaluate("document.getElementById('openBtn').click()"); };

rmSync(home, { recursive: true, force: true }); rmSync(openLog, { force: true });
let L = await launch();
let { control } = L;

try {
  // ======================================= first run =======================================
  await step("first run: title, field, checkbox, main button, 'no key?' block; no site tiles yet", async () => {
    assert.ok(await vis(control, "viewFirst") && !(await vis(control, "viewMain")) && !(await vis(control, "viewSettings")));
    assert.equal(await $(control, "firstTitle", "textContent"), "Российские сайты — в отдельном окне");
    assert.ok((await control.evaluate("document.querySelector('#viewFirst .lead').textContent")).includes("Подключение действует только в этом браузере."));
    assert.equal(await control.evaluate("document.querySelector('label[for=keyInput]').textContent"), "Ключ подключения");
    assert.equal(await $(control, "remember", "checked"), true);
    assert.equal(await $(control, "mainBtn", "textContent"), "Подключиться");
    assert.equal(await control.evaluate("document.querySelector('#getKeyFirst summary').textContent"), "Нет ключа?");
    assert.equal(await status(control), "Не подключено");
    assert.ok(!(await control.evaluate("document.body.textContent")).includes("из Telegram"), "the field must not be tied to Telegram");
    await control.evaluate("window.scrollTo(0, 0)"); await control.shot(join(shots, "ui-first-run.png"));
  });

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
    const c2 = spawn(exe, [], { stdio: "ignore", env: { ...process.env, RUNET_TEST_MODE: "1", RUNET_ACCESS_HOME: home, RUNET_NO_DIALOG: "1" } });
    const code = await Promise.race([new Promise((r) => c2.once("exit", r)), sleep(10000).then(() => "timeout")]);
    assert.equal(code, 1, "second instance exit: " + code);
  });

  await step("help links work BEFORE connecting: fixed list only, open by explicit click, copy button", async () => {
    await control.evaluate("document.querySelector('#getKeyFirst details').open = true");
    const txt = await control.evaluate("document.querySelector('#getKeyFirst .getkey').innerText");
    for (const s of ["Назад в СССР", "HLVPN", "Подключиться → Рунет", "vless://", "t.me/BackInTheUSSR_bot", "t.me/hlvpnbot"]) assert.ok(txt.includes(s), "missing: " + s);
    assert.equal(openedLinks().length, 0, "nothing may open by itself");
    await control.evaluate("document.querySelector('#getKeyFirst [data-open=bot-ussr]').click()");
    await control.evaluate("document.querySelector('#getKeyFirst [data-open=bot-hlvpn]').click()");
    await control.evaluate("document.querySelector('footer [data-open=thanks]').click()");
    assert.ok(await until(async () => openedLinks().length === 3, 8000), "links: " + JSON.stringify(openedLinks()));
    assert.deepEqual(openedLinks(), ["https://t.me/BackInTheUSSR_bot", "https://t.me/hlvpnbot", "https://t.me/W3_accelerators_GK"]);
    assert.ok(await control.waitFor("document.querySelector('footer').innerText.includes('Спасибо за помощь с подключением — Ускоритель WWW')", 5000), "thanks line missing");
    // copy (explicit click) puts the public link on the clipboard
    const origin = new URL(await control.url()).origin;
    await L.browser.send("Browser.grantPermissions", { origin, permissions: ["clipboardReadWrite", "clipboardSanitizedWrite"] }).catch(() => {});
    await L.browser.send("Target.activateTarget", { targetId: control.targetId });
    await control.evaluate("document.querySelector('#getKeyFirst [data-copy=bot-hlvpn]').click()");
    assert.ok(await control.waitFor("document.querySelector('#getKeyFirst [data-copy=bot-hlvpn]').textContent === 'Скопировано'", 5000), "copy gave no feedback");
    const clip = await control.evaluate("navigator.clipboard.readText().catch(() => 'unreadable')");
    if (clip !== "unreadable") assert.equal(clip, "https://t.me/hlvpnbot");
  });

  await step("the open-link call is no general launcher: unknown ids, URLs, no header, GET are all refused", async () => {
    const before = openedLinks().length;
    assert.equal((await apiPost(control, "/api/open-external", { id: "https://evil.example/" })).status, 404);
    assert.equal((await apiPost(control, "/api/open-external", { id: "calc.exe" })).status, 404);
    assert.equal((await apiPost(control, "/api/open-external", { url: "https://evil.example/" })).status, 404);
    assert.equal((await apiPost(control, "/api/open-external", { id: "bot-ussr" }, false)).status, 403);
    assert.equal(await control.evaluate("fetch('/api/open-external?id=bot-ussr').then((r) => r.status)"), 403);
    assert.equal((await apiPost(control, "/api/open-site", { url: "https://example.com/" })).status, 409, "a site must not open before the exit is verified");
    assert.equal(openedLinks().length, before);
  });

  await step("bad key (wrong shape): plain message under the field, key stays editable, nothing echoed, no core", async () => {
    const bad = "vless://11111111-2222-3333-4444-555555555555@192.0.2.10:443?security=tls&flow=xtls-rprx-vision";
    await setVal(control, "keyInput", bad);
    await click(control, "mainBtn");
    assert.ok(await control.waitFor("document.getElementById('keyError').textContent.length > 0", 8000));
    const t = await $(control, "keyError", "textContent");
    assert.match(t, /WebSocket|не поддерж/i);
    for (const s of ["11111111-2222", "192.0.2.10"]) assert.ok(!t.includes(s));
    assert.equal(await $(control, "keyInput", "value"), bad, "the field must keep the text so it can be corrected");
    assert.equal((await cores()).length, 0);
    assert.equal(await status(control), "Не подключено");
    assert.ok(!existsSync(keyFile));
  });

  await step("server unavailable: named plainly, 'Повторить' offered, never stuck busy, nothing saved", async () => {
    const creds = serverA.creds, key = serverA.key;
    serverA.stop(); assert.ok(await until(async () => !(await portOpen(creds.port)), 8000));
    await setVal(control, "keyInput", key);
    await click(control, "mainBtn");
    assert.ok(await statusIs(control, "Сервер недоступен", 30000), "status: " + await status(control));
    assert.equal(await $(control, "mainBtn", "disabled"), false, "stuck in busy");
    assert.equal(await vis(control, "retryBtn"), true);
    assert.equal((await cores()).length, 0);
    assert.ok(!existsSync(keyFile), "an unverified key must not be saved");
    assert.equal(await $(control, "keyInput", "value"), key, "the typed key must stay for the retry");
    await click(control, "retryBtn");
    assert.ok(await statusIs(control, "Сервер недоступен", 30000));
    // the same server comes back; one click on "Повторить" is enough
    serverA.cleanup(); serverA = await startSyntheticServer(mock.port, creds);
    await click(control, "retryBtn");
    const ok = await statusIs(control, "Подключено через Россию");
    assert.ok(ok, "status: " + await status(control) + " | " + await note(control));
  });

  await step("connected: main screen shows the sites, key field is gone, saved only after verification", async () => {
    assert.ok(await vis(control, "viewMain") && !(await vis(control, "viewFirst")));
    assert.equal(await $(control, "keyInput", "value"), "", "key left in the field");
    const tiles = await control.evaluate("[...document.querySelectorAll('.tile')].map((t) => t.dataset.url)");
    assert.deepEqual(tiles, ["https://www.gosuslugi.ru/", "https://www.nalog.gov.ru/", "https://minjust.gov.ru/"]);
    assert.equal(await control.evaluate("document.querySelector('label[for=siteUrl]').textContent"), "Другой сайт");
    assert.equal(await $(control, "openBtn", "textContent"), "Открыть");
    assert.equal(await vis(control, "disconnectBtn"), true);
    assert.ok(!(await control.evaluate("document.getElementById('statusBar').innerText")).match(/\d+\.\d+\.\d+\.\d+|:\d{2,5}\b/), "the status bar must not show IPs or ports");
    assert.ok(existsSync(keyFile) && statSync(keyFile).size > 100, "the verified key was not saved");
    assert.ok(mock.state.hits > 0, "mock was never reached: the probe did not use the tunnel");
    await control.evaluate("window.scrollTo(0, 0)"); await control.shot(join(shots, "ui-main-connected.png"));
  });

  await step("details block: exit country and address, ordinary address, re-check; safe diagnostics", async () => {
    await control.evaluate("document.getElementById('details').open = true");
    assert.equal((await $(control, "resExit", "textContent")), "RU · 203.0.113.77");
    assert.ok((await $(control, "resDirect", "textContent")).includes(DIRECT_IP));
    const diag = await $(control, "diagText", "textContent");
    assert.ok(diag.includes("Вердикт проверки: ok"));
    assert.ok(!diag.includes(DIRECT_IP) && !diag.includes("203.0.113.77"), "diagnostics must carry shortened addresses");
    for (const s of [serverA.uuid, String(serverA.port), "vless://", "127.0.0.1"]) assert.ok(!diag.includes(s), "diagnostics leak: " + s);
    await click(control, "detRecheck");
    assert.ok(await statusIs(control, "Подключено через Россию", 30000));
    await control.evaluate("document.getElementById('details').open = false");
  });

  await step("stored key is DPAPI-encrypted on disk (no plaintext UUID / pbk)", async () => {
    const txt = readFileSync(keyFile).toString("latin1");
    for (const s of [serverA.uuid, "vless://", "reality", "xtls"]) assert.ok(!txt.includes(s), "plaintext found: " + s);
  });

  await step("ALL traffic goes through the key: listed-nowhere sites, no domain list", async () => {
    const tab = await openPage(L.browser, "https://example.com/");
    assert.ok(await tab.waitFor("/Example Domain/.test(document.title)", 30000), "site did not load: " + await tab.url());
    await L.browser.send("Target.closeTarget", { targetId: tab.targetId }).catch(() => {});
    assert.equal(await fetchState(control, "https://api.ipify.org/"), "loaded");
    const log = sbLog(serverA);
    assert.ok(/example\.com/.test(log), "server never saw example.com");
    assert.ok(/api\.ipify\.org/.test(log), "server never saw api.ipify.org");
  });

  await step("the control page itself stays on loopback (not proxied)", async () => {
    const ctlPort = new URL(await control.url()).port;
    const log = sbLog(serverA);
    assert.ok(!log.includes(`connection to 127.0.0.1:${ctlPort}`) && !/inbound connection to 127\.0\.0\.1/.test(log), "loopback traffic reached the tunnel server");
  });

  await step("'Другой сайт': exactly ONE new tab, also on a double submit; bad address is refused inline", async () => {
    await closeTabs(L.browser, "https://example.com");
    await submitSite(control, "not a site");
    assert.ok(await vis(control, "siteError"));
    await control.evaluate(`(() => { const i = document.getElementById('siteUrl'); i.value = 'example.com'; const f = document.getElementById('otherForm'); f.requestSubmit(); f.requestSubmit(); return 1; })()`);
    assert.ok(await until(async () => (await tabs(L.browser, "https://example.com")).length >= 1, 20000), "no tab");
    await sleep(2500);
    assert.equal((await tabs(L.browser, "https://example.com")).length, 1, "more than one tab opened");
    const t = await pageWhere(L.browser, (u) => u.startsWith("https://example.com"), 5000);
    assert.ok(await t.waitFor("/Example Domain/.test(document.title)", 30000));
    await closeTabs(L.browser, "https://example.com");
  });

  await step("tile click opens ONE tab; rapid repeated clicks do not open more", async () => {
    await control.evaluate(`(() => { const t = document.querySelector('.tile[data-url="https://www.nalog.gov.ru/"]'); t.click(); t.click(); t.click(); return 1; })()`);
    assert.ok(await until(async () => (await tabs(L.browser, "https://www.nalog.gov.ru")).length >= 1, 20000), "no tab");
    await sleep(2500);
    assert.equal((await tabs(L.browser, "https://www.nalog.gov.ru")).length, 1, "more than one tab opened");
    await closeTabs(L.browser, "https://www.nalog.gov.ru");
  });

  await step("one core + the launcher are ours; the core came from dist", async () => {
    const names = (await ours()).filter((p) => p.Name !== "chrome.exe").map((p) => p.Name).sort();
    assert.deepEqual(names, ["RunetAccess.exe", "sing-box.exe"], JSON.stringify(names));
  });

  await step("core killed: confirmation is dropped at once, the window is cut off, the exit is checked AGAIN after the restart", async () => {
    mock.state.delayMs = 1800; // makes the 're-check' phase long enough to observe
    try {
    const core = (await cores())[0];
    const epoch0 = (await apiGet(control, "/api/state")).epoch;
    await killPid(core.ProcessId);
    assert.equal(await fetchState(control, "https://example.com/"), "failed", "site loaded while the core was dead");
    assert.ok(await until(async () => (await apiGet(control, "/api/state")).confirmed === false, 4000), "the old confirmation survived the core's death");
    assert.equal((await apiPost(control, "/api/open-site", { url: "https://example.com/" })).status, 409, "a site opened on an unconfirmed exit");
    const seen = new Set();
    const ok = await until(async () => { const s = await status(control); seen.add(s); return s === "Подключено через Россию" && (await apiGet(control, "/api/state")).epoch > epoch0 && (await apiGet(control, "/api/state")).confirmed; }, 40000);
    assert.ok(ok, "never confirmed again; saw " + [...seen].join(" | "));
    assert.ok(seen.has("Проверяем подключение через Россию…"), "no re-check was shown; saw " + [...seen].join(" | "));
    assert.equal(await fetchState(control, "https://example.com/"), "loaded", "traffic did not resume");
    } finally { mock.state.delayMs = 0; }
  });

  await step("tunnel server dies: green status is withdrawn ('Соединение прервано'), nothing opens, no silent direct exit", async () => {
    const creds = serverA.creds;
    serverA.stop(); assert.ok(await until(async () => !(await portOpen(creds.port)), 8000));
    assert.equal(await fetchState(control, "https://example.com/"), "failed");
    assert.ok(await statusIs(control, "Соединение прервано", 60000), "status: " + await status(control));
    assert.equal(await vis(control, "retryBtn"), true);
    assert.equal((await apiPost(control, "/api/open-site", { url: "https://example.com/" })).status, 409);
    // a tile click now must not open anything and must not leave the page busy
    await closeTabs(L.browser, "https://example.com");
    await submitSite(control, "example.com");
    assert.ok(await statusIs(control, "Сервер недоступен", 30000), "status: " + await status(control));
    assert.equal((await tabs(L.browser, "https://example.com")).length, 0, "a site opened although the connection failed");
    assert.equal(await $(control, "mainBtn", "disabled"), false);
    // server returns -> one click on 'Повторить'
    serverA.cleanup(); serverA = await startSyntheticServer(mock.port, creds);
    await click(control, "retryBtn");
    assert.ok(await statusIs(control, "Подключено через Россию", 60000), "status: " + await status(control));
    assert.equal(await fetchState(control, "https://example.com/"), "loaded");
  });

  await step("exit service silent but the server answers: 'Не удалось подтвердить', NOT 'key is broken'; re-check recovers", async () => {
    mock.state.fail = true;
    await control.evaluate("document.getElementById('details').open = true");
    await click(control, "detRecheck");
    assert.ok(await statusIs(control, "Не удалось подтвердить страну выхода", 90000), "status: " + await status(control));
    const n = await note(control);
    assert.ok(/не значит, что ключ неисправен/.test(n), n);
    assert.ok(!/ключ.*(неверн|устарел|не подход)/i.test(await status(control)));
    assert.equal(await vis(control, "recheckBtn"), true);
    await closeTabs(L.browser, "https://example.com");
    await submitSite(control, "example.com"); // re-verifies first; still unconfirmed -> nothing opens
    await statusIs(control, "Не удалось подтвердить страну выхода", 90000);
    await sleep(1500);
    assert.equal((await tabs(L.browser, "https://example.com")).length, 0, "a site opened on an unconfirmed exit");
    assert.equal(await $(control, "mainBtn", "disabled"), false);
    mock.state.fail = false;
    await click(control, "recheckBtn");
    assert.ok(await statusIs(control, "Подключено через Россию", 60000), "status: " + await status(control));
    await control.evaluate("document.getElementById('details').open = false");
  });

  await step("exit is not Russia: refused, disconnected, window cut off; 'same address' is named separately", async () => {
    try {
    mock.state.country = "DE";
    await click(control, "disconnectBtn");
    await control.waitFor("document.getElementById('statusLine').textContent === 'Не подключено'", 15000);
    await click(control, "connectBtn");
    assert.ok(await statusIs(control, "Выход не в России", 90000), "status: " + await status(control));
    assert.match(await note(control), /DE/);
    assert.equal((await cores()).length, 0);
    assert.equal(await fetchState(control, "https://example.com/"), "failed");
    mock.state.country = "RU"; mock.state.ip = DIRECT_IP;
    await click(control, "retryBtn");
    assert.ok(await statusIs(control, "Трафик идёт мимо ключа", 90000), "status: " + await status(control));
    } finally { mock.state.country = "RU"; mock.state.ip = "203.0.113.77"; }
  });

  await step("Disconnect: core stops, window stays cut off (fail-closed by design); no self-connect afterwards", async () => {
    await click(control, "retryBtn");
    assert.ok(await statusIs(control, "Подключено через Россию", 90000), "status: " + await status(control));
    await click(control, "disconnectBtn");
    assert.ok(await statusIs(control, "Не подключено", 20000), "status: " + await status(control));
    assert.ok(await until(async () => (await cores()).length === 0, 8000));
    assert.equal(await fetchState(control, "https://example.com/"), "failed");
    await sleep(6000);
    assert.equal((await cores()).length, 0, "the app connected on its own");
    assert.equal(await status(control), "Не подключено");
  });

  // ======================================= opening through a tile with a long wait =======================================
  await step("tile on a disconnected app: connect -> verify -> ONE tab, even though the wait outlasts Chrome's pop-up allowance", async () => {
    await closeTabs(L.browser, "https://example.com");
    mock.state.delayMs = 7000; // the exit check alone takes > 5 s: window.open() after it would be blocked
    await control.evaluate(`(() => { const i = document.getElementById('siteUrl'); i.value = 'example.com'; const f = document.getElementById('otherForm'); f.requestSubmit(); return 1; })()`);
    assert.ok(await control.waitFor("/Проверяем|Подключаемся/.test(document.getElementById('statusLine').textContent)", 15000), "no progress shown: " + await status(control));
    await control.evaluate(`(() => { const f = document.getElementById('otherForm'); f.requestSubmit(); f.requestSubmit(); return 1; })()`); // clicks while waiting
    assert.equal(await $(control, "cancelBtn", "classList.contains('hidden')"), false, "no way to cancel while waiting");
    assert.ok(await until(async () => (await tabs(L.browser, "https://example.com")).length >= 1, 45000), "no tab; status: " + await status(control));
    mock.state.delayMs = 0;
    await sleep(3000);
    assert.equal((await tabs(L.browser, "https://example.com")).length, 1, "more than one tab");
    assert.equal(await status(control), "Подключено через Россию");
    await closeTabs(L.browser, "https://example.com");
  });

  await step("Cancel while waiting: nothing opens later, the app is idle and not busy", async () => {
    await click(control, "disconnectBtn");
    await statusIs(control, "Не подключено", 15000);
    mock.state.delayMs = 6000;
    await control.evaluate(`(() => { const i = document.getElementById('siteUrl'); i.value = 'example.com'; document.getElementById('otherForm').requestSubmit(); return 1; })()`);
    assert.ok(await control.waitFor("/Проверяем/.test(document.getElementById('statusLine').textContent)", 20000), "never reached the check: " + await status(control));
    await click(control, "cancelBtn");
    assert.ok(await statusIs(control, "Не подключено", 15000), "status: " + await status(control));
    assert.ok(await until(async () => (await cores()).length === 0, 8000), "core still running after cancel");
    await sleep(8000);
    mock.state.delayMs = 0;
    assert.equal((await tabs(L.browser, "https://example.com")).length, 0, "a cancelled request opened a tab");
    assert.equal(await status(control), "Не подключено");
    assert.equal(await $(control, "mainBtn", "disabled"), false);
    assert.equal(await vis(control, "connectBtn"), true);
  });

  // ======================================= settings: replace / cancel / failed replace =======================================
  serverB = await startSyntheticServer(mock.port);
  await step("settings: replace with 'Отмена' keeps the saved key and the connection", async () => {
    await click(control, "connectBtn");
    assert.ok(await statusIs(control, "Подключено через Россию", 90000), "status: " + await status(control));
    const h0 = sha(keyFile); assert.ok(h0);
    await goSettings(control);
    assert.match(await $(control, "keyStatusText", "textContent"), /сохранён/);
    assert.match(await $(control, "settingsActions", "innerText"), /Заменить ключ/);
    assert.match(await $(control, "settingsActions", "innerText"), /Удалить сохранённый ключ/);
    assert.match(await $(control, "viewSettings", "innerText"), /зашифрован средствами Windows/);
    await control.evaluate("window.scrollTo(0, 0)"); await control.shot(join(shots, "ui-settings.png"));
    await click(control, "replaceOpen");
    await setVal(control, "newKeyInput", serverB.key);
    await click(control, "replaceCancel");
    assert.equal(await $(control, "newKeyInput", "value"), "", "the cancelled key stayed in the field");
    assert.equal(await vis(control, "replaceForm"), false);
    assert.equal(sha(keyFile), h0, "the saved key changed on cancel");
    assert.equal(await status(control), "Подключено через Россию");
    assert.equal(await fetchState(control, "https://example.com/"), "loaded");
  });

  await step("settings: replacement key of the wrong SHAPE changes nothing (old connection and key intact)", async () => {
    const h0 = sha(keyFile);
    await replaceWith(control, "vless://not-a-key");
    assert.ok(await control.waitFor("document.getElementById('newKeyError').textContent.length > 0", 10000));
    assert.match(await $(control, "newKeyError", "textContent"), /Прежнее подключение не изменено/);
    assert.equal(await status(control), "Подключено через Россию");
    assert.equal(sha(keyFile), h0);
    assert.equal(await fetchState(control, "https://example.com/"), "loaded");
    await click(control, "replaceCancel");
  });

  await step("settings: FAILED replacement (new key, exit not RU) does not destroy the saved key; the old one reconnects", async () => {
    const h0 = sha(keyFile);
    mock.state.country = "DE";
    await replaceWith(control, serverB.key);
    assert.ok(await statusIs(control, "Выход не в России", 90000), "status: " + await status(control));
    assert.match(await note(control), /Сохранённый прежний ключ не тронут/);
    assert.equal(sha(keyFile), h0, "the saved key was overwritten by a key that failed verification");
    assert.equal((await cores()).length, 0);
    assert.equal(await fetchState(control, "https://example.com/"), "failed", "the window reached the internet after a failed replacement");
    assert.equal(await vis(control, "replaceForm"), true, "the user must stay where they can correct the key");
    mock.state.country = "RU";
    await click(control, "retryBtn"); // returns to the saved (old) key
    assert.ok(await statusIs(control, "Подключено через Россию", 90000), "status: " + await status(control));
    assert.ok(/203\.0\.113\.77/.test(await $(control, "resExit", "textContent")));
    assert.ok(sbLog(serverA).length > 0);
    assert.equal(sha(keyFile), h0);
  });

  await step("settings: successful replacement is verified FIRST, then saved; the OLD connection is not passed off as the new one", async () => {
    const h0 = sha(keyFile);
    await replaceWith(control, serverB.key);
    assert.ok(await statusIs(control, "Подключено через Россию", 90000), "status: " + await status(control));
    assert.notEqual(sha(keyFile), h0, "the new key was not saved");
    const logA0 = sbLog(serverA).length, logB0 = sbLog(serverB).length;
    assert.ok(await until(async () => (await fetchState(control, "https://example.com/")) === "loaded", 20000));
    assert.ok(sbLog(serverB).length > logB0, "traffic does not go through the NEW server");
    assert.equal(sbLog(serverA).length, logA0, "traffic still goes through the OLD server");
    assert.ok(await vis(control, "viewMain"), "should return to the sites");
  });

  await step("responsive: small window and 125-150% zoom have no sideways scroll; dark theme works; screenshots", async () => {
    const send = (m, p) => L.browser.send(m, p, control.sid);
    for (const [w, h, dpr, name] of [[1280 / 1.5, 720 / 1.5, 1.5, "ui-main-150.png"], [1280 / 1.25, 720 / 1.25, 1.25, "ui-main-125.png"], [360, 640, 1, "ui-main-narrow.png"]]) {
      await send("Emulation.setDeviceMetricsOverride", { width: Math.round(w), height: Math.round(h), deviceScaleFactor: dpr, mobile: false });
      await sleep(300);
      const over = await control.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth");
      assert.ok(over <= 1, `${name}: horizontal overflow ${over}px`);
      await control.evaluate("window.scrollTo(0, 0)"); await control.shot(join(shots, name));
    }
    await send("Emulation.setDeviceMetricsOverride", { width: 900, height: 700, deviceScaleFactor: 1, mobile: false });
    await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
    await sleep(300);
    const bg = await control.evaluate("getComputedStyle(document.body).backgroundColor");
    assert.notEqual(bg, "rgb(244, 247, 251)", "dark theme not applied");
    await control.evaluate("window.scrollTo(0, 0)"); await control.shot(join(shots, "ui-main-dark.png"));
    await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });
    await send("Emulation.clearDeviceMetricsOverride", {});
  });

  await step("keyboard: every control is reachable and shows a visible focus ring", async () => {
    const n = await control.evaluate(`(() => { const els = [...document.querySelectorAll('button, input, textarea, summary')].filter((e) => e.offsetParent !== null); let bad = []; for (const e of els) { e.focus(); const cs = getComputedStyle(e); const ok = e.matches(':focus-visible') ? (cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) >= 2) : true; if (!ok) bad.push(e.id || e.className); } return JSON.stringify({ count: els.length, bad }); })()`);
    const r = JSON.parse(n);
    assert.ok(r.count > 5);
    assert.deepEqual(r.bad, []);
  });

  await step("DOCUMENTED FACT: Chrome blocks window.open() made after a long wait (why the launcher opens tabs itself)", async () => {
    await control.evaluate(`(() => { const b = document.createElement('button'); b.id = '__pp'; b.textContent = 'pp'; b.style.cssText = 'position:fixed;left:10px;top:10px;width:140px;height:44px;z-index:99999'; b.onclick = async () => { window.__pp = 'waiting'; await new Promise((r) => setTimeout(r, 7000)); const w = window.open('about:blank', '_blank'); window.__pp = w ? 'opened' : 'blocked'; if (w) w.close(); }; document.body.appendChild(b); return 1; })()`);
    await L.browser.send("Target.activateTarget", { targetId: control.targetId });
    const s = control.sid;
    await L.browser.send("Input.dispatchMouseEvent", { type: "mousePressed", x: 60, y: 30, button: "left", clickCount: 1 }, s);
    await L.browser.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: 60, y: 30, button: "left", clickCount: 1 }, s);
    assert.ok(await control.waitFor("window.__pp === 'opened' || window.__pp === 'blocked'", 15000));
    const late = await control.evaluate("window.__pp");
    console.log("      window.open() 7 s after a real click: " + late);
    await control.evaluate("document.getElementById('__pp').remove()");
    assert.equal(late, "blocked");
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

  // ======================================= second run: repeat start =======================================
  mock.state.country = "RU"; mock.state.ip = "203.0.113.77"; mock.state.delayMs = 0; mock.state.fail = false;
  L = await launch(); control = L.control;
  await step("repeat start: sites and 'Подключиться' are shown, the key is NOT asked for again, nothing connects by itself", async () => {
    assert.ok(await vis(control, "viewMain") && !(await vis(control, "viewFirst")));
    assert.equal(await status(control), "Не подключено");
    assert.equal(await vis(control, "connectBtn"), true);
    assert.equal(await $(control, "connectBtn", "textContent"), "Подключиться");
    await sleep(5000);
    assert.equal((await cores()).length, 0, "the app connected without a click");
    assert.equal(await status(control), "Не подключено");
    await control.evaluate("window.scrollTo(0, 0)"); await control.shot(join(shots, "ui-repeat-start.png"));
  });

  await step("repeat start: a tile click = connect -> verify RU -> open the site once", async () => {
    await closeTabs(L.browser, "https://www.minjust.gov.ru");
    await control.evaluate(`(() => { const t = document.querySelector('.tile[data-url="https://minjust.gov.ru/"]'); t.click(); t.click(); return 1; })()`);
    assert.ok(await until(async () => (await tabs(L.browser, "https://minjust.gov.ru")).length >= 1, 60000), "no tab; status: " + await status(control));
    await sleep(2500);
    assert.equal((await tabs(L.browser, "https://minjust.gov.ru")).length, 1);
    assert.equal(await status(control), "Подключено через Россию");
    await closeTabs(L.browser, "https://minjust.gov.ru");
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
  await step("stale lock from the crash is taken over; settings: 'Удалить сохранённый ключ' asks first, then removes the key", async () => {
    await goSettings(control);
    await click(control, "forgetBtn");
    assert.equal(await vis(control, "forgetConfirm"), true, "no confirmation");
    assert.ok(existsSync(keyFile), "deleted without confirmation");
    await click(control, "forgetNo");
    assert.ok(existsSync(keyFile), "cancel must keep the key");
    await click(control, "forgetBtn"); await click(control, "forgetYes");
    assert.ok(await until(async () => !existsSync(keyFile), 8000), "key file still on disk");
    assert.ok(await control.waitFor("/удалён/.test(document.getElementById('keyStatusText').textContent)", 5000), "no confirmation text: " + await $(control, "keyStatusText", "textContent"));
    await click(control, "backBtn");
    assert.ok(await control.waitFor("!document.getElementById('viewFirst').classList.contains('hidden')", 8000), "should return to the first-run screen");
  });
  await L.browser.send("Browser.close").catch(() => {});
  await Promise.race([L.exited, sleep(20000)]);

  await step("system proxy settings unchanged; no extension, no registry writes by the product", async () => {
    assert.equal(await sysProxy(), sysBefore);
  });
} finally {
  serverA.stop(); serverA.cleanup(); if (serverB) { serverB.stop(); serverB.cleanup(); } mock.close();
  for (const p of await ours()) await killPid(p.ProcessId); // our own test processes only (dist + our profile)
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
