// Key formats end to end, in a REAL Chrome started by RunetAccess.exe, with REAL Shadowsocks servers (sing-box)
// on loopback and a local HTTPS stand-in for a dynamic-key provider (ssconf://).
//   - ss:// (Outline style and AEAD-2022) really carries traffic through the Shadowsocks server;
//   - ssconf:// is fetched by the launcher over HTTPS (before any tunnel), the saved key is the LINK and the
//     settings are loaded again at the next connection;
//   - every failure is named exactly, leaves the previous key/connection alone and shows no secret;
//   - VLESS/Reality still works.
// Run (after scripts\build.ps1, from a hidden desktop if you do not want to see Chrome):
//   . .\scripts\env.ps1; node tests\keyformats-e2e.mjs
// Needs internet for: https://example.com/ (reached through the Shadowsocks server), the Reality mask host.
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { join, dirname } from "node:path";
import { createHash } from "node:crypto";
import https from "node:https";
import { existsSync, readFileSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import { root, connectBrowser, pageWhere, sleep } from "./cdp.mjs";
import { startMock, startSyntheticServer, startSsServer, tlsPair, freePort, portOpen, until, MOCK_HOST } from "./support.mjs";

const run = promisify(execFile);
const exe = process.env.RUNET_EXE || join(root, "dist", "runet-access", "RunetAccess.exe");
const exeDir = dirname(exe);
const work = join(root, ".local", "kf-work");
const home = join(work, "home");
const shots = join(root, ".local", "logs", "shots"); mkdirSync(shots, { recursive: true });
assert.ok(existsSync(exe), "build first: scripts\\build.ps1");
assert.ok((process.env.TEMP || "").startsWith(root), "run inside scripts\\env.ps1 so TEMP is under the repo root");
rmSync(work, { recursive: true, force: true }); mkdirSync(work, { recursive: true });

for (const ev of ["uncaughtException", "unhandledRejection"]) process.on(ev, (e) => { console.log("FATAL " + ev + ": " + ((e && e.stack) || e)); process.exit(1); });
let passed = 0, failed = 0;
const step = async (name, fn) => { try { await fn(); passed++; console.log("PASS  " + name); } catch (e) { failed++; console.log("FAIL  " + name + "\n      " + (e && e.message)); } };

const ps = async (script) => (await run("powershell", ["-NoProfile", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { maxBuffer: 1 << 24 })).stdout;
async function ours() {
  const out = await ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'RunetAccess*.exe' -or $_.Name -in 'sing-box.exe','chrome.exe' } | Select-Object Name,ProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress");
  if (!out.trim()) return [];
  const j = JSON.parse(out); const all = Array.isArray(j) ? j : [j];
  return all.filter((p) => ((p.ExecutablePath || "").toLowerCase().startsWith(exeDir.toLowerCase())) || ((p.ExecutablePath || "").toLowerCase().startsWith(home.toLowerCase())) || (p.Name === "chrome.exe" && (p.CommandLine || "").toLowerCase().includes(home.toLowerCase())));
}
const cores = async () => (await ours()).filter((p) => p.Name === "sing-box.exe");
const sysProxy = async () => (await run("reg", ["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"])).stdout.split(/\r?\n/).filter((l) => /Proxy|AutoConfig|AutoDetect/i.test(l)).sort().join("|");
const killPid = (pid) => run("taskkill", ["/F", "/PID", String(pid)]).catch(() => {});
const sha = (f) => (existsSync(f) ? createHash("sha256").update(readFileSync(f)).digest("hex") : "");
const keyFile = join(home, "key.dpapi");
const sysBefore = await sysProxy();

// ---- stand: mock country service, three real servers, a key provider --------------------------------------------------------------------
const DIRECT_IP = "198.51.100.7"; // documentation address: "the ordinary connection" (the launcher honours it in test mode only)
const mock = await startMock();
const ssA = await startSsServer(mock.port, "chacha20-ietf-poly1305");
const ss22 = await startSsServer(mock.port, "2022-blake3-aes-128-gcm");
const reality = await startSyntheticServer(mock.port);
const logOf = (s) => s.h.log.replace(/\x1b\[[0-9;]*m/g, "");

const SECRET_PATH = "/k/SECRET-PATH-" + Math.random().toString(36).slice(2, 10);
const TOKEN = "TOKEN-" + Math.random().toString(36).slice(2, 10);
const pair = tlsPair("localhost");
writeFileSync(join(work, "ca.pem"), pair.cert);
const routes = new Map(); // path -> (req,res) => void
const provider = https.createServer({ key: pair.key, cert: pair.cert }, (req, res) => {
  const path = req.url.split("?")[0];
  const h = routes.get(path);
  if (!h) { res.writeHead(404); res.end("no"); return; }
  h(req, res);
});
await new Promise((r) => provider.listen(0, "127.0.0.1", r));
const provPort = provider.address().port;
const dynKey = `ssconf://localhost:${provPort}${SECRET_PATH}?token=${TOKEN}#%D0%98%D0%BC%D1%8F%20%D0%BA%D0%BB%D1%8E%D1%87%D0%B0`;
const serve = (body, status = 200, type = "application/json") => (_req, res) => { res.writeHead(status, { "content-type": type }); res.end(body); };
routes.set(SECRET_PATH, serve(ssA.json()));
let providerHits = 0;
provider.on("request", () => { providerHits++; });
const SECRETS = [SECRET_PATH, SECRET_PATH.slice(3), TOKEN, ssA.password, ss22.password, `localhost:${provPort}`, String(provPort) + SECRET_PATH];

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
async function refused(p, expectInline, ...mentions) { // the refusal text of the last attempt, wherever it is shown
  assert.ok(await p.waitFor(`document.getElementById('${expectInline}').textContent.length > 0`, 30000), "no refusal text; status: " + await status(p));
  const t = await $(p, expectInline, "textContent");
  for (const m of mentions) assert.ok(t.includes(m), `refusal lacks '${m}': ${t}`);
  return t;
}
async function noSecrets(p, what) {
  await p.evaluate("document.querySelectorAll('textarea, input').forEach((e) => { if (e.type !== 'checkbox') e.value = ''; })"); // what the user typed is theirs
  const page = await p.evaluate("document.body.innerText + ' ' + document.documentElement.outerHTML");
  for (const s of SECRETS) assert.ok(!page.includes(s), `${what}: the page shows a secret (${s.slice(0, 6)}…)`);
  const cmd = (await ours()).map((x) => x.CommandLine || "").join("\n");
  for (const s of SECRETS) assert.ok(!cmd.includes(s), `${what}: a command line holds a secret`);
}
// New connections accepted by a server (log lines "inbound connection to ..."); closing messages of OLD connections do not count.
const accepted = (s) => (logOf(s).match(/inbound connection to/g) || []).length;
const growth = async (server, other, fn) => { const a0 = accepted(server), o0 = accepted(other); await fn(); await sleep(1500); return [accepted(server) - a0, accepted(other) - o0]; };

let L = await launch();
let control = L.control;
try {
  // ---------------------------------------------------------------------------------------------------- wording
  await step("first run: the field is not tied to vless://; the help lists the supported formats and says what is not supported", async () => {
    assert.equal(await $(control, "keyInput", "placeholder"), "Вставьте ключ подключения из бота");
    const all = await control.evaluate("document.body.innerText");
    assert.ok(!/Нужен ключ, который начинается/.test(all) && !/только vless/i.test(all) && !all.includes("из Telegram"));
    const help = await control.evaluate("(() => { const d = document.querySelector('#getKeyFirst details'); d.open = true; return d.innerText; })()");
    for (const s of ["vless://", "ss://", "ssconf://", "Outline", "префикс", "Скопируйте ключ целиком"]) assert.ok(help.includes(s), "help lacks " + s);
    await control.evaluate("window.scrollTo(0, 0)"); await control.shot(join(shots, "ui-keyformats-help.png"));
  });

  await step("unknown format (trojan://): named as such, the supported formats are listed, nothing changes", async () => {
    await setVal(control, "keyInput", "trojan://pw@203.0.113.1:443#x");
    await click(control, "mainBtn");
    await refused(control, "keyError", "Неизвестный формат ключа", "vless://", "ss://", "ssconf://");
    assert.equal(await status(control), "Не подключено");
    assert.equal((await cores()).length, 0);
    assert.ok(!existsSync(keyFile));
  });

  // ---------------------------------------------------------------------------------------------------- ss:// carries traffic
  await step("ss:// (Outline style, chacha20) : parsed -> core config -> connected, exit RU verified, REAL traffic crosses the Shadowsocks server", async () => {
    await setVal(control, "keyInput", ssA.key);
    const [viaA, viaOther] = await growth(ssA, ss22, async () => {
      await click(control, "mainBtn");
      assert.ok(await statusIs(control, "Подключено через Россию"), "status: " + await status(control) + " | " + await note(control));
      assert.equal(await fetchState(control, "https://example.com/"), "loaded");
    });
    assert.ok(viaA > 0 && viaOther === 0, `traffic: via A +${viaA}, via other +${viaOther}`);
    assert.ok(/example\.com/.test(logOf(ssA)), "the server never saw example.com");
    assert.ok(mock.state.hits > 0, "the country probe did not go through the tunnel");
    assert.ok(existsSync(keyFile) && sha(keyFile));
    const bytes = readFileSync(keyFile).toString("latin1");
    for (const s of [ssA.password, "ss://", "chacha20"]) assert.ok(!bytes.includes(s), "the stored key is readable on disk: " + s);
    assert.equal(await $(control, "keyInput", "value"), "", "key left in the field");
    await control.evaluate("window.scrollTo(0, 0)"); await control.shot(join(shots, "ui-keyformats-connected-ss.png"));
  });

  await step("fail-closed still holds with Shadowsocks: when the server dies the window is cut off, never direct", async () => {
    const creds = ssA.creds; ssA.stop();
    await until(async () => (await fetchState(control, "https://example.com/")) === "failed", 20000);
    assert.equal(await fetchState(control, "https://example.com/"), "failed");
    const s2 = await startSsServer(mock.port, "chacha20-ietf-poly1305", creds); ssA.proc = s2.proc; ssA.h = s2.h; ssA.cleanup = s2.cleanup; ssA.stop = s2.stop;
    assert.ok(await until(async () => (await fetchState(control, "https://example.com/")) === "loaded", 60000), "traffic did not resume after the server came back");
  });

  await step("AEAD-2022 ss:// (percent-encoded key, not base64): replacement is verified, saved, and traffic uses the NEW server only", async () => {
    const h0 = sha(keyFile);
    await replaceWith(control, ss22.key);
    assert.ok(await statusIs(control, "Подключено через Россию"), "status: " + await status(control) + " | " + await note(control));
    assert.notEqual(sha(keyFile), h0, "the new key was not saved");
    const [viaNew, viaOld] = await growth(ss22, ssA, async () => assert.equal(await fetchState(control, "https://example.com/"), "loaded"));
    assert.ok(viaNew > 0 && viaOld === 0, `traffic: via 2022 +${viaNew}, via old +${viaOld}`);
  });

  // ---------------------------------------------------------------------------------------------------- ssconf://
  await step("ssconf:// (dynamic key): settings fetched over HTTPS by the launcher, connected, traffic crosses the server named in the JSON", async () => {
    const hits0 = providerHits;
    await replaceWith(control, dynKey);
    assert.ok(await statusIs(control, "Подключено через Россию"), "status: " + await status(control) + " | " + await note(control));
    assert.ok(providerHits > hits0, "the provider was never asked");
    const [viaA, viaOther] = await growth(ssA, ss22, async () => assert.equal(await fetchState(control, "https://example.com/"), "loaded"));
    assert.ok(viaA > 0 && viaOther === 0, `traffic: via A +${viaA}, via other +${viaOther}`);
    await noSecrets(control, "after a dynamic connect");
    const bytes = readFileSync(keyFile).toString("latin1");
    for (const s of [SECRET_PATH, TOKEN, "ssconf"]) assert.ok(!bytes.includes(s), "the saved dynamic link is readable on disk: " + s);
  });

  await step("the saved key is the LINK: the settings are loaded again at the next connection (the provider now points to another server)", async () => {
    routes.set(SECRET_PATH, serve(ss22.json()));
    const hits0 = providerHits;
    await click(control, "disconnectBtn");
    assert.ok(await statusIs(control, "Не подключено", 20000));
    const [viaNew, viaOld] = await growth(ss22, ssA, async () => {
      await click(control, "connectBtn");
      assert.ok(await statusIs(control, "Подключено через Россию"), "status: " + await status(control) + " | " + await note(control));
      assert.equal(await fetchState(control, "https://example.com/"), "loaded");
    });
    assert.ok(providerHits > hits0, "the settings were not fetched again");
    assert.ok(viaNew > 0 && viaOld === 0, `traffic: via new +${viaNew}, via old +${viaOld}`);
  });

  await step("failed update of a saved dynamic key is NOT shown as a connection: named, no secrets, key kept, a retry works", async () => {
    const h0 = sha(keyFile);
    routes.set(SECRET_PATH, serve("oops", 500, "text/plain"));
    await click(control, "disconnectBtn");
    assert.ok(await statusIs(control, "Не подключено", 20000));
    await click(control, "connectBtn");
    assert.ok(await statusIs(control, "Не удалось загрузить настройки ключа", 60000), "status: " + await status(control));
    const n = await note(control); assert.ok(/кодом 500/.test(n), n);
    assert.equal((await cores()).length, 0, "a core runs although the settings were not loaded");
    assert.equal(await fetchState(control, "https://example.com/"), "failed");
    assert.equal(sha(keyFile), h0, "the saved key changed");
    assert.equal(await vis(control, "retryBtn"), true);
    await noSecrets(control, "after a failed fetch");
    routes.set(SECRET_PATH, serve(ssA.json()));
    await click(control, "retryBtn");
    assert.ok(await statusIs(control, "Подключено через Россию", 90000), "status: " + await status(control) + " | " + await note(control));
  });

  // ---------------------------------------------------------------------------------------------------- refusals in a replacement
  const attempts = [
    ["settings page answers 404", () => routes.set("/bad", serve("no", 404, "text/plain")), "/bad", ["Не удалось загрузить настройки ключа", "кодом 404"]],
    ["settings with a prefix that is not one byte per character (EURO SIGN)", () => routes.set("/prefix", serve(ssA.json({ prefix: String.fromCharCode(0x20ac) }))), "/prefix", ["Префикс в ключе записан неверно"]],
    ["settings with a plugin", () => routes.set("/plugin", serve(ssA.json({ plugin: "v2ray-plugin", plugin_opts: "tls;host=x" }))), "/plugin", ["неподдерживаемые параметры", "v2ray-plugin"]],
    ["settings with an unknown parameter", () => routes.set("/extra", serve(ssA.json({ routing: { final: "direct" } }))), "/extra", ["неподдерживаемые параметры", "routing"]],
    ["settings with an obsolete cipher", () => routes.set("/rc4", serve(JSON.stringify({ server: "127.0.0.1", server_port: ssA.port, password: "x", method: "rc4-md5" }))), "/rc4", ["неподдерживаемые параметры", "rc4-md5"]],
    ["YAML with a websocket transport", () => routes.set("/yws", serve("transport:\n  $type: tcpudp\n  tcp:\n    $type: websocket\n    url: wss://x.example.org/s\n", 200, "text/yaml")), "/yws", ["неподдерживаемые параметры", "websocket"]],
    ["YAML with a list", () => routes.set("/ylist", serve("transport:\n  - a\n", 200, "text/yaml")), "/ylist", ["неподдерживаемые параметры", "списки"]],
    ["a web page instead of settings", () => routes.set("/html", serve("<html>Sign in</html>", 200, "text/html")), "/html", ["неподдерживаемые параметры", "не похож"]],
    ["redirect to plain http", () => routes.set("/down", (_q, res) => { res.writeHead(302, { location: "http://example.org/x" }); res.end(); }), "/down", ["Не удалось загрузить настройки ключа", "HTTP"]],
    ["redirect to a private address", () => routes.set("/priv", (_q, res) => { res.writeHead(302, { location: "https://10.0.0.5/x" }); res.end(); }), "/priv", ["Не удалось загрузить настройки ключа", "локальную"]],
  ];
  for (const [name, setup, path, mentions] of attempts) {
    await step(`replacement refused (${name}): named exactly, no secrets, previous connection and saved key untouched`, async () => {
      setup();
      const h0 = sha(keyFile);
      await replaceWith(control, `ssconf://localhost:${provPort}${path}?token=${TOKEN}`);
      await refused(control, "newKeyError", ...mentions);
      assert.equal(await status(control), "Подключено через Россию", "the previous connection was dropped");
      assert.equal(sha(keyFile), h0, "the saved key changed");
      assert.equal(await fetchState(control, "https://example.com/"), "loaded");
      await noSecrets(control, name);
      await click(control, "replaceCancel");
    });
  }
  await step("replacement refused: nothing listens at the settings address / an internal address / an untrusted certificate", async () => {
    const dead = await freePort();
    for (const [key, mention] of [[`ssconf://localhost:${dead}/x`, "не удалось подключиться"], ["ssconf://10.1.2.3/x?token=" + TOKEN, "локальную"], ["ssconf://127.0.0.1:" + provPort + "/x", "сертификат"]]) {
      await replaceWith(control, key);
      const t = await refused(control, "newKeyError", "Не удалось загрузить настройки ключа");
      assert.ok(t.includes(mention), `${key.slice(0, 20)}…: ${t}`);
      assert.equal(await status(control), "Подключено через Россию");
      await noSecrets(control, key.slice(0, 14));
      await click(control, "replaceCancel");
    }
  });
  await step("static ss:// refused in a replacement: a bad prefix, plugin, obsolete cipher, wrong key length, unknown parameter", async () => {
    const b64 = (x) => Buffer.from(x).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const ui = b64("chacha20-ietf-poly1305:" + ssA.password);
    for (const [key, mention] of [
      [`ss://${ui}@127.0.0.1:${ssA.port}/?prefix=%E2%82%AC`, "Префикс"], [`ss://${ui}@127.0.0.1:${ssA.port}/?plugin=obfs-local%3Bobfs%3Dhttp`, "obfs-local"],
      [`ss://${b64("rc4-md5:x")}@127.0.0.1:${ssA.port}`, "rc4-md5"], [`ss://2022-blake3-aes-256-gcm:${encodeURIComponent(Buffer.from("short").toString("base64"))}@127.0.0.1:1`, "байт"],
      [`ss://${ui}@127.0.0.1:${ssA.port}/?udp-over-tcp=1`, "udp-over-tcp"]]) {
      const h0 = sha(keyFile);
      await replaceWith(control, key);
      const t = await refused(control, "newKeyError", mention);
      assert.ok(!t.includes(ssA.password) && !t.includes("127.0.0.1"), "the refusal shows the key: " + t);
      assert.equal(sha(keyFile), h0); assert.equal(await status(control), "Подключено через Россию");
      await click(control, "replaceCancel");
    }
  });

  // ---------------------------------------------------------------------------------------------------- RU not confirmed / server down
  await step("Shadowsocks exit not in Russia: refused, window cut off, the saved key survives and reconnects", async () => {
    const h0 = sha(keyFile);
    mock.state.country = "DE";
    await replaceWith(control, ss22.key);
    try {
      assert.ok(await statusIs(control, "Выход не в России", 90000), "status: " + await status(control));
      assert.equal((await cores()).length, 0);
      assert.equal(await fetchState(control, "https://example.com/"), "failed");
      assert.equal(sha(keyFile), h0, "the saved key was overwritten by a key that failed the exit check");
    } finally { mock.state.country = "RU"; }
    await click(control, "retryBtn");
    assert.ok(await statusIs(control, "Подключено через Россию", 90000), "status: " + await status(control));
  });
  await step("Shadowsocks server down: 'Сервер недоступен', retry works when it is back", async () => {
    const deadServer = await startSsServer(mock.port, "aes-256-gcm"); const creds = deadServer.creds; deadServer.stop(); await until(async () => !(await portOpen(creds.port)), 8000);
    const key = deadServer.key;
    await goSettings(control); if (!(await vis(control, "replaceForm"))) await click(control, "replaceOpen");
    await setVal(control, "newKeyInput", key); await click(control, "replaceGo");
    assert.ok(await statusIs(control, "Сервер недоступен", 40000), "status: " + await status(control));
    assert.equal((await cores()).length, 0);
    await click(control, "retryBtn"); // returns to the saved key
    assert.ok(await statusIs(control, "Подключено через Россию", 90000));
    deadServer.cleanup();
  });

  // ---------------------------------------------------------------------------------------------------- VLESS regression
  await step("regression: VLESS+Reality still connects and carries traffic (replacement, verified, saved)", async () => {
    const h0 = sha(keyFile);
    await replaceWith(control, reality.key);
    assert.ok(await statusIs(control, "Подключено через Россию", 90000), "status: " + await status(control) + " | " + await note(control));
    assert.notEqual(sha(keyFile), h0);
    assert.equal(await fetchState(control, "https://example.com/"), "loaded");
    assert.ok(/example\.com/.test(reality.h.log.replace(/\x1b\[[0-9;]*m/g, "")), "the Reality server never saw example.com");
  });
  await step("regression: the old refusals stay (VLESS with allowInsecure, TLS without WebSocket)", async () => {
    await replaceWith(control, `vless://11111111-2222-3333-4444-555555555555@127.0.0.1:443?security=tls&type=ws&sni=h.example.org&allowInsecure=1`);
    await refused(control, "newKeyError", "проверку сертификата");
    await click(control, "replaceCancel");
    assert.equal(await status(control), "Подключено через Россию");
  });

  await step("hygiene: no secret on screen or in any command line at the end; one core; system proxy untouched", async () => {
    await noSecrets(control, "final");
    assert.equal((await cores()).length, 1);
    assert.equal(await sysProxy(), sysBefore);
  });

  await step("close the last window: everything of ours ends", async () => {
    await L.browser.send("Browser.close").catch(() => {});
    const code = await Promise.race([L.exited, sleep(20000).then(() => "timeout")]);
    assert.notEqual(code, "timeout");
    assert.ok(await until(async () => (await ours()).length === 0, 15000), "leftover: " + JSON.stringify((await ours()).map((p) => p.Name)));
  });
} finally {
  for (const s of [ssA, ss22, reality]) { try { s.stop(); s.cleanup(); } catch {} }
  provider.close(); mock.close();
  for (const p of await ours()) await killPid(p.ProcessId);
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
