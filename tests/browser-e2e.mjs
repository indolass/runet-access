// End-to-end test in a REAL Chrome (separate profile under .local\browser-profile) with the native host
// registered. Run through scripts\run-browser-e2e.ps1, which registers the host (HKCU) for the test and
// ALWAYS removes it afterwards, and compares the Windows proxy settings before/after.
//
// Synthetic VLESS+Reality server; a mock of the country service reachable ONLY through the tunnel.
// Needs internet for: the Reality mask host, https://example.com/ (stand-in for a gov site), api.ipify.org.
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { existsSync, readdirSync, rmSync, mkdirSync } from "node:fs";
import assert from "node:assert/strict";
import { root, launchChrome, openPage } from "./cdp.mjs";
import { startMock, startSyntheticServer, buildTestExtension, sleep, until, MOCK_HOST } from "./support.mjs";

const shots = join(root, ".local", "logs", "shots"); mkdirSync(shots, { recursive: true });
// print fatal errors on stdout (PowerShell 5.1 mangles native stderr)
for (const ev of ["uncaughtException", "unhandledRejection"]) process.on(ev, (e) => { console.log("FATAL " + ev + ": " + ((e && e.stack) || e)); process.exit(1); });
let passed = 0, failed = 0;
const step = async (name, fn) => { try { await fn(); passed++; console.log("PASS  " + name); } catch (e) { failed++; console.log("FAIL  " + name + "\n      " + (e && e.message)); } };

const ps = (script) => spawnSync("powershell", ["-NoProfile", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { encoding: "utf8" }).stdout;
const coreProcs = () => {
  const out = ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -in 'sing-box.exe','runet-access-host.exe' } | Select-Object Name,ProcessId,ExecutablePath | ConvertTo-Json -Compress");
  if (!out.trim()) return [];
  const j = JSON.parse(out); return (Array.isArray(j) ? j : [j]).filter((p) => (p.ExecutablePath || "").toLowerCase().includes("dist\\runet-access"));
};
const curlDirect = () => spawnSync("curl.exe", ["-sS", "--max-time", "20", "https://api.ipify.org"], { encoding: "utf8" }).stdout.trim();
const killByName = (pid) => spawnSync("taskkill", ["/F", "/PID", String(pid)]);

const DIRECT_IP = curlDirect();
assert.match(DIRECT_IP, /^\d+\.\d+\.\d+\.\d+$/, "no direct internet for the reference IP");

const mock = await startMock();
let server = await startSyntheticServer(mock.port);
const testExt = buildTestExtension();
rmSync(join(root, ".local", "browser-profile", "e2e"), { recursive: true, force: true });
const chrome = await launchChrome({ profileName: "e2e", extensionDir: testExt });
const EXT = chrome.extId;
console.log("extension id:", EXT);

const $ = (p, id, prop) => p.evaluate(`document.getElementById('${id}').${prop}`);
const clickBtn = (p, id) => p.evaluate(`document.getElementById('${id}').click()`);
const setVal = (p, id, v) => p.evaluate(`(() => { const e = document.getElementById('${id}'); e.value = ${JSON.stringify(v)}; e.dispatchEvent(new Event('input')); return true; })()`);
const status = (p) => $(p, "statusLine", "textContent");
const proxyState = (p) => p.evaluate("chrome.proxy.settings.get({}).then((s) => JSON.stringify({ level: s.levelOfControl, mode: s.value.mode, pac: s.value.pacScript && s.value.pacScript.data }))").then(JSON.parse);
const fetchState = (p, url) => p.evaluate(`fetch(${JSON.stringify(url)}, { mode: 'no-cors', cache: 'no-store' }).then(() => 'loaded', () => 'failed')`);

const diag = async (p) => {
  const tail = server.h.log.replace(/\x1b\[[0-9;]*m/g, "").split("\n").slice(-12).join("\n");
  const sw = await p.evaluate("new Promise((r) => chrome.runtime.sendMessage({ cmd: 'logs' }, (x) => r(JSON.stringify(x.data.slice(-8)))))");
  const res = await p.evaluate("document.getElementById('results').innerText");
  console.log(`      DIAG mock hits=${mock.state.hits}\n      server log tail:\n${tail}\n      SW logs: ${sw}\n      results: ${res.replace(/\n/g, " | ")}`);
};

try {
  const popup = await openPage(chrome.browser, `chrome-extension://${EXT}/src/gov/gov.html`);
  assert.ok(await popup.waitFor("document.getElementById('statusLine').textContent !== 'Проверяю…'", 20000), "popup init stuck");

  await step("native host is found by Chrome (registered), the popup enables Connect", async () => {
    assert.equal(await popup.evaluate("document.getElementById('hostMissing').classList.contains('hidden')"), true, "host reported missing: " + await status(popup));
    assert.equal(await $(popup, "mainBtn", "disabled"), false);
  });

  await step("settings saved: site https://example.com/ (stand-in for the gov site)", async () => {
    await popup.evaluate("document.getElementById('settings').open = true");
    await setVal(popup, "siteUrl", "https://example.com/");
    await clickBtn(popup, "saveSettings");
    assert.ok(await popup.waitFor("document.getElementById('settingsMsg').textContent.startsWith('Сохранено')", 5000));
  });

  await step("paste key -> Connect -> exit confirmed (RU via the tunnel), site answers, field cleared", async () => {
    await setVal(popup, "keyInput", server.key);
    await clickBtn(popup, "mainBtn");
    const okc = await popup.waitFor("document.getElementById('statusLine').textContent.startsWith('Подключено')", 90000);
    if (!okc) await diag(popup);
    assert.ok(okc, "status: " + await status(popup));
    assert.equal(await $(popup, "resExit", "innerText").then((t) => t.replace(/\s+/g, " ")), "Выход через сервер RU · 203.0.113.77");
    assert.ok((await $(popup, "resDirect", "innerText")).includes(DIRECT_IP), "direct row: " + await $(popup, "resDirect", "innerText"));
    assert.match(await $(popup, "resSite", "innerText"), /отвечает/);
    assert.equal(await $(popup, "openBtn", "disabled"), false);
    assert.equal(await $(popup, "keyInput", "value"), "");
    assert.ok(mock.state.hits > 0, "mock never reached: the probe did not use the tunnel");
  });
  await popup.shot(join(shots, "popup-connected.png"));

  await step("Chrome proxy is a mandatory PAC that lists the site + probe and NOT the direct reference", async () => {
    const s = await proxyState(popup);
    assert.equal(s.level, "controlled_by_this_extension");
    assert.equal(s.mode, "pac_script");
    assert.ok(s.pac.includes("example.com") && s.pac.includes(MOCK_HOST));
    assert.ok(!s.pac.includes("api.ipify.org"));
  });

  await step("'Open site' opens the site in a new tab and it loads through the tunnel", async () => {
    await clickBtn(popup, "openBtn");
    let t = null;
    assert.ok(await until(async () => {
      const { targetInfos } = await chrome.browser.send("Target.getTargets");
      t = targetInfos.find((x) => x.type === "page" && x.url.startsWith("https://example.com"));
      return !!t;
    }, 15000), "no tab for the site");
    const sid = await chrome.browser.attach(t.targetId);
    await chrome.browser.send("Runtime.enable", {}, sid);
    let title = "";
    assert.ok(await until(async () => {
      const r = await chrome.browser.send("Runtime.evaluate", { expression: "document.title", returnByValue: true }, sid);
      title = r.result.value; return /Example Domain/.test(title);
    }, 20000), "title: " + title);
    assert.ok(/example\.com/.test(server.h.log), "server never saw example.com: the site did not use the tunnel");
  });

  await step("ordinary internet in the same Chrome profile stays direct (api.ipify.org shows the REAL ip)", async () => {
    const p = await openPage(chrome.browser, "https://api.ipify.org/");
    assert.ok(await p.waitFor("document.body && document.body.innerText.trim().length > 0", 20000));
    assert.equal((await p.evaluate("document.body.innerText")).trim(), DIRECT_IP);
    assert.equal(curlDirect(), DIRECT_IP, "other programs: direct ip changed");
    assert.ok(!/api\.ipify\.org/.test(server.h.log), "ordinary traffic reached the tunnel server");
  });

  await step("one core + one host are running, both from dist\\runet-access", async () => {
    const names = coreProcs().map((p) => p.Name).sort();
    assert.deepEqual(names, ["runet-access-host.exe", "sing-box.exe"], JSON.stringify(names));
  });

  await step("FAIL-CLOSED: tunnel dies -> the gov site does NOT silently load directly; ordinary internet still works", async () => {
    server.stop();
    await sleep(1500);
    assert.equal(await fetchState(popup, "https://example.com/"), "failed", "site loaded although the tunnel is dead");
    assert.equal(await fetchState(popup, "https://api.ipify.org/"), "loaded", "ordinary internet broke");
  });

  await step("re-check with a dead tunnel is reported as undetermined, never as success; Open site disabled", async () => {
    await clickBtn(popup, "recheckBtn");
    assert.ok(await popup.waitFor("document.getElementById('statusLine').textContent.includes('не удалось')", 60000), "status: " + await status(popup));
    assert.equal(await $(popup, "openBtn", "disabled"), true);
    assert.ok(!(await status(popup)).startsWith("Подключено"));
  });

  await step("Disconnect: proxy released, site now loads directly (proves the rule is gone), core and host stop", async () => {
    await clickBtn(popup, "mainBtn");
    assert.ok(await popup.waitFor("document.getElementById('statusLine').textContent.startsWith('Отключено')", 20000), "status: " + await status(popup));
    const s = await proxyState(popup);
    assert.notEqual(s.level, "controlled_by_this_extension", JSON.stringify({ level: s.level, mode: s.mode }));
    assert.equal(await fetchState(popup, "https://example.com/"), "loaded", "still not direct after disconnect");
    assert.ok(await until(() => coreProcs().filter((p) => p.Name === "sing-box.exe").length === 0, 8000), "core still running");
  });

  // ---- wrong exit country / traffic bypassing the proxy ----
  server.cleanup(); server = await startSyntheticServer(mock.port);

  await step("replace key; wrong exit country (DE) -> refused and automatically disconnected, proxy released", async () => {
    mock.state.country = "DE";
    await clickBtn(popup, "keyReplace");
    await setVal(popup, "keyInput", server.key);
    await clickBtn(popup, "mainBtn");
    assert.ok(await popup.waitFor("document.getElementById('statusLine').textContent.includes('не в нужной стране')", 90000), "status: " + await status(popup));
    assert.ok(await popup.waitFor("document.getElementById('mainBtn').textContent === 'Подключить'", 20000));
    assert.notEqual((await proxyState(popup)).level, "controlled_by_this_extension");
    assert.equal(await $(popup, "openBtn", "disabled"), true);
  });
  await popup.shot(join(shots, "popup-wrong-country.png"));

  await step("proxied probe returns the SAME ip as direct -> 'traffic is not using the server', disconnected", async () => {
    mock.state.country = "RU"; mock.state.ip = DIRECT_IP;
    await clickBtn(popup, "mainBtn");
    assert.ok(await popup.waitFor("document.getElementById('statusLine').textContent.includes('тот же адрес')", 90000), "status: " + await status(popup));
    assert.ok(await popup.waitFor("document.getElementById('mainBtn').textContent === 'Подключить'", 20000));
  });

  await step("recovery: good exit again -> Connected", async () => {
    mock.state.ip = "203.0.113.77";
    await clickBtn(popup, "mainBtn");
    assert.ok(await popup.waitFor("document.getElementById('statusLine').textContent.startsWith('Подключено')", 90000), "status: " + await status(popup));
  });

  await step("popup reopened while connected re-verifies by itself", async () => {
    const p2 = await openPage(chrome.browser, `chrome-extension://${EXT}/src/gov/gov.html`);
    assert.ok(await p2.waitFor("document.getElementById('statusLine').textContent.startsWith('Подключено')", 60000), "status: " + await status(p2));
    assert.equal(await p2.evaluate("document.getElementById('mainBtn').textContent"), "Отключить");
  });

  await step("Disconnect + 'Delete key' removes the saved key from extension storage", async () => {
    await clickBtn(popup, "mainBtn");
    assert.ok(await popup.waitFor("document.getElementById('statusLine').textContent.startsWith('Отключено')", 20000));
    await clickBtn(popup, "keyForget");
    assert.ok(await popup.waitFor("document.getElementById('statusLine').textContent.includes('Ключ удалён')", 5000));
    const all = await popup.evaluate("chrome.storage.local.get(null).then((d) => JSON.stringify(d))");
    for (const secret of [server.uuid, "pbk", "xtls-rprx-vision"]) assert.ok(!all.includes(secret), "storage still holds: " + secret);
  });
} finally {
  await chrome.close();
  server.stop(); server.cleanup(); mock.close();
}

await step("after Chrome exits: no host/core left, no work dir with a config", async () => {
  assert.ok(await until(() => coreProcs().length === 0, 15000), "leftover: " + JSON.stringify(coreProcs()));
  const wd = join(process.env.TEMP, "runet-access");
  await until(() => !existsSync(wd) || readdirSync(wd).length === 0, 10000);
  const left = existsSync(wd) ? readdirSync(wd) : [];
  // The secret is what matters: no config.json may survive. An empty per-host dir is reported, not a failure.
  for (const d of left) assert.ok(!existsSync(join(wd, d, "config.json")), "config.json left in " + d);
  console.log("      (work dirs remaining after Chrome exit: " + (left.length ? left.join(", ") + " — contents: [" + left.flatMap((d) => readdirSync(join(wd, d))).join(",") + "]" : "none") + ")");
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
