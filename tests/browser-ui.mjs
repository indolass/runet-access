// Browser test that needs NO registry changes: loads the built extension in a separate
// Chrome profile under .local\browser-profile and checks the UI without the native host.
// Run (after scripts\build.ps1):  . .\scripts\env.ps1; node tests\browser-ui.mjs
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { existsSync, mkdirSync } from "node:fs";
import assert from "node:assert/strict";
import { root, launchChrome, findExtensionId, openPage } from "./cdp.mjs";

const extDir = join(root, "dist", "runet-access", "extension");
const extId = execFileSync("node", [join(root, "scripts", "ext-id.mjs")], { encoding: "utf8" }).trim();
const shots = join(root, ".local", "logs", "shots"); mkdirSync(shots, { recursive: true });

let passed = 0, failed = 0;
const step = async (name, fn) => { try { await fn(); passed++; console.log("PASS  " + name); } catch (e) { failed++; console.log("FAIL  " + name + "\n      " + (e && e.message)); } };

const chrome = await launchChrome({ profileName: "ui-test", extensionDir: extDir });
try {
  assert.equal(chrome.extId, extId, "loaded extension id differs from the manifest-derived id");
  console.log("extension loaded, id matches manifest key:", chrome.extId === extId);

  const page = await openPage(chrome.browser, `chrome-extension://${extId}/src/gov/gov.html`);
  assert.ok(await page.waitFor("document.getElementById('statusLine').textContent !== 'Проверяю…'", 15000), "popup never left the initial state");

  await step("without the native host the popup says so, plainly", async () => {
    assert.equal(await page.evaluate("!document.getElementById('hostMissing').classList.contains('hidden')"), true);
    assert.match(await page.evaluate("document.getElementById('statusLine').textContent"), /не найдена/i);
    assert.equal(await page.evaluate("document.getElementById('mainBtn').disabled"), true);
  });
  await page.shot(join(shots, "popup-no-host.png"));

  const setKey = (v) => page.evaluate(`(() => { const t = document.getElementById('keyInput'); t.value = ${JSON.stringify(v)}; t.dispatchEvent(new Event('input')); return true; })()`);
  const errText = () => page.evaluate("document.getElementById('keyError').textContent");

  // Enable the button for validation tests by bypassing the host check (UI-only: we are testing validation).
  await page.evaluate("document.getElementById('mainBtn').disabled = false");

  const SYN = "vless://11111111-2222-3333-4444-555555555555@192.0.2.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=masque.example&fp=chrome&pbk=" + "A".repeat(43) + "&sid=abcd1234&type=tcp#synthetic";

  await step("bad key shows a plain message that does not repeat the key", async () => {
    await setKey("vless://11111111-2222-3333-4444-555555555555@192.0.2.10:443?security=tls&flow=xtls-rprx-vision");
    await page.evaluate("document.getElementById('mainBtn').click()");
    assert.ok(await page.waitFor("document.getElementById('keyError').textContent.length > 0", 3000));
    const t = await errText();
    assert.match(t, /Reality/);
    for (const s of ["11111111-2222", "192.0.2.10"]) assert.ok(!t.includes(s));
  });
  await page.shot(join(shots, "popup-bad-key.png"));

  await step("a good key is accepted by validation; with no host the failure is friendly and the field is cleared", async () => {
    await setKey(SYN);
    await page.evaluate("document.getElementById('mainBtn').click()");
    assert.ok(await page.waitFor("document.getElementById('statusLine').className.includes('err')", 15000), "no error status");
    const st = await page.evaluate("document.getElementById('statusLine').textContent");
    assert.match(st, /программа подключения|установщик/i);
    for (const s of ["11111111-2222", "192.0.2.10", "abcd1234"]) assert.ok(!st.includes(s), "status leaks key material");
    assert.equal(await page.evaluate("document.getElementById('keyInput').value"), "", "key left in the textarea");
  });

  await step("settings: https-only site URL, extra domains normalized, persisted", async () => {
    await page.evaluate("document.getElementById('settings').open = true");
    await page.evaluate("(() => { const u = document.getElementById('siteUrl'); u.value = 'http://insecure.example'; document.getElementById('saveSettings').click(); return true; })()");
    assert.ok(await page.waitFor("document.getElementById('settingsMsg').textContent.includes('https')", 3000));
    await page.evaluate("(() => { document.getElementById('siteUrl').value = 'https://lk.example.ru/start'; document.getElementById('siteExtra').value = 'SSO.example.ru\\nnot a domain'; document.getElementById('saveSettings').click(); return true; })()");
    assert.ok(await page.waitFor("document.getElementById('settingsMsg').textContent.startsWith('Сохранено')", 3000));
    assert.match(await page.evaluate("document.getElementById('settingsMsg').textContent"), /Не распознаны/);
    const stored = await page.evaluate("chrome.storage.local.get('gov').then((d) => JSON.stringify(d.gov))");
    const g = JSON.parse(stored);
    assert.equal(g.url, "https://lk.example.ru/start");
    assert.deepEqual(g.extraDomains, ["sso.example.ru"]);
    const routing = JSON.parse(await page.evaluate("chrome.storage.local.get('routing').then((d) => JSON.stringify(d.routing))"));
    assert.equal(routing.mode, "rules");
    assert.deepEqual(routing.proxyDomains.sort(), ["api.country.is", "ipwho.is", "lk.example.ru", "sso.example.ru"]);
  });
  await page.shot(join(shots, "popup-settings.png"));

  await step("the browser proxy setting was NOT touched by any of this", async () => {
    const lvl = await page.evaluate("chrome.proxy.settings.get({}).then((s) => JSON.stringify({ level: s.levelOfControl, mode: s.value.mode }))");
    const j = JSON.parse(lvl);
    assert.notEqual(j.level, "controlled_by_this_extension", lvl);
  });
} finally {
  await chrome.close();
}
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
