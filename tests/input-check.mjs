// Input path of the key field, in the REAL Chrome started by the shipped RunetAccess.exe.
//
// The other end-to-end tests fill the field by assigning element.value, which bypasses everything a user goes
// through. This test drives Chrome's own input pipeline via DevTools, bound to the test window only (no global
// keyboard or mouse events): a real mouse click into the field, real key events, Ctrl+V and Shift+Insert from
// the SYSTEM clipboard. The clipboard steps run only on a private window station (tests\input-check.ps1
// sets RUNET_PRIVATE_WINSTA), whose clipboard is separate from the one of the person at the computer.
// What is pasted is synthetic: no real key is needed or used.
//
//   . .\scripts\env.ps1; .\tests\input-check.ps1
import { spawn, execFile, spawnSync } from "node:child_process";
import { promisify } from "node:util";
import { join, dirname } from "node:path";
import { existsSync, rmSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { root, connectBrowser, pageWhere, sleep } from "./cdp.mjs";
import { freePort } from "./support.mjs";

const run = promisify(execFile);
const exe = process.env.RUNET_EXE || join(root, "dist", "runet-access", "RunetAccess.exe");
const exeDir = dirname(exe);
const home = join(root, ".local", "input-home");
const profile = join(home, "profile");
const shots = join(root, ".local", "logs", "shots"); mkdirSync(shots, { recursive: true });
assert.ok(existsSync(exe), "build first: scripts\\build.ps1 (or pass RUNET_EXE)");
assert.ok((process.env.TEMP || "").startsWith(root), "run inside scripts\\env.ps1 so TEMP is under the repo root");
const privateWinsta = process.env.RUNET_PRIVATE_WINSTA || "";

for (const ev of ["uncaughtException", "unhandledRejection"]) process.on(ev, (e) => { console.log("FATAL " + ev + ": " + ((e && e.stack) || e)); process.exit(1); });
let passed = 0, failed = 0, skipped = 0;
const step = async (name, fn) => { try { await fn(); passed++; console.log("PASS  " + name); } catch (e) { failed++; console.log("FAIL  " + name + "\n      " + (e && e.message)); } };
const skip = (name, why) => { skipped++; console.log("SKIP  " + name + "\n      " + why); };

const ps = async (script) => (await run("powershell", ["-NoProfile", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { maxBuffer: 1 << 24 })).stdout;
async function ours() {
  const out = await ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -in 'sing-box.exe','RunetAccess.exe','chrome.exe' } | Select-Object Name,ProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress");
  if (!out.trim()) return [];
  const j = JSON.parse(out); const all = Array.isArray(j) ? j : [j];
  const dist = exeDir.toLowerCase();
  return all.filter((p) => ((p.ExecutablePath || "").toLowerCase().startsWith(dist)) || (p.Name === "chrome.exe" && (p.CommandLine || "").toLowerCase().includes(profile.toLowerCase())));
}
const killPid = (pid) => run("taskkill", ["/F", "/PID", String(pid)]).catch(() => {});

// Synthetic texts. Nothing here is a working key.
const UUID = "11111111-2222-3333-4444-555555555555";
const SHORT = "ssconf://";
const TROJAN = "trojan://pw@203.0.113.1:443#x"; // unknown format for this program
const VLESS_TLS = `vless://${UUID}@192.0.2.10:443?security=tls&flow=xtls-rprx-vision`; // refused by shape, see launcher-e2e
const SSCONF = "ssconf://keys.example.invalid/api/v1/" + "a".repeat(140) + "#Synthetic%20Outline"; // a long dynamic key
const LONG = "vless://" + UUID + "@192.0.2.10:443?encryption=none&security=reality&sni=masque.example&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd1234&type=tcp&path=" + "x".repeat(3000) + "#synthetic";

async function launch() {
  const cdpPort = await freePort();
  const child = spawn(exe, [], {
    stdio: "ignore", windowsHide: false,
    env: { ...process.env, RUNET_TEST_MODE: "1", RUNET_ACCESS_HOME: home, RUNET_CHROME_EXTRA_ARGS: `--remote-debugging-port=${cdpPort}`,
      RUNET_NO_DIALOG: "1", RUNET_OPEN_LOG: join(home, "open.log") },
  });
  const exited = new Promise((r) => child.once("exit", r));
  const browser = await connectBrowser(cdpPort);
  const control = await pageWhere(browser, (u) => u.startsWith("http://127.0.0.1:"));
  assert.ok(await control.waitFor("document.getElementById('statusLine').textContent !== 'Загрузка…'", 20000), "control page did not initialise");
  return { child, exited, browser, control, cdpPort };
}
const $ = (p, id, prop) => p.evaluate(`document.getElementById('${id}').${prop}`);
const val = (p, id = "keyInput") => $(p, id, "value");
const vis = (p, id) => p.evaluate(`!document.getElementById('${id}').classList.contains('hidden')`);

// ---- real input, bound to the test page's target --------------------------------------------------------
const send = (L, method, params) => L.browser.send(method, params, L.control.sid);
async function center(L, id) {
  const r = JSON.parse(await L.control.evaluate(`(() => { const e = document.getElementById('${id}'); e.scrollIntoView({ block: 'center' }); const r = e.getBoundingClientRect(); return JSON.stringify({ x: r.left + r.width / 2, y: r.top + r.height / 2, w: r.width, h: r.height }); })()`));
  return r;
}
async function realClick(L, id) {
  const c = await center(L, id);
  await send(L, "Input.dispatchMouseEvent", { type: "mouseMoved", x: c.x, y: c.y });
  await send(L, "Input.dispatchMouseEvent", { type: "mousePressed", x: c.x, y: c.y, button: "left", clickCount: 1 });
  await send(L, "Input.dispatchMouseEvent", { type: "mouseReleased", x: c.x, y: c.y, button: "left", clickCount: 1 });
}
const VK = { a: 65, v: 86, Delete: 46, Insert: 45, Enter: 13, End: 35 };
async function key(L, k, { ctrl = false, shift = false, text } = {}) {
  const modifiers = (shift ? 8 : 0) | (ctrl ? 2 : 0);
  // A virtual-key code only for letters/digits (their VK equals the upper-case ASCII code). Deriving one from
  // punctuation would be wrong: "." is 46 = VK_DELETE, "&" is 38 = VK_UP, "#" is 35 = VK_END.
  const alnum = /^[a-z0-9]$/i.test(k);
  const code = alnum ? (/\d/.test(k) ? "Digit" + k : "Key" + k.toUpperCase()) : k;
  const vk = VK[k] ?? (alnum ? k.toUpperCase().charCodeAt(0) : 0);
  const down = { type: "keyDown", key: k, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk, modifiers };
  if (text !== undefined) { down.text = text; down.unmodifiedText = text; }
  await send(L, "Input.dispatchKeyEvent", down);
  await send(L, "Input.dispatchKeyEvent", { type: "keyUp", key: k, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk, modifiers });
}
async function typeText(L, s) { for (const ch of s) await key(L, ch, { text: ch }); }
// Focus the field first: after a click on a button the focus is on that button, and Ctrl+A would select the page.
async function selectAllDelete(L) { await realClick(L, "keyInput"); await key(L, "a", { ctrl: true }); await key(L, "Delete"); }

// System clipboard of THIS window station (private one only). Set-Clipboard runs as a child here, so it
// inherits the window station; nothing reaches WinSta0.
async function setClipboard(text) {
  assert.ok(privateWinsta, "clipboard steps need the private window station (tests\\input-check.ps1)");
  const b64 = Buffer.from(text, "utf8").toString("base64");
  await ps(`Set-Clipboard -Value ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}')))`);
  const back = (await ps(`[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Clipboard -Raw)))`)).trim();
  // Set-Clipboard/Get-Clipboard normalise a trailing line break; what matters is what Chrome pastes.
  assert.equal(Buffer.from(back, "base64").toString("utf8").replace(/\r?\n$/, ""), text.replace(/\r?\n$/, ""), "the private clipboard did not take the text");
}

rmSync(home, { recursive: true, force: true });
console.log(`exe: ${exe}`);
console.log(`window station: ${privateWinsta || "(none: clipboard steps are skipped)"}`);
let L = await launch();
let { control } = L;
const quit = async () => { L.child.kill(); await Promise.race([L.exited, sleep(5000)]); for (const p of await ours()) await killPid(p.ProcessId); };

try {
  await step("Chrome: real window, remote debugging; which targets exist besides the control page", async () => {
    await sleep(2500); // give first-run dialogs (if any) time to appear
    const { targetInfos } = await L.browser.send("Target.getTargets");
    const others = targetInfos.filter((t) => t.targetId !== control.targetId).map((t) => t.type + " " + t.url);
    console.log("      other targets: " + (others.length ? others.join(" | ") : "none"));
    const v = await L.browser.send("Browser.getVersion");
    const st = await control.evaluate("fetch('/api/state', { cache: 'no-store' }).then((r) => r.json())");
    console.log("      " + v.product + "; control page: " + await control.url() + "; RunetAccess " + st.version);
    const want = readFileSync(join(root, "VERSION"), "utf8").trim();
    if (!process.env.RUNET_EXE) assert.equal(st.version, want, "the exe under test is not the current VERSION");
    assert.ok(!others.some((u) => /search-engine-choice|privacy-sandbox|intro|signin/.test(u)), "a Chrome dialog is open over the window: " + others.join(" | "));
  });

  await step("first run: the key field is shown, enabled, writable, without a length limit, and nothing covers it", async () => {
    assert.ok(await vis(control, "viewFirst"), "first-run view hidden");
    const s = JSON.parse(await control.evaluate(`(() => { const e = document.getElementById('keyInput'); e.scrollIntoView({ block: 'center' }); const r = e.getBoundingClientRect(); const cs = getComputedStyle(e);
      const top = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
      return JSON.stringify({ disabled: e.disabled, readOnly: e.readOnly, maxLength: e.maxLength, w: r.width, h: r.height, display: cs.display, visibility: cs.visibility, pointer: cs.pointerEvents, select: cs.userSelect, top: top && (top.id || top.tagName), hidden: !!e.closest('.hidden') }); })()`));
    console.log("      field: " + JSON.stringify(s));
    assert.equal(s.disabled, false); assert.equal(s.readOnly, false); assert.equal(s.maxLength, -1, "a maxlength is set");
    assert.ok(s.w > 100 && s.h > 30, "field has no size"); assert.equal(s.hidden, false);
    assert.equal(s.display !== "none" && s.visibility === "visible" && s.pointer !== "none" && s.select !== "none", true);
    assert.equal(s.top, "keyInput", "something else is on top of the field: " + s.top);
  });

  await step("real mouse click into the field focuses it", async () => {
    await send(L, "Page.bringToFront", {});
    await send(L, "Emulation.setFocusEmulationEnabled", { enabled: true }); // the test window has no OS focus
    await realClick(L, "keyInput");
    assert.ok(await control.waitFor("document.activeElement && document.activeElement.id === 'keyInput'", 3000), "active element: " + await control.evaluate("document.activeElement && (document.activeElement.id || document.activeElement.tagName)"));
  });

  await step("real key events: typed text appears and stays through the periodic refresh (6 s)", async () => {
    await typeText(L, SHORT);
    assert.equal(await val(control), SHORT);
    await sleep(6000); // /api/state is polled every 2 s and re-renders the page
    assert.equal(await val(control), SHORT, "the field was changed by a refresh");
    assert.equal(await control.evaluate("document.activeElement.id"), "keyInput", "focus left the field");
  });

  await step("select all + Delete clears it; typing again works", async () => {
    await selectAllDelete(L);
    assert.equal(await val(control), "");
    await typeText(L, "ss");
    assert.equal(await val(control), "ss");
    await selectAllDelete(L);
  });

  if (privateWinsta) {
    await step("Ctrl+V from the system clipboard pastes a long dynamic key (ssconf://) unchanged", async () => {
      await setClipboard(SSCONF);
      await realClick(L, "keyInput");
      await key(L, "v", { ctrl: true });
      assert.ok(await control.waitFor("document.getElementById('keyInput').value.length > 0", 3000), "nothing was pasted");
      assert.equal(await val(control), SSCONF);
    });

    await step("the pasted text survives 5 s of status polling and the connect button is enabled", async () => {
      await sleep(5000);
      assert.equal(await val(control), SSCONF);
      assert.equal(await $(control, "mainBtn", "disabled"), false);
    });

    await step("Shift+Insert (the other paste shortcut) pastes a 3 000+ character key with nothing cut off", async () => {
      await setClipboard(LONG);
      await selectAllDelete(L);
      await key(L, "Insert", { shift: true });
      assert.ok(await control.waitFor("document.getElementById('keyInput').value.length > 0", 3000), "nothing was pasted");
      const v = await val(control);
      assert.equal(v.length, LONG.length, `length ${v.length} != ${LONG.length}`);
      assert.equal(v, LONG);
    });

    await step("paste with surrounding spaces/newlines is kept as typed (trimming happens in the launcher)", async () => {
      await setClipboard("  " + TROJAN + "\r\n");
      await selectAllDelete(L);
      await key(L, "v", { ctrl: true });
      await sleep(300);
      const v = await val(control);
      assert.ok(v.startsWith("  " + TROJAN), "pasted: " + JSON.stringify(v));
    });
  } else {
    for (const n of ["Ctrl+V from the system clipboard", "Shift+Insert paste", "paste with surrounding spaces"]) skip(n, "no private window station");
  }

  await step("unknown format: a real click on «Подключиться» shows the message, the typed text is kept and still editable", async () => {
    await realClick(L, "keyInput"); await selectAllDelete(L);
    await typeText(L, TROJAN);
    assert.equal(await val(control), TROJAN);
    await realClick(L, "mainBtn");
    assert.ok(await control.waitFor("document.getElementById('keyError').textContent.length > 0", 8000), "no message");
    const t = await $(control, "keyError", "textContent");
    console.log("      message: " + t.replace(/\n/g, " / "));
    assert.match(t, /Неизвестный формат ключа/);
    assert.ok((await val(control)).includes(TROJAN), "the text was lost: " + JSON.stringify(await val(control)));
    assert.equal(await vis(control, "viewFirst"), true);
    await realClick(L, "keyInput");
    await key(L, "End");
    await typeText(L, "z");
    assert.ok((await val(control)).endsWith("z"), "typing after the error does not work");
    assert.ok(await control.waitFor("document.getElementById('keyError').classList.contains('hidden')", 2000), "the message does not clear on input");
    await L.control.shot(join(shots, "input-check-format-error.png"));
  });

  await step("refused-by-shape key: the message names the reason, the field keeps the text, no connection started", async () => {
    await selectAllDelete(L);
    await typeText(L, VLESS_TLS);
    await realClick(L, "mainBtn");
    assert.ok(await control.waitFor("document.getElementById('keyError').textContent.length > 0", 8000), "no message");
    assert.equal(await val(control), VLESS_TLS);
    assert.equal(await $(control, "statusLine", "textContent"), "Не подключено");
    assert.equal((await ours()).filter((p) => p.Name === "sing-box.exe").length, 0);
  });

  await step("Enter in the field submits; an empty field says so and stays usable", async () => {
    await selectAllDelete(L);
    await key(L, "Enter", { text: "\r" });
    assert.ok(await control.waitFor("document.getElementById('keyError').textContent === 'Вставьте ключ подключения.'", 3000), "message: " + await $(control, "keyError", "textContent"));
    await typeText(L, "q");
    assert.equal(await val(control), "q");
    await selectAllDelete(L);
  });

  await step("a very long paste (> 8 KiB) is refused with a plain message and the text is kept", async () => {
    const huge = "ss://" + "A".repeat(9000) + "#x";
    await realClick(L, "keyInput"); await selectAllDelete(L);
    if (privateWinsta) { await setClipboard(huge); await key(L, "v", { ctrl: true }); }
    else await send(L, "Input.insertText", { text: huge });
    assert.ok(await control.waitFor(`document.getElementById('keyInput').value.length === ${huge.length}`, 3000), "length " + (await val(control)).length);
    await realClick(L, "mainBtn");
    assert.ok(await control.waitFor("document.getElementById('keyError').textContent.length > 0", 10000), "no message under the field; status: " + await $(control, "statusLine", "textContent") + " / " + await $(control, "statusNote", "textContent"));
    const under = await $(control, "keyError", "textContent");
    console.log("      under the field: " + JSON.stringify(under) + "; status: " + await $(control, "statusLine", "textContent") + " / " + await $(control, "statusNote", "textContent"));
    assert.equal((await val(control)).length, huge.length, "text lost");
    // 0.4.0 answered "Подключение не запустилось / Некорректный запрос." (the request body limit); since 0.4.1 the
    // message is under the field and says what is wrong.
    assert.match(under, /слишком длинный/);
    assert.equal(await $(control, "statusLine", "textContent"), "Не подключено");
    await selectAllDelete(L);
  });

  await step("the whole run: no core started, no key file, only our processes", async () => {
    assert.ok(!existsSync(join(home, "key.dpapi")));
    const mine = await ours();
    assert.equal(mine.filter((p) => p.Name === "sing-box.exe").length, 0);
    assert.ok(mine.some((p) => p.Name === "RunetAccess.exe"));
  });
} finally {
  await quit();
  const left = await ours();
  if (left.length) console.log("LEFTOVER processes: " + JSON.stringify(left.map((p) => p.Name + ":" + p.ProcessId)));
  rmSync(home, { recursive: true, force: true });
}
console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped`);
writeFileSync(join(root, ".local", "logs", "input-check.exit"), failed ? "1" : "0"); // read by tests\input-check.ps1
process.exit(failed ? 1 : 0);
