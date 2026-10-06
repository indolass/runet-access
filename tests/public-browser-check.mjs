// Browser part with a FOREIGN public server, through the real launcher (RunetAccess.exe) and real Chrome.
// Scenario A (standard rules, default expected country RU): the key's exit is NOT in RU, so the app must REFUSE
//   with a country message (not a connection error), disconnect, and keep the window cut off from the internet.
// Scenario B (test-only RUNET_EXPECTED_COUNTRY = the server's real exit country, the check itself unchanged and
//   real: real country service through the tunnel + direct-address comparison): connect, then load a PUBLIC test
//   page in the browser (visible content, https, no certificate error), then close the window and verify cleanup.
// The key comes from .local\data\selected.json, travels only inside a CDP message to the local control page and is
// never printed. Output has no keys, hosts or full IPs. The owner's test-key.txt is not touched.
// Usage: node tests/public-browser-check.mjs [candidateId]
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import net from "node:net";
import { existsSync, readFileSync, rmSync, mkdirSync } from "node:fs";
import { root, connectBrowser, pageWhere, openPage, sleep } from "./cdp.mjs";

const run = promisify(execFile);
const exe = join(root, "dist", "runet-access", "RunetAccess.exe");
const home = join(root, ".local", "pub-home");
const shots = join(root, ".local", "logs", "shots"); mkdirSync(shots, { recursive: true });
const cands = JSON.parse(readFileSync(join(root, ".local", "data", "selected.json"), "utf8"));
const sb = JSON.parse(readFileSync(join(root, ".local", "data", "singbox-results.json"), "utf8"));
const pick = process.argv[2] || (sb.find((x) => x.ok) || {}).id;
const cand = cands.find((c) => c.id === pick);
const cc = (sb.find((x) => x.id === pick) || {}).exitCountry;
if (!cand || !cc || !/^[A-Z]{2}$/.test(cc)) { console.log("нет кандидата с подтверждённым транспортом"); process.exit(2); }
if (!existsSync(exe)) { console.log("сначала scripts\\build.ps1"); process.exit(2); }

const maskIp = (s) => String(s).replace(/\b(\d{1,3})(\.\d{1,3}){3}\b/g, "$1.x.x.x");
const log = (s) => console.log(maskIp(s));
process.on("unhandledRejection", (e) => { log("FATAL " + (e && e.message)); process.exit(1); });
const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const ps = async (script) => (await run("powershell", ["-NoProfile", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")])).stdout;
const ownLeft = async () => Number((await ps("(Get-CimInstance Win32_Process | Where-Object { $_.Name -in 'sing-box.exe','RunetAccess.exe' -or ($_.Name -eq 'chrome.exe' -and $_.CommandLine -like '*pub-home*') } | Measure-Object).Count")).trim());
const sysProxy = async () => (await run("reg", ["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"])).stdout.split(/\r?\n/).filter((l) => /Proxy|AutoConfig|AutoDetect/i.test(l)).sort().join("|");

async function launch(env) {
  rmSync(home, { recursive: true, force: true });
  const port = await freePort();
  const child = spawn(exe, [], { stdio: "ignore", env: { ...process.env, RUNET_TEST_MODE: "1", RUNET_ACCESS_HOME: home, RUNET_CHROME_EXTRA_ARGS: `--remote-debugging-port=${port}`, RUNET_NO_DIALOG: "1", ...env } });
  const exited = new Promise((r) => child.once("exit", r));
  const browser = await connectBrowser(port);
  const control = await pageWhere(browser, (u) => u.startsWith("http://127.0.0.1:"));
  await control.waitFor("document.getElementById('statusLine').textContent !== 'Загрузка…'", 20000);
  return { child, exited, browser, control };
}
const $ = (p, id, prop) => p.evaluate(`document.getElementById('${id}').${prop}`);
const fetchState = (p, url) => p.evaluate(`fetch(${JSON.stringify(url)}, { mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(15000) }).then(() => 'loaded', () => 'failed')`);
async function connect(control) {
  await control.evaluate(`(() => { const t = document.getElementById('keyInput'); t.value = ${JSON.stringify(cand.key)}; document.getElementById('remember').checked = false; document.getElementById('mainBtn').click(); return 1; })()`);
  const final = /^(Подключено|Выход не в нужной|Проверка показала|Подключение запущено, но|Компонент|Соединение прервано)/;
  const t0 = Date.now(); let st = "";
  while (Date.now() - t0 < 120000) { st = await $(control, "statusLine", "textContent"); if (final.test(st)) break; const ke = await $(control, "keyError", "textContent"); if (ke) { st = "KEYERR " + ke; break; } await sleep(500); }
  return { st, exitRow: (await $(control, "resExit", "innerText")).replace(/\s+/g, " "), directRow: (await $(control, "resDirect", "innerText")).replace(/\s+/g, " ") };
}

const out = { candidate: cand.id, section: cand.label, serverExit: cc };
const sysBefore = await sysProxy();

// ---------------- A: standard rules (expected RU) ----------------
log(`\n== Сценарий A: штатные правила (нужна RU), сервер кандидата ${cand.id} выходит в ${cc} ==`);
let L = await launch({});
{
  const r = await connect(L.control);
  out.A = { status: maskIp(r.st), exitRow: maskIp(r.exitRow), cutOff: await fetchState(L.control, "https://example.com/") };
  log(`статус: ${r.st}`); log(`строка выхода: ${maskIp(r.exitRow)} | ${maskIp(r.directRow)}`);
  const refusedByCountry = /Выход не в нужной стране/.test(r.st);
  const connError = /Компонент|Соединение прервано|не удалось|KEYERR/.test(r.st);
  out.A.refusedByCountry = refusedByCountry; out.A.reportedAsConnectionError = connError;
  log(`отказ по стране (а не ошибка соединения): ${refusedByCountry && !connError}`);
  log(`после отказа окно отрезано от интернета (example.com): ${out.A.cutOff === "failed" ? "да, не загрузилось" : "НЕТ, загрузилось (дефект)"}`);
  out.A.mainBtnAfter = await $(L.control, "mainBtn", "textContent");
}
await L.browser.send("Browser.close").catch(() => {});
await Promise.race([L.exited, sleep(25000)]);
await sleep(1500);

// ---------------- B: test-only expected country = real exit country ----------------
log(`\n== Сценарий B: тест-режим (RUNET_EXPECTED_COUNTRY=${cc}; проверка страны настоящая) ==`);
L = await launch({ RUNET_EXPECTED_COUNTRY: cc });
{
  const r = await connect(L.control);
  out.B = { status: maskIp(r.st), exitRow: maskIp(r.exitRow), directRow: maskIp(r.directRow) };
  log(`статус: ${r.st}`); log(`строка выхода: ${maskIp(r.exitRow)} | обычное соединение: ${maskIp(r.directRow)}`);
  const ip = (s) => (s.match(/\b(\d{1,3}\.){3}\d{1,3}\b/) || [""])[0];
  out.B.exitDiffersFromOrdinary = !!ip(r.exitRow) && !!ip(r.directRow) && ip(r.exitRow) !== ip(r.directRow);
  out.B.connected = r.st.startsWith("Подключено");
  if (out.B.connected) {
    const tab = await openPage(L.browser, "https://example.com/");
    const loaded = await tab.waitFor("/Example Domain/.test(document.title) && document.body.innerText.length > 100", 40000);
    const info = loaded ? JSON.parse(await tab.evaluate("JSON.stringify({ proto: location.protocol, title: document.title, textLen: document.body.innerText.length, h1: (document.querySelector('h1')||{}).innerText })")) : null;
    out.B.page = info ? { loaded: true, https: info.proto === "https:", title: info.title, h1: info.h1, visibleTextChars: info.textLen } : { loaded: false, url: maskIp(await tab.url()) };
    await tab.shot(join(shots, "pub-example.png"));
    log(`страница в браузере: ${info ? `открылась (https, заголовок «${info.title}», видимого текста ${info.textLen} символов)` : "НЕ открылась: " + out.B.page.url}`);
    // a second, different public page (title/text only) to show this is not a single cached site
    const tab2 = await openPage(L.browser, "https://api.country.is/");
    const ok2 = await tab2.waitFor("document.body && /country/.test(document.body.innerText)", 30000);
    out.B.secondPublicPage = ok2; log(`вторая публичная страница (api.country.is): ${ok2 ? "открылась" : "нет"}`);
    // Disconnect and fail-closed
    await L.control.evaluate("document.getElementById('mainBtn').click()");
    await sleep(2500);
    out.B.afterDisconnectCutOff = await fetchState(L.control, "https://example.com/");
    log(`после «Отключить» окно отрезано от интернета: ${out.B.afterDisconnectCutOff === "failed" ? "да" : "НЕТ (дефект)"}`);
  }
}
await L.browser.send("Browser.close").catch(() => {});
const code = await Promise.race([L.exited, sleep(25000).then(() => "timeout")]);
await sleep(2000);
out.closing = { launcherExited: code !== "timeout", ownedProcessesLeft: await ownLeft(), lockLeft: existsSync(join(home, "run.lock")) };
log(`закрытие окна: лаунчер завершился=${out.closing.launcherExited}; оставшихся процессов: ${out.closing.ownedProcessesLeft}; блокировка осталась: ${out.closing.lockLeft}`);
out.systemProxyUnchanged = (await sysProxy()) === sysBefore;
log(`системный прокси не изменился: ${out.systemProxyUnchanged}`);
rmSync(home, { recursive: true, force: true });
const fs = await import("node:fs");
fs.writeFileSync(join(root, ".local", "data", "browser-results.json"), JSON.stringify(out, null, 2));
