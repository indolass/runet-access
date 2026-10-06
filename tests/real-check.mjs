// Real-key check of the special browser: Russian exit + public pages of three gov sites.
// The key is read from .local\secrets\test-key.txt INSIDE this process: it is never printed,
// never put in a command line, never logged. The file is NEVER deleted by this script (owner removes it).
// Only public pages are opened. No logins, no signing, no report submission. Captchas are NOT
// solved or bypassed: they are recorded as "Критерий не пройден: капча".
// Run:  . .\scripts\env.ps1; node tests\real-check.mjs
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import net from "node:net";
import { existsSync, readFileSync, rmSync, mkdirSync, writeFileSync, statSync } from "node:fs";
import { root, connectBrowser, pageWhere, sleep } from "./cdp.mjs";
import { classifyPage, DOM_PROBE } from "./page-verdict.mjs";

const run = promisify(execFile);
const exe = join(root, "dist", "runet-access", "RunetAccess.exe");
const home = join(root, ".local", "real-home");
const keyFile = join(root, ".local", "secrets", "test-key.txt");
const shots = join(root, ".local", "logs", "shots"); mkdirSync(shots, { recursive: true });
const SITES = [
  { id: "gosuslugi", name: "Госуслуги", url: "https://www.gosuslugi.ru/" },
  { id: "fns", name: "ФНС", url: "https://www.nalog.gov.ru/" },
  { id: "minjust", name: "Минюст", url: "https://minjust.gov.ru/" },
];

const maskIp = (s) => String(s || "").replace(/\b(\d{1,3})(\.\d{1,3}){3}\b/g, "$1.x.x.x");
const log = (s) => console.log(maskIp(s));
process.on("unhandledRejection", (e) => { log("FATAL " + (e && e.message)); cleanup().finally(() => process.exit(1)); });

async function cleanup() {
  // Owner's decision: the scripts NEVER delete the key file; the owner removes it when done.
}

// ---- wait for the key file (the owner pastes it locally) --------------------------------
mkdirSync(join(root, ".local", "secrets"), { recursive: true });
if (!existsSync(keyFile)) writeFileSync(keyFile, "");
log("Жду ключ в файле .local\\secrets\\test-key.txt (содержимое не читается в логи)...");
let key = "";
{
  const deadline = Date.now() + 40 * 60 * 1000;
  let lastSize = -1, stableSince = 0; const warned = new Set();
  while (Date.now() < deadline) {
    const sz = statSync(keyFile).size;
    if (sz > 0) {
      if (sz === lastSize) {
        if (Date.now() - stableSince > 3000 && !warned.has(sz)) {
          const t = readFileSync(keyFile, "utf8").trim();
          // the part after '#' is only a display name and may contain spaces
          if (/^vless:\/\/\S+$/i.test(t.split("#")[0])) { key = t; break; }
          warned.add(sz); // look at the file again only after it changes
          log(`В файле ${sz} байт, но это не одна строка vless://... без пробелов (пробельных символов до #: ${(t.split("#")[0].match(/\s/g) || []).length}; начинается с vless://: ${/^vless:\/\//i.test(t)}). Исправьте файл и сохраните; я жду.`);
        }
      }
      else { lastSize = sz; stableSince = Date.now(); }
    }
    await sleep(1500);
  }
  if (!key) { log("Ключ так и не появился в файле (или он не начинается с vless://). Проверка не выполнялась."); await cleanup(); process.exit(2); }
}
log("Ключ получен из файла (" + key.length + " символов; содержимое не показывается).");
{
  // Pre-check the format so a malformed paste does not cost a run (and the file is kept for correction).
  const ws = (key.split("#")[0].match(/\s/g) || []).length;
  const lines = readFileSync(keyFile, "utf8").split(/\r?\n/).filter((l) => l.trim()).length;
  if (ws > 0 || lines > 1) {
    log(`Ключ не принят: внутри ${ws} пробельных символов, непустых строк в файле: ${lines}. Нужна ОДНА строка без пробелов. Файл не удалён; исправьте его и запустите проверку снова.`);
    process.exit(3);
  }
}

// ---- start the special browser -----------------------------------------------------------
rmSync(home, { recursive: true, force: true });
const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const cdpPort = await freePort();
const child = spawn(exe, [], { stdio: "ignore", env: { ...process.env, RUNET_ACCESS_HOME: home, RUNET_CHROME_EXTRA_ARGS: `--remote-debugging-port=${cdpPort}`, RUNET_NO_DIALOG: "1" } });
const exited = new Promise((r) => child.once("exit", r));
const browser = await connectBrowser(cdpPort);
const control = await pageWhere(browser, (u) => u.startsWith("http://127.0.0.1:"));
await control.waitFor("document.getElementById('statusLine').textContent !== 'Загрузка…'", 20000);
const $ = (id, prop) => control.evaluate(`document.getElementById('${id}').${prop}`);

// ---- 1. connect with the real key + exit country ------------------------------------------
const report = { connect: {}, sites: [] };
// the key travels only inside this CDP message to the local control page, then the field is cleared
await control.evaluate(`(() => { const t = document.getElementById('keyInput'); t.value = ${JSON.stringify(key)}; document.getElementById('remember').checked = false; document.getElementById('mainBtn').click(); return 1; })()`);
key = "";
const final = /^(Подключено|Выход не в нужной|Проверка показала|Подключение запущено, но|Компонент|Не подключено|Соединение прервано)/;
const t0 = Date.now();
let st = "";
while (Date.now() - t0 < 150000) {
  st = await $("statusLine", "textContent");
  const kerr = await $("keyError", "textContent");
  if (kerr) { st = "KEYERR " + kerr; break; }
  if (final.test(st)) break;
  await sleep(500);
}
const exitRow = (await $("resExit", "innerText")).replace(/\s+/g, " ");
const directRow = (await $("resDirect", "innerText")).replace(/\s+/g, " ");
report.connect = { status: maskIp(st), exitRow: maskIp(exitRow), directRow: maskIp(directRow), seconds: Math.round((Date.now() - t0) / 1000) };
const exitIp = (exitRow.match(/\b(\d{1,3}\.){3}\d{1,3}\b/) || [""])[0], directIp = (directRow.match(/\b(\d{1,3}\.){3}\d{1,3}\b/) || [""])[0];
report.connect.exitDiffersFromOrdinary = !!exitIp && !!directIp && exitIp !== directIp;
const connected = st.startsWith("Подключено");
log("Подключение: " + st);
log("  " + maskIp(exitRow) + " | " + maskIp(directRow) + " | выход отличается от обычного: " + report.connect.exitDiffersFromOrdinary);

// ---- diagnosis when it did not work -------------------------------------------------------
if (!connected) {
  const d = {};
  if (st.startsWith("KEYERR")) d.layer = "ключ (формат): " + st.slice(7);
  else if (/Компонент/.test(st)) d.layer = "ядро не запустилось (локально)";
  else if (/Выход не в нужной/.test(st)) d.layer = "проверка страны: выход не в RU (" + maskIp(exitRow) + ")";
  else if (/Проверка показала/.test(st)) d.layer = "проверка страны: адрес выхода совпал с обычным";
  else {
    // the core runs; is the tunnel alive? is the probe service the problem?
    const alive = await control.evaluate("fetch('https://example.com/', { mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(15000) }).then(() => 'ok', () => 'fail')");
    d.tunnelCarriesTrafficToExampleCom = alive;
    d.layer = alive === "ok" ? "проверка страны (сервисы проверки недоступны через туннель, но трафик идёт)" : "сервер/транспорт (туннель не пропускает трафик: ключ устарел, сервер недоступен или блокируется)";
  }
  report.connect.diagnosis = d;
  log("Причина: " + d.layer + (d.tunnelCarriesTrafficToExampleCom ? " [example.com через туннель: " + d.tunnelCarriesTrafficToExampleCom + "]" : ""));
}

// ---- 2. public pages ------------------------------------------------------------------------
async function visit(site) {
  const r = { site: site.name, url: site.url };
  const { targetId } = await browser.send("Target.createTarget", { url: "about:blank" });
  const sid = await browser.attach(targetId);
  await browser.send("Runtime.enable", {}, sid); await browser.send("Page.enable", {}, sid);
  const ev = async (expression) => { const x = await browser.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, sid); return x.result?.value; };
  const nav = await browser.send("Page.navigate", { url: site.url }, sid).catch((e) => ({ errorText: e.message }));
  r.navError = nav.errorText || "";
  const t1 = Date.now(); let complete = false;
  while (Date.now() - t1 < 70000) {
    const rs = await ev("document.readyState").catch(() => null);
    // "interactive" = the document is parsed and shown; a stuck image or tracker keeps it from "complete"
    // (nalog.gov.ru stays "interactive" when its image host resets HTTP/2 streams). Only a document that never
    // got that far is a timeout.
    if (rs === "complete" || rs === "interactive") { complete = true; break; }
    await sleep(500);
  }
  // Single-page apps render long after readyState=complete (Gosuslugi needed ~30 s over the tunnel): wait until the
  // visible text has stopped changing (3 equal readings, 3 s apart) or the overall limit of 90 s from navigation.
  const series = []; let stable = false;
  while (Date.now() - t1 < 90000) {
    await sleep(3000);
    series.push(await ev("document.body ? document.body.innerText.length : -1").catch(() => -1));
    const n = series.length;
    if (n >= 3 && series[n - 1] === series[n - 2] && series[n - 2] === series[n - 3] && series[n - 1] >= 200) { stable = true; break; }
  }
  if (!stable && series.length >= 3) { const n = series.length; stable = series[n - 1] === series[n - 2] && series[n - 2] === series[n - 3]; }
  let info = null;
  for (let attempt = 0; attempt < 3 && !info; attempt++) { // the page may be mid-navigation for a moment
    info = await ev(DOM_PROBE).then((s) => JSON.parse(s)).catch(() => null);
    if (!info) await sleep(2000);
  }
  r.seconds = Math.round((Date.now() - t1) / 1000);
  r.textSeries = series;
  if (!info) { r.state = "ошибка"; r.error = "страница не отвечает"; }
  else {
    r.finalHost = new URL(info.url.startsWith("http") ? info.url : "http://x/").host;
    r.title = info.title; r.textLen = info.textLen; r.visibleCaptchaElements = info.visibleCaptchaElements;
    Object.assign(r, classifyPage({ ...info, complete, stable }));
    r.captcha = r.state === "Критерий не пройден: капча";
  }
  try { await browser.send("Target.activateTarget", { targetId }); const { data } = await browser.send("Page.captureScreenshot", { format: "png" }, sid); writeFileSync(join(shots, `real-${site.id}.png`), Buffer.from(data, "base64")); r.screenshot = `.local\\logs\\shots\\real-${site.id}.png`; } catch (e) { r.screenshot = "нет: " + e.message; }
  await browser.send("Target.closeTarget", { targetId }).catch(() => {});
  return r;
}

if (connected) {
  for (const s of SITES) { const r = await visit(s); report.sites.push(r); log(`${s.name}: ${r.state}${r.error ? " (" + r.error + ")" : ""}; заголовок: ${r.title ? JSON.stringify(r.title) : "-"}; видимого текста: ${r.textLen ?? "-"}; ${r.seconds} с`); }
} else log("Сайты не открывались: подключение не подтверждено.");

// ---- 3. close the special window; owned processes must end --------------------------------
await browser.send("Browser.close").catch(() => {});
const code = await Promise.race([exited, sleep(25000).then(() => "timeout")]);
const ps = async (script) => (await run("powershell", ["-NoProfile", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")])).stdout;
await sleep(2000);
const left = (await ps("Get-CimInstance Win32_Process | Where-Object { $_.Name -in 'sing-box.exe','RunetAccess.exe' -or ($_.Name -eq 'chrome.exe' -and $_.CommandLine -like '*real-home*') } | Measure-Object | Select-Object -ExpandProperty Count")).trim();
report.closing = { launcherExit: code === "timeout" ? "не завершился" : "завершился", ownedProcessesLeft: Number(left), lockLeft: existsSync(join(home, "run.lock")) };
log("Закрытие окна: лаунчер " + report.closing.launcherExit + "; оставшихся процессов: " + left + "; блокировка осталась: " + report.closing.lockLeft);

// ---- cleanup: temporary key file and the check profile -------------------------------------
// The key file is deleted only after a CONNECTED run; after a failed connection it is kept so the
// diagnosis (tests\real-diagnose.mjs) and a retry do not force the owner to paste it again.
log("Файл ключа не трогаю: он остаётся в .local\\secrets\\test-key.txt (удалите его сами, когда он больше не нужен).");
rmSync(home, { recursive: true, force: true });
report.keyFileDeleted = !existsSync(keyFile);
log("Файл ключа на месте: " + !report.keyFileDeleted);
writeFileSync(join(root, ".local", "logs", "real-check.json"), JSON.stringify(report, null, 2));
console.log("\nИТОГ (без ключа и полного IP):");
console.log("| Сайт | Открылся | Капча | Ошибка |\n|---|---|---|---|");
for (const s of report.sites) console.log(`| ${s.site} | ${s.state === "открылась" ? "да" : "нет"} | ${s.captcha ? "да" : "нет"} | ${s.state === "открылась" ? "-" : s.state + (s.error ? ": " + s.error : "")} |`);
process.exit(0);
