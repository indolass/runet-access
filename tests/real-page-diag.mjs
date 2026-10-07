// Why does a public page show only a skeleton / look "blocked"? Opens ONE public URL in the special browser
// (real launcher, real Chrome, standard rules: Russian exit required) and records what happened on the wire:
// main-document status, per-host resource status counts, failed requests (error text per host), console errors,
// a growth series of the visible text, and whether a captcha element is actually VISIBLE in the DOM.
// The key comes from .local\secrets\test-key.txt (read in-process, never printed, file never touched); output has
// no keys and no full IPs. No logins, no forms, nothing submitted.
// Usage: node tests/real-page-diag.mjs https://www.gosuslugi.ru/
import { spawn } from "node:child_process";
import { join } from "node:path";
import net from "node:net";
import { existsSync, readFileSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { root, connectBrowser, pageWhere, sleep } from "./cdp.mjs";

const url = process.argv[2];
if (!/^https:\/\/[a-z0-9.-]+\//i.test(url || "")) { console.log("usage: node tests/real-page-diag.mjs https://host/"); process.exit(2); }
const exe = join(root, "dist", "runet-access", "RunetAccess.exe");
const home = join(root, ".local", "diag-home");
const keyFile = process.env.RUNET_KEY_FILE ? join(root, process.env.RUNET_KEY_FILE) : join(root, ".local", "secrets", "test-key.txt"); // RUNET_KEY_FILE: another file under the repo root
const shots = join(root, ".local", "logs", "shots"); mkdirSync(shots, { recursive: true });
const maskIp = (s) => String(s).replace(/\b(\d{1,3})(\.\d{1,3}){3}\b/g, "$1.x.x.x");
const log = (s) => console.log(maskIp(s));
process.on("unhandledRejection", (e) => { log("FATAL " + (e && e.message)); process.exit(1); });

let key = readFileSync(keyFile, "utf8").trim();
if (!/^(vless|ss|ssconf):\/\/\S+$/i.test(key.split("#")[0])) { log("в файле ключа нет одной строки vless://, ss:// или ssconf://"); process.exit(2); }
rmSync(home, { recursive: true, force: true });
const port = await new Promise((res) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const child = spawn(exe, [], { stdio: "ignore", env: { ...process.env, RUNET_TEST_MODE: "1", RUNET_ACCESS_HOME: home, RUNET_CHROME_EXTRA_ARGS: `--remote-debugging-port=${port}`, RUNET_NO_DIALOG: "1" } });
const exited = new Promise((r) => child.once("exit", r));
const browser = await connectBrowser(port);
const control = await pageWhere(browser, (u) => u.startsWith("http://127.0.0.1:"));
await control.waitFor("document.getElementById('statusLine').textContent !== 'Загрузка…'", 20000);
await control.evaluate(`(() => { const t = document.getElementById('keyInput'); t.value = ${JSON.stringify(key)}; document.getElementById('remember').checked = false; document.getElementById('mainBtn').click(); return 1; })()`);
key = "";
let st = ""; const t0 = Date.now();
while (Date.now() - t0 < 120000) { st = await control.evaluate("document.getElementById('statusLine').textContent"); if (/^(Подключено|Выход не|Проверка показала|Подключение запущено, но|Компонент|Соединение)/.test(st)) break; await sleep(500); }
log("Подключение: " + st);
let report = { connect: st };
if (st.startsWith("Подключено")) {
  const { targetId } = await browser.send("Target.createTarget", { url: "about:blank" });
  const sid = await browser.attach(targetId);
  const reqs = new Map(), hosts = {}, failed = [], consoleErr = [];
  let main = null;
  const hostOf = (u) => { try { return new URL(u).host; } catch { return "?"; } };
  browser.onEvent((m) => {
    if (m.sessionId !== sid) return;
    const p = m.params || {};
    if (m.method === "Network.requestWillBeSent") reqs.set(p.requestId, { host: hostOf(p.request.url), type: p.type });
    else if (m.method === "Network.responseReceived") {
      const h = hostOf(p.response.url); (hosts[h] ||= {})[p.response.status] = ((hosts[h] || {})[p.response.status] || 0) + 1;
      if (p.type === "Document" && !main) main = { host: h, status: p.response.status, mime: p.response.mimeType };
    } else if (m.method === "Network.loadingFailed") {
      const r = reqs.get(p.requestId) || { host: "?", type: "?" };
      failed.push({ host: r.host, type: r.type, error: p.errorText, blocked: p.blockedReason || "" });
    } else if (m.method === "Runtime.exceptionThrown") consoleErr.push(String(p.exceptionDetails?.exception?.description || p.exceptionDetails?.text || "").split("\n")[0].slice(0, 140));
    else if (m.method === "Log.entryAdded" && p.entry.level === "error") consoleErr.push((p.entry.text || "").slice(0, 140) + " [" + hostOf(p.entry.url || "") + "]");
  });
  for (const d of ["Network", "Page", "Runtime", "Log"]) await browser.send(d + ".enable", {}, sid);
  const ev = async (e) => (await browser.send("Runtime.evaluate", { expression: e, returnByValue: true, awaitPromise: true }, sid)).result?.value;
  // not awaited: when the site never answers, Page.navigate itself takes longer than the 30 s CDP timeout
  const navT0 = Date.now(); let navResult = "pending";
  browser.send("Page.navigate", { url }, sid).then((r) => { navResult = r && r.errorText ? "errorText=" + r.errorText : "committed"; }, (e) => { navResult = "no answer: " + e.message; });
  const series = [];
  for (let i = 0; i < 16; i++) { await sleep(5000); series.push(await ev("document.body ? document.body.innerText.length : -1").catch(() => -1)); if (i >= 3 && series.at(-1) === series.at(-2) && series.at(-1) === series.at(-3) && series.at(-1) > 400) break; }
  const dom = JSON.parse(await ev(`JSON.stringify((() => {
    const vis = (e) => { const r = e.getBoundingClientRect(); const cs = getComputedStyle(e); return r.width > 20 && r.height > 20 && cs.visibility !== 'hidden' && cs.display !== 'none'; };
    const cap = [...document.querySelectorAll('[class*="captcha" i],[id*="captcha" i],iframe[src*="captcha" i],iframe[src*="challenge" i]')].filter(vis).length;
    const txt = document.body ? document.body.innerText : '';
    return { title: document.title, textLen: txt.length, visibleCaptchaElements: cap, captchaWordInVisibleText: /captcha|капч|я не робот|подтвердите,? что вы (не робот|человек)|проверка (безопасности|браузера)/i.test(txt), deniedWordInVisibleText: /доступ (к сайту )?(запрещ|ограничен)|access denied|forbidden|отказано в доступе/i.test(txt), buttons: document.querySelectorAll('button').length, images: document.images.length, scripts: document.scripts.length, readyState: document.readyState };
  })())`).catch(() => "{}") || "{}");
  await browser.send("Target.activateTarget", { targetId }).catch(() => {});
  try { const { data } = await browser.send("Page.captureScreenshot", { format: "png" }, sid); writeFileSync(join(shots, "diag-" + new URL(url).hostname + ".png"), Buffer.from(data, "base64")); } catch {}
  const failedBy = {}; for (const f of failed) { const k2 = `${f.host} ${f.type} ${f.error}${f.blocked ? " blocked=" + f.blocked : ""}`; failedBy[k2] = (failedBy[k2] || 0) + 1; }
  report = { ...report, main, hosts, failed: failedBy, consoleErr: [...new Set(consoleErr)].slice(0, 8), textSeries: series, dom };
  log(`Page.navigate: ${navResult} (${Math.round((Date.now() - navT0) / 1000)} с после старта)`);
  log(`основной документ: ${main ? `${main.host} HTTP ${main.status} (${main.mime})` : "ответа не было"}`);
  log("ответы по хостам (код: число): " + Object.entries(hosts).map(([h, c]) => `${h} {${Object.entries(c).map(([k3, v]) => k3 + ":" + v).join(", ")}}`).join("; "));
  log("сбои загрузки: " + (Object.keys(failedBy).length ? Object.entries(failedBy).map(([k3, v]) => `${k3} ×${v}`).join("; ") : "нет"));
  log("ошибки консоли: " + (report.consoleErr.length ? report.consoleErr.join(" | ") : "нет"));
  log(`рост видимого текста (каждые 5 с): ${series.join(", ")}`);
  log(`DOM: заголовок «${dom.title}», видимого текста ${dom.textLen}, видимых элементов капчи ${dom.visibleCaptchaElements}, слово «капча/робот» в видимом тексте: ${dom.captchaWordInVisibleText}, слова отказа: ${dom.deniedWordInVisibleText}, кнопок ${dom.buttons}, картинок ${dom.images}, скриптов ${dom.scripts}, readyState ${dom.readyState}`);
}
await browser.send("Browser.close").catch(() => {});
await Promise.race([exited, sleep(25000)]);
rmSync(home, { recursive: true, force: true });
writeFileSync(join(root, ".local", "data", "page-diag-" + new URL(url).hostname + ".json"), JSON.stringify(report, null, 2));
log("лаунчер закрыт; файл ключа на месте: " + existsSync(keyFile));
