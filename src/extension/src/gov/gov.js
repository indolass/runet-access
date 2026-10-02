// Runet Access popup: paste key -> connect -> verify exit -> open site -> disconnect.
// All DOM text is set via textContent; the key is never written to the DOM, logs or errors.

import { validateKey } from "./key.js";
import { runChecks } from "./check.js";
import {
  DEFAULT_GOV, GOV_STORAGE_KEY, GOV_PROFILE_ID, proxyDomainsFor, parseSiteUrl, normalizeDomain,
} from "./gov-config.js";
import { saveProfile, deleteProfile, getProfile, setActiveProfileId, setRouting } from "../lib/profiles.js";
import { PROXY_MODE } from "../common/constants.js";

const $ = (id) => document.getElementById(id);
const el = {
  hostMissing: $("hostMissing"), keyInput: $("keyInput"), keySaved: $("keySaved"), keyError: $("keyError"),
  keyReplace: $("keyReplace"), keyForget: $("keyForget"), mainBtn: $("mainBtn"), statusLine: $("statusLine"),
  results: $("results"), hint: $("hint"), openBtn: $("openBtn"), recheckBtn: $("recheckBtn"),
  siteUrl: $("siteUrl"), siteExtra: $("siteExtra"), country: $("country"), saveSettings: $("saveSettings"),
  settingsMsg: $("settingsMsg"),
};

let ui = { hostOk: null, hasKey: false, running: false, busy: false, verdict: null, gov: { ...DEFAULT_GOV } };

// ---- messaging -------------------------------------------------------------
function send(cmd, extra = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ cmd, ...extra }, (resp) => {
      const le = chrome.runtime.lastError;
      if (le) return reject(new Error(le.message));
      if (!resp || !resp.ok) return reject(new Error((resp && resp.error) || "no response"));
      resolve(resp.data);
    });
  });
}

/** Maps technical errors to a human sentence. Raw text is never shown. */
function friendly(err) {
  const m = String((err && err.message) || err || "");
  if (/native messaging host not found|cannot start native host|host not found/i.test(m))
    return "Не найдена программа подключения. Запустите установщик и перезапустите Chrome.";
  if (/forbidden/i.test(m))
    return "Chrome не разрешил запуск программы подключения. Переустановите Runet Access.";
  if (/sing-box binary not found/i.test(m))
    return "Не найден компонент подключения (sing-box). Переустановите Runet Access.";
  if (/exited right after start|did not open its port/i.test(m))
    return "Компонент подключения не запустился. Перезапустите Chrome; если повторяется — переустановите Runet Access.";
  if (/timeout/i.test(m)) return "Программа подключения не ответила вовремя. Попробуйте ещё раз.";
  if (/disconnected/i.test(m)) return "Связь с программой подключения оборвалась. Попробуйте ещё раз.";
  if (/config invalid|reality|handshake|verification/i.test(m))
    return "Сервер не принял ключ. Проверьте, что ключ скопирован целиком и не устарел.";
  if (/another extension|other extension|управля/i.test(m))
    return "Другое расширение Chrome управляет прокси. Отключите его и повторите.";
  return "Не удалось подключиться. Попробуйте ещё раз; если повторяется — сообщите оператору ключа.";
}

// ---- storage ---------------------------------------------------------------
async function loadGov() {
  const d = await chrome.storage.local.get(GOV_STORAGE_KEY);
  return { ...DEFAULT_GOV, ...(d[GOV_STORAGE_KEY] || {}) };
}
const saveGov = (g) => chrome.storage.local.set({ [GOV_STORAGE_KEY]: g });

async function applyRouting(gov) {
  await setRouting({
    mode: PROXY_MODE.RULES,
    proxyDomains: proxyDomainsFor(gov),
    directDomains: [],
    bypass: [],
    final: "proxy",
    rules: [],
  });
}

// ---- rendering -------------------------------------------------------------
function setStatus(text, kind = "idle") {
  el.statusLine.textContent = text;
  el.statusLine.className = "status status--" + kind;
}
function setRow(id, text, kind = "") {
  const v = $(id).querySelector(".v");
  v.textContent = text;
  v.className = "v " + kind;
}
function showHint(text) {
  el.hint.textContent = text || "";
  el.hint.classList.toggle("hidden", !text);
}
function showKeyError(text) {
  el.keyError.textContent = text || "";
  el.keyError.classList.toggle("hidden", !text);
}

function renderControls() {
  const site = parseSiteUrl(ui.gov.url);
  const showInput = !ui.hasKey || ui.replacing;
  el.keyInput.classList.toggle("hidden", !showInput);
  el.keySaved.classList.toggle("hidden", showInput || ui.running);
  el.keyReplace.disabled = el.keyForget.disabled = ui.busy;
  el.mainBtn.textContent = ui.running ? "Отключить" : "Подключить";
  el.mainBtn.classList.toggle("on", ui.running);
  el.mainBtn.disabled = ui.busy || ui.hostOk === false;
  el.keyInput.disabled = ui.running || ui.busy;
  const verified = ui.running && (ui.verdict === "ok" || ui.verdict === "ok-nodirect");
  el.openBtn.disabled = !(verified && site);
  el.openBtn.title = !site ? "Сначала укажите адрес сайта в настройках" : verified ? "" : "Сначала нужно подтвердить российский выход";
  el.recheckBtn.classList.toggle("hidden", !ui.running);
  el.recheckBtn.disabled = ui.busy;
  el.hostMissing.classList.toggle("hidden", ui.hostOk !== false);
}

function renderResult(r) {
  el.results.classList.remove("hidden");
  const p = r.proxied, d = r.direct;
  if (p && !p.error) setRow("resExit", `${p.country} · ${p.ip}`, p.country === r.expectedCountry ? "ok" : "err");
  else setRow("resExit", "не удалось определить", "warn");
  if (d && !d.error) setRow("resDirect", `напрямую · ${d.ip}`, d.ip === (p && p.ip) ? "err" : "ok");
  else setRow("resDirect", "не проверено", "warn");
  if (!r.site) setRow("resSite", "адрес не задан", "warn");
  else setRow("resSite", r.site.reachable ? "отвечает" : "не отвечает через этот выход", r.site.reachable ? "ok" : "err");
}

// ---- actions ---------------------------------------------------------------
async function verify() {
  ui.busy = true; ui.verdict = null; renderControls();
  setStatus("Проверяю выход через сервер…", "idle");
  const site = parseSiteUrl(ui.gov.url);
  let r;
  for (let attempt = 0; attempt < 2; attempt++) {
    r = await runChecks({ fetchImpl: fetch.bind(globalThis), expectedCountry: ui.gov.expectedCountry, siteUrl: site ? site.url : "" });
    if (r.verdict !== "unknown") break;
  }
  ui.verdict = r.verdict;
  renderResult(r);
  await chrome.storage.local.set({ govLast: { verdict: r.verdict, at: r.at } });

  const cc = ui.gov.expectedCountry;
  if (r.verdict === "ok" || r.verdict === "ok-nodirect") {
    setStatus(`Подключено. Выход подтверждён: ${r.proxied.country}.`, "ok");
    showHint(site ? (r.site && !r.site.reachable ? "Сервер в нужной стране, но сайт не отвечает. Возможно, сайт блокирует этот адрес." : "") : "Укажите адрес сайта в «Настройках сайта», чтобы кнопка «Открыть сайт» заработала.");
    ui.busy = false; renderControls();
    return;
  }
  if (r.verdict === "wrong-country") {
    setStatus(`Выход не в нужной стране: ${r.proxied.country} (ожидалась ${cc}). Отключаю.`, "err");
    showHint("Такой ключ не даст доступ к российскому сайту. Проверьте ключ у того, кто его выдал.");
    await disconnect({ keepMessage: true });
  } else if (r.verdict === "same-ip") {
    setStatus("Проверка показала тот же адрес, что и без подключения. Трафик не идёт через сервер. Отключаю.", "err");
    showHint("Возможно, другое расширение или программа перехватывает прокси, либо ключ ведёт в вашу же сеть.");
    await disconnect({ keepMessage: true });
  } else {
    setStatus("Подключение запущено, но выход подтвердить не удалось.", "warn");
    showHint("Это не успех: сервис проверки не ответил через сервер. Нажмите «Проверить ещё раз» или отключитесь.");
    ui.busy = false; renderControls();
  }
}

async function connect() {
  showKeyError("");
  showHint("");
  const typed = el.keyInput.value;
  let profile = null;
  if (typed.trim()) {
    const v = validateKey(typed);
    if (!v.ok) { showKeyError(v.message); return; }
    profile = v.profile;
  } else if (!ui.hasKey) {
    showKeyError("Вставьте ключ из Telegram.");
    return;
  }
  ui.busy = true; ui.verdict = null; renderControls();
  el.results.classList.add("hidden");
  setStatus("Подключаюсь…", "idle");
  try {
    if (profile) {
      await saveProfile(profile);
      el.keyInput.value = ""; // the key lives only in extension storage from now on
      ui.hasKey = true; ui.replacing = false;
    }
    await setActiveProfileId(GOV_PROFILE_ID);
    await applyRouting(ui.gov);
    await send("enable", { profileId: GOV_PROFILE_ID });
    ui.running = true;
  } catch (e) {
    // Do not leave the intent "on": it would keep retrying in the background.
    await send("disable").catch(() => {});
    ui.running = false; ui.busy = false; renderControls();
    setStatus(friendly(e), "err");
    return;
  }
  await verify();
}

async function disconnect({ keepMessage = false } = {}) {
  ui.busy = true; renderControls();
  try {
    await send("disable");
    ui.running = false; ui.verdict = null;
    if (!keepMessage) {
      setStatus("Отключено. Остальной интернет не затрагивался.", "idle");
      el.results.classList.add("hidden");
      showHint("");
    }
  } catch (e) {
    setStatus("Не удалось отключиться: " + friendly(e), "err");
  } finally {
    ui.busy = false; renderControls();
  }
}

async function forgetKey() {
  await deleteProfile(GOV_PROFILE_ID);
  ui.hasKey = false; ui.replacing = false;
  setStatus("Ключ удалён из этого профиля Chrome.", "idle");
  renderControls();
}

// ---- settings --------------------------------------------------------------
async function saveSettings() {
  const raw = el.siteUrl.value.trim();
  const msgs = [];
  let url = "";
  if (raw) {
    const s = parseSiteUrl(raw);
    if (!s) { el.settingsMsg.textContent = "Адрес должен быть https://… без логина и пароля."; return; }
    url = s.url;
  }
  const extras = [], bad = [];
  for (const line of el.siteExtra.value.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const n = normalizeDomain(line);
    if (n) extras.push(n); else bad.push(line.trim().slice(0, 40));
  }
  if (bad.length) msgs.push("Не распознаны: " + bad.join(", "));
  const cc = el.country.value.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) { el.settingsMsg.textContent = "Страна — двухбуквенный код, например RU."; return; }
  ui.gov = { url, extraDomains: extras, expectedCountry: cc };
  await saveGov(ui.gov);
  await applyRouting(ui.gov);
  if (ui.running) {
    try { await send("enable", { profileId: GOV_PROFILE_ID }); } catch (e) { msgs.push(friendly(e)); }
  }
  msgs.unshift("Сохранено.");
  el.settingsMsg.textContent = msgs.join(" ");
  renderControls();
}

// ---- init ------------------------------------------------------------------
async function init() {
  ui.gov = await loadGov();
  el.siteUrl.value = ui.gov.url;
  el.siteExtra.value = (ui.gov.extraDomains || []).join("\n");
  el.country.value = ui.gov.expectedCountry;
  ui.hasKey = !!(await getProfile(GOV_PROFILE_ID));

  el.mainBtn.addEventListener("click", () => (ui.running ? disconnect() : connect()));
  el.openBtn.addEventListener("click", () => {
    const s = parseSiteUrl(ui.gov.url);
    if (s && ui.running && (ui.verdict === "ok" || ui.verdict === "ok-nodirect")) chrome.tabs.create({ url: s.url });
  });
  el.recheckBtn.addEventListener("click", verify);
  el.keyReplace.addEventListener("click", () => { ui.replacing = true; renderControls(); el.keyInput.focus(); });
  el.keyForget.addEventListener("click", forgetKey);
  el.saveSettings.addEventListener("click", saveSettings);
  el.keyInput.addEventListener("input", () => showKeyError(""));

  // Is the native host installed at all?
  try {
    await send("hostVersion");
    ui.hostOk = true;
  } catch (e) {
    ui.hostOk = false;
  }
  if (ui.hostOk) {
    try {
      const st = await send("state");
      ui.running = !!(st && st.running);
      if (st && st.foreignProxy) setStatus("Другое расширение Chrome управляет прокси. Отключите его.", "err");
    } catch {
      ui.running = false;
    }
  }
  renderControls();
  if (ui.hostOk === false) setStatus("Программа подключения не найдена.", "err");
  else if (ui.running) await verify();
  else if (!el.statusLine.textContent || el.statusLine.textContent === "Проверяю…")
    setStatus(ui.hasKey ? "Не подключено. Нажмите «Подключить»." : "Не подключено. Вставьте ключ и нажмите «Подключить».", "idle");
}

init().catch((e) => setStatus(friendly(e), "err"));
