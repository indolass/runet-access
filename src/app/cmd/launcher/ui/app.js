// Runet Access control page. All DOM text is set via textContent. A typed key is sent once to the
// launcher and cleared from the field as soon as the launcher has accepted it.
//
// Rules this file enforces (see docs/UX.md):
//  - nothing connects by itself: every connection starts from a click;
//  - a site is opened only after the exit country was verified, exactly once, and a cancelled or
//    failed attempt drops the pending site;
//  - every operation has a generation number (ui.op): when the user cancels or starts something
//    else, the older operation notices and discards its result;
//  - a green status is never kept after a break is seen: a restart of the core (new epoch) clears
//    the confirmation and the exit is checked again.
import { runChecks } from "./check.js";

const $ = (id) => document.getElementById(id);

// Display/copy only. Opening goes through the launcher by id (a fixed list on its side).
const LINKS = {
  "bot-ussr": "https://t.me/BackInTheUSSR_bot",
  "bot-hlvpn": "https://t.me/hlvpnbot",
  thanks: "https://t.me/W3_accelerators_GK",
};

const STATES = {
  loading: { kind: "idle", text: "Загрузка…", acts: [] },
  idle: { kind: "idle", text: "Не подключено", acts: ["connect"] },
  connecting: { kind: "busy", text: "Подключаемся…", acts: ["cancel"] },
  checking: { kind: "busy", text: "Проверяем подключение через Россию…", acts: ["cancel"] },
  connected: { kind: "ok", text: "Подключено через Россию", acts: ["disconnect"] },
  "err-server": { kind: "err", text: "Сервер недоступен", acts: ["retry", "replace"],
    note: "Проверьте интернет и повторите. Если не помогает, ключ мог устареть: получите новый." },
  "err-key": { kind: "err", text: "Неверный или неподдерживаемый формат ключа", acts: ["replace"] },
  "err-unconfirmed": { kind: "warn", text: "Не удалось подтвердить страну выхода", acts: ["recheck", "disconnect"],
    note: "Это не значит, что ключ неисправен: сервис проверки мог не ответить. Сайты откроются после подтверждения." },
  "err-wrong": { kind: "err", text: "Выход не в России", acts: ["retry", "replace"],
    note: "Такой ключ не даёт доступа к российским сайтам. Подключение остановлено." },
  "err-same": { kind: "err", text: "Трафик идёт мимо ключа", acts: ["retry", "replace"],
    note: "Проверка показала ваш обычный адрес. Подключение остановлено." },
  "err-lost": { kind: "err", text: "Соединение прервано", acts: ["retry", "replace"],
    note: "Окно не выходит в интернет напрямую. Повторите подключение." },
  "err-core": { kind: "err", text: "Подключение не запустилось", acts: ["retry"] },
};
const ACTION_BTN = { connect: "connectBtn", retry: "retryBtn", recheck: "recheckBtn", replace: "replaceBtn", disconnect: "disconnectBtn", cancel: "cancelBtn" };

const ui = {
  state: "loading", note: "", view: "main", shownView: "",
  saved: false, memory: false, phase: "idle", version: "", epoch: 0,
  op: 0, flow: 0, abort: null, quiet: false, opening: false, stopping: false, waiting: null,
  last: null, lastAt: 0, reach: null, cfg: null,
  replaceOpen: false, forgetAsk: false, replacing: false, keyMsg: "",
};

// ---- helpers ------------------------------------------------------------------------------
async function api(path, body, timeoutMs = 20000) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const opt = body === undefined ? { cache: "no-store", signal: ctl.signal } : {
      method: "POST", cache: "no-store", signal: ctl.signal,
      headers: { "Content-Type": "application/json", "X-Runet": "1" },
      body: JSON.stringify(body),
    };
    const r = await fetch(path, opt);
    let j = null;
    try { j = await r.json(); } catch { /* empty body */ }
    return { ok: r.ok, status: r.status, data: j || {} };
  } catch {
    return { ok: false, status: 0, data: { code: "net", message: "Не удалось связаться с программой." } };
  } finally {
    clearTimeout(timer);
  }
}

const show = (el, on) => el.classList.toggle("hidden", !on);
// Only touch the text when it changes: re-writing the same text would make screen readers repeat it.
const setIf = (el, t) => { if (el.textContent !== t) el.textContent = t; };
const setText = (el, t) => { setIf(el, t || ""); show(el, !!t); };
const canConnect = () => ui.saved || ui.memory;
const live = (my) => my === ui.op;

let toastTimer = 0;
function toast(t) {
  setIf($("toast"), t || "");
  clearTimeout(toastTimer);
  if (t) toastTimer = setTimeout(() => { $("toast").textContent = ""; }, 12000);
}

function maskIp(ip) {
  const s = String(ip || "");
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) return s.split(".")[0] + ".x.x.x";
  return s.includes(":") ? s.split(":")[0] + ":…" : s;
}

function parseSite(input) {
  const s = String(input || "").trim();
  if (!s) return null;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : "https://" + s);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    if (u.username || u.password || !u.hostname.includes(".")) return null;
    return u.toString();
  } catch { return null; }
}

function setState(state, note = "") { ui.state = state; ui.note = note; render(); }

// ---- rendering ----------------------------------------------------------------------------
function currentView() {
  if (ui.view === "settings") return "settings";
  const liveConn = ui.state === "connected" || ui.state === "err-unconfirmed";
  return canConnect() || liveConn ? "main" : "first";
}

function render() {
  const st = STATES[ui.state] || STATES.loading;
  const view = currentView();
  show($("viewFirst"), view === "first");
  show($("viewMain"), view === "main");
  show($("viewSettings"), view === "settings");
  show($("settingsBtn"), view === "main");
  show($("backBtn"), view === "settings");
  if (view !== ui.shownView) {
    const first = ui.shownView === "";
    ui.shownView = view;
    if (!first) $({ first: "firstTitle", main: "mainTitle", settings: "settingsTitle" }[view]).focus({ preventScroll: true });
  }

  // status bar: always a text, never only a colour
  const bar = $("statusBar");
  bar.className = "statusbar status--" + st.kind;
  setIf($("statusLine"), st.text);
  let note = ui.note || st.note || "";
  if (ui.replacing && ui.saved && ui.state.startsWith("err-")) note += (note ? " " : "") + "Сохранённый прежний ключ не тронут.";
  setText($("statusNote"), note);

  const firstFieldFilled = $("keyInput").value.trim() !== "";
  const acts = new Set(st.acts);
  if (view === "first") { acts.delete("connect"); acts.delete("replace"); }
  if (acts.has("retry") && !(view === "first" ? firstFieldFilled : canConnect())) acts.delete("retry");
  for (const [a, id] of Object.entries(ACTION_BTN)) show($(id), acts.has(a));

  // tiles
  const busy = ui.flow !== 0;
  for (const t of document.querySelectorAll(".tile")) {
    const waiting = ui.waiting === t.dataset.url;
    t.classList.toggle("waiting", waiting);
    t.setAttribute("aria-busy", waiting ? "true" : "false");
  }
  $("tileHint").textContent = ui.state === "connected"
    ? "Выход через Россию подтверждён. Это не гарантирует, что конкретный сайт откроется без проверок и ограничений."
    : (canConnect() ? "Нажмите на сайт: подключимся, проверим выход через Россию и откроем его." : "");
  $("mainBtn").disabled = busy;
  $("replaceGo").disabled = busy;

  // settings
  $("keyStatusText").textContent = ui.keyMsg || (ui.saved ? "Ключ сохранён на этом компьютере."
    : ui.memory ? "Ключ не сохранён: он используется, пока программа открыта." : "Ключа нет.");
  show($("forgetBtn"), ui.saved && !ui.forgetAsk);
  show($("replaceOpen"), !ui.replaceOpen && !ui.forgetAsk);
  show($("forgetConfirm"), ui.forgetAsk);
  show($("replaceForm"), ui.replaceOpen);
  show($("newRememberRow"), !ui.saved);
  $("replaceNote").textContent = ui.saved ? "Если новый ключ не подойдёт, сохранённый прежний останется на месте." : "";
  renderDetails();
}

function renderDetails() {
  const r = ui.last;
  const p = r && r.proxied && !r.proxied.error ? r.proxied : null;
  const d = r && r.direct && !r.direct.error ? r.direct : null;
  $("resExit").textContent = p ? `${p.country} · ${p.ip}` : "не определён";
  $("resDirect").textContent = d ? d.ip : "не проверено";
  $("resTime").textContent = ui.lastAt ? new Date(ui.lastAt).toLocaleTimeString("ru-RU") : "—";
  const lines = [
    `Runet Access ${ui.version || "?"}`,
    `Состояние: ${ui.state}; программа: ${ui.phase}; запусков ядра: ${ui.epoch}`,
    `Ожидаемая страна: ${(ui.cfg && ui.cfg.expectedCountry) || "RU"}`,
    `Выход: ${p ? p.country + " " + maskIp(p.ip) + " (" + p.source + ")" : "не определён" + (r && r.proxied && r.proxied.error ? " — " + r.proxied.error : "")}`,
    `Обычное соединение: ${d ? maskIp(d.ip) : "не проверено" + (r && r.direct && r.direct.error ? " — " + r.direct.error : "")}`,
    `Вердикт проверки: ${r ? r.verdict : "—"}`,
    `Сервер ключа отвечает: ${ui.reach === null ? "не проверялось" : ui.reach ? "да" : "нет"}`,
    `Проверено: ${ui.lastAt ? new Date(ui.lastAt).toLocaleString("ru-RU") : "—"}`,
  ];
  $("diagText").textContent = lines.join("\n");
  $("detRecheck").disabled = ui.flow !== 0 || !(ui.state === "connected" || ui.state === "err-unconfirmed");
}

// ---- flows --------------------------------------------------------------------------------
const flowStart = () => { const my = ++ui.op; ui.flow = my; return my; };
function flowEnd(my) {
  if (ui.flow === my) { ui.flow = 0; ui.waiting = null; }
  render();
}

async function getCfg() {
  if (!ui.cfg) { const r = await api("/api/config", undefined, 8000); if (r.ok) ui.cfg = r.data; }
  return ui.cfg || { expectedCountry: "RU", timeoutMs: 8000, proxied: [], direct: { id: "ipify", url: "/api/direct-ip" }, recheckMs: 60000 };
}

/** Connects (stops whatever ran before), verifies the exit, then opens `open` once. */
async function connectFlow({ key = "", remember = false, open = null, fromReplace = false } = {}) {
  if (ui.flow) return;
  const prev = { state: ui.state, note: ui.note };
  ui.replacing = fromReplace;
  const my = flowStart();
  ui.waiting = open;
  setText($("keyError"), ""); setText($("newKeyError"), "");
  setState("connecting");
  try {
    const r = await api("/api/connect", { key, remember }, 45000);
    if (!live(my)) return;
    if (!r.ok) {
      const code = r.data.code, msg = r.data.message || "Не удалось подключиться.";
      if (code === "key") {
        ui.state = prev.state === "loading" ? "idle" : prev.state; ui.note = prev.note; // nothing was changed
        if (fromReplace) setText($("newKeyError"), msg + (ui.state === "connected" ? " Прежнее подключение не изменено." : ""));
        else if (key || currentView() === "first") setText($("keyError"), msg);
        else setState("err-key", msg);
      } else if (code === "server") setState("err-server");
      else if (code === "cancelled") { /* a newer operation owns the state */ }
      else setState("err-core", msg);
      return;
    }
    ui.epoch = r.data.epoch;
    $("keyInput").value = ""; $("newKeyInput").value = ""; // the key now lives only in the launcher
    const res = await verifyFlow(my, { open });
    if (res === "ok" && fromReplace) {
      ui.view = "main"; ui.replaceOpen = false; ui.keyMsg = "";
      toast("Ключ заменён и проверен.");
    }
  } finally {
    flowEnd(my);
  }
}

/** Verifies the exit of the running connection (no new connection). */
async function reverifyFlow({ open = null, canRetry = true } = {}) {
  if (ui.flow) return;
  const my = flowStart();
  ui.waiting = open;
  try { await verifyFlow(my, { open, canRetry }); } finally { flowEnd(my); }
}

/** Periodic check that does not take over the screen unless something is wrong. */
async function quietCheck() {
  if (ui.flow || ui.quiet || ui.state !== "connected") return;
  ui.quiet = true;
  const my = ui.op;
  try { await verifyFlow(my, { quiet: true }); } finally { ui.quiet = false; render(); }
}

async function verifyFlow(my, { open = null, quiet = false, canRetry = true } = {}) {
  const epoch = ui.epoch;
  if (!quiet) setState("checking");
  const cfg = await getCfg();
  const ctl = new AbortController();
  ui.abort = ctl;
  let r;
  try {
    for (let attempt = 0; attempt < 2; attempt++) {
      r = await runChecks({ fetchImpl: fetch.bind(window), cfg, signal: ctl.signal });
      if (!live(my)) return "cancelled";
      if (r.verdict !== "unknown") break;
    }
  } finally {
    if (ui.abort === ctl) ui.abort = null;
  }
  if (!live(my)) return "cancelled";
  ui.last = r; ui.lastAt = Date.now();

  if (r.verdict === "ok" || r.verdict === "ok-nodirect") {
    await api("/api/verdict", { ok: true, epoch }, 8000);
    if (!live(my)) return "cancelled";
    ui.reach = true;
    await pollState();
    setState("connected");
    if (open) await openSiteNow(open, canRetry);
    return "ok";
  }
  if (r.verdict === "wrong-country" || r.verdict === "same-ip") {
    await api("/api/disconnect", {}, 10000); // the window stays cut off from the internet
    if (!live(my)) return "cancelled";
    ui.epoch = 0;
    if (r.verdict === "same-ip") setState("err-same");
    else setState("err-wrong", `Определена страна: ${r.proxied.country} (нужна ${cfg.expectedCountry}). Такой ключ не даёт доступа к российским сайтам. Подключение остановлено.`);
    return "wrong";
  }
  // the exit could not be determined: say so, and find out whether the server itself answers
  await api("/api/verdict", { ok: false, epoch }, 8000);
  const reach = (await api("/api/reach", undefined, 10000)).data.reachable === true;
  if (!live(my)) return "cancelled";
  ui.reach = reach;
  setState(reach ? "err-unconfirmed" : (quiet ? "err-lost" : "err-server"));
  return "unknown";
}

async function stopAll(message) {
  ui.op++; ui.flow = 0; ui.waiting = null; ui.replacing = false; ui.stopping = true;
  if (ui.abort) ui.abort.abort();
  ui.last = null; ui.lastAt = 0; ui.epoch = 0;
  setState("idle");
  try {
    await api("/api/disconnect", {}, 10000);
    await pollState();
  } finally {
    ui.stopping = false;
  }
  if (message) toast(message);
}

async function openSiteNow(u, canRetry = true) {
  if (ui.opening) return;
  ui.opening = true;
  try {
    const r = await api("/api/open-site", { url: u }, 10000);
    if (r.ok) { toast("Открыто в соседней вкладке: " + new URL(u).host); return; }
    if (r.data.code === "not-confirmed" && canRetry) { // the core restarted since the check: check once more, once
      ui.opening = false;
      await reverifyFlow({ open: u, canRetry: false });
      return;
    }
    toast(r.data.message || "Не удалось открыть сайт.");
  } finally {
    setTimeout(() => { ui.opening = false; }, 800); // a double click must not open two tabs
  }
}

/** A site was chosen: open it now if the exit is verified, otherwise connect/verify first. */
async function requestSite(u) {
  if (ui.flow) { toast("Подождите: подключение уже выполняется."); return; }
  if (ui.opening) return;
  toast("");
  if (ui.state === "connected") return openSiteNow(u);
  if (ui.state === "err-unconfirmed") return reverifyFlow({ open: u });
  if (canConnect()) return connectFlow({ open: u });
}

// ---- state from the launcher --------------------------------------------------------------
async function pollState() {
  const r = await api("/api/state", undefined, 6000);
  if (!r.ok) return null;
  const s = r.data;
  ui.saved = !!s.saved; ui.memory = !!s.memory; ui.version = s.version || ""; ui.phase = s.phase;
  if (!ui.flow && !ui.stopping) reconcile(s);
  render();
  return s;
}

function reconcile(s) {
  const liveLike = ui.state === "connected" || ui.state === "err-unconfirmed";
  if (s.phase === "connected" && s.restarting) {
    // the core died and is being restarted: nothing can be verified yet, and nothing is green
    ui.last = null; ui.lastAt = 0;
    if (ui.state !== "connecting") setState("connecting");
  } else if (s.phase === "connected") {
    const epochChanged = s.epoch !== ui.epoch;
    if (epochChanged || (ui.state === "connected" && !s.confirmed) || ui.state === "loading") {
      // the core was (re)started or the page was reloaded: whatever was confirmed before is void
      ui.epoch = s.epoch;
      ui.last = null; ui.lastAt = 0;
      setTimeout(() => reverifyFlow(), 0);
      if (ui.state === "connected") { ui.state = "checking"; ui.note = ""; }
    }
  } else if (s.phase === "error") {
    if (liveLike || ui.state === "loading" || ui.state === "idle") setState("err-lost", s.error || "");
  } else if (s.phase === "connecting") {
    if (ui.state === "loading") setState("connecting");
  } else if (liveLike || ui.state === "loading") {
    setState("idle");
  }
}

// ---- external links and copying -----------------------------------------------------------
function flashButton(btn, text) {
  const orig = btn.dataset.orig || btn.textContent;
  btn.dataset.orig = orig;
  btn.textContent = text;
  clearTimeout(btn._t);
  btn._t = setTimeout(() => { btn.textContent = orig; }, 2000);
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch { /* fall back */ }
  try {
    const t = document.createElement("textarea");
    t.value = text; t.setAttribute("readonly", ""); t.style.position = "fixed"; t.style.opacity = "0";
    document.body.appendChild(t); t.select();
    const ok = document.execCommand("copy");
    t.remove();
    return ok;
  } catch { return false; }
}

async function openExternal(id, btn) {
  const note = btn.closest(".getkey")?.querySelector(".ext-note") || $("footNote");
  setText(note, "");
  const r = await api("/api/open-external", { id }, 10000);
  if (r.ok) flashButton(btn, "Открываю…");
  else setText(note, (r.data.message || "Не удалось открыть ссылку.") + " Скопируйте ссылку и откройте её вручную: " + LINKS[id]);
}

async function copyLink(id, btn) {
  const ok = await copyText(LINKS[id]);
  flashButton(btn, ok ? "Скопировано" : "Не удалось скопировать");
}

// ---- wiring -------------------------------------------------------------------------------
function focusLater(el) { setTimeout(() => el.focus(), 0); }

function openReplace() {
  if (!canConnect()) { ui.view = "main"; render(); focusLater($("keyInput")); return; }
  ui.view = "settings"; ui.replaceOpen = true; ui.forgetAsk = false; render();
  focusLater($("newKeyInput"));
}

function init() {
  for (const host of ["getKeyFirst", "getKeySettings"]) $(host).appendChild($("tplGetKey").content.cloneNode(true));
  document.addEventListener("click", (e) => {
    const o = e.target.closest("[data-open]");
    if (o) { openExternal(o.dataset.open, o); return; }
    const c = e.target.closest("[data-copy]");
    if (c) copyLink(c.dataset.copy, c);
  });

  $("mainBtn").addEventListener("click", () => {
    const key = $("keyInput").value;
    if (!key.trim()) { setText($("keyError"), "Вставьте ключ подключения."); return; }
    connectFlow({ key, remember: $("remember").checked });
  });
  $("keyInput").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("mainBtn").click(); } });
  $("keyInput").addEventListener("input", () => { setText($("keyError"), ""); render(); });
  $("connectBtn").addEventListener("click", () => connectFlow({}));
  $("retryBtn").addEventListener("click", () => {
    const typed = currentView() === "first" ? $("keyInput").value : "";
    connectFlow({ key: typed, remember: $("remember").checked });
  });
  $("recheckBtn").addEventListener("click", () => reverifyFlow());
  $("detRecheck").addEventListener("click", () => reverifyFlow());
  $("disconnectBtn").addEventListener("click", () => stopAll());
  $("cancelBtn").addEventListener("click", () => stopAll("Отменено."));
  $("replaceBtn").addEventListener("click", openReplace);

  $("settingsBtn").addEventListener("click", () => { ui.view = "settings"; ui.replaceOpen = false; ui.forgetAsk = false; ui.keyMsg = ""; render(); });
  $("backBtn").addEventListener("click", () => { ui.view = "main"; ui.replaceOpen = false; ui.forgetAsk = false; $("newKeyInput").value = ""; render(); });
  $("replaceOpen").addEventListener("click", openReplace);
  $("replaceCancel").addEventListener("click", () => { ui.replaceOpen = false; $("newKeyInput").value = ""; setText($("newKeyError"), ""); render(); focusLater($("replaceOpen")); });
  $("replaceGo").addEventListener("click", () => {
    const key = $("newKeyInput").value;
    if (!key.trim()) { setText($("newKeyError"), "Вставьте новый ключ."); return; }
    connectFlow({ key, remember: ui.saved ? true : $("newRemember").checked, fromReplace: true });
  });
  $("newKeyInput").addEventListener("input", () => setText($("newKeyError"), ""));
  $("forgetBtn").addEventListener("click", () => { ui.forgetAsk = true; render(); focusLater($("forgetNo")); });
  $("forgetNo").addEventListener("click", () => { ui.forgetAsk = false; render(); focusLater($("forgetBtn")); });
  $("forgetYes").addEventListener("click", async () => {
    ui.forgetAsk = false;
    await api("/api/forget", {});
    await pollState();
    ui.keyMsg = ui.memory ? "Сохранённый ключ удалён. Текущий ключ работает до закрытия программы." : "Сохранённый ключ удалён с этого компьютера.";
    render();
  });

  for (const t of document.querySelectorAll(".tile")) t.addEventListener("click", () => requestSite(t.dataset.url));
  $("otherForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const u = parseSite($("siteUrl").value);
    if (!u) { setText($("siteError"), "Введите адрес сайта, например nalog.gov.ru."); return; }
    setText($("siteError"), "");
    requestSite(u);
  });
  $("siteUrl").addEventListener("input", () => setText($("siteError"), ""));
  $("copyDiag").addEventListener("click", async (e) => flashButton(e.currentTarget, (await copyText($("diagText").textContent)) ? "Скопировано" : "Не удалось скопировать"));

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") pollState().then(() => { if (Date.now() - ui.lastAt > 30000) quietCheck(); });
  });

  render();
  pollState().then(async (s) => {
    if (!s) { setState("err-core", "Не удалось связаться с программой. Закройте окно и запустите Runet Access снова."); return; }
    if (ui.state === "loading") setState("idle");
    const cfg = await getCfg();
    render();
    setInterval(() => { if (!ui.flow) quietCheck(); }, Math.max(500, cfg.recheckMs || 60000));
  });
  setInterval(() => { pollState(); }, 2000);
}

init();
