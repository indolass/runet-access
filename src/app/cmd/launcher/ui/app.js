// Runet Access control page. All DOM text is set via textContent; the key is sent once to the
// launcher and cleared from the field immediately.
import { runChecks } from "./check.js";

const $ = (id) => document.getElementById(id);
const el = {
  keyInput: $("keyInput"), remember: $("remember"), rememberRow: $("rememberRow"), keySaved: $("keySaved"),
  keyReplace: $("keyReplace"), keyForget: $("keyForget"), keyError: $("keyError"), mainBtn: $("mainBtn"),
  statusLine: $("statusLine"), results: $("results"), hint: $("hint"), siteUrl: $("siteUrl"),
  openBtn: $("openBtn"), recheckBtn: $("recheckBtn"),
};

const ui = { phase: "idle", hasKey: false, replacing: false, busy: false, verdict: null };

async function api(path, body) {
  const opt = body === undefined ? { cache: "no-store" } : {
    method: "POST", cache: "no-store",
    headers: { "Content-Type": "application/json", "X-Runet": "1" },
    body: JSON.stringify(body),
  };
  const r = await fetch(path, opt);
  let j = null;
  try { j = await r.json(); } catch { /* empty body */ }
  return { ok: r.ok, status: r.status, data: j || {} };
}

const setStatus = (text, kind = "idle") => { el.statusLine.textContent = text; el.statusLine.className = "status status--" + kind; };
const setRow = (id, text, kind = "") => { const v = $(id).querySelector(".v"); v.textContent = text; v.className = "v " + kind; };
const showHint = (t) => { el.hint.textContent = t || ""; el.hint.classList.toggle("hidden", !t); };
const showKeyError = (t) => { el.keyError.textContent = t || ""; el.keyError.classList.toggle("hidden", !t); };

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

function render() {
  const connected = ui.phase === "connected";
  const showInput = !ui.hasKey || ui.replacing;
  el.keyInput.classList.toggle("hidden", !showInput);
  el.rememberRow.classList.toggle("hidden", !showInput);
  $("keyLabel").classList.toggle("hidden", !showInput);
  el.keySaved.classList.toggle("hidden", showInput || connected);
  el.keyInput.disabled = connected || ui.busy;
  el.keyReplace.disabled = el.keyForget.disabled = ui.busy;
  el.mainBtn.textContent = connected ? "Отключить" : "Подключить";
  el.mainBtn.classList.toggle("on", connected);
  el.mainBtn.disabled = ui.busy;
  const verified = connected && (ui.verdict === "ok" || ui.verdict === "ok-nodirect");
  el.openBtn.disabled = !(verified && parseSite(el.siteUrl.value));
  el.recheckBtn.classList.toggle("hidden", !connected);
  el.recheckBtn.disabled = ui.busy;
}

function renderResult(r) {
  el.results.classList.remove("hidden");
  const p = r.proxied, d = r.direct;
  if (p && !p.error) setRow("resExit", `${p.country} · ${p.ip}`, p.country === r.expectedCountry ? "ok" : "err");
  else setRow("resExit", "не удалось определить", "warn");
  if (d && !d.error) setRow("resDirect", d.ip, p && d.ip === p.ip ? "err" : "ok");
  else setRow("resDirect", "не проверено", "warn");
}

async function disconnect(quiet = false) {
  ui.busy = true; render();
  await api("/api/disconnect", {});
  ui.phase = "idle"; ui.verdict = null; ui.busy = false;
  if (!quiet) { setStatus("Отключено. Окно браузера сейчас не выходит в интернет вообще: так и задумано.", "idle"); el.results.classList.add("hidden"); showHint(""); }
  render();
}

async function verify() {
  ui.busy = true; ui.verdict = null; render();
  setStatus("Проверяю выход…", "idle");
  const cfgResp = await api("/api/config");
  let r;
  for (let attempt = 0; attempt < 2; attempt++) {
    r = await runChecks({ fetchImpl: fetch.bind(window), cfg: cfgResp.data });
    if (r.verdict !== "unknown") break;
  }
  ui.verdict = r.verdict;
  renderResult(r);
  const cc = cfgResp.data.expectedCountry;
  if (r.verdict === "ok" || r.verdict === "ok-nodirect") {
    setStatus(`Подключено. Выход подтверждён: ${r.proxied.country}. Весь трафик этого окна идёт через ключ.`, "ok");
    showHint(r.verdict === "ok-nodirect" ? "Обычный адрес для сравнения получить не удалось, но страна выхода подтверждена." : "");
  } else if (r.verdict === "wrong-country") {
    setStatus(`Выход не в нужной стране: ${r.proxied.country} (нужна ${cc}). Отключаю.`, "err");
    showHint("Такой ключ не даст доступ к российскому сайту. Проверьте ключ у того, кто его выдал.");
    await disconnect(true);
  } else if (r.verdict === "same-ip") {
    setStatus("Проверка показала тот же адрес, что и без ключа. Трафик не идёт через сервер. Отключаю.", "err");
    showHint("Возможно, ключ ведёт в вашу же сеть.");
    await disconnect(true);
  } else {
    setStatus("Подключение запущено, но выход подтвердить не удалось.", "warn");
    showHint("Это не успех: сервис проверки не ответил через ключ. Нажмите «Проверить выход ещё раз» или отключитесь.");
  }
  ui.busy = false; render();
}

async function connect() {
  showKeyError(""); showHint("");
  const key = el.keyInput.value;
  if (!key.trim() && !ui.hasKey) { showKeyError("Вставьте ключ из Telegram."); return; }
  ui.busy = true; ui.verdict = null; render();
  el.results.classList.add("hidden");
  setStatus("Подключаюсь…", "idle");
  const r = await api("/api/connect", { key, remember: el.remember.checked });
  if (!r.ok) {
    ui.busy = false;
    if (r.data.code === "key") { setStatus("Не подключено.", "idle"); showKeyError(r.data.message || "Ключ не подошёл."); }
    else setStatus(r.data.message || "Не удалось подключиться.", "err");
    await refreshState(); render();
    return;
  }
  el.keyInput.value = ""; // the key lives only in the launcher (and, if asked, DPAPI-encrypted on disk)
  ui.replacing = false; ui.phase = "connected";
  await refreshState();
  await verify();
}

async function refreshState() {
  const s = (await api("/api/state")).data;
  ui.hasKey = !!s.hasKey;
  if (!ui.busy) {
    const was = ui.phase;
    ui.phase = s.phase;
    if (s.phase === "error" && was !== "error") {
      setStatus(s.error || "Соединение прервано.", "err");
      el.results.classList.add("hidden"); ui.verdict = null;
    }
  }
  render();
  return s;
}

function openSite() {
  const u = parseSite(el.siteUrl.value);
  if (u && ui.phase === "connected" && (ui.verdict === "ok" || ui.verdict === "ok-nodirect")) window.open(u, "_blank", "noopener");
}

async function init() {
  el.mainBtn.addEventListener("click", () => (ui.phase === "connected" ? disconnect() : connect()));
  el.openBtn.addEventListener("click", openSite);
  el.siteUrl.addEventListener("input", render);
  el.siteUrl.addEventListener("keydown", (e) => { if (e.key === "Enter") openSite(); });
  el.recheckBtn.addEventListener("click", verify);
  el.keyReplace.addEventListener("click", () => { ui.replacing = true; render(); el.keyInput.focus(); });
  el.keyForget.addEventListener("click", async () => { await api("/api/forget", {}); ui.replacing = false; await refreshState(); setStatus("Ключ удалён с этого компьютера.", "idle"); });
  el.keyInput.addEventListener("input", () => showKeyError(""));

  const s = await refreshState();
  if (s.phase === "connected") await verify();
  else if (s.phase === "error") setStatus(s.error || "Ошибка.", "err");
  else setStatus(s.hasKey ? "Не подключено. Нажмите «Подключить»." : "Не подключено. Вставьте ключ и нажмите «Подключить».", "idle");
  setInterval(() => { if (!ui.busy) refreshState().catch(() => {}); }, 3000);
}

init().catch(() => setStatus("Не удалось связаться с программой. Закройте окно и запустите Runet Access снова.", "err"));
