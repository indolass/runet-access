// Minimal Chrome DevTools Protocol client (WebSocket) for the browser the launcher starts.
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFileSync } from "node:fs";

export const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class Cdp {
  constructor(url) { this.url = url; this.id = 0; this.pending = new Map(); this.listeners = []; }
  onEvent(fn) { this.listeners.push(fn); }
  open() {
    return new Promise((res, rej) => {
      this.ws = new WebSocket(this.url);
      this.ws.onopen = res;
      this.ws.onerror = () => rej(new Error("ws error"));
      this.ws.onclose = () => { for (const p of this.pending.values()) p.rej(new Error("ws closed")); this.pending.clear(); };
      this.ws.onmessage = (ev) => {
        const m = JSON.parse(ev.data);
        if (m.id && this.pending.has(m.id)) { const p = this.pending.get(m.id); this.pending.delete(m.id); m.error ? p.rej(new Error(m.error.message)) : p.res(m.result); }
        else if (m.method) for (const f of this.listeners) f(m);
      };
    });
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    return new Promise((res, rej) => {
      const t = setTimeout(() => { this.pending.delete(id); rej(new Error("CDP timeout: " + method)); }, 30000);
      this.pending.set(id, { res: (v) => { clearTimeout(t); res(v); }, rej: (e) => { clearTimeout(t); rej(e); } });
      this.ws.send(JSON.stringify({ id, method, params, sessionId }));
    });
  }
  async attach(targetId) { return (await this.send("Target.attachToTarget", { targetId, flatten: true })).sessionId; }
}

export async function connectBrowser(port, tries = 120) {
  for (let i = 0; i < tries; i++) {
    try {
      const v = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
      const c = new Cdp(v.webSocketDebuggerUrl);
      await c.open();
      return c;
    } catch { await sleep(250); }
  }
  throw new Error("Chrome did not expose DevTools on " + port);
}

/** Waits for a page target whose URL passes `match`, returns evaluate/waitFor/shot helpers. */
export async function pageWhere(browser, match, ms = 20000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    const { targetInfos } = await browser.send("Target.getTargets");
    const t = targetInfos.find((x) => x.type === "page" && match(x.url));
    if (t) return bind(browser, t.targetId);
    await sleep(250);
  }
  throw new Error("no page matched");
}

export async function openPage(browser, url) {
  const { targetId } = await browser.send("Target.createTarget", { url });
  return bind(browser, targetId);
}

async function bind(browser, targetId) {
  const sid = await browser.attach(targetId);
  await browser.send("Runtime.enable", {}, sid);
  const evaluate = async (expression) => {
    const r = await browser.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, sid);
    if (r.exceptionDetails) throw new Error("page exception: " + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
    return r.result.value;
  };
  const waitFor = async (expr, ms = 15000) => {
    const t = Date.now();
    while (Date.now() - t < ms) { try { if (await evaluate(expr)) return true; } catch {} await sleep(200); }
    return false;
  };
  const shot = async (file) => {
    try {
      await browser.send("Target.activateTarget", { targetId });
      const { data } = await browser.send("Page.captureScreenshot", { format: "png" }, sid);
      writeFileSync(file, Buffer.from(data, "base64"));
    } catch (e) { console.log("      (screenshot skipped: " + e.message + ")"); }
  };
  const url = async () => (await browser.send("Target.getTargetInfo", { targetId })).targetInfo.url;
  return { targetId, sid, evaluate, waitFor, shot, url };
}
