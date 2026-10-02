// Minimal Chrome DevTools Protocol driver for the test browser profile (inside the repo).
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function launchChrome({ profileName, extensionDir, extraArgs = [] }) {
  const profile = join(root, ".local", "browser-profile", profileName);
  mkdirSync(profile, { recursive: true });
  // Chrome 137+ ignores --load-extension. Extensions.loadUnpacked over a debugging PIPE
  // (with --enable-unsafe-extension-debugging) is the supported engineering route.
  const args = [
    `--user-data-dir=${profile}`, "--remote-debugging-pipe", "--enable-unsafe-extension-debugging",
    "--no-first-run", "--no-default-browser-check", "--window-size=900,900", ...extraArgs, "about:blank",
  ];
  const child = spawn(CHROME, args, { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] });
  const browser = new Cdp(child.stdio[3], child.stdio[4]);
  await sleep(1500);
  let extId = null;
  if (extensionDir) extId = (await browser.send("Extensions.loadUnpacked", { path: extensionDir })).id;
  return {
    child, browser, profile, extId,
    async close() {
      try { await browser.send("Browser.close"); } catch {}
      await sleep(1500);
      spawnSync("taskkill", ["/T", "/F", "/PID", String(child.pid)]);
    },
  };
}

export class Cdp {
  constructor(toChrome, fromChrome) {
    this.toChrome = toChrome; this.id = 0; this.pending = new Map(); this.handlers = []; this.buf = "";
    fromChrome.on("data", (d) => {
      this.buf += d.toString("utf8");
      let i;
      while ((i = this.buf.indexOf("\u0000")) >= 0) {
        const raw = this.buf.slice(0, i); this.buf = this.buf.slice(i + 1);
        const m = JSON.parse(raw);
        if (m.id && this.pending.has(m.id)) { const p = this.pending.get(m.id); this.pending.delete(m.id); m.error ? p.rej(new Error(m.error.message)) : p.res(m.result); }
        else for (const h of this.handlers) h(m);
      }
    });
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    return new Promise((res, rej) => {
      const t = setTimeout(() => { this.pending.delete(id); rej(new Error("CDP timeout: " + method)); }, 30000);
      this.pending.set(id, { res: (v) => { clearTimeout(t); res(v); }, rej: (e) => { clearTimeout(t); rej(e); } });
      this.toChrome.write(JSON.stringify({ id, method, params, sessionId }) + "\u0000");
    });
  }
  on(fn) { this.handlers.push(fn); }
  async attach(targetId) { return (await this.send("Target.attachToTarget", { targetId, flatten: true })).sessionId; }
}

export async function findExtensionId(browser, expectedId, tries = 40) {
  for (let i = 0; i < tries; i++) {
    const { targetInfos } = await browser.send("Target.getTargets");
    const t = targetInfos.find((x) => x.url.startsWith(`chrome-extension://${expectedId}/`));
    if (t) return expectedId;
    await sleep(250);
  }
  return null;
}

/** Opens a page, returns helpers bound to its session. */
export async function openPage(browser, url) {
  const { targetId } = await browser.send("Target.createTarget", { url });
  const sid = await browser.attach(targetId);
  await browser.send("Runtime.enable", {}, sid);
  const evaluate = async (expression) => {
    const r = await browser.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, sid);
    if (r.exceptionDetails) throw new Error("page exception: " + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
    return r.result.value;
  };
  const waitFor = async (expr, ms = 15000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await evaluate(expr)) return true; } catch {} await sleep(200); } return false; };
  const shot = async (file) => {
    try {
      await browser.send("Target.activateTarget", { targetId });
      const { data } = await browser.send("Page.captureScreenshot", { format: "png" }, sid);
      (await import("node:fs")).writeFileSync(file, Buffer.from(data, "base64"));
    } catch (e) { console.log("      (screenshot skipped: " + e.message + ")"); }
  };
  return { targetId, sid, evaluate, waitFor, shot };
}
