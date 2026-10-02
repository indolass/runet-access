// Run: node --test tests/check.test.mjs   (synthetic data, no network)
import { test } from "node:test";
import assert from "node:assert/strict";
import { runChecks } from "../src/app/cmd/launcher/ui/check.js";

const CFG = {
  expectedCountry: "RU", timeoutMs: 8000,
  proxied: [{ id: "country.is", url: "https://api.country.is/" }, { id: "ipwho.is", url: "https://ipwho.is/" }],
  direct: { id: "ipify", url: "/api/direct-ip" },
};
const reply = (body, ok = true) => async () => ({ ok, status: ok ? 200 : 500, json: async () => body });
function router(map) {
  return async (url, opts) => {
    for (const [prefix, h] of Object.entries(map)) if (url.startsWith(prefix)) return h(url, opts);
    throw new Error("unexpected url " + url);
  };
}
const DIRECT = { "/api/direct-ip": reply({ ip: "198.51.100.7" }) };
const run = (f, cfg = CFG) => runChecks({ fetchImpl: f, cfg });

test("verdict ok: RU exit, ordinary address differs", async () => {
  const r = await run(router({ "https://api.country.is": reply({ ip: "203.0.113.5", country: "RU" }), ...DIRECT }));
  assert.equal(r.verdict, "ok");
  assert.equal(r.proxied.country, "RU");
});

test("verdict wrong-country", async () => {
  assert.equal((await run(router({ "https://api.country.is": reply({ ip: "203.0.113.5", country: "DE" }), ...DIRECT }))).verdict, "wrong-country");
});

test("verdict same-ip: the proxied probe went out on the ordinary connection", async () => {
  assert.equal((await run(router({ "https://api.country.is": reply({ ip: "198.51.100.7", country: "RU" }), ...DIRECT }))).verdict, "same-ip");
});

test("failed diagnostics are 'unknown', never success", async () => {
  const f = router({
    "https://api.country.is": async () => { throw new Error("net down"); },
    "https://ipwho.is": reply({ success: false }),
    ...DIRECT,
  });
  const r = await run(f);
  assert.equal(r.verdict, "unknown");
  assert.match(r.proxied.error, /country\.is/);
});

test("falls back to the second proxied endpoint", async () => {
  const f = router({
    "https://api.country.is": reply({}, false),
    "https://ipwho.is": reply({ success: true, ip: "203.0.113.5", country_code: "ru" }),
    ...DIRECT,
  });
  const r = await run(f);
  assert.equal(r.verdict, "ok");
  assert.equal(r.proxied.source, "ipwho.is");
});

test("malformed answers are rejected", async () => {
  const f = router({
    "https://api.country.is": reply({ ip: "<script>", country: "RU" }),
    "https://ipwho.is": reply({ ip: "203.0.113.5", country_code: "Russia" }),
    ...DIRECT,
  });
  assert.equal((await run(f)).verdict, "unknown");
});

test("missing ordinary-address reference does not fail an RU exit", async () => {
  const f = router({
    "https://api.country.is": reply({ ip: "203.0.113.5", country: "RU" }),
    "/api/direct-ip": reply({ error: "unavailable" }, false),
  });
  assert.equal((await run(f)).verdict, "ok-nodirect");
});

test("a hanging probe times out instead of hanging", async () => {
  const hang = (_u, { signal }) => new Promise((_, rej) => signal.addEventListener("abort", () => rej(Object.assign(new Error("a"), { name: "AbortError" }))));
  const f = router({ "https://api.country.is": hang, "https://ipwho.is": hang, ...DIRECT });
  const r = await run(f, { ...CFG, timeoutMs: 30 });
  assert.equal(r.verdict, "unknown");
  assert.match(r.proxied.error, /timeout/);
});

test("same-origin reference is fetched with cookies, third-party probes without", async () => {
  const seen = {};
  const f = async (url, opts) => { seen[url] = opts.credentials; return reply(url.startsWith("/") ? { ip: "198.51.100.7" } : { ip: "203.0.113.5", country: "RU" })(); };
  await run(f);
  assert.equal(seen["/api/direct-ip"], "same-origin");
  assert.equal(seen["https://api.country.is/"], "omit");
});
