// Run: node --test tests/   (uses only synthetic data; no network)
import { test } from "node:test";
import assert from "node:assert/strict";
import { validateKey } from "../src/extension/src/gov/key.js";
import { runChecks } from "../src/extension/src/gov/check.js";
import { CHECKS, normalizeDomain, parseSiteUrl, proxyDomainsFor } from "../src/extension/src/gov/gov-config.js";

// Obviously synthetic: documentation-range host, fixed test UUID, made-up public key.
const UUID = "11111111-2222-3333-4444-555555555555";
const PBK = "A".repeat(43);
const good = (over = {}) => {
  const q = new URLSearchParams({
    encryption: "none", flow: "xtls-rprx-vision", security: "reality", sni: "masque.example",
    fp: "chrome", pbk: PBK, sid: "abcd1234", type: "tcp", ...over,
  });
  for (const [k, v] of Object.entries(over)) if (v === null) q.delete(k);
  return `vless://${UUID}@192.0.2.10:443?${q}#synthetic`;
};

test("accepts a vless+reality+vision key and builds a profile", () => {
  const r = validateKey(good());
  assert.equal(r.ok, true);
  assert.equal(r.profile.type, "vless");
  assert.equal(r.profile.server, "192.0.2.10");
  assert.equal(r.profile.port, 443);
  assert.equal(r.profile.flow, "xtls-rprx-vision");
  assert.equal(r.profile.tls.reality.publicKey, PBK);
  assert.equal(r.profile.name, "Runet Access"); // server must not leak into logs via the name
  assert.equal(r.profile.tls.utls.fingerprint, "chrome");
});

const rejects = [
  ["empty", "", "empty"],
  ["whitespace inside", good() + " extra", "multi"],
  ["other scheme", "vmess://abcdef", "scheme"],
  ["no reality", good({ security: "tls" }), "not-reality"],
  ["no flow", good({ flow: null }), "flow"],
  ["wrong flow", good({ flow: "xtls-rprx-direct" }), "flow"],
  ["bad pbk", good({ pbk: "short" }), "pbk"],
  ["bad sid", good({ sid: "zzzz" }), "sid"],
  ["no sni", good({ sni: null }), "sni"],
  ["ws transport", good({ type: "ws", path: "/x" }), "transport"],
  ["bad uuid", good().replace(UUID, "not-a-uuid"), "uuid"],
];
for (const [name, input, code] of rejects) {
  test("rejects: " + name, () => {
    const r = validateKey(input);
    assert.equal(r.ok, false);
    assert.equal(r.code, code);
  });
}

test("error messages never contain key material", () => {
  for (const [, input] of rejects) {
    const r = validateKey(input);
    for (const secret of [UUID, PBK, "192.0.2.10", "abcd1234"]) {
      assert.ok(!r.message.includes(secret), "message leaks " + secret);
    }
  }
});

test("domain normalization and site URL", () => {
  assert.equal(normalizeDomain("https://LK.Example.ru/path?q=1"), "lk.example.ru");
  assert.equal(normalizeDomain("*.example.ru"), "*.example.ru");
  assert.equal(normalizeDomain("localhost"), null);
  assert.equal(normalizeDomain('x"];alert(1);//.ru'), null);
  assert.equal(parseSiteUrl("http://example.ru"), null); // https only
  assert.equal(parseSiteUrl("https://user:pw@example.ru"), null);
  assert.equal(parseSiteUrl(""), null);
  assert.equal(parseSiteUrl("lk.example.ru/a").host, "lk.example.ru");
});

test("PAC proxy list contains the site, extras and the PROXIED probes only", () => {
  const d = proxyDomainsFor({ url: "https://lk.example.ru/", extraDomains: ["sso.example.ru", "bad domain"] });
  assert.deepEqual(d.sort(), ["api.country.is", "ipwho.is", "lk.example.ru", "sso.example.ru"].sort());
  assert.ok(!d.includes(CHECKS.direct.host), "direct reference must stay out of the PAC proxy list");
  // an unconfigured site still yields the probe hosts, so the check route is the PAC route
  assert.deepEqual(proxyDomainsFor({ url: "", extraDomains: [] }).sort(), ["api.country.is", "ipwho.is"]);
});

// ---- exit verification ------------------------------------------------------
const reply = (body, ok = true) => async () => ({ ok, status: ok ? 200 : 500, json: async () => body });
function router(map) {
  return async (url, opts) => {
    for (const [prefix, h] of Object.entries(map)) if (url.startsWith(prefix)) return h(url, opts);
    throw new Error("unexpected url " + url);
  };
}
const DIRECT = { "https://api.ipify.org": reply({ ip: "198.51.100.7" }) };

test("verdict ok: RU exit, direct IP differs", async () => {
  const f = router({ "https://api.country.is": reply({ ip: "203.0.113.5", country: "RU" }), ...DIRECT });
  const r = await runChecks({ fetchImpl: f });
  assert.equal(r.verdict, "ok");
  assert.equal(r.proxied.country, "RU");
});

test("verdict wrong-country", async () => {
  const f = router({ "https://api.country.is": reply({ ip: "203.0.113.5", country: "DE" }), ...DIRECT });
  assert.equal((await runChecks({ fetchImpl: f })).verdict, "wrong-country");
});

test("verdict same-ip: proxied probe went out directly", async () => {
  const f = router({ "https://api.country.is": reply({ ip: "198.51.100.7", country: "RU" }), ...DIRECT });
  assert.equal((await runChecks({ fetchImpl: f })).verdict, "same-ip");
});

test("failed diagnostics are 'unknown', never success", async () => {
  const f = router({
    "https://api.country.is": async () => { throw new Error("net down"); },
    "https://ipwho.is": reply({ success: false }),
    ...DIRECT,
  });
  const r = await runChecks({ fetchImpl: f });
  assert.equal(r.verdict, "unknown");
  assert.match(r.proxied.error, /country\.is/);
});

test("falls back to the second proxied endpoint", async () => {
  const f = router({
    "https://api.country.is": reply({}, false),
    "https://ipwho.is": reply({ success: true, ip: "203.0.113.5", country_code: "ru" }),
    ...DIRECT,
  });
  const r = await runChecks({ fetchImpl: f });
  assert.equal(r.verdict, "ok");
  assert.equal(r.proxied.source, "ipwho.is");
});

test("malformed answer is rejected", async () => {
  const f = router({
    "https://api.country.is": reply({ ip: "<script>", country: "RU" }),
    "https://ipwho.is": reply({ ip: "203.0.113.5", country_code: "Russia" }),
    ...DIRECT,
  });
  assert.equal((await runChecks({ fetchImpl: f })).verdict, "unknown");
});

test("missing direct reference does not fail an RU exit", async () => {
  const f = router({
    "https://api.country.is": reply({ ip: "203.0.113.5", country: "RU" }),
    "https://api.ipify.org": async () => { throw new Error("blocked"); },
  });
  assert.equal((await runChecks({ fetchImpl: f })).verdict, "ok-nodirect");
});

test("timeout is reported, not hung", async () => {
  const hang = (_u, { signal }) => new Promise((_, rej) => signal.addEventListener("abort", () => rej(Object.assign(new Error("a"), { name: "AbortError" }))));
  const f = router({ "https://api.country.is": hang, "https://ipwho.is": hang, ...DIRECT });
  const cfg = { ...CHECKS, timeoutMs: 30 };
  const r = await runChecks({ fetchImpl: f, cfg });
  assert.equal(r.verdict, "unknown");
  assert.match(r.proxied.error, /timeout/);
});

test("site reachability is separate from the exit verdict", async () => {
  const f = router({
    "https://api.country.is": reply({ ip: "203.0.113.5", country: "RU" }),
    "https://lk.example.ru": async () => { throw new TypeError("Failed to fetch"); },
    ...DIRECT,
  });
  const r = await runChecks({ fetchImpl: f, siteUrl: "https://lk.example.ru/" });
  assert.equal(r.verdict, "ok");
  assert.equal(r.site.reachable, false);
});
