import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";

globalThis.chrome = { i18n: { getMessage: () => "" }, runtime: { lastError: null } };
const { pacConfig } = await import("../src/extension/src/lib/proxy.js");
import { proxyDomainsFor } from "../src/extension/src/gov/gov-config.js";

// Chrome's PAC helpers, reimplemented faithfully enough for these rules.
const globToRegExp = (p) =>
  new RegExp("^" + p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$");

function makePac(domains) {
  const cfg = pacConfig("127.0.0.1", 12345, { proxyDomains: domains, directDomains: [] });
  assert.equal(cfg.mode, "pac_script");
  assert.equal(cfg.pacScript.mandatory, true, "PAC must be mandatory (fail-closed)");
  const ctx = {
    isPlainHostName: (h) => !h.includes("."),
    dnsDomainIs: (h, d) => h.endsWith(d),
    shExpMatch: (s, p) => globToRegExp(p).test(s),
  };
  vm.createContext(ctx);
  vm.runInContext(cfg.pacScript.data, ctx);
  return (url) => ctx.FindProxyForURL(url, new URL(url).hostname);
}

const gov = { url: "https://lk.example.ru/", extraDomains: ["sso.example.ru", "*.static.example.ru"] };
const pac = makePac(proxyDomainsFor(gov));
const PROXY = "SOCKS5 127.0.0.1:12345";

test("gov site, its subdomains, extras and the proxied probes go through the proxy", () => {
  for (const u of [
    "https://lk.example.ru/a", "https://x.lk.example.ru/", "https://sso.example.ru/",
    "https://cdn.static.example.ru/", "https://static.example.ru/",
    "https://api.country.is/", "https://ipwho.is/",
  ]) assert.equal(pac(u), PROXY, u);
});

test("everything else, including the DIRECT reference probe, stays direct", () => {
  for (const u of [
    "https://api.ipify.org/", "https://www.google.com/", "https://example.ru/",
    "https://evil-lk.example.ru/", "https://lk.example.ru.evil.com/", "https://notipwho.is/",
    "http://localhost:8080/", "http://127.0.0.1/", "http://intranet/",
  ]) assert.equal(pac(u), "DIRECT", u);
});

test("an unconfigured site still proxies only the probes", () => {
  const p = makePac(proxyDomainsFor({ url: "", extraDomains: [] }));
  assert.equal(p("https://api.country.is/"), PROXY);
  assert.equal(p("https://www.gosuslugi.ru/"), "DIRECT");
});
