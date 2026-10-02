// Exit verification. Pure logic over an injected fetch so it can be unit-tested.
//
// A started core proves nothing. The proxied probe goes through the SAME PAC route
// as the gov site; the direct probe shows the ordinary route is unchanged.
// Anything undeterminable is "unknown" — never a success.

import { CHECKS } from "./gov-config.js";

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]+$/i;

async function getJson(fetchImpl, url, timeoutMs) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetchImpl(url, { signal: ctl.signal, cache: "no-store", credentials: "omit" });
    if (!r.ok) throw new Error("http " + r.status);
    return await r.json();
  } finally {
    clearTimeout(timer);
  }
}

function normalize(id, body) {
  const ip = String(body?.ip ?? "");
  let country = "";
  if (id === "country.is") country = String(body?.country ?? "");
  else if (id === "ipwho.is") {
    if (body?.success === false) throw new Error("service reported failure");
    country = String(body?.country_code ?? "");
  }
  if (!IP_RE.test(ip)) throw new Error("no ip in answer");
  if (id !== "ipify" && !/^[A-Za-z]{2}$/.test(country)) throw new Error("no country in answer");
  return { ip, country: country.toUpperCase(), source: id };
}

const reason = (e) => (e && e.name === "AbortError" ? "timeout" : (e && e.message) || "error");

/** First proxied endpoint that answers sensibly wins. */
export async function probeProxied(fetchImpl, cfg = CHECKS) {
  const errors = [];
  for (const ep of cfg.proxied) {
    try {
      return normalize(ep.id, await getJson(fetchImpl, ep.url, cfg.timeoutMs));
    } catch (e) {
      errors.push(ep.id + ": " + reason(e));
    }
  }
  return { error: errors.join("; ") };
}

export async function probeDirect(fetchImpl, cfg = CHECKS) {
  try {
    return normalize(cfg.direct.id, await getJson(fetchImpl, cfg.direct.url, cfg.timeoutMs));
  } catch (e) {
    return { error: reason(e) };
  }
}

/** no-cors request: success means the TCP/TLS route works, NOT that login works. */
export async function probeSite(fetchImpl, url, timeoutMs = CHECKS.timeoutMs) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    await fetchImpl(url, { mode: "no-cors", signal: ctl.signal, cache: "no-store", credentials: "omit", redirect: "follow" });
    return { reachable: true };
  } catch (e) {
    return { reachable: false, error: e && e.name === "AbortError" ? "timeout" : "network" };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * verdict:
 *   ok            exit country matches and the ordinary route is demonstrably different
 *   ok-nodirect   exit country matches, direct reference unavailable (not a failure)
 *   wrong-country exit is somewhere else
 *   same-ip       proxied and direct IPs are identical -> traffic is NOT going through the proxy
 *   unknown       exit could not be determined
 */
export async function runChecks({ fetchImpl, expectedCountry = "RU", siteUrl = "", cfg = CHECKS }) {
  const [proxied, direct, site] = await Promise.all([
    probeProxied(fetchImpl, cfg),
    probeDirect(fetchImpl, cfg),
    siteUrl ? probeSite(fetchImpl, siteUrl, cfg.timeoutMs) : Promise.resolve(null),
  ]);
  let verdict;
  if (proxied.error) verdict = "unknown";
  else if (direct.ip && direct.ip === proxied.ip) verdict = "same-ip";
  else if (proxied.country !== String(expectedCountry).toUpperCase()) verdict = "wrong-country";
  else verdict = direct.error ? "ok-nodirect" : "ok";
  return { verdict, proxied, direct, site, expectedCountry, at: Date.now() };
}
