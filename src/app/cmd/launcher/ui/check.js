// Exit verification. Pure logic over an injected fetch so it can be unit-tested (node --test).
//
// A started core proves nothing. The proxied probes run in THIS browser window, whose whole
// traffic goes through the key, so they travel exactly the route every site uses. The direct
// reference comes from the launcher (outside the window) and shows the ordinary address.
// Anything undeterminable is "unknown" — never a success.

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]+$/i;

async function getJson(fetchImpl, url, timeoutMs) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetchImpl(url, {
      signal: ctl.signal,
      cache: "no-store",
      credentials: url.startsWith("/") ? "same-origin" : "omit",
    });
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
export async function probeProxied(fetchImpl, cfg) {
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

export async function probeDirect(fetchImpl, cfg) {
  try {
    return normalize(cfg.direct.id, await getJson(fetchImpl, cfg.direct.url, cfg.timeoutMs));
  } catch (e) {
    return { error: reason(e) };
  }
}

/**
 * verdict:
 *   ok            exit country matches and the ordinary address is demonstrably different
 *   ok-nodirect   exit country matches, the reference is unavailable (not a failure)
 *   wrong-country exit is somewhere else
 *   same-ip       proxied and ordinary addresses are identical -> traffic is NOT using the key
 *   unknown       the exit could not be determined
 */
export async function runChecks({ fetchImpl, cfg }) {
  const [proxied, direct] = await Promise.all([probeProxied(fetchImpl, cfg), probeDirect(fetchImpl, cfg)]);
  let verdict;
  if (proxied.error) verdict = "unknown";
  else if (direct.ip && direct.ip === proxied.ip) verdict = "same-ip";
  else if (proxied.country !== String(cfg.expectedCountry).toUpperCase()) verdict = "wrong-country";
  else verdict = direct.error ? "ok-nodirect" : "ok";
  return { verdict, proxied, direct, expectedCountry: cfg.expectedCountry, at: Date.now() };
}
