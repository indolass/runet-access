// Runet Access: defaults for the "one gov site" scenario.
//
// The portal address is NOT hard-coded: the owner has not named it yet and this
// project must not invent one. It is configured in the popup ("Настройки сайта")
// and stored in chrome.storage.local under GOV_STORAGE_KEY.

export const GOV_STORAGE_KEY = "gov";
export const GOV_PROFILE_ID = "runet-access-key"; // single saved key, replaced in place
export const GOV_PROFILE_NAME = "Runet Access"; // never the server name: it reaches logs

export const DEFAULT_GOV = {
  url: "", // https://… of the target site; empty until configured
  extraDomains: [], // login/CDN hosts of the site, e.g. the SSO host (owner-provided)
  expectedCountry: "RU",
};

// Diagnostic endpoints. The PROXIED ones are added to the PAC proxy list, so the
// check travels exactly the route the gov site uses (PAC -> local SOCKS -> VLESS).
// The DIRECT one must never be in the PAC list: it shows that ordinary traffic of
// this Chrome profile still leaves directly.
export const CHECKS = {
  proxied: [
    { id: "country.is", url: "https://api.country.is/", host: "api.country.is" },
    { id: "ipwho.is", url: "https://ipwho.is/", host: "ipwho.is" },
  ],
  direct: { id: "ipify", url: "https://api.ipify.org/?format=json", host: "api.ipify.org" },
  timeoutMs: 8000,
};

const HOST_RE = /^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

/** Normalizes user input ("https://lk.example.ru/path", "*.example.ru") to a host rule or null. */
export function normalizeDomain(input) {
  let s = String(input || "").trim().toLowerCase();
  if (!s) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(s)) {
    try {
      s = new URL(s).hostname;
    } catch {
      return null;
    }
  } else {
    s = s.split(/[/?#]/)[0].replace(/:\d+$/, "");
  }
  return HOST_RE.test(s) ? s : null;
}

/** Parses the target URL; only https is accepted. Returns {url, host} or null. */
export function parseSiteUrl(input) {
  const s = String(input || "").trim();
  if (!s) return null;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : "https://" + s);
    if (u.protocol !== "https:") return null;
    if (u.username || u.password) return null;
    const host = normalizeDomain(u.hostname);
    if (!host || host.startsWith("*.")) return null;
    return { url: u.toString(), host };
  } catch {
    return null;
  }
}

/** The list that goes into the PAC "proxy only these" rule. */
export function proxyDomainsFor(gov) {
  const out = new Set();
  const site = parseSiteUrl(gov.url);
  if (site) out.add(site.host);
  for (const d of gov.extraDomains || []) {
    const n = normalizeDomain(d);
    if (n) out.add(n);
  }
  for (const c of CHECKS.proxied) out.add(c.host);
  return [...out];
}
