// Validation of the pasted key. The accepted shape is exactly the scenario:
// vless:// + Reality + flow xtls-rprx-vision over plain TCP.
// Error messages NEVER echo any part of the key.

import { parseLink } from "../lib/parse.js";
import { GOV_PROFILE_ID, GOV_PROFILE_NAME } from "./gov-config.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PBK_RE = /^[A-Za-z0-9_-]{43}$/; // x25519 public key, base64url without padding
const SID_RE = /^[0-9a-fA-F]{0,16}$/;

const fail = (code, message) => ({ ok: false, code, message });

export function validateKey(raw) {
  const text = String(raw ?? "").trim();
  if (!text) return fail("empty", "Вставьте ключ из Telegram.");
  if (/\s/.test(text)) {
    return fail("multi", "Вставьте один ключ целиком, без пробелов и переносов строк.");
  }
  if (!/^vless:\/\//i.test(text)) {
    return fail("scheme", "Нужен ключ, который начинается с vless://");
  }
  let p;
  try {
    p = parseLink(text);
  } catch {
    return fail("broken", "Ключ повреждён или скопирован не целиком. Скопируйте его из Telegram ещё раз.");
  }
  if (!UUID_RE.test(p.uuid || "")) return fail("uuid", "В ключе нет корректного идентификатора пользователя.");
  if (!p.server || !(p.port >= 1 && p.port <= 65535)) return fail("server", "В ключе нет адреса сервера или порта.");
  if (!p.tls || !p.tls.enabled || !p.tls.reality || !p.tls.reality.enabled) {
    return fail("not-reality", "Ключ не использует Reality (security=reality). Такой ключ не подходит.");
  }
  if (!PBK_RE.test(p.tls.reality.publicKey || "")) {
    return fail("pbk", "В ключе нет корректного публичного ключа Reality (pbk).");
  }
  if (!SID_RE.test(p.tls.reality.shortId || "")) return fail("sid", "В ключе некорректный параметр sid.");
  // parseVless() silently falls back to the server address when sni is absent; for
  // Reality that is wrong (the mask host must be explicit), so look at the raw link.
  let explicitSni = "";
  try {
    const q = new URL(text).searchParams;
    explicitSni = q.get("sni") || q.get("peer") || "";
  } catch {
    /* parseLink already accepted it */
  }
  if (!explicitSni) return fail("sni", "В ключе нет имени сайта-маски (sni).");
  if (p.flow !== "xtls-rprx-vision") {
    return fail("flow", "В ключе нет flow=xtls-rprx-vision. Такой ключ не подходит.");
  }
  if (p.transport) {
    return fail("transport", "Ключ использует нестандартный транспорт. Нужен обычный TCP.");
  }
  // Same fields the host consumes; name/id are fixed so a replaced key overwrites the old one.
  return {
    ok: true,
    profile: {
      ...p,
      id: GOV_PROFILE_ID,
      name: GOV_PROFILE_NAME,
      tls: { ...p.tls, utls: p.tls.utls || { enabled: true, fingerprint: "chrome" } },
    },
  };
}
