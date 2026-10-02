// Prints the Chrome extension ID derived from the "key" field of the manifest.
// Usage: node scripts/ext-id.mjs [path/to/manifest.json]
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const path = process.argv[2] || new URL("../src/extension/manifest.json", import.meta.url);
const key = JSON.parse(readFileSync(path, "utf8")).key;
if (!key) throw new Error("manifest has no key");
const der = Buffer.from(key, "base64");
const id = [...createHash("sha256").update(der).digest().subarray(0, 16)]
  .map((b) => String.fromCharCode(97 + (b >> 4)) + String.fromCharCode(97 + (b & 15)))
  .join("");
console.log(id);
