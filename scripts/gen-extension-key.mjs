// Generates a fresh RSA public key for manifest.json "key" and prints the resulting
// extension ID. The PRIVATE key is intentionally discarded: unpacked/dev installs
// only need the public half to get a stable ID. A store release will get its own key.
import { generateKeyPairSync, createHash } from "node:crypto";
const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const der = publicKey.export({ type: "spki", format: "der" });
const id = [...createHash("sha256").update(der).digest().subarray(0, 16)]
  .map((b) => String.fromCharCode(97 + (b >> 4)) + String.fromCharCode(97 + (b & 15))).join("");
console.log(JSON.stringify({ key: der.toString("base64"), id }));
