// Prints ONLY the server ids (and config type) from a closed v2rayN database; nothing else is read or printed.
// Usage: node tests/dbget.mjs path\to\guiNDB.db
import { DatabaseSync } from "node:sqlite";
const db = new DatabaseSync(process.argv[2], { readOnly: true });
const rows = db.prepare("SELECT IndexId, ConfigType FROM ProfileItem").all();
console.log(JSON.stringify(rows.map((r) => ({ id: r.IndexId, type: r.ConfigType }))));
db.close();
