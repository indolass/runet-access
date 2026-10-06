// A stand-in for Google's download host, for tests of the "download and install Chrome" window.
// Loopback only. Serves a given file under several behaviours and counts requests.
//   node tests/chrome-fake-server.mjs <port> <file-to-serve>
//   /ok.exe        the file (application/x-msdos-program)
//   /slow.exe      headers, then one KB per second for a long time (to test cancelling)
//   /html          a web page instead of a program
//   /redirect-away redirects to another loopback host (not on the allow-list)
//   /404           not found
//   /__hits        JSON with the number of requests per path
import http from "node:http";
import { readFileSync } from "node:fs";

const [port, file] = [Number(process.argv[2]), process.argv[3]];
const body = readFileSync(file);
const hits = {};
http.createServer((req, res) => {
  const p = req.url.split("?")[0];
  if (p === "/__hits") { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(hits)); return; }
  hits[p] = (hits[p] || 0) + 1;
  if (p === "/ok.exe") { res.writeHead(200, { "content-type": "application/x-msdos-program", "content-length": body.length }); res.end(body); return; }
  if (p === "/slow.exe") {
    res.writeHead(200, { "content-type": "application/x-msdos-program", "content-length": 50_000_000 });
    const t = setInterval(() => res.write(Buffer.alloc(1024, 0x90)), 1000);
    req.on("close", () => clearInterval(t));
    return;
  }
  if (p === "/html") { res.writeHead(200, { "content-type": "text/html" }); res.end("<html>not a program</html>"); return; }
  if (p === "/redirect-away") { res.writeHead(302, { location: `http://127.0.0.2:${port}/ok.exe` }); res.end(); return; }
  res.writeHead(404); res.end("no");
}).listen(port, "127.0.0.1", () => console.log("listening " + port));
