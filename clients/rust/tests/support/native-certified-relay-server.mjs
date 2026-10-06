import { equal, ok } from "node:assert/strict";
import { createServer } from "node:https";
import { createInterface } from "node:readline";
import { createCertifiedVercelHandler } from "../../../../adapters/vercel/src/adapter.ts";

// This bridge is a second, test-owned HTTP/Fetch adapter, NOT the deployed
// Vercel runtime. It proves the actual certified constructor forwarding a
// real native loopback HTTP response, never a canonical fixture answer. The
// native listener is unauthenticated; this bridge never implies the native
// side or its own caller holds any client/origin authentication.
equal(process.version, "v22.20.0", "owning rust-tests lane must supply pinned Node");
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
const input = lines[Symbol.asyncIterator]();
const configLine = await input.next();
ok(!configLine.done, "disposable TLS configuration required on stdin");
const identity = JSON.parse(configLine.value);
ok(
  Number.isInteger(identity.nativePort) &&
    identity.nativePort >= 1 &&
    identity.nativePort <= 65535,
  "nativePort must be a bounded integer port",
);
// The sole translation from the fixed HTTPS test origin to the actual native
// listener: a literal loopback IP plus the given numeric port, never a DNS
// name and never a remote target.
const nativeOrigin = new URL(`http://127.0.0.1:${identity.nativePort}`);
equal(nativeOrigin.protocol, "http:");
equal(nativeOrigin.hostname, "127.0.0.1");

const closedGetPaths = [
  /^\/v1\/context$/,
  /^\/v1\/objects\/[0-9a-f]{64}$/,
  /^\/v1\/receipts\/[0-9a-f]{64}$/,
  /^\/v1\/senders\/[0-9a-f]{64}\/next-nonce$/,
];

const outcomes = [];
const handler = createCertifiedVercelHandler({
  nodeCoreUrl: "https://configured.invalid",
  bearerToken: "disposable-upstream-token",
  timeoutMilliseconds: 2000,
  async fetch(request) {
    equal(request.headers.get("authorization"), "Bearer disposable-upstream-token");
    equal(request.headers.get("cookie"), null);
    const url = new URL(request.url);
    equal(url.origin, "https://configured.invalid");
    equal(url.search, "");
    equal(url.hash, "");
    equal(url.username, "");
    equal(url.password, "");
    equal(request.method, "GET", "native bridge forwards only bodyless GET");
    equal(request.body, null, "native bridge forwards only bodyless GET");
    ok(
      closedGetPaths.some((pattern) => pattern.test(url.pathname)),
      "fixture forwards only its four closed GET paths",
    );
    const native = new Request(new URL(url.pathname, nativeOrigin), {
      method: "GET",
      redirect: "manual",
      signal: request.signal,
    });
    // The actual native response, unauthenticated and unmodified.
    return fetch(native);
  },
});

const watchdog = setTimeout(() => {
  process.stderr.write("local native relay bridge exceeded its bounded lifetime\n");
  process.exit(1);
}, 30000);
const server = createServer({ cert: identity.cert, key: identity.key }, async (req, res) => {
  let reader;
  try {
    equal(req.method, "GET", "bridge serves only the test's bodyless GET routes");
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
      if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(",") : value);
    }
    const request = new Request("https://relay.test" + req.url, { method: "GET", headers });
    const response = await handler(request);
    res.statusCode = response.status;
    response.headers.forEach((value, name) => res.setHeader(name, value));
    res.setHeader("connection", "close");
    equal(res.hasHeader("content-length"), false);
    res.flushHeaders();
    equal(res.chunkedEncoding, true, "actual Node wire must be chunked");
    ok(response.body !== null, "every closed GET response is nonempty");
    reader = response.body.getReader();
    let wrote = false;
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      await new Promise((resolve, reject) => res.write(Buffer.from(next.value), (error) => error ? reject(error) : resolve()));
      wrote = true;
    }
    ok(wrote, "fixture streamed a nonempty payload");
    res.end();
    outcomes.push("CHUNKED " + req.method + " " + req.url);
  } catch {
    // NEVER res.end() in finally: that would manufacture a clean zero chunk.
    res.destroy();
    outcomes.push("RESET " + req.method + " " + req.url);
    if (reader) await reader.cancel().catch(() => {});
  } finally {
    reader?.releaseLock();
  }
});
server.on("tlsClientError", () => {});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
ok(address && typeof address !== "string");
process.stdout.write(`READY ${address.port}\n`);
const stop = await input.next();
equal(stop.value, "STOP");
server.closeAllConnections();
await new Promise((resolve) => server.close(resolve));
clearTimeout(watchdog);
for (const outcome of outcomes) process.stdout.write(outcome + "\n");
process.stdout.write("DONE\n");
lines.close();
