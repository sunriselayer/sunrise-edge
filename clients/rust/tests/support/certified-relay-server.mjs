import { equal, ok } from "node:assert/strict";
import { createServer } from "node:https";
import { createInterface } from "node:readline";
import { createCertifiedVercelHandler } from "../../../../adapters/vercel/src/adapter.ts";

// This bridge is a test-owned HTTP/Fetch adapter, NOT the deployed Vercel runtime.
// The actual certified constructor and native Node HTTP/TLS framing are exercised.
equal(process.version, "v22.20.0", "owning rust-tests lane must supply pinned Node");
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
const input = lines[Symbol.asyncIterator]();
const configLine = await input.next();
ok(!configLine.done, "disposable TLS configuration required on stdin");
const identity = JSON.parse(configLine.value);
const latePath = "/v1/objects/" + "ee".repeat(32);
const outcomes = [];
let releaseLateError;
const lateGate = new Promise((resolve) => { releaseLateError = resolve; });
const expected = new Map([
  ["GET /v1/context", "query-bytes"],
  ["POST /v1/fastvote/prepare", "submission-bytes"],
]);
const handler = createCertifiedVercelHandler({
  nodeCoreUrl: "https://configured.invalid",
  bearerToken: "disposable-upstream-token",
  timeoutMilliseconds: 2000,
  async fetch(request) {
    equal(request.headers.get("authorization"), "Bearer disposable-upstream-token");
    equal(request.headers.get("cookie"), null);
    const url = new URL(request.url);
    equal(url.origin, "https://configured.invalid");
    const key = request.method + " " + url.pathname;
    if (key === "POST /v1/fastvote/drain/signer-page") {
      equal(Buffer.from(await request.arrayBuffer()).toString("hex"), "0102");
      return new Response(null, { status: 204 });
    }
    if (url.pathname === latePath) {
      let first = true;
      return new Response(new ReadableStream({
        async pull(controller) {
          if (first) {
            first = false;
            controller.enqueue(new TextEncoder().encode("already-received-prefix"));
            return;
          }
          await lateGate;
          controller.error(new Error("test-owned late upstream failure"));
        },
      }, { highWaterMark: 0 }), {
        headers: { "content-type": "application/vnd.sunrise-edge.query-result" },
      });
    }
    ok(expected.has(key), "fixture accepts only its fixed GET/POST routes");
    if (request.method === "POST") {
      equal(Buffer.from(await request.arrayBuffer()).toString("hex"), "0102");
    }
    const body = new TextEncoder().encode(expected.get(key));
    return new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(body.subarray(0, 3));
        controller.enqueue(body.subarray(3));
        controller.close();
      },
    }), {
      headers: { "content-type": request.method === "POST"
        ? "application/vnd.sunrise-edge.node-result"
        : "application/vnd.sunrise-edge.query-result" },
    });
  },
});

const watchdog = setTimeout(() => {
  process.stderr.write("local relay fixture exceeded its bounded lifetime\n");
  process.exit(1);
}, 30000);
const server = createServer({ cert: identity.cert, key: identity.key }, async (req, res) => {
  let reader;
  try {
    let count = 0;
    const parts = [];
    for await (const part of req) {
      count += part.length;
      ok(count <= 4096, "test-owned incoming request bound");
      parts.push(part);
    }
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
      if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(",") : value);
    }
    const request = new Request("https://relay.test" + req.url, {
      method: req.method,
      headers,
      ...(req.method === "POST" ? { body: Buffer.concat(parts), duplex: "half" } : {}),
    });
    const response = await handler(request);
    res.statusCode = response.status;
    response.headers.forEach((value, name) => res.setHeader(name, value));
    res.setHeader("connection", "close");
    const key = req.method + " " + req.url;
    if (response.body === null) {
      equal(response.status, 204);
      equal(res.hasHeader("content-length"), false);
      equal(res.hasHeader("transfer-encoding"), false);
      res.end();
      outcomes.push("EMPTY " + key);
      return;
    }
    equal(res.hasHeader("content-length"), false);
    res.flushHeaders();
    equal(res.chunkedEncoding, true, "actual Node wire must be chunked");
    reader = response.body.getReader();
    let wrote = false;
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      await new Promise((resolve, reject) => res.write(Buffer.from(next.value), (error) => error ? reject(error) : resolve()));
      if (!wrote) {
        wrote = true;
        if (req.url === latePath) releaseLateError();
      }
    }
    ok(wrote, "fixture streamed a nonempty payload");
    res.end();
    outcomes.push("CHUNKED " + key);
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
