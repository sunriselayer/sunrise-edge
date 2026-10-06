import { deepStrictEqual, equal, rejects } from "node:assert/strict";
import {
  fixturePath,
  parseCertifiedRouteFixtures,
} from "../../shared/test-support/certified-fixtures.ts";
import {
  createCertifiedVercelHandler,
  MAX_VERCEL_REQUEST_BODY_BYTES,
} from "../src/adapter.ts";

const fixtures = parseCertifiedRouteFixtures(
  await Deno.readTextFile(
    new URL("../../shared/certified-route-contract.tsv", import.meta.url),
  ),
);
const ROOT = "https://certified.internal.example";
const EVENT_MEDIA = "application/vnd.sunrise-edge.node-event";
const RESULT_MEDIA = "application/vnd.sunrise-edge.node-result";
const RESULT_BYTES = new Uint8Array([9, 8, 7]);

for (const fixture of fixtures) {
  Deno.test(`Vercel certified literal ${fixture.method} ${fixture.path}`, async () => {
    let forwarded: Request | undefined;
    const handler = createCertifiedVercelHandler({
      nodeCoreUrl: ROOT,
      bearerToken: "test-token",
      fetch(request) {
        forwarded = request;
        return Promise.resolve(
          new Response(fixture.success === "empty" ? null : RESULT_BYTES, {
            status: fixture.success === "empty" ? 204 : 200,
            headers: fixture.success === "empty" ? {} : {
              "content-type": fixture.method === "POST"
                ? RESULT_MEDIA
                : "application/vnd.sunrise-edge.query-result",
            },
          }),
        );
      },
    });
    const response = await handler(
      new Request("https://edge.example" + fixturePath(fixture), {
        method: fixture.method,
        headers: {
          authorization: "Bearer caller",
          cookie: "caller-cookie",
          ...(fixture.method === "POST" ? { "content-type": EVENT_MEDIA } : {}),
        },
        ...(fixture.method === "GET" ? {} : {
          body: fixture.emptyRequest ? new Uint8Array(0) : new Uint8Array([1]),
        }),
      }),
    );
    equal(forwarded?.url, ROOT + fixturePath(fixture));
    equal(forwarded?.method, fixture.method);
    equal(forwarded?.headers.get("authorization"), "Bearer test-token");
    equal(forwarded?.headers.get("cookie"), null);
    equal(forwarded?.redirect, "manual");
    equal(response.status, fixture.success === "empty" ? 204 : 200);
    deepStrictEqual(
      new Uint8Array(await response.arrayBuffer()),
      fixture.success === "empty" ? new Uint8Array(0) : RESULT_BYTES,
    );
  });
}

Deno.test("Vercel certified bounds both incoming frames and complete streamed responses at 4 MiB", async () => {
  let calls = 0;
  const handler = createCertifiedVercelHandler({
    nodeCoreUrl: ROOT,
    bearerToken: "test-token",
    fetch() {
      calls += 1;
      return Promise.resolve(
        new Response(null, {
          headers: {
            "content-type": RESULT_MEDIA,
            "content-length": String(MAX_VERCEL_REQUEST_BODY_BYTES + 1),
          },
        }),
      );
    },
  });
  const preDispatch = await handler(
    new Request("https://edge.example/v1/fastvote/prepare", {
      method: "POST",
      headers: {
        "content-type": EVENT_MEDIA,
        "content-length": String(MAX_VERCEL_REQUEST_BODY_BYTES + 1),
      },
      body: new Uint8Array([1]),
    }),
  );
  equal(preDispatch.status, 413);
  await preDispatch.arrayBuffer();
  equal(calls, 0);
  const invalidResponse = await handler(
    new Request("https://edge.example/v1/fastvote/certificates", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA },
      body: new Uint8Array([1]),
    }),
  );
  equal(calls, 1);
  equal(invalidResponse.status, 503);
  equal(await invalidResponse.text(), "node-core-outcome-unknown");

  let cancelled = false;
  let chunk = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      chunk += 1;
      controller.enqueue(
        new Uint8Array(chunk === 1 ? MAX_VERCEL_REQUEST_BODY_BYTES : 1),
      );
    },
    cancel() {
      cancelled = true;
    },
  }, { highWaterMark: 0 });
  const late = createCertifiedVercelHandler({
    nodeCoreUrl: ROOT,
    bearerToken: "test-token",
    fetch: () =>
      Promise.resolve(
        new Response(stream, { headers: { "content-type": RESULT_MEDIA } }),
      ),
  });
  const response = await late(
    new Request("https://edge.example/v1/fastvote/certificates", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA },
      body: new Uint8Array([1]),
    }),
  );
  equal(response.status, 200);
  await rejects(() => response.arrayBuffer());
  equal(cancelled, true);
  equal(stream.locked, false);
});

Deno.test("Vercel certified routing template uses a closed noncapturing inventory without query aliases", async () => {
  const text = await Deno.readTextFile(
    new URL("../vercel.certified.json", import.meta.url),
  );
  const configuration: unknown = JSON.parse(text);
  if (
    typeof configuration !== "object" || configuration === null ||
    !("routes" in configuration) || !Array.isArray(configuration.routes)
  ) throw new TypeError("invalid Vercel test configuration");
  const patterns: RegExp[] = [];
  const rows: readonly unknown[] = configuration.routes;
  for (const row of rows) {
    if (
      typeof row !== "object" || row === null || !("src" in row) ||
      !("dest" in row) ||
      typeof row.src !== "string" || row.dest !== "/api/ingress"
    ) throw new TypeError("invalid Vercel test route");
    equal(row.src.startsWith("^"), true);
    equal(row.src.endsWith("$"), true);
    equal(row.src.includes("("), false);
    equal(row.src.includes(":"), false);
    patterns.push(new RegExp(row.src));
  }
  equal(patterns.length, 22);
  for (const path of ["/health/live", ...fixtures.map(fixturePath)]) {
    equal(patterns.filter((pattern) => pattern.test(path)).length, 1, path);
    equal(patterns.some((pattern) => pattern.test(path + "/suffix")), false);
  }
  for (
    const path of ["/v1/events", "/v1/contracts/publications", "/v1/unlisted"]
  ) {
    equal(patterns.some((pattern) => pattern.test(path)), false);
  }
});
