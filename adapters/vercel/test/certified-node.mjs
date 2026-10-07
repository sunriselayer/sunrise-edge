import { deepStrictEqual, equal } from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { createCertifiedVercelHandler } from "../src/adapter.ts";
import {
  fixturePath,
  parseCertifiedRouteFixtures,
} from "../../shared/test-support/certified-fixtures.ts";

// Vercel's real Request is Undici, not Deno's web shim. This test uses native
// Node globals and intercepts fetch before any socket or hosted resource.
const fixtures = parseCertifiedRouteFixtures(
  await readFile(
    new URL("../../shared/certified-route-contract.tsv", import.meta.url),
    "utf8",
  ),
);
const eventMedia = "application/vnd.sunrise-edge.node-event";
const resultBytes = new Uint8Array([7, 6, 5]);

for (const fixture of fixtures) {
  test(`native Node certified ${fixture.method} ${fixture.path}`, async () => {
    let calls = 0;
    const payload = fixture.emptyRequest ? new Uint8Array(0) : new Uint8Array([1, 2]);
    const handler = createCertifiedVercelHandler({
      nodeCoreUrl: "https://configured.invalid",
      bearerToken: "disposable-test-token",
      async fetch(request) {
        calls += 1;
        equal(request.url, "https://configured.invalid" + fixturePath(fixture));
        equal(request.method, fixture.method);
        equal(request.redirect, "manual");
        equal(request.headers.get("authorization"), "Bearer disposable-test-token");
        equal(request.headers.get("cookie"), null);
        deepStrictEqual(
          new Uint8Array(await request.arrayBuffer()),
          fixture.method === "POST" ? payload : new Uint8Array(0),
        );
        return new Response(fixture.success === "empty" ? null : resultBytes, {
          status: fixture.success === "empty" ? 204 : 200,
          headers: fixture.success === "empty" ? {} : {
            "content-type": fixture.method === "POST"
              ? "application/vnd.sunrise-edge.node-result"
              : "application/vnd.sunrise-edge.query-result",
          },
        });
      },
    });
    const response = await handler(
      new Request("https://caller.invalid" + fixturePath(fixture), {
        method: fixture.method,
        headers: {
          authorization: "Bearer caller-token",
          cookie: "caller-cookie",
          ...(fixture.method === "POST" ? { "content-type": eventMedia } : {}),
        },
        ...(fixture.method === "POST" ? { body: payload } : {}),
      }),
    );
    equal(calls, 1);
    equal(response.status, fixture.success === "empty" ? 204 : 200);
    deepStrictEqual(
      new Uint8Array(await response.arrayBuffer()),
      fixture.success === "empty" ? new Uint8Array(0) : resultBytes,
    );
  });
}
