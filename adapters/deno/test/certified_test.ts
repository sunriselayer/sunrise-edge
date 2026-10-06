import { deepStrictEqual, equal, rejects, throws } from "node:assert/strict";
import { type AuthenticatedNodeCoreConfig } from "../../shared/authenticated-node-core.ts";
import {
  configuredIngressProfile,
  createCertifiedWebIngressHandler,
} from "../../shared/certified-web-ingress.ts";
import { resolveCertifiedRoute } from "../../shared/certified-routes.ts";
import {
  type CertifiedRouteFixture,
  fixturePath,
  parseCertifiedRouteFixtures,
} from "../../shared/test-support/certified-fixtures.ts";
import { createCertifiedDenoHandler, createDenoHandler } from "../src/adapter.ts";

const fixtures = parseCertifiedRouteFixtures(
  await Deno.readTextFile(
    new URL("../../shared/certified-route-contract.tsv", import.meta.url),
  ),
);
const EVENT_MEDIA = "application/vnd.sunrise-edge.node-event";
const RESULT_MEDIA = "application/vnd.sunrise-edge.node-result";
const QUERY_MEDIA = "application/vnd.sunrise-edge.query-result";
const ROOT = "https://certified.internal.example";
const REQUEST_BYTES = new Uint8Array([1, 2, 3]);
const RESULT_BYTES = new Uint8Array([9, 8, 7]);

function config(
  fetch: NonNullable<AuthenticatedNodeCoreConfig["fetch"]>,
): AuthenticatedNodeCoreConfig {
  return { nodeCoreUrl: ROOT, bearerToken: "relay-test-token", fetch };
}

function requestFor(fixture: CertifiedRouteFixture): Request {
  return new Request(`https://edge.example${fixturePath(fixture)}`, {
    method: fixture.method,
    headers: fixture.method === "POST" ? { "content-type": EVENT_MEDIA } : {},
    ...(fixture.method === "GET"
      ? {}
      : { body: fixture.emptyRequest ? new Uint8Array(0) : REQUEST_BYTES }),
  });
}

for (const fixture of fixtures) {
  Deno.test(`certified literal route and bounds: ${fixture.method} ${fixture.path}`, async () => {
    const policy = resolveCertifiedRoute(fixturePath(fixture));
    equal(policy?.method, fixture.method);
    equal(policy?.path, fixture.path);
    equal(policy?.maximumRequestBytes, fixture.requestBytes);
    equal(policy?.maximumResponseBytes, fixture.responseBytes);
    equal(policy?.success, fixture.success);
    equal(policy?.requiresEmptyBody, fixture.emptyRequest);
    const forwarded: Request[] = [];
    const handler = createCertifiedDenoHandler(config((request) => {
      forwarded.push(request);
      return Promise.resolve(
        new Response(fixture.success === "empty" ? null : RESULT_BYTES, {
          status: fixture.success === "empty" ? 204 : 200,
          headers: fixture.success === "empty" ? {} : {
            "content-type": fixture.method === "POST" ? RESULT_MEDIA : QUERY_MEDIA,
            "content-length": "3",
            "set-cookie": "must-not-leak=1",
            "x-node-secret": "must-not-leak",
          },
        }),
      );
    }));
    const input = requestFor(fixture);
    for (
      const [key, value] of Object.entries({
        authorization: "Bearer caller",
        cookie: "caller-cookie",
        host: "attacker.example",
        forwarded: "for=attacker",
        "x-forwarded-for": "attacker",
        "x-sunrise-profile": "event-only",
      })
    ) input.headers.set(key, value);
    const response = await handler(input);
    equal(forwarded.length, 1);
    const upstream = forwarded[0]!;
    equal(upstream.url, ROOT + fixturePath(fixture));
    equal(upstream.method, fixture.method);
    equal(upstream.headers.get("authorization"), "Bearer relay-test-token");
    equal(upstream.redirect, "manual");
    equal(upstream.headers.get("cache-control"), "no-store");
    deepStrictEqual(
      [...upstream.headers.keys()].sort(),
      fixture.method === "POST"
        ? ["authorization", "cache-control", "content-type"]
        : ["authorization", "cache-control"],
    );
    if (fixture.method === "POST") {
      equal(upstream.headers.get("content-type"), EVENT_MEDIA);
      deepStrictEqual(
        new Uint8Array(await upstream.arrayBuffer()),
        fixture.emptyRequest ? new Uint8Array(0) : REQUEST_BYTES,
      );
    } else equal(upstream.body, null);
    equal(response.status, fixture.success === "empty" ? 204 : 200);
    equal(response.headers.get("cache-control"), "no-store");
    equal(response.headers.get("set-cookie"), null);
    equal(response.headers.get("x-node-secret"), null);
    equal(response.headers.get("content-length"), null);
    if (fixture.success === "empty") equal(response.body, null);
    else {deepStrictEqual(
        new Uint8Array(await response.arrayBuffer()),
        RESULT_BYTES,
      );}
  });

  Deno.test(`certified rejects wrong method and unrelated 204: ${fixture.path}`, async () => {
    let calls = 0;
    const handler = createCertifiedDenoHandler(config(() => {
      calls += 1;
      return Promise.resolve(new Response(null, { status: 204 }));
    }));
    const wrong = new Request(`https://edge.example${fixturePath(fixture)}`, {
      method: fixture.method === "POST" ? "GET" : "POST",
    });
    const denied = await handler(wrong);
    equal(denied.status, 405);
    equal(denied.headers.get("allow"), fixture.method);
    equal(calls, 0);
    const response = await handler(requestFor(fixture));
    equal(response.status, fixture.success === "result" ? 503 : 204);
    equal(calls, 1);
    await response.arrayBuffer();
  });
}

Deno.test("certified closed route inventory excludes all direct mutations and aliases", async () => {
  equal(fixtures.length, 21);
  let calls = 0;
  const handler = createCertifiedDenoHandler(config(() => {
    calls += 1;
    return Promise.reject(new Error("unreachable"));
  }));
  for (
    const path of [
      "/v1/events",
      "/v1/contracts/publications",
      "/v1/contracts/executions",
      "/v1/contracts/paid-executions",
      "/v1/fastvote/unknown",
      "/v1/objects/" + "A".repeat(64),
      "/v1/objects/" + "1".repeat(63),
      "/v1/objects/%31" + "1".repeat(63),
      "/v1/objects/" + "1".repeat(64) + "/tail",
      "/v1/fastvote/prepare/",
    ]
  ) {
    const response = await handler(new Request("https://edge.example" + path));
    equal(response.status, 404, path);
    await response.arrayBuffer();
  }
  for (const method of ["HEAD", "OPTIONS"]) {
    const response = await handler(
      new Request("https://edge.example/v1/context", { method }),
    );
    equal(response.status, 405);
    await response.arrayBuffer();
  }
  const query = await handler(
    new Request("https://edge.example/v1/context?profile=certified-fastvote"),
  );
  equal(query.status, 400);
  await query.arrayBuffer();
  equal(calls, 0);
});

Deno.test("certified GET and local health refuse body/framing instead of stripping it", async () => {
  let calls = 0;
  const handler = createCertifiedDenoHandler(config(() => {
    calls += 1;
    return Promise.reject(new Error("unreachable"));
  }));
  const framingHeaders: readonly Record<string, string>[] = [
    { "content-type": "application/octet-stream" },
    { "transfer-encoding": "chunked" },
    { "content-length": "1" },
    { "content-length": "00" },
    { "content-length": "-1" },
  ];
  for (const path of ["/health/live", "/v1/context"]) {
    for (const headers of framingHeaders) {
      const response = await handler(
        new Request("https://edge.example" + path, { headers }),
      );
      equal(response.status, 400);
      await response.arrayBuffer();
    }
    const bodyRequest = new Request("https://edge.example" + path);
    Object.defineProperty(bodyRequest, "body", {
      value: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.close();
        },
      }),
    });
    const response = await handler(bodyRequest);
    equal(response.status, 400);
    await response.arrayBuffer();
  }
  const health = await handler(
    new Request("https://edge.example/health/live", {
      headers: { "content-length": "0" },
    }),
  );
  equal(health.status, 204);
  equal(calls, 0);
});

Deno.test("certified frontier alone permits a null empty POST and always synthesizes media", async () => {
  const forwarded: Request[] = [];
  const handler = createCertifiedDenoHandler(config((request) => {
    forwarded.push(request);
    return Promise.resolve(new Response(null, { status: 204 }));
  }));
  const response = await handler(
    new Request("https://edge.example/v1/fastvote/frontier/advance", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA },
    }),
  );
  equal(response.status, 204);
  equal(forwarded[0]?.headers.get("content-type"), EVENT_MEDIA);
  equal((await forwarded[0]!.arrayBuffer()).byteLength, 0);
  for (
    const path of ["/v1/fastvote/prepare", "/v1/fastvote/drain/signer-page"]
  ) {
    const missing = await handler(
      new Request("https://edge.example" + path, {
        method: "POST",
        headers: { "content-type": EVENT_MEDIA },
      }),
    );
    equal(missing.status, 400);
    equal(await missing.text(), "missing-body");
  }
  const nonempty = await handler(
    new Request("https://edge.example/v1/fastvote/frontier/advance", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA },
      body: new Uint8Array([1]),
    }),
  );
  equal(nonempty.status, 400);
  await nonempty.arrayBuffer();
  equal(forwarded.length, 1);
});

Deno.test("certified route and provider bounds are enforced before dispatch", async () => {
  let calls = 0;
  const handler = createCertifiedDenoHandler(config(() => {
    calls += 1;
    return Promise.reject(new Error("unreachable"));
  }));
  for (const length of ["129", "00", "-1", "1.0"]) {
    const response = await handler(
      new Request("https://edge.example/v1/fastvote/frontier/page", {
        method: "POST",
        headers: { "content-type": EVENT_MEDIA, "content-length": length },
        body: REQUEST_BYTES,
      }),
    );
    equal(response.status, length === "129" ? 413 : 400);
    await response.arrayBuffer();
  }
  const actual = await handler(
    new Request("https://edge.example/v1/fastvote/frontier/page", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA },
      body: new Uint8Array(129),
    }),
  );
  equal(actual.status, 413);
  await actual.arrayBuffer();
  const mismatch = await handler(
    new Request("https://edge.example/v1/fastvote/prepare", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA, "content-length": "2" },
      body: REQUEST_BYTES,
    }),
  );
  equal(mismatch.status, 400);
  equal(await mismatch.text(), "content-length-mismatch");
  const narrowed = createCertifiedDenoHandler({
    ...config(() => {
      calls += 1;
      return Promise.reject(new Error("unreachable"));
    }),
    maximumRequestBodyBytes: 2,
  });
  const denied = await narrowed(
    new Request("https://edge.example/v1/fastvote/prepare", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA },
      body: REQUEST_BYTES,
    }),
  );
  equal(denied.status, 413);
  await denied.arrayBuffer();
  equal(calls, 0);
});

Deno.test("certified native refusal statuses are fully bounded before headers", async () => {
  for (const status of [400, 401, 403, 404, 405, 409, 413, 415, 422]) {
    const handler = createCertifiedDenoHandler(
      config(() =>
        Promise.resolve(
          new Response("native-refusal", {
            status,
            headers: {
              "content-type": "text/plain; charset=utf-8",
              "set-cookie": "no-leak",
            },
          }),
        )
      ),
    );
    const response = await handler(
      new Request("https://edge.example/v1/fastvote/prepare", {
        method: "POST",
        headers: { "content-type": EVENT_MEDIA },
        body: REQUEST_BYTES,
      }),
    );
    equal(response.status, status);
    equal(await response.text(), "native-refusal");
    equal(response.headers.get("set-cookie"), null);
  }
  for (
    const [status, media, bytes] of [
      [409, "text/plain; charset=utf-8", 1025],
      [409, "text/html", 1],
      [429, "text/plain; charset=utf-8", 1],
      [503, "text/plain; charset=utf-8", 1],
      [302, "text/plain; charset=utf-8", 1],
    ] as const
  ) {
    const handler = createCertifiedDenoHandler(
      config(() =>
        Promise.resolve(
          new Response(new Uint8Array(bytes), {
            status,
            headers: { "content-type": media },
          }),
        )
      ),
    );
    const response = await handler(
      new Request("https://edge.example/v1/fastvote/prepare", {
        method: "POST",
        headers: { "content-type": EVENT_MEDIA },
        body: REQUEST_BYTES,
      }),
    );
    equal(response.status, 503);
    equal(await response.text(), "node-core-outcome-unknown");
  }
});

Deno.test("certified post-dispatch failure is unknown and never automatically retried", async () => {
  let calls = 0;
  let simulatedCommitted = false;
  const handler = createCertifiedDenoHandler(config(() => {
    calls += 1;
    simulatedCommitted = true;
    return Promise.reject(new Error("secret must not escape"));
  }));
  const response = await handler(
    new Request("https://edge.example/v1/fastvote/prepare", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA },
      body: REQUEST_BYTES,
    }),
  );
  equal(response.status, 503);
  equal(await response.text(), "node-core-outcome-unknown");
  equal(calls, 1);
  equal(simulatedCommitted, true);
  const read = await handler(new Request("https://edge.example/v1/context"));
  equal(read.status, 503);
  equal(await read.text(), "node-core-unavailable");
  equal(calls, 2);
});

Deno.test("certified streams preserve backpressure, exact bytes and reader cleanup", async () => {
  let pulls = 0;
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls += 1;
      controller.enqueue(RESULT_BYTES);
    },
    cancel() {
      cancelled = true;
    },
  }, { highWaterMark: 0 });
  const handler = createCertifiedDenoHandler(
    config(() =>
      Promise.resolve(
        new Response(stream, { headers: { "content-type": QUERY_MEDIA } }),
      )
    ),
  );
  const response = await handler(
    new Request("https://edge.example/v1/context"),
  );
  equal(pulls, 0);
  const reader = response.body!.getReader();
  deepStrictEqual((await reader.read()).value, RESULT_BYTES);
  equal(pulls, 1);
  await reader.cancel();
  reader.releaseLock();
  equal(cancelled, true);
  equal(stream.locked, false);
});

Deno.test("certified late oversize/length failure errors a stream without inventing a refusal", async () => {
  for (const length of [undefined, "3", "5"]) {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2]));
        controller.enqueue(new Uint8Array([3, 4]));
        controller.close();
      },
      cancel() {
        cancelled = true;
      },
    });
    const handler = createCertifiedWebIngressHandler(
      config(() =>
        Promise.resolve(
          new Response(stream, {
            headers: {
              "content-type": RESULT_MEDIA,
              ...(length === undefined ? {} : { "content-length": length }),
            },
          }),
        )
      ),
      { maximumResponseBodyBytes: 4 },
    );
    const response = await handler(
      new Request("https://edge.example/v1/fastvote/prepare", {
        method: "POST",
        headers: { "content-type": EVENT_MEDIA },
        body: REQUEST_BYTES,
      }),
    );
    if (length === "5") {
      equal(response.status, 503);
      equal(await response.text(), "node-core-outcome-unknown");
    } else if (length === "3") {
      equal(response.status, 200);
      await rejects(() => response.arrayBuffer());
    } else {
      equal(response.status, 200);
      deepStrictEqual(
        new Uint8Array(await response.arrayBuffer()),
        new Uint8Array([1, 2, 3, 4]),
      );
    }
    equal(stream.locked, false);
    if (length === "5") equal(cancelled, true);
  }
});

Deno.test("certified timeout covers fetch and the complete response body", async () => {
  const never = createCertifiedDenoHandler({
    ...config(() => new Promise<Response>(() => {})),
    timeoutMilliseconds: 10,
  });
  const pending = await never(
    new Request("https://edge.example/v1/fastvote/prepare", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA },
      body: REQUEST_BYTES,
    }),
  );
  equal(pending.status, 503);
  equal(await pending.text(), "node-core-outcome-unknown");
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    cancel() {
      cancelled = true;
    },
  });
  const slow = createCertifiedDenoHandler({
    ...config(() =>
      Promise.resolve(
        new Response(stream, { headers: { "content-type": RESULT_MEDIA } }),
      )
    ),
    timeoutMilliseconds: 10,
  });
  const response = await slow(
    new Request("https://edge.example/v1/fastvote/prepare", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA },
      body: REQUEST_BYTES,
    }),
  );
  equal(response.status, 200);
  await rejects(() => response.arrayBuffer());
  equal(cancelled, true);
  equal(stream.locked, false);
});

Deno.test("certified response guards refuse malformed lengths, encoding, 204 framing and opaque status", async () => {
  const invalidHeaders: readonly Record<string, string>[] = [
    { "content-type": RESULT_MEDIA, "content-length": "00" },
    { "content-type": RESULT_MEDIA, "content-length": "-1" },
    { "content-type": RESULT_MEDIA, "content-length": "33554433" },
    { "content-type": RESULT_MEDIA, "content-encoding": "gzip" },
    { "content-type": RESULT_MEDIA + "; version=1" },
  ];
  const responses: Response[] = invalidHeaders.map((headers) =>
    new Response(RESULT_BYTES, { headers })
  );
  responses.push(Response.error());
  for (const upstream of responses) {
    const handler = createCertifiedDenoHandler(config(() => Promise.resolve(upstream)));
    const response = await handler(
      new Request("https://edge.example/v1/fastvote/prepare", {
        method: "POST",
        headers: { "content-type": EVENT_MEDIA },
        body: REQUEST_BYTES,
      }),
    );
    equal(response.status, 503);
    equal(await response.text(), "node-core-outcome-unknown");
    equal(response.headers.get("location"), null);
  }
  for (
    const headers of [
      { "content-type": RESULT_MEDIA },
      { "content-length": "1" },
      { "content-encoding": "gzip" },
    ] as readonly Record<string, string>[]
  ) {
    const handler = createCertifiedDenoHandler(
      config(() => Promise.resolve(new Response(null, { status: 204, headers }))),
    );
    const response = await handler(
      new Request("https://edge.example/v1/fastvote/frontier/advance", {
        method: "POST",
        headers: { "content-type": EVENT_MEDIA },
      }),
    );
    equal(response.status, 503);
    await response.arrayBuffer();
  }
});

Deno.test("certified unknown-length oversize and declared underflow never expose an over-budget chunk", async () => {
  for (const declared of [undefined, "4"]) {
    let cancelled = false;
    let index = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        index += 1;
        if (index === 1) controller.enqueue(new Uint8Array([1, 2]));
        else if (declared === undefined) controller.enqueue(new Uint8Array([3, 4, 5]));
        else controller.close();
      },
      cancel() {
        cancelled = true;
      },
    }, { highWaterMark: 0 });
    const handler = createCertifiedWebIngressHandler(
      config(() =>
        Promise.resolve(
          new Response(stream, {
            headers: {
              "content-type": RESULT_MEDIA,
              ...(declared === undefined ? {} : { "content-length": declared }),
            },
          }),
        )
      ),
      { maximumResponseBodyBytes: 4 },
    );
    const response = await handler(
      new Request("https://edge.example/v1/fastvote/prepare", {
        method: "POST",
        headers: { "content-type": EVENT_MEDIA },
        body: REQUEST_BYTES,
      }),
    );
    equal(response.status, 200);
    const reader = response.body!.getReader();
    deepStrictEqual((await reader.read()).value, new Uint8Array([1, 2]));
    await rejects(() => reader.read());
    reader.releaseLock();
    equal(stream.locked, false);
    if (declared === undefined) equal(cancelled, true);
  }
});

Deno.test("certified disconnect and late fetch resolution cancel their response owners", async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    cancel() {
      cancelled = true;
    },
  });
  const controller = new AbortController();
  const handler = createCertifiedDenoHandler(
    config(() =>
      Promise.resolve(
        new Response(stream, {
          headers: { "content-type": RESULT_MEDIA },
        }),
      )
    ),
  );
  const response = await handler(
    new Request("https://edge.example/v1/fastvote/prepare", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA },
      body: REQUEST_BYTES,
      signal: controller.signal,
    }),
  );
  equal(response.status, 200);
  controller.abort();
  await rejects(() => response.arrayBuffer());
  equal(cancelled, true);
  equal(stream.locked, false);

  let resolveLate: ((response: Response) => void) | undefined;
  const late = createCertifiedDenoHandler({
    ...config(() =>
      new Promise<Response>((resolve) => {
        resolveLate = resolve;
      })
    ),
    timeoutMilliseconds: 10,
  });
  const unknown = await late(
    new Request("https://edge.example/v1/fastvote/prepare", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA },
      body: REQUEST_BYTES,
    }),
  );
  equal(unknown.status, 503);
  await unknown.arrayBuffer();
  let lateCancelled = false;
  const lateBody = new ReadableStream<Uint8Array>({
    cancel() {
      lateCancelled = true;
    },
  });
  resolveLate!(new Response(lateBody, { headers: { "content-type": RESULT_MEDIA } }));
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  equal(lateCancelled, true);
  equal(lateBody.locked, false);
});

Deno.test("certified bounded request overflow and read failure do not dispatch", async () => {
  let calls = 0;
  let cancelled = false;
  const handler = createCertifiedWebIngressHandler(
    config(() => {
      calls += 1;
      return Promise.reject(new Error("must not dispatch"));
    }),
    { maximumRequestBodyBytes: 2 },
  );
  const oversized = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new Uint8Array([1, 2, 3]));
    },
    cancel() {
      cancelled = true;
    },
  }, { highWaterMark: 0 });
  const refused = await handler(
    new Request("https://edge.example/v1/fastvote/prepare", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA },
      body: oversized,
    }),
  );
  equal(refused.status, 413);
  await refused.arrayBuffer();
  equal(cancelled, true);
  equal(oversized.locked, false);
  const failed = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.error(new Error("untrusted detail"));
    },
  });
  const invalid = await handler(
    new Request("https://edge.example/v1/fastvote/prepare", {
      method: "POST",
      headers: { "content-type": EVENT_MEDIA },
      body: failed,
    }),
  );
  equal(invalid.status, 400);
  equal(await invalid.text(), "invalid-request-body");
  equal(failed.locked, false);
  equal(calls, 0);
});

Deno.test("certified secret/origin/profile and capacity config fail closed, legacy stays event-only", async () => {
  equal(configuredIngressProfile(undefined), "event-only");
  equal(configuredIngressProfile("certified-fastvote"), "certified-fastvote");
  throws(() => configuredIngressProfile("future"), TypeError);
  for (
    const nodeCoreUrl of [
      "http://node.example",
      "https://user:pass@node.example",
      "https://node.example/base",
      "https://node.example?x=1",
      "https://node.example/#x",
      "https://node.example/v1/events",
    ]
  ) {
    throws(() =>
      createCertifiedDenoHandler({
        ...config(() => Promise.reject(new Error("unreachable"))),
        nodeCoreUrl,
      }), TypeError);
  }
  for (const maximumRequestBodyBytes of [0, -1, 1.5, NaN, 33_554_433]) {
    throws(() =>
      createCertifiedDenoHandler({
        ...config(() => Promise.reject(new Error("unreachable"))),
        maximumRequestBodyBytes,
      }), TypeError);
  }
  for (const bearerToken of ["", " token ", "token\nvalue", "x".repeat(8193)]) {
    throws(() =>
      createCertifiedDenoHandler({
        ...config(() => Promise.reject(new Error("unreachable"))),
        bearerToken,
      }), TypeError);
  }
  const legacy = createDenoHandler({
    nodeCoreUrl: ROOT + "/v1/events",
    bearerToken: "test",
    fetch: () => Promise.reject(new Error("unreachable")),
  });
  const denied = await legacy(new Request("https://edge.example/v1/context"));
  equal(denied.status, 404);
  await denied.arrayBuffer();
});
