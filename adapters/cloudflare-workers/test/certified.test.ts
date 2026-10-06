import { describe, expect, it } from "vitest";
import { createCertifiedNodeCoreFetcher } from "../../shared/authenticated-node-core";
import rawContract from "../../shared/certified-route-contract.tsv?raw";
import {
  type CertifiedRouteFixture,
  fixturePath,
  parseCertifiedRouteFixtures,
} from "../../shared/test-support/certified-fixtures";
import certifiedWorker, {
  createCertifiedCloudflareHandler,
  MAX_CERTIFIED_WORKER_REQUEST_BYTES,
} from "../src/certified";

const fixtures = parseCertifiedRouteFixtures(rawContract);
const testEnv: CertifiedRelayEnv = {
  SUNRISE_NODE_CORE_URL: "https://certified-host.invalid",
  SUNRISE_NODE_CORE_BEARER_TOKEN: "test-certified-relay",
};
const EVENT_MEDIA = "application/vnd.sunrise-edge.node-event";
const RESULT_BYTES = new Uint8Array([9, 8, 7]);

function requestFor(fixture: CertifiedRouteFixture): Request {
  return new Request(`https://edge.example${fixturePath(fixture)}`, {
    method: fixture.method,
    headers: {
      authorization: "Bearer caller-must-not-forward",
      cookie: "caller-cookie",
      forwarded: "for=attacker",
      "x-forwarded-for": "attacker",
      ...(fixture.method === "POST" ? { "content-type": EVENT_MEDIA } : {}),
    },
    ...(fixture.method === "GET" ? {} : {
      body: fixture.emptyRequest ? new Uint8Array(0) : new Uint8Array([1]),
    }),
  });
}

describe("separate certified HTTPS Worker, entirely local outbound fixture", () => {
  it("uses the local outbound fixture without real upstream access", async () => {
    const response = await fetch("https://certified-host.invalid/v1/context", {
      headers: { authorization: "Bearer test-certified-relay" },
    });
    expect(response.status).toBe(200);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(RESULT_BYTES);
  });

  it("constructs the configured transport Request in the actual Worker runtime", async () => {
    const capability = createCertifiedNodeCoreFetcher({
      nodeCoreUrl: testEnv.SUNRISE_NODE_CORE_URL,
      bearerToken: testEnv.SUNRISE_NODE_CORE_BEARER_TOKEN,
    });
    const response = await capability.fetch(
      new Request("https://ignored.invalid/v1/context"),
    );
    expect(response.status).toBe(200);
    await response.arrayBuffer();
  });

  it.each(fixtures)(
    "forwards the literal $method $path through workerd",
    async (fixture) => {
      const response = await certifiedWorker.fetch(
        requestFor(fixture),
        testEnv,
      );
      const empty = fixture.success !== "result";
      expect(response.status).toBe(empty ? 204 : 200);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("set-cookie")).toBeNull();
      expect(response.headers.get("content-length")).toBeNull();
      if (empty) {
        expect(response.body).toBeNull();
        expect(response.headers.get("content-type")).toBeNull();
      } else {
        expect(response.headers.get("content-type")).toBe(
          fixture.method === "POST"
            ? "application/vnd.sunrise-edge.node-result"
            : "application/vnd.sunrise-edge.query-result",
        );
        expect(new Uint8Array(await response.arrayBuffer())).toEqual(
          RESULT_BYTES,
        );
      }
    },
  );

  it("actually rejects redirects in workerd rather than just checking Request.redirect", async () => {
    const response = await certifiedWorker.fetch(
      new Request(
        "https://edge.example/v1/fastvote/prepare",
        {
          method: "POST",
          headers: { "content-type": EVENT_MEDIA },
          body: new Uint8Array([0xfc]),
        },
      ),
      testEnv,
    );
    expect(response.status).toBe(503);
    expect(await response.text()).toBe("node-core-outcome-unknown");
  });

  it("keeps local health, direct mutations and oversize outside dispatch", async () => {
    let calls = 0;
    const handler = createCertifiedCloudflareHandler(testEnv, () => {
      calls += 1;
      return Promise.reject(new Error("must not dispatch"));
    });
    expect(
      (await handler(new Request("https://edge.example/health/live"))).status,
    ).toBe(204);
    for (
      const path of [
        "/v1/events",
        "/v1/contracts/publications",
        "/v1/contracts/executions",
        "/v1/contracts/paid-executions",
        "/v1/unlisted",
      ]
    ) {
      const response = await handler(
        new Request("https://edge.example" + path, {
          method: "POST",
          headers: { "content-type": EVENT_MEDIA },
          body: new Uint8Array([1]),
        }),
      );
      expect(response.status).toBe(404);
      await response.arrayBuffer();
    }
    const oversize = await handler(
      new Request(
        "https://edge.example/v1/fastvote/publications/retain",
        {
          method: "POST",
          headers: {
            "content-type": EVENT_MEDIA,
            "content-length": String(MAX_CERTIFIED_WORKER_REQUEST_BYTES + 1),
          },
          body: new Uint8Array([1]),
        },
      ),
    );
    expect(oversize.status).toBe(413);
    await oversize.arrayBuffer();
    expect(calls).toBe(0);
  });

  it("preserves pull backpressure and releases upstream ownership on downstream cancel", async () => {
    let pulls = 0;
    let cancelled = false;
    const upstream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        controller.enqueue(RESULT_BYTES);
      },
      cancel() {
        cancelled = true;
      },
    }, { highWaterMark: 0 });
    const handler = createCertifiedCloudflareHandler(
      testEnv,
      () =>
        Promise.resolve(
          new Response(upstream, {
            headers: {
              "content-type": "application/vnd.sunrise-edge.node-result",
            },
          }),
        ),
    );
    const response = await handler(
      new Request("https://edge.example/v1/fastvote/prepare", {
        method: "POST",
        headers: { "content-type": EVENT_MEDIA },
        body: new Uint8Array([1]),
      }),
    );
    expect(response.status).toBe(200);
    expect(pulls).toBe(0);
    const reader = response.body!.getReader();
    expect((await reader.read()).value).toEqual(RESULT_BYTES);
    expect(pulls).toBe(1);
    await reader.cancel();
    reader.releaseLock();
    expect(cancelled).toBe(true);
    expect(upstream.locked).toBe(false);
  });

  it("fails a late oversized result stream without exposing its over-budget chunk", async () => {
    let cancelled = false;
    let pulls = 0;
    const upstream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        controller.enqueue(new Uint8Array(pulls === 1 ? 4096 : 1));
      },
      cancel() {
        cancelled = true;
      },
    }, { highWaterMark: 0 });
    const handler = createCertifiedCloudflareHandler(
      testEnv,
      () =>
        Promise.resolve(
          new Response(upstream, {
            headers: {
              "content-type": "application/vnd.sunrise-edge.node-result",
            },
          }),
        ),
    );
    const response = await handler(
      new Request("https://edge.example/v1/fastvote/prepare", {
        method: "POST",
        headers: { "content-type": EVENT_MEDIA },
        body: new Uint8Array([1]),
      }),
    );
    expect(response.status).toBe(200);
    const reader = response.body!.getReader();
    expect((await reader.read()).value?.byteLength).toBe(4096);
    await expect(reader.read()).rejects.toThrow(
      "node-core response stream failed",
    );
    reader.releaseLock();
    expect(cancelled).toBe(true);
    expect(upstream.locked).toBe(false);
  });

  it("propagates caller abort to response cancellation in workerd", async () => {
    let cancelled = false;
    const upstream = new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true;
      },
    });
    const handler = createCertifiedCloudflareHandler(
      testEnv,
      () =>
        Promise.resolve(
          new Response(upstream, {
            headers: {
              "content-type": "application/vnd.sunrise-edge.node-result",
            },
          }),
        ),
    );
    const controller = new AbortController();
    const response = await handler(
      new Request("https://edge.example/v1/fastvote/prepare", {
        method: "POST",
        headers: { "content-type": EVENT_MEDIA },
        body: new Uint8Array([1]),
        signal: controller.signal,
      }),
    );
    expect(response.status).toBe(200);
    controller.abort();
    await expect(response.arrayBuffer()).rejects.toThrow();
    expect(cancelled).toBe(true);
    expect(upstream.locked).toBe(false);
  });
});
