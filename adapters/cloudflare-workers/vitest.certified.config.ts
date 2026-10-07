import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { Request as LocalRequest, Response as LocalResponse } from "miniflare";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { include: ["test/certified.test.ts"] },
  plugins: [cloudflareTest({
    wrangler: { configPath: "./wrangler.certified.jsonc" },
    miniflare: {
      // Test runner support only; the production relay needs no Node APIs.
      compatibilityFlags: ["nodejs_compat", "enable_request_signal"],
      bindings: { SUNRISE_NODE_CORE_BEARER_TOKEN: "test-certified-relay" },
      // Intercept ALL outbound traffic locally. No DNS, provider account,
      // production secret or upstream network is used by this fixture.
      outboundService: async (
        request: LocalRequest,
      ): Promise<LocalResponse> => {
        const url: URL = new URL(request.url);
        if (url.origin === "https://redirect-target.invalid") {
          // Following a redirect would falsely produce success in the test.
          return new LocalResponse(new Uint8Array([99]), {
            headers: {
              "content-type": "application/vnd.sunrise-edge.node-result",
            },
          });
        }
        if (
          url.origin !== "https://certified-host.invalid" ||
          request.headers.get("authorization") !==
            "Bearer test-certified-relay" ||
          request.headers.has("cookie") || request.headers.has("forwarded") ||
          request.headers.has("x-forwarded-for")
        ) {
          return new LocalResponse("unexpected-local-request", {
            status: 403,
            headers: { "content-type": "text/plain; charset=utf-8" },
          });
        }
        const bytes: Uint8Array = new Uint8Array(await request.arrayBuffer());
        if (bytes[0] === 0xfc) {
          return new LocalResponse(null, {
            status: 302,
            headers: {
              location: "https://redirect-target.invalid/v1/fastvote/prepare",
            },
          });
        }
        if (
          [
            "/v1/fastvote/drain/signer-page",
            "/v1/fastvote/drain/member-confirm",
            "/v1/fastvote/frontier/advance",
            "/v1/fastvote/drain/union-advance",
          ].includes(url.pathname)
        ) {
          return new LocalResponse(null, { status: 204 });
        }
        return new LocalResponse(new Uint8Array([9, 8, 7]), {
          headers: {
            "content-type": request.method === "GET"
              ? "application/vnd.sunrise-edge.query-result"
              : "application/vnd.sunrise-edge.node-result",
            "content-length": "3",
            "set-cookie": "must-not-leak=1",
          },
        });
      },
    },
  })],
});
