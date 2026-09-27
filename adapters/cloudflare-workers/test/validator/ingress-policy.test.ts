import { describe, expect, it } from "vitest";
import { authorizeValidatorRequest, decodeValidatorRequest, VALIDATOR_BODY_LIMIT } from "../../src/validator/ingress-policy";

describe("certified-only DO ingress", () => {
  it("requires exact bounded bearer access independently of transaction signing", async () => {
    const token: string = "public-synthetic-test-token";
    expect(await authorizeValidatorRequest(new Request("https://edge.example", {
      headers: { authorization: `Bearer ${token}` },
    }), token)).toBe(true);
    expect(await authorizeValidatorRequest(new Request("https://edge.example", {
      headers: { authorization: `Bearer ${token}x` },
    }), token)).toBe(false);
    expect(await authorizeValidatorRequest(new Request("https://edge.example"), "")).toBe(false);
    expect(await authorizeValidatorRequest(new Request("https://edge.example"), undefined)).toBe(false);
    expect(await authorizeValidatorRequest(new Request("https://edge.example"), "bad token with spaces")).toBe(false);
  });

  it("never exposes direct, legacy or arbitrary mutating families", async () => {
    for (const path of ["/v1/events", "/v1/publications", "/v1/execution", "/v1/paid-execution"]) {
      const result = await decodeValidatorRequest(new Request(`https://edge.example${path}`, { method: "POST" }));
      expect(result).toBeInstanceOf(Response);
      if (!(result instanceof Response)) throw new Error("route exposed");
      expect(result.status).toBe(404);
    }
  });

  it("closes media, methods, selector and length boundaries before Rust dispatch", async () => {
    const cases: Array<[Request, number]> = [
      [new Request("https://edge.example/v1/fastvote/prepare"), 405],
      [new Request("https://edge.example/v1/context?domain=attacker"), 400],
      [new Request("https://edge.example/v1/objects/invalid"), 404],
      [new Request("https://edge.example/v1/fastvote/prepare", { method: "POST", headers: { "content-type": "application/json" } }), 415],
      [new Request("https://edge.example/v1/fastvote/prepare", { method: "POST", headers: {
        "content-type": "application/vnd.sunrise-edge.node-event", "content-length": `${VALIDATOR_BODY_LIMIT + 1}`,
      } }), 413],
      [new Request("https://edge.example/v1/fastvote/prepare", { method: "POST", body: new Uint8Array([1]), headers: {
        "content-type": "application/vnd.sunrise-edge.node-event", "content-length": "2",
      } }), 400],
    ];
    for (const [request, status] of cases) {
      const result = await decodeValidatorRequest(request);
      if (!(result instanceof Response)) throw new Error("invalid request admitted");
      expect(result.status).toBe(status);
    }
  });

  it("keeps ordinary CLI read selectors while refusing alternate body-query routes", async () => {
    for (const path of ["/v1/context", "/v1/contracts/paid-fee-policy",
      `/v1/contracts/publications/${"11".repeat(32)}/${"22".repeat(32)}`,
      `/v1/contracts/instances/${"11".repeat(32)}/${"22".repeat(32)}`]) {
      const result = await decodeValidatorRequest(new Request(`https://edge.example${path}`));
      expect(result).toEqual({ path, body: new Uint8Array() });
    }
    expect(await decodeValidatorRequest(new Request("https://edge.example/v1/query/object", {
      method: "POST", body: new Uint8Array(32),
    }))).toMatchObject({ status: 404 });
  });

  it("accepts only the bounded canonical certified frame carrier", async () => {
    const result = await decodeValidatorRequest(new Request("https://edge.example/v1/fastvote/prepare", {
      method: "POST", body: new Uint8Array([1, 2]),
      headers: { "content-type": "application/vnd.sunrise-edge.node-event" },
    }));
    if (result instanceof Response) throw new Error("valid carrier rejected");
    expect(result.body).toEqual(new Uint8Array([1, 2]));
  });
});
