import { DurableObject } from "cloudflare:workers";
import { DurableBlobHost } from "./blob-host";
import { DurableSqlHost } from "./sql-host";
import { authorizeValidatorRequest, decodeValidatorRequest } from "./ingress-policy";
import { initSync, ValidatorHost } from "./generated/sunrise_edge_cloudflare_validator";
import validatorModule from "./generated/sunrise_edge_cloudflare_validator_bg.wasm";

function decodeHex(value: string, maximumBytes: number): Uint8Array {
  if (value.length === 0 || value.length > maximumBytes * 2
    || !/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error("invalid validator configuration");
  const result: Uint8Array = new Uint8Array(value.length / 2);
  for (let index: number = 0; index < result.length; index += 1) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

function unavailable(): Response {
  return new Response("validator-unavailable-or-outcome-indeterminate", {
    status: 503, headers: { "cache-control": "no-store" },
  });
}

function dispatchFailure(error: unknown): Response {
  // Only the closed, non-secret categories exported by our Rust host are
  // meaningful here. Unknown/provider errors remain ambiguous 503 outcomes.
  if (error !== null && typeof error === "object" && "httpStatus" in error
    && (error.httpStatus === 400 || error.httpStatus === 404 || error.httpStatus === 409)) {
    return new Response("validator-request-rejected", {
      status: error.httpStatus, headers: { "cache-control": "no-store" },
    });
  }
  return unavailable();
}

/** Experimental certified-only host. Deployment credentials/configuration
 * bind a DO identity, not a request's URL, selector, or claimed domain.
 */
export class ValidatorObject extends DurableObject<ValidatorEnv> {
  private readonly node: ValidatorHost;

  constructor(ctx: DurableObjectState, env: ValidatorEnv) {
    super(ctx, env);
    if (typeof env.VALIDATOR_ACTOR_NAME !== "string" || env.VALIDATOR_ACTOR_NAME.length === 0
      || env.VALIDATOR_ACTOR_NAME === "unconfigured" || env.VALIDATOR_ACTOR_NAME.length > 256
      || !ctx.id.equals(env.VALIDATOR_STATE.idFromName(env.VALIDATOR_ACTOR_NAME))) {
      throw new Error("validator actor placement is not configured");
    }
    // The generated WASM module cache is executable code, not protocol state.
    // Each node owns its host receivers, signer and pinned namespace.
    initSync({ module: validatorModule });
    const config: Uint8Array = decodeHex(env.VALIDATOR_CONFIG, 65_536);
    const genesis: Uint8Array = decodeHex(env.VALIDATOR_GENESIS, 1_800_000);
    this.node = new ValidatorHost(config, new DurableSqlHost(ctx.storage), new DurableBlobHost(ctx.storage));
    try {
      this.node.installGenesis(genesis);
    } catch (error: unknown) {
      this.node.free();
      throw error;
    }
  }

  async fetch(request: Request): Promise<Response> {
    if (!(await authorizeValidatorRequest(request, this.env.VALIDATOR_BEARER_TOKEN))) {
      return new Response("unauthorized", { status: 401, headers: { "cache-control": "no-store" } });
    }
    const decoded = await decodeValidatorRequest(request);
    if (decoded instanceof Response) return decoded;
    let bytes: Uint8Array;
    try {
      bytes = this.node.dispatch(decoded.path, decoded.body);
    } catch (error: unknown) {
      return dispatchFailure(error);
    }
    try {
      // A synchronous transaction result is provisional until the host confirms
      // storage. Never release a signed vote/result after failed confirmation.
      await this.ctx.storage.sync();
      const responseBytes: Uint8Array<ArrayBuffer> = new Uint8Array(bytes.byteLength);
      responseBytes.set(bytes);
      return new Response(responseBytes, { headers: {
        "cache-control": "no-store",
        "content-length": responseBytes.byteLength.toString(),
        "content-type": decoded.path === "/v1/fastvote/prepare"
          || decoded.path === "/v1/fastvote/certificates"
          ? "application/vnd.sunrise-edge.node-result"
          : "application/vnd.sunrise-edge.query-result",
      } });
    } catch {
      // Keep keys, intent bodies and provider exceptions out of logs/responses.
      // Dispatch has already returned: even an adapter-shaped provider throw
      // cannot now be classified as a definite protocol rejection.
      return unavailable();
    }
  }
}

export default {
  async fetch(request: Request, env: ValidatorEnv): Promise<Response> {
    const url: URL = new URL(request.url);
    if (url.pathname === "/health/live" && request.method === "GET" && url.search === "") {
      return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
    }
    if (!(await authorizeValidatorRequest(request, env.VALIDATOR_BEARER_TOKEN))) {
      return new Response("unauthorized", { status: 401, headers: { "cache-control": "no-store" } });
    }
    const decoded = await decodeValidatorRequest(request);
    if (decoded instanceof Response) return decoded;
    if (typeof env.VALIDATOR_ACTOR_NAME !== "string" || env.VALIDATOR_ACTOR_NAME.length === 0
      || env.VALIDATOR_ACTOR_NAME === "unconfigured" || env.VALIDATOR_ACTOR_NAME.length > 256) return unavailable();
    try {
      const stub = env.VALIDATOR_STATE.getByName(env.VALIDATOR_ACTOR_NAME);
      const forwarded: Request = new Request(request.url, {
        method: request.method,
        headers: request.headers,
        ...(request.method === "POST" ? { body: new Uint8Array(decoded.body) } : {}),
      });
      return await stub.fetch(forwarded);
    } catch {
      return unavailable();
    }
  },
} satisfies ExportedHandler<ValidatorEnv>;
