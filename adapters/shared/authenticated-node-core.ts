import { NODE_EVENT_MEDIA_TYPE, type NodeCoreFetcher } from "./web-ingress.ts";
import { resolveCertifiedRoute } from "./certified-routes.ts";

const DEFAULT_TIMEOUT_MILLISECONDS = 5_000;
const MAXIMUM_TIMEOUT_MILLISECONDS = 30_000;
const MAXIMUM_BEARER_TOKEN_BYTES = 8 * 1024;

export type WebFetch = (request: Request) => Promise<Response>;

export interface AuthenticatedNodeCoreConfig {
  readonly nodeCoreUrl: string;
  readonly bearerToken: string;
  readonly timeoutMilliseconds?: number;
  readonly fetch?: WebFetch;
}

/** Creates a bounded HTTPS/Bearer capability for the shared ingress core. */
export function createAuthenticatedNodeCoreFetcher(
  config: AuthenticatedNodeCoreConfig,
): NodeCoreFetcher {
  return new AuthenticatedNodeCoreFetcher(config);
}

/** Separate trusted capability: nodeCoreUrl is an HTTPS origin, not an event URL. */
export function createCertifiedNodeCoreFetcher(
  config: AuthenticatedNodeCoreConfig,
): NodeCoreFetcher & { readonly timeoutMilliseconds: number } {
  return new AuthenticatedNodeCoreFetcher(config, true);
}

class AuthenticatedNodeCoreFetcher implements NodeCoreFetcher {
  readonly #endpoint: URL;
  readonly #bearerToken: string;
  readonly #timeoutMilliseconds: number;
  readonly #fetch: WebFetch;
  readonly #certified: boolean;

  constructor(config: AuthenticatedNodeCoreConfig, certified = false) {
    this.#certified = certified;
    this.#endpoint = certified
      ? validateNodeCoreOrigin(config.nodeCoreUrl)
      : validateNodeCoreUrl(config.nodeCoreUrl);
    this.#bearerToken = validateBearerToken(config.bearerToken);
    this.#timeoutMilliseconds = validateTimeout(
      config.timeoutMilliseconds ?? DEFAULT_TIMEOUT_MILLISECONDS,
    );
    this.#fetch = config.fetch ?? ((request) => fetch(request));
  }

  get timeoutMilliseconds(): number {
    return this.#timeoutMilliseconds;
  }

  fetch(request: Request): Promise<Response> {
    let endpoint: URL = this.#endpoint;
    if (this.#certified) {
      const url: URL = new URL(request.url);
      const route = resolveCertifiedRoute(url.pathname);
      if (
        route === undefined || request.method !== route.method ||
        url.search !== "" || url.hash !== "" ||
        (route.method === "POST" &&
          request.headers.get("content-type") !== NODE_EVENT_MEDIA_TYPE) ||
        (route.method === "GET" &&
          (request.body !== null || request.headers.has("content-type")))
      ) {
        throw new TypeError(
          "certified ingress produced an invalid node-core request",
        );
      }
      endpoint = new URL(url.pathname, this.#endpoint);
    } else if (
      request.method !== "POST" ||
      request.headers.get("content-type") !== NODE_EVENT_MEDIA_TYPE
    ) {
      throw new TypeError(
        "shared ingress produced an invalid node-core request",
      );
    }

    const upstreamInit: RequestInit & { readonly duplex?: "half" } = {
      method: this.#certified ? request.method : "POST",
      headers: {
        "authorization": `Bearer ${this.#bearerToken}`,
        "cache-control": "no-store",
        ...(request.method === "POST"
          ? { "content-type": NODE_EVENT_MEDIA_TYPE }
          : {}),
      },
      body: request.body,
      // Undici requires half-duplex when an already-bounded Request body is
      // represented as a stream. Keep the event-only constructor unchanged.
      ...(this.#certified && request.body !== null ? { duplex: "half" } : {}),
      // Pinned workerd rejects "error". Certified ingress rejects every 3xx
      // after this no-follow request; legacy HTTPS behavior stays unchanged.
      redirect: this.#certified ? "manual" : "error",
      signal: this.#certified
        ? AbortSignal.any([
          request.signal,
          AbortSignal.timeout(this.#timeoutMilliseconds),
        ])
        : AbortSignal.timeout(this.#timeoutMilliseconds),
    };
    const upstreamRequest: Request = new Request(endpoint, upstreamInit);
    return this.#fetch(upstreamRequest);
  }
}

function validateNodeCoreOrigin(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("nodeCoreUrl must be an absolute HTTPS origin");
  }
  if (
    url.protocol !== "https:" || url.username !== "" || url.password !== "" ||
    url.pathname !== "/" || url.search !== "" || url.hash !== ""
  ) {
    throw new TypeError("certified nodeCoreUrl must be an exact HTTPS origin");
  }
  return url;
}

function validateNodeCoreUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("nodeCoreUrl must be an absolute HTTPS URL");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/v1/events" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new TypeError(
      "nodeCoreUrl must be an exact HTTPS /v1/events endpoint",
    );
  }
  return url;
}

function validateBearerToken(value: string): string {
  const bytes = new TextEncoder().encode(value);
  if (
    value.length === 0 ||
    value.trim() !== value ||
    bytes.some((byte) => byte < 0x21 || byte > 0x7e) ||
    bytes.byteLength > MAXIMUM_BEARER_TOKEN_BYTES
  ) {
    throw new TypeError("bearerToken must be a non-empty bounded ASCII token");
  }
  return value;
}

function validateTimeout(value: number): number {
  if (
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    value > MAXIMUM_TIMEOUT_MILLISECONDS
  ) {
    throw new TypeError(
      `timeoutMilliseconds must be an integer from 1 to ${MAXIMUM_TIMEOUT_MILLISECONDS}`,
    );
  }
  return value;
}
