import {
  type AuthenticatedNodeCoreConfig,
  createCertifiedNodeCoreFetcher,
} from "./authenticated-node-core.ts";
import {
  type CertifiedRoute,
  DEFAULT_CERTIFIED_REQUEST_BODY_BYTES,
  isCertifiedRefusalStatus,
  MAX_CERTIFIED_BODY_BYTES,
  MAX_CERTIFIED_REFUSAL_BODY_BYTES,
  resolveCertifiedRoute,
} from "./certified-routes.ts";
import {
  IngressError,
  LIVENESS_PATH,
  NODE_EVENT_MEDIA_TYPE,
  readBoundedBody,
  validateEventRequestHeaders,
} from "./web-ingress.ts";

export interface CertifiedIngressOptions {
  readonly maximumRequestBodyBytes?: number;
  readonly maximumResponseBodyBytes?: number;
}

/** Environment-owned selection; this value is never read from an HTTP request. */
export function configuredIngressProfile(
  value: string | undefined,
): "event-only" | "certified-fastvote" {
  if (value === undefined || value === "event-only") return "event-only";
  if (value === "certified-fastvote") return value;
  throw new TypeError(
    "SUNRISE_INGRESS_PROFILE must be event-only or certified-fastvote",
  );
}

/**
 * Builds a closed HTTPS/Bearer relay. Configuration selects this capability;
 * neither a requester nor the event-only constructors can enable the profile.
 * Core still authenticates and commits; this handler does not decode authority.
 */
export function createCertifiedWebIngressHandler(
  config: AuthenticatedNodeCoreConfig,
  options: CertifiedIngressOptions = {},
): (request: Request) => Promise<Response> {
  const nodeCore = createCertifiedNodeCoreFetcher(config);
  const requestCeiling = validateCeiling(
    options.maximumRequestBodyBytes ?? DEFAULT_CERTIFIED_REQUEST_BODY_BYTES,
    "maximumRequestBodyBytes",
  );
  const responseCeiling = validateCeiling(
    options.maximumResponseBodyBytes ?? MAX_CERTIFIED_BODY_BYTES,
    "maximumResponseBodyBytes",
  );

  return async (request: Request): Promise<Response> => {
    const url: URL = new URL(request.url);
    if (url.search !== "" || url.hash !== "") {
      return refusal(400, "query-or-fragment-not-supported");
    }
    const localHealth = url.pathname === LIVENESS_PATH;
    const route = localHealth ? undefined : resolveCertifiedRoute(url.pathname);
    if (!localHealth && route === undefined) return refusal(404, "not-found");
    const method = localHealth ? "GET" : route!.method;
    if (request.method !== method) {
      const response = refusal(405, "method-not-allowed");
      response.headers.set("allow", method);
      return response;
    }

    let body: Uint8Array<ArrayBuffer> | undefined;
    try {
      if (method === "GET") {
        validateBodylessRequest(request);
      } else {
        const maximumBytes = Math.min(
          requestCeiling,
          route!.maximumRequestBytes,
        );
        validateEventRequestHeaders(request.headers, maximumBytes);
        body = route!.requiresEmptyBody && request.body === null
          ? new Uint8Array(0)
          : await readBoundedBody(request.body, maximumBytes);
        if (route!.requiresEmptyBody && body.byteLength !== 0) {
          throw new IngressError(400, "body-not-empty");
        }
        const declared = declaredLength(request.headers);
        if (declared !== null && declared !== body.byteLength) {
          throw new IngressError(400, "content-length-mismatch");
        }
      }
      if (request.signal.aborted) {
        throw new IngressError(400, "request-aborted");
      }
    } catch (error) {
      return error instanceof IngressError
        ? refusal(error.status, error.code)
        : refusal(400, "invalid-request-body");
    }
    if (localHealth) {
      return new Response(null, { status: 204, headers: noStore() });
    }

    // The budget starts after the incoming body is bounded. It covers dispatch
    // and the complete upstream response, including error-body consumption.
    const signal: AbortSignal = AbortSignal.any([
      request.signal,
      AbortSignal.timeout(nodeCore.timeoutMilliseconds),
    ]);
    const downstreamRequest = new Request(
      `https://node-core.internal${url.pathname}`,
      {
        method,
        headers: {
          "cache-control": "no-store",
          ...(method === "POST"
            ? { "content-type": NODE_EVENT_MEDIA_TYPE }
            : {}),
        },
        ...(body === undefined ? {} : { body }),
        signal,
      },
    );
    try {
      const fetched: Promise<Response> = nodeCore.fetch(downstreamRequest).then(
        async (response): Promise<Response> => {
          // A custom transport might resolve after cancellation. Dispose of
          // that late body too; never leave a second live response owner.
          if (signal.aborted) {
            await discardResponse(response, signal);
            throw new Error("node-core response interrupted");
          }
          return response;
        },
      );
      const downstream: Response = await withAbort(fetched, signal);
      return await acceptResponse(downstream, route!, responseCeiling, signal);
    } catch {
      // Dispatch has been attempted: even a timeout/invalid response is not
      // evidence that the signed operation or retention failed to commit.
      return refusal(
        503,
        method === "POST"
          ? "node-core-outcome-unknown"
          : "node-core-unavailable",
      );
    }
  };
}

function validateCeiling(value: number, name: string): number {
  if (
    !Number.isSafeInteger(value) || value <= 0 ||
    value > MAX_CERTIFIED_BODY_BYTES
  ) {
    throw new TypeError(
      `${name} must be an integer from 1 to ${MAX_CERTIFIED_BODY_BYTES}`,
    );
  }
  return value;
}

function validateBodylessRequest(request: Request): void {
  const length = request.headers.get("content-length");
  if (
    request.body !== null || request.headers.has("content-type") ||
    request.headers.has("transfer-encoding") ||
    (length !== null && length !== "0")
  ) {
    throw new IngressError(400, "bodyless-request-required");
  }
  const encoding = request.headers.get("content-encoding");
  if (encoding !== null && encoding.trim().toLowerCase() !== "identity") {
    throw new IngressError(415, "unsupported-content-encoding");
  }
}

function declaredLength(headers: Headers): number | null {
  const length = headers.get("content-length");
  if (length === null) return null;
  if (
    !/^(0|[1-9][0-9]*)$/.test(length) ||
    BigInt(length) > BigInt(MAX_CERTIFIED_BODY_BYTES)
  ) {
    throw new TypeError("invalid bounded content length");
  }
  return Number(length);
}

async function acceptResponse(
  response: Response,
  route: CertifiedRoute,
  providerCeiling: number,
  signal: AbortSignal,
): Promise<Response> {
  const status = response.status;
  try {
    signal.throwIfAborted();
    const length = declaredLength(response.headers);
    const encoding = response.headers.get("content-encoding");
    if (encoding !== null && encoding !== "identity") {
      throw new TypeError("encoded node-core response");
    }
    if (status === 204 && route.success !== "result") {
      if (
        response.body !== null || response.headers.has("content-type") ||
        (length !== null && length !== 0)
      ) {
        throw new TypeError("invalid empty node-core response");
      }
      return new Response(null, { status: 204, headers: noStore() });
    }
    const success = status === 200 && route.success !== "empty";
    const refusalStatus = isCertifiedRefusalStatus(status);
    if (!success && !refusalStatus) {
      throw new TypeError("unexpected node-core status");
    }
    const media = success
      ? route.responseMediaType
      : "text/plain; charset=utf-8";
    if (response.headers.get("content-type") !== media) {
      throw new TypeError("unexpected node-core media");
    }
    const ceiling = success
      ? Math.min(providerCeiling, route.maximumResponseBytes)
      : Math.min(providerCeiling, MAX_CERTIFIED_REFUSAL_BODY_BYTES);
    if (length !== null && length > ceiling) {
      throw new TypeError("node-core response too large");
    }
    const guarded = boundedResponseBody(response.body, ceiling, length, signal);
    // Refusals are completely checked before exposing a definite HTTP status.
    // Successes remain pull-driven; a late failure errors that stream instead
    // of inventing a rollback, replacement receipt or automatic resubmission.
    const body = success ? guarded : await new Response(guarded).arrayBuffer();
    return new Response(body, {
      status,
      headers: { "cache-control": "no-store", "content-type": media },
    });
  } catch (error) {
    await discardResponse(response, signal);
    throw error;
  }
}

function boundedResponseBody(
  body: ReadableStream<Uint8Array> | null,
  maximumBytes: number,
  declaredBytes: number | null,
  signal: AbortSignal,
): ReadableStream<Uint8Array> | null {
  if (body === null) {
    if (declaredBytes !== null && declaredBytes !== 0) {
      throw new TypeError("missing node-core body");
    }
    return null;
  }
  const reader = body.getReader();
  const ceiling = Math.min(maximumBytes, declaredBytes ?? maximumBytes);
  let total = 0;
  let finalized: Promise<void> | undefined;
  let onAbort: (() => void) | undefined;
  function finalize(cancel: boolean): Promise<void> {
    finalized ??= (async (): Promise<void> => {
      if (onAbort !== undefined) signal.removeEventListener("abort", onAbort);
      try {
        if (cancel) {
          await withAbort(reader.cancel("node-core stream stopped"), signal);
        }
      } catch {
        // Cancelling must not expose upstream messages or extend the budget.
      } finally {
        reader.releaseLock();
      }
    })();
    return finalized;
  }
  return new ReadableStream<Uint8Array>({
    start(controller) {
      onAbort = (): void => {
        controller.error(new Error("node-core response interrupted"));
        // This only cancels/releases ownership; it never pumps response bytes.
        void finalize(true).catch(() => {});
      };
      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) onAbort();
    },
    async pull(controller): Promise<void> {
      try {
        const item = await withAbort(reader.read(), signal);
        if (item.done) {
          if (declaredBytes !== null && total !== declaredBytes) {
            throw new TypeError("node-core length mismatch");
          }
          await finalize(false);
          controller.close();
        } else {
          if (item.value.byteLength > ceiling - total) {
            throw new TypeError("node-core body too large");
          }
          total += item.value.byteLength;
          controller.enqueue(item.value);
        }
      } catch {
        await finalize(true);
        controller.error(new Error("node-core response stream failed"));
      }
    },
    async cancel(): Promise<void> {
      await finalize(true);
    },
  }, { highWaterMark: 0 });
}

function withAbort<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => {
      signal.removeEventListener("abort", onAbort);
      reject(new Error("node-core response interrupted"));
    };
    if (signal.aborted) {
      // Attach rejection handling even when the operation raced an early abort.
      void operation.catch(() => {});
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
    void operation.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      () => {
        signal.removeEventListener("abort", onAbort);
        reject(new Error("node-core transport failed"));
      },
    );
  });
}

async function discardResponse(
  response: Response,
  signal: AbortSignal,
): Promise<void> {
  if (response.body === null || response.body.locked) return;
  try {
    await withAbort(response.body.cancel("invalid node-core response"), signal);
  } catch {
    // The existing timeout also bounds cleanup of a failed upstream response.
  }
}

function noStore(): HeadersInit {
  return { "cache-control": "no-store" };
}

function refusal(status: number, code: string): Response {
  return new Response(code, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "text/plain; charset=utf-8",
    },
  });
}
