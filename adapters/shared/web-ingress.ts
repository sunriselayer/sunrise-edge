export const NODE_EVENT_PATH = "/v1/events";
export const LIVENESS_PATH = "/health/live";
export const NODE_EVENT_MEDIA_TYPE = "application/vnd.sunrise-edge.node-event";
export const NODE_RESULT_MEDIA_TYPE =
  "application/vnd.sunrise-edge.node-result";
export const MAX_HTTP_EVENT_BODY_BYTES = 16 * 1024 * 1024 + 512;
export const MAX_HTTP_BODY_IDLE_MILLIS = 30_000;
export const MAX_HTTP_BODY_TOTAL_MILLIS = 120_000;

const NODE_CORE_URL = "https://node-core.internal/v1/events";

/** Minimum fetch capability required from a provider-specific node-core binding. */
export interface NodeCoreFetcher {
  fetch(request: Request): Promise<Response>;
}

export interface WebIngressOptions {
  /** A provider capacity limit that may narrow, but never raise, the protocol limit. */
  readonly maximumRequestBodyBytes?: number;
}

export interface BodyReadOptions {
  readonly signal?: AbortSignal;
  readonly idleTimeoutMilliseconds?: number;
  readonly totalTimeoutMilliseconds?: number;
}

/** A pre-dispatch framing refusal; never evidence of an upstream outcome. */
export class IngressError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(
    status: number,
    code: string,
  ) {
    super(code);
    this.status = status;
    this.code = code;
    this.name = "IngressError";
  }
}

/** Handles the shared Web Fetch API ingress contract for one provider binding. */
export async function handleWebRequest(
  request: Request,
  nodeCore: NodeCoreFetcher,
  options: WebIngressOptions = {},
): Promise<Response> {
  const maximumRequestBodyBytes = validateMaximumRequestBodyBytes(
    options.maximumRequestBodyBytes ?? MAX_HTTP_EVENT_BODY_BYTES,
  );
  const url = new URL(request.url);

  if (url.pathname === LIVENESS_PATH) {
    if (request.method !== "GET") {
      return methodNotAllowed("GET");
    }
    return new Response(null, {
      status: 204,
      headers: { "cache-control": "no-store" },
    });
  }
  if (url.pathname !== NODE_EVENT_PATH) {
    return errorResponse(404, "not-found");
  }
  if (request.method !== "POST") {
    return methodNotAllowed("POST");
  }

  try {
    validateEventRequestHeaders(request.headers, maximumRequestBodyBytes);
    const body = await readBoundedBody(
      request.body,
      maximumRequestBodyBytes,
      { signal: request.signal },
    );
    if (request.signal.aborted) {
      throw new IngressError(400, "request-aborted");
    }
    const downstreamRequest = new Request(NODE_CORE_URL, {
      method: "POST",
      headers: {
        "cache-control": "no-store",
        "content-type": NODE_EVENT_MEDIA_TYPE,
      },
      body,
    });
    const downstream = await nodeCore.fetch(downstreamRequest);
    if (downstream.status === 500) {
      await downstream.body?.cancel("node-core invocation failed");
      console.error(
        JSON.stringify({
          message: "node core returned an internal failure",
          method: request.method,
          path: url.pathname,
          status: downstream.status,
        }),
      );
      return errorResponse(502, "node-core-failure");
    }
    if (
      downstream.ok &&
      !hasExactMediaType(downstream.headers, NODE_RESULT_MEDIA_TYPE)
    ) {
      await downstream.body?.cancel("invalid node-core content type");
      return errorResponse(502, "invalid-node-core-response");
    }
    if (
      !downstream.ok &&
      downstream.headers.get("content-type") !== "text/plain; charset=utf-8"
    ) {
      await downstream.body?.cancel("invalid node-core error content type");
      return errorResponse(502, "invalid-node-core-response");
    }
    return sanitizeDownstreamResponse(downstream);
  } catch (error) {
    if (error instanceof IngressError) {
      return errorResponse(error.status, error.code);
    }
    console.error(
      JSON.stringify({
        message: "node core provider binding failed",
        method: request.method,
        path: url.pathname,
        error_kind: error instanceof Error ? error.name : "unknown",
      }),
    );
    return errorResponse(503, "node-core-unavailable");
  }
}

/** Reads at most `maximumBytes` from an incoming Web byte stream. */
export async function readBoundedBody(
  body: ReadableStream<Uint8Array> | null,
  maximumBytes: number,
  options: BodyReadOptions = {},
): Promise<Uint8Array<ArrayBuffer>> {
  if (body === null) {
    throw new IngressError(400, "missing-body");
  }
  const idleTimeoutMilliseconds = validateBodyReadTimeout(
    options.idleTimeoutMilliseconds ?? MAX_HTTP_BODY_IDLE_MILLIS,
    MAX_HTTP_BODY_IDLE_MILLIS,
  );
  const totalTimeoutMilliseconds = validateBodyReadTimeout(
    options.totalTimeoutMilliseconds ?? MAX_HTTP_BODY_TOTAL_MILLIS,
    MAX_HTTP_BODY_TOTAL_MILLIS,
  );
  const totalDeadline: number = performance.now() + totalTimeoutMilliseconds;
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  const interruption = (): IngressError =>
    options.signal?.aborted
      ? new IngressError(400, "request-aborted")
      : new IngressError(408, "request-body-timeout");
  try {
    while (true) {
      const remaining: number = totalDeadline - performance.now();
      if (remaining <= 0 || options.signal?.aborted) throw interruption();
      const result = await withBodyReadDeadline(
        reader.read(),
        Math.min(remaining, idleTimeoutMilliseconds),
        options.signal,
        interruption,
      );
      if (result.done) {
        break;
      }
      if (result.value.byteLength > maximumBytes - total) {
        throw new IngressError(413, "body-too-large");
      }
      chunks.push(result.value);
      total += result.value.byteLength;
    }
    if (performance.now() >= totalDeadline || options.signal?.aborted) {
      throw interruption();
    }
  } catch (error) {
    // A custom stream can keep its cancel promise pending. The admission
    // deadline must still end this invocation without waiting for that promise.
    try {
      void reader.cancel("request body admission stopped").catch(() => {});
    } catch {
      // Preserve the original admission failure.
    }
    throw error;
  } finally {
    reader.releaseLock();
  }

  const output: Uint8Array<ArrayBuffer> = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function validateBodyReadTimeout(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new TypeError(
      `body read timeout must be an integer from 1 to ${maximum}`,
    );
  }
  return value;
}

function withBodyReadDeadline<T>(
  operation: Promise<T>,
  timeoutMilliseconds: number,
  requestSignal: AbortSignal | undefined,
  interruption: () => IngressError,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const cleanup = (): void => {
      clearTimeout(timer);
      requestSignal?.removeEventListener("abort", onAbort);
    };
    const onAbort = (): void => {
      cleanup();
      reject(interruption());
    };
    const timer: ReturnType<typeof setTimeout> = setTimeout(
      onAbort,
      timeoutMilliseconds,
    );
    if (requestSignal?.aborted) {
      void operation.catch(() => {});
      onAbort();
      return;
    }
    requestSignal?.addEventListener("abort", onAbort, { once: true });
    void operation.then(
      (value: T) => {
        cleanup();
        resolve(value);
      },
      (error: unknown) => {
        cleanup();
        reject(error instanceof Error ? error : new Error("body read failed"));
      },
    );
  });
}

function validateMaximumRequestBodyBytes(value: number): number {
  if (
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    value > MAX_HTTP_EVENT_BODY_BYTES
  ) {
    throw new TypeError(
      `maximumRequestBodyBytes must be an integer from 1 to ${MAX_HTTP_EVENT_BODY_BYTES}`,
    );
  }
  return value;
}

/** Shared exact event media, encoding and canonical declared-length rules. */
export function validateEventRequestHeaders(
  headers: Headers,
  maximumRequestBodyBytes: number,
): void {
  if (!hasExactMediaType(headers, NODE_EVENT_MEDIA_TYPE)) {
    throw new IngressError(415, "unsupported-content-type");
  }
  const contentEncoding = headers.get("content-encoding");
  if (
    contentEncoding !== null &&
    contentEncoding.trim().toLowerCase() !== "identity"
  ) {
    throw new IngressError(415, "unsupported-content-encoding");
  }
  const contentLength = headers.get("content-length")?.trim() ?? null;
  if (contentLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(contentLength)) {
      throw new IngressError(400, "invalid-content-length");
    }
    if (BigInt(contentLength) > BigInt(maximumRequestBodyBytes)) {
      throw new IngressError(413, "body-too-large");
    }
  }
}

function hasExactMediaType(headers: Headers, expected: string): boolean {
  return headers.get("content-type")?.trim().toLowerCase() === expected;
}

function sanitizeDownstreamResponse(response: Response): Response {
  const headers = new Headers({ "cache-control": "no-store" });
  const contentType = response.headers.get("content-type");
  if (contentType !== null) {
    headers.set("content-type", contentType);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function methodNotAllowed(allow: string): Response {
  const response = errorResponse(405, "method-not-allowed");
  response.headers.set("allow", allow);
  return response;
}

function errorResponse(status: number, code: string): Response {
  return new Response(code, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "text/plain; charset=utf-8",
    },
  });
}
