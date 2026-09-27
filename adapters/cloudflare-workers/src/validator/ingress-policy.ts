import { readBoundedBody } from "../../../shared/web-ingress";
import { timingSafeEqual } from "node:crypto";

export const VALIDATOR_BODY_LIMIT = 1_800_000;
const AUTHORIZATION_LIMIT = 1024;

export type ValidatorRequest = { path: string; body: Uint8Array };

function rejected(status: number, message: string, allow?: string): Response {
  const headers: Headers = new Headers({ "cache-control": "no-store" });
  if (allow !== undefined) headers.set("allow", allow);
  return new Response(message, { status, headers });
}

/** Bearer authorization is transport access, never transaction authority.
 * Signed intents remain independently authenticated by the Rust core.
 */
export async function authorizeValidatorRequest(
  request: Request, token: unknown,
): Promise<boolean> {
  if (typeof token !== "string" || token.length < 16 || token.length > AUTHORIZATION_LIMIT
    || !/^[A-Za-z0-9._~+/-]+=*$/.test(token)) return false;
  const provided: string = request.headers.get("authorization") ?? "";
  if (provided.length > AUTHORIZATION_LIMIT + 7) return false;
  const encoder: TextEncoder = new TextEncoder();
  const [actual, expected]: [ArrayBuffer, ArrayBuffer] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(provided)),
    crypto.subtle.digest("SHA-256", encoder.encode(`Bearer ${token}`)),
  ]);
  return timingSafeEqual(new Uint8Array(actual), new Uint8Array(expected));
}

/** Closed certified-only HTTP surface; no direct mutating routes or arbitrary
 * event families are exposed by changing a runtime flag.
 */
export async function decodeValidatorRequest(
  request: Request,
): Promise<ValidatorRequest | Response> {
  const url: URL = new URL(request.url);
  if (url.search !== "") return rejected(400, "query-parameters-not-supported");
  const path: string = url.pathname;
  const query: boolean = path === "/v1/context"
    || path === "/v1/contracts/paid-fee-policy"
    || /^\/v1\/contracts\/(?:publications|instances)\/[0-9a-f]{64}\/[0-9a-f]{64}$/.test(path)
    || /^\/v1\/(?:objects|receipts)\/[0-9a-f]{64}$/.test(path)
    || /^\/v1\/senders\/[0-9a-f]{64}\/next-nonce$/.test(path);
  const mutation: boolean = path === "/v1/fastvote/prepare"
    || path === "/v1/fastvote/certificates";
  if (!query && !mutation) return rejected(404, "not-found");
  const allowed: string = query ? "GET" : "POST";
  if (request.method !== allowed) return rejected(405, "method-not-allowed", allowed);
  if (query) return { path, body: new Uint8Array() };
  const encoding: string | undefined = request.headers.get("content-encoding")?.trim().toLowerCase();
  if (request.headers.get("content-type")?.trim().toLowerCase()
    !== "application/vnd.sunrise-edge.node-event"
    || (encoding !== undefined && encoding !== "identity")) {
    return rejected(415, "unsupported-media-type");
  }
  const declaredLength: string | null = request.headers.get("content-length");
  if (declaredLength !== null && (!/^(0|[1-9][0-9]*)$/.test(declaredLength)
    || !Number.isSafeInteger(Number(declaredLength)))) {
    return rejected(400, "invalid-content-length");
  }
  if (declaredLength !== null && Number(declaredLength) > VALIDATOR_BODY_LIMIT) {
    return rejected(413, "request-too-large");
  }
  try {
    const body: Uint8Array = await readBoundedBody(request.body, VALIDATOR_BODY_LIMIT);
    if (declaredLength !== null && Number(declaredLength) !== body.byteLength) {
      return rejected(400, "content-length-mismatch");
    }
    return { path, body };
  } catch (error: unknown) {
    if (error instanceof Error && "status" in error && error.status === 413) {
      return rejected(413, "request-too-large");
    }
    return rejected(400, "invalid-request-body");
  }
}
