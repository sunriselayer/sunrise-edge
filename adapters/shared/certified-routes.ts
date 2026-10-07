import { NODE_RESULT_MEDIA_TYPE } from "./web-ingress.ts";

export const QUERY_RESULT_MEDIA_TYPE =
  "application/vnd.sunrise-edge.query-result";
export const MAX_CERTIFIED_BODY_BYTES = 32 * 1024 * 1024;
export const DEFAULT_CERTIFIED_REQUEST_BODY_BYTES = 8 * 1024 * 1024;
export const MAX_CERTIFIED_REFUSAL_BODY_BYTES = 1024;

export interface CertifiedRoute {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly maximumRequestBytes: number;
  readonly maximumResponseBytes: number;
  readonly responseMediaType: string;
  readonly success: "result" | "empty" | "result-or-empty";
  readonly requiresEmptyBody: boolean;
}

function post(
  path: string,
  maximumRequestBytes: number,
  maximumResponseBytes: number,
  success: CertifiedRoute["success"] = "result",
  requiresEmptyBody = false,
): CertifiedRoute {
  return Object.freeze({
    method: "POST",
    path,
    maximumRequestBytes,
    maximumResponseBytes,
    responseMediaType: NODE_RESULT_MEDIA_TYPE,
    success,
    requiresEmptyBody,
  });
}

function get(
  path: string,
  maximumResponseBytes = MAX_CERTIFIED_BODY_BYTES,
): CertifiedRoute {
  return Object.freeze({
    method: "GET",
    path,
    maximumRequestBytes: 0,
    maximumResponseBytes,
    responseMediaType: QUERY_RESULT_MEDIA_TYPE,
    success: "result",
    requiresEmptyBody: true,
  });
}

// DR-0204: one closed transport owner. The checked-in test TSV and native
// Rust oracle independently bind these ceilings to their actual codec owners.
// An outer HttpNodeResult is not bounded by its smaller nested paid payload.
const routes: readonly CertifiedRoute[] = Object.freeze([
  post("/v1/fastvote/prepare", 5_309_888, 4096),
  post("/v1/fastvote/certificates", 6_359_488, MAX_CERTIFIED_BODY_BYTES),
  post("/v1/fastvote/publications/source", 6_359_488, MAX_CERTIFIED_BODY_BYTES),
  post("/v1/fastvote/publications/retain", MAX_CERTIFIED_BODY_BYTES, 8192),
  post("/v1/fastvote/publications/apply", 7_408_064, MAX_CERTIFIED_BODY_BYTES),
  post(
    "/v1/fastvote/publications/retained-source",
    128,
    MAX_CERTIFIED_BODY_BYTES,
  ),
  post("/v1/fastvote/frontier/page", 128, 532_544),
  post("/v1/fastvote/frontier/advance", 1, 8192, "result-or-empty", true),
  post("/v1/fastvote/drain/signer-page", 532_608, 0, "empty"),
  post("/v1/fastvote/drain/member-confirm", 160, 0, "empty"),
  post("/v1/fastvote/drain/union-advance", 2_099_328, 4096, "result-or-empty"),
  post("/v1/fastvote/drain/signer-progress", 128, 534_912),
  post("/v1/fastvote/drain/apply", 128, MAX_CERTIFIED_BODY_BYTES),
  post(
    "/v1/fastvote/drain/import/{validator_id}",
    MAX_CERTIFIED_BODY_BYTES,
    2048,
  ),
  get("/v1/context"),
  get("/v1/objects/{object_id}"),
  get("/v1/receipts/{request_id}"),
  get("/v1/senders/{sender}/next-nonce"),
  get("/v1/contracts/paid-fee-policy", 16_384),
  get("/v1/contracts/publications/{publisher}/{origin_seed}", 5_310_144),
  get("/v1/contracts/instances/{creator}/{seed}"),
]);

const matchers: readonly { route: CertifiedRoute; pattern: RegExp }[] = routes
  .map((route) => ({
    route,
    pattern: new RegExp(
      `^${route.path.replace(/\{[a-z_]+\}/g, "[0-9a-f]{64}")}$`,
    ),
  }));

/** Closed locators only; a matched route supplies no application authority. */
export function resolveCertifiedRoute(
  pathname: string,
): CertifiedRoute | undefined {
  return matchers.find(({ pattern }) => pattern.test(pathname))?.route;
}

export function isCertifiedRefusalStatus(status: number): boolean {
  return [400, 401, 403, 404, 405, 409, 413, 415, 422].includes(status);
}
