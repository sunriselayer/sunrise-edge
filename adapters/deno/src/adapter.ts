import {
  type AuthenticatedNodeCoreConfig,
  createAuthenticatedNodeCoreFetcher,
  type WebFetch,
} from "../../shared/authenticated-node-core.ts";
import { handleWebRequest } from "../../shared/web-ingress.ts";
import { createCertifiedWebIngressHandler } from "../../shared/certified-web-ingress.ts";
import { DEFAULT_CERTIFIED_REQUEST_BODY_BYTES } from "../../shared/certified-routes.ts";

export type DenoFetch = WebFetch;
export type DenoIngressConfig = AuthenticatedNodeCoreConfig;

export interface CertifiedDenoIngressConfig extends AuthenticatedNodeCoreConfig {
  readonly maximumRequestBodyBytes?: number;
}

/** Explicit certified composition; the event-only constructor stays unchanged. */
export function createCertifiedDenoHandler(
  config: CertifiedDenoIngressConfig,
): (request: Request) => Promise<Response> {
  return createCertifiedWebIngressHandler(config, {
    maximumRequestBodyBytes: config.maximumRequestBodyBytes ??
      DEFAULT_CERTIFIED_REQUEST_BODY_BYTES,
  });
}

/** Builds an immutable Deno handler around an authenticated node-core client. */
export function createDenoHandler(
  config: DenoIngressConfig,
): (request: Request) => Promise<Response> {
  const nodeCore = createAuthenticatedNodeCoreFetcher(config);
  return (request) => handleWebRequest(request, nodeCore);
}
