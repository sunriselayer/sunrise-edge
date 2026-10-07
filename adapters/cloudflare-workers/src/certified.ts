import { type WebFetch } from "../../shared/authenticated-node-core";
import { createCertifiedWebIngressHandler } from "../../shared/certified-web-ingress";

export const MAX_CERTIFIED_WORKER_REQUEST_BYTES = 8 * 1024 * 1024;

/** Separate HTTPS/Bearer composition; no binding, database or provider authority. */
export function createCertifiedCloudflareHandler(
  env: CertifiedRelayEnv,
  upstreamFetch?: WebFetch,
): (request: Request) => Promise<Response> {
  return createCertifiedWebIngressHandler({
    nodeCoreUrl: env.SUNRISE_NODE_CORE_URL,
    bearerToken: env.SUNRISE_NODE_CORE_BEARER_TOKEN,
    ...(upstreamFetch === undefined ? {} : { fetch: upstreamFetch }),
  }, { maximumRequestBodyBytes: MAX_CERTIFIED_WORKER_REQUEST_BYTES });
}

export default {
  fetch(request: Request, env: CertifiedRelayEnv): Promise<Response> {
    return createCertifiedCloudflareHandler(env)(request);
  },
} satisfies ExportedHandler<CertifiedRelayEnv>;
