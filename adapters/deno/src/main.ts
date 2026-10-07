import { createCertifiedDenoHandler, createDenoHandler } from "./adapter.ts";
import { configuredIngressProfile } from "../../shared/certified-web-ingress.ts";
import { DEFAULT_CERTIFIED_REQUEST_BODY_BYTES } from "../../shared/certified-routes.ts";

const config = {
  nodeCoreUrl: requiredEnvironmentVariable("SUNRISE_NODE_CORE_URL"),
  bearerToken: requiredEnvironmentVariable("SUNRISE_NODE_CORE_BEARER_TOKEN"),
  timeoutMilliseconds: Number(
    Deno.env.get("SUNRISE_NODE_CORE_TIMEOUT_MS") ?? "5000",
  ),
};
const profile = configuredIngressProfile(
  Deno.env.get("SUNRISE_INGRESS_PROFILE"),
);
const handler = profile === "certified-fastvote"
  ? createCertifiedDenoHandler({
    ...config,
    maximumRequestBodyBytes: Number(
      Deno.env.get("SUNRISE_MAX_REQUEST_BYTES") ??
        DEFAULT_CERTIFIED_REQUEST_BODY_BYTES,
    ),
  })
  : createDenoHandler(config);

function requiredEnvironmentVariable(name: string): string {
  const value = Deno.env.get(name);
  if (value === undefined) {
    throw new TypeError(`${name} is required`);
  }
  return value;
}

export default {
  fetch(request: Request): Promise<Response> {
    return handler(request);
  },
} satisfies Deno.ServeDefaultExport;
