export interface CertifiedRouteFixture {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly requestBytes: number;
  readonly responseBytes: number;
  readonly success: "result" | "empty" | "result-or-empty";
  readonly emptyRequest: boolean;
}

/** Test-only parser; this literal oracle is never production routing or authority. */
export function parseCertifiedRouteFixtures(text: string): CertifiedRouteFixture[] {
  return text.split("\n").filter((line) => line !== "" && !line.startsWith("#")).map(
    (line) => {
      const fields = line.split("\t");
      const [method, path, requestBytes, responseBytes, success, emptyRequest] = fields;
      if (
        fields.length !== 6 || (method !== "GET" && method !== "POST") ||
        path === undefined ||
        (success !== "result" && success !== "empty" &&
          success !== "result-or-empty") ||
        (emptyRequest !== "0" && emptyRequest !== "1") ||
        requestBytes === undefined || !/^(0|[1-9][0-9]*)$/.test(requestBytes) ||
        responseBytes === undefined || !/^(0|[1-9][0-9]*)$/.test(responseBytes)
      ) {
        throw new TypeError("invalid independent certified route fixture");
      }
      return {
        method,
        path,
        requestBytes: Number(requestBytes),
        responseBytes: Number(responseBytes),
        success,
        emptyRequest: emptyRequest === "1",
      };
    },
  );
}

export function fixturePath(fixture: CertifiedRouteFixture): string {
  return fixture.path.replace(/\{[a-z_]+\}/g, "1".repeat(64));
}
