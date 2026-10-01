import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const registry = fileURLToPath(new URL("./ci-gates.sh", import.meta.url));
export const requiredGateGroups = execFileSync(
  "bash",
  ["-c", 'source "$1"; ci_gate_groups', "ci-gate-registry", registry],
  { encoding: "utf8" },
).trim().split("\n");

export function requireSuccessfulGateResults(needs) {
  if (needs === null || typeof needs !== "object" || Array.isArray(needs)) {
    throw new Error("Repository gate dependencies must be an object");
  }
  const names = Object.keys(needs).sort();
  const required = [...requiredGateGroups].sort();
  if (names.length !== required.length || names.some((name, i) => name !== required[i])) {
    throw new Error("Repository gate dependency membership is incomplete or unknown");
  }
  if (required.some((name) => needs[name]?.result !== "success")) {
    throw new Error("Every repository gate must finish successfully");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    requireSuccessfulGateResults(JSON.parse(process.env.CI_NEEDS_JSON ?? ""));
    console.log("All required repository gates succeeded");
  } catch {
    // Never print arbitrary dependency outputs or input JSON.
    console.error("Required repository gates are missing, unknown or unsuccessful");
    process.exitCode = 1;
  }
}
