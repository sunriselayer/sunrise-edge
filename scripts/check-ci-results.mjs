import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const registry = fileURLToPath(new URL("./ci-gates.sh", import.meta.url));
function readProfile(profile) {
  return Object.freeze(execFileSync(
    "bash",
    ["-c", 'source "$1"; ci_gate_groups "$2"', "ci-gate-registry", registry, profile],
    { encoding: "utf8" },
  ).trim().split("\n"));
}
export const requiredGateGroups = readProfile("required");
export const postgresGateGroups = readProfile("postgres");

export function requireSuccessfulGateResults(needs, profile = "required") {
  const groups = profile === "required" ? requiredGateGroups
    : profile === "postgres" ? postgresGateGroups : null;
  if (groups === null) throw new Error("Unknown repository gate profile");
  if (needs === null || typeof needs !== "object" || Array.isArray(needs)) {
    throw new Error("Repository gate dependencies must be an object");
  }
  const names = Object.keys(needs).sort();
  const required = [...groups].sort();
  if (names.length !== required.length || names.some((name, i) => name !== required[i])) {
    throw new Error("Repository gate dependency membership is incomplete or unknown");
  }
  if (required.some((name) => needs[name]?.result !== "success")) {
    throw new Error("Every repository gate must finish successfully");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args = process.argv.slice(2);
    let profile = "required";
    if (args.length !== 0) {
      if (args.length !== 2 || args[0] !== "--profile") {
        throw new Error("Malformed repository gate profile arguments");
      }
      profile = args[1];
    }
    requireSuccessfulGateResults(JSON.parse(process.env.CI_NEEDS_JSON ?? ""), profile);
    console.log(profile === "required" ? "All required repository gates succeeded"
      : "All explicit PostgreSQL gates succeeded");
  } catch {
    // Never print arbitrary dependency outputs or input JSON.
    console.error("Repository gate profile or dependencies are missing, unknown or unsuccessful");
    process.exitCode = 1;
  }
}
