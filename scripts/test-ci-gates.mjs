import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { requiredGateGroups, requireSuccessfulGateResults } from "./check-ci-results.mjs";

// This is a DB/compiler-free contract test, not a replacement for any real gate.
const root = fileURLToPath(new URL("../", import.meta.url));
const registry = join(root, "scripts/ci-gates.sh");
const groups = [
  "lint", "rust-tests", "pg-storage", "pg-lifecycle", "pg-drain-history",
  "pg-business-audit", "pg-recovery-economics", "portable-tools", "cloudflare",
];
assert.deepEqual(requiredGateGroups, groups);
function registryRows(array) {
  return execFileSync("bash", [
    "-c", `source "$1"; printf '%s\\n' "\${${array}[@]}"`, "ci-gate-registry", registry,
  ], { encoding: "utf8" }).trim().split("\n").map((row) => row.split("|"));
}
const cases = registryRows("CI_FASTVOTE_PG_CASES");
const auxiliary = registryRows("CI_AUXILIARY_IGNORED_CASES");
const expectedCases = [
  "fastvote_pg_operator_multivalidator_e2e",
  "fastvote_pg_operator_credential_isolated_multivalidator_e2e",
  "fastvote_host_pg_cli_multivalidator_e2e",
  "contract_lifecycle_pg_publish_instantiate_call_and_asset_verbs_multivalidator_e2e",
  "contract_lifecycle_pg_logical_publish_instantiate_call_and_asset_verbs_multivalidator_e2e",
  "contract_lifecycle_pg_ordered_freeze_and_frontier_binary_cli_e2e",
  "contract_lifecycle_pg_drainset_member_and_ordered_history_binary_cli_e2e",
  "business_audit_pg_genuine_causal_history_reopen_and_corruption_e2e",
  "certified_catch_up_pg_missed_prepare_binary_cli_e2e",
  "contract_lifecycle_catch_up_pg_missed_publish_instantiate_call_binary_cli_e2e",
  "economics_pg_offline_signed_claim_workflow_e2e",
  "ordered_economics_network_four_namespace_competing_claims_e2e",
  "fast_path::capacity_tests::live_postgres::live_postgres_concurrent_zero_share_claims_measure_retained_bytes_and_reopen_latency",
  "fast_path::capacity_tests::live_postgres::live_postgres_concurrent_positive_claims_measure_retained_bytes_and_writer_fence_recovery",
];
assert.deepEqual(cases.map((row) => row[3]), expectedCases);
assert.deepEqual(cases.map((row) => row[0]), [
  ...Array(6).fill("pg-lifecycle"), "pg-drain-history", "pg-business-audit",
  ...Array(6).fill("pg-recovery-economics"),
]);
assert.deepEqual(auxiliary.map((row) => row[2]), [
  "fee_claims::tests::certified_multi_escrow_inventory::export_certified_operator_fixture",
  "fee_claims::tests::certified_multi_escrow_inventory::export_certified_operator_fixture_postgres",
  "fee_escrow_inventory_pg_operator_e2e",
  "fast_path::soak_tests::live_postgres_certified_load_exports_recovery_handoff",
  "fee_escrow_soak_recovery_pg_operator_e2e",
]);
assert.deepEqual(auxiliary.map((row) => row[0]), ["rust-tests", ...Array(4).fill("pg-recovery-economics")]);
assert.equal(new Set([...expectedCases, ...auxiliary.map((row) => row[2])]).size, 19);
for (const [group, pkg, target, name, capture] of cases) {
  assert(groups.includes(group));
  assert.equal(pkg, target === "--lib" ? "node-core" : "sunrise-edge-operator");
  assert.equal(capture, target === "--lib" || target === "business_audit_pg_e2e" ? "yes" : "no");
  const path = target === "--lib" ? "crates/node-core/src/fast_path/capacity_tests.rs" : `apps/operator/tests/${target}.rs`;
  const source = readFileSync(join(root, path), "utf8");
  const leaf = name.split("::").at(-1);
  assert.match(source, new RegExp(`#\\[test\\]\\s*#\\[ignore[^\\n]*\\](?:\\s*#\\[[^\\n]*\\])*\\s*fn ${leaf}\\s*\\(`));
}
for (const [group, script, name] of auxiliary) {
  assert(groups.includes(group));
  assert(readFileSync(join(root, script), "utf8").includes(name));
}
const soak = readFileSync(join(root, "scripts/check-postgres-soak.sh"), "utf8");
for (const invariant of [
  "SUNRISE_EDGE_SOAK_ESCROWS=8", "SUNRISE_EDGE_SOAK_SENDERS=2",
  "SUNRISE_EDGE_SOAK_CLAIM_WRITERS=2", "SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC=32",
  "SUNRISE_EDGE_SOAK_DURATION_SECONDS=90", "SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS=180",
  "SUNRISE_EDGE_SOAK_RECOVERY_CYCLES=2", "SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE=1",
  'timeout --kill-after=30 "${SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS}s" bash -c run_phases',
]) assert(soak.includes(invariant));

const image = "postgres:18.6-alpine3.24@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2";
const faults = ["CRASH", "DISK_FULL", "WAL_FULL", "CONNECTION_EXHAUSTION", "BACKUP_RESTORE", "PGBOUNCER"];
function checkWorkflow(text) {
  assert(text.includes("\njobs:\n"));
  const jobText = text.slice(text.indexOf("\njobs:\n") + "\njobs:\n".length);
  const declarations = [...jobText.matchAll(/^  ([a-z][a-z0-9-]*):\n/gm)];
  assert.deepEqual(declarations.map((entry) => entry[1]), [...groups, "check"]);
  const jobs = new Map(declarations.map((entry, i) => [
    entry[1], jobText.slice(entry.index, declarations[i + 1]?.index ?? jobText.length),
  ]));
  const check = jobs.get("check");
  assert.deepEqual(check.split("\n").filter((line) => /^\s+(?:-\s+)?if\s*:/.test(line)), [
    "    if: ${{ always() }}",
  ]);
  assert.deepEqual([...check.matchAll(/^      - ([a-z][a-z0-9-]*)$/gm)].map((entry) => entry[1]), groups);
  assert(check.includes("CI_NEEDS_JSON: ${{ toJSON(needs) }}"));
  assert.deepEqual(check.split("\n").filter((line) => line.includes("scripts/check-ci-results.mjs")), [
    "        run: node scripts/check-ci-results.mjs",
  ]);
  assert(!/continue-on-error:|paths:|paths-ignore:/.test(text));
  for (const name of groups) {
    const job = jobs.get(name);
    assert(!/^\s+(?:-\s+)?if\s*:/m.test(job));
    assert.deepEqual(job.split("\n").filter((line) => line.includes("scripts/check-all.sh")), [
      `        run: ./scripts/check-all.sh --group ${name}`,
    ]);
    assert.equal(/services:/.test(job), name.startsWith("pg-"));
    assert.equal(/SUNRISE_EDGE_TEST_POSTGRES_URL:/.test(job), name.startsWith("pg-"));
    if (name.startsWith("pg-")) assert(job.includes(`image: ${image}`));
    for (const fault of faults) {
      assert.equal(job.includes(`SUNRISE_EDGE_TEST_POSTGRES_${fault}_REQUIRED: "1"`), name === "pg-storage");
    }
  }
  assert(jobs.get("pg-storage").includes("SUNRISE_EDGE_TEST_POSTGRES_CONTAINER_ID: ${{ job.services.postgres.id }}"));
  assert(jobs.get("pg-storage").includes("ghcr.io/icoretech/pgbouncer-docker:1.25.2@sha256:53dc42879de6b87efed6ad239558cfa6fef6f08c5fa4acc109da5f5af1868b89"));
  for (const fault of ["DISK_FULL", "WAL_FULL", "CONNECTION_EXHAUSTION", "BACKUP_RESTORE", "PGBOUNCER_POSTGRES"]) {
    assert(jobs.get("pg-storage").includes(`SUNRISE_EDGE_TEST_POSTGRES_${fault}_IMAGE: ${image}`));
  }
  for (const value of [
    "CARGO_INCREMENTAL: \"0\"", "CARGO_PROFILE_DEV_DEBUG: \"0\"", "CARGO_PROFILE_TEST_DEBUG: \"0\"",
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
    "denoland/setup-deno@22d081ff2d3a40755e97629de92e3bcbfa7cf2ed",
    "node-version: 22.20.0", "deno-version: 2.9.4",
    "cargo install wasm-bindgen-cli --version 0.2.127 --locked",
    "npm ci --prefix adapters/cloudflare-workers",
  ]) assert(text.includes(value));
}
const workflow = readFileSync(join(root, ".github/workflows/ci.yml"), "utf8");
checkWorkflow(workflow);
for (const mutation of [
  workflow.replace("      - pg-lifecycle\n", ""),
  workflow.replace("  pg-lifecycle:\n", "  unknown-group:\n"),
  workflow.replace("if: ${{ always() }}", "if: ${{ success() }}"),
  workflow.replace('SUNRISE_EDGE_TEST_POSTGRES_CRASH_REQUIRED: "1"', 'SUNRISE_EDGE_TEST_POSTGRES_CRASH_REQUIRED: "0"'),
]) assert.throws(() => checkWorkflow(mutation));
for (const name of groups) {
  const gate = `        run: ./scripts/check-all.sh --group ${name}`;
  for (const replacement of [
    `        if: false\n${gate}`, `${gate} || true`, `${gate} ; true`, `${gate}\n${gate}`,
  ]) assert.throws(() => checkWorkflow(workflow.replace(gate, replacement)));
  assert.throws(() => checkWorkflow(workflow.replace(`  ${name}:\n`, `  ${name}:\n    if: false\n`)));
}
const fanInGate = "        run: node scripts/check-ci-results.mjs";
for (const replacement of [
  `        if: false\n${fanInGate}`, `${fanInGate} || true`, `${fanInGate} ; true`, `${fanInGate}\n${fanInGate}`,
]) assert.throws(() => checkWorkflow(workflow.replace(fanInGate, replacement)));

const success = Object.fromEntries(groups.map((group) => [group, { result: "success" }]));
requireSuccessfulGateResults(success);
for (const group of groups) {
  for (const result of ["failure", "cancelled", "skipped", "", "unknown", undefined]) {
    assert.throws(() => requireSuccessfulGateResults({ ...success, [group]: { result } }));
  }
  const missing = { ...success };
  delete missing[group];
  assert.throws(() => requireSuccessfulGateResults(missing));
}
for (const bad of [null, [], "success", {}, { ...success, unknown: { result: "success" } }]) {
  assert.throws(() => requireSuccessfulGateResults(bad));
}
for (const [json, status] of [
  [JSON.stringify(success), 0],
  [JSON.stringify({ ...success, lint: { result: "failure" } }), 1],
  [JSON.stringify({ ...success, lint: { result: "cancelled" } }), 1],
  [JSON.stringify({ ...success, lint: { result: "skipped" } }), 1],
  [JSON.stringify({ ...success, lint: {} }), 1],
  [JSON.stringify({ ...success, unknown: { result: "success" } }), 1],
  ["{}", 1], ["not-json", 1], ["", 1],
]) {
  const result = spawnSync(process.execPath, [join(root, "scripts/check-ci-results.mjs")], {
    encoding: "utf8", env: { PATH: "/usr/bin:/bin", CI_NEEDS_JSON: json },
  });
  assert.ifError(result.error);
  assert.equal(result.status, status, result.stderr);
}

// PATH-only command doubles let the actual shell dispatch run without invoking
// Cargo, tools, databases or owning fixture scripts. All logs stay test-local.
const directory = mkdtempSync(join(tmpdir(), "sunrise-edge-ci-dispatch-"));
const logPath = join(directory, "commands.jsonl");
const realBash = "/bin/bash";
try {
  for (const tool of ["cargo", "rustfmt", "git", "node", "npm", "deno", "bash"]) {
    const body = `#!${process.execPath}
const {appendFileSync}=require('node:fs');
const {spawnSync}=require('node:child_process');
const tool=${JSON.stringify(tool)},args=process.argv.slice(2);
appendFileSync(process.env.CI_MOCK_LOG,JSON.stringify({tool,args,cwd:process.cwd()})+'\\n');
if(process.env.CI_MOCK_FAIL_TOOL===tool)process.exit(17);
if(tool==='bash'&&args[0]==='scripts/check-fastvote-pg.sh'){
 const child=spawnSync(${JSON.stringify(realBash)},args,{stdio:'inherit',env:process.env});
 process.exit(child.status??1);
}
if(tool==='cargo'&&args[0]==='test'&&args.includes('--ignored')&&args.includes('--list')){
 const name=args[args.indexOf('--')-1];
 if(name!==process.env.CI_MOCK_MISSING_TEST)console.log(name+': test');
}
if(tool==='cargo'&&args[0]==='test'&&!args.includes('--list')&&args.includes(process.env.CI_MOCK_FAIL_TEST))process.exit(18);
`;
    writeFileSync(join(directory, tool), body, { flag: "wx", mode: 0o755 });
  }
  function run(script, args = [], overrides = {}) {
    writeFileSync(logPath, "");
    const result = spawnSync(realBash, [join(root, script), ...args], {
      cwd: root, encoding: "utf8", timeout: 30_000,
      env: {
        PATH: `${directory}:/usr/bin:/bin`, CI_MOCK_LOG: logPath,
        GITHUB_ACTIONS: "true", SUNRISE_EDGE_TEST_POSTGRES_URL: "mock-only",
        ...overrides,
      },
    });
    assert.ifError(result.error);
    const text = readFileSync(logPath, "utf8").trim();
    return { ...result, log: text ? text.split("\n").map((row) => JSON.parse(row)) : [] };
  }
  function passed(run) { assert.equal(run.status, 0, run.stderr); return run.log; }
  const full = passed(run("scripts/check-all.sh"));
  const lanes = new Map(groups.map((group) => [group, passed(run("scripts/check-all.sh", ["--group", group]))]));
  const union = [...lanes.values()].flat();
  // An independent baseline stops deleting a gate from BOTH dispatch modes
  // from turning the union comparison below into a misleading success.
  assert.deepEqual(full.filter(({ tool, args }) => tool === "node" && args[0].endsWith("-vectors.mjs")).map(({ args }) => args[0]), [
    "call-value", "call-intent", "publication-submission", "local-execution",
    "call-authorization", "paid-execution", "fast-vote", "availability",
    "frozen-frontier", "drainset", "fast-path", "fastvote-apply-request",
    "fastvote-published-apply", "ordered-history",
  ].map((name) => `scripts/${name}-vectors.mjs`));
  assert.deepEqual(full.filter(({ tool }) => tool === "rustfmt").map(({ args }) => args), [[
    "--edition", "2024", "--check",
    ...["core_and_nonce", "durable_object_support", "authenticated_objects",
      "preinstalled_support", "preinstalled_execution", "durable_handlers", "queries", "fees",
    ].map((name) => `crates/node-core/src/tests/${name}.rs`),
    ...["fixture", "call", "publish", "verify", "codec"].map((name) => `crates/execution/tests/paid_execution_engine/${name}.rs`),
  ]]);
  assert.deepEqual(full.filter(({ tool }) => tool === "deno").map(({ args, cwd }) => [args, relative(root, cwd)]),
    ["deno", "vercel", "supabase-edge", "aws-lambda"].map((name) => [["task", "check"], `adapters/${name}`]));
  assert.deepEqual(full.filter(({ tool }) => tool === "bash").map(({ args }) => args), [
    ["scripts/check-fee-escrow-inventory.sh"], ["scripts/check-fee-escrow-inventory-pg.sh"],
    ["scripts/check-fastvote-pg.sh"], ["scripts/check-postgres-soak.sh", "--self-test-cli"],
    ["scripts/check-postgres-soak.sh", "--smoke"], ["scripts/build-cloudflare-validator.sh"],
  ]);
  assert(full.some(({ tool, args }) => tool === "cargo" && JSON.stringify(args) === JSON.stringify(["fmt", "--all", "--", "--check"])));
  assert(full.some(({ tool, args }) => tool === "cargo" && JSON.stringify(args) === JSON.stringify(["clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"])));
  assert(full.some(({ tool, args }) => tool === "cargo" && JSON.stringify(args) === JSON.stringify(["test", "--workspace", "--all-targets", "--all-features"])));
  assert.deepEqual(full.filter(({ tool }) => tool === "npm").map(({ args }) => args), [["--prefix", "adapters/cloudflare-workers", "run", "check"]]);
  assert.deepEqual(full.filter(({ tool }) => tool === "git").map(({ args }) => args), [["diff", "--check"]]);
  function ignoredExecutions(log) {
    return log.filter(({ tool, args }) => tool === "cargo" && args[0] === "test" && args.includes("--ignored") && !args.includes("--list"));
  }
  const fullIgnored = ignoredExecutions(full);
  assert.deepEqual(fullIgnored.map(({ args }) => args[args.indexOf("--") - 1]), expectedCases);
  assert.deepEqual(ignoredExecutions(union).map(({ args }) => args[args.indexOf("--") - 1]), expectedCases);
  for (const [group, pkg, target, name, capture] of cases) {
    const log = lanes.get(group);
    const checks = log.filter(({ tool, args }) => tool === "cargo" && args.includes(name));
    assert.equal(checks.length, 2, `${name} needs discovery and execution`);
    assert(checks[0].args.includes("--list"));
    assert(!checks[1].args.includes("--list"));
    assert(checks[1].args.includes("--exact"));
    assert.equal(checks[1].args[checks[1].args.indexOf("-p") + 1], pkg);
    assert.equal(checks[1].args.includes("--nocapture"), capture === "yes");
    assert(target === "--lib" ? checks[1].args.includes("--lib") : checks[1].args.includes(target));
  }
  function gateEvents(log) {
    return log.flatMap(({ tool, args, cwd }) => {
      if (tool === "cargo" && args[0] === "build") return [];
      if (tool === "cargo" && args.includes("--list")) return [];
      if (tool === "cargo" && args[0] === "test" && !args.includes("--ignored")) {
        if (args.includes("--workspace")) return args.includes("--exclude") ? ["rust-tests"] : ["rust-tests", "pg-storage"];
        assert.deepEqual(args, ["test", "-p", "runtime-postgres", "-p", "sunrise-edge-operator", "-p", "sunrise-edge-cloudflare-validator", "--all-targets", "--all-features", "--features", "sunrise-edge-cli/usb-hid"]);
        return ["pg-storage"];
      }
      if (tool === "bash" && args[0] === "scripts/check-fastvote-pg.sh") return [];
      return [JSON.stringify([tool, args, tool === "deno" ? relative(root, cwd) : ""])];
    }).sort();
  }
  assert.deepEqual(gateEvents(full), gateEvents(union));
  assert.deepEqual(lanes.get("rust-tests")[0].args, ["test", "--workspace", "--all-targets", "--all-features", "--exclude", "runtime-postgres"]);
  for (const group of ["pg-lifecycle", "pg-drain-history", "pg-business-audit", "pg-recovery-economics"]) {
    assert(lanes.get(group).some(({ tool, args }) => tool === "cargo" && args.includes("build") && args.includes("sunrise-edge-cli")));
  }
  assert(lanes.get("pg-business-audit").some(({ tool, args }) => tool === "cargo" && args.includes("build") && args.includes("business_audit_pg")));
  for (const script of ["scripts/check-all.sh", "scripts/check-fastvote-pg.sh"]) {
    for (const args of [["--group", "unknown"], ["--group"], ["--group", "all"], ["--group", "pg-lifecycle", "extra"]]) {
      const failed = run(script, args, { SUNRISE_EDGE_TEST_POSTGRES_URL: "" });
      assert.notEqual(failed.status, 0);
      assert.equal(failed.log.length, 0);
    }
  }
  for (const group of ["pg-storage", "pg-lifecycle", "pg-drain-history", "pg-business-audit", "pg-recovery-economics"]) {
    const failed = run("scripts/check-all.sh", ["--group", group], { SUNRISE_EDGE_TEST_POSTGRES_URL: "" });
    assert.notEqual(failed.status, 0);
    assert.equal(failed.log.length, 0);
    assert.equal(run("scripts/check-all.sh", ["--group", group], { SUNRISE_EDGE_TEST_POSTGRES_URL: "", GITHUB_ACTIONS: "" }).status, 0);
  }
  for (const fault of faults) {
    for (const value of ["1", "", "0", "invalid"]) {
      const failed = run("scripts/check-all.sh", ["--group", "pg-storage"], {
        SUNRISE_EDGE_TEST_POSTGRES_URL: "", GITHUB_ACTIONS: "",
        [`SUNRISE_EDGE_TEST_POSTGRES_${fault}_REQUIRED`]: value,
      });
      assert.notEqual(failed.status, 0);
      assert.equal(failed.log.length, 0);
    }
  }
  const absent = run("scripts/check-all.sh", [], { SUNRISE_EDGE_TEST_POSTGRES_URL: "" });
  assert.notEqual(absent.status, 0);
  assert.equal(absent.log.length, 0);
  for (const group of ["lint", "rust-tests", "portable-tools", "cloudflare"]) {
    passed(run("scripts/check-all.sh", ["--group", group], { SUNRISE_EDGE_TEST_POSTGRES_URL: "" }));
  }
  for (const name of expectedCases) {
    const group = cases.find((row) => row[3] === name)[0];
    const missing = run("scripts/check-all.sh", ["--group", group], { CI_MOCK_MISSING_TEST: name });
    assert.notEqual(missing.status, 0);
    assert(!ignoredExecutions(missing.log).some(({ args }) => args.includes(name)));
    assert.notEqual(run("scripts/check-all.sh", ["--group", group], { CI_MOCK_FAIL_TEST: name }).status, 0);
  }
  const failedFull = run("scripts/check-all.sh", [], { CI_MOCK_FAIL_TOOL: "cargo" });
  assert.notEqual(failedFull.status, 0);
  assert(!failedFull.log.some(({ tool, args }) => tool === "bash" && args.includes("scripts/check-fee-escrow-inventory.sh")));
  for (const [group, tool] of [
    ["rust-tests", "cargo"], ["pg-storage", "cargo"], ["lint", "rustfmt"],
    ["portable-tools", "node"], ["portable-tools", "deno"],
    ["cloudflare", "bash"], ["cloudflare", "npm"],
  ]) assert.notEqual(run("scripts/check-all.sh", ["--group", group], { CI_MOCK_FAIL_TOOL: tool }).status, 0);
  const missingSqlite = run("scripts/check-all.sh", ["--group", "rust-tests"], { CI_MOCK_MISSING_TEST: auxiliary[0][2] });
  assert.notEqual(missingSqlite.status, 0);
  assert(!missingSqlite.log.some(({ tool }) => tool === "bash"));
} finally {
  rmSync(directory, { recursive: true, force: true });
}
console.log("CI gate contract passed: 9 lanes, 19 required ignored selectors, complete serial coverage and fail-closed dispatch/results");
