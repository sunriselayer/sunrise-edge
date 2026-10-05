import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { requiredGateGroups, postgresGateGroups, requireSuccessfulGateResults } from "./check-ci-results.mjs";

// This is a DB/compiler-free contract test, not a replacement for any real gate.
const root = fileURLToPath(new URL("../", import.meta.url));
const registry = join(root, "scripts/ci-gates.sh");
const execution = join(root, "scripts/ci-execution.sh");
const requiredGroups = ["lint", "rust-tests", "portable-tools", "cloudflare", "core-recurrence", "readiness-sqlite"];
const postgresGroups = ["pg-storage", "pg-lifecycle", "pg-drain-history", "pg-business-audit", "pg-recovery-economics"];
const groups = [
  "lint", "rust-tests", "pg-storage", "pg-lifecycle", "pg-drain-history",
  "pg-business-audit", "pg-recovery-economics", "portable-tools", "cloudflare",
  "core-recurrence", "readiness-sqlite",
];
assert.deepEqual(requiredGateGroups, requiredGroups);
assert.deepEqual(postgresGateGroups, postgresGroups);
function registryRows(array) {
  return execFileSync("bash", [
    "-c", `source "$1"; printf '%s\\n' "\${${array}[@]}"`, "ci-gate-registry", registry,
  ], { encoding: "utf8" }).trim().split("\n").map((row) => row.split("|"));
}
// Fixed independent plan expectations accompany, not replace, the command
// coverage baselines below. The implementation registry cannot certify itself.
const expectedPlans = [
  ["required", "required", "gate-contract rust-style rust-tests-required sqlite-inventory core-recurrence readiness-sqlite soak-cli vectors cloudflare-build cloudflare-check deno-adapters diff-hygiene"],
  ["full", "postgres", "gate-contract rust-style rust-tests-full sqlite-inventory core-recurrence readiness-sqlite pg-inventory pg-protocol-all soak-cli pg-soak vectors cloudflare-build cloudflare-check deno-adapters diff-hygiene"],
  ["lint", "required", "gate-contract rust-style diff-hygiene"],
  ["rust-tests", "required", "rust-tests-required sqlite-inventory"],
  ["pg-storage", "postgres", "pg-storage-tests"],
  ["pg-lifecycle", "postgres", "pg-protocol-lifecycle"],
  ["pg-drain-history", "postgres", "pg-protocol-drain-history"],
  ["pg-business-audit", "postgres", "pg-protocol-business-audit"],
  ["pg-recovery-economics", "postgres", "pg-inventory pg-protocol-recovery-economics pg-soak"],
  ["portable-tools", "required", "soak-cli vectors deno-adapters"],
  ["cloudflare", "required", "cloudflare-build cloudflare-check"],
  ["core-recurrence", "required", "core-recurrence"],
  ["readiness-sqlite", "required", "readiness-sqlite"],
];
function checkPlans(rows) { assert.deepEqual(rows, expectedPlans); }
const plans = registryRows("CI_EXECUTION_PLANS");
checkPlans(plans);
assert.deepEqual(plans.slice(2).map(([group]) => group), groups);
for (const mutation of [
  plans.filter(([group]) => group !== "cloudflare"),
  [...plans, plans[2]],
  plans.map(([group, profile, actions]) => [group, profile, actions.replace("vectors", "unknown-action")]),
  plans.map(([group, profile, actions]) => [group, profile, actions.split(" ").filter((action) => action !== "vectors").join(" ")]),
  plans.map(([group, profile, actions]) => [group, group === "full" ? "required" : profile, actions]),
  plans.map(([group, profile, actions]) => [group, profile, group === "full" ? [...actions.split(" ")].reverse().join(" ") : actions]),
]) assert.throws(() => checkPlans(mutation));
for (const [selection, profile, actions] of expectedPlans) {
  for (const [fn, expected] of [["ci_execution_profile", [profile]], ["ci_execution_plan", actions.split(" ")]]) {
    const actual = execFileSync("/bin/bash", ["-c", 'source "$1"; "$2" "$3"', "ci-gate-registry", registry, fn, selection], { encoding: "utf8" });
    assert.deepEqual(actual.trim().split("\n"), expected);
  }
}
for (const fn of ["ci_execution_profile", "ci_execution_plan"]) {
  for (const args of [[], ["unknown"], [""], ["postgres"], ["required", "extra"], ["vectors; true"]]) {
    const result = spawnSync("/bin/bash", ["-c", 'source "$1"; shift; "$@"', "ci-gate-registry", registry, fn, ...args], { encoding: "utf8" });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, "");
  }
}
assert.deepEqual([...requiredGroups, ...postgresGroups].sort(), [...groups].sort());
for (const args of [["unknown"], [""], ["full"], ["required", "extra"]]) {
  const result = spawnSync("/bin/bash", ["-c", 'source "$1"; shift; ci_gate_groups "$@"', "ci-gate-registry", registry, ...args], { encoding: "utf8" });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, "");
}
const cases = registryRows("CI_FASTVOTE_PG_CASES");
const auxiliary = registryRows("CI_AUXILIARY_IGNORED_CASES");
const recurringCases = registryRows("CI_REQUIRED_EXTENDED_CASES");
const expectedRecurringCases = [
  ["core-recurrence", "node-core", "--lib", "ordered_economics::tests::causal_placement::control_reconstruction::frozen_completion::successor_activation::successor_recurring_delay::genuine_recurring_sqlite_handoffs_reach_configured_seven_epoch_withdrawal_unlock", "no"],
  ["readiness-sqlite", "sunrise-edge-operator", "conditional_readiness_sqlite", "compiled_conditional_readiness_real_retention_restart_and_distinct_certificate", "no"],
];
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
assert.deepEqual(recurringCases, expectedRecurringCases);
assert(!recurringCases.some((row) => row[3].includes("compiled_registered_replacement_and_recurring_successor_hosts")));
const recurringSourcePaths = ["crates/node-core/src/ordered_economics/tests/causal_placement/control_reconstruction/frozen_completion/successor_recurring_delay.rs", "apps/operator/tests/conditional_readiness_sqlite.rs"];
const coreRecurrenceSource = readFileSync(join(root, recurringSourcePaths[0]), "utf8");
assert.match(coreRecurrenceSource, new RegExp(`#\\[ignore[^\\n]*\\]\\s*\\n\\s*fn ${recurringCases[0][3].split("::").at(-1)}\\s*\\(`));
const readinessSqliteSource = readFileSync(join(root, recurringSourcePaths[1]), "utf8");
assert.match(readinessSqliteSource, new RegExp(`#\\[ignore[^\\n]*\\]\\s*\\n\\s*async fn ${recurringCases[1][3].split("::").at(-1)}\\s*\\(`));
for (const row of recurringCases) { assert(groups.includes(row[0])); }
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
assert.equal(auxiliary.filter((row) => requiredGroups.includes(row[0])).length, 1);
assert.equal(cases.length + auxiliary.filter((row) => postgresGroups.includes(row[0])).length, 18);
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
function checkWorkflow(text, profile) {
  assert(profile === "required" || profile === "postgres");
  const pg = profile === "postgres";
  const members = pg ? postgresGroups : requiredGroups;
  const finalName = pg ? "postgres-check" : "check";
  assert.equal(text.slice(0, text.indexOf("\npermissions:")), pg
    ? "name: postgres checks\n\non:\n  workflow_dispatch:\n"
    : "name: repository checks\n\non:\n  pull_request:\n  push:\n    branches:\n      - main\n");
  assert(text.includes("\njobs:\n"));
  const jobText = text.slice(text.indexOf("\njobs:\n") + "\njobs:\n".length);
  const declarations = [...jobText.matchAll(/^  ([a-z][a-z0-9-]*):\n/gm)];
  assert.deepEqual(declarations.map((entry) => entry[1]), [...members, finalName]);
  const jobs = new Map(declarations.map((entry, i) => [
    entry[1], jobText.slice(entry.index, declarations[i + 1]?.index ?? jobText.length),
  ]));
  const check = jobs.get(finalName);
  assert.deepEqual(check.split("\n").filter((line) => /^\s+(?:-\s+)?if\s*:/.test(line)), [
    "    if: ${{ always() }}",
  ]);
  assert.deepEqual([...check.matchAll(/^      - ([a-z][a-z0-9-]*)$/gm)].map((entry) => entry[1]), members);
  assert(check.includes("CI_NEEDS_JSON: ${{ toJSON(needs) }}"));
  assert.deepEqual(check.split("\n").filter((line) => line.includes("scripts/check-ci-results.mjs")), [
    `        run: node scripts/check-ci-results.mjs${pg ? " --profile postgres" : ""}`,
  ]);
  assert(!/continue-on-error:|paths:|paths-ignore:/.test(text));
  if (!pg) assert(!/services:|SUNRISE_EDGE_TEST_POSTGRES_|pg-/.test(text));
  for (const name of members) {
    const job = jobs.get(name);
    assert(!/^\s+(?:-\s+)?if\s*:/m.test(job));
    assert.deepEqual(job.split("\n").filter((line) => line.includes("scripts/check-all.sh")), [
      `        run: ./scripts/check-all.sh --group ${name}`,
    ]);
    assert.equal(/services:/.test(job), pg);
    assert.equal(/SUNRISE_EDGE_TEST_POSTGRES_URL:/.test(job), pg);
    assert.equal([...job.matchAll(/^    timeout-minutes: (\d+)$/gm)].map((match) => Number(match[1])).join(),
      String(name === "pg-business-audit" ? 90
        : name === "lint" || name === "portable-tools" ? 45
        : name === "core-recurrence" || name === "readiness-sqlite" ? 120
        : 60));
    if (pg) assert(job.includes(`image: ${image}`));
    for (const fault of faults) {
      assert.equal(job.includes(`SUNRISE_EDGE_TEST_POSTGRES_${fault}_REQUIRED: "1"`), name === "pg-storage");
    }
  }
  if (pg) {
    assert(jobs.get("pg-storage").includes("SUNRISE_EDGE_TEST_POSTGRES_CONTAINER_ID: ${{ job.services.postgres.id }}"));
    assert(jobs.get("pg-storage").includes("ghcr.io/icoretech/pgbouncer-docker:1.25.2@sha256:53dc42879de6b87efed6ad239558cfa6fef6f08c5fa4acc109da5f5af1868b89"));
    for (const fault of ["DISK_FULL", "WAL_FULL", "CONNECTION_EXHAUSTION", "BACKUP_RESTORE", "PGBOUNCER_POSTGRES"]) {
      assert(jobs.get("pg-storage").includes(`SUNRISE_EDGE_TEST_POSTGRES_${fault}_IMAGE: ${image}`));
    }
  }
  for (const value of [
    "CARGO_INCREMENTAL: \"0\"", "CARGO_PROFILE_DEV_DEBUG: \"0\"", "CARGO_PROFILE_TEST_DEBUG: \"0\"",
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
    "node-version: 22.20.0",
  ]) assert(text.includes(value));
  if (!pg) for (const value of [
    "denoland/setup-deno@22d081ff2d3a40755e97629de92e3bcbfa7cf2ed", "deno-version: 2.9.4",
    "cargo install wasm-bindgen-cli --version 0.2.127 --locked", "npm ci --prefix adapters/cloudflare-workers",
  ]) assert(text.includes(value));
  return jobs;
}
const profiles = [["required", requiredGroups, ".github/workflows/ci.yml"], ["postgres", postgresGroups, ".github/workflows/postgres.yml"]];
for (const [profile, members, path] of profiles) {
  const workflow = readFileSync(join(root, path), "utf8");
  checkWorkflow(workflow, profile);
  for (const mutation of [
    workflow.replace(`      - ${members[0]}\n`, ""),
    workflow.replace(`  ${members[0]}:\n`, "  unknown-group:\n"),
    workflow.replace("if: ${{ always() }}", "if: ${{ success() }}"),
    workflow.replace("on:\n", "on:\n  schedule:\n    - cron: '0 0 * * *'\n"),
    workflow.replace("jobs:\n", "jobs:\n  path-skipped:\n    if: false\n"),
  ]) assert.throws(() => checkWorkflow(mutation, profile));
  for (const name of members) {
    const gate = `        run: ./scripts/check-all.sh --group ${name}`;
    for (const replacement of [
      `        if: false\n${gate}`, `${gate} || true`, `${gate} ; true`, `${gate}\n${gate}`,
    ]) assert.throws(() => checkWorkflow(workflow.replace(gate, replacement), profile));
    assert.throws(() => checkWorkflow(workflow.replace(`  ${name}:\n`, `  ${name}:\n    if: false\n`), profile));
  }
  const fanInGate = `        run: node scripts/check-ci-results.mjs${profile === "postgres" ? " --profile postgres" : ""}`;
  for (const replacement of [
    `        if: false\n${fanInGate}`, `${fanInGate} || true`, `${fanInGate} ; true`, `${fanInGate}\n${fanInGate}`,
    `${fanInGate} --profile unknown`,
  ]) assert.throws(() => checkWorkflow(workflow.replace(fanInGate, replacement), profile));
  if (profile === "postgres") {
    assert.throws(() => checkWorkflow(workflow.replace('SUNRISE_EDGE_TEST_POSTGRES_CRASH_REQUIRED: "1"', 'SUNRISE_EDGE_TEST_POSTGRES_CRASH_REQUIRED: "0"'), profile));
    assert.throws(() => checkWorkflow(workflow.replace("  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request:\n"), profile));
    assert.throws(() => checkWorkflow(workflow.replace(" --profile postgres", ""), profile));
  } else {
    for (const extra of ["  SUNRISE_EDGE_TEST_POSTGRES_URL: unused\n", "  services:\n    postgres: unused\n"]) {
      assert.throws(() => checkWorkflow(workflow.replace("env:\n", `env:\n${extra}`), profile));
    }
  }

  const success = Object.fromEntries(members.map((group) => [group, { result: "success" }]));
  requireSuccessfulGateResults(success, profile);
  if (profile === "required") requireSuccessfulGateResults(success);
  for (const group of members) {
    for (const result of ["failure", "cancelled", "skipped", "", "unknown", undefined]) {
      assert.throws(() => requireSuccessfulGateResults({ ...success, [group]: { result } }, profile));
    }
    const missing = { ...success };
    delete missing[group];
    assert.throws(() => requireSuccessfulGateResults(missing, profile));
  }
  for (const bad of [null, [], "success", {}, { ...success, unknown: { result: "success" } },
    Object.fromEntries(groups.map((group) => [group, { result: "success" }]))]) {
    assert.throws(() => requireSuccessfulGateResults(bad, profile));
  }
  function resultCommand(json, status, args) {
    const result = spawnSync(process.execPath, [join(root, "scripts/check-ci-results.mjs"), ...args], {
      encoding: "utf8", env: { PATH: "/usr/bin:/bin", CI_NEEDS_JSON: json },
    });
    assert.ifError(result.error);
    assert.equal(result.status, status, result.stderr);
  }
  const profileArgs = profile === "required" ? [] : ["--profile", "postgres"];
  for (const [json, status] of [
    [JSON.stringify(success), 0],
    ...["failure", "cancelled", "skipped", undefined].map((result) => [JSON.stringify({ ...success, [members[0]]: { result } }), 1]),
    [JSON.stringify({ ...success, unknown: { result: "success" } }), 1],
    ["{}", 1], ["not-json", 1], ["", 1],
  ]) resultCommand(json, status, profileArgs);
  resultCommand(JSON.stringify(success), 0, ["--profile", profile]);
  const other = profile === "required" ? "postgres" : "required";
  resultCommand(JSON.stringify(success), 1, ["--profile", other]);
  for (const args of [["--profile"], ["--profile", "unknown"], ["--profile", ""], ["--profile", "full"], ["--full"], ["--profile", profile, "extra"]]) {
    resultCommand(JSON.stringify(success), 1, args);
  }
  for (const unknown of ["unknown", "full", "__proto__", null]) {
    assert.throws(() => requireSuccessfulGateResults(success, unknown));
  }
}

// PATH-only command doubles let the actual shell dispatch run without invoking
// Cargo, tools, databases or owning fixture scripts. All logs stay test-local.
const directory = mkdtempSync(join(tmpdir(), "sunrise-edge-ci-dispatch-"));
const logPath = join(directory, "commands.jsonl");
const realBash = "/bin/bash";
try {
  for (const tool of ["cargo", "rustfmt", "git", "node", "npm", "deno", "bash", "dirname", "basename"]) {
    const body = `#!${process.execPath}
const {appendFileSync,writeFileSync}=require('node:fs');
const {join}=require('node:path');
const {spawnSync}=require('node:child_process');
const tool=${JSON.stringify(tool)},args=process.argv.slice(2);
appendFileSync(process.env.CI_MOCK_LOG,JSON.stringify({tool,args,cwd:process.cwd()})+'\\n');
if(process.env.CI_MOCK_FAIL_TOOL===tool)process.exit(17);
if(process.env.CI_MOCK_FAIL_ARG&&args.includes(process.env.CI_MOCK_FAIL_ARG))process.exit(19);
const script=args[0]?.split('/').at(-1);
if(tool==='bash'&&(['check-fastvote-pg.sh','check-fee-escrow-inventory-pg.sh'].includes(script)
 ||(script==='check-postgres-soak.sh'&&!(args.length===2&&args[1]==='--self-test-cli'))
 ||(args[0]==='-c'&&args[1]==='run_phases'))){
 const child=spawnSync(${JSON.stringify(realBash)},args,{stdio:'inherit',env:process.env});
 process.exit(child.status??1);
}
if(tool==='cargo'&&args[0]==='test'&&args.includes('--ignored')&&args.includes('--list')){
 const name=args[args.indexOf('--')-1];
 if(name!==process.env.CI_MOCK_MISSING_TEST)console.log(name+': test');
 if(name===process.env.CI_MOCK_DUPLICATE_TEST)console.log(name+': test');
}
if(tool==='cargo'&&args[0]==='test'&&!args.includes('--list')&&args.includes(process.env.CI_MOCK_FAIL_TEST))process.exit(18);
// Only shell-dispatch sentinels, never authentic fixture material/test bodies.
if(tool==='cargo'&&args[0]==='test'&&!args.includes('--list')){
 if(args.includes('fee_claims::tests::certified_multi_escrow_inventory::export_certified_operator_fixture_postgres')){
  writeFileSync(join(process.env.SUNRISE_EDGE_ESCROW_FIXTURE_DIR,'validator_id.hex'),'0'.repeat(64)+'\\n');
 }
 if(args.includes('fast_path::soak_tests::live_postgres_certified_load_exports_recovery_handoff')){
  writeFileSync(join(process.env.SUNRISE_EDGE_SOAK_DIR,'handoff.kv'),'mock dispatch sentinel only\\n');
 }
}
`;
    writeFileSync(join(directory, tool), body, { flag: "wx", mode: 0o755 });
  }
  function runBash(args, overrides = {}) {
    writeFileSync(logPath, "");
    const result = spawnSync(realBash, args, {
      cwd: root, encoding: "utf8", timeout: 30_000,
      env: {
        PATH: `${directory}:/usr/bin:/bin`, CI_MOCK_LOG: logPath,
        GITHUB_ACTIONS: "true",
        ...overrides,
      },
    });
    assert.ifError(result.error);
    const text = readFileSync(logPath, "utf8").trim();
    return { ...result, log: text ? text.split("\n").map((row) => JSON.parse(row)) : [] };
  }
  function run(script, args = [], overrides = {}) {
    return runBash([join(root, script), ...args], overrides);
  }
  const functionScript = join(directory, "gate-function.sh");
  writeFileSync(functionScript, [
    "set -euo pipefail", 'source "$1"', 'source "$2"', "shift 2",
    'case "${CI_MOCK_FAIL_PREREQUISITE-}" in',
    "  ci_require_exact_ignored_test) ci_require_exact_ignored_test() { return 9; } ;;",
    "  ci_require_storage_neutral) ci_require_storage_neutral() { return 9; } ;;",
    "  ci_require_postgres) ci_require_postgres() { return 9; } ;;",
    "  ci_execution_profile) ci_execution_profile() { return 9; } ;;",
    "  ci_execution_plan) ci_execution_plan() { return 9; } ;;",
    '  "") ;;', "  *) exit 98 ;;", "esac",
    'if [[ "${CI_MOCK_DRAIN_ACTION_STDIN-}" == "1" ]]; then',
    '  ci_run_action() {',
    '    printf "ACTION:%s\\n" "$1"',
    '    while IFS= read -r consumed; do printf "UNEXPECTED_STDIN:%s\\n" "$consumed"; done',
    '    return 0',
    '  }',
    'fi',
    // An if condition disables errexit throughout nested functions, just as
    // the gate runner's OR-list does. Helpers must propagate returned errors.
    'if "$@"; then exit 0; else exit "$?"; fi', "",
  ].join("\n"), { flag: "wx", mode: 0o700 });
  function runFunction(fn, args = [], overrides = {}) {
    return runBash([functionScript, registry, execution, fn, ...args], overrides);
  }
  function passed(run) { assert.equal(run.status, 0, run.stderr); return run.log; }
  assert.deepEqual(passed(runFunction(":")), [], "sourcing the registry/recipes must not execute a gate");
  for (const [fn, args] of [
    ["ci_run_gate", []], ["ci_run_gate", ["unknown"]], ["ci_run_gate", ["required", "extra"]],
    ["ci_run_action", []], ["ci_run_action", ["unknown"]], ["ci_run_action", ["vectors; true"]],
    ["ci_run_action", ["gate-contract", "extra"]],
    ["ci_run_exact_ignored_test", []], ["ci_run_exact_ignored_test", ["name", "invalid", "--lib"]],
  ]) {
    const refused = runFunction(fn, args);
    assert.notEqual(refused.status, 0);
    assert.equal(refused.log.length, 0);
  }
  for (const [prerequisite, fn, args] of [
    ["ci_require_exact_ignored_test", "ci_check_sqlite_inventory", []],
    ["ci_require_exact_ignored_test", "ci_run_action", ["sqlite-inventory"]],
    ["ci_require_exact_ignored_test", "ci_run_exact_ignored_test", ["name", "yes", "-p", "node-core", "--lib"]],
    ["ci_require_storage_neutral", "ci_run_gate", ["required"]],
    ["ci_require_postgres", "ci_run_gate", ["full"]],
    ["ci_execution_profile", "ci_run_gate", ["required"]],
    ["ci_execution_plan", "ci_run_gate", ["required"]],
    ["ci_require_exact_ignored_test", "ci_run_required_extended_group", ["core-recurrence"]],
    ["ci_execution_profile", "ci_run_required_extended_group", ["core-recurrence"]],
    ["ci_execution_plan", "ci_run_required_extended_group", ["core-recurrence"]],
  ]) {
    const refused = runFunction(fn, args, { CI_MOCK_FAIL_PREREQUISITE: prerequisite });
    assert.equal(refused.status, 9, `${fn} must propagate ${prerequisite}'s returned failure`);
    assert.deepEqual(refused.log, [], `${fn} must not run a consumer after a failed prerequisite`);
  }
  const refusedInventory = runFunction("ci_run_gate", ["rust-tests"], { CI_MOCK_FAIL_PREREQUISITE: "ci_require_exact_ignored_test" });
  assert.equal(refusedInventory.status, 9);
  assert.deepEqual(refusedInventory.log.map(({ tool, args }) => [tool, args]), [[
    "cargo", ["test", "--workspace", "--all-targets", "--all-features", "--exclude", "runtime-postgres"],
  ]], "failed discovery must stop the nested gate before the inventory consumer");
  for (const group of groups) {
    const result = runFunction("ci_fastvote_pg_group_is_known", [group]);
    assert.equal(result.status, ["pg-lifecycle", "pg-drain-history", "pg-business-audit", "pg-recovery-economics"].includes(group) ? 0 : 1);
    assert.equal(result.log.length, 0);
  }
  for (const args of [[], ["all"], ["unknown"], ["pg-lifecycle", "extra"]]) {
    const result = runFunction("ci_fastvote_pg_group_is_known", args);
    assert.notEqual(result.status, 0);
    assert.equal(result.log.length, 0);
  }
  const pgEnvironment = { SUNRISE_EDGE_TEST_POSTGRES_URL: "mock-only" };
  // A recipe that drains its input must see EOF, never the coordinator's
  // remaining plan. Compare every real plan with independent expectations.
  for (const [selection, profile, actions] of expectedPlans) {
    const checked = runFunction("ci_run_gate", [selection], {
      ...(profile === "postgres" ? pgEnvironment : {}),
      CI_MOCK_DRAIN_ACTION_STDIN: "1",
    });
    assert.equal(checked.status, 0, checked.stderr);
    assert.deepEqual(checked.log, []);
    assert.deepEqual(checked.stdout.trim().split("\n"), actions.split(" ").map((action) => `ACTION:${action}`));
  }
  const unsafeExecution = join(directory, "unsafe-stdin-execution.sh");
  const safeExecutionText = readFileSync(execution, "utf8");
  const unsafeExecutionText = safeExecutionText.replace('ci_run_action "$action" </dev/null', 'ci_run_action "$action"');
  assert.notEqual(unsafeExecutionText, safeExecutionText);
  writeFileSync(unsafeExecution, unsafeExecutionText, { flag: "wx", mode: 0o700 });
  const drainedPlan = runBash([functionScript, registry, unsafeExecution, "ci_run_gate", "lint"], {
    CI_MOCK_DRAIN_ACTION_STDIN: "1",
  });
  assert.equal(drainedPlan.status, 0, drainedPlan.stderr);
  assert.deepEqual(drainedPlan.stdout.trim().split("\n"), [
    "ACTION:gate-contract", "UNEXPECTED_STDIN:rust-style", "UNEXPECTED_STDIN:diff-hygiene",
  ], "the negative control must reproduce skipped later actions, not certify itself");
  const required = passed(run("scripts/check-all.sh"));
  const full = passed(run("scripts/check-all.sh", ["--full"], pgEnvironment));
  const lanes = new Map(groups.map((group) => [group, passed(run("scripts/check-all.sh", ["--group", group], postgresGroups.includes(group) ? pgEnvironment : {}))]));
  const union = [...lanes.values()].flat();
  // An independent baseline stops deleting a gate from BOTH dispatch modes
  // from turning the union comparison below into a misleading success.
  assert.deepEqual(full.filter(({ tool, args }) => tool === "node" && args[0].endsWith("-vectors.mjs")).map(({ args }) => args[0]), [
    "call-value", "call-intent", "publication-submission", "local-execution",
    "call-authorization", "paid-execution", "fast-vote", "availability",
    "frozen-frontier", "drainset", "fast-path", "fastvote-apply-request",
    "fastvote-published-apply", "ordered-history", "business-cut", "business-import", "bond-registration", "conditional-readiness", "ordered-seal", "ordered-seal-successor", "successor-serving",
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
  assert.deepEqual(full.filter(({ tool, args }) => tool === "bash" && args[0].startsWith("scripts/")).map(({ args }) => args), [
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
  function ignoredName({ args }) {
    return args.find((arg) => [...expectedCases, ...auxiliary.map((row) => row[2]), ...recurringCases.map((row) => row[3])].includes(arg));
  }
  const expectedPgOrder = [...auxiliary.slice(1, 3).map((row) => row[2]), ...expectedCases, ...auxiliary.slice(3).map((row) => row[2])];
  const expectedIgnoredOrder = [...recurringCases.map((row) => row[3]), ...expectedPgOrder];
  assert.deepEqual(fullIgnored.map(ignoredName), expectedIgnoredOrder);
  assert.deepEqual(ignoredExecutions(union).map(ignoredName).sort(), [...expectedIgnoredOrder].sort());
  for (const log of [full, union]) {
    assert.deepEqual(ignoredExecutions(log).map(ignoredName).filter((name) => expectedCases.includes(name)), expectedCases);
  }
  assert.equal(ignoredExecutions(required).length, recurringCases.length);
  assert.deepEqual(ignoredExecutions(required).map(ignoredName).sort(), recurringCases.map((row) => row[3]).sort());
  assert.deepEqual(required.filter(({ tool, args }) => tool === "bash").map(({ args }) => args), [
    ["scripts/check-fee-escrow-inventory.sh"], ["scripts/check-postgres-soak.sh", "--self-test-cli"], ["scripts/build-cloudflare-validator.sh"],
  ]);
  assert.deepEqual(required.filter(({ tool, args }) => tool === "cargo" && args[0] === "test").map(({ args }) => args), [
    ["test", "--workspace", "--all-targets", "--all-features", "--exclude", "runtime-postgres"],
    ["test", "--quiet", "-p", "node-core", "--lib", auxiliary[0][2], "--", "--ignored", "--exact", "--list"],
    ["test", "--quiet", "-p", "node-core", "--lib", recurringCases[0][3], "--", "--ignored", "--exact", "--list"],
    ["test", "--quiet", "-p", "node-core", "--lib", recurringCases[0][3], "--", "--ignored", "--exact"],
    ["test", "--quiet", "-p", "sunrise-edge-operator", "--test", recurringCases[1][2], recurringCases[1][3], "--", "--ignored", "--exact", "--list"],
    ["test", "--quiet", "-p", "sunrise-edge-operator", "--test", recurringCases[1][2], recurringCases[1][3], "--", "--ignored", "--exact"],
  ]);
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
  for (const [group, pkg, target, name, capture] of recurringCases) {
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
  for (const [group, , name] of auxiliary) {
    const checks = lanes.get(group).filter(({ tool, args }) => tool === "cargo" && args.includes(name));
    assert.equal(checks.length, group === "rust-tests" ? 1 : 2, `${name} must retain its discovery/owning script`);
    assert(checks[0].args.includes("--list"));
    if (group !== "rust-tests") assert(checks[1].args.includes("--ignored") && checks[1].args.includes("--exact"));
  }
  function gateEvents(log) {
    return log.flatMap(({ tool, args, cwd }) => {
      if (tool === "cargo" && args[0] === "build") return [];
      if (tool === "cargo" && args.includes("--list")) return [];
      if (tool === "cargo" && args[0] === "test" && !args.includes("--ignored")) {
        if (args.includes("--workspace")) {
          assert.deepEqual(args, ["test", "--workspace", "--all-targets", "--all-features", ...(args.includes("--exclude") ? ["--exclude", "runtime-postgres"] : [])]);
          return args.includes("--exclude") ? ["rust-tests"] : ["rust-tests", "pg-storage"];
        }
        assert.deepEqual(args, ["test", "-p", "runtime-postgres", "-p", "sunrise-edge-operator", "-p", "sunrise-edge-cloudflare-validator", "-p", "sunrise-claim", "--all-targets", "--all-features", "--features", "sunrise-edge-cli/usb-hid"]);
        return ["pg-storage"];
      }
      if (tool === "bash" && args[0] === "scripts/check-fastvote-pg.sh") return [];
      if (tool === "bash" && args[0] === "-c" && args[1] === "run_phases") return [];
      return [JSON.stringify([tool, args, tool === "deno" ? relative(root, cwd) : ""])];
    }).sort();
  }
  assert.deepEqual(gateEvents(full), gateEvents(union));
  assert.deepEqual(gateEvents(required), gateEvents(requiredGroups.flatMap((group) => lanes.get(group))));
  const commonFull = full.filter(({ tool, args }) => !(
    (tool === "cargo" && args.some((arg) => expectedPgOrder.includes(arg))) ||
    (tool === "bash" && (args[0] === "scripts/check-fee-escrow-inventory-pg.sh" || args[0] === "scripts/check-fastvote-pg.sh" ||
      (args[0] === "scripts/check-postgres-soak.sh" && args[1] === "--smoke") || args[0] === "-c"))
  )).map((event) => event.tool === "cargo" && event.args[0] === "test" && event.args.includes("--workspace")
    ? { ...event, args: [...event.args, "--exclude", "runtime-postgres"] } : event);
  assert.deepEqual(gateEvents(required), gateEvents(commonFull));
  const storageEvent = lanes.get("pg-storage")[0];
  for (const anchor of ["runtime-postgres", "sunrise-edge-operator", "sunrise-edge-cloudflare-validator", "sunrise-claim"]) {
    const withoutAnchor = storageEvent.args.slice();
    const index = withoutAnchor.indexOf(anchor);
    assert(index > 0 && withoutAnchor[index - 1] === "-p");
    withoutAnchor.splice(index - 1, 2);
    assert.throws(() => gateEvents([{ ...storageEvent, args: withoutAnchor }]));
  }
  assert.deepEqual(lanes.get("rust-tests")[0].args, ["test", "--workspace", "--all-targets", "--all-features", "--exclude", "runtime-postgres"]);
  for (const group of ["pg-lifecycle", "pg-drain-history", "pg-business-audit", "pg-recovery-economics"]) {
    assert(lanes.get(group).some(({ tool, args }) => tool === "cargo" && args.includes("build") && args.includes("sunrise-edge-cli")));
  }
  assert(lanes.get("pg-business-audit").some(({ tool, args }) => tool === "cargo" && args.includes("build") && args.includes("business_audit_pg")));
  for (const script of ["scripts/check-all.sh", "scripts/check-fastvote-pg.sh"]) {
    for (const args of [["--group", "unknown"], ["--group"], ["--group", "all"], ["--group", ""], ["--group", "required"],
      ["--group", "full"], ["--group", "pg-lifecycle", "extra"], ["--full", "extra"], ["--full", "--group", "pg-storage"], ["--unknown"]]) {
      const failed = run(script, args, pgEnvironment);
      assert.notEqual(failed.status, 0);
      assert.equal(failed.log.length, 0);
    }
  }
  const pgRequests = [
    ["scripts/check-all.sh", ["--full"]],
    ...postgresGroups.map((group) => ["scripts/check-all.sh", ["--group", group]]),
    ["scripts/check-fastvote-pg.sh", []],
    ...postgresGroups.filter((group) => group !== "pg-storage").map((group) => ["scripts/check-fastvote-pg.sh", ["--group", group]]),
    ["scripts/check-fee-escrow-inventory-pg.sh", []], ["scripts/check-postgres-soak.sh", ["--smoke"]],
  ];
  for (const [script, args] of pgRequests) {
    for (const actions of ["true", ""]) {
      const failed = run(script, args, { GITHUB_ACTIONS: actions });
      assert.notEqual(failed.status, 0);
      assert.equal(failed.log.length, 0);
    }
  }
  for (const fault of faults) {
    for (const value of ["1", "", "0", "invalid"]) {
      for (const args of [[], ["--group", "pg-storage"]]) {
        const failed = run("scripts/check-all.sh", args, {
          GITHUB_ACTIONS: "", [`SUNRISE_EDGE_TEST_POSTGRES_${fault}_REQUIRED`]: value,
        });
        assert.notEqual(failed.status, 0);
        assert.equal(failed.log.length, 0);
      }
    }
  }
  for (const args of [[], ...requiredGroups.map((group) => ["--group", group])]) {
    for (const override of [pgEnvironment, { SUNRISE_EDGE_TEST_POSTGRES_URL: "" }, { SUNRISE_EDGE_TEST_POSTGRES_CONTAINER_ID: "" },
      { SUNRISE_EDGE_TEST_POSTGRES_DISK_FULL_IMAGE: "mock-only" }, { SUNRISE_EDGE_TEST_POSTGRES_UNKNOWN_SETTING: "1" }]) {
      const refused = run("scripts/check-all.sh", args, override);
      assert.notEqual(refused.status, 0);
      assert.equal(refused.log.length, 0);
    }
  }
  for (const name of expectedCases) {
    const group = cases.find((row) => row[3] === name)[0];
    const missing = run("scripts/check-all.sh", ["--group", group], { ...pgEnvironment, CI_MOCK_MISSING_TEST: name });
    assert.notEqual(missing.status, 0);
    assert(!ignoredExecutions(missing.log).some(({ args }) => args.includes(name)));
    assert.notEqual(run("scripts/check-all.sh", ["--group", group], { ...pgEnvironment, CI_MOCK_FAIL_TEST: name }).status, 0);
  }
  const missingCoreRecurrence = run("scripts/check-all.sh", ["--group", "core-recurrence"], { CI_MOCK_MISSING_TEST: recurringCases[0][3] });
  assert.notEqual(missingCoreRecurrence.status, 0);
  assert(!ignoredExecutions(missingCoreRecurrence.log).some((event) => ignoredName(event) === recurringCases[0][3]));
  assert.notEqual(run("scripts/check-all.sh", ["--group", "core-recurrence"], { CI_MOCK_FAIL_TEST: recurringCases[0][3] }).status, 0);
  const missingReadinessSqlite = run("scripts/check-all.sh", ["--group", "readiness-sqlite"], { CI_MOCK_MISSING_TEST: recurringCases[1][3] });
  assert.notEqual(missingReadinessSqlite.status, 0);
  assert(!ignoredExecutions(missingReadinessSqlite.log).some((event) => ignoredName(event) === recurringCases[1][3]));
  assert.notEqual(run("scripts/check-all.sh", ["--group", "readiness-sqlite"], { CI_MOCK_FAIL_TEST: recurringCases[1][3] }).status, 0);
  for (const [group, , , name] of recurringCases) {
    const duplicate = run("scripts/check-all.sh", ["--group", group], { CI_MOCK_DUPLICATE_TEST: name });
    assert.notEqual(duplicate.status, 0);
    assert.equal(ignoredExecutions(duplicate.log).length, 0, "ambiguous discovery must not execute a test");
  }
  for (const args of [[], ["unknown"], ["lint"], ["core-recurrence", "extra"]]) {
    const invalid = runFunction("ci_run_required_extended_group", args);
    assert.notEqual(invalid.status, 0);
    assert.deepEqual(invalid.log, []);
  }
  const requiredInventoryText = readFileSync(registry, "utf8");
  const requiredInventoryPattern = /readonly CI_REQUIRED_EXTENDED_CASES=\(\n[\s\S]*?\n\)/;
  const registryMutations = [
    [...recurringCases, recurringCases[0]],
    [...recurringCases, ["readiness-sqlite", ...recurringCases[0].slice(1)]],
    recurringCases.slice(1),
    [...recurringCases, ["unknown", ...recurringCases[0].slice(1)]],
    [...recurringCases, ["pg-storage", ...recurringCases[0].slice(1)]],
    [...recurringCases, [...recurringCases[0], "unexpected"]],
    [...recurringCases, [...recurringCases[0].slice(0, 4), "invalid"]],
  ];
  for (const [index, rows] of registryMutations.entries()) {
    const changedRegistry = requiredInventoryText.replace(requiredInventoryPattern,
      `readonly CI_REQUIRED_EXTENDED_CASES=(\n${rows.map((row) => `  '${row.join("|")}'`).join("\n")}\n)`);
    assert.notEqual(changedRegistry, requiredInventoryText);
    const changedRegistryPath = join(directory, `required-inventory-mutation-${index}.sh`);
    writeFileSync(changedRegistryPath, changedRegistry, { flag: "wx", mode: 0o600 });
    const refused = runBash([functionScript, changedRegistryPath, execution,
      "ci_run_required_extended_group", "core-recurrence"]);
    assert.notEqual(refused.status, 0);
    assert.deepEqual(refused.log, [], "invalid complete inventory must fail before any selected test");
  }
  for (const [group, , name] of auxiliary.slice(1)) {
    const missing = run("scripts/check-all.sh", ["--group", group], { ...pgEnvironment, CI_MOCK_MISSING_TEST: name });
    assert.notEqual(missing.status, 0);
    assert(!ignoredExecutions(missing.log).some((event) => ignoredName(event) === name));
    assert.notEqual(run("scripts/check-all.sh", ["--group", group], { ...pgEnvironment, CI_MOCK_FAIL_TEST: name }).status, 0);
  }
  for (const args of [[], ["--full"]]) {
    const failed = run("scripts/check-all.sh", args, { ...(args.length ? pgEnvironment : {}), CI_MOCK_FAIL_TOOL: "cargo" });
    assert.notEqual(failed.status, 0);
    assert(!failed.log.some(({ tool, args }) => tool === "bash" && args.includes("scripts/check-fee-escrow-inventory.sh")));
  }
  for (const [group, tool] of [
    ["rust-tests", "cargo"], ["pg-storage", "cargo"], ["lint", "rustfmt"],
    ["portable-tools", "node"], ["portable-tools", "deno"],
    ["cloudflare", "bash"], ["cloudflare", "npm"],
  ]) assert.notEqual(run("scripts/check-all.sh", ["--group", group], { ...(postgresGroups.includes(group) ? pgEnvironment : {}), CI_MOCK_FAIL_TOOL: tool }).status, 0);
  // Failures inside a multi-command recipe must not be hidden by its later
  // commands, even when the gate runner handles the recipe's return status.
  for (const [group, argument, forbidden] of [
    ["lint", "fmt", "rustfmt"], ["lint", "--edition", "clippy"], ["lint", "clippy", "git"],
    ["portable-tools", "scripts/drainset-vectors.mjs", "scripts/fast-path-vectors.mjs"],
  ]) {
    const failed = run("scripts/check-all.sh", ["--group", group], { CI_MOCK_FAIL_ARG: argument });
    assert.notEqual(failed.status, 0);
    assert(!failed.log.some(({ tool, args }) => tool === forbidden || args.includes(forbidden)));
  }
  const missingSqlite = run("scripts/check-all.sh", ["--group", "rust-tests"], { CI_MOCK_MISSING_TEST: auxiliary[0][2] });
  assert.notEqual(missingSqlite.status, 0);
  assert(!missingSqlite.log.some(({ tool }) => tool === "bash"));
  const selfTest = run("scripts/check-postgres-soak.sh", ["--self-test-cli"]);
  assert.equal(selfTest.status, 0, selfTest.stderr);
  assert(selfTest.stdout.includes("all CLI self-test cases passed"));
  assert.equal(selfTest.log.filter(({ tool }) => tool === "cargo").length, 0);
} finally {
  rmSync(directory, { recursive: true, force: true });
}
console.log("CI gate contract passed: 6 required lanes, 5 explicit PostgreSQL lanes, 19 retained plus 2 new required-recurrence ignored selectors, complete required/full coverage and fail-closed dispatch/results");
