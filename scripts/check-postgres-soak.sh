#!/usr/bin/env bash
set -euo pipefail

# DR-0146: bounded certified PostgreSQL load and recovery harness driver.
# Runs the core certified-load workload test, then the operator recovery
# reader test, against one disposable loopback `sunrise_edge_test` service.
# A completed run is evidence, not a network-capacity or soak certification.

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

# ---- --self-test-cli: fast, DB-free regression check of this script's own
# argument/bounds validation. Never touches PostgreSQL or cargo. Kept first
# and independent of everything else below. ----
self_test_failures=0

self_test_case() {
  local description="$1" expected="$2"
  shift 2
  local -a envs=()
  while [[ "$1" != "--" ]]; do
    envs+=("$1")
    shift
  done
  shift
  local actual=0
  env -u SUNRISE_EDGE_TEST_POSTGRES_URL -u SUNRISE_EDGE_SOAK_ESCROWS -u SUNRISE_EDGE_SOAK_SENDERS \
    -u SUNRISE_EDGE_SOAK_CLAIM_WRITERS -u SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC \
    -u SUNRISE_EDGE_SOAK_DURATION_SECONDS -u SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS \
    -u SUNRISE_EDGE_SOAK_RECOVERY_CYCLES -u SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE -u GITHUB_ACTIONS \
    "${envs[@]}" bash "$0" "$@" >/dev/null 2>&1 || actual=$?
  if [[ "$actual" -eq "$expected" ]]; then
    echo "self-test ok: $description"
  else
    echo "self-test FAILED: $description (expected exit $expected, got $actual)" >&2
    self_test_failures=$((self_test_failures + 1))
  fi
}

run_cli_self_tests() {
  self_test_case "extra arguments after --self-test-cli are rejected" 1 -- --self-test-cli --smoke
  self_test_case "no arguments is a usage error" 1 --
  self_test_case "unknown flag is rejected" 1 -- --bogus
  self_test_case "both --smoke and --run is rejected" 1 -- --smoke --run
  self_test_case "--run missing vars is rejected without a PG URL configured" 1 -- --run
  self_test_case "--run senders exceeding escrows is rejected" 1 \
    SUNRISE_EDGE_SOAK_ESCROWS=4 SUNRISE_EDGE_SOAK_SENDERS=8 SUNRISE_EDGE_SOAK_CLAIM_WRITERS=2 \
    SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC=8 SUNRISE_EDGE_SOAK_DURATION_SECONDS=10 \
    SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS=20 SUNRISE_EDGE_SOAK_RECOVERY_CYCLES=1 \
    SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE=1 -- --run
  self_test_case "--run without disposable confirmation is rejected" 1 \
    SUNRISE_EDGE_SOAK_ESCROWS=4 SUNRISE_EDGE_SOAK_SENDERS=2 SUNRISE_EDGE_SOAK_CLAIM_WRITERS=2 \
    SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC=8 SUNRISE_EDGE_SOAK_DURATION_SECONDS=10 \
    SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS=20 SUNRISE_EDGE_SOAK_RECOVERY_CYCLES=1 -- --run
  self_test_case "--run leading-zero escrows count is rejected" 1 \
    SUNRISE_EDGE_SOAK_ESCROWS=04 SUNRISE_EDGE_SOAK_SENDERS=2 SUNRISE_EDGE_SOAK_CLAIM_WRITERS=2 \
    SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC=8 SUNRISE_EDGE_SOAK_DURATION_SECONDS=10 \
    SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS=20 SUNRISE_EDGE_SOAK_RECOVERY_CYCLES=1 \
    SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE=1 -- --run
  self_test_case "--run overlong escrows digit string is rejected before arithmetic" 1 \
    SUNRISE_EDGE_SOAK_ESCROWS=99999999999999999999 SUNRISE_EDGE_SOAK_SENDERS=2 \
    SUNRISE_EDGE_SOAK_CLAIM_WRITERS=2 SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC=8 \
    SUNRISE_EDGE_SOAK_DURATION_SECONDS=10 SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS=20 \
    SUNRISE_EDGE_SOAK_RECOVERY_CYCLES=1 SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE=1 -- --run
  self_test_case "--smoke with no PG URL configured cleanly skips" 0 -- --smoke
  self_test_case "--smoke with no PG URL configured errors under GITHUB_ACTIONS" 1 \
    GITHUB_ACTIONS=true -- --smoke
  self_test_case "--run with valid bounded vars and no PG URL configured errors, never skips" 1 \
    SUNRISE_EDGE_SOAK_ESCROWS=4 SUNRISE_EDGE_SOAK_SENDERS=2 SUNRISE_EDGE_SOAK_CLAIM_WRITERS=2 \
    SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC=8 SUNRISE_EDGE_SOAK_DURATION_SECONDS=10 \
    SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS=20 SUNRISE_EDGE_SOAK_RECOVERY_CYCLES=1 \
    SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE=1 -- --run

  if [[ "$self_test_failures" -ne 0 ]]; then
    echo "$self_test_failures CLI self-test case(s) failed" >&2
    exit 1
  fi
  echo "all CLI self-test cases passed"
}

if [[ "${1:-}" == "--self-test-cli" ]]; then
  if [[ "$#" -ne 1 ]]; then
    echo "--self-test-cli accepts no additional arguments" >&2
    exit 1
  fi
  run_cli_self_tests
  exit 0
fi

# ---- argument and (for --run) bounds/confirmation validation happens
# before the PG-URL gate below: an invalid invocation must fail closed
# regardless of whether a live PostgreSQL service happens to be configured,
# never silently "succeed" via the unset-PG-URL skip path. ----
mode=""
for arg in "$@"; do
  case "$arg" in
    --smoke|--run)
      if [[ -n "$mode" ]]; then
        echo "specify exactly one of --smoke or --run" >&2
        exit 1
      fi
      mode="${arg#--}"
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done
if [[ -z "$mode" ]]; then
  echo "usage: $(basename "$0") --smoke|--run" >&2
  exit 1
fi

require_bounded_int() {
  local name="$1" value="$2" min="$3" max="$4"
  # Bound the canonical decimal length (at most 10 digits, no leading zero
  # unless the value is exactly "0") BEFORE any Bash arithmetic: an
  # arbitrarily long digit string could overflow Bash's 64-bit `(( ))`
  # arithmetic and wrap to a value that wrongly passes the bounds check
  # below, and a leading-zero form is never treated as an implicit bypass.
  if ! [[ "$value" =~ ^(0|[1-9][0-9]{0,9})$ ]]; then
    echo "invalid $name: ${value:-<unset>} (must be a canonical decimal integer, no leading zero, at most 10 digits)" >&2
    exit 1
  fi
  if (( 10#$value < min || 10#$value > max )); then
    echo "$name=$value out of bounds [$min, $max]" >&2
    exit 1
  fi
}

if [[ "$mode" == "run" ]]; then
  for name in ESCROWS SENDERS CLAIM_WRITERS MAX_CLAIM_RATE_PER_SEC DURATION_SECONDS \
    WALL_DEADLINE_SECONDS RECOVERY_CYCLES; do
    var="SUNRISE_EDGE_SOAK_${name}"
    if [[ -z "${!var:-}" ]]; then
      echo "--run requires $var to be set explicitly" >&2
      exit 1
    fi
  done
  if [[ "${SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE:-}" != "1" ]]; then
    echo "--run requires SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE=1, confirming this targets only a disposable loopback sunrise_edge_test service" >&2
    exit 1
  fi
  require_bounded_int SUNRISE_EDGE_SOAK_ESCROWS "$SUNRISE_EDGE_SOAK_ESCROWS" 1 4096
  require_bounded_int SUNRISE_EDGE_SOAK_SENDERS "$SUNRISE_EDGE_SOAK_SENDERS" 1 64
  if (( 10#$SUNRISE_EDGE_SOAK_SENDERS > 10#$SUNRISE_EDGE_SOAK_ESCROWS )); then
    echo "SUNRISE_EDGE_SOAK_SENDERS must not exceed SUNRISE_EDGE_SOAK_ESCROWS" >&2
    exit 1
  fi
  require_bounded_int SUNRISE_EDGE_SOAK_CLAIM_WRITERS "$SUNRISE_EDGE_SOAK_CLAIM_WRITERS" 1 16
  require_bounded_int SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC "$SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC" 1 1000
  require_bounded_int SUNRISE_EDGE_SOAK_DURATION_SECONDS "$SUNRISE_EDGE_SOAK_DURATION_SECONDS" 1 21600
  require_bounded_int SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS "$SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS" 1 25200
  if (( 10#$SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS <= 10#$SUNRISE_EDGE_SOAK_DURATION_SECONDS )); then
    echo "SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS must exceed SUNRISE_EDGE_SOAK_DURATION_SECONDS" >&2
    exit 1
  fi
  require_bounded_int SUNRISE_EDGE_SOAK_RECOVERY_CYCLES "$SUNRISE_EDGE_SOAK_RECOVERY_CYCLES" 1 32
fi

# Mirrors check-all.sh's own top-of-file rule: CI must exercise this against
# the live PostgreSQL service; local checks may run without one and skip.
# Reached only once the invocation itself is already known to be valid. Only
# `--smoke` may skip locally: a manual `--run` is a deliberate, explicit
# long-run invocation and an unconfigured target is always a hard error.
if [[ -z "${SUNRISE_EDGE_TEST_POSTGRES_URL:-}" ]]; then
  if [[ "$mode" == "run" ]]; then
    echo "--run requires SUNRISE_EDGE_TEST_POSTGRES_URL to be set to a disposable loopback PostgreSQL service" >&2
    exit 1
  fi
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "CI requires SUNRISE_EDGE_TEST_POSTGRES_URL for the PostgreSQL certified load/recovery harness" >&2
    exit 1
  fi
  echo "skipping PostgreSQL certified load/recovery harness: SUNRISE_EDGE_TEST_POSTGRES_URL is unset"
  exit 0
fi

if [[ "$mode" == "smoke" ]]; then
  # Fixed, bounded CI/quick-check profile. Deliberately overrides any
  # long-run sizing already present in the caller's shell: CI must never
  # silently inherit operator long-run vars.
  export SUNRISE_EDGE_SOAK_ESCROWS=8
  export SUNRISE_EDGE_SOAK_SENDERS=2
  export SUNRISE_EDGE_SOAK_CLAIM_WRITERS=2
  export SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC=32
  export SUNRISE_EDGE_SOAK_DURATION_SECONDS=90
  export SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS=180
  export SUNRISE_EDGE_SOAK_RECOVERY_CYCLES=2
  export SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE=1
fi

soak_dir="$(mktemp -d "${TMPDIR:-/tmp}/sunrise-edge-soak-pg.XXXXXXXX")"
cleanup() {
  if [[ -n "$soak_dir" && -d "$soak_dir" ]]; then
    rm -rf -- "$soak_dir"
  fi
}
trap cleanup EXIT
export SUNRISE_EDGE_SOAK_DIR="$soak_dir"

require_exact_test() {
  local test_name="$1"
  shift
  if ! cargo test --quiet "$@" "$test_name" -- --ignored --list | grep -Fqx "$test_name: test"; then
    echo "missing expected PostgreSQL soak test: $test_name" >&2
    exit 1
  fi
}
export -f require_exact_test

run_phases() {
  set -euo pipefail
  require_exact_test \
    fast_path::soak_tests::live_postgres_certified_load_exports_recovery_handoff \
    -p node-core --lib
  cargo test --quiet -p node-core --lib \
    fast_path::soak_tests::live_postgres_certified_load_exports_recovery_handoff \
    -- --ignored --exact --nocapture

  if [[ ! -f "$SUNRISE_EDGE_SOAK_DIR/handoff.kv" ]]; then
    echo "certified load workload did not publish handoff.kv" >&2
    exit 1
  fi

  require_exact_test fee_escrow_soak_recovery_pg_operator_e2e \
    -p sunrise-edge-operator --test fee_escrow_soak_recovery_pg_e2e
  cargo test --quiet -p sunrise-edge-operator --test fee_escrow_soak_recovery_pg_e2e \
    -- --ignored --exact --nocapture fee_escrow_soak_recovery_pg_operator_e2e
}
export -f run_phases

# One whole-run deadline over both phases and their exact-test checks: the
# harness must finish every planned unit before success, never "succeed" on
# a partial, deadline-truncated run.
if ! timeout --kill-after=30 "${SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS}s" bash -c run_phases; then
  echo "PostgreSQL certified load/recovery harness failed or exceeded its wall deadline" >&2
  exit 1
fi

echo "sunrise_edge_soak_v1 kind=totals complete=true mode=${mode} escrows=${SUNRISE_EDGE_SOAK_ESCROWS} recovery_cycles=${SUNRISE_EDGE_SOAK_RECOVERY_CYCLES}"
