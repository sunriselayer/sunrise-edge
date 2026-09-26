#!/usr/bin/env bash
set -euo pipefail

# DR-0146: bounded certified PostgreSQL load and recovery harness driver.
# Runs the core certified-load workload test, then the operator recovery
# reader test, against one disposable loopback `sunrise_edge_test` service.
# A completed run is evidence, not a network-capacity or soak certification.

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

# Mirrors check-all.sh's own top-of-file rule: CI must exercise this against
# the live PostgreSQL service; local checks may run without one and skip.
if [[ -z "${SUNRISE_EDGE_TEST_POSTGRES_URL:-}" ]]; then
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "CI requires SUNRISE_EDGE_TEST_POSTGRES_URL for the PostgreSQL certified load/recovery harness" >&2
    exit 1
  fi
  echo "skipping PostgreSQL certified load/recovery harness: SUNRISE_EDGE_TEST_POSTGRES_URL is unset"
  exit 0
fi

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
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "invalid $name: ${value:-<unset>}" >&2
    exit 1
  fi
  if (( 10#$value < min || 10#$value > max )); then
    echo "$name=$value out of bounds [$min, $max]" >&2
    exit 1
  fi
}

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
else
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
# harness must finish every planned unit before success, never "succeed"
# on a partial, deadline-truncated run.
if ! timeout --kill-after=30 "${SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS}s" bash -c run_phases; then
  echo "PostgreSQL certified load/recovery harness failed or exceeded its wall deadline" >&2
  exit 1
fi

echo "sunrise_edge_soak_v1 kind=totals complete=true mode=${mode} escrows=${SUNRISE_EDGE_SOAK_ESCROWS} recovery_cycles=${SUNRISE_EDGE_SOAK_RECOVERY_CYCLES}"
