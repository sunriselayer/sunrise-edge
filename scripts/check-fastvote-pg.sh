#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

# Mirrors check-all.sh's own top-of-file rule: CI must exercise this against
# the live PostgreSQL service; local checks may run without one and skip.
if [[ -z "${SUNRISE_EDGE_TEST_POSTGRES_URL:-}" ]]; then
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "CI requires SUNRISE_EDGE_TEST_POSTGRES_URL for the PostgreSQL fastvote_pg multi-validator operator E2E" >&2
    exit 1
  fi
  echo "skipping PostgreSQL fastvote_pg multi-validator operator E2E: SUNRISE_EDGE_TEST_POSTGRES_URL is unset"
  exit 0
fi

require_exact_test() {
  local test_name="$1"
  shift
  if ! cargo test --quiet "$@" "$test_name" -- --list | grep -Fqx "$test_name: test"; then
    echo "missing expected PostgreSQL FastVote test: $test_name" >&2
    exit 1
  fi
}

require_exact_test fastvote_pg_operator_multivalidator_e2e \
  -p sunrise-edge-operator --test fastvote_pg_e2e
cargo test --quiet -p sunrise-edge-operator --test fastvote_pg_e2e \
  -- --ignored --exact fastvote_pg_operator_multivalidator_e2e

require_exact_test fastvote_pg_operator_credential_isolated_multivalidator_e2e \
  -p sunrise-edge-operator --test fastvote_pg_credential_isolation_e2e
cargo test --quiet -p sunrise-edge-operator --test fastvote_pg_credential_isolation_e2e \
  -- --ignored --exact fastvote_pg_operator_credential_isolated_multivalidator_e2e

require_exact_test fast_path::capacity_tests::live_postgres::live_postgres_concurrent_zero_share_claims_measure_retained_bytes_and_reopen_latency \
  -p node-core --lib
cargo test --quiet -p node-core --lib \
  fast_path::capacity_tests::live_postgres::live_postgres_concurrent_zero_share_claims_measure_retained_bytes_and_reopen_latency \
  -- --ignored --exact --nocapture
require_exact_test fast_path::capacity_tests::live_postgres::live_postgres_concurrent_positive_claims_measure_retained_bytes_and_writer_fence_recovery \
  -p node-core --lib
cargo test --quiet -p node-core --lib \
  fast_path::capacity_tests::live_postgres::live_postgres_concurrent_positive_claims_measure_retained_bytes_and_writer_fence_recovery \
  -- --ignored --exact --nocapture

echo "live PostgreSQL FastVote multi-validator, credential-isolation and bounded fee-claim capacity E2Es passed"
