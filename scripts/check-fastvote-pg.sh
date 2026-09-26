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
  if ! cargo test --quiet "$@" "$test_name" -- --ignored --list | grep -Fqx "$test_name: test"; then
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

require_exact_test fastvote_host_pg_cli_multivalidator_e2e \
  -p sunrise-edge-operator --test fastvote_host_pg_cli_e2e
cargo test --quiet -p sunrise-edge-operator --test fastvote_host_pg_cli_e2e \
  -- --ignored --exact fastvote_host_pg_cli_multivalidator_e2e

# Both the lifecycle submission E2E and the catch-up E2E below execute the
# actual separately compiled CLI binary as a subprocess, never its library
# entrypoint. Cargo puts it beside the test binary's own deps directory even
# when CARGO_TARGET_DIR is explicitly configured, so it must be built once,
# before either of them runs.
cargo build --quiet -p sunrise-edge-cli --bin sunrise-edge-cli

# DR-0151 delivery 1: real user-selected paid-publish -> paid-instantiate ->
# paid-call plus ordinary Standard Asset create/transfer/split/merge/mint/burn,
# all over --fastvote-network, driven through the compiled sunrise-edge-cli
# binary.
require_exact_test contract_lifecycle_pg_publish_instantiate_call_and_asset_verbs_multivalidator_e2e \
  -p sunrise-edge-operator --test contract_lifecycle_pg_e2e
cargo test --quiet -p sunrise-edge-operator --test contract_lifecycle_pg_e2e \
  -- --ignored --exact contract_lifecycle_pg_publish_instantiate_call_and_asset_verbs_multivalidator_e2e

require_exact_test certified_catch_up_pg_missed_prepare_binary_cli_e2e \
  -p sunrise-edge-operator --test certified_catch_up_pg_e2e
cargo test --quiet -p sunrise-edge-operator --test certified_catch_up_pg_e2e \
  -- --ignored --exact certified_catch_up_pg_missed_prepare_binary_cli_e2e

# DR-0151 delivery 1: recovers a validator kept offline from before the first
# publish through the full declared Publish -> Instantiate -> asset-verb ->
# charged-trap lifecycle via the compiled CLI's signerless fastvote-catch-up,
# also proving same-boot and real host-restart idempotent replay, prefix
# commits on a wrong-dependency-order manifest, and pre-POST rejection of an
# output collision or mismatched protocol pins.
require_exact_test contract_lifecycle_catch_up_pg_missed_publish_instantiate_call_binary_cli_e2e \
  -p sunrise-edge-operator --test contract_lifecycle_catch_up_pg_e2e
cargo test --quiet -p sunrise-edge-operator --test contract_lifecycle_catch_up_pg_e2e \
  -- --ignored --exact contract_lifecycle_catch_up_pg_missed_publish_instantiate_call_binary_cli_e2e

require_exact_test economics_pg_offline_signed_claim_workflow_e2e \
  -p sunrise-edge-operator --test economics_pg_e2e
cargo test --quiet -p sunrise-edge-operator --test economics_pg_e2e \
  -- --ignored --exact economics_pg_offline_signed_claim_workflow_e2e

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

echo "live PostgreSQL FastVote multi-validator, credential-isolation, real-CLI host-serving and bounded fee-claim capacity E2Es passed"
