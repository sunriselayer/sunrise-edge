#!/usr/bin/env bash
# Closed repository gate membership. Sourcing this file never runs a gate.
readonly CI_GATE_GROUPS=(
  lint rust-tests pg-storage pg-lifecycle pg-drain-history pg-business-audit
  pg-recovery-economics portable-tools cloudflare
)

# group | package | existing test target (or --lib) | exact ignored name | nocapture
readonly CI_FASTVOTE_PG_CASES=(
  'pg-lifecycle|sunrise-edge-operator|fastvote_pg_e2e|fastvote_pg_operator_multivalidator_e2e|no'
  'pg-lifecycle|sunrise-edge-operator|fastvote_pg_credential_isolation_e2e|fastvote_pg_operator_credential_isolated_multivalidator_e2e|no'
  'pg-lifecycle|sunrise-edge-operator|fastvote_host_pg_cli_e2e|fastvote_host_pg_cli_multivalidator_e2e|no'
  'pg-lifecycle|sunrise-edge-operator|contract_lifecycle_pg_e2e|contract_lifecycle_pg_publish_instantiate_call_and_asset_verbs_multivalidator_e2e|no'
  'pg-lifecycle|sunrise-edge-operator|contract_lifecycle_pg_e2e|contract_lifecycle_pg_logical_publish_instantiate_call_and_asset_verbs_multivalidator_e2e|no'
  'pg-lifecycle|sunrise-edge-operator|contract_lifecycle_pg_e2e|contract_lifecycle_pg_ordered_freeze_and_frontier_binary_cli_e2e|no'
  'pg-drain-history|sunrise-edge-operator|contract_lifecycle_pg_e2e|contract_lifecycle_pg_drainset_member_and_ordered_history_binary_cli_e2e|no'
  'pg-business-audit|sunrise-edge-operator|business_audit_pg_e2e|business_audit_pg_genuine_causal_history_reopen_and_corruption_e2e|yes'
  'pg-recovery-economics|sunrise-edge-operator|certified_catch_up_pg_e2e|certified_catch_up_pg_missed_prepare_binary_cli_e2e|no'
  'pg-recovery-economics|sunrise-edge-operator|contract_lifecycle_catch_up_pg_e2e|contract_lifecycle_catch_up_pg_missed_publish_instantiate_call_binary_cli_e2e|no'
  'pg-recovery-economics|sunrise-edge-operator|economics_pg_e2e|economics_pg_offline_signed_claim_workflow_e2e|no'
  'pg-recovery-economics|sunrise-edge-operator|ordered_economics_network_pg_e2e|ordered_economics_network_four_namespace_competing_claims_e2e|no'
  'pg-recovery-economics|node-core|--lib|fast_path::capacity_tests::live_postgres::live_postgres_concurrent_zero_share_claims_measure_retained_bytes_and_reopen_latency|yes'
  'pg-recovery-economics|node-core|--lib|fast_path::capacity_tests::live_postgres::live_postgres_concurrent_positive_claims_measure_retained_bytes_and_writer_fence_recovery|yes'
)

# These paired fixtures stay inside their existing owning scripts, not separate jobs.
readonly CI_AUXILIARY_IGNORED_CASES=(
  'rust-tests|scripts/check-fee-escrow-inventory.sh|fee_claims::tests::certified_multi_escrow_inventory::export_certified_operator_fixture'
  'pg-recovery-economics|scripts/check-fee-escrow-inventory-pg.sh|fee_claims::tests::certified_multi_escrow_inventory::export_certified_operator_fixture_postgres'
  'pg-recovery-economics|scripts/check-fee-escrow-inventory-pg.sh|fee_escrow_inventory_pg_operator_e2e'
  'pg-recovery-economics|scripts/check-postgres-soak.sh|fast_path::soak_tests::live_postgres_certified_load_exports_recovery_handoff'
  'pg-recovery-economics|scripts/check-postgres-soak.sh|fee_escrow_soak_recovery_pg_operator_e2e'
)

ci_gate_groups() {
  printf '%s\n' "${CI_GATE_GROUPS[@]}"
}

ci_group_is_known() {
  local group
  for group in "${CI_GATE_GROUPS[@]}"; do
    if [[ "$group" == "$1" ]]; then
      return 0
    fi
  done
  return 1
}

ci_require_postgres() {
  if [[ -n "${SUNRISE_EDGE_TEST_POSTGRES_URL:-}" ]]; then
    return 0
  fi
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo 'CI requires SUNRISE_EDGE_TEST_POSTGRES_URL for live PostgreSQL gates' >&2
    exit 1
  fi
  echo 'skipping live PostgreSQL gate: SUNRISE_EDGE_TEST_POSTGRES_URL is unset'
  return 1
}

ci_require_exact_ignored_test() {
  local test_name="$1"
  shift
  if ! cargo test --quiet "$@" "$test_name" -- --ignored --list | grep -Fqx "$test_name: test"; then
    echo "missing expected ignored repository test: $test_name" >&2
    exit 1
  fi
}
