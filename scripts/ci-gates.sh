#!/usr/bin/env bash
# Closed selection | prerequisite profile | ordered action IDs.
# Sourcing this file only defines the registry and its read-only interface.
# Full preserves the former serial order and full-workspace feature union;
# it is deliberately not concatenation of the isolated CI lane plans.
readonly CI_EXECUTION_PLANS=(
  'required|required|gate-contract rust-style rust-tests-required sqlite-inventory core-recurrence readiness-sqlite recurring-sqlite soak-cli vectors cloudflare-build cloudflare-check deno-adapters diff-hygiene'
  'full|postgres|gate-contract rust-style rust-tests-full sqlite-inventory core-recurrence readiness-sqlite recurring-sqlite pg-inventory pg-protocol-all soak-cli pg-soak vectors cloudflare-build cloudflare-check deno-adapters diff-hygiene'
  'lint|required|gate-contract rust-style diff-hygiene'
  'rust-tests|required|rust-tests-required sqlite-inventory'
  'pg-storage|postgres|pg-storage-tests'
  'pg-lifecycle|postgres|pg-protocol-lifecycle'
  'pg-drain-history|postgres|pg-protocol-drain-history'
  'pg-business-audit|postgres|pg-protocol-business-audit'
  'pg-recovery-economics|postgres|pg-inventory pg-protocol-recovery-economics pg-soak'
  'portable-tools|required|soak-cli vectors deno-adapters'
  'cloudflare|required|cloudflare-build cloudflare-check'
  'core-recurrence|required|core-recurrence'
  'readiness-sqlite|required|readiness-sqlite'
  'recurring-sqlite|required|recurring-sqlite'
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

# Each row documents one unconditional (never PostgreSQL-gated) required-lane
# owner: one whole group, its package/target and its exact ignored selector.
# `ci_run_required_extended_group` in ci-execution.sh is the sole dispatcher
# for every row here, reusing the existing `ci_run_exact_ignored_test`
# discovery/execution helper, never a second engine. It rejects an unknown
# or empty group and a group whose rows duplicate one exact selector before
# running any test. Extending coverage for a dependent branch's new ignored
# case is exactly one appended row here plus that case's own `#[ignore]`
# attribute; it is never inferred from an absent selector.
readonly CI_REQUIRED_EXTENDED_CASES=(
  'core-recurrence|node-core|--lib|ordered_economics::tests::causal_placement::control_reconstruction::frozen_completion::successor_activation::successor_recurring_delay::genuine_recurring_sqlite_handoffs_reach_configured_seven_epoch_withdrawal_unlock|no'
  'readiness-sqlite|sunrise-edge-operator|conditional_readiness_sqlite|compiled_conditional_readiness_real_retention_restart_and_distinct_certificate|no'
  'recurring-sqlite|sunrise-edge-operator|conditional_readiness_sqlite|compiled_registered_replacement_and_recurring_successor_hosts|no'
)

ci_gate_groups() {
  if [[ "$#" -gt 1 ]]; then
    echo 'unknown repository gate profile' >&2
    return 1
  fi
  local requested_profile="${1-required}"
  case "$requested_profile" in
    required|postgres) ;;
    *) echo 'unknown repository gate profile' >&2; return 1 ;;
  esac
  local row selection profile actions
  for row in "${CI_EXECUTION_PLANS[@]}"; do
    IFS='|' read -r selection profile actions <<< "$row"
    if [[ "$selection" != required && "$selection" != full && "$profile" == "$requested_profile" ]]; then
      printf '%s\n' "$selection"
    fi
  done
}

ci_plan_row() {
  if [[ "$#" -ne 1 ]]; then
    echo 'unknown repository gate selection' >&2
    return 1
  fi
  local row selection profile actions
  for row in "${CI_EXECUTION_PLANS[@]}"; do
    IFS='|' read -r selection profile actions <<< "$row"
    if [[ "$selection" == "$1" ]]; then
      printf '%s\n' "$row"
      return 0
    fi
  done
  echo 'unknown repository gate selection' >&2
  return 1
}

ci_group_is_known() {
  [[ "$#" -eq 1 && "$1" != required && "$1" != full ]] || return 1
  ci_plan_row "$1" >/dev/null
}

ci_execution_profile() {
  local row selection profile actions
  row="$(ci_plan_row "$@")" || return 1
  IFS='|' read -r selection profile actions <<< "$row"
  printf '%s\n' "$profile"
}

ci_execution_plan() {
  local row selection profile actions
  local -a action_ids=()
  row="$(ci_plan_row "$@")" || return 1
  IFS='|' read -r selection profile actions <<< "$row"
  read -r -a action_ids <<< "$actions"
  printf '%s\n' "${action_ids[@]}"
}

ci_fastvote_pg_group_is_known() {
  [[ "$#" -eq 1 ]] || return 1
  ci_group_is_known "$1" || return 1
  local row
  for row in "${CI_FASTVOTE_PG_CASES[@]}"; do
    if [[ "${row%%|*}" == "$1" ]]; then
      return 0
    fi
  done
  return 1
}

ci_require_postgres() {
  if [[ -n "${SUNRISE_EDGE_TEST_POSTGRES_URL:-}" ]]; then
    return 0
  fi
  echo 'explicit PostgreSQL gates require SUNRISE_EDGE_TEST_POSTGRES_URL' >&2
  exit 1
}

ci_require_storage_neutral() {
  local variable
  # Reject even empty/unknown test-PG settings instead of inheriting a partial
  # database profile. Explicit --full and PG groups select that profile.
  for variable in ${!SUNRISE_EDGE_TEST_POSTGRES_@}; do
    echo 'required gates refuse PostgreSQL configuration; select --full or a PG group' >&2
    exit 1
  done
}
