#!/usr/bin/env bash
# Owning recipes for the closed action IDs in ci-gates.sh. Sourcing never
# executes a gate. Callers supply their repository cwd and source the registry.

ci_require_exact_ignored_test() {
  local test_name="$1"
  shift
  local listed test_line matches=0
  listed="$(cargo test --quiet "$@" "$test_name" -- --ignored --exact --list)" || return "$?"
  while IFS= read -r test_line; do
    if [[ "$test_line" == "$test_name: test" ]]; then
      matches=$((matches + 1))
    fi
  done <<< "$listed"
  if [[ "$matches" -ne 1 ]]; then
    echo "expected exactly one ignored repository test: $test_name (found $matches)" >&2
    return 1
  fi
}

# The selector, capture policy and Cargo target are supplied by the owning
# fixture script/closed registry, never an evaluated command string. Producer
# environment, artifact checks and whole-run deadlines stay with that owner.
ci_run_exact_ignored_test() {
  if [[ "$#" -lt 3 || -z "$1" ]]; then
    echo 'malformed exact ignored-test request' >&2
    return 1
  fi
  local test_name="$1" nocapture="$2"
  local -a test_args=(--ignored --exact)
  case "$nocapture" in
    yes) test_args+=(--nocapture) ;;
    no) ;;
    *) echo 'invalid ignored-test capture policy' >&2; return 1 ;;
  esac
  shift 2
  ci_require_exact_ignored_test "$test_name" "$@" || return "$?"
  cargo test --quiet "$@" "$test_name" -- "${test_args[@]}"
}

ci_check_rust_style() {
  cargo fmt --all -- --check || return "$?"
  rustfmt --edition 2024 --check \
    crates/node-core/src/tests/core_and_nonce.rs \
    crates/node-core/src/tests/durable_object_support.rs \
    crates/node-core/src/tests/authenticated_objects.rs \
    crates/node-core/src/tests/preinstalled_support.rs \
    crates/node-core/src/tests/preinstalled_execution.rs \
    crates/node-core/src/tests/durable_handlers.rs \
    crates/node-core/src/tests/queries.rs \
    crates/node-core/src/tests/fees.rs \
    crates/execution/tests/paid_execution_engine/fixture.rs \
    crates/execution/tests/paid_execution_engine/call.rs \
    crates/execution/tests/paid_execution_engine/publish.rs \
    crates/execution/tests/paid_execution_engine/verify.rs \
    crates/execution/tests/paid_execution_engine/codec.rs || return "$?"
  cargo clippy --workspace --all-targets --all-features -- -D warnings
}

ci_check_sqlite_inventory() {
  ci_require_exact_ignored_test \
    fee_claims::tests::certified_multi_escrow_inventory::export_certified_operator_fixture \
    -p node-core --lib || return "$?"
  bash scripts/check-fee-escrow-inventory.sh
}

# Validate the complete closed inventory before executing any selected row.
# Ownership is the package/target/exact selector, never an inferred name filter.
ci_run_required_extended_group() {
  if [[ "$#" -ne 1 || -z "$1" ]]; then
    echo 'malformed required extended gate group' >&2
    return 1
  fi
  local requested="$1" row case_group package target test_name nocapture identity previous profile plan
  local -a selected=() seen=()
  profile="$(ci_execution_profile "$requested")" || return "$?"
  plan="$(ci_execution_plan "$requested")" || return "$?"
  [[ "$profile" == required && "$plan" == "$requested" ]] || return 1
  for row in "${CI_REQUIRED_EXTENDED_CASES[@]}"; do
    if [[ ! "$row" =~ ^[^\|]+\|[^\|]+\|[^\|]+\|[^\|]+\|(yes|no)$ ]]; then
      echo 'malformed required extended test ownership row' >&2
      return 1
    fi
    IFS='|' read -r case_group package target test_name nocapture <<< "$row"
    profile="$(ci_execution_profile "$case_group")" || return "$?"
    plan="$(ci_execution_plan "$case_group")" || return "$?"
    [[ "$profile" == required && "$plan" == "$case_group" ]] || return 1
    [[ "$package" =~ ^[a-z][a-z0-9-]*$ && "$test_name" =~ ^[a-zA-Z0-9_:]+$ ]] || return 1
    [[ "$target" == --lib || "$target" =~ ^[a-zA-Z_][a-zA-Z0-9_-]*$ ]] || return 1
    identity="$package|$target|$test_name"
    for previous in "${seen[@]}"; do
      if [[ "$identity" == "$previous" ]]; then
        echo 'duplicate required extended test ownership' >&2
        return 1
      fi
    done
    seen+=("$identity")
    if [[ "$case_group" == "$requested" ]]; then selected+=("$row"); fi
  done
  if [[ "${#selected[@]}" -eq 0 ]]; then
    echo 'required extended gate group has no registered test' >&2
    return 1
  fi
  for row in "${selected[@]}"; do
    IFS='|' read -r case_group package target test_name nocapture <<< "$row"
    local -a args=(-p "$package")
    if [[ "$target" == --lib ]]; then args+=(--lib); else args+=(--test "$target"); fi
    ci_run_exact_ignored_test "$test_name" "$nocapture" "${args[@]}" || return "$?"
  done
}

ci_check_vectors() {
  local vector
  for vector in \
    call-value call-intent publication-submission local-execution \
    call-authorization paid-execution fast-vote availability frozen-frontier \
    drainset fast-path fastvote-apply-request fastvote-published-apply \
    ordered-history business-cut business-import bond-registration conditional-readiness ordered-seal ordered-seal-successor successor-serving; do
    node "scripts/$vector-vectors.mjs" || return "$?"
  done
}

ci_check_deno_adapters() {
  local adapter
  for adapter in deno vercel supabase-edge aws-lambda; do
    (
      cd "adapters/$adapter" || exit "$?"
      deno task check
    ) || return "$?"
  done
}

ci_run_action() {
  if [[ "$#" -ne 1 ]]; then
    echo 'malformed repository gate action' >&2
    return 1
  fi
  case "$1" in
    gate-contract) node scripts/test-ci-gates.mjs ;;
    rust-style) ci_check_rust_style ;;
    rust-tests-required)
      cargo build -p sunrise-edge-cli --bin sunrise-edge-cli --all-features || return "$?"
      cargo test --workspace --all-targets --all-features --exclude runtime-postgres
      ;;
    rust-tests-full)
      cargo build -p sunrise-edge-cli --bin sunrise-edge-cli --all-features || return "$?"
      cargo test --workspace --all-targets --all-features
      ;;
    sqlite-inventory) ci_check_sqlite_inventory ;;
    core-recurrence|readiness-sqlite|recurring-sqlite) ci_run_required_extended_group "$1" ;;
    pg-storage-tests)
      # Operator --all-targets includes nonignored compiled-CLI process tests;
      # this isolated lane builds that separate binary like rust-tests does.
      cargo build -p sunrise-edge-cli --bin sunrise-edge-cli --all-features || return "$?"
      # Keep native feature anchors and USB-HID identical to the former lane.
      cargo test -p runtime-postgres -p sunrise-edge-operator \
        -p sunrise-edge-cloudflare-validator -p sunrise-claim \
        --all-targets --all-features \
        --features sunrise-edge-cli/usb-hid
      ;;
    pg-inventory) bash scripts/check-fee-escrow-inventory-pg.sh ;;
    pg-protocol-all) bash scripts/check-fastvote-pg.sh ;;
    pg-protocol-lifecycle|pg-protocol-drain-history|pg-protocol-business-audit|pg-protocol-recovery-economics)
      bash scripts/check-fastvote-pg.sh --group "pg-${1#pg-protocol-}"
      ;;
    soak-cli) bash scripts/check-postgres-soak.sh --self-test-cli ;;
    pg-soak) bash scripts/check-postgres-soak.sh --smoke ;;
    vectors) ci_check_vectors ;;
    cloudflare-build) bash scripts/build-cloudflare-validator.sh ;;
    cloudflare-check) npm --prefix adapters/cloudflare-workers run check ;;
    deno-adapters) ci_check_deno_adapters ;;
    diff-hygiene) git diff --check ;;
    *) echo 'unknown repository gate action' >&2; return 1 ;;
  esac
}

ci_run_gate() {
  local profile plan action
  profile="$(ci_execution_profile "$@")" || return "$?"
  case "$profile" in
    required) ci_require_storage_neutral || return "$?" ;;
    postgres) ci_require_postgres || return "$?" ;;
    *) echo 'unknown repository gate prerequisite profile' >&2; return 1 ;;
  esac
  plan="$(ci_execution_plan "$@")" || return "$?"
  while IFS= read -r action; do
    # Recipe input is not the coordinator's remaining execution plan. A tool
    # reading stdin must not consume later actions and silently skip a gate.
    ci_run_action "$action" </dev/null || return "$?"
  done <<< "$plan"
}
