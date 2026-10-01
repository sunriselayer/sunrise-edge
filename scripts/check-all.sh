#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

# shellcheck source=scripts/ci-gates.sh
source "$project_root/scripts/ci-gates.sh"

group=all
if [[ "$#" -ne 0 ]]; then
  if [[ "$#" -ne 2 || "$1" != '--group' ]] || ! ci_group_is_known "$2"; then
    echo 'usage: check-all.sh [--group <known repository gate>]' >&2
    exit 1
  fi
  group="$2"
fi

check_rust_style() {
  cargo fmt --all -- --check
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
    crates/execution/tests/paid_execution_engine/codec.rs
  cargo clippy --workspace --all-targets --all-features -- -D warnings
}

check_sqlite_inventory() {
  ci_require_exact_ignored_test \
    fee_claims::tests::certified_multi_escrow_inventory::export_certified_operator_fixture \
    -p node-core --lib
  bash scripts/check-fee-escrow-inventory.sh
}

check_vectors() {
  node scripts/call-value-vectors.mjs
  node scripts/call-intent-vectors.mjs
  node scripts/publication-submission-vectors.mjs
  node scripts/local-execution-vectors.mjs
  node scripts/call-authorization-vectors.mjs
  node scripts/paid-execution-vectors.mjs
  node scripts/fast-vote-vectors.mjs
  node scripts/availability-vectors.mjs
  node scripts/frozen-frontier-vectors.mjs
  node scripts/drainset-vectors.mjs
  node scripts/fast-path-vectors.mjs
  node scripts/fastvote-apply-request-vectors.mjs
  node scripts/fastvote-published-apply-vectors.mjs
  node scripts/ordered-history-vectors.mjs
}

check_deno_adapters() {
  for adapter in deno vercel supabase-edge aws-lambda; do
    (
      cd "adapters/$adapter"
      deno task check
    )
  done
}

case "$group" in
  all)
    # Keep the complete local gate serial and in its original order. CI may
    # dispatch closed lanes, but a default run never becomes a partial run.
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
      ci_require_postgres
    fi
    node scripts/test-ci-gates.mjs
    check_rust_style
    cargo test --workspace --all-targets --all-features
    check_sqlite_inventory
    bash scripts/check-fee-escrow-inventory-pg.sh
    bash scripts/check-fastvote-pg.sh
    bash scripts/check-postgres-soak.sh --self-test-cli
    bash scripts/check-postgres-soak.sh --smoke
    check_vectors
    bash scripts/build-cloudflare-validator.sh
    npm --prefix adapters/cloudflare-workers run check
    check_deno_adapters
    git diff --check
    ;;
  lint)
    node scripts/test-ci-gates.mjs
    check_rust_style
    git diff --check
    ;;
  rust-tests)
    cargo test --workspace --all-targets --all-features --exclude runtime-postgres
    check_sqlite_inventory
    ;;
  pg-storage)
    # Explicit fault configuration must not silently skip even outside CI.
    if [[ -z "${SUNRISE_EDGE_TEST_POSTGRES_URL:-}" ]]; then
      for fault_var in \
        SUNRISE_EDGE_TEST_POSTGRES_CONTAINER_ID SUNRISE_EDGE_TEST_POSTGRES_CRASH_REQUIRED \
        SUNRISE_EDGE_TEST_POSTGRES_DISK_FULL_IMAGE SUNRISE_EDGE_TEST_POSTGRES_DISK_FULL_REQUIRED \
        SUNRISE_EDGE_TEST_POSTGRES_WAL_FULL_IMAGE SUNRISE_EDGE_TEST_POSTGRES_WAL_FULL_REQUIRED \
        SUNRISE_EDGE_TEST_POSTGRES_CONNECTION_EXHAUSTION_IMAGE SUNRISE_EDGE_TEST_POSTGRES_CONNECTION_EXHAUSTION_REQUIRED \
        SUNRISE_EDGE_TEST_POSTGRES_BACKUP_RESTORE_IMAGE SUNRISE_EDGE_TEST_POSTGRES_BACKUP_RESTORE_REQUIRED \
        SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_POSTGRES_IMAGE SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_IMAGE \
        SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_REQUIRED; do
        if [[ -v "$fault_var" ]]; then
          echo 'configured PostgreSQL faults require a disposable live PostgreSQL URL' >&2
          exit 1
        fi
      done
    fi
    if ! ci_require_postgres; then exit 0; fi
    # Native feature-anchor packages preserve the current workspace union;
    # their ordinary tests repeat here rather than weakening storage features.
    cargo test -p runtime-postgres -p sunrise-edge-operator \
      -p sunrise-edge-cloudflare-validator -p sunrise-claim \
      --all-targets --all-features \
      --features sunrise-edge-cli/usb-hid
    ;;
  pg-lifecycle|pg-drain-history|pg-business-audit)
    if ! ci_require_postgres; then exit 0; fi
    bash scripts/check-fastvote-pg.sh --group "$group"
    ;;
  pg-recovery-economics)
    if ! ci_require_postgres; then exit 0; fi
    bash scripts/check-fee-escrow-inventory-pg.sh
    bash scripts/check-fastvote-pg.sh --group "$group"
    # Keep producer, handoff and recovery together under their existing deadline.
    bash scripts/check-postgres-soak.sh --smoke
    ;;
  portable-tools)
    bash scripts/check-postgres-soak.sh --self-test-cli
    check_vectors
    check_deno_adapters
    ;;
  cloudflare)
    bash scripts/build-cloudflare-validator.sh
    npm --prefix adapters/cloudflare-workers run check
    ;;
esac
