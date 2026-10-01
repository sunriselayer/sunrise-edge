#!/usr/bin/env bash
set -euo pipefail

script_directory="${BASH_SOURCE[0]%/*}"
if [[ "$script_directory" == "${BASH_SOURCE[0]}" ]]; then script_directory=.; fi
project_root="$(cd "$script_directory/.." && pwd)"
cd "$project_root"

# shellcheck source=scripts/ci-gates.sh
source "$project_root/scripts/ci-gates.sh"

group=required
if [[ "$#" -eq 1 && "$1" == '--full' ]]; then
  group=full
elif [[ "$#" -ne 0 ]]; then
  if [[ "$#" -ne 2 || "$1" != '--group' ]] || ! ci_group_is_known "$2"; then
    echo 'usage: check-all.sh [--full | --group <known repository gate>]' >&2
    exit 1
  fi
  group="$2"
fi
case "$group" in
  full|pg-*) ci_require_postgres ;;
  *) ci_require_storage_neutral ;;
esac

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
  node scripts/business-cut-vectors.mjs
  node scripts/business-import-vectors.mjs
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
  required)
    node scripts/test-ci-gates.mjs
    check_rust_style
    cargo test --workspace --all-targets --all-features --exclude runtime-postgres
    check_sqlite_inventory
    bash scripts/check-postgres-soak.sh --self-test-cli
    check_vectors
    bash scripts/build-cloudflare-validator.sh
    npm --prefix adapters/cloudflare-workers run check
    check_deno_adapters
    git diff --check
    ;;
  full)
    # Explicit extended validation preserves the former complete serial order.
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
    # Native feature-anchor packages preserve the current workspace union;
    # their ordinary tests repeat here rather than weakening storage features.
    cargo test -p runtime-postgres -p sunrise-edge-operator \
      -p sunrise-edge-cloudflare-validator -p sunrise-claim \
      --all-targets --all-features \
      --features sunrise-edge-cli/usb-hid
    ;;
  pg-lifecycle|pg-drain-history|pg-business-audit)
    bash scripts/check-fastvote-pg.sh --group "$group"
    ;;
  pg-recovery-economics)
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
