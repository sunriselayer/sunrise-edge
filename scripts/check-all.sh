#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

# CI must exercise the live PostgreSQL conformance; local checks may run
# without a disposable database and report those tests as skipped.
if [[ "${GITHUB_ACTIONS:-}" == "true" && -z "${SUNRISE_EDGE_TEST_POSTGRES_URL:-}" ]]; then
  echo "CI requires SUNRISE_EDGE_TEST_POSTGRES_URL for live PostgreSQL tests" >&2
  exit 1
fi

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
cargo test --workspace --all-targets --all-features
bash scripts/check-fee-escrow-inventory.sh
bash scripts/check-fee-escrow-inventory-pg.sh
bash scripts/check-fastvote-pg.sh
bash scripts/check-postgres-soak.sh --self-test-cli
bash scripts/check-postgres-soak.sh --smoke

node scripts/call-value-vectors.mjs
node scripts/call-intent-vectors.mjs
node scripts/publication-submission-vectors.mjs
node scripts/local-execution-vectors.mjs
node scripts/call-authorization-vectors.mjs
node scripts/paid-execution-vectors.mjs
node scripts/fast-vote-vectors.mjs
node scripts/fast-path-vectors.mjs
node scripts/fastvote-apply-request-vectors.mjs

npm --prefix adapters/cloudflare-workers run check

for adapter in deno vercel supabase-edge aws-lambda; do
  (
    cd "adapters/$adapter"
    deno task check
  )
done

git diff --check
