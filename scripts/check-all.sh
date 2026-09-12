#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

cargo fmt --all -- --check
rustfmt --edition 2024 --check \
  crates/execution/tests/paid_execution_engine/fixture.rs \
  crates/execution/tests/paid_execution_engine/call.rs \
  crates/execution/tests/paid_execution_engine/publish.rs \
  crates/execution/tests/paid_execution_engine/verify.rs \
  crates/execution/tests/paid_execution_engine/codec.rs
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features

node scripts/call-value-vectors.mjs
node scripts/call-intent-vectors.mjs
node scripts/publication-submission-vectors.mjs
node scripts/local-execution-vectors.mjs
node scripts/call-authorization-vectors.mjs
node scripts/paid-execution-vectors.mjs

npm --prefix adapters/cloudflare-workers run check

for adapter in deno vercel supabase-edge aws-lambda; do
  (
    cd "adapters/$adapter"
    deno task check
  )
done

git diff --check
