#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

if ! command -v wasm-bindgen >/dev/null; then
  echo 'Install wasm-bindgen-cli 0.2.127 before building the experimental validator.' >&2
  exit 1
fi
if [[ "$(wasm-bindgen --version)" != 'wasm-bindgen 0.2.127' ]]; then
  echo 'The experimental validator requires wasm-bindgen-cli 0.2.127.' >&2
  exit 1
fi

cargo build --locked --release --target wasm32-unknown-unknown \
  -p sunrise-edge-cloudflare-validator
task_target_dir="${CARGO_TARGET_DIR:-$project_root/target}"
wasm-bindgen \
  "$task_target_dir/wasm32-unknown-unknown/release/sunrise_edge_cloudflare_validator.wasm" \
  --target web \
  --out-dir adapters/cloudflare-workers/src/validator/generated

# Generated oracle uses only public development keys and the native Wasmi/core,
# never operator secrets. workerd consumes its exact canonical bytes.
cargo run --locked --quiet -p sunrise-edge-operator \
  --example cloudflare_contract_fixture \
  > adapters/cloudflare-workers/src/validator/generated/contract-fixture.json.next
mv adapters/cloudflare-workers/src/validator/generated/contract-fixture.json.next \
  adapters/cloudflare-workers/src/validator/generated/contract-fixture.json
