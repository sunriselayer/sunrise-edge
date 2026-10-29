#!/usr/bin/env bash
set -euo pipefail

script_directory="${BASH_SOURCE[0]%/*}"
if [[ "$script_directory" == "${BASH_SOURCE[0]}" ]]; then script_directory=.; fi
project_root="$(cd "$script_directory/.." && pwd)"
cd "$project_root"

# shellcheck source=scripts/ci-execution.sh
source "$project_root/scripts/ci-execution.sh"

fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/sunrise-escrow-operator.XXXXXXXX")"
cleanup() {
  if [[ -n "$fixture_dir" && -d "$fixture_dir" ]]; then
    rm -rf -- "$fixture_dir"
  fi
}
trap cleanup EXIT

SUNRISE_EDGE_ESCROW_FIXTURE_DIR="$fixture_dir" \
  ci_run_exact_ignored_test \
  fee_claims::tests::certified_multi_escrow_inventory::export_certified_operator_fixture no \
  -p node-core --lib

validator_id="$(<"$fixture_dir/validator_id.hex")"
if [[ ! "$validator_id" =~ ^[0-9a-f]{64}$ ]]; then
  echo "certified fixture did not emit one validator ID" >&2
  exit 1
fi

result="$(cargo run --quiet -p sunrise-edge-devnet --bin fee_escrow_inventory -- \
  --data-dir "$fixture_dir" \
  --chain-id paid-durable \
  --validator-id "$validator_id" \
  --domain "$(printf '08%.0s' {1..32})" \
  --protocol-version 3 \
  --suite 0:1:1:1:1:1:1:1 \
  --page-size 1 --timeout-seconds 60 \
  --confirm-offline-fence-advance)"

for field in complete=true writer_generation=2 pages=2 verified_rows=2 verified_claims=0 verified_payouts=0; do
  if [[ " $result " != *" $field "* ]]; then
    echo "operator inventory result lacks $field: $result" >&2
    exit 1
  fi
done
echo "certified nonempty SQLite operator inventory passed: $result"
