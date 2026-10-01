#!/usr/bin/env bash
set -euo pipefail

script_directory="${BASH_SOURCE[0]%/*}"
if [[ "$script_directory" == "${BASH_SOURCE[0]}" ]]; then script_directory=.; fi
project_root="$(cd "$script_directory/.." && pwd)"
cd "$project_root"

# shellcheck source=scripts/ci-gates.sh
source "$project_root/scripts/ci-gates.sh"
ci_require_postgres

require_exact_test() {
  local test_name="$1"
  shift
  if ! cargo test --quiet "$@" "$test_name" -- --ignored --list | grep -Fqx "$test_name: test"; then
    echo "missing expected PostgreSQL escrow inventory test: $test_name" >&2
    exit 1
  fi
}

fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/sunrise-escrow-operator-pg.XXXXXXXX")"
cleanup() {
  if [[ -n "$fixture_dir" && -d "$fixture_dir" ]]; then
    rm -rf -- "$fixture_dir"
  fi
}
trap cleanup EXIT

require_exact_test fee_claims::tests::certified_multi_escrow_inventory::export_certified_operator_fixture_postgres \
  -p node-core --lib
SUNRISE_EDGE_ESCROW_FIXTURE_DIR="$fixture_dir" \
  cargo test --quiet -p node-core --lib \
  "fee_claims::tests::certified_multi_escrow_inventory::export_certified_operator_fixture_postgres" \
  -- --ignored --exact

if [[ ! -f "$fixture_dir/validator_id.hex" ]]; then
  echo "certified PostgreSQL fixture did not emit a validator ID" >&2
  exit 1
fi
validator_id="$(<"$fixture_dir/validator_id.hex")"
if [[ ! "$validator_id" =~ ^[0-9a-f]{64}$ ]]; then
  echo "certified PostgreSQL fixture emitted an invalid validator ID" >&2
  exit 1
fi

require_exact_test fee_escrow_inventory_pg_operator_e2e \
  -p sunrise-edge-operator --test fee_escrow_inventory_pg_e2e
SUNRISE_EDGE_ESCROW_FIXTURE_DIR="$fixture_dir" \
  cargo test --quiet -p sunrise-edge-operator --test fee_escrow_inventory_pg_e2e \
  -- --ignored --exact --nocapture fee_escrow_inventory_pg_operator_e2e

echo "certified nonempty PostgreSQL operator inventory E2E passed"
