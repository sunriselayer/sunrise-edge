#!/usr/bin/env bash
set -euo pipefail

script_directory="${BASH_SOURCE[0]%/*}"
if [[ "$script_directory" == "${BASH_SOURCE[0]}" ]]; then script_directory=.; fi
project_root="$(cd "$script_directory/.." && pwd)"
cd "$project_root"

# shellcheck source=scripts/ci-gates.sh
source "$project_root/scripts/ci-gates.sh"
# shellcheck source=scripts/ci-execution.sh
source "$project_root/scripts/ci-execution.sh"
ci_require_postgres

fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/sunrise-escrow-operator-pg.XXXXXXXX")"
cleanup() {
  if [[ -n "$fixture_dir" && -d "$fixture_dir" ]]; then
    rm -rf -- "$fixture_dir"
  fi
}
trap cleanup EXIT

SUNRISE_EDGE_ESCROW_FIXTURE_DIR="$fixture_dir" \
  ci_run_exact_ignored_test \
  fee_claims::tests::certified_multi_escrow_inventory::export_certified_operator_fixture_postgres no \
  -p node-core --lib

if [[ ! -f "$fixture_dir/validator_id.hex" ]]; then
  echo "certified PostgreSQL fixture did not emit a validator ID" >&2
  exit 1
fi
validator_id="$(<"$fixture_dir/validator_id.hex")"
if [[ ! "$validator_id" =~ ^[0-9a-f]{64}$ ]]; then
  echo "certified PostgreSQL fixture emitted an invalid validator ID" >&2
  exit 1
fi

SUNRISE_EDGE_ESCROW_FIXTURE_DIR="$fixture_dir" \
  ci_run_exact_ignored_test fee_escrow_inventory_pg_operator_e2e yes \
  -p sunrise-edge-operator --test fee_escrow_inventory_pg_e2e

echo "certified nonempty PostgreSQL operator inventory E2E passed"
