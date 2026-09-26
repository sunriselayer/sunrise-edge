#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

# Mirrors check-all.sh's own top-of-file rule: CI must exercise this against
# the live PostgreSQL service; local checks may run without one and skip.
if [[ -z "${SUNRISE_EDGE_TEST_POSTGRES_URL:-}" ]]; then
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "CI requires SUNRISE_EDGE_TEST_POSTGRES_URL for the PostgreSQL fee-escrow inventory operator E2E" >&2
    exit 1
  fi
  echo "skipping PostgreSQL fee-escrow inventory operator E2E: SUNRISE_EDGE_TEST_POSTGRES_URL is unset"
  exit 0
fi

fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/sunrise-escrow-operator-pg.XXXXXXXX")"
cleanup() {
  if [[ -n "$fixture_dir" && -d "$fixture_dir" ]]; then
    rm -rf -- "$fixture_dir"
  fi
}
trap cleanup EXIT

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

SUNRISE_EDGE_ESCROW_FIXTURE_DIR="$fixture_dir" \
  cargo test --quiet -p sunrise-edge-operator --test fee_escrow_inventory_pg_e2e \
  -- --ignored --exact --nocapture fee_escrow_inventory_pg_operator_e2e

echo "certified nonempty PostgreSQL operator inventory E2E passed"
