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

group=all
if [[ "$#" -ne 0 ]]; then
  if [[ "$#" -ne 2 || "$1" != '--group' ]]; then
    echo 'usage: check-fastvote-pg.sh [--group <known PostgreSQL protocol gate>]' >&2
    exit 1
  fi
  if ! ci_fastvote_pg_group_is_known "$2"; then
    echo 'unknown PostgreSQL protocol gate' >&2
    exit 1
  fi
  group="$2"
fi
ci_require_postgres

cli_built=false
for row in "${CI_FASTVOTE_PG_CASES[@]}"; do
  IFS='|' read -r case_group package target test_name nocapture <<< "$row"
  if [[ "$group" != all && "$group" != "$case_group" ]]; then
    continue
  fi

  # Preserve the default run's first three cases before the separately built
  # CLI. Each isolated lane builds its own required binaries, never shares them.
  case "$target" in
    fastvote_pg_e2e|fastvote_pg_credential_isolation_e2e|fastvote_host_pg_cli_e2e|--lib) ;;
    *)
      if [[ "$cli_built" == false ]]; then
        cargo build --quiet -p sunrise-edge-cli --bin sunrise-edge-cli
        cli_built=true
      fi
      ;;
  esac
  if [[ "$target" == business_audit_pg_e2e ]]; then
    cargo build --quiet -p sunrise-edge-operator --bin business_audit_pg
  fi

  args=(-p "$package")
  if [[ "$target" == --lib ]]; then
    args+=(--lib)
  else
    args+=(--test "$target")
  fi
  ci_run_exact_ignored_test "$test_name" "$nocapture" "${args[@]}"
done

echo "live PostgreSQL protocol gate passed: $group"
