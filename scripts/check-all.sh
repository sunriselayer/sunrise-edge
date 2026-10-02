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

selection=required
if [[ "$#" -eq 1 && "$1" == '--full' ]]; then
  selection=full
elif [[ "$#" -ne 0 ]]; then
  if [[ "$#" -ne 2 || "$1" != '--group' ]] || ! ci_group_is_known "$2"; then
    echo 'usage: check-all.sh [--full | --group <known repository gate>]' >&2
    exit 1
  fi
  selection="$2"
fi
ci_run_gate "$selection"
