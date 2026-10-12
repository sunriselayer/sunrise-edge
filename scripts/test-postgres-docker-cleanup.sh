#!/usr/bin/env bash
set -Eeuo pipefail

script_directory="${BASH_SOURCE[0]%/*}"
if [[ "$script_directory" == "${BASH_SOURCE[0]}" ]]; then script_directory=.; fi
if ! project_root="$(cd "$script_directory/.." && pwd)"; then
  echo 'failed to resolve the actual PG cleanup project root' >&2
  exit 1
fi
readonly project_root
readonly OWNER_LABEL='sunrise-edge.pg-test-owner'
readonly OWNER='0123456789abcdef0123456789abcdef'
readonly CONTAINER_NAME='sunrise-edge-pg-cleanup-test-postgres'
readonly KEEPER_NAME='sunrise-edge-pg-cleanup-test-keeper'
readonly VOLUME_NAME='sunrise-edge-pg-cleanup-test-data'
readonly CONTAINER_ID='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
readonly OTHER_ID='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
readonly CONTAINER_FORMAT='{{.Id}}|{{.Name}}|{{index .Config.Labels "sunrise-edge.pg-test-owner"}}'
readonly VOLUME_FORMAT='{{.Name}}|{{.Driver}}|{{index .Labels "sunrise-edge.pg-test-owner"}}'
if ! test_directory="$(mktemp -d /tmp/sunrise-edge-pg-cleanup-test.XXXXXXXX)"; then
  echo 'failed to create the disposable PG cleanup test directory' >&2
  exit 1
fi
if [[ "$test_directory" != /tmp/sunrise-edge-pg-cleanup-test.?* \
    || "$test_directory" == /tmp/sunrise-edge-pg-cleanup-test.*/* \
    || ! -d "$test_directory" || -L "$test_directory" ]]; then
  echo 'refusing an invalid disposable PG cleanup test directory' >&2
  exit 1
fi
readonly test_directory
mock_directory=''
case_count=0

cleanup_test_files() {
  case "$test_directory" in
    /tmp/sunrise-edge-pg-cleanup-test.*) rm -rf -- "$test_directory" ;;
    *) echo 'refusing unexpected test cleanup path' >&2; return 1 ;;
  esac
}
trap cleanup_test_files EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  echo "PG cleanup control failed: $*" >&2
  exit 1
}

mock_reset() {
  local name="$1"
  [[ "$name" =~ ^[a-z0-9_-]+$ ]] || fail 'invalid fixture name'
  mock_directory="$test_directory/$name"
  [[ ! -e "$mock_directory" ]] || fail 'fixture directory already exists'
  mkdir "$mock_directory"
  printf '0\n' > "$mock_directory/planned"
  printf '1\n' > "$mock_directory/next"
  : > "$mock_directory/effects"
  : > "$mock_directory/unexpected"
  printf '0\n' > "$mock_directory/container_removed"
  printf '0\n' > "$mock_directory/volume_removed"
  printf '0\n' > "$mock_directory/stopped"
  printf '0\n' > "$mock_directory/killed"
}

# Each planned argv is NUL-framed, not a space-joined command or function copy.
mock_plan() {
  local status="$1"
  local output="$2"
  shift 2
  local index
  index="$(< "$mock_directory/planned")"
  index="$((index + 1))"
  printf '%s\n' "$index" > "$mock_directory/planned"
  printf '%s\0' "$@" > "$mock_directory/expected-$index.argv"
  printf '%s' "$output" > "$mock_directory/output-$index"
  printf '%s\n' "$status" > "$mock_directory/status-$index"
}

# These records survive command-substitution subshells in the ACTUAL library.
# This function is the only Docker endpoint; no real daemon/CLI is invoked.
docker() {
  local index status
  local kind="${1:-}"
  local action="${2:-}"
  [[ -n "$mock_directory" ]] || return 99
  index="$(< "$mock_directory/next")"
  printf '%s\n' "$((index + 1))" > "$mock_directory/next"
  printf '%s\0' "$@" > "$mock_directory/actual-$index.argv"
  if [[ ! -f "$mock_directory/expected-$index.argv" ]] ||
      ! cmp -s "$mock_directory/expected-$index.argv" "$mock_directory/actual-$index.argv"; then
    printf 'unexpected Docker argv at call %s\n' "$index" >> "$mock_directory/unexpected"
    return 99
  fi
  status="$(< "$mock_directory/status-$index")"
  case "$kind|$action" in
    'container|stop'|'container|kill'|'container|rm'|'volume|rm')
      printf '%s|%s\n' "$kind" "$action" >> "$mock_directory/effects"
      ;;
  esac
  if [[ "$status" -eq 0 ]]; then
    case "$kind|$action" in
      'container|stop') printf '1\n' > "$mock_directory/stopped" ;;
      'container|kill') printf '1\n' > "$mock_directory/killed" ;;
      'container|rm') printf '1\n' > "$mock_directory/container_removed" ;;
      'volume|rm') printf '1\n' > "$mock_directory/volume_removed" ;;
    esac
  fi
  cat "$mock_directory/output-$index"
  return "$status"
}

# No copied production function bodies and no production test-mode switch.
# shellcheck source=scripts/postgres-docker-cleanup.sh
source "$project_root/scripts/postgres-docker-cleanup.sh"
[[ "$(type -t docker)" == function ]] || fail 'fake Docker endpoint is not active'

assert_case() {
  local expected_status="$1"
  local expected_effects="$2"
  shift 2
  local status planned next
  if "$@" > "$mock_directory/stdout" 2> "$mock_directory/stderr"; then
    status=0
  else
    status="$?"
  fi
  [[ "$status" -eq "$expected_status" ]] ||
    fail "status $status differs from $expected_status in $mock_directory"
  [[ ! -s "$mock_directory/unexpected" ]] || fail 'unexpected Docker argv/order'
  planned="$(< "$mock_directory/planned")"
  next="$(< "$mock_directory/next")"
  [[ "$next" -eq "$((planned + 1))" ]] || fail 'planned call was omitted or duplicated'
  printf '%s' "$expected_effects" > "$mock_directory/expected-effects"
  cmp -s "$mock_directory/expected-effects" "$mock_directory/effects" ||
    fail 'stop/kill/remove effects differ'
  case_count="$((case_count + 1))"
}

assert_state() {
  local field="$1"
  local expected="$2"
  local actual
  actual="$(< "$mock_directory/$field")"
  [[ "$actual" == "$expected" ]] || fail "mock state $field differs"
}

plan_container_inspect() {
  local status="$1"
  local output="$2"
  local name="${3:-$CONTAINER_NAME}"
  mock_plan "$status" "$output" container inspect --format "$CONTAINER_FORMAT" "$name"
}

plan_container_list() {
  mock_plan "$1" "$2" container ls --all --filter "name=$CONTAINER_NAME" --format '{{.Names}}'
}

plan_volume_inspect() {
  mock_plan "$1" "$2" volume inspect --format "$VOLUME_FORMAT" "$VOLUME_NAME"
}

plan_volume_list() {
  mock_plan "$1" "$2" volume ls --filter "name=$VOLUME_NAME" --format '{{.Name}}'
}

plan_owned_container() {
  local name="${1:-$CONTAINER_NAME}"
  plan_container_inspect 0 "$CONTAINER_ID|/$name|$OWNER"$'\n' "$name"
}

plan_running() {
  mock_plan "$1" "$2" container inspect --format '{{.State.Running}}' "$CONTAINER_ID"
}

container_absence_case() {
  local name="$1"
  local list_status="$2"
  local list_output="$3"
  local expected_status="$4"
  mock_reset "$name"
  plan_container_inspect 1 ''
  plan_container_list "$list_status" "$list_output"
  assert_case "$expected_status" '' stop_and_remove_owned_container postgres "$CONTAINER_NAME" "$CONTAINER_ID"
  assert_state container_removed 0
  assert_state stopped 0
  assert_state killed 0
}

volume_absence_case() {
  local name="$1"
  local list_status="$2"
  local list_output="$3"
  local expected_status="$4"
  mock_reset "$name"
  plan_volume_inspect 1 ''
  plan_volume_list "$list_status" "$list_output"
  assert_case "$expected_status" '' remove_owned_volume retained-data "$VOLUME_NAME"
  assert_state volume_removed 0
}

container_absence_case container_inspect_and_list_unavailable 1 '' 1
container_absence_case container_failed_listing_with_output 1 "$CONTAINER_NAME-other"$'\n' 1
container_absence_case container_exact_name_still_listed 0 "$CONTAINER_NAME"$'\n' 1
container_absence_case container_exact_among_other_names 0 "$CONTAINER_NAME-other"$'\n'"$CONTAINER_NAME"$'\n' 1
container_absence_case container_malformed_name 0 $'bad name\n' 1
container_absence_case container_empty_internal_row 0 $'other\n\nlast\n' 1
container_absence_case container_empty_terminal_row 0 $'other\n\n' 1
container_absence_case container_unterminated_row 0 'other' 1
container_absence_case container_control_byte_row 0 $'other\034\n' 1
container_absence_case container_confirmed_absent_empty 0 '' 0
container_absence_case container_confirmed_absent_prefix_other 0 "$CONTAINER_NAME-other"$'\n' 0

volume_absence_case volume_inspect_and_list_unavailable 1 '' 1
volume_absence_case volume_failed_listing_with_output 1 "$VOLUME_NAME-other"$'\n' 1
volume_absence_case volume_exact_name_still_listed 0 "$VOLUME_NAME"$'\n' 1
volume_absence_case volume_malformed_name 0 $'bad/name\n' 1
volume_absence_case volume_empty_internal_row 0 $'other\n\nlast\n' 1
volume_absence_case volume_empty_terminal_row 0 $'other\n\n' 1
volume_absence_case volume_unterminated_row 0 'other' 1
volume_absence_case volume_control_byte_row 0 $'other\034\n' 1
volume_absence_case volume_confirmed_absent_empty 0 '' 0
volume_absence_case volume_confirmed_absent_prefix_other 0 "$VOLUME_NAME-other"$'\n' 0

mock_reset container_wrong_owner
plan_container_inspect 0 "$CONTAINER_ID|/$CONTAINER_NAME|another-owner"$'\n'
plan_container_list 0 "$CONTAINER_NAME"$'\n'
assert_case 1 '' stop_and_remove_owned_container postgres "$CONTAINER_NAME" "$CONTAINER_ID"
assert_state container_removed 0

mock_reset container_wrong_id
plan_container_inspect 0 "$OTHER_ID|/$CONTAINER_NAME|$OWNER"$'\n'
plan_container_list 0 "$CONTAINER_NAME"$'\n'
assert_case 1 '' stop_and_remove_owned_container postgres "$CONTAINER_NAME" "$CONTAINER_ID"
assert_state container_removed 0

mock_reset container_malformed_inspect
plan_container_inspect 0 "not-an-id|/$CONTAINER_NAME|$OWNER"$'\n'
plan_container_list 0 "$CONTAINER_NAME"$'\n'
assert_case 1 '' stop_and_remove_owned_container postgres "$CONTAINER_NAME" "$CONTAINER_ID"
assert_state container_removed 0

mock_reset volume_wrong_owner
plan_volume_inspect 0 "$VOLUME_NAME|local|another-owner"$'\n'
assert_case 1 '' remove_owned_volume retained-data "$VOLUME_NAME"
assert_state volume_removed 0

mock_reset volume_wrong_driver
plan_volume_inspect 0 "$VOLUME_NAME|foreign|$OWNER"$'\n'
assert_case 1 '' remove_owned_volume retained-data "$VOLUME_NAME"
assert_state volume_removed 0

mock_reset volume_wrong_name
plan_volume_inspect 0 "$VOLUME_NAME-other|local|$OWNER"$'\n'
assert_case 1 '' remove_owned_volume retained-data "$VOLUME_NAME"
assert_state volume_removed 0

mock_reset malformed_unknown_kind
assert_case 1 '' confirm_absent image "$VOLUME_NAME"
mock_reset malformed_empty_name
assert_case 1 '' confirm_absent container ''
mock_reset malformed_target_name
assert_case 1 '' confirm_absent volume '../foreign'
mock_reset malformed_missing_argument
assert_case 1 '' confirm_absent container
mock_reset malformed_extra_argument
assert_case 1 '' confirm_absent volume "$VOLUME_NAME" extra

mock_reset owned_running_container
plan_owned_container
plan_running 0 $'true\n'
mock_plan 0 '' container stop --time 10 "$CONTAINER_ID"
plan_running 0 $'false\n'
mock_plan 0 '' container rm "$CONTAINER_ID"
assert_case 0 $'container|stop\ncontainer|rm\n' stop_and_remove_owned_container postgres "$CONTAINER_NAME" "$CONTAINER_ID"
assert_state stopped 1
assert_state killed 0
assert_state container_removed 1

mock_reset owned_stopped_container
plan_owned_container "$KEEPER_NAME"
plan_running 0 $'false\n'
plan_running 0 $'false\n'
mock_plan 0 '' container rm "$CONTAINER_ID"
assert_case 0 $'container|rm\n' stop_and_remove_owned_container keeper "$KEEPER_NAME" "$CONTAINER_ID"
assert_state stopped 0
assert_state killed 0
assert_state container_removed 1

mock_reset owned_stop_failure_kill_success
plan_owned_container
plan_running 0 $'true\n'
mock_plan 1 '' container stop --time 10 "$CONTAINER_ID"
mock_plan 0 '' container kill "$CONTAINER_ID"
plan_running 0 $'false\n'
mock_plan 0 '' container rm "$CONTAINER_ID"
assert_case 0 $'container|stop\ncontainer|kill\ncontainer|rm\n' stop_and_remove_owned_container postgres "$CONTAINER_NAME" "$CONTAINER_ID"
assert_state stopped 0
assert_state killed 1
assert_state container_removed 1

mock_reset owned_first_running_inspect_unavailable
plan_owned_container
plan_running 1 ''
assert_case 1 '' stop_and_remove_owned_container postgres "$CONTAINER_NAME" "$CONTAINER_ID"
assert_state container_removed 0

mock_reset owned_malformed_running_state
plan_owned_container
plan_running 0 $'unknown\n'
assert_case 1 '' stop_and_remove_owned_container postgres "$CONTAINER_NAME" "$CONTAINER_ID"
assert_state container_removed 0

mock_reset owned_stop_and_kill_unavailable
plan_owned_container
plan_running 0 $'true\n'
mock_plan 1 '' container stop --time 10 "$CONTAINER_ID"
mock_plan 1 '' container kill "$CONTAINER_ID"
assert_case 1 $'container|stop\ncontainer|kill\n' stop_and_remove_owned_container postgres "$CONTAINER_NAME" "$CONTAINER_ID"
assert_state container_removed 0

mock_reset owned_post_stop_inspect_unavailable
plan_owned_container
plan_running 0 $'true\n'
mock_plan 0 '' container stop --time 10 "$CONTAINER_ID"
plan_running 1 ''
assert_case 1 $'container|stop\n' stop_and_remove_owned_container postgres "$CONTAINER_NAME" "$CONTAINER_ID"
assert_state container_removed 0

mock_reset owned_still_running_after_stop
plan_owned_container
plan_running 0 $'true\n'
mock_plan 0 '' container stop --time 10 "$CONTAINER_ID"
plan_running 0 $'true\n'
assert_case 1 $'container|stop\n' stop_and_remove_owned_container postgres "$CONTAINER_NAME" "$CONTAINER_ID"
assert_state container_removed 0

mock_reset owned_container_remove_unavailable
plan_owned_container
plan_running 0 $'false\n'
plan_running 0 $'false\n'
mock_plan 42 '' container rm "$CONTAINER_ID"
assert_case 42 $'container|rm\n' stop_and_remove_owned_container postgres "$CONTAINER_NAME" "$CONTAINER_ID"
assert_state container_removed 0

mock_reset owned_volume
plan_volume_inspect 0 "$VOLUME_NAME|local|$OWNER"$'\n'
mock_plan 0 '' volume rm "$VOLUME_NAME"
assert_case 0 $'volume|rm\n' remove_owned_volume retained-data "$VOLUME_NAME"
assert_state volume_removed 1

mock_reset owned_volume_remove_unavailable
plan_volume_inspect 0 "$VOLUME_NAME|local|$OWNER"$'\n'
mock_plan 42 '' volume rm "$VOLUME_NAME"
assert_case 42 $'volume|rm\n' remove_owned_volume retained-data "$VOLUME_NAME"
assert_state volume_removed 0

printf 'PG cleanup mock controls passed: %s. No real Docker operation was executed.\n' "$case_count"
