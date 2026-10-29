# shellcheck shell=bash
# Source-only cleanup functions for the actual disposable PG runner.
# OWNER and OWNER_LABEL are supplied by that runner; sourcing performs no Docker operation.

confirm_absent() {
  [[ "$#" -eq 2 ]] || return 1
  local kind="$1"
  local exact_name="$2"
  local listing row
  [[ "$exact_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || return 1
  # Preserve output framing with a terminal sentinel; command substitution
  # otherwise discards empty terminal rows. Failed listing is never absence.
  case "$kind" in
    container)
      listing="$(docker container ls --all --filter "name=$exact_name" \
        --format '{{.Names}}' && printf '\034')" || return 1
      ;;
    volume)
      listing="$(docker volume ls --filter "name=$exact_name" \
        --format '{{.Name}}' && printf '\034')" || return 1
      ;;
    *) return 1 ;;
  esac
  [[ "$listing" == *$'\034' ]] || return 1
  listing="${listing%$'\034'}"
  [[ -n "$listing" ]] || return 0
  [[ "$listing" == *$'\n' ]] || return 1
  while IFS= read -r row; do
    [[ "$row" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || return 1
    [[ "$row" != "$exact_name" ]] || return 1
  done <<< "${listing%$'\n'}"
  return 0
}

inspect_owned_container() {
  local name="$1"
  local expected_id="$2"
  local row actual_id actual_name actual_owner
  row="$(docker container inspect --format \
    "{{.Id}}|{{.Name}}|{{index .Config.Labels \"$OWNER_LABEL\"}}" "$name" 2>/dev/null)" || return 1
  IFS='|' read -r actual_id actual_name actual_owner <<< "$row"
  [[ "$actual_id" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ "$actual_name" == "/$name" && "$actual_owner" == "$OWNER" ]] || return 1
  [[ -z "$expected_id" || "$actual_id" == "$expected_id" ]] || return 1
  printf '%s\n' "$actual_id"
}

stop_and_remove_owned_container() {
  local role="$1"
  local name="$2"
  local expected_id="$3"
  local actual_id running
  if ! actual_id="$(inspect_owned_container "$name" "$expected_id")"; then
    if confirm_absent container "$name"; then
      return 0
    fi
    echo "refusing to clean $role container: ownership or confirmed absence unavailable: $name" >&2
    return 1
  fi
  running="$(docker container inspect --format '{{.State.Running}}' "$actual_id")" || return 1
  if [[ "$running" != true && "$running" != false ]]; then
    echo "owned $role container running state is unknown: $actual_id" >&2
    return 1
  fi
  if [[ "$running" == true ]]; then
    if ! docker container stop --time 10 "$actual_id" >/dev/null; then
      docker container kill "$actual_id" >/dev/null || return 1
    fi
  fi
  running="$(docker container inspect --format '{{.State.Running}}' "$actual_id")" || return 1
  if [[ "$running" != false ]]; then
    echo "owned $role container did not stop: $actual_id" >&2
    return 1
  fi
  docker container rm "$actual_id" >/dev/null
}

remove_owned_volume() {
  local role="$1"
  local expected_name="$2"
  local row name driver owner
  if ! row="$(docker volume inspect --format \
    "{{.Name}}|{{.Driver}}|{{index .Labels \"$OWNER_LABEL\"}}" "$expected_name" 2>/dev/null)"; then
    if confirm_absent volume "$expected_name"; then
      return 0
    fi
    echo "refusing to clean $role volume: confirmed absence unavailable: $expected_name" >&2
    return 1
  fi
  IFS='|' read -r name driver owner <<< "$row"
  if [[ "$name" != "$expected_name" || "$driver" != local || "$owner" != "$OWNER" ]]; then
    echo "refusing to clean $role volume with mismatched ownership: $expected_name" >&2
    return 1
  fi
  docker volume rm "$expected_name" >/dev/null
}
