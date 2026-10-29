#!/usr/bin/env bash
set -Eeuo pipefail

readonly POSTGRES_IMAGE='postgres:18.6-alpine3.24@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2'
readonly PGBOUNCER_IMAGE='ghcr.io/icoretech/pgbouncer-docker:1.25.2@sha256:53dc42879de6b87efed6ad239558cfa6fef6f08c5fa4acc109da5f5af1868b89'
readonly OWNER_LABEL='sunrise-edge.pg-test-owner'
readonly PG_DATABASE='sunrise_edge_test'
readonly VOLUME_OPTIONS='rw,nosuid,nodev,noexec,noswap,size=512m,nr_inodes=16384,mode=1777,uid=70,gid=70'
readonly TMP_VOLUME_OPTIONS='rw,nosuid,nodev,noexec,noswap,size=16m,nr_inodes=2048,mode=1777'
readonly RUN_VOLUME_OPTIONS='rw,nosuid,nodev,noexec,noswap,size=4m,nr_inodes=1024,mode=3775,uid=70,gid=70'

usage() {
  cat >&2 <<'EOF'
usage: scripts/run-postgres-docker-tests.sh <schema|crash|suite|profile>

  schema  Run only the live postgres_schema integration target.
  crash   Run only the live postgres_crash_recovery integration target.
  suite   Run every runtime-postgres target with every optional PG fixture required.
  profile Run all five existing PG storage/protocol/recovery/soak workflow groups.

The digest-pinned images must already exist locally. This script never pulls.
EOF
}

if [[ "$#" -ne 1 ]]; then
  usage
  exit 2
fi
readonly SELECTION="$1"
case "$SELECTION" in
  schema|crash|suite|profile) ;;
  *) usage; exit 2 ;;
esac

script_directory="${BASH_SOURCE[0]%/*}"
if [[ "$script_directory" == "${BASH_SOURCE[0]}" ]]; then script_directory=.; fi
project_root="$(cd "$script_directory/.." && pwd)"
cd "$project_root"

# shellcheck source=scripts/postgres-docker-cleanup.sh
source "$project_root/scripts/postgres-docker-cleanup.sh"

command -v docker >/dev/null 2>&1 || {
  echo 'docker is required' >&2
  exit 1
}
command -v cargo >/dev/null 2>&1 || {
  echo 'cargo is required' >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || {
  echo 'python3 is required for a disposable loopback port' >&2
  exit 1
}

# A digest reference already present in the local image store is mandatory.
# `image inspect` is read-only and never causes a pull.
docker image inspect "$POSTGRES_IMAGE" >/dev/null 2>&1 || {
  echo "required local PostgreSQL image is absent: $POSTGRES_IMAGE" >&2
  exit 1
}
if [[ "$SELECTION" == suite || "$SELECTION" == profile ]]; then
  docker image inspect "$PGBOUNCER_IMAGE" >/dev/null 2>&1 || {
    echo "required local PgBouncer image is absent: $PGBOUNCER_IMAGE" >&2
    exit 1
  }
fi

random_hex() {
  local bytes="$1"
  od -An -N "$bytes" -tx1 /dev/urandom | tr -d ' \n'
}

readonly OWNER="$(random_hex 16)"
readonly PREFIX="sunrise-edge-pg-${OWNER}"
readonly VOLUME_NAME="${PREFIX}-data"
readonly TMP_VOLUME_NAME="${PREFIX}-tmp"
readonly RUN_VOLUME_NAME="${PREFIX}-run"
readonly KEEPER_NAME="${PREFIX}-keeper"
readonly POSTGRES_NAME="${PREFIX}-postgres"
readonly POSTGRES_PASSWORD="$(random_hex 32)"
# Docker's empty HostPort request can choose a different port after SIGKILL /
# start. Select one concrete loopback port before creation and refuse any bind
# collision, rather than changing the test's endpoint or touching its owner.
readonly REQUESTED_POSTGRES_PORT="$(python3 -I -B -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
[[ "$REQUESTED_POSTGRES_PORT" =~ ^[0-9]+$ \
    && "$REQUESTED_POSTGRES_PORT" -ge 1024 \
    && "$REQUESTED_POSTGRES_PORT" -le 65535 ]] || {
  echo 'invalid disposable loopback port' >&2
  exit 1
}

volume_expected=0
tmp_volume_expected=0
run_volume_expected=0
keeper_expected=0
postgres_expected=0
keeper_id=''
postgres_id=''

create_owned_tmpfs_volume() {
  local role="$1"
  local volume_name="$2"
  local volume_options="$3"
  local created_volume volume_shape expected_volume_shape
  created_volume="$(docker volume create \
    --driver local \
    --label "$OWNER_LABEL=$OWNER" \
    --opt type=tmpfs \
    --opt device=tmpfs \
    --opt "o=$volume_options" \
    "$volume_name")"
  [[ "$created_volume" == "$volume_name" ]] || {
    echo "Docker returned an unexpected $role volume identity" >&2
    return 1
  }
  volume_shape="$(docker volume inspect --format \
    "{{.Name}}|{{.Driver}}|{{.Scope}}|{{index .Labels \"$OWNER_LABEL\"}}|{{index .Options \"type\"}}|{{index .Options \"device\"}}|{{index .Options \"o\"}}" \
    "$volume_name")"
  expected_volume_shape="$volume_name|local|local|$OWNER|tmpfs|tmpfs|$volume_options"
  [[ "$volume_shape" == "$expected_volume_shape" ]] || {
    echo "effective $role volume configuration differs from the bounded tmpfs request" >&2
    return 1
  }
}

cleanup() {
  local status="$?"
  local cleanup_status=0
  trap - EXIT INT TERM
  set +e
  # Stop the database service before releasing the keeper or its retained
  # tmpfs mount. Each removal is limited to the exact generated name, ID and
  # owner label recorded by this invocation.
  if [[ "$postgres_expected" -eq 1 ]]; then
    stop_and_remove_owned_container postgres "$POSTGRES_NAME" "$postgres_id" || cleanup_status=1
  fi
  if [[ "$run_volume_expected" -eq 1 ]]; then
    remove_owned_volume postgres-run "$RUN_VOLUME_NAME" || cleanup_status=1
  fi
  if [[ "$tmp_volume_expected" -eq 1 ]]; then
    remove_owned_volume postgres-tmp "$TMP_VOLUME_NAME" || cleanup_status=1
  fi
  if [[ "$keeper_expected" -eq 1 ]]; then
    stop_and_remove_owned_container keeper "$KEEPER_NAME" "$keeper_id" || cleanup_status=1
  fi
  if [[ "$volume_expected" -eq 1 ]]; then
    remove_owned_volume retained-data "$VOLUME_NAME" || cleanup_status=1
  fi
  if [[ "$cleanup_status" -ne 0 ]]; then
    echo "cleanup incomplete; exact owner=$OWNER data_volume=$VOLUME_NAME tmp_volume=$TMP_VOLUME_NAME run_volume=$RUN_VOLUME_NAME" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

volume_expected=1
create_owned_tmpfs_volume retained-data "$VOLUME_NAME" "$VOLUME_OPTIONS"

tmp_volume_expected=1
create_owned_tmpfs_volume postgres-tmp "$TMP_VOLUME_NAME" "$TMP_VOLUME_OPTIONS"

run_volume_expected=1
create_owned_tmpfs_volume postgres-run "$RUN_VOLUME_NAME" "$RUN_VOLUME_OPTIONS"

keeper_expected=1
keeper_id="$(docker container create \
  --pull=never \
  --name "$KEEPER_NAME" \
  --label "$OWNER_LABEL=$OWNER" \
  --network none \
  --ipc none \
  --memory 64m \
  --memory-swap 64m \
  --pids-limit 32 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --log-driver none \
  --no-healthcheck \
  --restart no \
  --user 70:70 \
  --env "SUNRISE_EDGE_PG_RUNNER_OWNER=$OWNER" \
  --mount "type=volume,source=$VOLUME_NAME,target=/var/lib/postgresql,volume-nocopy" \
  --entrypoint /bin/sh \
  "$POSTGRES_IMAGE" \
  -ceu 'printf "%s\n" "$SUNRISE_EDGE_PG_RUNNER_OWNER" > /var/lib/postgresql/.sunrise-edge-runner-owner; trap "exit 0" TERM INT HUP; while :; do sleep 60 & wait $!; done')"
[[ "$keeper_id" =~ ^[0-9a-f]{64}$ ]] || {
  echo 'Docker returned an invalid keeper container ID' >&2
  exit 1
}
docker container start "$keeper_id" >/dev/null

keeper_limits="$(docker container inspect --format \
  '{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.Privileged}}|{{.HostConfig.ReadonlyRootfs}}' \
  "$keeper_id")"
[[ "$keeper_limits" == '67108864|67108864|32|none|false|true' ]] || {
  echo 'effective keeper resource or isolation limits differ' >&2
  exit 1
}

validate_mount_script=$(cat <<'EOF'
set -eu
owner="$1"
target="$2"
matches="$(awk -v target="$target" '
  $5 == target {
    count += 1
    separator = 0
    for (i = 7; i <= NF; i += 1) if ($i == "-") { separator = i; break }
    if (separator == 0 || $4 != "/" || $(separator + 1) != "tmpfs") exit 20
    options = "," $6 "," $(separator + 3) ","
    if (options !~ /,rw,/ || options !~ /,nosuid,/ || options !~ /,nodev,/ ||
        options !~ /,noexec,/ || options !~ /,noswap,/) exit 21
    print $3
  }
  END { if (count != 1) exit 22 }
' /proc/self/mountinfo)"
blocks="$(df -Pk "$target" | awk 'NR == 2 { print $2 }')"
inodes="$(df -Pi "$target" | awk 'NR == 2 { print $2 }')"
[ "$blocks" = 524288 ]
[ "$inodes" = 16384 ]
[ "$(cat "$target/.sunrise-edge-runner-owner")" = "$owner" ]
printf '%s\n' "$matches"
EOF
)

validate_scratch_mount_script=$(cat <<'EOF'
set -eu
target="$(readlink -f "$1")"
expected_blocks="$2"
expected_inodes="$3"
expected_metadata="$4"
matches="$(awk -v target="$target" '
  $5 == target {
    count += 1
    separator = 0
    for (i = 7; i <= NF; i += 1) if ($i == "-") { separator = i; break }
    if (separator == 0 || $4 != "/" || $(separator + 1) != "tmpfs") exit 20
    options = "," $6 "," $(separator + 3) ","
    if (options !~ /,rw,/ || options !~ /,nosuid,/ || options !~ /,nodev,/ ||
        options !~ /,noexec,/ || options !~ /,noswap,/) exit 21
    print $3
  }
  END { if (count != 1) exit 22 }
' /proc/self/mountinfo)"
[ "$(df -Pk "$target" | awk 'NR == 2 { print $2 }')" = "$expected_blocks" ]
[ "$(df -Pi "$target" | awk 'NR == 2 { print $2 }')" = "$expected_inodes" ]
[ "$(stat -c '%a|%u|%g' "$target")" = "$expected_metadata" ]
printf '%s\n' "$matches"
EOF
)

keeper_device=''
for _ in $(seq 1 20); do
  if keeper_device="$(docker container exec "$keeper_id" /bin/sh -ceu \
    "$validate_mount_script" -- "$OWNER" /var/lib/postgresql 2>/dev/null)"; then
    break
  fi
  keeper_device=''
  sleep 0.1
done
[[ "$keeper_device" =~ ^[0-9]+:[0-9]+$ ]] || {
  echo 'keeper retained mount did not become valid within two seconds' >&2
  exit 1
}
keeper_effective_limits="$(docker container exec "$keeper_id" /bin/sh -ceu \
  'printf "%s|%s|%s\n" "$(cat /sys/fs/cgroup/memory.max)" "$(cat /sys/fs/cgroup/memory.swap.max)" "$(cat /sys/fs/cgroup/pids.max)"')"
[[ "$keeper_effective_limits" == '67108864|0|32' ]] || {
  echo 'effective keeper cgroup limits differ' >&2
  exit 1
}

postgres_expected=1
postgres_id="$(docker container create \
  --pull=never \
  --name "$POSTGRES_NAME" \
  --label "$OWNER_LABEL=$OWNER" \
  --network bridge \
  --publish "127.0.0.1:$REQUESTED_POSTGRES_PORT:5432" \
  --memory 1g \
  --memory-swap 1g \
  --pids-limit 512 \
  --shm-size 64m \
  --read-only \
  --security-opt no-new-privileges=true \
  --log-driver none \
  --no-healthcheck \
  --restart no \
  --mount "type=volume,source=$VOLUME_NAME,target=/var/lib/postgresql,volume-nocopy" \
  --mount "type=volume,source=$TMP_VOLUME_NAME,target=/tmp,volume-nocopy" \
  --mount "type=volume,source=$RUN_VOLUME_NAME,target=/var/run/postgresql,volume-nocopy" \
  --env "POSTGRES_PASSWORD=$POSTGRES_PASSWORD" \
  --env POSTGRES_USER=postgres \
  --env "POSTGRES_DB=$PG_DATABASE" \
  --env PGDATA=/var/lib/postgresql/18/docker \
  --env 'POSTGRES_INITDB_ARGS=--locale=C --encoding=UTF8 --auth-local=trust --auth-host=scram-sha-256' \
  "$POSTGRES_IMAGE" \
  -c fsync=on \
  -c synchronous_commit=on)"
[[ "$postgres_id" =~ ^[0-9a-f]{64}$ ]] || {
  echo 'Docker returned an invalid PostgreSQL container ID' >&2
  exit 1
}

postgres_limits="$(docker container inspect --format \
  '{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Privileged}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.LogConfig.Type}}|{{json .HostConfig.Binds}}' \
  "$postgres_id")"
case "$postgres_limits" in
  '1073741824|1073741824|512|false|true|none|null'|'1073741824|1073741824|512|false|true|none|[]') ;;
  *) echo 'effective PostgreSQL resource limits or bind policy differ' >&2; exit 1 ;;
esac

postgres_mounts="$(docker container inspect --format \
  '{{range .Mounts}}{{printf "%s|%s|%s|%t\n" .Name .Type .Destination .RW}}{{end}}' \
  "$postgres_id")"
# Docker adds its own terminal newline after this already LF-framed template.
# Strip terminal framing before sorting, so it cannot become a leading empty row.
postgres_mounts="$(printf '%s\n' "$postgres_mounts" | sort)"
expected_postgres_mounts=$(printf '%s\n%s\n%s\n' \
  "$VOLUME_NAME|volume|/var/lib/postgresql|true" \
  "$TMP_VOLUME_NAME|volume|/tmp|true" \
  "$RUN_VOLUME_NAME|volume|/var/run/postgresql|true" | sort)
[[ "$postgres_mounts" == "$expected_postgres_mounts" ]] || {
  echo 'PostgreSQL is not attached only to the three exact bounded volumes' >&2
  printf 'actual mounts: %s\nexpected mounts: %s\n' "$postgres_mounts" "$expected_postgres_mounts" >&2
  exit 1
}

docker container start "$postgres_id" >/dev/null

tmp_device="$(docker container exec "$postgres_id" /bin/sh -ceu \
  "$validate_scratch_mount_script" -- /tmp 16384 2048 '1777|0|0')"
run_device="$(docker container exec "$postgres_id" /bin/sh -ceu \
  "$validate_scratch_mount_script" -- /var/run/postgresql 4096 1024 '3775|70|70')"
[[ "$tmp_device" =~ ^[0-9]+:[0-9]+$ && "$run_device" =~ ^[0-9]+:[0-9]+$ \
    && "$tmp_device" != "$run_device" && "$tmp_device" != "$keeper_device" \
    && "$run_device" != "$keeper_device" ]] || {
  echo 'PostgreSQL scratch tmpfs mount identities are not distinct and valid' >&2
  exit 1
}

ready=0
for _ in $(seq 1 120); do
  # Image initialization briefly starts a Unix-socket-only temporary server.
  # Require TCP readiness so that server cannot be mistaken for final startup.
  if docker container exec "$postgres_id" pg_isready -q -h 127.0.0.1 -p 5432 -U postgres -d "$PG_DATABASE"; then
    ready=1
    break
  fi
  sleep 0.5
done
[[ "$ready" -eq 1 ]] || {
  echo 'PostgreSQL did not become ready within 60 seconds' >&2
  exit 1
}

postgres_effective_limits="$(docker container exec "$postgres_id" /bin/sh -ceu \
  'printf "%s|%s|%s\n" "$(cat /sys/fs/cgroup/memory.max)" "$(cat /sys/fs/cgroup/memory.swap.max)" "$(cat /sys/fs/cgroup/pids.max)"')"
[[ "$postgres_effective_limits" == '1073741824|0|512' ]] || {
  echo 'effective PostgreSQL cgroup limits differ' >&2
  exit 1
}

port_row="$(docker container port "$postgres_id" 5432/tcp)"
[[ "$port_row" =~ ^127\.0\.0\.1:([0-9]+)$ ]] || {
  echo "unexpected PostgreSQL published endpoint: $port_row" >&2
  exit 1
}
readonly POSTGRES_PORT="${BASH_REMATCH[1]}"
[[ "$POSTGRES_PORT" == "$REQUESTED_POSTGRES_PORT" ]] || {
  echo 'PostgreSQL endpoint differs from the concrete requested port' >&2
  exit 1
}
readonly POSTGRES_URL="postgresql://postgres:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${PG_DATABASE}"

postgres_device="$(docker container exec "$postgres_id" /bin/sh -ceu "$validate_mount_script" -- "$OWNER" /var/lib/postgresql)"
[[ "$postgres_device" == "$keeper_device" ]] || {
  echo 'keeper and PostgreSQL do not observe the same retained tmpfs' >&2
  exit 1
}

database_identity="$(docker container exec "$postgres_id" psql -X -qAt \
  -U postgres -d "$PG_DATABASE" \
  -c "SELECT current_database(), system_identifier::text, current_setting('data_directory'), current_setting('fsync'), current_setting('synchronous_commit') FROM pg_control_system();")"
IFS='|' read -r actual_database initial_cluster data_directory fsync synchronous_commit <<< "$database_identity"
[[ "$actual_database" == "$PG_DATABASE" ]] || {
  echo 'refusing to run against a non-test database' >&2
  exit 1
}
[[ "$initial_cluster" =~ ^[0-9]+$ && "$data_directory" == /var/lib/postgresql/18/docker && "$fsync" == on ]] || {
  echo 'PostgreSQL identity or durability settings differ' >&2
  exit 1
}
case "$synchronous_commit" in
  on|remote_apply) ;;
  *) echo 'PostgreSQL synchronous_commit does not provide the required acknowledgement' >&2; exit 1 ;;
esac

# Remove any inherited profile fragments so a selected target cannot be
# broadened, redirected or silently downgraded by the invoking environment.
unset SUNRISE_EDGE_TEST_POSTGRES_URL \
  SUNRISE_EDGE_TEST_POSTGRES_CONTAINER_ID \
  SUNRISE_EDGE_TEST_POSTGRES_CRASH_REQUIRED \
  SUNRISE_EDGE_TEST_POSTGRES_DISK_FULL_IMAGE \
  SUNRISE_EDGE_TEST_POSTGRES_DISK_FULL_REQUIRED \
  SUNRISE_EDGE_TEST_POSTGRES_WAL_FULL_IMAGE \
  SUNRISE_EDGE_TEST_POSTGRES_WAL_FULL_REQUIRED \
  SUNRISE_EDGE_TEST_POSTGRES_CONNECTION_EXHAUSTION_IMAGE \
  SUNRISE_EDGE_TEST_POSTGRES_CONNECTION_EXHAUSTION_REQUIRED \
  SUNRISE_EDGE_TEST_POSTGRES_BACKUP_RESTORE_IMAGE \
  SUNRISE_EDGE_TEST_POSTGRES_BACKUP_RESTORE_REQUIRED \
  SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_POSTGRES_IMAGE \
  SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_IMAGE \
  SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_REQUIRED

export SUNRISE_EDGE_TEST_POSTGRES_URL="$POSTGRES_URL"
if [[ "$SELECTION" != schema ]]; then
  export SUNRISE_EDGE_TEST_POSTGRES_CONTAINER_ID="$postgres_id"
  export SUNRISE_EDGE_TEST_POSTGRES_CRASH_REQUIRED=1
fi

printf 'POSTGRES_RUNNER_RECEIPT selection=%s owner=%s data_volume=%s tmp_volume=%s run_volume=%s keeper_name=%s keeper_id=%s postgres_name=%s postgres_id=%s loopback_port=%s\n' \
  "$SELECTION" "$OWNER" "$VOLUME_NAME" "$TMP_VOLUME_NAME" "$RUN_VOLUME_NAME" \
  "$KEEPER_NAME" "$keeper_id" "$POSTGRES_NAME" "$postgres_id" "$POSTGRES_PORT"

case "$SELECTION" in
  schema)
    cargo test --locked --offline -p runtime-postgres --all-features --test postgres_schema -- --nocapture --test-threads=1
    ;;
  crash)
    cargo test --locked --offline -p runtime-postgres --all-features --test postgres_crash_recovery -- --nocapture --test-threads=1
    ;;
  suite|profile)
    export SUNRISE_EDGE_TEST_POSTGRES_DISK_FULL_IMAGE="$POSTGRES_IMAGE"
    export SUNRISE_EDGE_TEST_POSTGRES_DISK_FULL_REQUIRED=1
    export SUNRISE_EDGE_TEST_POSTGRES_WAL_FULL_IMAGE="$POSTGRES_IMAGE"
    export SUNRISE_EDGE_TEST_POSTGRES_WAL_FULL_REQUIRED=1
    export SUNRISE_EDGE_TEST_POSTGRES_CONNECTION_EXHAUSTION_IMAGE="$POSTGRES_IMAGE"
    export SUNRISE_EDGE_TEST_POSTGRES_CONNECTION_EXHAUSTION_REQUIRED=1
    export SUNRISE_EDGE_TEST_POSTGRES_BACKUP_RESTORE_IMAGE="$POSTGRES_IMAGE"
    export SUNRISE_EDGE_TEST_POSTGRES_BACKUP_RESTORE_REQUIRED=1
    export SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_POSTGRES_IMAGE="$POSTGRES_IMAGE"
    export SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_IMAGE="$PGBOUNCER_IMAGE"
    export SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_REQUIRED=1
    # Fault cases deliberately restart shared disposable services. Serialize
    # them without omitting a target, selector or required prerequisite.
    if [[ "$SELECTION" == suite ]]; then
      cargo test --locked --offline -p runtime-postgres --all-targets --all-features -- --nocapture --test-threads=1
    else
      export RUST_TEST_THREADS=1
      for group in pg-storage pg-lifecycle pg-drain-history pg-business-audit pg-recovery-economics; do
        bash scripts/check-all.sh --group "$group"
      done
    fi
    ;;
esac

# A successful crash selection is accepted only if the same keeper, volume,
# marker and PostgreSQL system identifier remain after the test. This proves
# the restarted service did not merely initialize a new empty container tmpfs.
post_keeper_id="$(inspect_owned_container "$KEEPER_NAME" "$keeper_id")"
post_postgres_id="$(inspect_owned_container "$POSTGRES_NAME" "$postgres_id")"
[[ "$post_keeper_id" == "$keeper_id" && "$post_postgres_id" == "$postgres_id" ]] || {
  echo 'owned container identity changed during the test' >&2
  exit 1
}
post_keeper_device="$(docker container exec "$keeper_id" /bin/sh -ceu "$validate_mount_script" -- "$OWNER" /var/lib/postgresql)"
post_postgres_device="$(docker container exec "$postgres_id" /bin/sh -ceu "$validate_mount_script" -- "$OWNER" /var/lib/postgresql)"
[[ "$post_keeper_device" == "$keeper_device" && "$post_postgres_device" == "$keeper_device" ]] || {
  echo 'retained tmpfs identity changed during the test' >&2
  exit 1
}
final_cluster="$(docker container exec "$postgres_id" psql -X -qAt \
  -U postgres -d "$PG_DATABASE" -c 'SELECT system_identifier::text FROM pg_control_system();')"
[[ "$final_cluster" == "$initial_cluster" ]] || {
  echo 'PostgreSQL cluster identity changed; refusing restart-empty recovery evidence' >&2
  exit 1
}
[[ "$(docker container port "$postgres_id" 5432/tcp)" == "127.0.0.1:$POSTGRES_PORT" ]] || {
  echo 'PostgreSQL loopback endpoint changed during the test' >&2
  exit 1
}

printf 'PostgreSQL %s tests passed with retained cluster %s on loopback port %s.\n' \
  "$SELECTION" "$final_cluster" "$POSTGRES_PORT"
