#!/usr/bin/env node
// Docker/Linux-UID/PTY acceptance fixture for the publication-only local OS
// custody implementation (DR-0238,
// docs/architecture/local-publication-custody.md). This is Docker-only
// capability/behavior evidence for genuinely distinct real Linux UIDs and a
// real pseudo-terminal, not a Rust unit-test substitute and not a claim that
// the production candidate is otherwise defect-free: owner/socket-cleanup/
// timeout issues in the candidate are tracked and fixed separately, and this
// fixture is deliberately not weakened to paper over them.
//
// This script never executes anything itself at import time beyond Docker
// CLI subprocesses and `ldd` on two already-compiled host paths it is given;
// it builds, launches, and tears down exactly one container.
//
// Required inputs (no default, no discovery/globbing):
//   --cli-binary <absolute path>   the compiled `sunrise-edge-cli` binary
//   --test-binary <absolute path>  the compiled `sunrise-edge-cli` *test*
//                                  harness binary (the one `cargo test -p
//                                  sunrise-edge-cli --lib --no-run` reports
//                                  as the crate's `Executable(...)`), which
//                                  contains the fixture-only ignored probe
//                                  `custody::client::tests::fixture_distinct_uid_round_trip`
//                                  added to apps/cli/src/custody/client.rs.
//
// Exact owning command (see this file's own header comment for how to
// obtain --test-binary; this is a separately selected Docker profile):
//   node scripts/check-docker-custody-fixture-1013.mjs \
//     --cli-binary /abs/path/to/target/.../sunrise-edge-cli \
//     --test-binary /abs/path/to/target/.../deps/sunrise_edge_cli-<hash>
import { spawn, execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { existsSync, statSync } from 'node:fs';
import { basename } from 'node:path';

const image = 'python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea';
const imageId = 'sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea';
const endpoint = 'unix:///var/run/docker.sock';
const owner = randomUUID();
const name = `sunrise-edge-custody-fixture-1013-${owner}`;
const label = 'sunrise-edge.custody-fixture-1013-owner';
const volumeName = `${name}-memory`;
const volumeOptions = 'rw,nosuid,nodev,noexec,size=64m,nr_inodes=16384,mode=0711,uid=0,gid=0,noswap';
const deadline = performance.now() + 280_000;
const outputLimit = 65_536;
const cleanupReserve = 16_384;
const dockerEnvironment = { ...process.env };
for (const variable of ['DOCKER_CONTEXT', 'DOCKER_HOST', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) {
  delete dockerEnvironment[variable];
}
const pendingClients = new Set();
let outputBytes = 0;
let containerId;
let primaryError;
let result;
let volumeExpected = false;
let volumeMountpoint;

// ---- argument parsing: explicit, absolute, pre-validated host paths only ----

function parseArgs(argv) {
  const out = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--cli-binary') out.cliBinary = value;
    else if (flag === '--test-binary') out.testBinary = value;
    else throw new Error(`unknown or incomplete argument: ${flag ?? '(missing)'}`);
  }
  if (!out.cliBinary || !out.testBinary) {
    throw new Error('both --cli-binary and --test-binary are required, with no default or discovery');
  }
  for (const [label_, path] of [['--cli-binary', out.cliBinary], ['--test-binary', out.testBinary]]) {
    if (!path.startsWith('/')) throw new Error(`${label_} must be an absolute path`);
    if (!existsSync(path)) throw new Error(`${label_} does not exist: ${path}`);
    const info = statSync(path);
    if (!info.isFile() || (info.mode & 0o111) === 0) {
      throw new Error(`${label_} is not an executable regular file: ${path}`);
    }
    assertMountSafePath(label_, path);
  }
  return out;
}

// `--mount` values are comma-delimited `key=value` pairs with no escaping,
// so every path embedded in one must be rejected if it could itself alter
// that parsing.
function assertMountSafePath(label_, path) {
  if (/["',\s]/.test(path)) {
    throw new Error(`${label_} must not contain whitespace, a comma, or a quote character: ${path}`);
  }
}

const { cliBinary, testBinary } = parseArgs(process.argv.slice(2));

// ---- resolving the exact dynamic-linker/shared-library closure via `ldd` ----
//
// Mounted at a dedicated /mnt/libs namespace (never at the image's own
// system-library paths), and invoked via an explicit `ld.so --library-path`
// call, so the host's glibc never shadows or replaces anything the base
// image's own Python needs.

function lddClosure(binaryPath) {
  const output = execFileSync('ldd', [binaryPath], { encoding: 'utf8' });
  let interpreter;
  const libs = new Map();
  for (const rawLine of output.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    const arrowMatch = line.match(/=>\s*(\/\S+)\s+\(0x/);
    const directMatch = line.match(/^(\/\S+)\s+\(0x/);
    const candidate = arrowMatch ? arrowMatch[1] : directMatch ? directMatch[1] : null;
    if (!candidate || !existsSync(candidate)) continue;
    assertMountSafePath(`${binaryPath} dependency`, candidate);
    if (basename(candidate).startsWith('ld-linux') || basename(candidate) === 'ld.so') {
      if (interpreter !== undefined && interpreter !== candidate) {
        throw new Error(`${binaryPath}: ambiguous dynamic linker (${interpreter} vs ${candidate})`);
      }
      interpreter = candidate;
      continue;
    }
    const existing = libs.get(basename(candidate));
    if (existing !== undefined && existing !== candidate) {
      throw new Error(`${binaryPath}: two different libraries share the basename ${basename(candidate)}`);
    }
    libs.set(basename(candidate), candidate);
  }
  if (interpreter === undefined) throw new Error(`${binaryPath}: no dynamic linker found in ldd output`);
  return { interpreter, libs };
}

function mergeClosures(a, b) {
  if (a.interpreter !== b.interpreter) {
    throw new Error(`the CLI and test binaries require two different dynamic linkers (${a.interpreter} vs ${b.interpreter})`);
  }
  const libs = new Map(a.libs);
  for (const [name_, path] of b.libs) {
    const existing = libs.get(name_);
    if (existing !== undefined && existing !== path) {
      throw new Error(`the CLI and test binaries require two different libraries named ${name_}`);
    }
    libs.set(name_, path);
  }
  return { interpreter: a.interpreter, libs };
}

const closure = mergeClosures(lddClosure(cliBinary), lddClosure(testBinary));

const binds = [
  `type=bind,source=${cliBinary},target=/mnt/bin/cli,readonly`,
  `type=bind,source=${testBinary},target=/mnt/bin/harness,readonly`,
  `type=bind,source=${closure.interpreter},target=/mnt/libs/ld.so,readonly`,
  ...[...closure.libs.values()].map((path) => `type=bind,source=${path},target=/mnt/libs/${basename(path)},readonly`),
];

// ---- the embedded fixture probe: every real Linux-UID/PTY/socket/filesystem ----
// behavior runs here, as PID 1 inside the container (root, with exactly the
// four capabilities it needs to create/own the fixture's UID-separated
// paths and to `setuid`/`setgid` into each fixture UID before ever running
// a custody binary); no host user, dependency install, or `docker exec` is
// used. See apps/cli/src/custody/client.rs for the one test-only probe this
// invokes by its exact name, and docs/architecture/local-publication-custody.md
// for the recipe this follows.

const probe = String.raw`
import errno, json, os, pty, select, socket, stat, subprocess, sys, time

ROOT = "/work"
CUSTODY_UID, CUSTODY_GID = 12001, 12001
OPERATOR_UID, OPERATOR_GID = 12002, 12002
INTRUDER_UID, INTRUDER_GID = 12003, 12003

LD_SO = "/mnt/libs/ld.so"
LIB_DIR = "/mnt/libs"
CLI = "/mnt/bin/cli"
HARNESS = "/mnt/bin/harness"

CHAIN_ID = "sunrise-local-devnet"
PROTOCOL_VERSION = "3"
EPOCH = "0"
HASH_SUITE_ID = "1"
DOMAIN_HEX = "44" * 32
MAIN_REQUEST_ID = "5a" * 32
UNAPPROVED_REQUEST_ID = "11" * 32
EXPIRING_REQUEST_ID = "22" * 32

INTERNAL_DEADLINE = time.monotonic() + 230.0
OUTPUT_CAP = 262_144
_output_used = 0


class FixtureFailure(RuntimeError):
    pass


def remaining():
    left = INTERNAL_DEADLINE - time.monotonic()
    if left <= 0:
        raise FixtureFailure("internal fixture deadline exceeded")
    return left


def charge_output(count):
    global _output_used
    _output_used += count
    if _output_used > OUTPUT_CAP:
        raise FixtureFailure("captured command/PTY output exceeds the fixture's bounded allocation")


def run_exec(argv, uid, gid, groups, env=None, timeout=20, input_bytes=None):
    def preexec():
        os.setgroups(groups)
        os.setgid(gid)
        os.setuid(uid)

    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=preexec,
        env=env or {},
        cwd="/",
    )
    try:
        out, err = proc.communicate(input=input_bytes, timeout=min(timeout, remaining()))
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        raise FixtureFailure(f"command timed out: {argv!r}")
    charge_output(len(out) + len(err))
    return proc.returncode, out, err


def cli_argv(*args):
    return [LD_SO, "--library-path", LIB_DIR, CLI, *args]


def harness_argv():
    return [
        LD_SO, "--library-path", LIB_DIR, HARNESS,
        "custody::client::tests::fixture_distinct_uid_round_trip",
        "--exact", "--ignored", "--nocapture",
    ]


def harness_env(mode, **overrides):
    env = {
        "CUSTODY_FIXTURE_MODE": mode,
        "CUSTODY_FIXTURE_CHAIN_ID": CHAIN_ID,
        "CUSTODY_FIXTURE_PROTOCOL_VERSION": PROTOCOL_VERSION,
        "CUSTODY_FIXTURE_EPOCH": EPOCH,
        "CUSTODY_FIXTURE_HASH_SUITE_ID": HASH_SUITE_ID,
        "CUSTODY_FIXTURE_DOMAIN_HEX": DOMAIN_HEX,
        "CUSTODY_FIXTURE_NONCE": "1",
        "CUSTODY_FIXTURE_REQUEST_ID_HEX": MAIN_REQUEST_ID,
    }
    env.update(overrides)
    return env


def last_json_line(raw_bytes):
    text = raw_bytes.decode("utf8", "replace")
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    raise FixtureFailure("expected JSON evidence line was not found in harness output")


def phase_setup():
    for path, expected in [
        ("/sys/fs/cgroup/memory.max", "536870912"),
        ("/sys/fs/cgroup/memory.swap.max", "0"),
        ("/sys/fs/cgroup/pids.max", "64"),
        ("/sys/fs/cgroup/cpu.max", "100000 100000"),
    ]:
        with open(path) as source:
            if source.read(128).strip() != expected:
                raise FixtureFailure("effective custody fixture resource bound differs")
    with open("/proc/self/mountinfo") as source:
        mounts = source.read(65537)
    if len(mounts) > 65536:
        raise FixtureFailure("fixture mount inventory exceeds bound")
    rows = [line.split() for line in mounts.splitlines() if line.split()[4] == ROOT]
    if len(rows) != 1:
        raise FixtureFailure("fixture allocation is not one literal mount")
    row = rows[0]
    separator = row.index("-")
    options = set(row[5].split(",")) | set(row[separator + 3].split(","))
    if row[separator + 1] != "tmpfs" or not {"rw", "noswap", "nosuid", "nodev", "noexec"}.issubset(options):
        raise FixtureFailure("fixture allocation lacks effective tmpfs/noswap isolation")
    allocation = os.statvfs(ROOT)
    if allocation.f_frsize * allocation.f_blocks != 64 * 1024 * 1024:
        raise FixtureFailure("fixture allocation is not exactly 64MiB")
    os.umask(0)
    entries = [
        (f"{ROOT}/custody-keys", 0o700, CUSTODY_UID, CUSTODY_GID),
        (f"{ROOT}/custody-approvals", 0o700, CUSTODY_UID, CUSTODY_GID),
        (f"{ROOT}/custody-artifacts", 0o700, CUSTODY_UID, CUSTODY_GID),
        (f"{ROOT}/run", 0o750, CUSTODY_UID, CUSTODY_GID),
        (f"{ROOT}/operator", 0o700, OPERATOR_UID, OPERATOR_GID),
        (f"{ROOT}/intruder", 0o700, INTRUDER_UID, INTRUDER_GID),
        # Narrowly scoped: used only as the transient coordination point for
        # the impostor-peer-UID listener both the intruder (bind) and the
        # operator (connect) must reach; nothing sensitive is ever stored
        # here, and the socket is unlinked immediately after that one check.
        (f"{ROOT}/shared", 0o777, 0, 0),
    ]
    for path, mode, uid, gid in entries:
        os.mkdir(path, mode)
        os.chmod(path, mode)
        os.chown(path, uid, gid)


def phase_missing_prerequisite_fails():
    rc, _out, err = run_exec(harness_argv(), OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID], env={}, timeout=15)
    if rc == 0:
        raise FixtureFailure(
            "the fixture probe succeeded (or was silently skipped) with every "
            "required environment variable missing; it must fail closed instead"
        )
    if b"prerequisite missing" not in err:
        raise FixtureFailure("the fixture probe did not fail with its documented missing-prerequisite message")


def phase_keygen():
    rc, out, err = run_exec(
        cli_argv("custody", "keygen", "--key-file", f"{ROOT}/custody-keys/custody.seed"),
        CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID], timeout=20,
    )
    if rc != 0:
        raise FixtureFailure(f"custody keygen failed: {err.decode('utf8', 'replace')}")
    public_key = None
    for line in out.decode("ascii", "strict").splitlines():
        if line.startswith("public_key="):
            public_key = line.split("=", 1)[1].strip()
    if not public_key or len(public_key) != 64:
        raise FixtureFailure("custody keygen did not print a 64-hex public_key")
    # Metadata only: the seed's own bytes are never read, printed, or compared.
    key_stat = os.stat(f"{ROOT}/custody-keys/custody.seed")
    if stat.S_IMODE(key_stat.st_mode) != 0o600 or key_stat.st_uid != CUSTODY_UID:
        raise FixtureFailure("custody key file metadata is not exactly owner=custody, mode 0600")
    dir_stat = os.stat(f"{ROOT}/custody-keys")
    if stat.S_IMODE(dir_stat.st_mode) != 0o700:
        raise FixtureFailure("custody key directory metadata is not exactly mode 0700")
    return public_key


def phase_write_config(public_key):
    config_path = f"{ROOT}/custody-keys/custody.config"
    text = (
        f"chain_id={CHAIN_ID}\n"
        f"protocol_version={PROTOCOL_VERSION}\n"
        f"epoch={EPOCH}\n"
        f"hash_suite_id={HASH_SUITE_ID}\n"
        f"domain={DOMAIN_HEX}\n"
        f"publisher_public_key={public_key}\n"
        f"operator_uid={OPERATOR_UID}\n"
    )
    fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, text.encode("ascii"))
    finally:
        os.close(fd)
    os.chown(config_path, CUSTODY_UID, CUSTODY_GID)
    return config_path


def phase_generate_artifact(public_key, request_id_hex, nonce, out_path, wasm_first_byte="0"):
    env = harness_env(
        "generate-artifact",
        CUSTODY_FIXTURE_PUBLISHER_HEX=public_key,
        CUSTODY_FIXTURE_REQUEST_ID_HEX=request_id_hex,
        CUSTODY_FIXTURE_NONCE=str(nonce),
        CUSTODY_FIXTURE_ARTIFACT_OUT=out_path,
        CUSTODY_FIXTURE_WASM_FIRST_BYTE=wasm_first_byte,
    )
    rc, out, err = run_exec(harness_argv(), CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID], env=env, timeout=20)
    if rc != 0:
        raise FixtureFailure(f"independent artifact generation failed: {err.decode('utf8', 'replace')}")
    evidence = last_json_line(out)
    if evidence.get("mode") != "generate-artifact" or not isinstance(evidence.get("artifact_bytes"), int) or evidence["artifact_bytes"] <= 0:
        raise FixtureFailure("artifact generation did not report a positive byte count")
    size = os.stat(out_path).st_size
    if size != evidence["artifact_bytes"]:
        raise FixtureFailure("the generated artifact file size does not match its own reported byte count")
    artifact_stat = os.stat(out_path)
    if artifact_stat.st_uid != CUSTODY_UID or stat.S_IMODE(artifact_stat.st_mode) != 0o600:
        raise FixtureFailure("the independently approved preimage is not custody-owned mode 0600")


def phase_approve_via_pty(config_path, artifact_path, nonce, request_id_hex, expires_in_seconds):
    argv = cli_argv(
        "custody", "approve",
        "--config", config_path,
        "--approvals-dir", f"{ROOT}/custody-approvals",
        "--approved-artifact", artifact_path,
        "--nonce", str(nonce),
        "--request-id", request_id_hex,
        "--expires-in-seconds", str(expires_in_seconds),
    )
    pid, master_fd = pty.fork()
    if pid == 0:
        try:
            os.setgroups([CUSTODY_GID])
            os.setgid(CUSTODY_GID)
            os.setuid(CUSTODY_UID)
            os.execv(argv[0], argv)
        finally:
            os._exit(127)

    captured = b""
    cap = 16_384
    marker = "Type exactly to approve:\n"
    confirmation_line = None
    pty_deadline = time.monotonic() + min(20, remaining())
    try:
        while True:
            left = pty_deadline - time.monotonic()
            if left <= 0:
                raise FixtureFailure("custody approve PTY interaction timed out")
            ready, _, _ = select.select([master_fd], [], [], left)
            if not ready:
                continue
            try:
                chunk = os.read(master_fd, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    break  # the PTY slave closed: the child has exited
                raise
            if not chunk:
                break
            captured += chunk
            if len(captured) > cap:
                raise FixtureFailure("custody approve PTY output exceeds its bounded allocation")
            if confirmation_line is None:
                text = captured.decode("utf8", "replace").replace("\r\n", "\n")
                if marker in text:
                    after = text.split(marker, 1)[1]
                    if "\n" in after:
                        confirmation_line = after.split("\n", 1)[0].strip()
                        os.write(master_fd, (confirmation_line + "\n").encode("ascii"))
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass
    _pid, status = os.waitpid(pid, 0)
    if confirmation_line is None:
        raise FixtureFailure("custody approve never printed the expected typed-confirmation prompt")
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise FixtureFailure(f"custody approve over a real PTY exited abnormally: status={status}")
    record_path = f"{ROOT}/custody-approvals/{request_id_hex}"
    record_stat = os.stat(record_path)
    if stat.S_IMODE(record_stat.st_mode) != 0o600 or record_stat.st_uid != CUSTODY_UID:
        raise FixtureFailure("the written approval record's metadata is not exactly owner=custody, mode 0600")


def phase_approve_without_terminal(config_path, artifact_path):
    argv = cli_argv(
        "custody", "approve",
        "--config", config_path,
        "--approvals-dir", f"{ROOT}/custody-approvals",
        "--approved-artifact", artifact_path,
        "--nonce", "1",
        "--request-id", MAIN_REQUEST_ID,
        "--expires-in-seconds", "3600",
    )
    rc, _out, _err = run_exec(argv, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID], timeout=10)
    if rc == 0:
        raise FixtureFailure("custody approve succeeded without a real terminal on stdin/stdout")
    if b"custody approve requires an interactive terminal" not in _err:
        raise FixtureFailure("non-terminal approval failed for a different reason")


def phase_operator_cannot_read_or_edit(request_id_hex):
    def attempt(path, flags):
        pid = os.fork()
        if pid == 0:
            try:
                os.setgroups([OPERATOR_GID, CUSTODY_GID])
                os.setgid(OPERATOR_GID)
                os.setuid(OPERATOR_UID)
                try:
                    fd = os.open(path, flags)
                    os.close(fd)
                    os._exit(1)
                except PermissionError:
                    os._exit(0)
                except OSError:
                    os._exit(2)
            finally:
                os._exit(127)
        _pid, status = os.waitpid(pid, 0)
        return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0

    seed_blocked = attempt(f"{ROOT}/custody-keys/custody.seed", os.O_RDONLY)
    approval_blocked = attempt(f"{ROOT}/custody-approvals/{request_id_hex}", os.O_WRONLY | os.O_TRUNC)
    if not seed_blocked:
        raise FixtureFailure("the operator UID could read custody's seed file")
    if not approval_blocked:
        raise FixtureFailure("the operator UID could edit an existing approval record")


def start_serve(socket_path, total_deadline_secs, max_connections, max_requests):
    argv = cli_argv(
        "custody", "serve",
        "--config", f"{ROOT}/custody-keys/custody.config",
        "--key-file", f"{ROOT}/custody-keys/custody.seed",
        "--socket", socket_path,
        "--approvals-dir", f"{ROOT}/custody-approvals",
        "--max-connections", str(max_connections),
        "--max-requests", str(max_requests),
        "--total-deadline-secs", str(total_deadline_secs),
    )

    def preexec():
        os.setgroups([CUSTODY_GID])
        os.setgid(CUSTODY_GID)
        os.setuid(CUSTODY_UID)

    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=preexec, env={}, cwd="/")
    bind_deadline = time.monotonic() + 10
    while not os.path.exists(socket_path) or stat.S_IMODE(os.stat(socket_path).st_mode) != 0o660:
        if time.monotonic() > bind_deadline:
            proc.kill()
            raise FixtureFailure("custody serve did not bind its socket in time")
        time.sleep(0.05)
    sock_stat = os.stat(socket_path)
    if stat.S_IMODE(sock_stat.st_mode) != 0o660:
        proc.kill()
        raise FixtureFailure("the bound custody socket file mode is not exactly 0660")
    run_stat = os.stat(f"{ROOT}/run")
    if stat.S_IMODE(run_stat.st_mode) != 0o750:
        proc.kill()
        raise FixtureFailure("the custody run directory mode is not exactly 0750")
    return proc


def wait_serve(proc, extra_seconds):
    try:
        out, err = proc.communicate(timeout=min(extra_seconds, remaining()))
    except subprocess.TimeoutExpired:
        proc.kill()
        raise FixtureFailure("custody serve did not self-terminate within its own bounded lifetime")
    charge_output(len(out) + len(err))
    if proc.returncode != 0:
        raise FixtureFailure(f"custody serve exited with a failure status: {err.decode('utf8', 'replace')}")
    return out.decode("utf8", "replace")


def phase_intruder_wrong_peer_uid(socket_path):
    pid = os.fork()
    if pid == 0:
        try:
            # Same group as the operator (custody's own group), so this
            # proves the server checks the exact peer UID, not merely group
            # membership on the socket's directory/file.
            os.setgroups([INTRUDER_GID, CUSTODY_GID])
            os.setgid(INTRUDER_GID)
            os.setuid(INTRUDER_UID)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5)
            connected = False
            try:
                sock.connect(socket_path)
                connected = True
                sock.sendall(b"\x00\x00\x00\x01\x00")
                data = sock.recv(16)
                os._exit(0 if data == b"" else 3)
            except (ConnectionResetError, BrokenPipeError):
                os._exit(0 if connected else 2)
            except OSError:
                os._exit(2)
            finally:
                sock.close()
        finally:
            os._exit(127)
    _pid, status = os.waitpid(pid, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise FixtureFailure("the intruder UID, despite sharing custody's group, was not refused before any byte was read")


def phase_impostor_peer_uid_refusal(public_key, impostor_path):
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([INTRUDER_GID])
            os.setgid(INTRUDER_GID)
            os.setuid(INTRUDER_UID)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(impostor_path)
            sock.listen(1)
            sock.settimeout(8)
            try:
                connection, _addr = sock.accept()
                connection.close()
            except socket.timeout:
                pass
            sock.close()
            os._exit(0)
        finally:
            os._exit(127)
    bind_deadline = time.monotonic() + 5
    while not os.path.exists(impostor_path):
        if time.monotonic() > bind_deadline:
            raise FixtureFailure("the impostor listener did not bind in time")
        time.sleep(0.02)
    env = harness_env(
        "sign-and-verify",
        CUSTODY_FIXTURE_PUBLISHER_HEX=public_key,
        CUSTODY_FIXTURE_SOCKET=impostor_path,
        CUSTODY_FIXTURE_CUSTODY_UID=str(CUSTODY_UID),
    )
    rc, _out, err = run_exec(harness_argv(), OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID], env=env, timeout=15)
    os.waitpid(pid, 0)
    try:
        os.unlink(impostor_path)
    except FileNotFoundError:
        pass
    if rc == 0:
        raise FixtureFailure("the Rust custody client signed against an impostor-peer-UID socket instead of refusing it")
    if b"UnexpectedPeerUid" not in err:
        raise FixtureFailure("the Rust custody client did not report the expected UnexpectedPeerUid refusal")


def expect_sign_failure(label, public_key, socket_path, request_id_hex, nonce, wasm_first_byte="0"):
    env = harness_env(
        "sign-and-verify",
        CUSTODY_FIXTURE_PUBLISHER_HEX=public_key,
        CUSTODY_FIXTURE_SOCKET=socket_path,
        CUSTODY_FIXTURE_CUSTODY_UID=str(CUSTODY_UID),
        CUSTODY_FIXTURE_REQUEST_ID_HEX=request_id_hex,
        CUSTODY_FIXTURE_NONCE=str(nonce),
        CUSTODY_FIXTURE_WASM_FIRST_BYTE=wasm_first_byte,
    )
    rc, _out, err = run_exec(harness_argv(), OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID], env=env, timeout=15)
    if rc == 0:
        raise FixtureFailure(f"{label}: signing unexpectedly succeeded")
    if b"Refused(NoApproval)" not in err:
        raise FixtureFailure(f"{label}: did not report the expected closed refusal")


def expect_sign_success(public_key, socket_path, request_id_hex, nonce):
    env = harness_env(
        "sign-and-verify",
        CUSTODY_FIXTURE_PUBLISHER_HEX=public_key,
        CUSTODY_FIXTURE_SOCKET=socket_path,
        CUSTODY_FIXTURE_CUSTODY_UID=str(CUSTODY_UID),
        CUSTODY_FIXTURE_REQUEST_ID_HEX=request_id_hex,
        CUSTODY_FIXTURE_NONCE=str(nonce),
    )
    rc, out, err = run_exec(harness_argv(), OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID], env=env, timeout=15)
    if rc != 0:
        raise FixtureFailure(f"expected signing success failed: {err.decode('utf8', 'replace')}")
    evidence = last_json_line(out)
    if evidence.get("mode") != "sign-and-verify" or evidence.get("verified") is not True:
        raise FixtureFailure("sign-and-verify did not report independent finalize/verification")
    return evidence


def main():
    phase_setup()
    phase_missing_prerequisite_fails()

    public_key = phase_keygen()
    config_path = phase_write_config(public_key)

    main_artifact = f"{ROOT}/custody-artifacts/main.bin"
    phase_generate_artifact(public_key, MAIN_REQUEST_ID, 1, main_artifact)
    phase_approve_via_pty(config_path, main_artifact, 1, MAIN_REQUEST_ID, 3600)
    phase_approve_without_terminal(config_path, main_artifact)

    expiring_artifact = f"{ROOT}/custody-artifacts/expiring.bin"
    phase_generate_artifact(public_key, EXPIRING_REQUEST_ID, 1, expiring_artifact)
    phase_approve_via_pty(config_path, expiring_artifact, 1, EXPIRING_REQUEST_ID, 1)

    phase_operator_cannot_read_or_edit(MAIN_REQUEST_ID)

    socket_path = f"{ROOT}/run/custody.sock"
    serve_proc = start_serve(socket_path, total_deadline_secs=60, max_connections=6, max_requests=5)

    phase_intruder_wrong_peer_uid(socket_path)
    phase_impostor_peer_uid_refusal(public_key, f"{ROOT}/shared/impostor.sock")

    expect_sign_failure("no-approval", public_key, socket_path, UNAPPROVED_REQUEST_ID, 1)
    expect_sign_failure("changed-nonce", public_key, socket_path, MAIN_REQUEST_ID, 2)
    expect_sign_failure("changed-artifact", public_key, socket_path, MAIN_REQUEST_ID, 1, wasm_first_byte="7")

    time.sleep(2)  # safely past the one-second expiry approved above
    expect_sign_failure("expired-approval", public_key, socket_path, EXPIRING_REQUEST_ID, 1)

    first = expect_sign_success(public_key, socket_path, MAIN_REQUEST_ID, 1)
    serve_summary = wait_serve(serve_proc, extra_seconds=20)
    expected_summary = {
        "connections_accepted": "6", "requests_handled": "5",
        "requests_signed": "1", "requests_refused": "4",
    }
    if dict(line.split("=", 1) for line in serve_summary.splitlines()) != expected_summary:
        raise FixtureFailure("serve counts do not prove exact peer/request refusals")

    if os.path.lexists(socket_path):
        raise FixtureFailure("cleanly exited custody left its bound socket behind")
    second_proc = start_serve(socket_path, total_deadline_secs=10, max_connections=1, max_requests=1)
    second = expect_sign_success(public_key, socket_path, MAIN_REQUEST_ID, 1)
    restarted_summary = wait_serve(second_proc, extra_seconds=8)
    if dict(line.split("=", 1) for line in restarted_summary.splitlines()) != {
        "connections_accepted": "1", "requests_handled": "1",
        "requests_signed": "1", "requests_refused": "0",
    }:
        raise FixtureFailure("restarted serve counts do not match the one approved request")
    if os.path.lexists(socket_path):
        raise FixtureFailure("restarted custody left its bound socket behind")

    if first["signature_hex"] != second["signature_hex"]:
        raise FixtureFailure("the restarted serve process did not reproduce the identical persisted signature")

    total_bytes = 0
    for dirpath, _dirnames, filenames in os.walk(ROOT):
        for filename in filenames:
            try:
                total_bytes += os.stat(os.path.join(dirpath, filename)).st_size
            except FileNotFoundError:
                continue
    if total_bytes > 64 * 1024 * 1024:
        raise FixtureFailure("generated fixture files exceed the 64MiB bound")

    print(json.dumps({
        "ok": True,
        "scope": "custody_fixture_1013_docker_linux_uid_pty",
        "serve_summary": serve_summary.strip().splitlines(),
        "restart_signature_match": True,
        "generated_bytes_total": total_bytes,
    }, sort_keys=True))


try:
    main()
except FixtureFailure as failure:
    print(json.dumps({"ok": False, "error": str(failure)}, sort_keys=True))
    sys.exit(1)
except Exception as error:  # last resort: never a silent success on an unexpected error
    print(json.dumps({"ok": False, "error": f"unexpected: {error!r}"}, sort_keys=True))
    sys.exit(1)
`;

// ---- Docker subprocess wrapper: bounded deadline, bounded captured output, ----
// full EOF/exit-code accounting. Mirrors
// scripts/check-docker-fault-environment.mjs's own wrapper exactly, since
// that is this repository's accepted pattern for Docker-only evidence.

async function docker(args, cleanup = false) {
  const allowance = Math.floor(deadline - performance.now() - (cleanup ? 0 : 25_000));
  const remaining = cleanup ? Math.min(5_000, allowance) : allowance;
  if (remaining <= 0) throw new Error('fixture deadline expired');
  const commandEnd = performance.now() + remaining;
  const activeLimit = cleanup ? outputLimit : outputLimit - cleanupReserve;
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/local/bin/docker', ['--host', endpoint, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: dockerEnvironment,
    });
    pendingClients.add(child);
    const stdout = [];
    const stderr = [];
    let stdoutEof = false;
    let stderrEof = false;
    let failure;
    let settled = false;
    let reapTimer;
    function rejectOnce(error) {
      if (settled) return;
      settled = true;
      reject(error);
    }
    function abort(error) {
      failure ??= error;
      child.kill('SIGKILL');
      if (reapTimer) return;
      reapTimer = setTimeout(() => {
        child.unref();
        child.stdout.destroy();
        child.stderr.destroy();
        rejectOnce(new Error(`${failure.message}; Docker client reap/EOF unresolved, pid=${child.pid ?? 'unknown'}`));
      }, Math.max(1, Math.min(1_000, Math.floor(deadline - performance.now()))));
    }
    const timer = setTimeout(() => {
      abort(new Error('Docker operation exceeded its deadline'));
    }, remaining);
    function collect(target, chunk) {
      if (failure) return;
      if (chunk.length > activeLimit - outputBytes) {
        abort(new Error('complete output exceeds capability evidence allocation'));
        return;
      }
      outputBytes += chunk.length;
      target.push(chunk);
    }
    child.stdout.on('data', (chunk) => collect(stdout, chunk));
    child.stderr.on('data', (chunk) => collect(stderr, chunk));
    child.stdout.on('end', () => { stdoutEof = true; });
    child.stderr.on('end', () => { stderrEof = true; });
    child.stdout.on('error', abort);
    child.stderr.on('error', abort);
    child.on('error', abort);
    child.on('close', (code, signal) => {
      pendingClients.delete(child);
      clearTimeout(timer);
      if (reapTimer) clearTimeout(reapTimer);
      if (settled) return;
      if (performance.now() > commandEnd) failure ??= new Error('Docker completion was observed after its deadline');
      if (failure) return rejectOnce(failure);
      if (!stdoutEof || !stderrEof) return rejectOnce(new Error('Docker output lacks both physical EOFs'));
      const answer = {
        code, signal,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      };
      if (code !== 0 || signal !== null) {
        const error = new Error(`Docker refused ${args[0]}: ${answer.stderr.trim()}`);
        error.command = args[0];
        return rejectOnce(error);
      }
      settled = true;
      resolve(answer);
    });
  });
}

// Only the fields these checks actually consume; `Config.Env` is never
// requested or inspected.
const identityFormat = '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"State":{{json .State}},"Config":{"Labels":{{json .Config.Labels}}}}';
const configurationFormat = '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"State":{{json .State}},"Config":{"Labels":{{json .Config.Labels}},"User":{{json .Config.User}},"Entrypoint":{{json .Config.Entrypoint}}},"Mounts":{{json .Mounts}},"HostConfig":{"Memory":{{json .HostConfig.Memory}},"MemorySwap":{{json .HostConfig.MemorySwap}},"PidsLimit":{{json .HostConfig.PidsLimit}},"NanoCpus":{{json .HostConfig.NanoCpus}},"NetworkMode":{{json .HostConfig.NetworkMode}},"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},"LogConfig":{{json .HostConfig.LogConfig}},"CapAdd":{{json .HostConfig.CapAdd}},"CapDrop":{{json .HostConfig.CapDrop}},"SecurityOpt":{{json .HostConfig.SecurityOpt}},"Tmpfs":{{json (index .HostConfig "Tmpfs")}},"Binds":{{json (index .HostConfig "Binds")}}}}';

async function inspect(reference, cleanup = false, withConfiguration = false) {
  const format = withConfiguration ? configurationFormat : identityFormat;
  const captured = await docker(['container', 'inspect', '--format', format, reference], cleanup);
  const state = JSON.parse(captured.stdout);
  if (state === null || Array.isArray(state) || typeof state !== 'object') {
    throw new Error('container inspection is not unique');
  }
  if (state.Name !== `/${name}` || state.Config.Labels?.[label] !== owner || state.Image !== imageId) {
    throw new Error('container is not the exact owned custody fixture');
  }
  return state;
}

async function findVolume(cleanup = false) {
  const captured = await docker(['volume', 'ls', '-q', '--filter', `name=^${volumeName}$`], cleanup);
  const found = captured.stdout.trim();
  if (found && found !== volumeName) throw new Error('volume lookup is not exact');
  return found === volumeName;
}

async function inspectVolume(cleanup = false) {
  const captured = await docker(['volume', 'inspect', volumeName], cleanup);
  const rows = JSON.parse(captured.stdout);
  if (!Array.isArray(rows) || rows.length !== 1) throw new Error('volume inspection is not unique');
  const volume = rows[0];
  if (volume.Name !== volumeName || volume.Driver !== 'local' || volume.Scope !== 'local' ||
      volume.Labels?.[label] !== owner ||
      JSON.stringify(Object.keys(volume.Options ?? {}).sort()) !== '["device","o","type"]' ||
      volume.Options.type !== 'tmpfs' || volume.Options.device !== 'tmpfs' ||
      volume.Options.o !== volumeOptions || typeof volume.Mountpoint !== 'string' ||
      !volume.Mountpoint.startsWith('/') || volume.Mountpoint.includes('\0')) {
    throw new Error('volume is not the exact owned noswap allocation');
  }
  if (volumeMountpoint !== undefined && volume.Mountpoint !== volumeMountpoint) {
    throw new Error('owned volume attachment changed');
  }
  volumeMountpoint = volume.Mountpoint;
  return volume;
}

try {
  const localImage = await docker(['image', 'inspect', '--format', '{{.Id}}', image]);
  if (localImage.stdout.trim() !== imageId) throw new Error('pinned local image attachment differs');
  if (await findVolume()) throw new Error('fresh custody volume already exists');
  volumeExpected = true;
  const createdVolume = await docker([
    'volume', 'create', '--driver', 'local', '--name', volumeName,
    '--label', `${label}=${owner}`, '--opt', 'type=tmpfs', '--opt', 'device=tmpfs',
    '--opt', `o=${volumeOptions}`,
  ]);
  if (createdVolume.stdout.trim() !== volumeName) throw new Error('volume creation identity differs');
  await inspectVolume();
  const created = await docker([
    'create', '--pull=never', '--name', name, '--label', `${label}=${owner}`,
    '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE', '--cap-add', 'SETUID', '--cap-add', 'SETGID',
    '--security-opt', 'no-new-privileges', '--user', '0:0',
    '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
    '--pids-limit', '64', '--log-driver', 'none',
    '--mount', `type=volume,source=${volumeName},target=/work,volume-nocopy`,
    ...binds.flatMap((bind) => ['--mount', bind]),
    '--entrypoint', '/usr/local/bin/python3', image, '-I', '-B', '-c', probe,
  ]);
  containerId = created.stdout.trim();
  if (!/^[0-9a-f]{64}$/.test(containerId)) throw new Error('invalid exact container identity');

  const initial = await inspect(containerId, false, true);
  const config = initial.HostConfig;
  const mounts = initial.Mounts;
  const allocations = mounts.filter((mount) => mount.Type === 'volume');
  if (allocations.length !== 1 || allocations[0].Name !== volumeName ||
      allocations[0].Destination !== '/work' || allocations[0].RW !== true ||
      allocations[0].Source !== volumeMountpoint) throw new Error('owned allocation attachment differs');
  const readonlyMounts = mounts.filter((mount) => mount.Type === 'bind');
  const expectedMountCount = 3 + closure.libs.size; // cli + harness + ld.so + each shared library
  if (!Array.isArray(mounts) || mounts.length !== expectedMountCount + 1 ||
      readonlyMounts.length !== expectedMountCount || !readonlyMounts.every((mount) => mount.RW === false)) {
    throw new Error('bind mounts are not exactly the owned read-only custody/library closure');
  }
  if (config.Memory !== 512 * 1024 * 1024 || config.MemorySwap !== 512 * 1024 * 1024 ||
      config.PidsLimit !== 64 || config.NanoCpus !== 1_000_000_000 ||
      config.NetworkMode !== 'none' || config.ReadonlyRootfs !== true ||
      config.LogConfig.Type !== 'none' || initial.Config.User !== '0:0' ||
      JSON.stringify(config.CapDrop) !== '["ALL"]' ||
      JSON.stringify([...config.CapAdd].sort()) !== JSON.stringify(['CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_SETGID', 'CAP_SETUID']) ||
      !config.SecurityOpt.includes('no-new-privileges') ||
      JSON.stringify(initial.Config.Entrypoint) !== '["/usr/local/bin/python3"]' ||
      Object.keys(config.Tmpfs ?? {}).length !== 0 ||
      (config.Binds ?? []).length !== 0) {
    throw new Error(`effective Docker configuration differs: ${JSON.stringify({
      memory: config.Memory, swap: config.MemorySwap, pids: config.PidsLimit,
      cpu: config.NanoCpus, network: config.NetworkMode, readonly: config.ReadonlyRootfs,
      log: config.LogConfig.Type, user: initial.Config.User, capAdd: config.CapAdd,
      capDrop: config.CapDrop, security: config.SecurityOpt, entrypoint: initial.Config.Entrypoint,
      tmpfs: config.Tmpfs, binds: config.Binds,
    })}`);
  }

  const completed = await docker(['start', '--attach', containerId]);
  const terminal = await inspect(containerId);
  if (terminal.State.Running || terminal.State.OOMKilled || terminal.State.Dead || terminal.State.Pid !== 0) {
    throw new Error('the fixture container lacks a clean terminal state');
  }

  const lines = completed.stdout.trim().split('\n').filter((line) => line.length > 0);
  if (lines.length === 0) throw new Error('the fixture produced no evidence line');
  result = JSON.parse(lines[lines.length - 1]);
  if (completed.code !== 0 || result.ok !== true) {
    throw new Error(`fixture reported failure: ${result?.error ?? completed.stderr.trim() ?? 'unknown'}`);
  }
  if (result.scope !== 'custody_fixture_1013_docker_linux_uid_pty' || result.restart_signature_match !== true ||
      !Number.isSafeInteger(result.generated_bytes_total) || result.generated_bytes_total <= 0 ||
      result.generated_bytes_total > 64 * 1024 * 1024) {
    throw new Error('the fixture evidence line is incomplete');
  }
} catch (error) {
  primaryError = error;
} finally {
  try {
    let owned;
    if (containerId) {
      owned = await inspect(containerId, true);
    } else {
      const lookup = await docker(['container', 'ls', '-aq', '--no-trunc', '--filter', `name=^/${name}$`], true);
      const found = lookup.stdout.trim();
      if (found) owned = await inspect(found, true);
    }
    if (owned) {
      if (owned.State.Running) await docker(['kill', owned.Id], true);
      const stopped = await inspect(owned.Id, true);
      if (stopped.State.Running || stopped.State.Pid !== 0) throw new Error('owned fixture container did not stop');
      await docker(['rm', owned.Id], true);
    }
    const remaining = await docker(['container', 'ls', '-aq', '--no-trunc', '--filter', `label=${label}=${owner}`], true);
    if (remaining.stdout.trim()) throw new Error('owned fixture container residue remains');
    if (volumeExpected && await findVolume(true)) {
      await inspectVolume(true);
      await docker(['volume', 'rm', volumeName], true);
    }
    const volumes = await docker(['volume', 'ls', '-q', '--filter', `label=${label}=${owner}`], true);
    if (volumes.stdout.trim()) throw new Error('owned fixture volume residue remains');
  } catch (error) {
    primaryError = new Error(`${primaryError?.message ?? 'fixture'}; cleanup unresolved: ${error.message}; owned name=${name}`);
  }
}

if (pendingClients.size !== 0 || performance.now() > deadline) {
  primaryError = new Error(`${primaryError?.message ?? 'fixture'}; end/owned client release unresolved`);
}

if (primaryError) {
  console.error(primaryError.message);
  process.exitCode = primaryError.command === 'create' ? 78 : 1;
} else {
  console.log(JSON.stringify({ ...result, image, container_removed: true, evidence_bytes: outputBytes }));
}
