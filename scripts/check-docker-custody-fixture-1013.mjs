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
// Beyond the original keygen/approve/serve/restart round trip, this fixture
// also exercises the custody revocation lifecycle (`custody revoke
// --approvals-dir --request-id`: an immutable `<id>.revoked` marker,
// idempotent on an exact repeat, refusing reapproval before any terminal is
// ever touched, and leaving every later signature attempt for that id with
// the ordinary `NoApproval` refusal), a custody-owned private recovery of
// the same disposable seed through a backup/restored path pair, a second,
// independently keyed custody identity, the distinct-UID protected
// whole-coin transfer family (DR-0246), the distinct-UID protected
// split/merge family (DR-0249), the distinct-UID protected genesis
// TreasuryCap mint/burn family (DR-0253, a fourth closed wire kind 4, never
// kind 1/2/3), and the distinct-UID protected create-asset family (DR-0255,
// a fifth closed wire kind 5, never kind 1-4): the only family whose paid
// `Instantiate` targets a fresh derived instance rather than the pinned
// genesis one, with no pre-existing owned Coin/TreasuryCap input, only a
// fee source. None of this ever prints or argv-passes key material; every
// copy of key bytes happens inside a custody-UID child process; only the
// child's exit status crosses that boundary.
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
RECOVERY_REQUEST_ID = "33" * 32
NEW_IDENTITY_REQUEST_ID = "44" * 32
WRONG_PUBLIC_KEY_HEX = "99" * 32
SPLIT_REQUEST_ID = "91" * 32
MERGE_REQUEST_ID = "92" * 32
MINT_REQUEST_ID = "93" * 32
BURN_REQUEST_ID = "94" * 32
CREATE_REQUEST_ID = "95" * 32
# DR-0258: the application-pinned mint/burn request IDs for the asset this
# same fixture run just created, distinct from MINT_REQUEST_ID/BURN_REQUEST_ID
# (93/94) below, which only ever target the pinned genesis TreasuryCap.
OWN_MINT_REQUEST_ID = "96" * 32
OWN_BURN_REQUEST_ID = "97" * 32
# The new application instance's own creator-scoped logical seed (DR-0255):
# public, caller-supplied, never a private key. Custody independently
# rederives the exact InstanceTarget from this seed plus its own pinned
# sender/context/code; it is never trusted as signing authority by itself.
CREATE_INSTANCE_SEED_HEX = "5f" * 32
# Half of apps/devnet's DEVNET_PAID_SPEND_COIN_BALANCE (10_000_000); the
# split amount must stay strictly between zero and the held balance.
SPLIT_AMOUNT = 5_000_000
RECOMBINED_AMOUNT = 10_000_000
# The whole minted Coin is burned in full (burn has no amount argument), so
# this amount is never partial and never leaves a mint-only residue.
MINT_AMOUNT = 5_000_000
# DR-0258: minted then fully burned against the asset this fixture run just
# created, independent of MINT_AMOUNT above (the pinned genesis TreasuryCap).
OWN_ASSET_MINT_AMOUNT = 5_000_000

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
        "--exact", "--ignored", "--nocapture", "--format", "terse",
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
    if "1 passed; 0 failed; 0 ignored" not in text:
        raise FixtureFailure("the exact fixture probe did not complete one successful test")
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


def phase_keygen(key_path=f"{ROOT}/custody-keys/custody.seed"):
    rc, out, err = run_exec(
        cli_argv("custody", "keygen", "--key-file", key_path),
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
    key_stat = os.stat(key_path)
    if stat.S_IMODE(key_stat.st_mode) != 0o600 or key_stat.st_uid != CUSTODY_UID:
        raise FixtureFailure("custody key file metadata is not exactly owner=custody, mode 0600")
    dir_stat = os.stat(f"{ROOT}/custody-keys")
    if stat.S_IMODE(dir_stat.st_mode) != 0o700:
        raise FixtureFailure("custody key directory metadata is not exactly mode 0700")
    return public_key


def phase_write_config(public_key, config_path=f"{ROOT}/custody-keys/custody.config"):
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


def phase_approve_via_pty(config_path, artifact_path, nonce, request_id_hex, expires_in_seconds, command=None):
    argv = command or cli_argv(
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


def revoke_argv(approvals_dir, request_id_hex):
    return cli_argv("custody", "revoke", "--approvals-dir", approvals_dir, "--request-id", request_id_hex)


def phase_operator_cannot_revoke(approvals_dir, request_id_hex):
    marker_path = f"{approvals_dir}/{request_id_hex}.revoked"
    rc, _out, err = run_exec(
        revoke_argv(approvals_dir, request_id_hex),
        OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID], timeout=10,
    )
    if rc == 0:
        raise FixtureFailure("the operator UID was able to run custody revoke")
    if b"must be owned by UID" not in err:
        raise FixtureFailure("the operator revoke did not reach the expected owner refusal")
    if os.path.lexists(marker_path):
        raise FixtureFailure("the operator UID's refused revoke attempt still left a revocation marker")


def phase_revoke(approvals_dir, request_id_hex):
    rc, _out, err = run_exec(
        revoke_argv(approvals_dir, request_id_hex),
        CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID], timeout=10,
    )
    if rc != 0:
        raise FixtureFailure(f"custody revoke failed: {err.decode('utf8', 'replace')}")
    marker_path = f"{approvals_dir}/{request_id_hex}.revoked"
    marker_stat = os.stat(marker_path)
    if marker_stat.st_uid != CUSTODY_UID or stat.S_IMODE(marker_stat.st_mode) != 0o600:
        raise FixtureFailure("the custody revocation marker's metadata is not exactly owner=custody, mode 0600")


def read_file_bytes_as_root(path, max_bytes=65536):
    # Root reads only non-secret evidence here (an approval record, never a
    # key): bounded, and only ever used for byte-for-byte comparison.
    with open(path, "rb") as source:
        data = source.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise FixtureFailure(f"file at {path} exceeds the bounded comparison read")
    return data


def phase_revoke_is_idempotent_and_preserves_approval(approvals_dir, request_id_hex):
    approval_path = f"{approvals_dir}/{request_id_hex}"
    before = read_file_bytes_as_root(approval_path)
    phase_revoke(approvals_dir, request_id_hex)
    after_first = read_file_bytes_as_root(approval_path)
    marker_path = f"{approval_path}.revoked"
    expected_marker = bytes([1]) + bytes.fromhex(request_id_hex)
    if read_file_bytes_as_root(marker_path, max_bytes=33) != expected_marker:
        raise FixtureFailure("the revocation marker does not bind its exact version and request ID")
    phase_revoke(approvals_dir, request_id_hex)  # exact repeat must also succeed
    after_second = read_file_bytes_as_root(approval_path)
    if before != after_first or before != after_second:
        raise FixtureFailure("revoking a request changed its own already-written approval record bytes")
    if read_file_bytes_as_root(marker_path, max_bytes=33) != expected_marker:
        raise FixtureFailure("idempotent revocation changed the marker bytes")


def phase_reject_reapproval_of_revoked(config_path, artifact_path, nonce, request_id_hex):
    argv = cli_argv(
        "custody", "approve",
        "--config", config_path,
        "--approvals-dir", f"{ROOT}/custody-approvals",
        "--approved-artifact", artifact_path,
        "--nonce", str(nonce),
        "--request-id", request_id_hex,
        "--expires-in-seconds", "3600",
    )
    # No PTY here at all (unlike phase_approve_via_pty): this both keeps the
    # negative case simple and proves the revoked refusal is reported before
    # any terminal is ever required, since a terminal-requirement refusal
    # would otherwise mask it.
    rc, _out, err = run_exec(argv, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID], timeout=10)
    if rc == 0:
        raise FixtureFailure("reapproving a revoked request id unexpectedly succeeded")
    if b"custody approval request ID is revoked" not in err:
        raise FixtureFailure(f"reapproving a revoked request id did not report the expected revoked refusal: {err!r}")


def custody_private_copy(source_path, dest_path, max_bytes=256, replace=False):
    # Fixed disposable paths only. Key bytes never leave the custody UID.
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([CUSTODY_GID])
            os.setgid(CUSTODY_GID)
            os.setuid(CUSTODY_UID)
            src_fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                source_stat = os.fstat(src_fd)
                if (not stat.S_ISREG(source_stat.st_mode) or source_stat.st_uid != CUSTODY_UID
                        or stat.S_IMODE(source_stat.st_mode) != 0o600):
                    os._exit(3)
                data = bytearray()
                while len(data) <= max_bytes:
                    chunk = os.read(src_fd, max_bytes + 1 - len(data))
                    if not chunk:
                        break
                    data.extend(chunk)
            finally:
                os.close(src_fd)
            if not data or len(data) > max_bytes:
                os._exit(5)
            parent = os.path.dirname(dest_path)
            parent_stat = os.lstat(parent)
            if (not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != CUSTODY_UID
                    or stat.S_IMODE(parent_stat.st_mode) != 0o700):
                os._exit(4)
            if replace:
                os.unlink(dest_path)  # fixture-only, stopped, already checked approval path
            dst_fd = os.open(dest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                written = 0
                while written < len(data):
                    count = os.write(dst_fd, memoryview(data)[written:])
                    if count <= 0:
                        os._exit(6)
                    written += count
                os.fsync(dst_fd)
            finally:
                os.close(dst_fd)
            directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            os._exit(0)
        except OSError:
            os._exit(2)
        finally:
            os._exit(127)
    _pid, status = os.waitpid(pid, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def phase_recover_private_key(source_key_path):
    backup_path = f"{ROOT}/custody-keys/custody.seed.backup"
    restored_path = f"{ROOT}/custody-keys/custody.seed.restored"
    if not custody_private_copy(source_key_path, backup_path):
        raise FixtureFailure("custody-owned private backup of the disposable seed failed")
    if not custody_private_copy(backup_path, restored_path):
        raise FixtureFailure("custody-owned private restore of the backed-up seed failed")
    for path in (backup_path, restored_path):
        key_stat = os.stat(path)
        if key_stat.st_uid != CUSTODY_UID or stat.S_IMODE(key_stat.st_mode) != 0o600:
            raise FixtureFailure(f"recovered key path {path} metadata is not exactly owner=custody, mode 0600")
    return restored_path


def start_serve(
    socket_path, total_deadline_secs, max_connections, max_requests,
    key_file=f"{ROOT}/custody-keys/custody.seed", config_path=f"{ROOT}/custody-keys/custody.config",
    command=None,
):
    argv = command or cli_argv(
        "custody", "serve",
        "--config", config_path,
        "--key-file", key_file,
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


def expect_serve_startup_failure(label, key_file, config_path, socket_path, expected_substring):
    argv = cli_argv(
        "custody", "serve",
        "--config", config_path,
        "--key-file", key_file,
        "--socket", socket_path,
        "--approvals-dir", f"{ROOT}/custody-approvals",
        "--max-connections", "1",
        "--max-requests", "1",
        "--total-deadline-secs", "5",
    )

    def preexec():
        os.setgroups([CUSTODY_GID])
        os.setgid(CUSTODY_GID)
        os.setuid(CUSTODY_UID)

    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=preexec, env={}, cwd="/")
    try:
        out, err = proc.communicate(timeout=min(10, remaining()))
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        raise FixtureFailure(f"{label}: custody serve startup failure did not exit in time")
    charge_output(len(out) + len(err))
    if proc.returncode == 0:
        raise FixtureFailure(f"{label}: custody serve unexpectedly started successfully")
    if expected_substring.encode("utf8") not in err:
        raise FixtureFailure(
            f"{label}: did not report the expected exact startup failure; stderr={err.decode('utf8', 'replace')!r}"
        )
    if os.path.lexists(socket_path):
        raise FixtureFailure(f"{label}: a socket was created despite the startup failure")


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


def expect_sign_failure(label, public_key, socket_path, request_id_hex, nonce, wasm_first_byte="0", expected="NoApproval"):
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
    if f"Refused({expected})".encode("ascii") not in err:
        raise FixtureFailure(f"{label}: did not report the expected closed refusal Refused({expected})")


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


def check_summary(label, summary_text, expected):
    if dict(line.split("=", 1) for line in summary_text.splitlines()) != expected:
        raise FixtureFailure(f"{label}: serve counts do not match the expected exact summary {expected}")


def phase_recovery_verification(public_key, config_path, original_key_path, restored_key_path, socket_path):
    recovery_artifact = f"{ROOT}/custody-artifacts/recovery.bin"
    phase_generate_artifact(public_key, RECOVERY_REQUEST_ID, 1, recovery_artifact)
    phase_approve_via_pty(config_path, recovery_artifact, 1, RECOVERY_REQUEST_ID, 3600)

    before_proc = start_serve(
        socket_path, total_deadline_secs=10, max_connections=1, max_requests=1,
        key_file=original_key_path, config_path=config_path,
    )
    before = expect_sign_success(public_key, socket_path, RECOVERY_REQUEST_ID, 1)
    before_summary = wait_serve(before_proc, extra_seconds=8)
    check_summary("original-key sign", before_summary, {
        "connections_accepted": "1", "requests_handled": "1",
        "requests_signed": "1", "requests_refused": "0",
    })

    after_proc = start_serve(
        socket_path, total_deadline_secs=10, max_connections=1, max_requests=1,
        key_file=restored_key_path, config_path=config_path,
    )
    after = expect_sign_success(public_key, socket_path, RECOVERY_REQUEST_ID, 1)
    after_summary = wait_serve(after_proc, extra_seconds=8)
    check_summary("recovered-key sign", after_summary, {
        "connections_accepted": "1", "requests_handled": "1",
        "requests_signed": "1", "requests_refused": "0",
    })

    if before["signature_hex"] != after["signature_hex"]:
        raise FixtureFailure("the recovered key produced a different signature for the identical approved request")
    return before_summary.strip().splitlines(), after_summary.strip().splitlines()


def phase_retain_revocation_through_recovery(approvals_dir, request_id_hex, public_key, key_file, config_path, socket_path):
    approval_path = f"{approvals_dir}/{request_id_hex}"
    marker_path = f"{approval_path}.revoked"
    backup_path = f"{ROOT}/custody-artifacts/main-approval.backup"
    if not custody_private_copy(approval_path, backup_path, max_bytes=65536):
        raise FixtureFailure("backing up the revoked request's own approval record failed")
    original_bytes = read_file_bytes_as_root(approval_path)
    if not custody_private_copy(backup_path, approval_path, max_bytes=65536, replace=True):
        raise FixtureFailure("restoring the revoked request's own approval record from its backup failed")
    if read_file_bytes_as_root(approval_path) != original_bytes:
        raise FixtureFailure("restoring the approval record from its own backup changed its bytes")
    if not os.path.lexists(marker_path):
        raise FixtureFailure("the revocation marker did not survive restoring the approval record")

    proc = start_serve(
        socket_path, total_deadline_secs=10, max_connections=1, max_requests=1,
        key_file=key_file, config_path=config_path,
    )
    expect_sign_failure("revoked-after-approval-restore", public_key, socket_path, request_id_hex, 1)
    summary = wait_serve(proc, extra_seconds=8)
    check_summary("revocation-retained-through-recovery", summary, {
        "connections_accepted": "1", "requests_handled": "1",
        "requests_signed": "0", "requests_refused": "1",
    })
    return summary.strip().splitlines()


def phase_new_identity(socket_path, old_public_key):
    new_key_path = f"{ROOT}/custody-keys/custody2.seed"
    new_public_key = phase_keygen(new_key_path)
    new_config_path = phase_write_config(new_public_key, f"{ROOT}/custody-keys/custody2.config")

    new_identity_artifact = f"{ROOT}/custody-artifacts/new-identity.bin"
    phase_generate_artifact(new_public_key, NEW_IDENTITY_REQUEST_ID, 1, new_identity_artifact)
    phase_approve_via_pty(new_config_path, new_identity_artifact, 1, NEW_IDENTITY_REQUEST_ID, 3600)

    main_key_path = f"{ROOT}/custody-keys/custody.seed"
    main_config_path = f"{ROOT}/custody-keys/custody.config"
    mismatch_message = "custody key file's derived public key does not match the configured publisher"

    expect_serve_startup_failure("old-key-new-config", main_key_path, new_config_path, socket_path, mismatch_message)
    expect_serve_startup_failure("new-key-old-config", new_key_path, main_config_path, socket_path, mismatch_message)

    proc = start_serve(
        socket_path, total_deadline_secs=15, max_connections=3, max_requests=3,
        key_file=new_key_path, config_path=new_config_path,
    )
    expect_sign_failure(
        "old-publisher-artifact", old_public_key, socket_path, NEW_IDENTITY_REQUEST_ID, 1,
        expected="PublisherMismatch",
    )
    expect_sign_failure("new-publisher-unapproved", new_public_key, socket_path, UNAPPROVED_REQUEST_ID, 1)
    expect_sign_success(new_public_key, socket_path, NEW_IDENTITY_REQUEST_ID, 1)
    summary = wait_serve(proc, extra_seconds=12)
    check_summary("new-identity", summary, {
        "connections_accepted": "3", "requests_handled": "3",
        "requests_signed": "1", "requests_refused": "2",
    })
    if os.path.lexists(socket_path):
        raise FixtureFailure("new-identity serve left its bound socket behind")
    return summary.strip().splitlines()


def phase_transfer(public_key):
    custody_dir, operator_dir = f"{ROOT}/custody-transfer", f"{ROOT}/operator/transfer"
    for path, uid, gid in [(custody_dir, CUSTODY_UID, CUSTODY_GID), (operator_dir, OPERATOR_UID, OPERATOR_GID)]:
        os.mkdir(path, 0o700)
        os.chown(path, uid, gid)
    probe_argv = [LD_SO, "--library-path", LIB_DIR, HARNESS,
                  "custody::asset_fixture::distinct_uid_transfer_probe", "--exact", "--ignored", "--nocapture", "--format", "terse"]
    def probe_env(mode, directory):
        return {"CUSTODY_TRANSFER_MODE": mode, "CUSTODY_TRANSFER_DIR": directory, "CUSTODY_TRANSFER_PUBLIC_KEY": public_key}
    rc, out, err = run_exec(probe_argv, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID], env=probe_env("generate", custody_dir))
    if rc != 0:
        raise FixtureFailure(f"transfer preimage generation failed: {err!r}")
    generated = last_json_line(out)
    config_text = f"chain_id=custody-whole-coin-test\nprotocol_version=7\nepoch=0\nhash_suite_id=1\ndomain={DOMAIN_HEX}\npublisher_public_key={public_key}\noperator_uid={OPERATOR_UID}\n"
    with open(f"{custody_dir}/config", "x") as output:
        output.write(config_text)
    os.chmod(f"{custody_dir}/config", 0o600)
    os.chown(f"{custody_dir}/config", CUSTODY_UID, CUSTODY_GID)
    def trust_flags(directory):
        return ["--config", f"{directory}/config", "--genesis-manifest-file", f"{directory}/genesis.bin", "--genesis-digest", generated["digest"]]
    request_id = "75" * 32
    command = cli_argv("custody", "prepare-transfer", *trust_flags(custody_dir),
        "--coin-file", f"{custody_dir}/coin.bin", "--fee-source-file", f"{custody_dir}/fee.bin",
        "--recipient", generated["recipient"], "--nonce", "0", "--request-id", request_id,
        "--max-fee", "1000000", "--gas-limit", "200000", "--out", f"{custody_dir}/request.bin")
    rc, out, err = run_exec(command, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
    if rc != 0 or b"transfer_request_exported=true" not in out:
        raise FixtureFailure(f"transfer prepare failed: {err!r}")
    for name in ["config", "genesis.bin", "request.bin"]:
        with open(f"{custody_dir}/{name}", "rb") as source:
            content = source.read(1024 * 1024)
        with open(f"{operator_dir}/{name}", "xb") as target:
            target.write(content)
        os.chmod(f"{operator_dir}/{name}", 0o600)
        os.chown(f"{operator_dir}/{name}", OPERATOR_UID, OPERATOR_GID)
    approvals = f"{ROOT}/custody-approvals"
    approve = cli_argv("custody", "approve-transfer", *trust_flags(custody_dir),
        "--request-file", f"{custody_dir}/request.bin", "--approvals-dir", approvals, "--expires-in-seconds", "3600")
    rc, _out, refusal = run_exec(approve, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
    if rc == 0 or b"custody approve requires an interactive terminal" not in refusal:
        raise FixtureFailure("transfer approval unexpectedly accepted a pipe")
    phase_approve_via_pty(None, None, 0, request_id, 3600, command=approve)
    socket_path = f"{ROOT}/run/transfer.sock"
    def serve_command(count):
        return cli_argv("custody", "serve-transfer", *trust_flags(custody_dir),
            "--key-file", f"{ROOT}/custody-keys/custody.seed", "--socket", socket_path,
            "--approvals-dir", approvals, "--max-connections", str(count), "--max-requests", str(count), "--total-deadline-secs", "30")
    signer = ["--custody-socket", socket_path, "--custody-uid", str(CUSTODY_UID), "--custody-expected-public-key", public_key]
    serve = start_serve(socket_path, 30, 3, 3, command=serve_command(3))
    sign = cli_argv("custody", "sign-transfer", *trust_flags(operator_dir), "--request-file", f"{operator_dir}/request.bin", *signer)
    rc, _out, err = run_exec([*sign, "--out", f"{operator_dir}/offline.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
    if rc != 0:
        raise FixtureFailure(f"protected offline transfer sign failed: {err!r}")
    # SQLite pins readable ancestor directory descriptors. The original
    # publication phase used an execute-only volume root. Only this new
    # SQLite phase exposes the fixed top-level names; every key, approval,
    # operator and database directory stays private and no write permission
    # is granted. Re-run the actual operator key/approval refusals here.
    os.chmod(ROOT, 0o755)
    phase_operator_cannot_read_or_edit(request_id)
    def operator_identity():
        os.setgroups([OPERATOR_GID]); os.setgid(OPERATOR_GID); os.setuid(OPERATOR_UID)
    native = subprocess.Popen(probe_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=operator_identity,
        env=probe_env("serve", operator_dir), cwd="/")
    address = None
    startup_end = time.monotonic() + min(10, remaining())
    prefix = b""
    while address is None:
        if time.monotonic() >= startup_end:
            native.kill(); native.wait(timeout=5)
            raise FixtureFailure("transfer native host did not start")
        ready, _, _ = select.select([native.stdout], [], [], min(1, remaining()))
        if ready:
            line = native.stdout.readline(16385)
            if not line:
                tail, failure = native.communicate(timeout=min(5, remaining()))
                charge_output(len(tail) + len(failure))
                raise FixtureFailure(f"transfer native host exited before its address: {failure[:16384]!r}")
            prefix += line; charge_output(len(line))
            if len(prefix) > 16384:
                raise FixtureFailure("transfer native startup output exceeds bound")
            if line.startswith(b'{"address":'):
                address = json.loads(line)["address"]
    try:
        command = cli_argv("transfer", "--endpoint", address, *signer,
            "--expected-chain-id", "custody-whole-coin-test", "--expected-protocol-version", "7",
            "--expected-epoch", "0", "--expected-hash-suite-id", "1", "--expected-domain", DOMAIN_HEX,
            "--coin", generated["coin"], "--fee-source", generated["fee"], "--recipient", generated["recipient"],
            "--nonce", "0", "--request-id", request_id, "--max-fee", "1000000", "--gas-limit", "200000",
            "--submission-out", f"{operator_dir}/submission.bin", "--result-out", f"{operator_dir}/result.bin")
        rc, out, err = run_exec(command, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0 or b"paid_status=Success" not in out:
            raise FixtureFailure(f"actual protected transfer CLI failed: {out!r} {err!r}")
        with open(f"{operator_dir}/offline.bin", "rb") as source:
            offline = source.read(1048577)
        with open(f"{operator_dir}/submission.bin", "rb") as source:
            if source.read(1048577) != offline:
                raise FixtureFailure("offline and actual CLI transfer signed bytes differ")
        environment = probe_env("verify", operator_dir)
        environment["CUSTODY_TRANSFER_ENDPOINT"] = address
        rc, out, err = run_exec(probe_argv, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID], env=environment)
        verified = last_json_line(out)
        if rc != 0 or verified.get("whole_coin") is not True or verified.get("replay_equal") is not True:
            raise FixtureFailure(f"actual transfer/replay verification failed: {err!r}")
        rc, _out, err = run_exec(cli_argv("custody", "revoke", "--approvals-dir", approvals, "--request-id", request_id),
            CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"transfer revoke failed: {err!r}")
        rc, _out, refusal = run_exec([*sign, "--out", f"{operator_dir}/revoked.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/revoked.bin"):
            raise FixtureFailure("revoked transfer produced signed output")
        summary = wait_serve(serve, extra_seconds=8)
        check_summary("transfer", summary, {"connections_accepted":"3", "requests_handled":"3", "requests_signed":"2", "requests_refused":"1"})
        with open(f"{operator_dir}/stop-native", "xb") as completed:
            completed.write(b"complete\n")
        os.chmod(f"{operator_dir}/stop-native", 0o600)
        os.chown(f"{operator_dir}/stop-native", OPERATOR_UID, OPERATOR_GID)
        out, err = native.communicate(timeout=min(25, remaining()))
        charge_output(len(out) + len(err))
        if native.returncode != 0 or b"1 passed; 0 failed; 0 ignored" not in out:
            raise FixtureFailure(f"transfer native host did not finish cleanly: {err!r}")
    finally:
        for process in [native, serve]:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
        os.chmod(ROOT, 0o711)
    restarted = start_serve(socket_path, 30, 1, 1, command=serve_command(1))
    try:
        rc, _out, refusal = run_exec([*sign, "--out", f"{operator_dir}/revoked-restart.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/revoked-restart.bin"):
            raise FixtureFailure("revoked transfer produced output after restart")
        check_summary("transfer revoked restart", wait_serve(restarted, extra_seconds=8),
            {"connections_accepted":"1", "requests_handled":"1", "requests_signed":"0", "requests_refused":"1"})
    finally:
        if restarted.poll() is None:
            restarted.kill(); restarted.wait(timeout=5)
    return {"actual_cli":True, "whole_coin":True, "offline_bytes_equal":True, "replay_equal":True, "revoked":True, "revoked_after_restart":True}


def phase_split_merge(public_key):
    # Fresh phase directories only: this reuses the exact same one-owner,
    # one-app-coin/one-fee-coin devnet genesis 'distinct_uid_transfer_probe'
    # already builds (via its own unmodified "generate"/"serve" modes),
    # booted into a brand-new store here. It never touches phase_transfer's
    # own custody-transfer/operator/transfer directories, genesis, coins or
    # assertions.
    custody_dir, operator_dir = f"{ROOT}/custody-split-merge", f"{ROOT}/operator/split-merge"
    for path, uid, gid in [(custody_dir, CUSTODY_UID, CUSTODY_GID), (operator_dir, OPERATOR_UID, OPERATOR_GID)]:
        os.mkdir(path, 0o700)
        os.chown(path, uid, gid)
    probe_argv = [LD_SO, "--library-path", LIB_DIR, HARNESS,
                  "custody::asset_fixture::distinct_uid_transfer_probe", "--exact", "--ignored", "--nocapture", "--format", "terse"]
    def probe_env(mode, directory):
        return {"CUSTODY_TRANSFER_MODE": mode, "CUSTODY_TRANSFER_DIR": directory, "CUSTODY_TRANSFER_PUBLIC_KEY": public_key}
    rc, out, err = run_exec(probe_argv, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID], env=probe_env("generate", custody_dir))
    if rc != 0:
        raise FixtureFailure(f"split/merge preimage generation failed: {err!r}")
    generated = last_json_line(out)
    config_text = f"chain_id=custody-whole-coin-test\nprotocol_version=7\nepoch=0\nhash_suite_id=1\ndomain={DOMAIN_HEX}\npublisher_public_key={public_key}\noperator_uid={OPERATOR_UID}\n"
    with open(f"{custody_dir}/config", "x") as output:
        output.write(config_text)
    os.chmod(f"{custody_dir}/config", 0o600)
    os.chown(f"{custody_dir}/config", CUSTODY_UID, CUSTODY_GID)
    def trust_flags(directory):
        return ["--config", f"{directory}/config", "--genesis-manifest-file", f"{directory}/genesis.bin", "--genesis-digest", generated["digest"]]

    def copy_private(src_dir, dst_dir, name, dst_uid, dst_gid):
        with open(f"{src_dir}/{name}", "rb") as source:
            content = source.read(1024 * 1024)
        with open(f"{dst_dir}/{name}", "xb") as target:
            target.write(content)
        os.chmod(f"{dst_dir}/{name}", 0o600)
        os.chown(f"{dst_dir}/{name}", dst_uid, dst_gid)

    approvals = f"{ROOT}/custody-approvals"
    socket_path = f"{ROOT}/run/split-merge.sock"
    signer = ["--custody-socket", socket_path, "--custody-uid", str(CUSTODY_UID), "--custody-expected-public-key", public_key]

    def serve_command(count):
        return cli_argv("custody", "serve-split-merge", *trust_flags(custody_dir),
            "--key-file", f"{ROOT}/custody-keys/custody.seed", "--socket", socket_path,
            "--approvals-dir", approvals, "--max-connections", str(count), "--max-requests", str(count), "--total-deadline-secs", "30")

    # ---- split: prepare / approve / offline sign / actual CLI split ----
    prepare_split = cli_argv("custody", "prepare-split", *trust_flags(custody_dir),
        "--coin-file", f"{custody_dir}/coin.bin", "--fee-source-file", f"{custody_dir}/fee.bin",
        "--amount", str(SPLIT_AMOUNT), "--recipient", public_key, "--nonce", "0", "--request-id", SPLIT_REQUEST_ID,
        "--max-fee", "1000000", "--gas-limit", "200000", "--out", f"{custody_dir}/split-request.bin")
    rc, out, err = run_exec(prepare_split, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
    if rc != 0 or b"split_request_exported=true" not in out:
        raise FixtureFailure(f"split prepare failed: {err!r}")
    for name in ["config", "genesis.bin", "split-request.bin"]:
        copy_private(custody_dir, operator_dir, name, OPERATOR_UID, OPERATOR_GID)

    approve_split = cli_argv("custody", "approve-split", *trust_flags(custody_dir),
        "--request-file", f"{custody_dir}/split-request.bin", "--approvals-dir", approvals, "--expires-in-seconds", "3600")
    rc, _out, refusal = run_exec(approve_split, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
    if rc == 0 or b"custody approve requires an interactive terminal" not in refusal:
        raise FixtureFailure("split approval unexpectedly accepted a pipe")
    phase_approve_via_pty(None, None, 0, SPLIT_REQUEST_ID, 3600, command=approve_split)

    serve = None
    native = None
    try:
        serve = start_serve(socket_path, 30, 6, 6, command=serve_command(6))
        sign_split = cli_argv("custody", "sign-split", *trust_flags(operator_dir),
            "--request-file", f"{operator_dir}/split-request.bin", *signer)
        rc, _out, err = run_exec([*sign_split, "--out", f"{operator_dir}/offline-split.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"protected offline split sign failed: {err!r}")

        os.chmod(ROOT, 0o755)
        phase_operator_cannot_read_or_edit(SPLIT_REQUEST_ID)
        native = subprocess.Popen(probe_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=lambda: (os.setgroups([OPERATOR_GID]), os.setgid(OPERATOR_GID), os.setuid(OPERATOR_UID)),
            env=probe_env("serve", operator_dir), cwd="/")
        address = None
        startup_end = time.monotonic() + min(10, remaining())
        prefix = b""
        while address is None:
            if time.monotonic() >= startup_end:
                native.kill(); native.wait(timeout=5)
                raise FixtureFailure("split/merge native host did not start")
            ready, _, _ = select.select([native.stdout], [], [], min(1, remaining()))
            if ready:
                line = native.stdout.readline(16385)
                if not line:
                    tail, failure = native.communicate(timeout=min(5, remaining()))
                    charge_output(len(tail) + len(failure))
                    raise FixtureFailure(f"split/merge native host exited before its address: {failure[:16384]!r}")
                prefix += line; charge_output(len(line))
                if len(prefix) > 16384:
                    raise FixtureFailure("split/merge native startup output exceeds bound")
                if line.startswith(b'{"address":'):
                    address = json.loads(line)["address"]

        split_command = cli_argv("split", "--endpoint", address, *signer,
            "--expected-chain-id", "custody-whole-coin-test", "--expected-protocol-version", "7",
            "--expected-epoch", "0", "--expected-hash-suite-id", "1", "--expected-domain", DOMAIN_HEX,
            "--coin", generated["coin"], "--fee-source", generated["fee"], "--amount", str(SPLIT_AMOUNT),
            "--recipient", public_key, "--nonce", "0", "--request-id", SPLIT_REQUEST_ID,
            "--max-fee", "1000000", "--gas-limit", "200000",
            "--submission-out", f"{operator_dir}/split-submission.bin", "--result-out", f"{operator_dir}/split-result.bin")
        rc, out, err = run_exec(split_command, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0 or b"paid_status=Success" not in out:
            raise FixtureFailure(f"actual protected split CLI failed: {out!r} {err!r}")
        with open(f"{operator_dir}/offline-split.bin", "rb") as source:
            offline_split = source.read(1048577)
        with open(f"{operator_dir}/split-submission.bin", "rb") as source:
            if source.read(1048577) != offline_split:
                raise FixtureFailure("offline and actual CLI split signed bytes differ")

        # ---- after-split: independent verification plus fresh merge preimages ----
        split_merge_probe_argv = [LD_SO, "--library-path", LIB_DIR, HARNESS,
            "custody::asset_split_merge_fixture::distinct_uid_split_merge_probe", "--exact", "--ignored", "--nocapture", "--format", "terse"]
        def split_merge_env(mode, **overrides):
            env = {
                "CUSTODY_SPLIT_MERGE_MODE": mode,
                "CUSTODY_SPLIT_MERGE_DIR": operator_dir,
                "CUSTODY_SPLIT_MERGE_ENDPOINT": address,
                "CUSTODY_SPLIT_MERGE_PUBLIC_KEY": public_key,
                "CUSTODY_SPLIT_MERGE_ORIGINAL_COIN_HEX": generated["coin"],
                "CUSTODY_SPLIT_MERGE_FEE_COIN_HEX": generated["fee"],
            }
            env.update(overrides)
            return env
        rc, out, err = run_exec(split_merge_probe_argv, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID],
            env=split_merge_env("after-split", CUSTODY_SPLIT_MERGE_SPLIT_AMOUNT=str(SPLIT_AMOUNT)))
        after_split = last_json_line(out)
        if rc != 0 or after_split.get("mode") != "after-split" or after_split.get("verified") is not True:
            raise FixtureFailure(f"after-split verification failed: {err!r}")
        if after_split.get("next_nonce") != 1:
            raise FixtureFailure("after-split next_nonce did not reach 1")
        new_coin_hex = after_split["new_coin_hex"]

        merge_inputs_dir = f"{custody_dir}/merge-inputs"
        os.mkdir(merge_inputs_dir, 0o700)
        os.chown(merge_inputs_dir, CUSTODY_UID, CUSTODY_GID)
        for name in ["into.bin", "from.bin", "fee.bin"]:
            copy_private(operator_dir, merge_inputs_dir, name, CUSTODY_UID, CUSTODY_GID)

        # ---- merge: prepare / approve / offline sign / actual CLI merge ----
        prepare_merge = cli_argv("custody", "prepare-merge", *trust_flags(custody_dir),
            "--into-file", f"{merge_inputs_dir}/into.bin", "--from-file", f"{merge_inputs_dir}/from.bin",
            "--fee-source-file", f"{merge_inputs_dir}/fee.bin", "--nonce", "1", "--request-id", MERGE_REQUEST_ID,
            "--max-fee", "1000000", "--gas-limit", "200000", "--out", f"{custody_dir}/merge-request.bin")
        rc, out, err = run_exec(prepare_merge, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc != 0 or b"merge_request_exported=true" not in out:
            raise FixtureFailure(f"merge prepare failed: {err!r}")
        copy_private(custody_dir, operator_dir, "merge-request.bin", OPERATOR_UID, OPERATOR_GID)

        approve_merge = cli_argv("custody", "approve-merge", *trust_flags(custody_dir),
            "--request-file", f"{custody_dir}/merge-request.bin", "--approvals-dir", approvals, "--expires-in-seconds", "3600")
        rc, _out, refusal = run_exec(approve_merge, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc == 0 or b"custody approve requires an interactive terminal" not in refusal:
            raise FixtureFailure("merge approval unexpectedly accepted a pipe")
        phase_approve_via_pty(None, None, 1, MERGE_REQUEST_ID, 3600, command=approve_merge)

        sign_merge = cli_argv("custody", "sign-merge", *trust_flags(operator_dir),
            "--request-file", f"{operator_dir}/merge-request.bin", *signer)
        rc, _out, err = run_exec([*sign_merge, "--out", f"{operator_dir}/offline-merge.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"protected offline merge sign failed: {err!r}")

        merge_command = cli_argv("merge", "--endpoint", address, *signer,
            "--expected-chain-id", "custody-whole-coin-test", "--expected-protocol-version", "7",
            "--expected-epoch", "0", "--expected-hash-suite-id", "1", "--expected-domain", DOMAIN_HEX,
            "--into", generated["coin"], "--from", new_coin_hex, "--fee-source", generated["fee"],
            "--nonce", "1", "--request-id", MERGE_REQUEST_ID, "--max-fee", "1000000", "--gas-limit", "200000",
            "--submission-out", f"{operator_dir}/merge-submission.bin", "--result-out", f"{operator_dir}/merge-result.bin")
        rc, out, err = run_exec(merge_command, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0 or b"paid_status=Success" not in out:
            raise FixtureFailure(f"actual protected merge CLI failed: {out!r} {err!r}")
        with open(f"{operator_dir}/offline-merge.bin", "rb") as source:
            offline_merge = source.read(1048577)
        with open(f"{operator_dir}/merge-submission.bin", "rb") as source:
            if source.read(1048577) != offline_merge:
                raise FixtureFailure("offline and actual CLI merge signed bytes differ")

        # ---- verify-merge: independent verification plus both-request replay ----
        rc, out, err = run_exec(split_merge_probe_argv, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID],
            env=split_merge_env("verify-merge",
                CUSTODY_SPLIT_MERGE_NEW_COIN_HEX=new_coin_hex,
                CUSTODY_SPLIT_MERGE_RECOMBINED_AMOUNT=str(RECOMBINED_AMOUNT)))
        verify_merge = last_json_line(out)
        if (rc != 0 or verify_merge.get("mode") != "verify-merge" or verify_merge.get("verified") is not True
                or verify_merge.get("replay_equal") is not True or verify_merge.get("next_nonce") != 2):
            raise FixtureFailure(f"verify-merge verification failed: {err!r}")

        # ---- revocation: both requests refused, same process, no output ----
        rc, _out, err = run_exec(cli_argv("custody", "revoke", "--approvals-dir", approvals, "--request-id", SPLIT_REQUEST_ID),
            CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"split revoke failed: {err!r}")
        rc, _out, err = run_exec(cli_argv("custody", "revoke", "--approvals-dir", approvals, "--request-id", MERGE_REQUEST_ID),
            CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"merge revoke failed: {err!r}")
        rc, _out, refusal = run_exec([*sign_split, "--out", f"{operator_dir}/revoked-split.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/revoked-split.bin"):
            raise FixtureFailure("revoked split produced signed output")
        rc, _out, refusal = run_exec([*sign_merge, "--out", f"{operator_dir}/revoked-merge.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/revoked-merge.bin"):
            raise FixtureFailure("revoked merge produced signed output")

        summary = wait_serve(serve, extra_seconds=10)
        check_summary("split_merge", summary, {
            "connections_accepted": "6", "requests_handled": "6",
            "requests_signed": "4", "requests_refused": "2",
        })

        with open(f"{operator_dir}/stop-native", "xb") as completed:
            completed.write(b"complete\n")
        os.chmod(f"{operator_dir}/stop-native", 0o600)
        os.chown(f"{operator_dir}/stop-native", OPERATOR_UID, OPERATOR_GID)
        out, err = native.communicate(timeout=min(25, remaining()))
        charge_output(len(out) + len(err))
        if native.returncode != 0 or b"1 passed; 0 failed; 0 ignored" not in out:
            raise FixtureFailure(f"split/merge native host did not finish cleanly: {err!r}")
    finally:
        for process in [native, serve]:
            if process is not None and process.poll() is None:
                process.kill(); process.wait(timeout=5)
        os.chmod(ROOT, 0o711)

    restarted = start_serve(socket_path, 30, 2, 2, command=serve_command(2))
    try:
        rc, _out, refusal = run_exec([*sign_split, "--out", f"{operator_dir}/revoked-split-restart.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/revoked-split-restart.bin"):
            raise FixtureFailure("revoked split produced output after restart")
        rc, _out, refusal = run_exec([*sign_merge, "--out", f"{operator_dir}/revoked-merge-restart.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/revoked-merge-restart.bin"):
            raise FixtureFailure("revoked merge produced output after restart")
        restarted_summary = wait_serve(restarted, extra_seconds=8)
        check_summary("split_merge revoked restart", restarted_summary,
            {"connections_accepted": "2", "requests_handled": "2", "requests_signed": "0", "requests_refused": "2"})
    finally:
        if restarted.poll() is None:
            restarted.kill(); restarted.wait(timeout=5)

    return {
        "actual_cli": True, "split_self": True, "after_split_verified": True,
        "merge_verified": verify_merge.get("verified") is True,
        "offline_bytes_equal": True, "replay_equal": verify_merge.get("replay_equal") is True,
        "revoked": True, "revoked_after_restart": True,
        "serve_summary": summary.strip().splitlines(),
        "restart_summary": restarted_summary.strip().splitlines(),
    }


def phase_mint_burn(public_key):
    # Fresh phase directories only: this reuses the exact same one-owner,
    # one-app-coin/one-fee-coin devnet genesis 'distinct_uid_transfer_probe'
    # already builds (via its own unmodified "generate"/"serve" modes),
    # booted into a brand-new store here. It never touches phase_transfer's
    # or phase_split_merge's own directories, genesis, coins or assertions.
    # The TreasuryCap preimage those modes never export is independently
    # rebuilt by 'asset_mint_burn_fixture::distinct_uid_mint_burn_probe's own
    # "generate-cap" mode instead.
    custody_dir, operator_dir = f"{ROOT}/custody-mint-burn", f"{ROOT}/operator/mint-burn"
    for path, uid, gid in [(custody_dir, CUSTODY_UID, CUSTODY_GID), (operator_dir, OPERATOR_UID, OPERATOR_GID)]:
        os.mkdir(path, 0o700)
        os.chown(path, uid, gid)
    probe_argv = [LD_SO, "--library-path", LIB_DIR, HARNESS,
                  "custody::asset_fixture::distinct_uid_transfer_probe", "--exact", "--ignored", "--nocapture", "--format", "terse"]
    def probe_env(mode, directory):
        return {"CUSTODY_TRANSFER_MODE": mode, "CUSTODY_TRANSFER_DIR": directory, "CUSTODY_TRANSFER_PUBLIC_KEY": public_key}
    rc, out, err = run_exec(probe_argv, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID], env=probe_env("generate", custody_dir))
    if rc != 0:
        raise FixtureFailure(f"mint/burn preimage generation failed: {err!r}")
    generated = last_json_line(out)

    mint_burn_probe_argv = [LD_SO, "--library-path", LIB_DIR, HARNESS,
        "custody::asset_mint_burn_fixture::distinct_uid_mint_burn_probe", "--exact", "--ignored", "--nocapture", "--format", "terse"]
    def mint_burn_env(mode, **overrides):
        env = {
            "CUSTODY_MINT_BURN_MODE": mode,
            "CUSTODY_MINT_BURN_DIR": custody_dir,
            "CUSTODY_MINT_BURN_PUBLIC_KEY": public_key,
        }
        env.update(overrides)
        return env
    rc, out, err = run_exec(mint_burn_probe_argv, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID], env=mint_burn_env("generate-cap"))
    if rc != 0:
        raise FixtureFailure(f"mint/burn cap preimage generation failed: {err!r}")
    generated_cap = last_json_line(out)
    if generated_cap.get("mode") != "generate-cap" or generated_cap.get("digest") != generated["digest"]:
        raise FixtureFailure("mint/burn cap preimage generation did not match the shared genesis digest")
    cap_hex = generated_cap["cap_hex"]

    config_text = f"chain_id=custody-whole-coin-test\nprotocol_version=7\nepoch=0\nhash_suite_id=1\ndomain={DOMAIN_HEX}\npublisher_public_key={public_key}\noperator_uid={OPERATOR_UID}\n"
    with open(f"{custody_dir}/config", "x") as output:
        output.write(config_text)
    os.chmod(f"{custody_dir}/config", 0o600)
    os.chown(f"{custody_dir}/config", CUSTODY_UID, CUSTODY_GID)
    def trust_flags(directory):
        return ["--config", f"{directory}/config", "--genesis-manifest-file", f"{directory}/genesis.bin", "--genesis-digest", generated["digest"]]

    def copy_private(src_dir, dst_dir, name, dst_uid, dst_gid):
        with open(f"{src_dir}/{name}", "rb") as source:
            content = source.read(1024 * 1024)
        with open(f"{dst_dir}/{name}", "xb") as target:
            target.write(content)
        os.chmod(f"{dst_dir}/{name}", 0o600)
        os.chown(f"{dst_dir}/{name}", dst_uid, dst_gid)

    approvals = f"{ROOT}/custody-approvals"
    socket_path = f"{ROOT}/run/mint-burn.sock"
    signer = ["--custody-socket", socket_path, "--custody-uid", str(CUSTODY_UID), "--custody-expected-public-key", public_key]

    def serve_command(count):
        return cli_argv("custody", "serve-mint-burn", *trust_flags(custody_dir),
            "--key-file", f"{ROOT}/custody-keys/custody.seed", "--socket", socket_path,
            "--approvals-dir", approvals, "--max-connections", str(count), "--max-requests", str(count), "--total-deadline-secs", "30")

    # ---- mint: prepare / approve / offline sign / actual CLI mint ----
    prepare_mint = cli_argv("custody", "prepare-mint", *trust_flags(custody_dir),
        "--cap-file", f"{custody_dir}/cap.bin", "--fee-source-file", f"{custody_dir}/fee.bin",
        "--amount", str(MINT_AMOUNT), "--recipient", public_key, "--nonce", "0", "--request-id", MINT_REQUEST_ID,
        "--max-fee", "1000000", "--gas-limit", "200000", "--out", f"{custody_dir}/mint-request.bin")
    rc, out, err = run_exec(prepare_mint, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
    if rc != 0 or b"mint_request_exported=true" not in out:
        raise FixtureFailure(f"mint prepare failed: {err!r}")
    for name in ["config", "genesis.bin", "mint-request.bin"]:
        copy_private(custody_dir, operator_dir, name, OPERATOR_UID, OPERATOR_GID)

    approve_mint = cli_argv("custody", "approve-mint", *trust_flags(custody_dir),
        "--request-file", f"{custody_dir}/mint-request.bin", "--approvals-dir", approvals, "--expires-in-seconds", "3600")
    rc, _out, refusal = run_exec(approve_mint, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
    if rc == 0 or b"custody approve requires an interactive terminal" not in refusal:
        raise FixtureFailure("mint approval unexpectedly accepted a pipe")
    phase_approve_via_pty(None, None, 0, MINT_REQUEST_ID, 3600, command=approve_mint)

    serve = None
    native = None
    try:
        serve = start_serve(socket_path, 30, 6, 6, command=serve_command(6))
        sign_mint = cli_argv("custody", "sign-mint", *trust_flags(operator_dir),
            "--request-file", f"{operator_dir}/mint-request.bin", *signer)
        rc, _out, err = run_exec([*sign_mint, "--out", f"{operator_dir}/offline-mint.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"protected offline mint sign failed: {err!r}")

        os.chmod(ROOT, 0o755)
        phase_operator_cannot_read_or_edit(MINT_REQUEST_ID)
        native = subprocess.Popen(probe_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=lambda: (os.setgroups([OPERATOR_GID]), os.setgid(OPERATOR_GID), os.setuid(OPERATOR_UID)),
            env=probe_env("serve", operator_dir), cwd="/")
        address = None
        startup_end = time.monotonic() + min(10, remaining())
        prefix = b""
        while address is None:
            if time.monotonic() >= startup_end:
                native.kill(); native.wait(timeout=5)
                raise FixtureFailure("mint/burn native host did not start")
            ready, _, _ = select.select([native.stdout], [], [], min(1, remaining()))
            if ready:
                line = native.stdout.readline(16385)
                if not line:
                    tail, failure = native.communicate(timeout=min(5, remaining()))
                    charge_output(len(tail) + len(failure))
                    raise FixtureFailure(f"mint/burn native host exited before its address: {failure[:16384]!r}")
                prefix += line; charge_output(len(line))
                if len(prefix) > 16384:
                    raise FixtureFailure("mint/burn native startup output exceeds bound")
                if line.startswith(b'{"address":'):
                    address = json.loads(line)["address"]

        mint_command = cli_argv("mint", "--endpoint", address, *signer,
            "--expected-chain-id", "custody-whole-coin-test", "--expected-protocol-version", "7",
            "--expected-epoch", "0", "--expected-hash-suite-id", "1", "--expected-domain", DOMAIN_HEX,
            "--treasury-cap", cap_hex, "--amount", str(MINT_AMOUNT), "--recipient", public_key,
            "--fee-source", generated["fee"],
            "--nonce", "0", "--request-id", MINT_REQUEST_ID, "--max-fee", "1000000", "--gas-limit", "200000",
            "--submission-out", f"{operator_dir}/mint-submission.bin", "--result-out", f"{operator_dir}/mint-result.bin")
        rc, out, err = run_exec(mint_command, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0 or b"paid_status=Success" not in out:
            raise FixtureFailure(f"actual protected mint CLI failed: {out!r} {err!r}")
        with open(f"{operator_dir}/offline-mint.bin", "rb") as source:
            offline_mint = source.read(1048577)
        with open(f"{operator_dir}/mint-submission.bin", "rb") as source:
            if source.read(1048577) != offline_mint:
                raise FixtureFailure("offline and actual CLI mint signed bytes differ")

        # ---- after-mint: independent verification plus fresh burn preimages ----
        rc, out, err = run_exec(mint_burn_probe_argv, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID],
            env=mint_burn_env("after-mint", CUSTODY_MINT_BURN_DIR=operator_dir, CUSTODY_MINT_BURN_ENDPOINT=address,
                CUSTODY_MINT_BURN_CAP_HEX=cap_hex, CUSTODY_MINT_BURN_FEE_COIN_HEX=generated["fee"],
                CUSTODY_MINT_BURN_MINT_AMOUNT=str(MINT_AMOUNT)))
        after_mint = last_json_line(out)
        if rc != 0 or after_mint.get("mode") != "after-mint" or after_mint.get("verified") is not True:
            raise FixtureFailure(f"after-mint verification failed: {err!r}")
        if after_mint.get("next_nonce") != 1:
            raise FixtureFailure("after-mint next_nonce did not reach 1")
        new_coin_hex = after_mint["new_coin_hex"]

        burn_inputs_dir = f"{custody_dir}/burn-inputs"
        os.mkdir(burn_inputs_dir, 0o700)
        os.chown(burn_inputs_dir, CUSTODY_UID, CUSTODY_GID)
        for name in ["cap.bin", "coin.bin", "fee.bin"]:
            copy_private(operator_dir, burn_inputs_dir, name, CUSTODY_UID, CUSTODY_GID)

        # ---- burn: prepare / approve / offline sign / actual CLI burn ----
        prepare_burn = cli_argv("custody", "prepare-burn", *trust_flags(custody_dir),
            "--cap-file", f"{burn_inputs_dir}/cap.bin", "--coin-file", f"{burn_inputs_dir}/coin.bin",
            "--fee-source-file", f"{burn_inputs_dir}/fee.bin", "--nonce", "1", "--request-id", BURN_REQUEST_ID,
            "--max-fee", "1000000", "--gas-limit", "200000", "--out", f"{custody_dir}/burn-request.bin")
        rc, out, err = run_exec(prepare_burn, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc != 0 or b"burn_request_exported=true" not in out:
            raise FixtureFailure(f"burn prepare failed: {err!r}")
        copy_private(custody_dir, operator_dir, "burn-request.bin", OPERATOR_UID, OPERATOR_GID)

        approve_burn = cli_argv("custody", "approve-burn", *trust_flags(custody_dir),
            "--request-file", f"{custody_dir}/burn-request.bin", "--approvals-dir", approvals, "--expires-in-seconds", "3600")
        rc, _out, refusal = run_exec(approve_burn, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc == 0 or b"custody approve requires an interactive terminal" not in refusal:
            raise FixtureFailure("burn approval unexpectedly accepted a pipe")
        phase_approve_via_pty(None, None, 1, BURN_REQUEST_ID, 3600, command=approve_burn)

        sign_burn = cli_argv("custody", "sign-burn", *trust_flags(operator_dir),
            "--request-file", f"{operator_dir}/burn-request.bin", *signer)
        rc, _out, err = run_exec([*sign_burn, "--out", f"{operator_dir}/offline-burn.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"protected offline burn sign failed: {err!r}")

        burn_command = cli_argv("burn", "--endpoint", address, *signer,
            "--expected-chain-id", "custody-whole-coin-test", "--expected-protocol-version", "7",
            "--expected-epoch", "0", "--expected-hash-suite-id", "1", "--expected-domain", DOMAIN_HEX,
            "--treasury-cap", cap_hex, "--coin", new_coin_hex,
            "--fee-source", generated["fee"],
            "--nonce", "1", "--request-id", BURN_REQUEST_ID, "--max-fee", "1000000", "--gas-limit", "200000",
            "--submission-out", f"{operator_dir}/burn-submission.bin", "--result-out", f"{operator_dir}/burn-result.bin")
        rc, out, err = run_exec(burn_command, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0 or b"paid_status=Success" not in out:
            raise FixtureFailure(f"actual protected burn CLI failed: {out!r} {err!r}")
        with open(f"{operator_dir}/offline-burn.bin", "rb") as source:
            offline_burn = source.read(1048577)
        with open(f"{operator_dir}/burn-submission.bin", "rb") as source:
            if source.read(1048577) != offline_burn:
                raise FixtureFailure("offline and actual CLI burn signed bytes differ")

        # ---- verify-burn: independent verification plus both-request replay ----
        rc, out, err = run_exec(mint_burn_probe_argv, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID],
            env=mint_burn_env("verify-burn", CUSTODY_MINT_BURN_DIR=operator_dir, CUSTODY_MINT_BURN_ENDPOINT=address,
                CUSTODY_MINT_BURN_CAP_HEX=cap_hex, CUSTODY_MINT_BURN_FEE_COIN_HEX=generated["fee"],
                CUSTODY_MINT_BURN_NEW_COIN_HEX=new_coin_hex))
        verify_burn = last_json_line(out)
        if (rc != 0 or verify_burn.get("mode") != "verify-burn" or verify_burn.get("verified") is not True
                or verify_burn.get("replay_equal") is not True or verify_burn.get("next_nonce") != 2):
            raise FixtureFailure(f"verify-burn verification failed: {err!r}")

        # ---- revocation: both requests refused, same process, no output ----
        rc, _out, err = run_exec(cli_argv("custody", "revoke", "--approvals-dir", approvals, "--request-id", MINT_REQUEST_ID),
            CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"mint revoke failed: {err!r}")
        rc, _out, err = run_exec(cli_argv("custody", "revoke", "--approvals-dir", approvals, "--request-id", BURN_REQUEST_ID),
            CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"burn revoke failed: {err!r}")
        rc, _out, refusal = run_exec([*sign_mint, "--out", f"{operator_dir}/revoked-mint.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/revoked-mint.bin"):
            raise FixtureFailure("revoked mint produced signed output")
        rc, _out, refusal = run_exec([*sign_burn, "--out", f"{operator_dir}/revoked-burn.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/revoked-burn.bin"):
            raise FixtureFailure("revoked burn produced signed output")

        summary = wait_serve(serve, extra_seconds=10)
        check_summary("mint_burn", summary, {
            "connections_accepted": "6", "requests_handled": "6",
            "requests_signed": "4", "requests_refused": "2",
        })

        with open(f"{operator_dir}/stop-native", "xb") as completed:
            completed.write(b"complete\n")
        os.chmod(f"{operator_dir}/stop-native", 0o600)
        os.chown(f"{operator_dir}/stop-native", OPERATOR_UID, OPERATOR_GID)
        out, err = native.communicate(timeout=min(25, remaining()))
        charge_output(len(out) + len(err))
        if native.returncode != 0 or b"1 passed; 0 failed; 0 ignored" not in out:
            raise FixtureFailure(f"mint/burn native host did not finish cleanly: {err!r}")
    finally:
        for process in [native, serve]:
            if process is not None and process.poll() is None:
                process.kill(); process.wait(timeout=5)
        os.chmod(ROOT, 0o711)

    restarted = start_serve(socket_path, 30, 2, 2, command=serve_command(2))
    try:
        rc, _out, refusal = run_exec([*sign_mint, "--out", f"{operator_dir}/revoked-mint-restart.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/revoked-mint-restart.bin"):
            raise FixtureFailure("revoked mint produced output after restart")
        rc, _out, refusal = run_exec([*sign_burn, "--out", f"{operator_dir}/revoked-burn-restart.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/revoked-burn-restart.bin"):
            raise FixtureFailure("revoked burn produced output after restart")
        restarted_summary = wait_serve(restarted, extra_seconds=8)
        check_summary("mint_burn revoked restart", restarted_summary,
            {"connections_accepted": "2", "requests_handled": "2", "requests_signed": "0", "requests_refused": "2"})
    finally:
        if restarted.poll() is None:
            restarted.kill(); restarted.wait(timeout=5)

    return {
        "actual_cli": True, "mint_self": True, "after_mint_verified": True,
        "burn_verified": verify_burn.get("verified") is True,
        "offline_bytes_equal": True, "replay_equal": verify_burn.get("replay_equal") is True,
        "revoked": True, "revoked_after_restart": True,
        "serve_summary": summary.strip().splitlines(),
        "restart_summary": restarted_summary.strip().splitlines(),
    }


def stop_owned_process(process, uid, gid):
    # CAP_KILL is deliberately absent. Signal only our Popen child, as its UID,
    # using the already permitted SETUID/SETGID boundary and one shared 5s cap.
    if process is None or process.poll() is not None:
        return
    cleanup_deadline = time.monotonic() + 5
    code = "import os,sys\ntry: os.kill(int(sys.argv[1]),9)\nexcept ProcessLookupError: pass"
    rc, _out, err = run_exec([sys.executable, "-I", "-S", "-c", code, str(process.pid)],
        uid, gid, [gid], timeout=5)
    if rc != 0:
        raise FixtureFailure(f"owned child cleanup signal failed: {err!r}")
    left = cleanup_deadline - time.monotonic()
    if left <= 0:
        raise FixtureFailure("owned child cleanup exceeded its original 5s bound")
    process.wait(timeout=left)


def phase_own_asset_mint_burn(custody_dir, operator_dir, public_key, address, generated, definition_hex, cap_hex):
    # DR-0258: runs while phase_create_asset's own native backend (address)
    # is still alive, reusing its custody/operator directories and the exact
    # genesis fee trust those already set up. serve-create's own socket is
    # already dead by this point (it exits once its own fixed request
    # budget is spent), so this opens its own separate kind-4
    # serve-mint-burn process on a fresh socket, pinned via --asset/
    # --instance-ref to the asset phase_create_asset's own earlier steps
    # just created, never the pinned genesis TreasuryCap. Shape mirrors
    # phase_mint_burn's own two-operation (mint then burn) lifecycle exactly,
    # but never starts a second native backend.
    def trust_flags(directory):
        return ["--config", f"{directory}/config", "--genesis-manifest-file", f"{directory}/genesis.bin", "--genesis-digest", generated["digest"]]
    def application_flags(directory):
        return [*trust_flags(directory), "--asset", definition_hex, "--instance-ref", f"{directory}/create-instance.bin"]

    def copy_private(src_dir, dst_dir, name, dst_uid, dst_gid):
        with open(f"{src_dir}/{name}", "rb") as source:
            content = source.read(1024 * 1024)
        with open(f"{dst_dir}/{name}", "xb") as target:
            target.write(content)
        os.chmod(f"{dst_dir}/{name}", 0o600)
        os.chown(f"{dst_dir}/{name}", dst_uid, dst_gid)

    for name in ["own-cap.bin", "own-fee.bin", "create-instance.bin"]:
        copy_private(operator_dir, custody_dir, name, CUSTODY_UID, CUSTODY_GID)

    # Public CLI output becomes the operator's own independently local pin.
    # Its owner sets the required private mode; the supervisor needs no FOWNER.
    rc, _out, err = run_exec(
        [sys.executable, "-I", "-S", "-c", "import os,sys;os.chmod(sys.argv[1],0o600)", f"{operator_dir}/create-instance.bin"],
        OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID], timeout=5)
    if rc != 0:
        raise FixtureFailure(f"operator instance pin could not be made private: {err!r}")

    approvals = f"{ROOT}/custody-approvals"
    socket_path = f"{ROOT}/run/create-mint-burn.sock"
    signer = ["--custody-socket", socket_path, "--custody-uid", str(CUSTODY_UID), "--custody-expected-public-key", public_key]

    def serve_command(count):
        return cli_argv("custody", "serve-mint-burn", *application_flags(custody_dir),
            "--key-file", f"{ROOT}/custody-keys/custody.seed", "--socket", socket_path,
            "--approvals-dir", approvals, "--max-connections", str(count), "--max-requests", str(count), "--total-deadline-secs", "30")

    # ---- own-mint: prepare / approve / offline sign / actual CLI mint ----
    prepare_mint = cli_argv("custody", "prepare-mint", *application_flags(custody_dir),
        "--cap-file", f"{custody_dir}/own-cap.bin", "--fee-source-file", f"{custody_dir}/own-fee.bin",
        "--amount", str(OWN_ASSET_MINT_AMOUNT), "--recipient", public_key, "--nonce", "1", "--request-id", OWN_MINT_REQUEST_ID,
        "--max-fee", "1000000", "--gas-limit", "200000", "--out", f"{custody_dir}/own-mint-request.bin")
    rc, out, err = run_exec(prepare_mint, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
    if rc != 0 or b"mint_request_exported=true" not in out:
        raise FixtureFailure(f"own-asset mint prepare failed: {err!r}")
    copy_private(custody_dir, operator_dir, "own-mint-request.bin", OPERATOR_UID, OPERATOR_GID)

    approve_mint = cli_argv("custody", "approve-mint", *application_flags(custody_dir),
        "--request-file", f"{custody_dir}/own-mint-request.bin", "--approvals-dir", approvals, "--expires-in-seconds", "3600")
    rc, _out, refusal = run_exec(approve_mint, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
    if rc == 0 or b"custody approve requires an interactive terminal" not in refusal:
        raise FixtureFailure("own-asset mint approval unexpectedly accepted a pipe")
    phase_approve_via_pty(None, None, 1, OWN_MINT_REQUEST_ID, 3600, command=approve_mint)

    create_probe_argv = [LD_SO, "--library-path", LIB_DIR, HARNESS,
        "custody::asset_create_fixture::distinct_uid_create_asset_probe", "--exact", "--ignored", "--nocapture", "--format", "terse"]
    own_env = {
        "CUSTODY_CREATE_MODE": "after-own-mint",
        "CUSTODY_CREATE_DIR": operator_dir,
        "CUSTODY_CREATE_PUBLIC_KEY": public_key,
        "CUSTODY_CREATE_ENDPOINT": address,
    }

    serve = None
    try:
        serve = start_serve(socket_path, 30, 6, 6, command=serve_command(6))
        sign_mint = cli_argv("custody", "sign-mint", *application_flags(operator_dir),
            "--request-file", f"{operator_dir}/own-mint-request.bin", *signer)
        rc, _out, err = run_exec([*sign_mint, "--out", f"{operator_dir}/own-offline-mint.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"protected offline own-asset mint sign failed: {err!r}")

        mint_command = cli_argv("mint", "--endpoint", address, *signer,
            "--expected-chain-id", "custody-whole-coin-test", "--expected-protocol-version", "7",
            "--expected-epoch", "0", "--expected-hash-suite-id", "1", "--expected-domain", DOMAIN_HEX,
            "--treasury-cap", cap_hex, "--amount", str(OWN_ASSET_MINT_AMOUNT), "--recipient", public_key,
            "--asset", definition_hex, "--instance-ref", f"{operator_dir}/create-instance.bin",
            "--fee-source", generated["fee"],
            "--nonce", "1", "--request-id", OWN_MINT_REQUEST_ID, "--max-fee", "1000000", "--gas-limit", "200000",
            "--submission-out", f"{operator_dir}/own-mint-submission.bin", "--result-out", f"{operator_dir}/own-mint-result.bin")
        rc, out, err = run_exec(mint_command, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0 or b"paid_status=Success" not in out:
            raise FixtureFailure(f"actual protected own-asset mint CLI failed: {out!r} {err!r}")
        with open(f"{operator_dir}/own-offline-mint.bin", "rb") as source:
            offline_mint = source.read(1048577)
        with open(f"{operator_dir}/own-mint-submission.bin", "rb") as source:
            if source.read(1048577) != offline_mint:
                raise FixtureFailure("offline and actual CLI own-asset mint signed bytes differ")

        rc, out, err = run_exec(create_probe_argv, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID], env=own_env)
        after_own_mint = last_json_line(out)
        if (rc != 0 or after_own_mint.get("mode") != "after-own-mint" or after_own_mint.get("verified") is not True
                or after_own_mint.get("next_nonce") != 2):
            raise FixtureFailure(f"after-own-mint verification failed: {err!r}")
        new_coin_hex = after_own_mint["new_coin_hex"]

        # Distinct source names from after-create's own own-cap.bin/own-fee.bin
        # (copied into custody_dir earlier, for the mint leg): after-own-mint
        # exports the post-mint burn-input preimages under own-burn-cap.bin/
        # own-burn-fee.bin precisely to avoid colliding with those, since
        # write_review_preimage never overwrites an existing path.
        burn_inputs_dir = f"{custody_dir}/own-burn-inputs"
        os.mkdir(burn_inputs_dir, 0o700)
        os.chown(burn_inputs_dir, CUSTODY_UID, CUSTODY_GID)
        for name in ["own-burn-cap.bin", "own-coin.bin", "own-burn-fee.bin"]:
            copy_private(operator_dir, burn_inputs_dir, name, CUSTODY_UID, CUSTODY_GID)

        # ---- own-burn: prepare / approve / offline sign / actual CLI burn ----
        prepare_burn = cli_argv("custody", "prepare-burn", *application_flags(custody_dir),
            "--cap-file", f"{burn_inputs_dir}/own-burn-cap.bin", "--coin-file", f"{burn_inputs_dir}/own-coin.bin",
            "--fee-source-file", f"{burn_inputs_dir}/own-burn-fee.bin", "--nonce", "2", "--request-id", OWN_BURN_REQUEST_ID,
            "--max-fee", "1000000", "--gas-limit", "200000", "--out", f"{custody_dir}/own-burn-request.bin")
        rc, out, err = run_exec(prepare_burn, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc != 0 or b"burn_request_exported=true" not in out:
            raise FixtureFailure(f"own-asset burn prepare failed: {err!r}")
        copy_private(custody_dir, operator_dir, "own-burn-request.bin", OPERATOR_UID, OPERATOR_GID)

        approve_burn = cli_argv("custody", "approve-burn", *application_flags(custody_dir),
            "--request-file", f"{custody_dir}/own-burn-request.bin", "--approvals-dir", approvals, "--expires-in-seconds", "3600")
        rc, _out, refusal = run_exec(approve_burn, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc == 0 or b"custody approve requires an interactive terminal" not in refusal:
            raise FixtureFailure("own-asset burn approval unexpectedly accepted a pipe")
        phase_approve_via_pty(None, None, 2, OWN_BURN_REQUEST_ID, 3600, command=approve_burn)

        sign_burn = cli_argv("custody", "sign-burn", *application_flags(operator_dir),
            "--request-file", f"{operator_dir}/own-burn-request.bin", *signer)
        rc, _out, err = run_exec([*sign_burn, "--out", f"{operator_dir}/own-offline-burn.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"protected offline own-asset burn sign failed: {err!r}")

        burn_command = cli_argv("burn", "--endpoint", address, *signer,
            "--expected-chain-id", "custody-whole-coin-test", "--expected-protocol-version", "7",
            "--expected-epoch", "0", "--expected-hash-suite-id", "1", "--expected-domain", DOMAIN_HEX,
            "--treasury-cap", cap_hex, "--coin", new_coin_hex,
            "--asset", definition_hex, "--instance-ref", f"{operator_dir}/create-instance.bin",
            "--fee-source", generated["fee"],
            "--nonce", "2", "--request-id", OWN_BURN_REQUEST_ID, "--max-fee", "1000000", "--gas-limit", "200000",
            "--submission-out", f"{operator_dir}/own-burn-submission.bin", "--result-out", f"{operator_dir}/own-burn-result.bin")
        rc, out, err = run_exec(burn_command, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0 or b"paid_status=Success" not in out:
            raise FixtureFailure(f"actual protected own-asset burn CLI failed: {out!r} {err!r}")
        with open(f"{operator_dir}/own-offline-burn.bin", "rb") as source:
            offline_burn = source.read(1048577)
        with open(f"{operator_dir}/own-burn-submission.bin", "rb") as source:
            if source.read(1048577) != offline_burn:
                raise FixtureFailure("offline and actual CLI own-asset burn signed bytes differ")

        rc, out, err = run_exec(create_probe_argv, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID],
            env={**own_env, "CUSTODY_CREATE_MODE": "verify-own-burn"})
        verify_own_burn = last_json_line(out)
        if (rc != 0 or verify_own_burn.get("mode") != "verify-own-burn" or verify_own_burn.get("verified") is not True
                or verify_own_burn.get("replay_equal") is not True or verify_own_burn.get("next_nonce") != 3):
            raise FixtureFailure(f"verify-own-burn verification failed: {err!r}")

        # ---- revocation: both requests refused, same process, no output ----
        rc, _out, err = run_exec(cli_argv("custody", "revoke", "--approvals-dir", approvals, "--request-id", OWN_MINT_REQUEST_ID),
            CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"own-asset mint revoke failed: {err!r}")
        rc, _out, err = run_exec(cli_argv("custody", "revoke", "--approvals-dir", approvals, "--request-id", OWN_BURN_REQUEST_ID),
            CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"own-asset burn revoke failed: {err!r}")
        rc, _out, refusal = run_exec([*sign_mint, "--out", f"{operator_dir}/own-revoked-mint.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/own-revoked-mint.bin"):
            raise FixtureFailure("revoked own-asset mint produced signed output")
        rc, _out, refusal = run_exec([*sign_burn, "--out", f"{operator_dir}/own-revoked-burn.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/own-revoked-burn.bin"):
            raise FixtureFailure("revoked own-asset burn produced signed output")

        summary = wait_serve(serve, extra_seconds=10)
        check_summary("own_mint_burn", summary, {
            "connections_accepted": "6", "requests_handled": "6",
            "requests_signed": "4", "requests_refused": "2",
        })
    finally:
        if serve is not None and serve.poll() is None:
            stop_owned_process(serve, CUSTODY_UID, CUSTODY_GID)

    restarted = start_serve(socket_path, 30, 2, 2, command=serve_command(2))
    try:
        rc, _out, refusal = run_exec([*sign_mint, "--out", f"{operator_dir}/own-revoked-mint-restart.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/own-revoked-mint-restart.bin"):
            raise FixtureFailure("revoked own-asset mint produced output after restart")
        rc, _out, refusal = run_exec([*sign_burn, "--out", f"{operator_dir}/own-revoked-burn-restart.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/own-revoked-burn-restart.bin"):
            raise FixtureFailure("revoked own-asset burn produced output after restart")
        restarted_summary = wait_serve(restarted, extra_seconds=8)
        check_summary("own_mint_burn revoked restart", restarted_summary,
            {"connections_accepted": "2", "requests_handled": "2", "requests_signed": "0", "requests_refused": "2"})
    finally:
        if restarted.poll() is None:
            stop_owned_process(restarted, CUSTODY_UID, CUSTODY_GID)

    return {
        "actual_cli": True, "own_mint_self": True, "after_own_mint_verified": True,
        "own_burn_verified": verify_own_burn.get("verified") is True,
        "offline_bytes_equal": True, "replay_equal": verify_own_burn.get("replay_equal") is True,
        "revoked": True, "revoked_after_restart": True,
        "asset_hex": after_own_mint.get("asset_hex"),
        "new_coin_hex": new_coin_hex,
        "serve_summary": summary.strip().splitlines(),
        "restart_summary": restarted_summary.strip().splitlines(),
    }


def phase_create_asset(public_key):
    # Fresh phase directories only: this reuses the exact same one-owner,
    # one-app-coin/one-fee-coin devnet genesis 'distinct_uid_transfer_probe'
    # already builds (via its own unmodified "generate"/"serve" modes), with
    # the SAME custody-held publisher used by transfer/split-merge/mint-burn
    # (dev_owners[0]/mint authority, distinct from the genesis signer/fee
    # recipient), booted into a brand-new store here. It never touches any
    # other phase's own genesis, coins, custody-approvals entries, or
    # assertions.
    #
    # DR-0255/M2: a fifth closed wire kind (5), under custody's own
    # prepare-create/approve-create/sign-create/serve-create commands. The
    # only family whose Instantiate targets a FRESH derived instance rather
    # than the pinned genesis one, and whose own custody request carries no
    # pre-existing owned Coin/TreasuryCap input, only a fee source. Shape
    # mirrors phase_transfer's single-operation lifecycle (one signed
    # request, not two like split/merge or mint/burn): offline sign-create
    # plus the actual CLI's own custody-mediated signing both succeed against
    # the live approval, then revocation leaves both the same server and a
    # fresh restart refusing further signatures.
    custody_dir, operator_dir = f"{ROOT}/custody-create", f"{ROOT}/operator/create"
    for path, uid, gid in [(custody_dir, CUSTODY_UID, CUSTODY_GID), (operator_dir, OPERATOR_UID, OPERATOR_GID)]:
        os.mkdir(path, 0o700)
        os.chown(path, uid, gid)
    probe_argv = [LD_SO, "--library-path", LIB_DIR, HARNESS,
                  "custody::asset_fixture::distinct_uid_transfer_probe", "--exact", "--ignored", "--nocapture", "--format", "terse"]
    def probe_env(mode, directory):
        return {"CUSTODY_TRANSFER_MODE": mode, "CUSTODY_TRANSFER_DIR": directory, "CUSTODY_TRANSFER_PUBLIC_KEY": public_key}
    rc, out, err = run_exec(probe_argv, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID], env=probe_env("generate", custody_dir))
    if rc != 0:
        raise FixtureFailure(f"create-asset preimage generation failed: {err!r}")
    generated = last_json_line(out)
    config_text = f"chain_id=custody-whole-coin-test\nprotocol_version=7\nepoch=0\nhash_suite_id=1\ndomain={DOMAIN_HEX}\npublisher_public_key={public_key}\noperator_uid={OPERATOR_UID}\n"
    with open(f"{custody_dir}/config", "x") as output:
        output.write(config_text)
    os.chmod(f"{custody_dir}/config", 0o600)
    os.chown(f"{custody_dir}/config", CUSTODY_UID, CUSTODY_GID)
    def trust_flags(directory):
        return ["--config", f"{directory}/config", "--genesis-manifest-file", f"{directory}/genesis.bin", "--genesis-digest", generated["digest"]]

    def copy_private(src_dir, dst_dir, name, dst_uid, dst_gid):
        with open(f"{src_dir}/{name}", "rb") as source:
            content = source.read(1024 * 1024)
        with open(f"{dst_dir}/{name}", "xb") as target:
            target.write(content)
        os.chmod(f"{dst_dir}/{name}", 0o600)
        os.chown(f"{dst_dir}/{name}", dst_uid, dst_gid)

    approvals = f"{ROOT}/custody-approvals"
    socket_path = f"{ROOT}/run/create.sock"
    signer = ["--custody-socket", socket_path, "--custody-uid", str(CUSTODY_UID), "--custody-expected-public-key", public_key]

    def serve_command(count):
        return cli_argv("custody", "serve-create", *trust_flags(custody_dir),
            "--key-file", f"{ROOT}/custody-keys/custody.seed", "--socket", socket_path,
            "--approvals-dir", approvals, "--max-connections", str(count), "--max-requests", str(count), "--total-deadline-secs", "30")

    # ---- create: prepare / approve (real PTY, full typed confirmation) / ----
    # offline sign / actual CLI create-asset, with --fee-source and the real
    # canonical fee preimage, never a Coin/TreasuryCap input.
    prepare_create = cli_argv("custody", "prepare-create", *trust_flags(custody_dir),
        "--seed", CREATE_INSTANCE_SEED_HEX, "--fee-source-file", f"{custody_dir}/fee.bin",
        "--nonce", "0", "--request-id", CREATE_REQUEST_ID,
        "--max-fee", "1000000", "--gas-limit", "200000", "--out", f"{custody_dir}/create-request.bin")
    rc, out, err = run_exec(prepare_create, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
    if rc != 0 or b"create_request_exported=true" not in out:
        raise FixtureFailure(f"create prepare failed: {err!r}")
    for name in ["config", "genesis.bin", "create-request.bin"]:
        copy_private(custody_dir, operator_dir, name, OPERATOR_UID, OPERATOR_GID)

    approve_create = cli_argv("custody", "approve-create", *trust_flags(custody_dir),
        "--request-file", f"{custody_dir}/create-request.bin", "--approvals-dir", approvals, "--expires-in-seconds", "3600")
    rc, _out, refusal = run_exec(approve_create, CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
    if rc == 0 or b"custody approve requires an interactive terminal" not in refusal:
        raise FixtureFailure("create approval unexpectedly accepted a pipe")
    # phase_approve_via_pty captures whatever exact "Type exactly to
    # approve:\n<confirmation>" line approve-create actually prints (its
    # own full "APPROVE-CREATE sender=... seed=... new_instance_*
    # fee_balance=... max_fee=... nonce=... request_id=... not_after=..."
    # shape, distinct from every other family's confirmation text) and
    # echoes it back verbatim; it never hardcodes the text itself.
    phase_approve_via_pty(None, None, 0, CREATE_REQUEST_ID, 3600, command=approve_create)

    serve = None
    native = None
    try:
        serve = start_serve(socket_path, 30, 3, 3, command=serve_command(3))
        sign_create = cli_argv("custody", "sign-create", *trust_flags(operator_dir),
            "--request-file", f"{operator_dir}/create-request.bin", *signer)
        rc, _out, err = run_exec([*sign_create, "--out", f"{operator_dir}/offline-create.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"protected offline create sign failed: {err!r}")

        os.chmod(ROOT, 0o755)
        phase_operator_cannot_read_or_edit(CREATE_REQUEST_ID)
        native = subprocess.Popen(probe_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=lambda: (os.setgroups([OPERATOR_GID]), os.setgid(OPERATOR_GID), os.setuid(OPERATOR_UID)),
            env=probe_env("serve", operator_dir), cwd="/")
        address = None
        startup_end = time.monotonic() + min(10, remaining())
        prefix = b""
        while address is None:
            if time.monotonic() >= startup_end:
                native.kill(); native.wait(timeout=5)
                raise FixtureFailure("create-asset native host did not start")
            ready, _, _ = select.select([native.stdout], [], [], min(1, remaining()))
            if ready:
                line = native.stdout.readline(16385)
                if not line:
                    tail, failure = native.communicate(timeout=min(5, remaining()))
                    charge_output(len(tail) + len(failure))
                    raise FixtureFailure(f"create-asset native host exited before its address: {failure[:16384]!r}")
                prefix += line; charge_output(len(line))
                if len(prefix) > 16384:
                    raise FixtureFailure("create-asset native startup output exceeds bound")
                if line.startswith(b'{"address":'):
                    address = json.loads(line)["address"]

        # The real standard_asset create-asset CLI, custody-mediated: the
        # required --fee-source plus --instance-seed/--instance-ref-out it
        # already had, now driven through --custody-socket/--custody-uid/
        # --custody-expected-public-key like every other protected family.
        create_command = cli_argv("create-asset", "--endpoint", address, *signer,
            "--expected-chain-id", "custody-whole-coin-test", "--expected-protocol-version", "7",
            "--expected-epoch", "0", "--expected-hash-suite-id", "1", "--expected-domain", DOMAIN_HEX,
            "--fee-source", generated["fee"], "--nonce", "0", "--request-id", CREATE_REQUEST_ID,
            "--max-fee", "1000000", "--gas-limit", "200000",
            "--instance-seed", CREATE_INSTANCE_SEED_HEX, "--instance-ref-out", f"{operator_dir}/create-instance.bin",
            "--submission-out", f"{operator_dir}/create-submission.bin", "--result-out", f"{operator_dir}/create-result.bin")
        rc, out, err = run_exec(create_command, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc != 0 or b"paid_status=Success" not in out:
            raise FixtureFailure(f"actual protected create-asset CLI failed: {out!r} {err!r}")
        with open(f"{operator_dir}/offline-create.bin", "rb") as source:
            offline_create = source.read(1048577)
        with open(f"{operator_dir}/create-submission.bin", "rb") as source:
            if source.read(1048577) != offline_create:
                raise FixtureFailure("offline and actual CLI create signed bytes differ")

        # ---- after-create: independent verification plus exact replay ----
        create_probe_argv = [LD_SO, "--library-path", LIB_DIR, HARNESS,
            "custody::asset_create_fixture::distinct_uid_create_asset_probe", "--exact", "--ignored", "--nocapture", "--format", "terse"]
        create_env = {
            "CUSTODY_CREATE_MODE": "after-create",
            "CUSTODY_CREATE_DIR": operator_dir,
            "CUSTODY_CREATE_PUBLIC_KEY": public_key,
            "CUSTODY_CREATE_ENDPOINT": address,
            "CUSTODY_CREATE_INSTANCE_SEED_HEX": CREATE_INSTANCE_SEED_HEX,
        }
        rc, out, err = run_exec(create_probe_argv, OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID], env=create_env)
        after_create = last_json_line(out)
        if (rc != 0 or after_create.get("mode") != "after-create" or after_create.get("verified") is not True
                or after_create.get("replay_equal") is not True or after_create.get("next_nonce") != 1):
            raise FixtureFailure(f"after-create verification failed: {err!r}")

        # ---- revocation: refused on the same server, no signed output ----
        rc, _out, err = run_exec(cli_argv("custody", "revoke", "--approvals-dir", approvals, "--request-id", CREATE_REQUEST_ID),
            CUSTODY_UID, CUSTODY_GID, [CUSTODY_GID])
        if rc != 0:
            raise FixtureFailure(f"create revoke failed: {err!r}")
        rc, _out, refusal = run_exec([*sign_create, "--out", f"{operator_dir}/revoked-create.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/revoked-create.bin"):
            raise FixtureFailure("revoked create produced signed output")

        summary = wait_serve(serve, extra_seconds=10)
        check_summary("create", summary, {
            "connections_accepted": "3", "requests_handled": "3",
            "requests_signed": "2", "requests_refused": "1",
        })

        # DR-0258: before this phase's own native backend is ever stopped,
        # independently exercise an application-pinned mint-then-burn round
        # trip against the asset it just created, through a separate
        # kind-4 serve-mint-burn process.
        own_mint_burn_summary = phase_own_asset_mint_burn(
            custody_dir, operator_dir, public_key, address, generated,
            after_create["definition_hex"], after_create["treasury_cap_hex"],
        )

        with open(f"{operator_dir}/stop-native", "xb") as completed:
            completed.write(b"complete\n")
        os.chmod(f"{operator_dir}/stop-native", 0o600)
        os.chown(f"{operator_dir}/stop-native", OPERATOR_UID, OPERATOR_GID)
        out, err = native.communicate(timeout=min(25, remaining()))
        charge_output(len(out) + len(err))
        if native.returncode != 0 or b"1 passed; 0 failed; 0 ignored" not in out:
            raise FixtureFailure(f"create-asset native host did not finish cleanly: {err!r}")
    finally:
        for process, uid, gid in [(native, OPERATOR_UID, OPERATOR_GID), (serve, CUSTODY_UID, CUSTODY_GID)]:
            stop_owned_process(process, uid, gid)
        os.chmod(ROOT, 0o711)

    # ---- restart: the same revoked request id stays refused ----
    restarted = start_serve(socket_path, 30, 1, 1, command=serve_command(1))
    try:
        rc, _out, refusal = run_exec([*sign_create, "--out", f"{operator_dir}/revoked-create-restart.bin"], OPERATOR_UID, OPERATOR_GID, [OPERATOR_GID, CUSTODY_GID])
        if rc == 0 or b"custody refused the request: no_approval" not in refusal or os.path.lexists(f"{operator_dir}/revoked-create-restart.bin"):
            raise FixtureFailure("revoked create produced output after restart")
        restarted_summary = wait_serve(restarted, extra_seconds=8)
        check_summary("create revoked restart", restarted_summary,
            {"connections_accepted": "1", "requests_handled": "1", "requests_signed": "0", "requests_refused": "1"})
    finally:
        if restarted.poll() is None:
            stop_owned_process(restarted, CUSTODY_UID, CUSTODY_GID)

    return {
        "actual_cli": True, "create_self": True, "after_create_verified": True,
        "replay_equal": after_create.get("replay_equal") is True,
        "definition_hex": after_create.get("definition_hex"),
        "treasury_cap_hex": after_create.get("treasury_cap_hex"),
        "offline_bytes_equal": True,
        "revoked": True, "revoked_after_restart": True,
        "serve_summary": summary.strip().splitlines(),
        "restart_summary": restarted_summary.strip().splitlines(),
    }, own_mint_burn_summary


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

    # ---- Custody revocation lifecycle ----
    approvals_dir = f"{ROOT}/custody-approvals"
    phase_operator_cannot_revoke(approvals_dir, MAIN_REQUEST_ID)
    live_proc = start_serve(socket_path, total_deadline_secs=10, max_connections=2, max_requests=2)
    live_signature = expect_sign_success(public_key, socket_path, MAIN_REQUEST_ID, 1)
    if live_signature["signature_hex"] != first["signature_hex"]:
        raise FixtureFailure("the live cancellation baseline did not match the original signature")
    phase_revoke_is_idempotent_and_preserves_approval(approvals_dir, MAIN_REQUEST_ID)
    phase_reject_reapproval_of_revoked(config_path, main_artifact, 1, MAIN_REQUEST_ID)
    expect_sign_failure("revoked-on-same-process", public_key, socket_path, MAIN_REQUEST_ID, 1)
    live_summary = wait_serve(live_proc, extra_seconds=8)
    check_summary("live cancellation", live_summary, {
        "connections_accepted": "2", "requests_handled": "2",
        "requests_signed": "1", "requests_refused": "1",
    })

    third_proc = start_serve(socket_path, total_deadline_secs=10, max_connections=1, max_requests=1)
    expect_sign_failure("revoked-main", public_key, socket_path, MAIN_REQUEST_ID, 1)
    third_summary = wait_serve(third_proc, extra_seconds=8)
    check_summary("post-revocation restart", third_summary, {
        "connections_accepted": "1", "requests_handled": "1",
        "requests_signed": "0", "requests_refused": "1",
    })
    if os.path.lexists(socket_path):
        raise FixtureFailure("post-revocation restarted custody left its bound socket behind")

    # ---- Custody-owned private recovery of the same disposable seed ----
    main_key_path = f"{ROOT}/custody-keys/custody.seed"
    restored_key_path = phase_recover_private_key(main_key_path)
    recovery_summaries = phase_recovery_verification(
        public_key, config_path, main_key_path, restored_key_path, socket_path,
    )
    restored_approval_summary = phase_retain_revocation_through_recovery(
        approvals_dir, MAIN_REQUEST_ID, public_key, restored_key_path, config_path, socket_path,
    )

    missing_recovered_key_path = f"{ROOT}/custody-keys/custody.seed.missing"
    expect_serve_startup_failure(
        "missing-recovered-key", missing_recovered_key_path, config_path, socket_path,
        f'custody I/O failed for "{missing_recovered_key_path}": No such file or directory (os error 2)',
    )
    mismatched_config_path = phase_write_config(WRONG_PUBLIC_KEY_HEX, f"{ROOT}/custody-keys/mismatched.config")
    expect_serve_startup_failure(
        "recovered-key-wrong-config", restored_key_path, mismatched_config_path, socket_path,
        "custody key file's derived public key does not match the configured publisher",
    )

    # ---- A second, independently keyed custody identity ----
    new_identity_summary = phase_new_identity(socket_path, public_key)

    transfer_summary = phase_transfer(public_key)
    split_merge_summary = phase_split_merge(public_key)
    mint_burn_summary = phase_mint_burn(public_key)
    create_asset_summary, created_asset_mint_burn_summary = phase_create_asset(public_key)

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
        "revocation_enforced": True,
        "recovery_signature_match": True,
        "revocation_retained_through_recovery": True,
        "new_identity_verified": True,
        "transfer": transfer_summary,
        "split_merge": split_merge_summary,
        "mint_burn": mint_burn_summary,
        "create_asset": create_asset_summary,
        "created_asset_mint_burn": created_asset_mint_burn_summary,
        "lifecycle_summaries": [live_summary.strip().splitlines(), third_summary.strip().splitlines(), *recovery_summaries,
                                restored_approval_summary, new_identity_summary],
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
        const diagnostic = answer.stderr.trim() || answer.stdout.trim();
        const error = new Error(`Docker refused ${args[0]}: ${diagnostic}`);
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
      result.generated_bytes_total > 64 * 1024 * 1024 ||
      result.revocation_enforced !== true || result.recovery_signature_match !== true ||
      result.revocation_retained_through_recovery !== true || result.new_identity_verified !== true) {
    throw new Error('the fixture evidence line is incomplete');
  }
  const expectedLifecycle = [[2, 2, 1, 1], [1, 1, 0, 1], [1, 1, 1, 0], [1, 1, 1, 0], [1, 1, 0, 1], [3, 3, 1, 2]];
  if (!result.transfer || ['actual_cli', 'whole_coin', 'offline_bytes_equal', 'replay_equal', 'revoked', 'revoked_after_restart']
    .some((key) => result.transfer[key] !== true)) {
    throw new Error('the distinct-UID protected transfer evidence is incomplete');
  }
  // `phase_split_merge`'s own `check_summary` calls already enforce the
  // exact kind-3 serve counts (6/6/4/2, then 2/2/0/2 after revocation and
  // restart) by raising inside the container on any mismatch, exactly like
  // `phase_transfer`'s own serve-count enforcement above; this check only
  // requires every one of its own completion flags, the same shape as the
  // `result.transfer` check immediately above.
  if (!result.split_merge || ['actual_cli', 'split_self', 'after_split_verified', 'merge_verified',
      'offline_bytes_equal', 'replay_equal', 'revoked', 'revoked_after_restart']
    .some((key) => result.split_merge[key] !== true)) {
    throw new Error('the distinct-UID protected split/merge evidence is incomplete');
  }
  const countKeys = ['connections_accepted', 'requests_handled', 'requests_signed', 'requests_refused'];
  for (const [key, counts] of [['serve_summary', [6, 6, 4, 2]], ['restart_summary', [2, 2, 0, 2]]]) {
    if (JSON.stringify(result.split_merge[key]) !== JSON.stringify(countKeys.map((name, index) => `${name}=${counts[index]}`))) {
      throw new Error('the split/merge serve counters are incomplete or differ');
    }
  }
  // `phase_mint_burn`'s own `check_summary` calls already enforce the exact
  // kind-4 serve counts (6/6/4/2, then 2/2/0/2 after revocation and
  // restart) by raising inside the container on any mismatch, exactly like
  // `phase_split_merge`'s own serve-count enforcement above; this check
  // only requires every one of its own completion flags, the same shape as
  // the `result.split_merge` check immediately above.
  if (!result.mint_burn || ['actual_cli', 'mint_self', 'after_mint_verified', 'burn_verified',
      'offline_bytes_equal', 'replay_equal', 'revoked', 'revoked_after_restart']
    .some((key) => result.mint_burn[key] !== true)) {
    throw new Error('the distinct-UID protected mint/burn evidence is incomplete');
  }
  for (const [key, counts] of [['serve_summary', [6, 6, 4, 2]], ['restart_summary', [2, 2, 0, 2]]]) {
    if (JSON.stringify(result.mint_burn[key]) !== JSON.stringify(countKeys.map((name, index) => `${name}=${counts[index]}`))) {
      throw new Error('the mint/burn serve counters are incomplete or differ');
    }
  }
  // `phase_create_asset`'s own `check_summary` calls already enforce the
  // exact kind-5 serve counts (3/3/2/1, then 1/1/0/1 after revocation and
  // restart) by raising inside the container on any mismatch, exactly like
  // `phase_transfer`'s own serve-count enforcement above (create-asset is a
  // single-operation family, like transfer, not a two-operation family like
  // split/merge or mint/burn); this check only requires every one of its
  // own completion flags, plus independently verified by
  // `asset_create_fixture`'s own `after-create` mode (created Definition/
  // TreasuryCap, durable instance query, dedup receipt, exact-replay).
  if (!result.create_asset || ['actual_cli', 'create_self', 'after_create_verified', 'replay_equal',
      'offline_bytes_equal', 'revoked', 'revoked_after_restart']
    .some((key) => result.create_asset[key] !== true) ||
    typeof result.create_asset.definition_hex !== 'string' || typeof result.create_asset.treasury_cap_hex !== 'string' ||
    result.create_asset.definition_hex === result.create_asset.treasury_cap_hex) {
    throw new Error('the distinct-UID create-asset evidence is incomplete');
  }
  for (const [key, counts] of [['serve_summary', [3, 3, 2, 1]], ['restart_summary', [1, 1, 0, 1]]]) {
    if (JSON.stringify(result.create_asset[key]) !== JSON.stringify(countKeys.map((name, index) => `${name}=${counts[index]}`))) {
      throw new Error('the create-asset serve counters are incomplete or differ');
    }
  }
  // `phase_own_asset_mint_burn`'s own `check_summary` calls already enforce
  // the exact kind-4 serve counts (6/6/4/2, then 2/2/0/2 after revocation
  // and restart) for the application-pinned mint/burn custody family
  // (DR-0258), targeting the asset `phase_create_asset`'s own earlier steps
  // just created rather than the pinned genesis TreasuryCap, by raising
  // inside the container on any mismatch, exactly like `phase_mint_burn`'s
  // own serve-count enforcement above; this check only requires every one
  // of its own completion flags, plus independently verified by
  // `asset_create_fixture`'s own `after-own-mint`/`verify-own-burn` modes
  // (TreasuryCap supply 0->5,000,000->0, a fresh Coin created then
  // tombstoned, the exact same genesis fee Coin reused, and idempotent
  // replay of both requests).
  if (!result.created_asset_mint_burn || ['actual_cli', 'own_mint_self', 'after_own_mint_verified', 'own_burn_verified',
      'offline_bytes_equal', 'replay_equal', 'revoked', 'revoked_after_restart']
    .some((key) => result.created_asset_mint_burn[key] !== true) ||
    typeof result.created_asset_mint_burn.asset_hex !== 'string' || typeof result.created_asset_mint_burn.new_coin_hex !== 'string' ||
    result.created_asset_mint_burn.asset_hex !== result.create_asset.definition_hex ||
    result.created_asset_mint_burn.new_coin_hex === result.created_asset_mint_burn.asset_hex) {
    throw new Error('the application-pinned own-asset mint/burn evidence is incomplete');
  }
  for (const [key, counts] of [['serve_summary', [6, 6, 4, 2]], ['restart_summary', [2, 2, 0, 2]]]) {
    if (JSON.stringify(result.created_asset_mint_burn[key]) !== JSON.stringify(countKeys.map((name, index) => `${name}=${counts[index]}`))) {
      throw new Error('the own-asset mint/burn serve counters are incomplete or differ');
    }
  }
  if (!Array.isArray(result.lifecycle_summaries) || result.lifecycle_summaries.length !== expectedLifecycle.length ||
      result.lifecycle_summaries.some((summary, index) =>
        JSON.stringify(summary) !== JSON.stringify(countKeys.map((key, column) => `${key}=${expectedLifecycle[index][column]}`)))) {
    throw new Error('the lifecycle serve summaries are incomplete or differ');
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
