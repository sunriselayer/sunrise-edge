#!/usr/bin/env python3
"""Disposable distinct-UID/PTY generic paid Publish/Instantiate/Call acceptance.

Requires already-built CLI and either devnet_paid_contract_e2e (direct mode) or
fastvote_network_e2e (--fastvote mode) test binaries. The container has no
network access; its real SQLite/native-HTTP server and CLI communicate on
loopback. The test uses a disposable fixed key, never a live key.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

IMAGE = "python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
IMAGE_ID = "sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
OPERATOR = 12002
CUSTODY = 12001
LD = "/mnt/libs/ld.so"
LIB = "/mnt/libs"
CLI = "/mnt/bin/cli"
HARNESS = "/mnt/bin/harness"
ROOT = Path("/work")
DOCKER_ENV = {key: value for key, value in os.environ.items()
              if key not in {"DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"}}


def checked(args, **kw):
    if args[0] == "docker":
        kw["env"] = DOCKER_ENV
    result = subprocess.run(args, text=True, capture_output=True, **kw)
    if result.returncode:
        raise RuntimeError(f"command failed ({args[0]} {args[1]}): {result.stderr[-1200:]}")
    return result


def closure(path):
    lines = checked(["ldd", str(path)]).stdout.splitlines()
    interpreter = None
    libraries = {}
    for line in lines:
        match = re.search(r"=>\s*(/\S+)\s+\(0x", line) or re.search(r"^\s*(/\S+)\s+\(0x", line)
        if not match:
            continue
        dependency = Path(match.group(1))
        if not dependency.exists():
            continue
        if dependency.name.startswith("ld-linux") or dependency.name == "ld.so":
            if interpreter is not None and interpreter != dependency:
                raise RuntimeError("ambiguous loader")
            interpreter = dependency
        elif dependency.name in libraries and libraries[dependency.name] != dependency:
            raise RuntimeError("library basename collision")
        else:
            libraries[dependency.name] = dependency
    if interpreter is None:
        raise RuntimeError(f"no dynamic loader for {path}")
    return interpreter, libraries


def mount(src, dst):
    return ["--mount", f"type=bind,source={src},target={dst},readonly"]


def host(cli, harness, fastvote=False):
    for path in (cli, harness):
        if not path.is_absolute() or not path.is_file() or path.is_symlink():
            raise RuntimeError("exact regular absolute binary paths required")
    if checked(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE]).stdout.strip() != IMAGE_ID:
        raise RuntimeError("pinned Python image unavailable")
    loader_a, libs_a = closure(cli)
    loader_b, libs_b = closure(harness)
    if loader_a != loader_b:
        raise RuntimeError("different loaders")
    for name, path in libs_b.items():
        if name in libs_a and libs_a[name] != path:
            raise RuntimeError("library collision")
        libs_a[name] = path
    name = "sunrise-generic-paid-uid-" + uuid.uuid4().hex
    # Docker Desktop shares the user's workspace, not host /usr/lib. Copy the
    # exact small loader closure into this task's cache and remove it afterward.
    library_copy = Path(tempfile.mkdtemp(prefix="generic-paid-libs-", dir=cli.parent))
    try:
        shutil.copy2(loader_a, library_copy / "ld.so")
        for name_, path in libs_a.items():
            shutil.copy2(path, library_copy / name_)
    except BaseException:
        shutil.rmtree(library_copy)
        raise
    script = Path(__file__).resolve()
    args = [
        "docker", "create", "--pull=never", "--name", name,
        "--label", f"sunrise-edge.generic-paid-uid={name}",
        "--network", "none", "--read-only", "--user", "0:0",
        "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
        "--cap-add", "SETUID", "--cap-add", "SETGID",
        "--security-opt", "no-new-privileges", "--memory", "768m", "--memory-swap", "768m",
        "--pids-limit", "48", "--cpus", "2", "--log-driver", "none",
        "--tmpfs", "/work:rw,nosuid,nodev,size=96m,mode=0711",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m,mode=1777",
        *mount(cli, CLI), *mount(harness, HARNESS), *mount(script, "/mnt/fixture.py"),
        *mount(library_copy / "ld.so", LD),
    ]
    for name_ in sorted(libs_a):
        args.extend(mount(library_copy / name_, f"{LIB}/{name_}"))
    args.extend(["--entrypoint", "/usr/local/bin/python3", IMAGE, "-I", "-B", "/mnt/fixture.py", "--inside"])
    if fastvote:
        args.append("--fastvote")
    container_id = None
    try:
        container_id = checked(args).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeError("invalid owned container id")
        started = subprocess.run(["docker", "start", "--attach", container_id], text=True, capture_output=True, timeout=180, env=DOCKER_ENV)
        state = json.loads(checked(["docker", "inspect", "--format", "{{json .State}}", container_id]).stdout)
        if started.returncode or state["ExitCode"]:
            raise RuntimeError(f"fixture failed: exit={state['ExitCode']}; stdout={started.stdout[-3000:]}; stderr={started.stderr[-3000:]}")
        print(started.stdout.strip())
    finally:
        try:
            if container_id is not None:
                removed = subprocess.run(["docker", "rm", "-f", container_id], capture_output=True, timeout=20, env=DOCKER_ENV)
                if removed.returncode:
                    raise RuntimeError(f"owned container removal failed: {removed.stderr[-1000:]!r}")
            residue = checked(["docker", "ps", "-aq", "--no-trunc", "--filter", f"name=^/{name}$"]).stdout.strip()
            if residue:
                raise RuntimeError("owned container cleanup incomplete")
        finally:
            shutil.rmtree(library_copy)


def as_uid(uid):
    def action():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return action


def command(args, uid, success=True, timeout=20):
    proc = subprocess.run(args, text=True, capture_output=True, timeout=timeout, preexec_fn=as_uid(uid))
    if (proc.returncode == 0) != success:
        raise RuntimeError(f"unexpected CLI exit={proc.returncode}: {proc.stderr[-1200:]}")
    return proc


def cli(*args):
    return [LD, "--library-path", LIB, CLI, *args]


def private_dir(path, uid):
    path.mkdir(mode=0o700)
    os.chown(path, uid, uid)


def private_file(path, data, uid):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    os.chown(path, uid, uid)


def terminal_approve(args, expected_success, pins, request, nonce="0", operation="publish", content=None):
    master, slave = pty.openpty()
    proc = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=subprocess.PIPE, preexec_fn=as_uid(CUSTODY))
    os.close(slave)
    output = bytearray()
    deadline = time.monotonic() + 20
    marker = b"Type exactly to approve:\r\n"
    try:
        while marker not in output:
            if time.monotonic() > deadline:
                raise RuntimeError("approval prompt timeout")
            if master in select.select([master], [], [], 0.1)[0]:
                data = os.read(master, 4096)
                if not data:
                    raise RuntimeError("approval exited before prompt")
                output.extend(data)
                if len(output) > 65536:
                    raise RuntimeError("approval output exceeds cap")
        tail = output.split(marker, 1)[1]
        while b"\r\n" not in tail:
            if time.monotonic() > deadline:
                raise RuntimeError("approval confirmation timeout")
            if master in select.select([master], [], [], 0.1)[0]:
                tail += os.read(master, 4096)
        confirmation = tail.split(b"\r\n", 1)[0]
        if not confirmation.startswith(b"APPROVE-PAID ") or len(confirmation) > 2048:
            raise RuntimeError("incorrect approval confirmation frame")
        review = dict(line.split("=", 1) for line in output.split(marker, 1)[0].decode().replace("\r", "").splitlines())
        expected = {
            "chain_id": pins.get("chain_id", "cli-paid-contract"), "sender": pins["publisher"],
            "request_id": request, "nonce": nonce, "operation": operation,
            "fee_source.id": pins["fee_source"], "fee_source.access": "write",
            "max_fee": "1000000", "gas_limit": "200000",
        }
        if content is None:
            expected.update({
                "origin.publisher": pins["publisher"], "origin.seed": "31" * 32,
                "export_count": "2", "export[0]": "init", "export[1]": "run",
                "wasm_bytes": pins["wasm_bytes"], "abi_bytes": pins["abi_bytes"],
            })
        else:
            expected.update(content)
        if any(review.get(key) != value for key, value in expected.items()):
            raise RuntimeError("human-visible paid review differs from fixture pins")
        frame = dict(field.split("=", 1) for field in confirmation.decode().split()[1:])
        frame_expected = {
            "sender": pins["publisher"], "request_id": request, "nonce": nonce,
            "policy": review["fee_policy_digest"], "fee_source": pins["fee_source"],
            "max_fee": "1000000",
        }
        if any(frame.get(key) != value for key, value in frame_expected.items()):
            raise RuntimeError("typed paid confirmation differs from displayed review")
        os.write(master, confirmation + b"\n" if expected_success else b"NO\n")
        while time.monotonic() < deadline:
            if master in select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 4096)
                except OSError:
                    break
                if not data:
                    break
                output.extend(data)
                if len(output) > 65536:
                    raise RuntimeError("approval output exceeds cap")
            if proc.poll() is not None:
                break
        rc = proc.wait(timeout=2)
        stderr = proc.stderr.read(8192)
        if (rc == 0) != expected_success:
            raise RuntimeError(f"unexpected PTY approval exit={rc}: {stderr[-1000:]!r}")
        if not expected_success and b"confirmation did not match" not in stderr:
            raise RuntimeError("wrong PTY confirmation refused for another reason")
        return hashlib.sha256(confirmation).hexdigest(), int(frame["not_after"])
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)
        os.close(master)
        proc.stderr.close()


def inside():
    deadline = time.monotonic() + 135
    server_dir = ROOT / "server"
    ready = ROOT / "paid-ready"
    stop = ROOT / "paid-stop"
    env = dict(os.environ, SUNRISE_GENERIC_PAID_CUSTODY_FIXTURE_DIR=str(server_dir))
    server = subprocess.Popen(
        [LD, "--library-path", LIB, HARNESS, "--exact", "paid_publish_instantiate_and_call_cross_cli_http_and_sqlite", "--nocapture"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
    )
    try:
        while not ready.exists():
            if server.poll() is not None:
                raise RuntimeError("paid fixture server exited before ready")
            if time.monotonic() > deadline:
                raise RuntimeError("paid fixture server startup timeout")
            time.sleep(0.05)
        pins = dict(line.split("=", 1) for line in ready.read_text().splitlines())
        for key in ("endpoint", "protocol_version", "domain", "publisher", "fee_source"):
            if key not in pins:
                raise RuntimeError("missing fixture pin")
        pins["wasm_bytes"] = str((server_dir / "contract.wasm").stat().st_size)
        pins["abi_bytes"] = str((server_dir / "contract.abi").stat().st_size)
        operator = ROOT / "operator"
        custody = ROOT / "custody"
        private_dir(operator, OPERATOR)
        private_dir(custody, CUSTODY)
        approvals = custody / "approvals"
        private_dir(approvals, CUSTODY)
        private_file(custody / "key", b"07" * 32 + b"\n", CUSTODY)
        config = (
            f"chain_id=cli-paid-contract\nprotocol_version={pins['protocol_version']}\nepoch=0\n"
            f"hash_suite_id=1\ndomain={pins['domain']}\npublisher_public_key={pins['publisher']}\noperator_uid={OPERATOR}\n"
        ).encode()
        private_file(custody / "config", config, CUSTODY)
        private_file(custody / "policy", (server_dir / "paid-policy").read_bytes(), CUSTODY)
        inaccessible = command(["/usr/local/bin/python3", "-c", "import pathlib; pathlib.Path('/work/custody/key').read_bytes()"], OPERATOR, success=False)
        if "PermissionError" not in inaccessible.stderr:
            raise RuntimeError("operator key access did not fail by OS permission")
        no_approval_write = command(["/usr/local/bin/python3", "-c", "import pathlib; pathlib.Path('/work/custody/approvals/probe').write_bytes(b'x')"], OPERATOR, success=False)
        if "PermissionError" not in no_approval_write.stderr:
            raise RuntimeError("operator approval-store write did not fail by OS permission")
        common = [
            "--endpoint", pins["endpoint"], "--expected-chain-id", "cli-paid-contract",
            "--expected-protocol-version", pins["protocol_version"], "--expected-epoch", "0",
            "--expected-hash-suite-id", "1", "--expected-domain", pins["domain"],
        ]
        request = "41" * 32
        command(cli(
            "contract", "paid-publish", *common,
            "--custody-socket", "/work/nonexistent-custody.sock", "--custody-uid", str(CUSTODY),
            "--custody-expected-public-key", pins["publisher"],
            "--fee-source", pins["fee_source"], "--fee-access", "write", "--max-fee", "1000000",
            "--gas-limit", "200000", "--request-id", request, "--nonce", "0",
            "--wasm", str(server_dir / "contract.wasm"), "--abi", str(server_dir / "contract.abi"),
            "--entrypoints", "init,run", "--origin-seed", "31" * 32,
            "--unsigned-out", str(operator / "unsigned"),
        ), OPERATOR)
        private_file(custody / "request", (operator / "unsigned").read_bytes(), CUSTODY)
        sign = cli(
            "custody", "sign-paid", "--config", str(custody / "config"),
            "--policy-file", str(custody / "policy"), "--request-file", str(custody / "request"),
            "--approvals-dir", str(approvals), "--endpoint", pins["endpoint"],
            "--key-file", str(custody / "key"), "--out", str(custody / "signed"),
        )
        before_approval = command(sign, CUSTODY, success=False)
        if "no approval for paid request" not in before_approval.stderr:
            raise RuntimeError("preapproval signing refused for another reason")
        if (custody / "signed").exists():
            raise RuntimeError("signed before approval")
        approve = cli(
            "custody", "approve-paid", "--config", str(custody / "config"),
            "--policy-file", str(custody / "policy"), "--request-file", str(custody / "request"),
            "--approvals-dir", str(approvals), "--endpoint", pins["endpoint"],
            "--expires-in-seconds", "120",
        )
        no_tty = command(approve, CUSTODY, success=False)
        if "terminal" not in no_tty.stderr.lower():
            raise RuntimeError("non-PTY approval did not refuse at terminal gate")
        terminal_approve(approve, expected_success=False, pins=pins, request=request)
        if list(approvals.iterdir()):
            raise RuntimeError("wrong PTY confirmation created an approval")
        frame_hash, not_after = terminal_approve(approve, expected_success=True, pins=pins, request=request)
        command(sign, CUSTODY)
        signed = (custody / "signed").read_bytes()
        # Prove the source and exact approval are still usable before revoke.
        command([*sign[:-1], str(custody / "signed-again")], CUSTODY)
        if (custody / "signed-again").read_bytes() != signed:
            raise RuntimeError("approved repeat signature changed")
        if time.time() + 5 >= not_after:
            raise RuntimeError("approval expired before revocation probe")
        command(cli("custody", "revoke", "--approvals-dir", str(approvals), "--request-id", request), CUSTODY)
        if (approvals / f"{request}.revoked").read_bytes() != b"\x01" + bytes.fromhex(request):
            raise RuntimeError("revocation record differs from request")
        new_out = custody / "signed-after-revoke"
        after_revoke = command([*sign[:-1], str(new_out)], CUSTODY, success=False)
        if "paid approval is expired, revoked, or differs" not in after_revoke.stderr or new_out.exists():
            raise RuntimeError("revoked approval did not block new signing")
        private_file(operator / "signed", signed, OPERATOR)
        submitted = command(cli(
            "contract", "paid-submit-signed", *common,
            "--signed-file", str(operator / "signed"),
            "--result-out", str(operator / "result"),
            "--dependency-ref-out", str(operator / "contract.ref"),
        ), OPERATOR)
        if ("paid_status=Success" not in submitted.stdout
                or not (operator / "result").is_file()
                or not (operator / "contract.ref").is_file()):
            raise RuntimeError("protected paid Publish did not succeed")
        # Existing signed bytes remain replayable; revocation blocks only new signatures.

        def next_paid(kind, request_byte, nonce, application_flags, content, derived_flag=None):
            request_id = request_byte * 32
            unsigned_path = operator / f"unsigned-{kind}"
            custody_request = custody / f"request-{kind}"
            custody_signed = custody / f"signed-{kind}"
            operator_signed = operator / f"signed-{kind}"
            result_path = operator / f"result-{kind}"
            command(cli(
                "contract", f"paid-{kind}", *common,
                "--custody-socket", "/work/nonexistent-custody.sock", "--custody-uid", str(CUSTODY),
                "--custody-expected-public-key", pins["publisher"],
                "--fee-source", pins["fee_source"], "--fee-access", "write", "--max-fee", "1000000",
                "--gas-limit", "200000", "--request-id", request_id, "--nonce", str(nonce),
                *application_flags, "--unsigned-out", str(unsigned_path),
            ), OPERATOR)
            private_file(custody_request, unsigned_path.read_bytes(), CUSTODY)
            sign_next = cli(
                "custody", "sign-paid", "--config", str(custody / "config"),
                "--policy-file", str(custody / "policy"), "--request-file", str(custody_request),
                "--approvals-dir", str(approvals), "--endpoint", pins["endpoint"],
                "--key-file", str(custody / "key"), "--out", str(custody_signed),
            )
            refused = command(sign_next, CUSTODY, success=False)
            if "no approval for paid request" not in refused.stderr or custody_signed.exists():
                raise RuntimeError(f"{kind} signed before approval")
            approve_next = cli(
                "custody", "approve-paid", "--config", str(custody / "config"),
                "--policy-file", str(custody / "policy"), "--request-file", str(custody_request),
                "--approvals-dir", str(approvals), "--endpoint", pins["endpoint"],
                "--expires-in-seconds", "120",
            )
            terminal_approve(approve_next, expected_success=False, pins=pins, request=request_id,
                             nonce=str(nonce), operation=kind, content=content)
            if (approvals / request_id).exists():
                raise RuntimeError(f"{kind} wrong confirmation wrote approval")
            frame_sha, _ = terminal_approve(approve_next, expected_success=True, pins=pins,
                                             request=request_id, nonce=str(nonce), operation=kind,
                                             content=content)
            command(sign_next, CUSTODY)
            signed_bytes = custody_signed.read_bytes()
            private_file(operator_signed, signed_bytes, OPERATOR)
            submit_flags = [] if derived_flag is None else [derived_flag, str(operator / f"{kind}.ref")]
            completed = command(cli(
                "contract", "paid-submit-signed", *common,
                "--signed-file", str(operator_signed), "--result-out", str(result_path),
                *submit_flags,
            ), OPERATOR)
            if ("paid_status=Success" not in completed.stdout or not result_path.is_file()
                    or (derived_flag is not None and not (operator / f"{kind}.ref").is_file())):
                raise RuntimeError(f"protected paid {kind} did not succeed")
            return {"operation": kind, "unsigned_bytes": unsigned_path.stat().st_size,
                    "signed_bytes": len(signed_bytes), "pty_confirmation_sha256": frame_sha,
                    "submitted": True, "refusals": ["sign_before_approval", "wrong_confirmation"]}

        opaque_args = (server_dir / "args").read_bytes().hex()
        instantiate = next_paid(
            "instantiate", "42", 1,
            ["--code-ref", str(operator / "contract.ref"), "--instance-seed", "32" * 32,
             "--args", str(server_dir / "args")],
            {"code.publisher": pins["publisher"], "code.seed": "31" * 32,
             "instance.creator": pins["publisher"], "instance.seed": "32" * 32, "entrypoint": "init",
             "arguments.opaque": opaque_args, "type_argument_count": "0"},
            "--instance-ref-out",
        )
        call = next_paid(
            "call", "43", 2,
            ["--instance-ref", str(operator / "instantiate.ref"), "--entrypoint", "run",
             "--access", str(server_dir / "access"), "--args", str(server_dir / "args")],
            {"code.publisher": pins["publisher"], "code.seed": "31" * 32,
             "instance.creator": pins["publisher"], "instance.seed": "32" * 32, "entrypoint": "run", "access_count": "0",
             "arguments.opaque": opaque_args, "type_argument_count": "0"},
        )
        print(json.dumps({
            "source": "real SQLite/native HTTP", "operations": ["publish", "instantiate", "call"],
            "operator_uid": OPERATOR, "custody_uid": CUSTODY,
            "pty_confirmation_sha256": frame_hash,
            "unsigned_bytes": (operator / "unsigned").stat().st_size,
            "signed_bytes": len(signed), "submitted": True,
            "refusals": ["operator_key_read", "operator_approval_write", "sign_before_approval", "approval_without_pty", "wrong_confirmation", "sign_after_revoke"],
            "instantiate": instantiate, "call": call,
        }, sort_keys=True))
    finally:
        stop.touch()
        try:
            server.communicate(timeout=8)
            if server.returncode:
                raise RuntimeError(f"paid server exit={server.returncode}")
        except subprocess.TimeoutExpired:
            server.kill()
            server.communicate(timeout=2)
            raise RuntimeError("fixture server failed to stop")
        if time.monotonic() > deadline:
            raise RuntimeError("fixture deadline exceeded")


def inside_fastvote():
    """Run the same protected CLI custody path against four real SQLite validators."""
    deadline = time.monotonic() + 135
    server_dir = ROOT / "server"
    ready = ROOT / "paid-ready"
    stop = ROOT / "paid-stop"
    log_path = ROOT / "fastvote-server.log"
    env = dict(os.environ, SUNRISE_GENERIC_PAID_FASTVOTE_FIXTURE_DIR=str(server_dir))
    with log_path.open("wb") as log:
        server = subprocess.Popen(
            [LD, "--library-path", LIB, HARNESS, "--ignored", "--exact",
             "generic_paid_custody_fastvote_fixture_server", "--nocapture"],
            stdout=log, stderr=log, env=env,
        )
        try:
            while not ready.exists():
                if server.poll() is not None:
                    raise RuntimeError(f"FastVote server exited before ready: {log_path.read_bytes()[-1800:]!r}")
                if time.monotonic() > deadline:
                    raise RuntimeError("FastVote server startup deadline")
                time.sleep(0.05)
            pins = dict(line.split("=", 1) for line in ready.read_text().splitlines())
            for key in ("endpoint", "chain_id", "protocol_version", "domain", "publisher",
                        "fee_source", "genesis_digest"):
                if key not in pins:
                    raise RuntimeError(f"missing FastVote pin: {key}")
            context = dict(line.split("=", 1) for line in
                           command(cli("context", "--endpoint", pins["endpoint"]),
                                   OPERATOR).stdout.splitlines())
            expected_context = {
                "chain_id": pins["chain_id"], "protocol_version": pins["protocol_version"],
                "epoch": "0", "transaction_auth_profile_id": "2", "domain": pins["domain"],
            }
            if any(context.get(key) != value for key, value in expected_context.items()):
                raise RuntimeError("FastVote host context does not match signed-genesis fixture pins")
            pins["wasm_bytes"] = str((server_dir / "contract.wasm").stat().st_size)
            pins["abi_bytes"] = str((server_dir / "contract.abi").stat().st_size)
            operator = ROOT / "operator"
            custody = ROOT / "custody"
            private_dir(operator, OPERATOR)
            private_dir(custody, CUSTODY)
            approvals = custody / "approvals"
            private_dir(approvals, CUSTODY)
            private_file(custody / "key", b"21" * 32 + b"\n", CUSTODY)
            private_file(custody / "config", (
                f"chain_id={pins['chain_id']}\nprotocol_version={pins['protocol_version']}\nepoch=0\n"
                f"hash_suite_id=1\ndomain={pins['domain']}\npublisher_public_key={pins['publisher']}\n"
                f"operator_uid={OPERATOR}\n"
            ).encode(), CUSTODY)
            private_file(custody / "policy", (server_dir / "paid-policy").read_bytes(), CUSTODY)
            common = [
                "--endpoint", pins["endpoint"], "--expected-chain-id", pins["chain_id"],
                "--expected-protocol-version", pins["protocol_version"], "--expected-epoch", "0",
                "--expected-hash-suite-id", "1", "--expected-domain", pins["domain"],
            ]
            expected_only = common[2:]
            network = [
                "--fastvote-network", str(server_dir / "fastvote-network"),
                "--fastvote-genesis-manifest", str(server_dir / "genesis-manifest"),
                "--fastvote-expected-genesis-digest", pins["genesis_digest"],
                "--fastvote-deadline-seconds", "30", "--fastvote-per-request-cap-seconds", "10",
            ]
            previous_certificate = None

            def protected(kind, request_byte, nonce, application_flags, content, derived_flag=None):
                nonlocal previous_certificate
                request_id = request_byte * 32
                unsigned = operator / f"unsigned-{kind}"
                custody_request = custody / f"request-{kind}"
                signed_path = custody / f"signed-{kind}"
                operator_signed = operator / f"signed-{kind}"
                certificate = operator / f"certificate-{kind}"
                result = operator / f"result-{kind}"
                command(cli(
                    "contract", f"paid-{kind}", *common, *network,
                    "--custody-socket", "/work/nonexistent-custody.sock", "--custody-uid", str(CUSTODY),
                    "--custody-expected-public-key", pins["publisher"],
                    "--fee-source", pins["fee_source"], "--fee-access", "write", "--max-fee", "1000000",
                    "--gas-limit", "200000", "--request-id", request_id, "--nonce", str(nonce),
                    *application_flags, "--unsigned-out", str(unsigned),
                ), OPERATOR)
                private_file(custody_request, unsigned.read_bytes(), CUSTODY)
                approve = cli(
                    "custody", "approve-paid", "--config", str(custody / "config"),
                    "--policy-file", str(custody / "policy"), "--request-file", str(custody_request),
                    "--approvals-dir", str(approvals), "--endpoint", pins["endpoint"],
                    "--expires-in-seconds", "120",
                )
                sign = cli(
                    "custody", "sign-paid", "--config", str(custody / "config"),
                    "--policy-file", str(custody / "policy"), "--request-file", str(custody_request),
                    "--approvals-dir", str(approvals), "--endpoint", pins["endpoint"],
                    "--key-file", str(custody / "key"), "--out", str(signed_path),
                )
                before = command(sign, CUSTODY, success=False)
                if "no approval for paid request" not in before.stderr or signed_path.exists():
                    raise RuntimeError(f"FastVote {kind} signed before approval")
                terminal_approve(approve, False, pins, request_id, str(nonce), kind, content)
                if (approvals / request_id).exists():
                    raise RuntimeError(f"FastVote {kind} wrong confirmation created approval")
                frame_hash, _ = terminal_approve(approve, True, pins, request_id, str(nonce), kind, content)
                command(sign, CUSTODY)
                signed = signed_path.read_bytes()
                private_file(operator_signed, signed, OPERATOR)
                replay = ["contract", "fastvote-replay", *expected_only, *network,
                          "--submission", str(operator_signed)]
                if kind == "publish":
                    wrong_context = expected_only.copy()
                    wrong_context[wrong_context.index("--expected-chain-id") + 1] += "-wrong"
                    wrong_chain = command(cli("contract", "fastvote-replay", *wrong_context,
                                              *network, "--submission", str(operator_signed)),
                                          OPERATOR, success=False)
                    if "genesis manifest commitment does not match" not in wrong_chain.stderr.lower():
                        raise RuntimeError(f"FastVote wrong chain refused for another reason: {wrong_chain.stderr[-1200:]}")
                if previous_certificate is not None:
                    mismatch = command(cli(*replay, "--certificate", str(previous_certificate)),
                                       OPERATOR, success=False)
                    if ("fastvote apply preflight rejected" not in mismatch.stderr.lower()
                            or "expected the exact submitted intent's own digest" not in mismatch.stderr.lower()):
                        raise RuntimeError(f"FastVote {kind} mismatched certificate refused for another reason: {mismatch.stderr[-1200:]}")
                elif kind == "publish":
                    private_file(operator / "corrupt-certificate", b"\x00", OPERATOR)
                    malformed = command(cli(*replay, "--certificate", str(operator / "corrupt-certificate")),
                                        OPERATOR, success=False)
                    if "cannot read exact saved certificate artifact" not in malformed.stderr.lower():
                        raise RuntimeError(f"malformed FastVote certificate refused for another reason: {malformed.stderr[-1200:]}")
                derived = [] if derived_flag is None else [derived_flag, str(operator / f"{kind}.ref")]
                applied = command(cli(*replay, "--fastvote-certificate-out", str(certificate),
                                      "--result-out", str(result), *derived), OPERATOR, timeout=45)
                if ("paid_status=Success" not in applied.stdout or not certificate.is_file()
                        or not result.is_file()
                        or (derived_flag is not None and not (operator / f"{kind}.ref").is_file())):
                    raise RuntimeError(f"FastVote {kind} did not apply")
                repeat = operator / f"result-replay-{kind}"
                replayed = command(cli(*replay, "--certificate", str(certificate),
                                       "--result-out", str(repeat)), OPERATOR, timeout=45)
                if "paid_status=Success" not in replayed.stdout or repeat.read_bytes() != result.read_bytes():
                    raise RuntimeError(f"FastVote {kind} exact certificate replay differed")
                previous_certificate = certificate
                return {"operation": kind, "unsigned_bytes": unsigned.stat().st_size,
                        "signed_bytes": len(signed), "certificate_bytes": certificate.stat().st_size,
                        "pty_confirmation_sha256": frame_hash, "applied": True,
                        "exact_replay": True,
                        "refusals": (["sign_before_approval", "wrong_confirmation", "bad_certificate",
                                      "wrong_chain"] if kind == "publish" else
                                     ["sign_before_approval", "wrong_confirmation", "bad_certificate"])}

            publish = protected(
                "publish", "41", 0,
                ["--wasm", str(server_dir / "contract.wasm"), "--abi", str(server_dir / "contract.abi"),
                 "--entrypoints", "init,run", "--origin-seed", "31" * 32],
                {"origin.publisher": pins["publisher"], "origin.seed": "31" * 32,
                 "export_count": "2", "export[0]": "init", "export[1]": "run",
                 "wasm_bytes": pins["wasm_bytes"], "abi_bytes": pins["abi_bytes"]},
                "--dependency-ref-out",
            )
            opaque_args = (server_dir / "args").read_bytes().hex()
            instantiate = protected(
                "instantiate", "42", 1,
                ["--code-ref", str(operator / "publish.ref"), "--instance-seed", "32" * 32,
                 "--args", str(server_dir / "args")],
                {"code.publisher": pins["publisher"], "code.seed": "31" * 32,
                 "instance.creator": pins["publisher"], "instance.seed": "32" * 32,
                 "entrypoint": "init", "arguments.opaque": opaque_args,
                 "type_argument_count": "0"},
                "--instance-ref-out",
            )
            call = protected(
                "call", "43", 2,
                ["--instance-ref", str(operator / "instantiate.ref"), "--entrypoint", "run",
                 "--access", str(server_dir / "access"), "--args", str(server_dir / "args")],
                {"code.publisher": pins["publisher"], "code.seed": "31" * 32,
                 "instance.creator": pins["publisher"], "instance.seed": "32" * 32,
                 "entrypoint": "run", "arguments.opaque": opaque_args,
                 "type_argument_count": "0", "access_count": "0"},
            )
            print(json.dumps({"mode": "fastvote", "source": "four real SQLite/native-HTTP validators",
                              "operator_uid": OPERATOR, "custody_uid": CUSTODY,
                              "publish": publish, "instantiate": instantiate, "call": call}, sort_keys=True))
        finally:
            stop.touch()
            try:
                server.communicate(timeout=8)
                if server.returncode:
                    raise RuntimeError(f"FastVote server exit={server.returncode}: {log_path.read_bytes()[-1800:]!r}")
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate(timeout=2)
                raise RuntimeError("FastVote fixture server failed to stop")
            if time.monotonic() > deadline:
                raise RuntimeError("FastVote fixture deadline exceeded")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--cli-binary", type=Path)
    p.add_argument("--test-binary", type=Path)
    p.add_argument("--inside", action="store_true")
    p.add_argument("--fastvote", action="store_true")
    a = p.parse_args()
    if a.inside:
        inside_fastvote() if a.fastvote else inside()
    elif a.cli_binary and a.test_binary:
        host(a.cli_binary.resolve(), a.test_binary.resolve(), a.fastvote)
    else:
        p.error("both exact binary paths required")
