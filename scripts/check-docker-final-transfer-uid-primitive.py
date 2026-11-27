#!/usr/bin/env python3
"""Disposable FinalTransfer phase 3/4 approval primitive, not live successor authority.

Usage: python3 scripts/check-docker-final-transfer-uid-primitive.py PATH_TO_CLI_LIB_TEST
The test binary must be built from the checkout under validation. No image pull.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys

IMAGE = "python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
IMAGE_ID = "sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
TEST = "custody::final_transfer_uid_fixture::final_transfer_uid_pty_primitive_probe"

CONTROLLER = r'''
import errno, glob, os, pty, select, shutil, subprocess, sys, time
loader, binary, test = sys.argv[1:]
root = '/work/custody'
for path in [root, root + '/keys', root + '/approvals']:
    os.mkdir(path, 0o700)
    os.chown(path, 12001, 12001)
def demote(uid):
    def do():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return do
def args():
    return [loader, '--library-path', '/tmp', binary, test, '--exact', '--ignored', '--nocapture', '--test-threads=1']
def run(mode, uid=12001, terminal=False):
    env = dict(os.environ, FINAL_TRANSFER_UID_ROOT=root, FINAL_TRANSFER_UID_MODE=mode)
    if terminal:
        master, slave = pty.openpty()
        proc = subprocess.Popen(args(), stdin=slave, stdout=slave, stderr=slave,
                                env=env, preexec_fn=demote(uid), start_new_session=True)
        os.close(slave)
        output = bytearray()
        challenge = ('APPROVE-SYNTHETIC-FINAL:' + mode + ':').encode()
        deadline = time.monotonic() + 30
        sent = False
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.25)
            if ready:
                try: piece = os.read(master, 4096)
                except OSError as error:
                    if error.errno == errno.EIO: break
                    raise
                if not piece: break
                output.extend(piece)
                if len(output) > 65536: raise RuntimeError('PTY output cap')
                if not sent and challenge in output:
                    line = next(line for line in output.splitlines() if challenge in line)
                    exact = line[line.index(challenge):].strip()
                    if len(exact) > 256: raise RuntimeError('challenge too long')
                    os.write(master, exact + b'\n')
                    sent = True
            if proc.poll() is not None and not ready: break
        os.close(master)
        if not sent: raise RuntimeError('real PTY challenge absent: ' + repr(output[-1000:]))
        try: code = proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill(); raise
        if code: raise RuntimeError(mode + ' failed: ' + repr(output[-3000:]))
        captured = bytes(output)
    else:
        done = subprocess.run(args(), env=env, preexec_fn=demote(uid),
                              capture_output=True, timeout=30)
        if done.returncode: raise RuntimeError(mode + ' failed: ' + repr(done.stdout[-2000:] + done.stderr[-2000:]))
        if len(done.stdout) + len(done.stderr) > 65536: raise RuntimeError('output cap')
        captured = done.stdout + done.stderr
    if b'1 passed; 0 failed' not in captured or ('final_uid_mode=' + mode + ':passed').encode() not in captured:
        raise RuntimeError(mode + ' did not run exactly one successful test: ' + repr(captured[-3000:]))
    print('phase_primitive=' + mode + ':passed', flush=True)
run('provision-leg')
run('approve-leg', terminal=True)
run('approve-claim', terminal=True)
os.mkdir('/work/open', 0o711)
leg_record, = glob.glob(root + '/approvals/*.positive-fee-split.final-leg')
for source, name in [(root + '/keys/historical.seed', 'key'), (leg_record, 'approval')]:
    destination = '/work/open/' + name
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o600)
run('operator-permissions', uid=12002)
run('refuse-changed-leg')
run('refuse-changed-claim')
run('sign-leg')
run('sign-claim')
run('recover-key')
run('recover-leg')
run('recover-claim')
run('revoke-leg')
run('refuse-revoked-leg')
run('refuse-revoked-claim')
print('final_transfer_uid_pty_primitive=passed; successor_and_live_host=unverified', flush=True)
'''

def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    binary = Path(sys.argv[1]).resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit("expected executable CLI library test")
    image = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE],
                           capture_output=True, text=True, timeout=15, check=True)
    if image.stdout.strip() != IMAGE_ID:
        raise SystemExit("pinned local image mismatch")
    lines = subprocess.run(["ldd", str(binary)], capture_output=True, text=True,
                           timeout=10, check=True).stdout.splitlines()
    paths = []
    for line in lines:
        match = re.search(r"=>\s*(/\S+)\s+\(0x", line) or re.match(r"\s*(/\S+)\s+\(0x", line)
        if match:
            path = Path(match.group(1))
            path.resolve(strict=True)
            paths.append(path)
    loaders = [path for path in paths if path.name.startswith("ld-linux")]
    if len(loaders) != 1:
        raise SystemExit("unique host loader missing")
    libraries = [path for path in paths if path not in loaders]
    if len({path.name for path in libraries}) != len(libraries):
        raise SystemExit("duplicate library basename")
    source = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], capture_output=True,
                            text=True, timeout=10, check=True).stdout.strip()
    status = subprocess.run(["git", "status", "--porcelain"], capture_output=True,
                            text=True, timeout=10, check=True).stdout
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    print(f"head_tree={source} working_tree={'dirty' if status else 'clean'} "
          f"test_binary_sha256={digest} runtime_image={IMAGE_ID}", flush=True)
    cmd = ["docker", "create", "--pull=never", "--network=none",
           "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE",
           "--cap-add=SETUID", "--cap-add=SETGID", "--security-opt=no-new-privileges",
           "--user=0:0", "--memory=512m", "--memory-swap=512m", "--cpus=1",
           "--pids-limit=64", "--tmpfs=/work:rw,nosuid,nodev,size=16m,mode=0711",
           "--entrypoint=/usr/local/bin/python3", IMAGE,
           "-I", "-B", "-c", CONTROLLER, "/tmp/ld.so", "/tmp/harness", TEST]
    container = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=True).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{64}", container):
        raise SystemExit("unexpected container ID")
    try:
        for source_path, destination in [(binary, "harness"), (loaders[0], "ld.so"),
                                         *((path, path.name) for path in libraries)]:
            subprocess.run(["docker", "cp", str(source_path.resolve(strict=True)), f"{container}:/tmp/{destination}"],
                           timeout=90, check=True)
        result = subprocess.run(["docker", "start", "-a", container], timeout=240)
        if result.returncode:
            raise SystemExit(result.returncode)
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=30, check=True)

if __name__ == "__main__":
    main()
