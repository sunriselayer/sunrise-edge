#!/usr/bin/env python3
"""Test-only real-PTY confirmation driver for a disposable local Call."""
import errno
import os
import pty
import select
import subprocess
import sys
import time


def main():
    reject = len(sys.argv) > 1 and sys.argv[1] == "--reject"
    command = sys.argv[2:] if reject else sys.argv[1:]
    if not command:
        raise SystemExit("expected CLI and complete custody approval arguments")
    master, slave = pty.openpty()
    process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                               start_new_session=True)
    os.close(slave)
    output = bytearray()
    challenge = b"APPROVE-LOCAL-CALL sender="
    answered = False
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    piece = os.read(master, 4096)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not piece:
                    break
                output.extend(piece)
                if len(output) > 256 * 1024:
                    raise RuntimeError("bounded PTY output exceeded")
                if not answered:
                    lines = output.splitlines(keepends=True)
                    for line in lines:
                        if challenge in line and line.endswith(b"\n"):
                            exact = line[line.index(challenge):].strip()
                            if len(exact) > 1024:
                                raise RuntimeError("confirmation too long")
                            os.write(master, b"WRONG\n" if reject else exact + b"\n")
                            answered = True
                            break
            if process.poll() is not None and not ready:
                break
        if not answered:
            raise RuntimeError("approval confirmation was not displayed: " + repr(output[-3000:]))
        code = process.wait(timeout=3)
        if reject:
            if code == 0 or b"confirmation" not in output or b"approved_local_call=true" in output:
                raise RuntimeError("wrong confirmation was accepted: " + repr(output[-3000:]))
            print("local_call_real_pty_refusal=passed", flush=True)
        else:
            if code != 0 or b"approved_local_call=true" not in output:
                raise RuntimeError("approval failed: " + repr(output[-3000:]))
            print("local_call_real_pty_approval=passed", flush=True)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        os.close(master)


if __name__ == "__main__":
    main()
