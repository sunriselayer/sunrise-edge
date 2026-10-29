#!/usr/bin/python3
"""Fetch one pinned public runtime into a new task-local directory only."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
import zipfile

URL = "https://github.com/denoland/deno/releases/download/v2.9.4/deno-x86_64-unknown-linux-gnu.zip"
ZIP_SHA256 = "c24f955d9fbfe0ea5ae2b501c8e71ae76e31e4c9782390a54a284b3364fda725"
NETWORK_LIMIT = 48 * 1024**2
BINARY_LIMIT = 256 * 1024**2
MIN_FREE = 5 * 1024**3
SECONDS = 300


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    require(len(sys.argv) == 2, "usage: prepare-deno.py NEW_TASK_DIRECTORY")
    root = Path(sys.argv[1])
    require(root.is_absolute() and root.parent.resolve() == root.parent,
            "absolute nonaliased task directory required")
    require(not root.exists() and shutil.disk_usage(root.parent).free >= MIN_FREE,
            "new directory and at least 5 GiB free required")
    os.umask(0o077)
    root.mkdir(mode=0o700)
    start = time.monotonic()
    receipt = {"url": URL, "zipSha256Expected": ZIP_SHA256,
               "networkLimitBytes": NETWORK_LIMIT, "binaryLimitBytes": BINARY_LIMIT,
               "timeLimitSeconds": SECONDS, "globalEnvironmentChanged": False,
               "state": "started"}
    try:
        archive = root / "deno.zip"
        digest = hashlib.sha256()
        count = 0
        with urllib.request.urlopen(URL, timeout=15) as response, archive.open("xb") as output:
            length = response.headers.get("Content-Length")
            require(length is None or int(length) <= NETWORK_LIMIT, "network size limit")
            while True:
                require(time.monotonic() - start < SECONDS, "download deadline")
                require(shutil.disk_usage(root).free >= MIN_FREE, "free-space reserve")
                chunk = response.read(min(256 * 1024, NETWORK_LIMIT - count + 1))
                if not chunk:
                    break
                count += len(chunk)
                require(count <= NETWORK_LIMIT, "network byte limit")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        require(digest.hexdigest() == ZIP_SHA256, "official archive digest mismatch")
        binary = root / "deno"
        with zipfile.ZipFile(archive) as source:
            require(source.namelist() == ["deno"], "one exact binary required")
            entry = source.getinfo("deno")
            require(0 < entry.file_size <= BINARY_LIMIT and
                    not stat.S_ISLNK(entry.external_attr >> 16), "binary entry bound/type")
            with source.open(entry) as input_stream, binary.open("xb") as output:
                written = 0
                while chunk := input_stream.read(256 * 1024):
                    require(time.monotonic() - start < SECONDS, "extraction deadline")
                    require(shutil.disk_usage(root).free >= MIN_FREE, "free-space reserve")
                    written += len(chunk)
                    require(written <= entry.file_size <= BINARY_LIMIT, "binary size limit")
                    output.write(chunk)
                require(written == entry.file_size, "complete binary required")
                output.flush()
                os.fsync(output.fileno())
        binary.chmod(0o555)
        version = subprocess.run([str(binary), "--version"], text=True,
                                 capture_output=True, timeout=15, check=True)
        require(version.stdout.splitlines()[0].startswith("deno 2.9.4 "),
                "exact Deno version required")
        receipt.update({"state": "completed", "networkBytes": count,
                        "zipSha256Actual": digest.hexdigest(),
                        "binaryBytes": binary.stat().st_size,
                        "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                        "version": version.stdout, "seconds": time.monotonic() - start})
    except BaseException as error:
        receipt.update({"state": "failed", "error": repr(error),
                        "seconds": time.monotonic() - start})
        raise
    finally:
        with (root / "prepare-receipt.json").open("x") as output:
            json.dump(receipt, output, indent=2, sort_keys=True)
            output.write("\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
