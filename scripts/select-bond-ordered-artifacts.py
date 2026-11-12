#!/usr/bin/env python3
"""Select the exact protected bond test, CLI and real source binaries.

The required/full Rust gate supplies complete --message-format=json records
from its own build/no-run commands. No target-directory glob or test ordering
chooses executable code.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def select(path: Path, source: Path, name: str, kind: str, target: Path) -> Path:
    matches: list[Path] = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            event = json.loads(line)
            if event.get("reason") != "compiler-artifact":
                continue
            artifact = event.get("target", {})
            if (
                artifact.get("name") != name
                or artifact.get("kind") != [kind]
                or Path(artifact.get("src_path", "")).resolve() != source
            ):
                continue
            value = event.get("executable")
            if not isinstance(value, str):
                raise ValueError(f"{name} has no executable")
            executable = Path(value)
            if not executable.is_absolute() or executable.resolve() != executable:
                raise ValueError(f"{name} executable is not a canonical absolute path")
            info = executable.lstat()
            if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
                raise ValueError(f"{name} executable is not a regular executable")
            if not executable.is_relative_to(target):
                raise ValueError(f"{name} executable escaped the selected Cargo target")
            matches.append(executable)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {name} executable, found {len(matches)}")
    return matches[0]


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> None:
    if len(sys.argv) != 4:
        raise ValueError("expected CLI build, operator build and no-run JSON paths")
    root = Path(__file__).resolve().parent.parent
    target_value = os.environ.get("CARGO_TARGET_DIR")
    target = Path(target_value).resolve() if target_value else root / "target"
    if not target.is_dir():
        raise ValueError("Cargo target directory is absent")
    cli = select(
        Path(sys.argv[1]),
        root / "apps/cli/src/main.rs",
        "sunrise-edge-cli",
        "bin",
        target,
    )
    genesis = select(
        Path(sys.argv[2]),
        root / "apps/operator/src/bin/sqlite_genesis.rs",
        "sqlite_genesis",
        "bin",
        target,
    )
    host = select(
        Path(sys.argv[2]),
        root / "apps/operator/src/bin/sqlite_source_host.rs",
        "sqlite_source_host",
        "bin",
        target,
    )
    harness = select(
        Path(sys.argv[3]),
        root / "apps/cli/tests/bond_registration.rs",
        "bond_registration",
        "test",
        target,
    )
    for value in (str(cli), str(harness), str(genesis), str(host)):
        if any(character in value for character in ("\n", "\r", "\0", "=")):
            raise ValueError("artifact path cannot be exported safely")
    print(f"SUNRISE_BOND_ORDERED_CLI={cli}")
    print(f"SUNRISE_BOND_ORDERED_CLI_SHA256={sha256(cli)}")
    print(f"SUNRISE_BOND_ORDERED_HARNESS={harness}")
    print(f"SUNRISE_BOND_ORDERED_HARNESS_SHA256={sha256(harness)}")
    print(f"SUNRISE_BOND_REAL_SQLITE_GENESIS={genesis}")
    print(f"SUNRISE_BOND_REAL_SQLITE_GENESIS_SHA256={sha256(genesis)}")
    print(f"SUNRISE_BOND_REAL_SQLITE_SOURCE_HOST={host}")
    print(f"SUNRISE_BOND_REAL_SQLITE_SOURCE_HOST_SHA256={sha256(host)}")


if __name__ == "__main__":
    main()
