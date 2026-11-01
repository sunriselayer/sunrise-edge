#!/usr/bin/env -S /usr/bin/python3.14 -I -B
"""Cargo input view for the repository's unchanged owning check recipes."""
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import tomllib
import urllib.parse

ROOT = pathlib.Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-m2-m3-followup-1021')
BASE = pathlib.Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013')
CONFIG = pathlib.Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-signing-env-1101-wrapper-core.json')
CONFIG_SHA256 = 'f2cc3560b382411513040f447c08330268b88ac50bf6bdf860207cdd644c5f8e'

def load_config():
    # Every final-source/directory pin is checked before output, source reads,
    # target/cache observation or subprocess admission. No helper import/run.
    if hashlib.sha256(CONFIG.read_bytes()).hexdigest() != CONFIG_SHA256:
        raise RuntimeError('fixed integration configuration differs')
    value = json.loads(CONFIG.read_text())
    if (value.get('schema') != 1 or value.get('sourceRoot') != str(ROOT) or
            re.fullmatch(r'[0-9a-f]{40}', value.get('sourceHead', '')) is None or
            re.fullmatch(r'[0-9a-f]{40}', value.get('sourceTree', '')) is None or
            re.fullmatch(r'[0-9a-f]{64}', value.get('sourceIndexSha256', '')) is None or
            re.fullmatch(r'[0-9a-f]{64}', value.get('runtimeInputsSha256', '')) is None or
            not isinstance(value.get('trackedFileCount'), int) or value['trackedFileCount'] <= 0):
        raise RuntimeError('INERT: final source HEAD/tree/index/count/runtime inputs PENDING')
    expected_paths = {
        'target': ROOT / 'target', 'temporary': ROOT / 'target/recipe-tmp',
        'cacheRoot': BASE / 'm2-m3-followup-1021-cache',
    }
    expected_paths.update({key: expected_paths['cacheRoot'] / suffix for key, suffix in
        [('cargoHome', 'cargo-home'), ('npmCache', 'npm-cache'),
         ('denoCache', 'deno-cache'), ('xdgCache', 'xdg-cache')]})
    if set(value.get('directories', {})) != set(expected_paths):
        raise RuntimeError('INERT: complete private directory pins PENDING')
    for key, path in expected_paths.items():
        row = value['directories'][key]
        pin = row.get('pin')
        if (row.get('path') != str(path) or not isinstance(pin, list) or len(pin) != 4 or
                not all(isinstance(n, int) for n in pin) or pin[2] != os.geteuid() or pin[3] != 0o700):
            raise RuntimeError('INERT: private directory identity PENDING: ' + key)
    for key in ('sourceIndexPath', 'runtimeInputsPath'):
        path = pathlib.Path(value[key])
        if path.parent != BASE or not path.is_absolute():
            raise RuntimeError('fixed input index path escaped task evidence root')
    return value

def checked_directory(settings, key):
    row = settings['directories'][key]
    path = pathlib.Path(row['path'])
    metadata = path.lstat()
    actual = [metadata.st_dev, metadata.st_ino, metadata.st_uid, stat.S_IMODE(metadata.st_mode)]
    if not stat.S_ISDIR(metadata.st_mode) or actual != row['pin'] or path.resolve() != path:
        raise RuntimeError('private directory identity differs: ' + key)
    return path

settings = load_config()
root = ROOT
for key in settings['directories']:
    checked_directory(settings, key)
allowed = [ROOT]
cwd = pathlib.Path.cwd().resolve()
roots = [p for p in allowed if cwd == p or p in cwd.parents]
if len(roots) != 1:
    raise SystemExit('Cargo recipe cwd is outside this task')
root = roots[0]
home = pathlib.Path(settings['directories']['cargoHome']['path'])
cache = home / 'registry/cache/index.crates.io-1949cf8c6b5b557f'
tool = pathlib.Path('/home/yu/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin')
target = pathlib.Path(settings['directories']['target']['path'])
target.mkdir(mode=0o700, exist_ok=True)
argv = ['/usr/bin/bwrap', '--ro-bind', '/', '/',
        '--tmpfs', '/home/yu/.cargo', '--bind', str(home), str(home),
        '--bind', str(target), str(target), '--tmpfs', '/tmp', '--dev', '/dev',
        '--proc', '/proc', '--die-with-parent', '--tmpfs', str(cache)]
locked = tomllib.loads((root / 'Cargo.lock').read_text())['package']
if sum(bool(p.get('source')) for p in locked) != 311:
    raise SystemExit('exact311 locked registry archives required')
for p in locked:
    if not p.get('source'):
        continue
    if p['source'] != 'registry+https://github.com/rust-lang/crates.io-index':
        raise SystemExit('unrecognized locked source')
    name = p['name'] + '-' + p['version'] + '.crate'
    source = cache / name
    if source.resolve() != source or not source.is_file():
        raise SystemExit('locked private archive absent or alias; no fallback')
    data = source.read_bytes()
    if len(data) > 16 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != p['checksum']:
        raise SystemExit('locked archive input differs')
    argv += ['--ro-bind', str(source), str(cache / name)]
environment = {'PATH': str(pathlib.Path(__file__).resolve().parent) + ':' + str(BASE / 'bin-m2-m3-stable-full-required-1022') + ':' + str(tool) + ':/home/linuxbrew/.linuxbrew/bin:/home/yu/.local/bin:/usr/local/bin:/usr/bin:/bin',
               'CARGO_HOME': str(home), 'RUSTC': str(tool / 'rustc'),
               'RUSTDOC': str(tool / 'rustdoc'), 'CARGO_TARGET_DIR': str(target),
               'CARGO_INCREMENTAL': '0', 'CARGO_NET_OFFLINE': 'true', 'CARGO_BUILD_JOBS': '1'}
# Fixed compilation profile matching the single hosted recurring lane.
# All original workload/checks remain; no caller-controlled flags are forwarded.
environment.update({
    'CARGO_PROFILE_DEV_OPT_LEVEL': '2',
    'CARGO_PROFILE_TEST_OPT_LEVEL': '2',
    'CARGO_PROFILE_DEV_DEBUG_ASSERTIONS': 'true',
    'CARGO_PROFILE_TEST_DEBUG_ASSERTIONS': 'true',
    'CARGO_PROFILE_DEV_OVERFLOW_CHECKS': 'true',
    'CARGO_PROFILE_TEST_OVERFLOW_CHECKS': 'true',
    'CARGO_PROFILE_DEV_DEBUG': '0',
    'CARGO_PROFILE_TEST_DEBUG': '0',
})
for name, value in os.environ.items():
    if name.startswith('SUNRISE_EDGE_TEST_POSTGRES_'):
        if name.endswith('_URL') and urllib.parse.urlsplit(value).hostname != '127.0.0.1':
            raise SystemExit('non-loopback PG fixture refused')
        environment[name] = value
    elif name in ('SUNRISE_EDGE_ESCROW_FIXTURE_DIR', 'SUNRISE_EDGE_SOAK_DIR'):
        fixture = pathlib.Path(value)
        parent = pathlib.Path(settings['directories']['temporary']['path'])
        prefixes = ('sunrise-escrow-operator.', 'sunrise-escrow-operator-pg.', 'sunrise-edge-soak-pg.')
        if (not fixture.is_absolute() or fixture.parent != parent or
                not fixture.name.startswith(prefixes) or fixture.resolve() != fixture):
            raise SystemExit('fixture path outside task-owned temporary output')
        metadata = fixture.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 or
                metadata.st_uid != os.geteuid()):
            raise SystemExit('fixture output ownership differs')
        environment[name] = value
    elif name in ('SUNRISE_EDGE_SOAK_ESCROWS', 'SUNRISE_EDGE_SOAK_SENDERS',
                  'SUNRISE_EDGE_SOAK_CLAIM_WRITERS', 'SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC',
                  'SUNRISE_EDGE_SOAK_DURATION_SECONDS', 'SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS',
                  'SUNRISE_EDGE_SOAK_RECOVERY_CYCLES', 'SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE'):
        if not re.fullmatch(r'(0|[1-9][0-9]{0,9})', value):
            raise SystemExit('noncanonical fixture bound')
        environment[name] = value
if 'RUST_TEST_THREADS' in os.environ:
    if os.environ['RUST_TEST_THREADS'] != '1':
        raise SystemExit('shared PG fault fixture must remain serialized')
    environment['RUST_TEST_THREADS'] = '1'
argv += [str(tool / 'cargo')] + sys.argv[1:]
# Fixture credentials remain in the process environment, never argv or output.
os.umask(0o022)  # compiler creates normal0755 ELFs; no later chmod
os.execve(argv[0], argv, environment)
