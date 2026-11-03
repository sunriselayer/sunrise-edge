#!/usr/bin/python3.14 -I -B
"""Read-only post-terminal qualification. Never launches validation or signals a unit.

Run only after the required owner and its observer have naturally terminated.
Raw logs are read as bytes and never rewritten or emitted to the terminal.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import traceback

BASE = Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013')
SOURCE = Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-m2-m3-followup-1021')
PREFIX = 'm2-signing-env-1101-'
HEAD = '2e2c10fe0c360f99400be79ee50cad18f5e2336f'
TREE = 'd392a0da9c8805a8bcc8bf84acd674eb3a42f54e'
PINS = {
    'bundle-v2.json': '3dc6f0dd51402ca8f34a497046fbf1bbc88570a91d7d02af70017d1e12711788',
    'launch.json': '96d96de5c6df5529bf529256379cd0cf6846e5f50935e63fe3937f5166181fc7',
    'driver-v2.py': 'd7f89448899d5544fd0c3240d72be18f9fe066da4d4f95b24e1e439ba98b4c54',
    'ci-root-verified.json': '41cf175c2bcd5233a0af0a1591d31d9ddea63fe05f042524c23d6deae226d73e',
}
START = time.monotonic()
READS = {}
PROGRESS = []


def require(ok, message):
    if not ok:
        raise RuntimeError(message)
    if time.monotonic() - START > 600:
        raise RuntimeError('finite 600-second qualification deadline exceeded')


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def metadata(s, kind=False):
    value = dict(device=s.st_dev, inode=s.st_ino, uid=s.st_uid, gid=s.st_gid,
                 mode=stat.S_IMODE(s.st_mode), nlink=s.st_nlink, length=s.st_size,
                 mtimeNs=s.st_mtime_ns, ctimeNs=s.st_ctime_ns)
    if kind:
        value['type'] = ('symlink' if stat.S_ISLNK(s.st_mode) else
                         'file' if stat.S_ISREG(s.st_mode) else
                         'directory' if stat.S_ISDIR(s.st_mode) else 'unsupported')
    return value


def read(path, cap=256 * 1024**2):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= cap,
            'bounded regular file required: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(metadata(os.fstat(fd)) == metadata(before), 'opened identity changed: ' + str(path))
        data = bytearray()
        while True:
            require(len(data) <= cap, 'read byte cap: ' + str(path))
            block = os.read(fd, min(1024**2, cap + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        require(metadata(os.fstat(fd)) == metadata(before), 'file changed during read: ' + str(path))
    finally:
        os.close(fd)
    require(metadata(path.lstat()) == metadata(before) and len(data) == before.st_size,
            'read length or final identity changed: ' + str(path))
    raw = bytes(data)
    READS[str(path)] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    return raw


def load(path, expected=None, length=None):
    raw = read(path)
    require(expected is None or hashlib.sha256(raw).hexdigest() == expected,
            'pinned hash differs: ' + str(path))
    require(length is None or len(raw) == length, 'pinned length differs: ' + str(path))
    return json.loads(raw)


def pinned(name):
    path = BASE / (PREFIX + name)
    raw = read(path)
    require(hashlib.sha256(raw).hexdigest() == PINS[name], 'immutable schema input changed: ' + name)
    return raw


def tool_identity(path):
    path = Path(path)
    entry = path.lstat()
    resolved = path.resolve(strict=True)
    link = os.readlink(path) if stat.S_ISLNK(entry.st_mode) else None
    before = resolved.lstat()
    raw = read(resolved)
    value = {'configured': metadata(entry, True), 'linkTarget': link,
             'resolvedPath': str(resolved),
             'resolved': dict(metadata(before), sha256=hashlib.sha256(raw).hexdigest())}
    require(metadata(path.lstat(), True) == value['configured'] and
            path.resolve(strict=True) == resolved and
            (link is None or os.readlink(path) == link), 'tool entry changed while reading: ' + str(path))
    return value


def command(argv):
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_PAGER='cat', LC_ALL='C', NO_COLOR='1')
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, env=env)
    require(result.returncode == 0, 'read-only command failed: ' + repr(argv) + ': ' + repr(result.stderr[:1000]))
    require(len(result.stdout) <= 8 * 1024**2, 'read-only command output cap')
    return result.stdout


def unit_state(unit):
    names = ['MainPID', 'ExecMainPID', 'ActiveState', 'SubState', 'Result',
             'ExecMainStatus', 'ExecMainCode', 'InvocationID', 'ControlGroup', 'NRestarts']
    raw = command(['/usr/bin/systemctl', '--user', 'show', unit] +
                  ['--property=' + name for name in names])
    return dict(line.split('=', 1) for line in raw.decode().splitlines())


def terminal(state, launch):
    initial = dict(line.split('=', 1) for line in launch['unitShow']['stdout'].splitlines())
    require(state['MainPID'] == '0' and state['Result'] == 'success' and
            state['ExecMainStatus'] == '0' and state['ExecMainCode'] == '1' and
            state['NRestarts'] == '0' and state['SubState'] == 'exited',
            'natural successful terminal systemd owner required; no active-run reads allowed')
    require(state['InvocationID'] == initial['InvocationID'] and
            state['ExecMainPID'] == str(launch['ownerPid']), 'systemd owner identity differs')
    saved_group = Path('/sys/fs/cgroup') / initial['ControlGroup'].lstrip('/')
    require(state['ControlGroup'] == initial['ControlGroup'] or
            (state['ControlGroup'] == '' and not saved_group.exists()),
            'current group differs without physical saved-group release')


def process_start(pid):
    try:
        raw = Path('/proc') .joinpath(str(pid), 'stat').read_text()
    except FileNotFoundError:
        return None
    return raw.rsplit(')', 1)[1].split()[19]


def released(pid, ticks):
    now = process_start(pid)
    require(now is None or now != str(ticks), 'sampled process identity still exists: ' + str(pid))
    return {'pid': pid, 'admittedStartTicks': str(ticks), 'currentStartTicks': now,
            'released': True, 'pidReused': now is not None}


def empty_cgroup(relative):
    require(relative.startswith('/') and '..' not in Path(relative).parts, 'invalid cgroup path')
    root = Path('/sys/fs/cgroup') / relative.lstrip('/')
    exists = root.exists()
    tasks = set()
    directories = 0
    if exists:
        for directory, children, _files in os.walk(root, followlinks=False):
            directories += 1
            require(directories <= 512 and len(children) <= 512, 'cgroup enumeration cap')
            for name in ['cgroup.procs', 'cgroup.threads']:
                try:
                    tasks.update((Path(directory) / name).read_text().split())
                except FileNotFoundError:
                    pass
    require(not tasks, 'owned cgroup tasks remain')
    return {'path': str(root), 'exists': exists, 'tasks': [], 'directories': directories,
            'emptyExistingCgroupPermittedUntilRootStop': True, 'signaledOrStopped': False}


def cf_layout(root):
    result = {}
    pending = [Path(root)]
    while pending:
        path = pending.pop()
        require(len(result) < 8192, 'CF inventory bound')
        value = metadata(path.lstat(), True)
        require(value['type'] != 'unsupported', 'unsupported CF inventory entry')
        if value['type'] == 'symlink':
            target = os.readlink(path)
            require(not Path(target).is_absolute(), 'CF link must remain relative')
            resolved = path.resolve(strict=True)
            require(resolved.is_relative_to(root), 'CF relative link escapes private closure')
            value.update(linkTarget=target, resolvedPath=str(resolved))
        elif value['type'] == 'directory':
            pending.extend(Path(entry.path) for entry in os.scandir(path))
        result[str(path)] = value
    return result


def verify_source(admitted):
    def git(args):
        return command(['/usr/bin/git', '-C', str(SOURCE)] + args)
    require(SOURCE.resolve(strict=True) == SOURCE, 'source root route changed')
    require(git(['rev-parse', 'HEAD']).decode().strip() == HEAD and
            git(['rev-parse', 'HEAD^{tree}']).decode().strip() == TREE, 'live source head/tree differs')
    require(git(['status', '--porcelain=v1', '--untracked-files=normal']) == b'', 'live source is not clean')
    files = {}
    total = 0
    for item in git(['ls-files', '--stage', '-z']).split(b'\0'):
        if not item:
            continue
        header, relative = item.split(b'\t', 1)
        mode, blob, stage = header.decode().split()
        name = os.fsdecode(relative)
        require(stage == '0' and name not in files and not Path(name).is_absolute() and
                '..' not in Path(name).parts and len(files) < 8192, 'live index stage/path bound')
        path = SOURCE / name
        s = path.lstat()
        if mode == '120000':
            require(stat.S_ISLNK(s.st_mode), 'tracked link changed')
            body = os.fsencode(os.readlink(path))
        else:
            require(mode in ['100644', '100755'] and stat.S_ISREG(s.st_mode), 'tracked file mode changed')
            body = read(path)
        total += len(body)
        require(total <= 1024**3, 'tracked source total cap')
        files[name] = {'mode': mode, 'gitBlob': blob, 'sha256': hashlib.sha256(body).hexdigest(),
                       'size': len(body), 'metadata': [s.st_dev, s.st_ino, stat.S_IMODE(s.st_mode),
                       s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]}
    current = dict(head=HEAD, tree=TREE, clean=True, trackedFileCount=len(files), files=files)
    require(current == admitted, 'live complete source index differs')
    return {'head': HEAD, 'tree': TREE, 'trackedFilesRehashed': len(files), 'bytes': total}


def main(args):
    bundle = json.loads(pinned('bundle-v2.json'))
    launch = json.loads(pinned('launch.json'))
    pinned('driver-v2.py')
    ci = json.loads(pinned('ci-root-verified.json'))
    unit = 'm2-signing-env-1101-required-v1.service'
    state = unit_state(unit)
    terminal(state, launch)  # Must precede every active-run/result/source/cache/tool read.
    PROGRESS.append('natural terminal owner verified before dynamic reads')
    owner = released(launch['ownerPid'], launch['ownerStartTicks'])
    cgroup = empty_cgroup(dict(line.split('=', 1) for line in launch['unitShow']['stdout'].splitlines())['ControlGroup'])
    watch = load(args.watch)
    require(watch['productSuccessNotInferred'] is True, 'observer must remain diagnostic')
    require(process_start(watch['observerPid']) is None, 'observer PID still exists')
    identities = watch.get('knownIdentities', [])
    require(isinstance(identities, list), 'sampled identity inventory must be a list')
    sampled = [released(int(row['pid']), row['startTicks']) for row in identities]
    run = BASE / (PREFIX + 'run-v1')
    result = load(run / 'result.json')
    require(result['accepted'] is True and result['error'] is None and
            'finalizationError' not in result and result['processCleanupComplete'] is True and
            result['remainingOwnedPids'] == [] and result['unit'] == unit and
            result['expectedHead'] == HEAD and result['sourceRoot'] == str(SOURCE), 'driver result not accepted')
    rows = result['commands']
    labels = ['source-before-head', 'source-before-tree', 'source-before-clean', 'source-before-index',
              'npm-ci', 'required', 'source-after-head', 'source-after-tree', 'source-after-clean', 'source-after-index']
    require([row['label'] for row in rows] == labels, 'exact ten command order differs')
    require(rows[4]['argv'] == ['npm', 'ci', '--prefix', 'adapters/cloudflare-workers'] and
            rows[5]['argv'] == ['./scripts/check-all.sh'], 'two literal required commands differ')
    log_total = 0
    receipts = []
    required_raw = []
    last_end = None
    for number, row in enumerate(rows):
        require(row['exitCode'] == 0 and row['waitReapCompleted'] is True and row['fullCapture'] is True and
                row['signals'] == [] and 'error' not in row and 'cleanupError' not in row and
                row['cwd'] == str(SOURCE), 'command actual exit/wait/full capture differs: ' + row['label'])
        began = datetime.datetime.fromisoformat(row['startedUtc'])
        ended = datetime.datetime.fromisoformat(row['endedUtc'])
        require(began <= ended and (last_end is None or last_end <= began), 'commands overlap or time order differs')
        last_end = ended
        require(process_start(row['pid']) is None, 'known command PID remains: ' + str(row['pid']))
        prefix = str(number).zfill(2) + '-' + row['label']
        require(load(run / (prefix + '.json')) == row, 'standalone command receipt differs')
        for stream in ['stdout', 'stderr']:
            r = row[stream]
            path = run / (prefix + '.' + stream + '.log')
            require(r['path'] == str(path) and r['eof'] is True and
                    r['capturedBytes'] == r['observedBytes'], 'stream path/EOF/full length differs')
            raw = read(path, 64 * 1024**2)
            require(len(raw) == r['capturedBytes'] and hashlib.sha256(raw).hexdigest() == r['sha256'],
                    'raw stream length/hash differs')
            log_total += len(raw)
            require(log_total <= 256 * 1024**2, 'combined raw stream cap')
            if row['label'] == 'required':
                required_raw.append(raw)
        receipts.append({'label': row['label'], 'pid': row['pid'], 'actualExit': 0,
                         'waitReapCompleted': True, 'bothEOFs': True, 'rawHashesVerified': True})
    require(log_total == result['capturedOutputBytes'], 'total captured output byte count differs')
    artifacts = bundle['artifacts']
    docs = {}
    for name, pin in artifacts.items():
        raw = read(pin['path'])
        require(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'],
                'bundle artifact changed: ' + name)
        if not name.startswith('wrapper-') and name != 'driver':
            docs[name] = json.loads(raw)
    require(bundle['sourceHead'] == HEAD and bundle['sourceTree'] == TREE, 'bundle source identity differs')
    admitted = docs['sourceIndex']
    require(admitted['head'] == HEAD and admitted['tree'] == TREE and admitted['clean'] is True and
            admitted['trackedFileCount'] == 1246 and len(admitted['files']) == 1246, 'admitted source count differs')
    for label in ['source-before', 'source-after']:
        pin = result[label]
        require(pin['path'] == str(run / (label + '.json')), 'source snapshot path differs')
        require(load(pin['path'], pin['sha256'], pin['bytes']) == admitted, 'source snapshot differs from admitted index')
    source = verify_source(admitted)
    require(result['inputsBefore'] == result['inputsAfter'] and
            result['wrappersBefore'] == result['wrappersAfter'], 'before/after inputs or wrappers differ')
    computed = {}
    for name in ['transition', 'cfManifest', 'runtimeInputs', 'sourceIndex', 'core', 'admission']:
        pin = artifacts[name]
        computed[pin['path']] = {'sha256': pin['sha256'], 'size': pin['bytes']}
    core = docs['core']
    require(len(core['directories']) == 7, 'directory pin count differs')
    for name, row in core['directories'].items():
        path = Path(row['path']); s = path.lstat()
        value = [s.st_dev, s.st_ino, s.st_uid, stat.S_IMODE(s.st_mode)]
        require(stat.S_ISDIR(s.st_mode) and path.resolve(strict=True) == path and value == row['pin'],
                'post-run directory pin changed: ' + name)
        computed['directory:' + name] = value
    tools = docs['runtimeInputs']['tools']
    require(len(tools) == 17 and len({row['name'] for row in tools}) == 17, 'runtime role count differs')
    for row in tools:
        value = tool_identity(row['path'])
        require(value == row['admittedIdentity'] and value['resolvedPath'] == row['resolvedPath'] and
                value['resolved']['sha256'] == row['sha256'], 'runtime full identity differs: ' + row['name'])
        computed['tool:' + row['name']] = value
    require(computed == result['inputsBefore'] == result['inputsAfter'], 'current complete inputs differ from run inputs')
    wrappers = {}
    for name in ['cargo', 'cf', 'node', 'npm', 'npx', 'python3']:
        pin = artifacts['wrapper-' + name]
        wrappers[name] = {'sha256': pin['sha256'], 'size': pin['bytes']}
    require(wrappers == result['wrappersBefore'] == result['wrappersAfter'], 'current wrappers differ from run')
    cf = docs['cfManifest']
    require(len(cf['layout']) == 2725 and len(cf['tools']) == 2347 and
            cf['counts'] == {'actualGlobalRuntimeRoles': 9, 'directories': 349, 'layout': 2725,
                            'privateConfiguredFileRoles': 2338, 'privateRegularFiles': 2335,
                            'relativeLinks': 41, 'tools': 2347}, 'full CF closure counts differ')
    root = Path(cf['privateRoot'])
    require(cf_layout(root) == cf['layout'], 'post-run exact CF inventory/metadata/links differ')
    private_files = {path for path, row in cf['layout'].items() if row['type'] == 'file'}
    require(len(private_files) == 2335 and private_files.issubset(cf['tools']), 'private regular bodies lack role coverage')
    for path, row in cf['tools'].items():
        require(tool_identity(path) == row, 'post-run CF full role identity differs: ' + path)
    require(cf_layout(root) == cf['layout'], 'CF exact inventory changed while hashing bodies')
    # Decode only a temporary parsing view; the exact raw byte files stay untouched.
    plain = re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]', b'', b'\n'.join(required_raw)).decode('utf-8', errors='replace')
    rust = [tuple(map(int, row)) for row in re.findall(
        r'test result: [^\n]*? (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out', plain)]
    totals = [sum(row[i] for row in rust) for i in range(3)]
    cf_suites = [int(value) for value in re.findall(r'\bTests\s+(\d+)\s+passed', plain)]
    require(len(rust) == 147 and totals == [4427, 0, 43], 'Rust invocation summary count/totals differ')
    require(cf_suites == [13, 28, 10, 15], 'Cloudflare suite totals differ')
    require(ci['head'] == HEAD and ci['run'] == 41163320441 and ci['jobs'] == 8 and
            ci['rustResultSummaries'] == 147 and ci['rustInvocationTotals'] == totals and
            ci['cloudflareSuites'] == cf_suites, 'independent pinned CI correspondence differs')
    terminal(unit_state(unit), launch)
    cgroup = empty_cgroup(dict(line.split('=', 1) for line in launch['unitShow']['stdout'].splitlines())['ControlGroup'])
    return {'schema': 1, 'accepted': True, 'qualifiedUtc': utc(), 'source': source,
            'naturalTerminalUnit': state, 'ownerIdentityReleased': owner,
            'sampledIdentitiesReleased': sampled, 'observerPidAbsent': watch['observerPid'],
            'watchDiagnostic': {'outcome': watch.get('outcome'), 'error': watch.get('error'),
                                'lastUnit': watch.get('lastUnit'),
                                'sampleCount': len(watch.get('samples', [])),
                                'productSuccessNotInferred': True,
                                'doesNotOverrideFreshUnitOrProductResult': True},
            'ownedCgroup': cgroup, 'commandReceipts': receipts, 'capturedRawBytes': log_total,
            'metadataFilesVerified': 6, 'runtimeFullIdentitiesVerified': 17,
            'wrappersVerified': 6, 'cfLayoutRows': 2725, 'cfToolRoles': 2347,
            'privateRegularBodiesVerified': 2335, 'cfExactInventoryBeforeAndAfterHashing': True,
            'rustInvocationSummaries': 147, 'rustInvocationTotals': totals, 'cloudflareSuites': cf_suites,
            'countLimit': 'Per-invocation totals, not globally unique tests.',
            'localTimingMarkersRequired': False,
            'ciTimingEvidence': {'receipt': str(BASE / (PREFIX + 'ci-root-verified.json')),
                                 'epochs': ci['epochs'], 'computedUnlock': ci['computedUnlock']},
            'rawANSIRewritten': False, 'unitStoppedOrSignaled': False,
            'elapsedSeconds': round(time.monotonic() - START, 3), 'verifiedReads': READS}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--watch', type=Path, default=BASE / (PREFIX + 'watch-result.json'))
    parser.add_argument('--output', type=Path, default=BASE / (PREFIX + 'root-qualified.json'))
    args = parser.parse_args()
    try:
        require(args.output.parent == BASE and args.output.name.startswith(PREFIX) and
                not args.output.exists(), 'qualification output must be a new dedicated BASE file')
        value = main(args)
        with args.output.open('xb') as stream:
            stream.write((json.dumps(value, indent=2, sort_keys=True) + '\n').encode())
            stream.flush(); os.fsync(stream.fileno())
        print(json.dumps({'accepted': True, 'path': str(args.output)}))
    except Exception as error:
        failure = BASE / (PREFIX + 'qualifier-reader-failed-' +
                          datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') +
                          '-' + str(os.getpid()) + '.json')
        value = {'accepted': False, 'error': str(error), 'traceback': traceback.format_exc(),
                 'utc': utc(), 'progress': PROGRESS, 'verifiedReads': READS,
                 'successOutputWritten': False, 'unitStoppedOrSignaled': False}
        with failure.open('xb') as stream:
            stream.write((json.dumps(value, indent=2, sort_keys=True) + '\n').encode())
            stream.flush(); os.fsync(stream.fileno())
        print(json.dumps({'accepted': False, 'diagnostic': str(failure), 'error': str(error)}))
        sys.exit(1)
