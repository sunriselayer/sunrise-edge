#!/usr/bin/python3.14 -I -B
"""Prepare-only artifact: finite, source-bound ordinary required validation."""
import argparse
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

BASE = Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013')
SOURCE = Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-m2-m3-followup-1021')
BIN = BASE / 'm2-signing-env-1101-bin'
RUST = Path('/home/yu/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin')
CACHE = BASE / 'm2-m3-followup-1021-cache'
STREAM_CAP = 64 * 1024**2
TOTAL_CAP = 256 * 1024**2
STOP_SIGNAL = None

ADMITTED_HEAD = '2e2c10fe0c360f99400be79ee50cad18f5e2336f'
INPUT_PINS = {'/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-signing-env-1101-device-transition.json': '58db4481786efcfd98c4152272a4d98e90a9cffda9a10c3ddda098699e266337', '/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-signing-env-1101-cf-closure.json': '9a4a2b4930909282aae2327f14a7be8e36f29f7d333fd03d721225aa3495e9be', '/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-signing-env-1101-runtime-inputs.json': 'b07d7b9088c0f14f6a97e5c9e162f44acdb49017ae1c46d51dee1b016589c872', '/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-signing-env-1101-source-index.json': '09e72bc59b16129c01430d4b56f52822abf26b2e8c8e4495ef81a7467a759988', '/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-signing-env-1101-wrapper-core.json': 'f2cc3560b382411513040f447c08330268b88ac50bf6bdf860207cdd644c5f8e', '/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-signing-env-1101-admission.json': '2866130ce961714ad37fe2e67d8ca9bf92dcb434686852033a6d3a8a8a296309'}
WRAPPERS = {
    'node': '3792686720650533f4b872be1cd9099ea7fab0564e84a9ecb063ce2b6399a2f2',
    'npm': '9ddeabc1a481a464bd7d02373e6e35c6b3dae61c4295cf8edbaad44d182874d9',
    'npx': '9d6785d28d30c355e761a9830e5eaaeaf7245ecbfc975cf507af50b1aa795fb5',
    'cargo': '381861d7686b84ee8de4b51739d747c49a50b0eb4a32d5b6a2b8849a6361da7b',
    'cf': '882869800e50a57cb12c4cd03259dd75c7b419455caffe9620f12549b3b04c04',
    'python3': '75122b4fe125329e936b8c2a0eb369e0778123f9cca05c8222aad83f543a8fca',
}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def utc():
    return datetime.datetime.now(datetime.UTC).isoformat()


def save(path, value):
    payload = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return {'path': str(path), 'sha256': hashlib.sha256(payload).hexdigest(), 'bytes': len(payload)}


def interrupted(signum, _frame):
    global STOP_SIGNAL
    STOP_SIGNAL = signum


class Driver:
    def __init__(self, args, started):
        self.started = started
        self.hard_end = started + 28200
        self.work_end = self.hard_end - 300
        self.head = args.head
        require(self.head == ADMITTED_HEAD, '--head differs from admitted final source')
        self.output = Path(args.output)
        require(re.fullmatch(r'[0-9a-f]{40}', self.head), '--head must be a full commit ID')
        require(self.output.parent == BASE and self.output.name.startswith('m2-signing-env-1101-run-'),
                '--output must be a new dedicated direct child of the validation directory')
        self.output.mkdir(mode=0o700, exist_ok=False)
        self.records = []
        self.total = 0
        self.adopted = []
        self.active_pid = None
        self.result = {'schema': 1, 'accepted': False, 'expectedHead': self.head,
                       'sourceRoot': str(SOURCE), 'startedUtc': utc(), 'commands': self.records,
                       'adoptedChildrenReaped': self.adopted, 'hardOverallSeconds': 28200,
                       'cleanupReserveSeconds': 300, 'commandTimeoutSeconds': {'npm-ci': 300, 'required': 26000}}
        self.env = self.environment()
        self.unit = args.unit

    def check_time(self, end):
        require(STOP_SIGNAL is None, 'driver interrupted by signal ' + str(STOP_SIGNAL))
        require(time.monotonic() < end, 'finite driver deadline exceeded')

    def environment(self):
        return {
            'PATH': str(BIN) + ':' + str(BASE / 'bin-m2-m3-stable-full-required-1022') + ':' + str(RUST) +
                    ':/home/linuxbrew/.linuxbrew/bin:/home/yu/.local/bin:/usr/local/bin:/usr/bin:/bin',
            'HOME': '/home/yu', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'CI': 'true', 'NO_COLOR': '1',
            'TMPDIR': str(SOURCE / 'target/recipe-tmp'), 'CARGO_HOME': str(CACHE / 'cargo-home'),
            'CARGO_TARGET_DIR': str(SOURCE / 'target'), 'RUSTC': str(RUST / 'rustc'), 'RUSTDOC': str(RUST / 'rustdoc'),
            'CARGO_NET_OFFLINE': 'true', 'CARGO_BUILD_JOBS': '1', 'CARGO_INCREMENTAL': '0',
            'CARGO_PROFILE_DEV_OPT_LEVEL': '2', 'CARGO_PROFILE_TEST_OPT_LEVEL': '2',
            'CARGO_PROFILE_DEV_DEBUG_ASSERTIONS': 'true', 'CARGO_PROFILE_TEST_DEBUG_ASSERTIONS': 'true',
            'CARGO_PROFILE_DEV_OVERFLOW_CHECKS': 'true', 'CARGO_PROFILE_TEST_OVERFLOW_CHECKS': 'true',
            'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0',
            'npm_config_cache': str(CACHE / 'npm-cache'), 'npm_config_offline': 'true',
            'npm_config_audit': 'false', 'npm_config_fund': 'false', 'npm_config_userconfig': '/dev/null',
            'npm_config_globalconfig': str(SOURCE / 'target/recipe-tmp/global.npmrc'),
            'DENO_DIR': str(CACHE / 'deno-cache'), 'DENO_NO_UPDATE_CHECK': '1', 'XDG_CACHE_HOME': str(CACHE / 'xdg-cache'),
            'CF_SEND_TELEMETRY': 'false', 'DO_NOT_TRACK': '1', 'DOCKER_HOST': 'unix:///var/run/docker.sock',
        }

    def setup(self):
        require(sys.version_info[:2] == (3, 14), 'existing Python 3.14 required')
        require(re.fullmatch(r'm2-signing-env-1101-[A-Za-z0-9_.-]+\.service', self.unit), 'dedicated --unit required')
        rows = Path('/proc/self/cgroup').read_text().splitlines()
        require(len(rows) == 1 and rows[0].startswith('0::/'), 'unified cgroup required')
        relative = rows[0][3:]
        require(relative.endswith('/' + self.unit) and '..' not in Path(relative).parts, 'wrong dedicated systemd unit')
        self.cgroup = Path('/sys/fs/cgroup') / relative.lstrip('/')
        limits = {name: (self.cgroup / name).read_text().strip()
                  for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
        quota, period = limits['cpu.max'].split()
        require(limits['memory.max'] == str(12 * 1024**3) and limits['memory.swap.max'] == '0' and
                limits['pids.max'] == '512' and quota != 'max' and int(quota) == 4 * int(period),
                'required 12G/no-swap/CPU400/Tasks512 cgroup limits differ')
        self.result.update({'unit': self.unit, 'cgroup': str(self.cgroup), 'cgroupLimits': limits})
        require(self.cgroup_pids() == {os.getpid()}, 'dedicated cgroup already has other processes')
        require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0, 'child subreaper setup failed')
        self.result['inputsBefore'] = self.admitted_inputs()
        core = json.loads(Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-signing-env-1101-wrapper-core.json').read_text())
        for key, row in core['directories'].items():
            path = Path(row['path']); s = path.lstat()
            require(row['pin'] == [s.st_dev, s.st_ino, s.st_uid, stat.S_IMODE(s.st_mode)] and path.resolve() == path,
                    'admitted directory identity differs: ' + key)
        paths = [SOURCE / 'target', SOURCE / 'target/recipe-tmp', CACHE]
        paths += [CACHE / name for name in ('cargo-home', 'npm-cache', 'deno-cache', 'xdg-cache')]
        for path in paths:
            metadata = path.lstat()
            require(path.resolve() == path and stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid() and
                    stat.S_IMODE(metadata.st_mode) == 0o700, 'existing private directory differs: ' + str(path))

    def cgroup_pids(self):
        values = set()
        count = 0
        for directory, children, _files in os.walk(self.cgroup):
            count += 1
            require(count <= 512 and len(children) <= 512, 'cgroup enumeration bound')
            try:
                values.update(int(value) for value in (Path(directory) / 'cgroup.procs').read_text().split())
            except FileNotFoundError:
                pass
        require(len(values) <= 512, 'cgroup process bound')
        return values

    def reap_adopted(self):
        children = Path('/proc/self/task/' + str(os.getpid()) + '/children').read_text().split()
        require(len(children) <= 512, 'adopted-child bound')
        for value in children:
            pid = int(value)
            if pid == self.active_pid:
                continue
            try:
                observed, status = os.waitpid(pid, os.WNOHANG)
                if observed:
                    self.adopted.append({'pid': observed, 'waitStatus': status})
            except ChildProcessError:
                pass

    @staticmethod
    def signal_group(pgid, signum, record):
        try:
            os.killpg(pgid, signum)
            record['signals'].append({'signal': signum, 'utc': utc()})
        except ProcessLookupError:
            pass

    @staticmethod
    def group_exists(pgid):
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False

    def command(self, label, argv, timeout_seconds, retain=False, final=False):
        end = min(self.hard_end if final else self.work_end, time.monotonic() + timeout_seconds)
        self.check_time(end)
        prefix = str(len(self.records)).zfill(2) + '-' + label
        record = {'label': label, 'argv': argv, 'cwd': str(SOURCE), 'startedUtc': utc(),
                  'exitCode': None, 'waitReapCompleted': False, 'signals': [], 'fullCapture': True}
        self.records.append(record)
        logs = {name: (self.output / (prefix + '.' + name + '.log')).open('xb') for name in ('stdout', 'stderr')}
        digests = {name: hashlib.sha256() for name in logs}
        for name in logs:
            record[name] = {'capturedBytes': 0, 'observedBytes': 0, 'eof': False, 'path': str(self.output / (prefix + '.' + name + '.log'))}
        retained = bytearray()
        selector = selectors.DefaultSelector()
        process = None
        failure = None
        cleanup_end = None
        term_end = None
        killed = False
        started = time.monotonic()
        try:
            process = subprocess.Popen(argv, cwd=SOURCE, env=self.env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            self.active_pid = process.pid
            record['pid'] = record['processGroup'] = process.pid
            for name in logs:
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            print('START ' + label + ' pid=' + str(process.pid), flush=True)
            while True:
                now = time.monotonic()
                if failure is None and (STOP_SIGNAL is not None or now >= end):
                    failure = 'driver interrupted by signal ' + str(STOP_SIGNAL) if STOP_SIGNAL else 'command deadline exceeded'
                if failure is not None and cleanup_end is None:
                    cleanup_end = min(self.hard_end, now + 300)
                    term_end = min(cleanup_end, now + 45)
                    self.signal_group(process.pid, signal.SIGTERM, record)
                if cleanup_end is not None:
                    if now >= term_end and not killed:
                        self.signal_group(process.pid, signal.SIGKILL, record)
                        killed = True
                    if now >= cleanup_end:
                        break
                for key, _events in selector.select(0.1):
                    name = key.data
                    try:
                        data = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(key.fileobj)
                        record[name]['eof'] = True
                        continue
                    record[name]['observedBytes'] += len(data)
                    remaining = min(STREAM_CAP - record[name]['capturedBytes'], TOTAL_CAP - self.total)
                    if retain and name == 'stdout':
                        remaining = min(remaining, 8 * 1024**2 - len(retained))
                    kept = data[:max(0, remaining)]
                    logs[name].write(kept)
                    digests[name].update(kept)
                    record[name]['capturedBytes'] += len(kept)
                    self.total += len(kept)
                    if retain and name == 'stdout':
                        retained.extend(kept)
                    if len(kept) != len(data):
                        record['fullCapture'] = False
                        failure = failure or 'finite output cap exceeded'
                self.reap_adopted()
                observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if observed is not None and not selector.get_map():
                    break
            wait_end = cleanup_end or end
            try:
                record['exitCode'] = process.wait(timeout=max(0.001, wait_end - time.monotonic()))
                record['waitReapCompleted'] = True
                self.active_pid = None
                self.reap_adopted()
            except subprocess.TimeoutExpired:
                failure = failure or 'direct child could not be reaped within finite deadline'
            if record['waitReapCompleted'] and self.group_exists(process.pid):
                failure = failure or 'command left process-group descendants'
                cleanup_end = cleanup_end or min(self.hard_end, time.monotonic() + 300)
                self.signal_group(process.pid, signal.SIGTERM, record)
                term_end = min(cleanup_end, time.monotonic() + 45)
                while self.group_exists(process.pid) and time.monotonic() < term_end:
                    self.reap_adopted()
                    time.sleep(0.05)
                if self.group_exists(process.pid):
                    self.signal_group(process.pid, signal.SIGKILL, record)
                while self.group_exists(process.pid) and time.monotonic() < cleanup_end:
                    self.reap_adopted()
                    time.sleep(0.05)
                require(not self.group_exists(process.pid), 'command group survives finite cleanup')
            require(failure is None, failure or 'command failed')
            require(record['exitCode'] == 0, 'command failed with actual exit ' + str(record['exitCode']))
            require(record['stdout']['eof'] and record['stderr']['eof'] and record['fullCapture'], 'complete captured pipe EOFs required')
            return bytes(retained) if retain else None
        except Exception as error:
            record['error'] = str(error)
            if process is not None and not record['waitReapCompleted']:
                self.signal_group(process.pid, signal.SIGKILL, record)
                try:
                    record['exitCode'] = process.wait(timeout=max(0.001, min(self.hard_end, time.monotonic() + 5) - time.monotonic()))
                    record['waitReapCompleted'] = True
                    self.active_pid = None
                except subprocess.TimeoutExpired:
                    record['cleanupError'] = 'direct child remains; systemd control-group cleanup required'
            raise
        finally:
            for pipe in (process.stdout, process.stderr) if process is not None else ():
                pipe.close()
            selector.close()
            for name, stream in logs.items():
                stream.flush()
                os.fsync(stream.fileno())
                stream.close()
                record[name]['sha256'] = digests[name].hexdigest()
            record['endedUtc'] = utc()
            record['elapsedSeconds'] = round(time.monotonic() - started, 3)
            save(self.output / (prefix + '.json'), record)
            print('END ' + label + ' exit=' + str(record['exitCode']), flush=True)

    def file_digest(self, path, end):
        self.check_time(end)
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 256 * 1024**2, 'bounded regular file required: ' + str(path))
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            while True:
                self.check_time(end)
                block = stream.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
        after = path.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(before, key) == getattr(after, key) for key in fields), 'file changed while hashing: ' + str(path))
        return {'sha256': digest.hexdigest(), 'size': before.st_size}

    def wrappers(self, final=False):
        end = self.hard_end if final else self.work_end
        values = {name: self.file_digest(BIN / name, end) for name in WRAPPERS}
        require(all(values[name]['sha256'] == digest for name, digest in WRAPPERS.items()), 'retained wrapper body differs')
        return values

    def admitted_inputs(self, final=False):
        end = self.hard_end if final else self.work_end
        values = {}
        for path, expected in INPUT_PINS.items():
            value = self.file_digest(Path(path), end)
            require(value['sha256'] == expected, 'admitted metadata file differs: ' + path)
            values[path] = value
        core = json.loads(Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-signing-env-1101-wrapper-core.json').read_text())
        for key, row in core['directories'].items():
            path = Path(row['path']); s = path.lstat()
            pin = [s.st_dev, s.st_ino, s.st_uid, stat.S_IMODE(s.st_mode)]
            require(row['pin'] == pin and stat.S_ISDIR(s.st_mode) and path.resolve() == path,
                    'admitted directory identity differs: ' + key)
            values['directory:' + key] = pin
        runtime = json.loads(Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-signing-env-1101-runtime-inputs.json').read_text())
        def meta(s, kind=False):
            value = {'device': s.st_dev, 'inode': s.st_ino, 'uid': s.st_uid, 'gid': s.st_gid,
                     'mode': stat.S_IMODE(s.st_mode), 'nlink': s.st_nlink, 'length': s.st_size,
                     'mtimeNs': s.st_mtime_ns, 'ctimeNs': s.st_ctime_ns}
            if kind:
                value['type'] = 'symlink' if stat.S_ISLNK(s.st_mode) else 'file' if stat.S_ISREG(s.st_mode) else 'unsupported'
            return value
        for row in runtime['tools']:
            self.check_time(end)
            path = Path(row['path']); entry = path.lstat(); resolved = path.resolve(strict=True)
            link = os.readlink(path) if path.is_symlink() else None
            before = resolved.lstat(); body = self.file_digest(resolved, end)
            value = {'configured': meta(entry, True), 'linkTarget': link, 'resolvedPath': str(resolved),
                     'resolved': {**meta(before), 'sha256': body['sha256']}}
            require(value == row['admittedIdentity'] and str(resolved) == row['resolvedPath'] and body['sha256'] == row['sha256'],
                    'admitted runtime entry/resolution/body differs: ' + row['name'])
            require(meta(resolved.lstat()) == meta(before) and meta(path.lstat(), True) == value['configured'] and path.resolve(strict=True) == resolved and
                    (link is None or os.readlink(path) == link), 'runtime entry changed while hashing')
            values['tool:' + row['name']] = value
        return values

    def snapshot(self, label, final=False):
        def git(suffix, argv):
            return self.command(label + '-' + suffix, ['/usr/bin/git', '-C', str(SOURCE)] + argv, 30, True, final)
        head = git('head', ['rev-parse', 'HEAD']).decode().strip()
        tree = git('tree', ['rev-parse', 'HEAD^{tree}']).decode().strip()
        require(head == self.head and re.fullmatch(r'[0-9a-f]{40}', tree), 'current source identity differs from --head')
        require(git('clean', ['status', '--porcelain=v1', '--untracked-files=normal']) == b'', 'final committed source must be clean')
        files = {}
        total = 0
        for row in git('index', ['ls-files', '--stage', '-z']).split(b'\0'):
            if not row:
                continue
            header, raw_path = row.split(b'\t', 1)
            mode, blob, stage = header.decode().split()
            relative = os.fsdecode(raw_path)
            require(len(files) < 8192 and len(raw_path) <= 4096 and stage == '0' and relative not in files and
                    not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'tracked source inventory bound or stage differs')
            path = SOURCE / relative
            if mode == '120000':
                require(path.is_symlink(), 'tracked symlink differs')
                data = os.fsencode(os.readlink(path))
                value = {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
            else:
                require(mode in ('100644', '100755') and not path.is_symlink(), 'tracked regular-file mode differs')
                value = self.file_digest(path, self.hard_end if final else self.work_end)
            total += value['size']
            require(total <= 1024**3, 'tracked source total-byte bound')
            s = path.lstat()
            value['metadata'] = [s.st_dev, s.st_ino, stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
            files[relative] = {'mode': mode, 'gitBlob': blob, **value}
        value = {'head': head, 'tree': tree, 'clean': True, 'trackedFileCount': len(files), 'files': files}
        require(value == json.loads(Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-signing-env-1101-source-index.json').read_text()), 'source differs from admitted complete source index')
        self.result[label] = save(self.output / (label + '.json'), value)
        return value

    def run(self):
        failure = None
        before = None
        ready = False
        try:
            self.setup()
            ready = True
            self.result['wrappersBefore'] = self.wrappers()
            before = self.snapshot('source-before')
            for label, argv, seconds in (
                    ('npm-ci', ['npm', 'ci', '--prefix', 'adapters/cloudflare-workers'], 300),
                    ('required', ['./scripts/check-all.sh'], 26000)):
                self.reap_adopted()
                require(self.cgroup_pids() == {os.getpid()}, 'other owned processes remain before next producer')
                self.command(label, argv, seconds)
        except Exception as error:
            failure = str(error)
        try:
            require(ready, 'setup incomplete; no commands admitted')
            after = self.snapshot('source-after', True)
            require(before is not None and before == after, 'tracked source changed during validation')
            self.result['inputsAfter'] = self.admitted_inputs(True)
            require(self.result['inputsBefore'] == self.result['inputsAfter'], 'admitted inputs changed during validation')
            self.result['wrappersAfter'] = self.wrappers(True)
            require(self.result['wrappersBefore'] == self.result['wrappersAfter'], 'wrapper identities changed during validation')
            self.reap_adopted()
            remaining = sorted(self.cgroup_pids() - {os.getpid()})
            self.result['remainingOwnedPids'] = remaining
            require(not remaining, 'owned descendants remain; systemd control-group cleanup required')
            self.result['processCleanupComplete'] = True
        except Exception as error:
            self.result['finalizationError'] = str(error)
            failure = failure or str(error)
        self.result.update({'accepted': failure is None, 'error': failure, 'finishedUtc': utc(),
                            'elapsedSeconds': round(time.monotonic() - self.started, 3), 'capturedOutputBytes': self.total})
        save(self.output / 'result.json', self.result)
        print('RESULT ' + str(self.output / 'result.json') + ' accepted=' + str(self.result['accepted']), flush=True)
        return 0 if self.result['accepted'] else 1


def main():
    started = time.monotonic()
    parser = argparse.ArgumentParser()
    parser.add_argument('--head', required=True)
    parser.add_argument('--unit', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    return Driver(args, started).run()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
