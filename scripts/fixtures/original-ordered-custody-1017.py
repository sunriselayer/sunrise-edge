"""Disposable controller source, transported by its SHA-pinned Node owner.
Never execute directly on a host. Every writable path is beneath verified /work.
"""
import errno
import hashlib
import json
import os
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

START = time.monotonic()
END = START + 230.0
WORK_END = START + 175.0
OUTPUT_CAP = 262144
UID_WORKER, UID_FRONT, UID_INTRUDER = 12001, 12002, 12003
GROUP = UID_WORKER
selector = selectors.DefaultSelector()
children = []
output_bytes = 0
phases = []


def remaining(end=END):
    value = end - time.monotonic()
    if value <= 0:
        raise RuntimeError('fixed fixture deadline exceeded')
    return value


def bounded_read(path, cap):
    with open(path, 'rb') as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        raise RuntimeError('bounded input exceeded')
    return data


def make_directory(path, mode, uid=0, gid=0):
    os.mkdir(path, mode)
    os.chmod(path, mode)
    os.chown(path, uid, gid)


def new_file(path, data, uid=0, gid=0, mode=0o600):
    if len(data) > 1048576:
        raise RuntimeError('generated file cap')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise RuntimeError('generated file write incomplete')
            offset += written
        os.fsync(fd)
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
    finally:
        os.close(fd)


def allocation():
    total, count = 0, 0
    for parent, dirs, files in os.walk('/work', followlinks=False):
        for name in dirs + files:
            info = os.lstat(os.path.join(parent, name))
            count += 1
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
            elif not (stat.S_ISDIR(info.st_mode) or stat.S_ISSOCK(info.st_mode)):
                raise RuntimeError('unexpected generated inode kind')
    if total > 67108864 or count > 16384:
        raise RuntimeError('generated allocation exceeded')
    return {'bytes': total, 'inodes': count}


ROLE_CHECK = """import os,sys
uid=int(sys.argv[1]);gid=int(sys.argv[2]);groups=[int(v) for v in sys.argv[3].split(',') if v]
assert os.geteuid()==uid and os.getegid()==gid and sorted(os.getgroups())==sorted(groups)
status=open('/proc/self/status').read();assert '\\nCapEff:\\t0000000000000000\\n' in status
os.umask(0o077)
print('role_checked uid='+str(uid)+' gid='+str(gid)+' caps=0',flush=True)
os.execve(sys.argv[4],sys.argv[4:],dict(os.environ))
"""


class Child:
    def __init__(self, label, argv, uid, gid, groups=(), env=None, end=WORK_END):
        remaining(end)
        def drop():
            os.setgroups(list(groups)); os.setgid(gid); os.setuid(uid)
        values = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'TMPDIR': '/work/front/v0' if uid == UID_FRONT else '/work/worker/setup',
                  'RUST_BACKTRACE': '0', 'RUST_TEST_THREADS': '1'}
        values.update(env or {})
        wrapper = ['/usr/local/bin/python3', '-I', '-B', '-c', ROLE_CHECK,
                   str(uid), str(gid), ','.join(str(v) for v in groups)] + argv
        self.proc = subprocess.Popen(wrapper, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, preexec_fn=drop, env=values)
        self.label, self.uid, self.gid = label, uid, gid
        self.data = {'stdout': bytearray(), 'stderr': bytearray()}
        self.eof = set(); self.offset = 0; self.code = None; self.waited = False
        children.append(self)
        for name, stream in [('stdout', self.proc.stdout), ('stderr', self.proc.stderr)]:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (self, name))
        marker = self.line(min(end, time.monotonic() + 3))
        if marker != f'role_checked uid={uid} gid={gid} caps=0\n':
            raise RuntimeError('effective role UID/group/capability marker differs')

    def exited(self):
        if self.waited:
            return True
        return os.waitid(os.P_PID, self.proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None

    def line(self, end):
        while True:
            remaining(end)
            data = self.data['stdout']
            index = data.find(b'\n', self.offset)
            if index >= 0:
                value = bytes(data[self.offset:index + 1]); self.offset = index + 1
                if len(value) > 4096:
                    raise RuntimeError('startup line cap')
                return value.decode('ascii')
            if 'stdout' in self.eof:
                raise RuntimeError('EOF before complete startup line')
            pump(end)

    def finish(self, end, expected=0):
        while not (self.exited() and len(self.eof) == 2):
            pump(end)
        self.code = self.proc.wait(timeout=min(1, remaining(end)))
        self.waited = True
        if expected is not None and self.code != expected:
            raise RuntimeError(f'owned child {self.label} exit differs: {self.code}')
        return bytes(self.data['stdout'][self.offset:]), bytes(self.data['stderr'])


def pump(end):
    global output_bytes
    for key, _ in selector.select(min(0.1, remaining(end))):
        child, name = key.data
        chunk = os.read(key.fileobj.fileno(), 8192)
        if not chunk:
            selector.unregister(key.fileobj); key.fileobj.close(); child.eof.add(name)
            continue
        output_bytes += len(chunk)
        if output_bytes > OUTPUT_CAP or len(child.data[name]) + len(chunk) > 65536:
            raise RuntimeError('complete child output cap exceeded; capture incomplete')
        child.data[name].extend(chunk)


def command(label, argv, uid=UID_WORKER, gid=UID_WORKER, groups=(), env=None, expected=0, cap=20, end=WORK_END):
    child = Child(label, argv, uid, gid, groups, env, end=end)
    result = child.finish(min(end, time.monotonic() + cap), expected)
    return result, child


def elf(name, args):
    return ['/mnt/libs/ld.so', '--library-path', '/mnt/libs', '/mnt/bin/' + name] + args


def probe(phase, uid=UID_FRONT):
    groups = (GROUP,) if uid == UID_FRONT else ()
    result, child = command('probe-' + phase, elf('harness', [
        '--ignored', '--exact', 'fixture_original_ordered_role_probe', '--nocapture', '--test-threads=1']),
        uid, uid, groups, {'SUNRISE_ORDERED_FIXTURE_PHASE': phase}, cap=30)
    if b'test result: ok. 1 passed; 0 failed;' not in result[0]:
        raise RuntimeError('actual fixture probe did not complete one selected test')
    phases.append(phase)
    allocation()
    return child


def pins():
    text = bounded_read('/work/public/pins', 16384).decode('ascii')
    result = {}
    for line in text.splitlines():
        key, value = line.split('=', 1)
        if key in result:
            raise RuntimeError('duplicate public pin')
        result[key] = value
    if set(result) != {'chain-id', 'authority', 'domain', 'suite'} | {f'validator-{i}' for i in range(4)}:
        raise RuntimeError('public pins shape')
    return result


def root_args(index):
    p = pins()
    digest = bounded_read('/work/public/digest', 64).decode('ascii')
    return ['--chain-id', p['chain-id'], '--protocol-version', '7', '--epoch', '0',
            '--suite', p['suite'], '--validator-id', p[f'validator-{index}'], '--domain', p['domain'],
            '--genesis-manifest', f'/work/worker/v{index}/genesis.bin',
            '--expected-genesis-digest', digest, '--state-db', f'/work/source/v{index}/state.sqlite',
            '--blob-db', f'/work/source/v{index}/body.sqlite']


def namespace_args(index):
    p = pins()
    return ['--chain-id', p['chain-id'], '--validator-id', p[f'validator-{index}'],
            '--domain', p['domain'], '--state-db', f'/work/source/v{index}/state.sqlite',
            '--blob-db', f'/work/source/v{index}/body.sqlite']


def parse_fields(text):
    fields = {}
    for token in text.split():
        if '=' in token:
            key, value = token.split('=', 1)
            if key in fields:
                raise RuntimeError('duplicate result field')
            fields[key] = value
    return fields


def anchor(index, mode, end=WORK_END):
    argv = [mode] + namespace_args(index)
    if mode != 'anchor-inspect':
        argv += ['--independent-anchor-db', f'/work/authority/v{index}/anchor.sqlite']
    result, _ = command(f'{mode}-{index}', elf('host', argv), end=end)
    fields = parse_fields(result[0].decode('ascii'))
    if fields.get('complete') != 'true':
        raise RuntimeError('actual anchor command lacks completion')
    return fields


def configurations():
    p = pins(); digest = bounded_read('/work/public/digest', 64).decode('ascii')
    for index in range(4):
        common = {'chain-id': p['chain-id'], 'protocol-version': '7', 'epoch': '0', 'suite': p['suite'],
                  'domain': p['domain'], 'validator-id': p[f'validator-{index}'],
                  'expected-genesis-digest': digest, 'timeout-seconds': '2', 'max-concurrent': '2',
                  'max-requests': '128', 'total-deadline-seconds': '200', 'socket': f'/work/run/v{index}/worker.sock'}
        worker = dict(common, **{'genesis-manifest': f'/work/worker/v{index}/genesis.bin',
                  'signing-key-file': f'/work/worker/v{index}/validator.key',
                  'state-db': f'/work/source/v{index}/state.sqlite', 'blob-db': f'/work/source/v{index}/body.sqlite',
                  'independent-anchor-db': f'/work/authority/v{index}/anchor.sqlite',
                  'frontend-uid': str(UID_FRONT), 'max-connections': '160', 'confirm-offline-fence-advance': 'true'})
        front = dict(common, **{'genesis-manifest': f'/work/front/v{index}/genesis.bin', 'worker-uid': str(UID_WORKER),
                  'listen': '127.0.0.1:0', 'tls-cert-der-file': f'/work/front/v{index}/leaf.der',
                  'tls-key-pkcs8-der-file': f'/work/front/v{index}/tls.key'})
        for role, values, uid in [('worker', worker, UID_WORKER), ('front', front, UID_FRONT)]:
            data = ''.join(f'{key}={value}\n' for key, value in values.items()).encode('ascii')
            new_file(f'/work/{role}/v{index}/config', data, uid, uid)


def start_workers():
    result = []
    for index in range(4):
        child = Child(f'worker-{index}', elf('host', ['protocol-worker', '--config', f'/work/worker/v{index}/config']), UID_WORKER, UID_WORKER)
        line = child.line(min(WORK_END, time.monotonic() + 5))
        fields = parse_fields(line)
        if fields.get('complete') != 'true' or fields.get('mode') != 'protocol-worker':
            raise RuntimeError('worker readiness differs')
        result.append(child)
    return result


def start_frontends():
    result = []
    for index in range(4):
        child = Child(f'frontend-{index}', elf('host', ['protocol-frontend', '--config', f'/work/front/v{index}/config']), UID_FRONT, UID_FRONT, (GROUP,))
        fields = parse_fields(child.line(min(WORK_END, time.monotonic() + 5)))
        if fields.get('complete') != 'true' or fields.get('mode') != 'protocol-frontend' or fields.get('authority') != 'none':
            raise RuntimeError('frontend readiness differs')
        address = fields.get('listen', '')
        if not address.startswith('127.0.0.1:') or not 1 <= int(address.split(':')[1]) <= 65535:
            raise RuntimeError('actual frontend loopback address differs')
        new_file(f'/work/public/address-{index}', address.encode('ascii'), mode=0o644)
        result.append(child)
    return result


def send_signal(child, number, cleanup=False, end=WORK_END):
    if child.waited:
        return
    if child.exited():
        if not cleanup:
            raise RuntimeError('owned role exited before orderly signal')
        return
    if not isinstance(child.proc.pid, int) or not 1 <= child.proc.pid <= 2147483647:
        raise RuntimeError('owned signal PID bound')
    # Unreaped ownership prevents PID reuse while this same-UID helper signals.
    argv = ['/usr/local/bin/python3', '-I', '-B', '-c',
            'import os,sys;os.kill(int(sys.argv[1]),int(sys.argv[2]))', str(child.proc.pid), str(number)]
    command('cleanup-signal' if cleanup else 'orderly-signal', argv, child.uid, child.gid,
            (GROUP,) if child.uid == UID_FRONT else (), cap=2, end=END if cleanup else end)



def stop_roles(roles, end=WORK_END):
    for child in roles:
        send_signal(child, signal.SIGTERM, end=end)
    for child in roles:
        _, stderr = child.finish(min(end, time.monotonic() + 5))
        if stderr != b'protocol_custody complete=true admission=closed work=drained\n':
            raise RuntimeError('owned role lacks exact drained completion')


class Oracle:
    def __init__(self):
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind('/work/oracle/control.sock')
        os.chown('/work/oracle/control.sock', 0, UID_WORKER); os.chmod('/work/oracle/control.sock', 0o660)
        self.listener.listen(1); self.listener.settimeout(min(5, remaining(WORK_END)))
        self.child = Child('row-oracle', elf('harness', ['--ignored', '--exact', 'fixture_original_ordered_role_probe', '--nocapture', '--test-threads=1']),
                           UID_WORKER, UID_WORKER, env={'SUNRISE_ORDERED_FIXTURE_PHASE': 'oracle'})
        self.stream, _ = self.listener.accept()
        pid, uid, gid = struct.unpack('3i', self.stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if (pid, uid, gid) != (self.child.proc.pid, UID_WORKER, UID_WORKER):
            raise RuntimeError('oracle peer is not exact owned worker-UID helper')
        self.listener.close(); self.stream.settimeout(min(2, remaining(WORK_END)))
        self.count = 0

    def phase(self, value, end=WORK_END):
        if value not in ['baseline', 'unchanged', 'fence-2', 'fence-3', 'retained-1', 'retained-2', 'finish'] or self.count >= 64:
            raise RuntimeError('closed oracle phase')
        self.count += 1
        phase_end = min(end, time.monotonic() + 2.0)
        self.stream.settimeout(remaining(phase_end))
        self.stream.sendall((value + '\n').encode('ascii'))
        remaining(phase_end)
        data = bytearray()
        while not data.endswith(b'\n'):
            self.stream.settimeout(remaining(phase_end))
            if len(data) >= 64:
                raise RuntimeError('oracle acknowledgement cap')
            chunk = self.stream.recv(64 - len(data))
            if not chunk:
                raise RuntimeError('oracle EOF before acknowledgement')
            data.extend(chunk)
        remaining(phase_end)
        if data != ('ok ' + value + '\n').encode('ascii'):
            raise RuntimeError('oracle acknowledgement differs')
        phases.append('oracle-' + value)


def filesystem_refusals():
    names = []
    for index in range(4):
        names += [f'/work/source/v{index}/state.sqlite', f'/work/source/v{index}/body.sqlite',
                  f'/work/worker/v{index}/validator.key', f'/work/worker/v{index}/config',
                  f'/work/authority/v{index}/anchor.sqlite', f'/work/authority/v{index}/anchor.sqlite.lease']
    for name in names:
        info = os.lstat(name)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != UID_WORKER or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError('private role input inode/owner/mode differs')
    source = """import errno,json,os,sys
for path in json.loads(sys.argv[1]):
 try: f=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 except OSError as error: assert error.errno==errno.EACCES
 else: os.close(f);raise RuntimeError('private authority became readable')
"""
    for uid in [UID_FRONT, UID_INTRUDER]:
        command('filesystem-refusal', ['/usr/local/bin/python3', '-I', '-B', '-c', source, json.dumps(names)], uid, uid, (GROUP,))
    phases.append('filesystem-refusals')


def intruder_socket():
    source = """import socket,sys
for i in range(4):
 s=socket.socket(socket.AF_UNIX);s.settimeout(2);s.connect('/work/run/v'+str(i)+'/worker.sock')
 assert s.recv(1)==b'';s.close()
"""
    command('intruder-before-body', ['/usr/local/bin/python3', '-I', '-B', '-c', source], UID_INTRUDER, UID_INTRUDER, (GROUP,))
    phases.append('intruder-before-body')


def authenticated_stalled_body():
    source = """import socket,time
for i in range(4):
 s=socket.socket(socket.AF_UNIX);s.settimeout(4);s.connect('/work/run/v'+str(i)+'/worker.sock')
 start=time.monotonic();s.sendall(b'\\x00');assert s.recv(1)==b''
 elapsed=time.monotonic()-start;assert 1.5<=elapsed<4;s.close()
"""
    command('authenticated-stalled-body-deadline', ['/usr/local/bin/python3', '-I', '-B', '-c', source], UID_FRONT, UID_FRONT, (GROUP,), cap=12)
    phases.append('authenticated-stalled-body-deadline')


def impostor_worker():
    make_directory('/work/impostor', 0o755, UID_INTRUDER, UID_INTRUDER)
    source = """import socket,os
s=socket.socket(socket.AF_UNIX);s.bind('/work/impostor/fake.sock');os.chmod('/work/impostor/fake.sock',0o666)
s.listen(1);s.settimeout(5);print('impostor_ready',flush=True)
c,_=s.accept();c.settimeout(2);assert c.recv(1)==b'';c.close();s.close()
print('impostor_zero_request_bytes',flush=True)
"""
    listener = Child('impostor-listener', ['/usr/local/bin/python3', '-I', '-B', '-c', source], UID_INTRUDER, UID_INTRUDER)
    if listener.line(min(WORK_END, time.monotonic() + 3)) != 'impostor_ready\n':
        raise RuntimeError('impostor listener readiness differs')
    data = bounded_read('/work/front/v0/config', 16384).decode('ascii')
    lines = ['socket=/work/impostor/fake.sock' if line.startswith('socket=') else line for line in data.splitlines()]
    target = '/work/front/v0/impostor.config'
    new_file(target, ('\n'.join(lines) + '\n').encode(), UID_FRONT, UID_FRONT)
    result, child = command('frontend-refuses-impostor', elf('host', ['protocol-frontend', '--config', target]), UID_FRONT, UID_FRONT, (GROUP,), expected=None)
    if child.code == 0 or result[0]:
        raise RuntimeError('frontend accepted wrong-UID worker or advertised readiness')
    output, _ = listener.finish(min(WORK_END, time.monotonic() + 3))
    if output != b'impostor_zero_request_bytes\n':
        raise RuntimeError('wrong worker peer received request bytes')
    phases.append('frontend-refuses-impostor-before-body')


def missing_and_competing():
    data = bounded_read('/work/worker/v0/config', 16384).decode('ascii')
    for tag, extra in [('missing', None), ('competing', '/work/run/competing/worker.sock')]:
        lines = []
        for line in data.splitlines():
            if tag == 'missing' and line.startswith('independent-anchor-db='):
                continue
            if line.startswith('socket='):
                line = 'socket=/work/run/competing/worker.sock'
            lines.append(line)
        target = f'/work/worker/v0/{tag}.config'
        new_file(target, ('\n'.join(lines) + '\n').encode(), UID_WORKER, UID_WORKER)
        result, child = command('refused-' + tag, elf('host', ['protocol-worker', '--config', target]), expected=None)
        if child.code == 0 or result[0]:
            raise RuntimeError('refused worker advertised success')
    phases.append('missing-anchor-and-competing-lease')


def verify_environment():
    if os.geteuid() != 0 or os.listdir('/work'):
        raise RuntimeError('controller requires fresh disposable root allocation')
    status = bounded_read('/proc/self/status', 8192).decode()
    if '\nCapEff:\t00000000000000c3\n' not in status:
        raise RuntimeError('controller capability set differs')
    expected = {'memory.max': '536870912', 'memory.swap.max': '0', 'pids.max': '64', 'cpu.max': '100000 100000'}
    for name, value in expected.items():
        if bounded_read('/sys/fs/cgroup/' + name, 128).decode().strip() != value:
            raise RuntimeError('actual cgroup limit differs: ' + name)
    mounts = bounded_read('/proc/self/mountinfo', 65536).decode().splitlines()
    selected = [line for line in mounts if line.split()[4] == '/work']
    if len(selected) != 1:
        raise RuntimeError('tmpfs attachment is not unique')
    left, right = selected[0].split(' - ', 1)
    if right.split()[0] != 'tmpfs':
        raise RuntimeError('work allocation is not tmpfs')
    options = set(left.split()[5].split(',')) | set(right.split()[2].split(','))
    if not {'rw', 'nosuid', 'nodev', 'noexec', 'noswap'} <= options:
        raise RuntimeError('actual tmpfs protections differ')
    info = os.statvfs('/work')
    if info.f_frsize * info.f_blocks != 67108864 or info.f_files != 16384:
        raise RuntimeError('actual tmpfs byte/inode bounds differ')
    if stat.S_IMODE(os.stat('/work').st_mode) != 0o755:
        raise RuntimeError('actual tmpfs root permissions differ')
    return expected


def main():
    limits = verify_environment()
    for tree in ['source', 'authority', 'worker', 'run', 'front']:
        make_directory('/work/' + tree, 0o755)
    make_directory('/work/worker/setup', 0o700, UID_WORKER, UID_WORKER)
    make_directory('/work/public', 0o755, UID_WORKER, UID_WORKER)
    make_directory('/work/public/wire', 0o755, UID_FRONT, UID_FRONT)
    make_directory('/work/artifacts', 0o700, UID_FRONT, UID_FRONT)
    make_directory('/work/oracle', 0o700, UID_WORKER, UID_WORKER)
    for index in range(4):
        for tree in ['source', 'authority', 'worker', 'front', 'run']:
            uid = UID_FRONT if tree == 'front' else UID_WORKER
            make_directory(f'/work/{tree}/v{index}', 0o750 if tree == 'run' else 0o700, uid, uid)
    make_directory('/work/run/competing', 0o750, UID_WORKER, UID_WORKER)
    probe('prepare-inputs', UID_WORKER)
    args = bounded_read('/work/public/author-arguments', 16384).decode('ascii').splitlines()
    authored, _ = command('actual-author', elf('author', args))
    fields = parse_fields(authored[0].decode('ascii'))
    digest = fields.get('manifest_digest', '')
    if fields.get('complete') != 'true' or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
        raise RuntimeError('actual author digest pin missing')
    new_file('/work/public/digest', digest.encode(), mode=0o644)
    p = pins()
    inspected, _ = command('actual-inspect', elf('inspect', ['inspect', '--chain-id', p['chain-id'],
        '--protocol-version', '7', '--epoch', '0', '--suite', p['suite'], '--expected-genesis-authority', p['authority'],
        '--expected-manifest-digest', digest, '--validation-domain', '41' * 32, '--validation-checkpoint', '10',
        '--timeout-seconds', '2', '--genesis-manifest', '/work/worker/setup/genesis.bin']))
    if inspected[0].count(b'complete=true') != 1:
        raise RuntimeError('actual inspector completion differs')
    probe('publish-genesis', UID_WORKER)
    for index in range(4):
        prepared, _ = command(f'actual-prepare-{index}', elf('genesis', ['prepare'] + root_args(index) + ['--created-checkpoint', '10']))
        if parse_fields(prepared[0].decode()).get('writer_fence') != '1':
            raise RuntimeError('initial fence is not exactly1')
        command(f'actual-preflight-{index}', elf('genesis', ['preflight'] + root_args(index) + ['--validator-public-key', p[f'validator-{index}']]))
        observed = anchor(index, 'anchor-inspect')
        enrolled, _ = command(f'actual-enroll-{index}', elf('host', ['anchor-enroll'] + namespace_args(index) + [
            '--independent-anchor-db', f'/work/authority/v{index}/anchor.sqlite',
            '--expected-initial-state-root', observed['state_root'], '--expected-initial-body-manifest-root', observed['body_manifest_root'],
            '--confirm-writers-and-signers-stopped']))
        if parse_fields(enrolled[0].decode()).get('sequence') != '1':
            raise RuntimeError('initial enrolled anchor sequence differs')
        anchor(index, 'anchor-checkpoint')
    probe('frontend-inputs')
    configurations(); filesystem_refusals()
    oracle = Oracle(); oracle.phase('baseline')
    workers = start_workers(); oracle.phase('fence-2')
    frontends = start_frontends()
    oracle.phase('baseline'); intruder_socket(); authenticated_stalled_body(); impostor_worker(); missing_and_competing(); oracle.phase('unchanged')
    probe('propose-first'); oracle.phase('baseline'); probe('propose-repeat'); oracle.phase('unchanged')
    probe('votes-first'); oracle.phase('retained-1'); probe('votes-repeat'); oracle.phase('unchanged')
    probe('bad-input'); oracle.phase('unchanged')
    stop_roles(workers)
    for index in range(4):
        if os.path.lexists(f'/work/run/v{index}/worker.sock'):
            raise RuntimeError('stopped worker socket remains')
        anchor(index, 'anchor-checkpoint')
    oracle.phase('unchanged'); probe('worker-down'); oracle.phase('unchanged')
    workers = start_workers(); oracle.phase('fence-3')
    probe('votes-repeat'); oracle.phase('unchanged'); probe('certificate'); probe('fresh'); oracle.phase('retained-2')
    probe('replay'); oracle.phase('unchanged')
    remaining(WORK_END)
    stop_roles(frontends + workers, end=END); oracle.phase('finish', end=END); oracle.stream.close()
    oracle_output, _ = oracle.child.finish(min(END, time.monotonic() + 5))
    if b'test result: ok. 1 passed; 0 failed;' not in oracle_output:
        raise RuntimeError('actual selected oracle test did not complete')
    if any(not child.waited for child in children):
        raise RuntimeError('owned child wait unresolved')
    for index in range(4):
        if os.path.lexists(f'/work/run/v{index}/worker.sock'):
            raise RuntimeError('tail socket remains')
        anchor(index, 'anchor-checkpoint', end=END)
    return {'passed': True, 'limits': limits, 'phases': phases, 'allocation': allocation(),
            'fixed_deadlines': [280, 230, 175], 'final_fence': 3, 'fresh_height': 2,
            'qc_votes': 3, 'actual_votes': 4, 'actual_peer_responses': 4, 'all_children_waited': True, 'no_validator_key_in_frontend': True}


result = None
failure = None
try:
    result = main()
except BaseException as error:
    failure = type(error).__name__ + ': ' + str(error)
finally:
    cleanup_errors = []
    for child in list(children):
        if child.waited:
            continue
        try:
            send_signal(child, signal.SIGKILL, True)
            child.finish(END, expected=None)
        except BaseException as error:
            cleanup_errors.append(type(error).__name__ + ': ' + str(error))
    if cleanup_errors:
        failure = (failure or 'fixture') + '; child cleanup unresolved: ' + '; '.join(cleanup_errors)
    records = [{'label': child.label, 'uid': child.uid, 'gid': child.gid, 'pid': child.proc.pid,
                'exit': child.code, 'waited': child.waited, 'stdout_eof': 'stdout' in child.eof,
                'stderr_eof': 'stderr' in child.eof,
                'stdout': bytes(child.data['stdout']).decode('utf-8', 'replace'),
                'stderr': bytes(child.data['stderr']).decode('utf-8', 'replace')} for child in children]
    final = dict(result or {}, passed=failure is None and result is not None, error=failure,
                 child_records=records, captured_output_bytes=output_bytes, elapsed=time.monotonic() - START)
    print(json.dumps(final, separators=(',', ':')), flush=True)
    if failure:
        sys.exit(1)
