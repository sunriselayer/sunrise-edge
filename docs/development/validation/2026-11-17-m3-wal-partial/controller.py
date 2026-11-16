#!/usr/bin/python3
"""Bounded independently anchored NativeSQLite virtual fault owner. Source review and execution approval required."""
import argparse
import gc
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import time

BASE = Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013')
parser = argparse.ArgumentParser()
parser.add_argument('--elf', required=True)
parser.add_argument('--elf-sha256', required=True)
parser.add_argument('--attempt', required=True)
args = parser.parse_args()
if not re.fullmatch(r'qga[0-9a-z]{1,7}', args.attempt):
    parser.error('attempt must be a fresh short task-owned qg identifier')
if not re.fullmatch(r'[0-9a-f]{64}', args.elf_sha256):
    parser.error('exact reviewed ELF SHA-256 required')
ELF = Path(args.elf)
if not ELF.is_absolute() or ELF.is_symlink() or not ELF.is_file():
    parser.error('absolute regular nonsymlink owned test ELF required')
elf_metadata = ELF.lstat()
if elf_metadata.st_uid != os.getuid() or elf_metadata.st_nlink != 1 or stat.S_IMODE(elf_metadata.st_mode) != 0o755:
    parser.error('retained normal current-UID single-link0755 test ELF required')
ROOT = BASE / args.attempt
os.umask(0o077)
START = time.monotonic()
END = START + 1280
CLEANUP_END = START + 1320
GUEST_SECONDS = 0.0
GENERATED = 2 * 1024 * 1024 * 1024
GROSS = 8 * 1024 * 1024 * 1024
RAW_LIMIT = 16 * 1024 * 1024
FRAME_LIMIT = 64 * 1024
TERMINAL_LIMIT = 4 * 1024 * 1024
TERMINAL_RESERVE = 16 * 1024
SOURCE_BYTES = 64 * 1024 * 1024
AUTHORITY_BYTES = 32 * 1024 * 1024
CASES = ['source-write']
PRIOR_ROOTS = [BASE / name for name in ['qg1017a', 'qg1017b', 'qemu1017p1', 'qm1017a',
                                        'qga1116c', 'qga1116d', 'qga1116e', 'qga1116f', 'qga1117a', 'qga1117b', 'qga1117c', 'qga1117d', 'qga1117e']]
PRIOR_BYTES = 5731255352
AGGREGATE_RETAINED = 8 * 1024 ** 3
prior_inventory = None
FORENSIC = ROOT / 'forensic'
immutable_images = []
PINS = {
    '/usr/bin/qemu-system-x86_64': 'c43e631d642ba63a5af8f02a555fc679c30d38bdda8d4cd08897c3ca1dfa233a',
    '/usr/bin/bash': 'c14c8f498f3be96f076ceb07d65dba584a86dca3c86b5dce65ed0f6cae73358d',
    '/usr/bin/mount': 'ca6c26aa2b11a8431481d39ee562bc07a88984f3294f34846d3257ec28ae9c91',
    '/usr/bin/filefrag': '03f12bac42946df2e1e5d7d1fd7d7958d8117d3d72cf94dc3cf95f4d41172c0a',
    '/usr/bin/mkfs.ext4': '0ad4756fd858ee0a3a7fcaa34875af0c1050b9bccaf0d363c242d87d70575657',
    '/proc/config.gz': 'fcb764d08890f8d31414c1d87aa3b9c33ac311b867b226993a8200252fb8d3b5',
    '/boot/vmlinuz-linux': 'be373165e6d54bfee8e95b6ba6ffd7e5726544fbb571893773d45c806ba18ef9',
    '/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/qga1017a/kernel': '5806981b246bfd6e0b9f8dd0ee5e5d2e35561aca66bdf8377f190c8abcc4b2cc',
    str(ELF): args.elf_sha256,
}
gross = 0
raw_bytes = 0
children = []
inputs = {}
attempts = []
peak_memory = 0
LOG = None
controller_io = None
CG = None
root_identity = None


def charge(count, enforce=True):
    global gross
    gross += count
    if enforce and gross > GROSS:
        raise RuntimeError('gross logical I/O budget exceeded')


def read(path, limit=32 * 1024 * 1024):
    with Path(path).open('rb') as source:
        data = source.read(limit + 1)
    charge(len(data))
    if len(data) > limit:
        raise RuntimeError('input byte limit: ' + str(path))
    return data


def write(path, data, mode=0o600):
    charge(len(data))
    with Path(path).open('xb') as output:
        os.chmod(path, mode)
        output.write(data)


def log(tag, data):
    global raw_bytes
    framed = (tag + ': ').encode() + data
    raw_bytes += len(framed)
    if raw_bytes > RAW_LIMIT:
        raise RuntimeError('raw output limit')
    charge(len(framed))
    LOG.write(framed)
    LOG.flush()


def cgroup_state():
    return {name: (CG / name).read_text().strip() for name in
            ['memory.current', 'memory.peak', 'memory.swap.current', 'memory.events', 'cgroup.procs']}


def cgroup_errors(state, require_only_owner=False):
    errors = []
    if int(state['memory.peak']) > 1024 ** 3:
        errors.append('memory peak exceeds1GiB')
    if int(state['memory.swap.current']) != 0:
        errors.append('nonzero memory swap use')
    events = {key: int(value) for key, value in (line.split() for line in state['memory.events'].splitlines())}
    if any(events.get(key, 0) != 0 for key in ['oom', 'oom_kill', 'oom_group_kill']):
        errors.append('actual OOM event')
    if require_only_owner and set(map(int, state['cgroup.procs'].split())) != {os.getpid()}:
        errors.append('unexpected remaining process in owned cgroup')
    return errors


def guard():
    global peak_memory, gross, controller_io
    controller_io = {line.split(':')[0]: int(line.split(':')[1]) for line in Path('/proc/self/io').read_text().splitlines()}
    observed = controller_io['rchar'] + controller_io['wchar'] + sum(child.last_io for child in children)
    gross = max(gross, observed)  # Includes even metadata/log/accounting I/O omitted by explicit data charging.
    if time.monotonic() >= END:
        raise RuntimeError('whole product owner deadline with final cleanup reserve')
    if gross > GROSS:
        raise RuntimeError('gross logical I/O budget exceeded')
    usage = os.statvfs(ROOT)
    if usage.f_bavail * usage.f_frsize < 5 * 1024 ** 3:
        raise RuntimeError('free-space headroom')
    total = generated_bytes()
    if prior_inventory is not None and any(tree_inventory(path) != prior_inventory[str(path)] for path in PRIOR_ROOTS):
        raise RuntimeError('preserved earlier VM roots changed')
    if total + PRIOR_BYTES > AGGREGATE_RETAINED:
        raise RuntimeError('aggregate prior plus new VM retention cap')
    if total > GENERATED - TERMINAL_RESERVE:
        raise RuntimeError('generated byte limit with compact terminal reserve')
    for guest in guests:
        if hasattr(guest, 'trace_path') and guest.trace_path.exists() and guest.trace_path.stat().st_size > 8 * 1024 * 1024:
            raise RuntimeError('live QEMU write-trace 8MiB cap')
    state = cgroup_state()
    peak_memory = max(peak_memory, int(state['memory.peak']))
    failures = cgroup_errors(state)
    if failures:
        raise RuntimeError('actual cgroup resource violation: ' + repr(failures))
    for child in children:
        child.sample_io()


class Owned:
    def __init__(self, argv, name, guest=None):
        self.name = name
        self.last_io = 0
        self.reaped = False
        self.eof = False
        self.io_final = None
        self.discarded_cleanup_bytes = 0
        self.stream = (ROOT / (name + '.raw')).open('xb')
        try:
            self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, env=ENV, cwd=ROOT)
        except BaseException:
            self.stream.close()
            raise
        # Register the allocation immediately after Popen, before any fallible
        # descriptor configuration, logging, socket discovery, or guest pumping.
        children.append(self)
        if guest is not None:
            guest.child = self
        os.set_blocking(self.p.stdout.fileno(), False)
        log(name + '-argv', (json.dumps(argv) + '\n').encode())

    def sample_io(self, enforce=True):
        if self.reaped:
            return
        data = Path(f'/proc/{self.p.pid}/io').read_text()
        values = {line.split(':')[0]: int(line.split(':')[1]) for line in data.splitlines()}
        current = values['rchar'] + values['wchar']
        if current < self.last_io:
            raise RuntimeError('nonmonotonic child I/O')
        charge(current - self.last_io, enforce=enforce)
        self.last_io = current
        self.io_final = values

    def exited(self):
        return os.waitid(os.P_PID, self.p.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)

    def output(self, quiet=False):
        if not select.select([self.p.stdout], [], [], 0)[0]:
            return b''
        try:
            data = os.read(self.p.stdout.fileno(), 16 * 1024)
        except BlockingIOError:
            return b''
        if not data:
            self.eof = True
        elif quiet and (raw_bytes + len(data) + 128 > RAW_LIMIT or gross + len(data) + 128 > GROSS):
            self.discarded_cleanup_bytes += len(data)
        else:
            charge(len(data))
            self.stream.write(data)
            self.stream.flush()
            log(self.name, data)
        return data

    def finish(self, kill=False):
        if self.reaped:
            return self.returncode
        if kill and not self.exited():
            # Popen.kill() may internally poll/reap on POSIX. Preserve the
            # WNOWAIT terminal process until exact /proc I/O was sampled.
            try:
                os.kill(self.p.pid, 9)
            except ProcessLookupError:
                pass
        cleanup_end = min(CLEANUP_END, time.monotonic() + 10)
        while not self.exited():
            self.output(quiet=kill)
            self.sample_io(enforce=not kill)
            if time.monotonic() >= cleanup_end:
                raise RuntimeError('owned child reap deadline')
            select.select([self.p.stdout], [], [], 0.02)
        while not self.eof:
            self.output(quiet=kill)
            if not self.eof:
                if time.monotonic() >= cleanup_end:
                    raise RuntimeError('owned stdout EOF deadline')
                select.select([self.p.stdout], [], [], 0.02)
        self.sample_io(enforce=not kill)  # WNOWAIT retains exact terminal /proc I/O until this sample.
        self.returncode = self.p.wait(timeout=1)
        self.reaped = True
        self.p.stdin.close()
        self.p.stdout.close()
        self.finished_at = time.monotonic()
        self.stream.close()
        return self.returncode


def command(argv, name, seconds=30):
    child = Owned(argv, name)
    end = min(END, time.monotonic() + seconds)
    data = bytearray()
    while not child.exited():
        data.extend(child.output())
        if len(data) > FRAME_LIMIT:
            raise RuntimeError('helper output bound')
        guard()
        if time.monotonic() >= end:
            raise RuntimeError('helper deadline')
        select.select([child.p.stdout], [], [], 0.02)
    while not child.eof:
        data.extend(child.output())
        if len(data) > FRAME_LIMIT:
            raise RuntimeError('helper terminal output bound')
        if not child.eof:
            guard()
            if time.monotonic() >= end:
                raise RuntimeError('helper stdout EOF deadline')
            select.select([child.p.stdout], [], [], 0.02)
    if child.finish() != 0:
        raise RuntimeError('helper failed: ' + name)
    return bytes(data)


def pin(path):
    data = read(path, 128 * 1024 * 1024 if Path(path) == ELF else 32 * 1024 * 1024)
    digest = hashlib.sha256(data).hexdigest()
    if path in PINS and digest != PINS[path]:
        raise RuntimeError('changed pinned input: ' + path)
    inputs[path] = {'sha256': digest, 'bytes': len(data)}
    return data


def entry(output, name, mode, data=b'', major=0, minor=0):
    encoded = name.encode() + b'\0'
    fields = [len(inputs) + len(name), mode, 0, 0, 1, 0, len(data), 0, 0,
              major, minor, len(encoded), 0]
    output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields))
    output.write(encoded)
    output.write(b'\0' * (-output.tell() % 4))
    output.write(data)
    output.write(b'\0' * (-output.tell() % 4))


INIT = r'''#!/bin/bash
set -u -f
export PATH=/bin LC_ALL=C
nonce= case_name= mode=
/bin/mount -t proc proc /proc || exit 71
/bin/mount -t sysfs sysfs /sys || exit 72
/bin/mount -t devtmpfs devtmpfs /dev || exit 73
for arg in $(</proc/cmdline); do
  case "$arg" in sunrise_nonce=*) nonce=${arg#*=};; sunrise_case=*) case_name=${arg#*=};; sunrise_mode=*) mode=${arg#*=};; esac
done
[[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || exit 74
case "$case_name" in ack|prepared|pre-finalize|source-write|source-flush|prepare-write|prepare-flush|finalize-write|finalize-flush) :;; *) exit 75;; esac
[[ "$mode" == fault || "$mode" == recover ]] || exit 75
discovery_end=$((SECONDS + 30))
while [[ ! -b /dev/vda1 || ! -b /dev/vdb1 || ! -r /sys/block/vda/serial || ! -r /sys/block/vdb/serial ]]; do
  (( SECONDS < discovery_end )) || exit 76
  IFS= read -r -t 0.05 ignored
  wait_result=$?
  (( wait_result > 128 )) || exit 76
done
source_serial=$(</sys/block/vda/serial)
authority_serial=$(</sys/block/vdb/serial)
[[ "$source_serial" == "s-${nonce:0:16}" && "$authority_serial" == "a-${nonce:0:16}" ]] || exit 76
/bin/mount -t ext4 -o rw /dev/vda1 /data || exit 77
/bin/mount -t ext4 -o rw /dev/vdb1 /authority || exit 77
found=0
while IFS= read -r line; do
  if [[ ( "$line" == *" /data "* && "$line" == *" - ext4 /dev/vda1 "* ) || ( "$line" == *" /authority "* && "$line" == *" - ext4 /dev/vdb1 "* ) ]]; then
    printf 'MOUNT nonce=%s %s\n' "$nonce" "$line"
    found=$((found+1))
  fi
done </proc/self/mountinfo
[[ "$found" == 2 ]] || exit 78
export SUNRISE_SQLITE_GUEST_PROFILE=native-sqlite-qemu-anchored-v1
export SUNRISE_WAL_GEOMETRY_PROBE=1
/bin/sqlite-tests --ignored --exact structured::ownership_tests::blob_crash::guest_fault::anchored::virtual_anchored_fault_guest --nocapture --test-threads=1
result=$?
printf 'INIT-EXIT nonce=%s case=%s mode=%s rc=%s\n' "$nonce" "$case_name" "$mode" "$result"
while IFS= read -r ignored; do :; done
'''


class Guest:
    def __init__(self, case, mode, nonce, source_image, authority_image, source=None, authority=None, source_partition=None):
        if any(not child.reaped and child.name.startswith('qemu-') for child in children):
            raise RuntimeError('another owned guest remains live')
        if case not in CASES or mode not in ['fault', 'recover'] or (mode == 'recover') != (source is not None and authority is not None):
            raise RuntimeError('closed guest launch shape')
        self.source_image = source_image
        self.authority_image = authority_image
        self.source_partition = source_partition
        image_identity(source_image, SOURCE_BYTES, active=True)
        image_identity(authority_image, AUTHORITY_BYTES, active=True)
        self.case = case
        self.mode = mode
        self.nonce = nonce
        self.name = case + '-' + mode
        self.started = time.monotonic()
        self.end = min(END, self.started + 140)
        self.serial = bytearray()
        self.qbuf = bytearray()
        self.messages = []
        self.events = []
        self.next_id = 0
        self.socket_path = ROOT / (self.name + '.qmp')
        self.socket_identity = None
        self.socket_captured_during_cleanup = False
        self.child = None
        if len(os.fsencode(self.socket_path)) >= 108 or os.path.lexists(self.socket_path):
            raise RuntimeError('owned QMP socket bound or previous allocation')
        cache = {'direct': True, 'no-flush': False}
        command_line = ('console=ttyS0 rdinit=/init panic=-1 loglevel=4 '
                        f'sunrise_profile=native-sqlite-qemu-anchored-v1 sunrise_nonce={nonce} '
                        f'sunrise_case={case} sunrise_mode={mode}')
        if source is not None:
            if not re.fullmatch(r'[0-9a-f]{32}', source) or not re.fullmatch(r'[0-9]{1,20}(:[0-9]{1,20}){3}', authority):
                raise RuntimeError('cold source/authority identity pin')
            command_line += ' sunrise_source=' + source + ' sunrise_authority=' + authority
        argv = ['/usr/bin/qemu-system-x86_64', '-no-user-config', '-nodefaults',
                '-machine', 'q35,accel=kvm', '-smp', '1', '-m', '512', '-nic', 'none',
                '-display', 'none', '-no-reboot', '-serial', 'stdio', '-monitor', 'none',
                '-qmp', f'unix:{self.socket_path},server=on,wait=off',
                '-kernel', str(ROOT / 'kernel'), '-initrd', str(ROOT / 'initrd.gz'),
                '-append', command_line]
        if mode == 'fault':
            self.trace_path = ROOT / (self.name + '.trace')
            argv += ['-trace', 'enable=bdrv_co_pwritev_part,file=' + str(self.trace_path)]
        for role, image, serial in [('source', source_image, 's-'), ('authority', authority_image, 'a-')]:
            argv += ['-blockdev', json.dumps({'driver': 'file', 'filename': str(image), 'node-name': role + '-file', 'cache': cache, 'aio': 'threads'}),
                     '-blockdev', json.dumps({'driver': 'raw', 'file': role + '-file', 'node-name': role + '-data', 'cache': cache}),
                     '-device', f'virtio-blk-pci,drive={role}-data,id={role},serial={serial}{nonce[:16]},write-cache=on,rerror=report,werror=report']
        if any(str(FORENSIC) in value for value in argv):
            raise RuntimeError('forensic authority must never be attached')
        guests.append(self)
        Owned(argv, 'qemu-' + self.name, guest=self)
        while not self.capture_socket():
            self.pump(serial_only=True)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(1)
        self.sock.connect(str(self.socket_path))
        self.sock.setblocking(False)
        self.until(lambda: any('QMP' in message for message in self.messages))
        self.qmp('qmp_capabilities')

    def capture_socket(self, cleanup=False):
        metadata = ROOT.lstat()
        if [metadata.st_dev, metadata.st_ino] != root_identity or stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.getuid():
            raise RuntimeError('private owner root attachment changed')
        try:
            metadata = self.socket_path.lstat()
        except FileNotFoundError:
            return False
        current = [metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode), metadata.st_uid, metadata.st_nlink]
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_nlink != 1:
            raise RuntimeError('unexpected QMP socket type/owner/link identity')
        if self.socket_identity is not None and current != self.socket_identity:
            raise RuntimeError('QMP socket attachment changed; refusing unlink')
        if self.socket_identity is None:
            if self.child is None:
                raise RuntimeError('QMP socket without tracked spawned allocation')
            # A constructor/log/pump error can occur before first discovery.
            # Admission was absent in this fresh0700 root, and the allocated
            # child is tracked before those operations. Capture once after its
            # reap, then still compare the attachment immediately before unlink.
            self.socket_identity = current
            self.socket_captured_during_cleanup = cleanup
        return True

    def cleanup_socket(self):
        present = self.capture_socket(cleanup=True)
        if present:
            if self.child is None or not self.child.reaped or Path(f'/proc/{self.child.p.pid}').exists():
                raise RuntimeError('refusing QMP unlink before actual child reap')
            self.capture_socket(cleanup=True)
            self.socket_path.unlink()
        if os.path.lexists(self.socket_path):
            raise RuntimeError('owned QMP socket remains')
        return {'absent': True, 'ownedIdentity': self.socket_identity,
                'firstCapturedDuringCleanup': self.socket_captured_during_cleanup}

    def pump(self, serial_only=False):
        guard()
        if time.monotonic() >= self.end:
            raise RuntimeError('guest absolute deadline')
        self.serial.extend(self.child.output())
        if len(self.serial) > RAW_LIMIT:
            raise RuntimeError('serial byte cap')
        failed = re.search(rb'INIT-EXIT nonce=' + self.nonce.encode() + rb' case=' + self.case.encode() +
                           rb' mode=' + self.mode.encode() + rb' rc=([1-9][0-9]*)', self.serial)
        if failed:
            raise RuntimeError('guest test exited nonzero before expected event: rc=' + failed.group(1).decode())
        if self.child.exited():
            raise RuntimeError('guest exited before owner completion')
        if not serial_only:
            try:
                data = self.sock.recv(FRAME_LIMIT + 1)
            except BlockingIOError:
                data = None
            if data == b'':
                raise RuntimeError('unexpected QMP EOF')
            if data:
                self.qbuf.extend(data)
                while b'\n' in self.qbuf:
                    frame, _, remaining = self.qbuf.partition(b'\n')
                    self.qbuf = bytearray(remaining)
                    if len(frame) > FRAME_LIMIT:
                        raise RuntimeError('QMP frame cap')
                    log('qmp-' + self.name, frame + b'\n')
                    message = json.loads(frame)
                    self.messages.append(message)
                    if 'event' in message:
                        self.events.append(message)
                if len(self.qbuf) > FRAME_LIMIT:
                    raise RuntimeError('partial QMP frame cap')
        sources = [self.child.p.stdout] if serial_only else [self.child.p.stdout, self.sock]
        select.select(sources, [], [], 0.02)

    def until(self, predicate):
        while not predicate():
            self.pump()

    def qmp(self, command, arguments=None):
        self.next_id += 1
        request = {'execute': command, 'id': self.next_id}
        if arguments is not None:
            request['arguments'] = arguments
        data = (json.dumps(request) + '\n').encode()
        if len(data) > FRAME_LIMIT:
            raise RuntimeError('QMP request cap')
        log('qmp-request-' + self.name, data)
        self.sock.sendall(data)
        self.until(lambda: any(message.get('id') == self.next_id for message in self.messages))
        result = next(message for message in self.messages if message.get('id') == self.next_id)
        if 'error' in result:
            raise RuntimeError('QMP error: ' + json.dumps(result['error']))
        return result['return']

    def graph(self, debug_role=None):
        graph = self.qmp('x-debug-query-block-graph')
        nodes = {node['name']: node['id'] for node in graph['nodes'] if node['type'] == 'block-driver'}
        for role in ['source', 'authority']:
            expected = 'fault-debug' if debug_role == role else role + '-file'
            if not any(edge['parent'] == nodes[role + '-data'] and edge['child'] == nodes[expected]
                       and edge['name'] == 'file' for edge in graph['edges']):
                raise RuntimeError('actual independently selected raw child graph differs')
        if debug_role is not None and not any(edge['parent'] == nodes['fault-debug'] and edge['child'] == nodes[debug_role + '-file']
                                              for edge in graph['edges']):
            raise RuntimeError('debug node does not own exact selected backing file')
        named = self.qmp('query-named-block-nodes')
        expected_nodes = {'source-data', 'source-file', 'authority-data', 'authority-file'}
        if debug_role is not None:
            expected_nodes.add('fault-debug')
        by_name = {item['node-name']: item for item in named}
        if len(by_name) != len(named) or set(by_name) != expected_nodes:
            raise RuntimeError('unexpected actual named block node inventory')
        cache_observations = {}
        for name, item in by_name.items():
            cache = item.get('cache')
            if not isinstance(cache, dict) or cache.get('direct') is not True or cache.get('no-flush') is not False:
                raise RuntimeError('actual direct/flush-honoring cache differs: ' + name)
            cache_observations[name] = cache
        files = {item['node-name']: item for item in named if item.get('drv') == 'file'}
        if set(files) != {'source-file', 'authority-file'}:
            raise RuntimeError('unexpected actual block file inventory')
        for role, image in [('source', self.source_image), ('authority', self.authority_image)]:
            if files[role + '-file'].get('file') != str(image):
                raise RuntimeError('actual backing file path differs from role pin')
        if str(FORENSIC) in json.dumps(named):
            raise RuntimeError('forensic authority appeared in actual block graph')
        return {'graph': graph, 'namedNodes': named, 'actualCacheByNode': cache_observations}

    def event(self, event):
        prefix = (f'SUNRISE-ANCHOR-GUEST v1 nonce={self.nonce} case={self.case} '
                  f'mode={self.mode} event={event} ').encode()
        pattern = re.compile(rb'(?:^|\n)' + re.escape(prefix) + rb'([^\r\n]*)\r?\n')
        self.until(lambda: pattern.search(self.serial) is not None)
        matches = pattern.findall(self.serial)
        if len(matches) != 1:
            raise RuntimeError('nonunique guest event')
        return matches[0].decode('ascii')

    def kill(self):
        global GUEST_SECONDS
        if hasattr(self, 'sock'):
            self.sock.close()
        status = self.child.finish(kill=True)
        if status != -9 or not self.child.eof or Path(f'/proc/{self.child.p.pid}').exists():
            raise RuntimeError('owned QEMU kill/reap/EOF/absence not observed')
        socket_cleanup = self.cleanup_socket()
        elapsed = self.child.finished_at - self.started
        if elapsed > 150:
            raise RuntimeError('guest budget including cleanup')
        GUEST_SECONDS += elapsed
        if GUEST_SECONDS > 1200:
            raise RuntimeError('aggregate guest-time ceiling')
        return {'qemuExit': status, 'stdoutEof': True, 'waitCompleted': True,
                'pidAbsent': True, 'qmpSocketAbsent': True,
                'seconds': time.monotonic() - self.started, 'io': self.child.io_final,
                'socketCleanup': socket_cleanup}

    def fault(self):
        initial = self.graph()
        detail = self.event('baseline')
        observed = re.fullmatch(r'source=([0-9a-f]{32}) authority=([0-9]{1,20}(:[0-9]{1,20}){3})', detail)
        if not observed:
            raise RuntimeError('independent pre-fault source/authority identity missing')
        result = {'case': self.case, 'nonce': self.nonce, 'source': observed.group(1),
                  'authorityIdentity': observed.group(2), 'initialGraph': initial}
        if self.case == 'ack':
            warmup = self.event('wal-warmup')
            if not re.fullmatch(r'busy=0 frames=[1-9][0-9]* checkpointed=[1-9][0-9]*', warmup):
                raise RuntimeError('complete SQLite WAL RESTART checkpoint missing')
            result['walWarmup'] = warmup
            result['walStat'] = self.event('wal-stat')
            geometry = self.event('wal-geometry')
            if not re.fullmatch(r'size=[0-9]+ partition_start=[0-9]+ logical_sector=[0-9]+ filefrag_hex=[0-9a-f]+ block4096_sha256=[0-9a-f,]+', geometry):
                raise RuntimeError('real SQLite WAL geometry frame missing')
            result['walGeometry'] = geometry
            self.child.p.stdin.write(f'release {self.nonce}\n'.encode())
            self.child.p.stdin.flush()
            if self.event('acknowledged') != 'authority=finalized':
                raise RuntimeError('caller ACK missing finalized authority')
        elif self.case == 'prepared':
            self.event('prepared-before-source')
        elif self.case == 'pre-finalize':
            self.event('source-committed')
        else:
            phase, kind = self.case.split('-')
            role = 'source' if phase == 'source' else 'authority'
            self.event('before-' + phase + '-commit')
            if self.case == 'source-write':
                warmup = self.event('wal-warmup')
                if not re.fullmatch(r'busy=0 frames=([1-9][0-9]*) checkpointed=\1', warmup):
                    raise RuntimeError('complete SQLite WAL RESTART checkpoint missing')
                result['walWarmup'] = warmup
                result['walStat'] = self.event('wal-stat')
                result['walGeometry'] = self.event('wal-geometry')
                result['walTarget'] = wal_target(result['walGeometry'], self.source_partition, self.nonce)
                pretrace = self.trace_path.read_bytes()
                charge(len(pretrace))
                first = result['walTarget']['firstImageOffset']
                pointers = re.findall(rb'bdrv_co_pwritev_part bs (0x[0-9a-f]+) offset ' +
                                      str(first).encode() + rb' bytes 4096 flags ', pretrace)
                if (not pretrace.endswith(b'\n') or len(pointers) < 2 or len(pointers) % 2 or
                        len(set(pointers)) != 2 or pointers[0] == pointers[1] or
                        any(pointer != pointers[0] for pointer in pointers[::2]) or
                        any(pointer != pointers[1] for pointer in pointers[1::2])):
                    raise RuntimeError('prearm source-data/source-file WAL trace pointer pair missing')
                result['prearmSourceFileTracePointer'] = pointers[1].decode()
            if phase == 'finalize':
                self.event('source-committed')
            rule = {'event': 'none', 'iotype': kind, 'errno': 5,
                    'sector': result['walTarget']['secondSector512'], 'once': True,
                    'immediately': False}
            self.qmp('blockdev-add', {'driver': 'blkdebug', 'node-name': 'fault-debug',
                                      'image': role + '-file', 'cache': {'direct': True, 'no-flush': False},
                                      'align': 4096, 'max-transfer': 4096, 'inject-error': [rule]})
            self.qmp('blockdev-reopen', {'options': [{'driver': 'raw', 'node-name': role + '-data', 'file': 'fault-debug',
                                                     'cache': {'direct': True, 'no-flush': False}}]})
            result['armedGraph'] = self.graph(debug_role=role)
            result['armedRule'] = rule
            result['selectedDeviceRole'] = role
            result['prearmTraceBytes'] = self.trace_path.stat().st_size
            self.child.p.stdin.write(f'release {self.nonce}\n'.encode())
            self.child.p.stdin.flush()
            error = self.event('commit-error')
            observed_error = re.fullmatch(r'phase=' + phase + r' extended=([0-9]{1,5})', error)
            actual = int(observed_error.group(1)) if observed_error else None
            if actual not in ((1034,) if kind == 'flush' else (778, 1034)):
                raise RuntimeError('actual SQLite phase COMMIT error differs: ' + error)
            self.until(lambda: any(event.get('event') == 'BLOCK_IO_ERROR' for event in self.events))
            matching = [event for event in self.events if event.get('event') == 'BLOCK_IO_ERROR'
                        and event.get('data', {}).get('node-name') == role + '-data'
                        and event.get('data', {}).get('action') == 'report'
                        and event.get('data', {}).get('reason') == 'Input/output error']
            if not matching:
                raise RuntimeError('actual selected device error missing')
            if b'event=acknowledged ' in self.serial:
                raise RuntimeError('phase EIO falsely acknowledged')
            if phase == 'prepare' and (b'event=source-dispatched ' in self.serial or b'event=source-committed ' in self.serial):
                raise RuntimeError('source dispatched after authority prepare failure')
            result.update({'sqliteExtendedCommitError': actual, 'blockIoErrors': matching})
        result['termination'] = self.kill()
        if self.case == 'source-write':
            if partition_identity(self.source_image) != self.source_partition:
                raise RuntimeError('source MBR changed after fault')
            target = result['walTarget']
            with self.source_image.open('rb') as source:
                source.seek(target['firstImageOffset'])
                durable = source.read(8192)
            charge(len(durable))
            if len(durable) != 8192:
                raise RuntimeError('short detached source WAL extent')
            first_sha = hashlib.sha256(durable[:4096]).hexdigest()
            old_second_prefix = durable[4096:4096 + target['oldSecondPrefixBytes']]
            second_prefix_sha = hashlib.sha256(old_second_prefix).hexdigest()
            if first_sha == target['oldBlockSha256'][0] or second_prefix_sha != target['oldBlockSha256'][1]:
                raise RuntimeError('mixed persistent real WAL bytes not demonstrated')
            trace = self.trace_path.read_bytes()
            charge(len(trace))
            if len(trace) > 8 * 1024 * 1024 or result['prearmTraceBytes'] >= len(trace):
                raise RuntimeError('bounded post-arm QEMU write trace missing')
            post = trace[result['prearmTraceBytes']:]
            first = target['firstImageOffset']
            if (f'offset {first} bytes 8192'.encode() not in post or
                    b'bdrv_co_pwritev_part bs ' + result['prearmSourceFileTracePointer'].encode() +
                    f' offset {first} bytes 4096 flags '.encode() not in post):
                raise RuntimeError('actual post-arm WAL 8KiB request/lower source-file first4KiB not traced')
            result['durableWal'] = {'first4096Sha256': first_sha,
                                    'secondOldPrefixSha256': second_prefix_sha,
                                    'second4096Sha256': hashlib.sha256(durable[4096:]).hexdigest(),
                                    'first4096Changed': True, 'secondOldPrefixUnchanged': True,
                                    'rawReadOnlyAfterGuestReaped': True}
            result['writeTrace'] = {'path': str(self.trace_path), 'bytes': len(trace),
                                    'sha256': hashlib.sha256(trace).hexdigest(),
                                    'prearmBytes': result['prearmTraceBytes'],
                                    'postarmSplitObserved': True}
        if self.case == 'ack':
            trace = self.trace_path.read_bytes()
            charge(len(trace))
            if len(trace) > 8 * 1024 * 1024 or b'bdrv_co_pwritev_part' not in trace:
                raise RuntimeError('bounded actual QEMU write trace missing')
            with self.source_image.open('rb') as source:
                mbr = source.read(512)
            charge(len(mbr))
            if len(mbr) != 512 or mbr[510:512] != b'\x55\xaa' or mbr[450] != 0x83:
                raise RuntimeError('source device partition table differs')
            partition_start, partition_sectors = struct.unpack_from('<II', mbr, 454)
            observed_start = int(re.search(r'partition_start=([0-9]+)', result['walGeometry']).group(1))
            if observed_start != partition_start or partition_start * 512 + partition_sectors * 512 != SOURCE_BYTES:
                raise RuntimeError('actual guest partition start differs from raw image MBR')
            result['actualPartition'] = {'start512Sector': partition_start,
                                         'sectorCount512': partition_sectors,
                                         'byteOffset': partition_start * 512}
            result['writeTrace'] = {'path': str(self.trace_path), 'bytes': len(trace),
                                    'sha256': hashlib.sha256(trace).hexdigest()}
        return result

    def recover(self):
        initial = self.graph()
        recovered = (f'SUNRISE-ANCHOR-GUEST v1 nonce={self.nonce} case={self.case} mode=recover event=recovered ').encode()
        stopped = recovered.replace(b'event=recovered ', b'event=stopped ')
        self.until(lambda: recovered in self.serial or stopped in self.serial)
        failstop = stopped in self.serial
        if failstop:
            detail = self.event('stopped')
            if detail != 'initial=none tables=12+2 authority=2 collections=4 bodies=2 fence=1 pending=2 repeated=3':
                raise RuntimeError('actual repeated Pending+old fail-stop oracle missing')
            if self.case not in ['prepared', 'source-write', 'source-flush', 'prepare-write', 'prepare-flush']:
                raise RuntimeError('unexpected stopped state for acknowledged/source-committed cut')
        else:
            detail = self.event('recovered')
            match = re.fullmatch(r'initial=(none|all) tables=12\+2 authority=2 collections=4 bodies=2 sequence=3 fence=2 anchor_sequence=4', detail)
            if not match:
                raise RuntimeError('cold complete anchored recovery/fresh-work oracle missing')
            if self.case == 'prepared' or (self.case.startswith('prepare-') and match.group(1) != 'none'):
                raise RuntimeError('source dispatched at before-source/failed-prepare cut')
            if self.case in ['ack', 'pre-finalize'] or self.case.startswith('finalize-'):
                if match.group(1) != 'all':
                    raise RuntimeError('successful real source COMMIT lost')
        exit_frame = f'INIT-EXIT nonce={self.nonce} case={self.case} mode=recover rc=0'.encode()
        self.until(lambda: exit_frame in self.serial and b'1 passed; 0 failed; 0 ignored;' in self.serial)
        return {'initialGraph': initial, 'oracle': detail, 'failstop': failstop,
                'actualGuestTestExit': 0, 'termination': self.kill()}


def image_identity(path, expected_bytes, active=False, mode=0o600):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != os.getuid() or metadata.st_size != expected_bytes or stat.S_IMODE(metadata.st_mode) != mode:
        raise RuntimeError('owned image identity differs')
    if active and (path.parent != ROOT or FORENSIC in path.parents):
        raise RuntimeError('only original active-role image paths may be attached')
    return {'path': str(path), 'bytes': metadata.st_size, 'device': metadata.st_dev, 'inode': metadata.st_ino}


def partition_identity(path):
    # Called only before a guest attaches or after it has been reaped.
    with path.open('rb') as source:
        mbr = source.read(512)
    charge(len(mbr))
    if len(mbr) != 512 or mbr[510:512] != b'\x55\xaa' or mbr[450] != 0x83:
        raise RuntimeError('source MBR partition identity missing')
    start, sectors = struct.unpack_from('<II', mbr, 454)
    if start == 0 or start * 512 + sectors * 512 != SOURCE_BYTES:
        raise RuntimeError('source MBR partition range differs')
    return {'start512Sector': start, 'sectorCount512': sectors, 'byteOffset': start * 512}


def wal_target(geometry, partition, nonce):
    matched = re.fullmatch(r'size=([0-9]+) partition_start=([0-9]+) logical_sector=([0-9]+) filefrag_hex=([0-9a-f]+) block4096_sha256=([0-9a-f,]+)', geometry)
    if not matched:
        raise RuntimeError('real SQLite WAL geometry frame missing')
    size, start, sector = map(int, matched.group(1, 2, 3))
    if not 4096 < size <= 8192 or start != partition['start512Sector'] or sector != 512:
        raise RuntimeError('WAL size/guest partition/device sector differs')
    mapping = bytes.fromhex(matched.group(4)).decode('ascii')
    if ('state.db-wal' not in mapping or nonce not in mapping or
            f'({(size + 4095) // 4096} blocks of 4096 bytes)' not in mapping or
            '1 extent found' not in mapping or
            any(flag in mapping for flag in ['unwritten', 'delalloc', 'unknown'])):
        raise RuntimeError('WAL FIEMAP file/block/extent flags differ')
    extent = re.search(r'^\s*0:\s*0\.\.\s*1:\s*([0-9]+)\.\.\s*([0-9]+):\s*2:.*last,eof\s*$', mapping, re.MULTILINE)
    if extent is None:
        raise RuntimeError('WAL lacks one stable two-block mapped extent')
    first, second = map(int, extent.groups())
    if second != first + 1:
        raise RuntimeError('WAL physical blocks not contiguous')
    hashes = matched.group(5).split(',')
    if len(hashes) != 2 or any(not re.fullmatch(r'[0-9a-f]{64}', value) for value in hashes):
        raise RuntimeError('two exact WAL preimage block hashes missing')
    first_offset = partition['byteOffset'] + first * 4096
    second_offset = first_offset + 4096
    if second_offset + 4096 > SOURCE_BYTES or second_offset % 512:
        raise RuntimeError('WAL target outside verified source partition')
    return {'walBytes': size, 'guestFilefrag': mapping, 'physicalExt4Blocks': [first, second],
            'firstImageOffset': first_offset, 'secondImageOffset': second_offset,
            'secondSector512': second_offset // 512, 'oldBlockSha256': hashes,
            'oldSecondPrefixBytes': size - 4096, 'partition': partition}


def image_hash(path, expected_bytes, mode=0o600):
    before = image_identity(path, expected_bytes, mode=mode)
    digest = hashlib.sha256()
    with path.open('rb') as reader:
        for _ in range(expected_bytes // (1024 * 1024)):
            chunk = reader.read(1024 * 1024)
            if len(chunk) != 1024 * 1024:
                raise RuntimeError('short owned immutable image')
            charge(len(chunk))
            digest.update(chunk)
            guard()
        if reader.read(1):
            raise RuntimeError('oversized image')
    if image_identity(path, expected_bytes, mode=mode) != before:
        raise RuntimeError('image identity changed during hash')
    return digest.hexdigest()


def copy_image(source, destination, expected_bytes, forensic=False):
    before = image_identity(source, expected_bytes)
    digest = hashlib.sha256()
    with source.open('rb') as reader, destination.open('xb') as writer:
        os.chmod(destination, 0o600)
        for _ in range(expected_bytes // (1024 * 1024)):
            chunk = reader.read(1024 * 1024)
            if len(chunk) != 1024 * 1024:
                raise RuntimeError('short immutable fault image')
            digest.update(chunk)
            charge(len(chunk) * 2)
            writer.write(chunk)
            guard()
        if reader.read(1):
            raise RuntimeError('oversized immutable fault image')
        writer.flush()
        os.fsync(writer.fileno())
    if image_identity(source, expected_bytes) != before:
        raise RuntimeError('source image attachment changed while copying')
    expected = digest.hexdigest()
    if image_hash(destination, expected_bytes) != expected:
        raise RuntimeError('fresh image copy differs')
    if forensic:
        if destination.parent != FORENSIC:
            raise RuntimeError('forensic copy outside its never-attached directory')
        os.chmod(destination, 0o400)
    return expected


def create_image(path, expected_bytes, name):
    with path.open('xb') as disk:
        os.chmod(path, 0o600)
        os.ftruncate(disk.fileno(), expected_bytes)
        sectors = expected_bytes // 512 - 2048
        mbr = bytearray(512)
        mbr[446:462] = struct.pack('<B3sB3sII', 0, b'\0\2\0', 0x83, b'\xfe\xff\xff', 2048, sectors)
        mbr[510:512] = b'\x55\xaa'
        disk.write(mbr)
        charge(len(mbr))
    command(['/usr/bin/mkfs.ext4', '-F', '-q', '-b', '4096', '-E',
             'offset=1048576,lazy_itable_init=0,lazy_journal_init=0', str(path), str((expected_bytes-1048576)//4096)], 'mkfs-' + name)
    return image_identity(path, expected_bytes, active=True)


def tree_inventory(root):
    result = {}
    count = 0
    for path in root.rglob('*'):
        count += 1
        if count > 128:
            raise RuntimeError('owned retained tree entry bound')
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError('symlink in retained owner tree')
        if stat.S_ISREG(metadata.st_mode):
            result[str(path)] = [metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns]
        elif not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISSOCK(metadata.st_mode)):
            raise RuntimeError('unexpected retained tree node')
    return result


def generated_bytes():
    return sum(value[2] for value in tree_inventory(ROOT).values())


def terminal_candidate(value, generated, prior, logical_io):
    # All accounting fields are fixed before publication. Their own decimal
    # widths are included by converging on the exact serialized byte count.
    result = dict(value)
    encoded = b''
    for _ in range(16):
        size = len(encoded)
        result['terminalBytes'] = size
        result['generatedBytesIncludingTerminal'] = generated + size
        result['aggregateRetainedBytesIncludingTerminal'] = prior + generated + size
        result['grossLogicalIoBytesIncludingTerminal'] = logical_io + size
        updated = (json.dumps(result, indent=2) + '\n').encode()
        if len(updated) == size:
            return result, updated
        encoded = updated
    raise RuntimeError('terminal accounting failed to converge')


def bounded_terminal(value, generated, prior, logical_io):
    def admitted(encoded):
        return (generated is not None and len(encoded) <= TERMINAL_LIMIT
                and generated + len(encoded) <= GENERATED
                and prior + generated + len(encoded) <= AGGREGATE_RETAINED
                and logical_io + len(encoded) <= GROSS)
    if generated is not None:
        result, encoded = terminal_candidate(value, generated, prior, logical_io)
        if admitted(encoded):
            return result, encoded
    else:
        encoded = (json.dumps(value, indent=2) + '\n').encode()
    compact = {
        'passed': False, 'attempt': args.attempt, 'terminalBoundError': True,
        'scope': 'Failed bounded anchored virtual-fault attempt; full receipt omitted',
        'error': str(value.get('error', 'terminal evidence bound exceeded'))[:2048],
        'fullReceiptSha256': hashlib.sha256(encoded).hexdigest(),
        'fullReceiptBytes': len(encoded), 'rawLogSha256': value.get('rawLogSha256'),
        'rawLogBytes': value.get('rawLogBytes'),
        'allOwnedChildrenReaped': value.get('allOwnedChildrenReaped'),
        'cleanupOutputComplete': value.get('cleanupOutputComplete'),
        'cleanupErrors': [str(error)[:512] for error in value.get('cleanupErrors', [])[:8]],
        'cgroupAfterCleanup': value.get('cgroupAfterCleanup'),
        'finalCgroupErrors': value.get('finalCgroupErrors'),
        'finalInventoryError': str(value.get('finalInventoryError'))[:512],
    }
    if generated is not None:
        compact, encoded = terminal_candidate(compact, generated, prior, logical_io)
        if admitted(encoded):
            return compact, encoded
    # No owned file is written when even the compact FAILED receipt would
    # cross a resource cap or the exact existing inventory cannot be proven.
    compact['terminalNotPublished'] = 'no proven room within exact retained/I/O caps'
    return compact, None


ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': str(ROOT),
       'TMPDIR': str(ROOT), 'QEMU_AUDIO_DRV': 'none'}
guests = []
created_root = False
receipt = {'scope': 'One real SQLite WAL sector-targeted partial persistent source-write attempt plus original-authority cold oracle on selected QEMU11/Arch pins; no broader M3 acceptance claim',
           'attempts': attempts, 'passed': False}

try:
    if ROOT.exists():
        raise RuntimeError('owned root already exists; no overwrite/retry')
    ROOT.mkdir(mode=0o700)
    created_root = True
    root_metadata = ROOT.lstat()
    root_identity = [root_metadata.st_dev, root_metadata.st_ino]
    receipt['hostKernelRelease'] = os.uname().release
    if receipt['hostKernelRelease'] != '7.2.15-arch1-1':
        raise RuntimeError('booted host kernel release differs from selected profile')
    FORENSIC.mkdir(mode=0o700)
    prior_inventory = {str(path): tree_inventory(path) for path in PRIOR_ROOTS}
    if sum(value[2] for entries in prior_inventory.values() for value in entries.values()) != PRIOR_BYTES:
        raise RuntimeError('retained earlier VM root size differs from reviewed accounting')
    receipt['priorRetainedRoots'] = prior_inventory
    receipt['aggregateRetainedLimitBytes'] = AGGREGATE_RETAINED
    LOG = (ROOT / 'raw.log').open('xb')
    group = Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]
    CG = Path('/sys/fs/cgroup') / group.lstrip('/')
    limits = {name: (CG / name).read_text().strip() for name in
              ['memory.max', 'memory.swap.max', 'cpu.max', 'pids.max']}
    if limits != {'memory.max': '1073741824', 'memory.swap.max': '0',
                  'cpu.max': '100000 100000', 'pids.max': '128'}:
        raise RuntimeError('incorrect actual cgroup limits: ' + repr(limits))
    receipt['cgroup'] = {'path': str(CG), 'limits': limits}
    guard()
    for path in PINS:
        pin(path)
    pin(str(Path(__file__).resolve()))
    pin('/usr/bin/ldd')
    config = gzip.decompress(read('/proc/config.gz')).decode()
    for name in ['VIRTIO_PCI', 'VIRTIO_BLK', 'EXT4_FS', 'JBD2', 'DEVTMPFS', 'SERIAL_8250_CONSOLE', 'MSDOS_PARTITION']:
        if f'CONFIG_{name}=y\n' not in config:
            raise RuntimeError('missing pinned built-in ' + name)
    copied = {}
    programs = ['/usr/bin/bash', '/usr/bin/mount', '/usr/bin/filefrag', str(ELF)]
    for index, program in enumerate(programs):
        copied['bin/' + ('sqlite-tests' if Path(program) == ELF else Path(program).name)] = pin(program)
        dependencies = command(['/usr/bin/ldd', program], 'ldd-' + str(index)).decode()
        if 'not found' in dependencies:
            raise RuntimeError('missing trusted dependency')
        for library in re.findall(r'(?:=>\s+)?(/[^\s]+)', dependencies):
            if library.lstrip('/') not in copied:
                copied[library.lstrip('/')] = pin(library)
    utility_bytes = sum(len(data) for name, data in copied.items() if name != 'bin/sqlite-tests')
    if utility_bytes > 32 * 1024 * 1024 or len(copied['bin/sqlite-tests']) > 128 * 1024 * 1024:
        raise RuntimeError('ELF/dependency byte ceiling')
    archive = io.BytesIO()
    for directory in ['.', 'bin', 'lib64', 'lib', 'usr', 'usr/lib', 'usr/lib64', 'proc', 'sys', 'dev', 'data', 'authority', 'tmp']:
        entry(archive, directory, stat.S_IFDIR | (0o1777 if directory == 'tmp' else 0o755))
    for name, data in copied.items():
        entry(archive, name, stat.S_IFREG | 0o755, data)
    entry(archive, 'init', stat.S_IFREG | 0o700, INIT.encode())
    for name, major, minor in [('console', 5, 1), ('null', 1, 3), ('zero', 1, 5)]:
        entry(archive, 'dev/' + name, stat.S_IFCHR | 0o600, major=major, minor=minor)
    entry(archive, 'TRAILER!!!', 0)
    if archive.tell() > 164 * 1024 * 1024:
        raise RuntimeError('uncompressed initramfs ceiling')
    compressed = gzip.compress(archive.getvalue(), mtime=0)
    if len(compressed) > 164 * 1024 * 1024:
        raise RuntimeError('compressed initramfs ceiling')
    write(ROOT / 'initrd.gz', compressed)
    receipt['initramfs'] = {'compressedBytes': len(compressed), 'uncompressedBytes': archive.tell(),
                            'elfBytes': len(copied['bin/sqlite-tests']), 'utilityLibraryBytes': utility_bytes}
    del compressed, archive, copied
    gc.collect()  # No retained archive/ELF buffers while a512MiB guest is live.
    write(ROOT / 'kernel', pin('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/qga1017a/kernel'))
    receipt['inputs'] = inputs
    for case in CASES:
        source_image = ROOT / (case + '-source.raw')
        authority_image = ROOT / (case + '-authority.raw')
        nonce = os.urandom(16).hex()
        attempts.append({'case': case, 'nonce': nonce, 'state': 'started'})
        source_identity = create_image(source_image, SOURCE_BYTES, case + '-source')
        authority_identity = create_image(authority_image, AUTHORITY_BYTES, case + '-authority')
        source_partition = partition_identity(source_image)
        fault = Guest(case, 'fault', nonce, source_image, authority_image,
                      source_partition=source_partition)
        fault_result = fault.fault()
        if image_identity(source_image, SOURCE_BYTES, active=True) != source_identity or image_identity(authority_image, AUTHORITY_BYTES, active=True) != authority_identity:
            raise RuntimeError('original source/authority attachment changed')
        forensic_path = FORENSIC / (case + '-authority.never-attach')
        forensic_hash = copy_image(authority_image, forensic_path, AUTHORITY_BYTES, forensic=True)
        immutable_images.append((forensic_path, AUTHORITY_BYTES, 0o400, forensic_hash))
        fault_result['authorityForensic'] = {'role': 'untrusted-never-attached-evidence', 'path': str(forensic_path), 'sha256': forensic_hash,
                                            'identity': image_identity(forensic_path, AUTHORITY_BYTES, mode=0o400)}
        recovery_image = source_image
        if '-' in case and case != 'pre-finalize':
            recovery_image = ROOT / (case + '-recover-source.raw')
            fault_result['immutableSourceImageSha256'] = copy_image(source_image, recovery_image, SOURCE_BYTES)
            immutable_images.append((source_image, SOURCE_BYTES, 0o600, fault_result['immutableSourceImageSha256']))
        cold = Guest(case, 'recover', nonce, recovery_image, authority_image,
                     fault_result['source'], fault_result['authorityIdentity'])
        recovery_result = cold.recover()
        if image_identity(authority_image, AUTHORITY_BYTES, active=True) != authority_identity:
            raise RuntimeError('cold recovery substituted original authority image')
        attempts[-1] = {'case': case, 'nonce': nonce, 'state': 'completed', 'fault': fault_result,
                        'recovery': recovery_result, 'sourceImage': source_identity,
                        'actualColdSource': image_identity(recovery_image, SOURCE_BYTES, active=True),
                        'actualColdAuthorityOriginal': authority_identity}
    for path, size, mode, expected in immutable_images:
        if image_hash(path, size, mode) != expected:
            raise RuntimeError('immutable source/never-attached authority evidence changed')
    receipt['authorityForensicCopiesNeverAttached'] = True

    for path, before in inputs.items():
        limit = 128 * 1024 * 1024 if Path(path) == ELF else 32 * 1024 * 1024
        if hashlib.sha256(read(path, limit)).hexdigest() != before['sha256']:
            raise RuntimeError('input changed after product run: ' + path)
    guard()
    receipt['cgroupAfter'] = cgroup_state()
    failures = cgroup_errors(receipt['cgroupAfter'], require_only_owner=True)
    if failures:
        raise RuntimeError('actual terminal cgroup resource violation: ' + repr(failures))
    receipt['passed'] = True
except BaseException as error:
    receipt['error'] = repr(error)
finally:
    for guest in guests:
        if hasattr(guest, 'sock'):
            guest.sock.close()
    for child in children:
        if not child.reaped:
            try:
                child.finish(kill=True)
            except BaseException as error:
                receipt.setdefault('cleanupErrors', []).append(repr(error))
    for guest in guests:
        try:
            cleanup = guest.cleanup_socket()
            receipt.setdefault('qmpSocketCleanup', []).append({'name': guest.name, **cleanup})
            if guest.child is not None and Path(f'/proc/{guest.child.p.pid}').exists():
                raise RuntimeError('guest process remains after cleanup')
        except BaseException as error:
            receipt.setdefault('cleanupErrors', []).append(repr(error))
    receipt['cleanupOutputComplete'] = not any(child.discarded_cleanup_bytes for child in children)
    if receipt.get('cleanupErrors') or not receipt['cleanupOutputComplete'] or not all(child.reaped and child.eof and not Path(f'/proc/{child.p.pid}').exists() for child in children):
        receipt['passed'] = False
    if LOG is not None:
        LOG.close()
        receipt['rawLogBytes'] = (ROOT / 'raw.log').stat().st_size
        raw = (ROOT / 'raw.log').read_bytes()
        charge(len(raw), enforce=False)
        receipt['rawLogSha256'] = hashlib.sha256(raw).hexdigest()
        del raw
    mounts = Path('/proc/self/mountinfo').read_text()
    receipt['ownedHostMountsAbsent'] = not any(str(ROOT) in line for line in mounts.splitlines())
    if not receipt['ownedHostMountsAbsent']:
        receipt['passed'] = False
    receipt['seconds'] = time.monotonic() - START
    receipt['aggregateGuestSeconds'] = sum(getattr(guest.child, 'finished_at', time.monotonic()) - guest.started for guest in guests if guest.child is not None)
    if receipt['aggregateGuestSeconds'] > 1200:
        receipt['passed'] = False
        receipt['aggregateGuestTimeExceeded'] = True
    receipt['grossLogicalIoBytes'] = gross
    receipt['controllerObservedIo'] = controller_io
    if gross > GROSS:
        receipt['passed'] = False
        receipt['grossIoExceeded'] = True
    if CG is not None:
        try:
            receipt['cgroupAfterCleanup'] = cgroup_state()
            peak_memory = max(peak_memory, int(receipt['cgroupAfterCleanup']['memory.peak']))
            failures = cgroup_errors(receipt['cgroupAfterCleanup'], require_only_owner=True)
            if failures:
                receipt['passed'] = False
                receipt['finalCgroupErrors'] = failures
        except BaseException as error:
            receipt['passed'] = False
            receipt['finalCgroupReadError'] = repr(error)
    receipt['memoryPeakBytes'] = peak_memory
    receipt['allOwnedChildrenReaped'] = all(child.reaped for child in children)
    receipt['ownedProcesses'] = [{'name': child.name, 'pid': child.p.pid, 'reaped': child.reaped,
                                 'eof': child.eof, 'pidAbsent': not Path(f'/proc/{child.p.pid}').exists(),
                                 'exit': getattr(child, 'returncode', None), 'io': child.io_final,
                                 'discardedCleanupBytes': child.discarded_cleanup_bytes} for child in children]
    try:
        if prior_inventory is not None and any(tree_inventory(path) != prior_inventory[str(path)] for path in PRIOR_ROOTS):
            raise RuntimeError('preserved earlier VM roots changed during final cleanup')
        receipt['generatedBytes'] = generated_bytes() if ROOT.exists() else 0
        receipt['aggregateRetainedBytesBeforeTerminal'] = receipt['generatedBytes'] + PRIOR_BYTES
        if receipt['aggregateRetainedBytesBeforeTerminal'] > AGGREGATE_RETAINED:
            receipt['passed'] = False
            receipt['aggregateRetentionExceeded'] = True
    except BaseException as error:
        receipt['passed'] = False
        receipt['generatedBytes'] = None
        receipt['finalInventoryError'] = repr(error)
    receipt, encoded = bounded_terminal(receipt, receipt['generatedBytes'], PRIOR_BYTES, gross)
    published = False
    if created_root and encoded is not None:
        with (ROOT / 'terminal.json').open('xb') as terminal:
            terminal.write(encoded)
        published = True
    # Publication is the final receipt operation; never mutate its status or
    # evidence after writing. The console reports the already-final decision.
    print(json.dumps({'passed': receipt['passed'], 'seconds': time.monotonic() - START,
                      'error': receipt.get('error'), 'terminalPublished': published,
                      'receipt': str(ROOT / 'terminal.json') if published else None}), flush=True)
sys.exit(0 if receipt['passed'] and not receipt.get('cleanupErrors') else 1)
