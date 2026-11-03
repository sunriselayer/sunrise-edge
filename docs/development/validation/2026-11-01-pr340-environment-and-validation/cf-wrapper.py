#!/usr/bin/env -S /usr/bin/python3.14 -I -B
"""Private validation-only cf version/types view; empty HOME, no API/deploy command."""
import hashlib,json,os,pathlib,re,stat,sys,time
from pathlib import Path
ROOT = pathlib.Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-m2-m3-followup-1021')
BASE = pathlib.Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013')
CONFIG = pathlib.Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-signing-env-1101-wrapper-core.json')
CONFIG_SHA256 = 'f2cc3560b382411513040f447c08330268b88ac50bf6bdf860207cdd644c5f8e'
TOOLS = pathlib.Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-signing-env-1101-cf-closure.json')
TOOLS_SHA256 = '9a4a2b4930909282aae2327f14a7be8e36f29f7d333fd03d721225aa3495e9be'
NODE = pathlib.Path('/home/yu/.nvm/versions/node/v24.19.0/bin/node')
CF_PACKAGE = pathlib.Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/manual-cf-isolation-1019-v4-private/rootfs/home/yu/.local/share/pnpm/global/v11/194b48-18dd09e1dc445024-0/node_modules/.pnpm/cf@1.0.0-beta.13/node_modules/cf')
CF_CONFIG_PACKAGE = pathlib.Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/manual-cf-isolation-1019-v4-private/rootfs/home/yu/.local/share/pnpm/global/v11/194b48-18dd09e1dc445024-0/node_modules/.pnpm/@cloudflare+config@0.24.0/node_modules/@cloudflare/config')
PRIVATE_CF_ROLE_COUNT = 2347
PRIVATE_ROOT = pathlib.Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/manual-cf-isolation-1019-v4-private')
PRIVATE_MIRROR = pathlib.Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/manual-cf-isolation-1019-v4-private/rootfs')
PRIVATE_LAYOUT_ENTRY_COUNT = 2725

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

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def digest(path, end):
    value = hashlib.sha256()
    with path.open('rb') as handle:
        while True:
            require(time.monotonic() < end, 'input hash deadline')
            chunk = handle.read(256 * 1024)
            if not chunk:
                break
            value.update(chunk)
    return value.hexdigest()

def identity(path, end):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= 512 * 1024**2,
            'bounded regular input required: ' + str(path))
    result = {'sha256': digest(path, end), 'length': before.st_size,
              'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid,
              'gid': before.st_gid, 'nlink': before.st_nlink,
              'device': before.st_dev, 'inode': before.st_ino,
              'mtimeNs': before.st_mtime_ns, 'ctimeNs': before.st_ctime_ns}
    after = path.lstat()
    fields = ('st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid', 'st_gid',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    require(all(getattr(before, k) == getattr(after, k) for k in fields),
            'input changed during hashing: ' + str(path))
    return result

def tool_identity(path, end):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode), 'tool entry type differs')
    configured = {'device': before.st_dev, 'inode': before.st_ino, 'uid': before.st_uid,
                  'gid': before.st_gid, 'mode': stat.S_IMODE(before.st_mode), 'nlink': before.st_nlink,
                  'length': before.st_size, 'mtimeNs': before.st_mtime_ns, 'ctimeNs': before.st_ctime_ns,
                  'type': 'symlink' if stat.S_ISLNK(before.st_mode) else 'file'}
    link = os.readlink(path) if stat.S_ISLNK(before.st_mode) else None
    require(link is None or len(os.fsencode(link)) <= 4096, 'tool link target bound')
    resolved = path.resolve(strict=True)
    actual = identity(resolved, end)
    after = path.lstat()
    require(all(getattr(before, k) == getattr(after, k) for k in
                ('st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')) and
            path.resolve(strict=True) == resolved and
            (link is None or os.readlink(path) == link), 'tool alias changed during hashing')
    return {'configured': configured, 'linkTarget': link, 'resolvedPath': str(resolved), 'resolved': actual}

def private_layout_snapshot(expected, end):
    require(len(expected) == PRIVATE_LAYOUT_ENTRY_COUNT,
            'fixed private cf layout entry count differs')
    observed = {}
    pending = [PRIVATE_ROOT]
    while pending:
        require(time.monotonic() < end, 'private cf layout deadline')
        path = pending.pop()
        require(str(path) in expected and str(path) not in observed,
                'unexpected private cf layout entry')
        before = path.lstat()
        kind = ('symlink' if stat.S_ISLNK(before.st_mode) else
                'directory' if stat.S_ISDIR(before.st_mode) else
                'file' if stat.S_ISREG(before.st_mode) else 'unsupported')
        require(kind != 'unsupported', 'unsupported private cf layout entry')
        value = {'device': before.st_dev, 'inode': before.st_ino,
                 'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid,
                 'gid': before.st_gid, 'nlink': before.st_nlink,
                 'length': before.st_size, 'mtimeNs': before.st_mtime_ns,
                 'ctimeNs': before.st_ctime_ns, 'type': kind}
        if kind == 'directory':
            require(path.resolve(strict=True) == path and
                    (path == PRIVATE_ROOT or path.is_relative_to(PRIVATE_MIRROR)),
                    'private cf directory route differs')
            with os.scandir(path) as entries:
                for entry in entries:
                    require(time.monotonic() < end and
                            len(observed) + len(pending) < PRIVATE_LAYOUT_ENTRY_COUNT,
                            'private cf layout bound')
                    pending.append(pathlib.Path(entry.path))
        elif kind == 'symlink':
            link = os.readlink(path)
            require(not os.path.isabs(link) and len(os.fsencode(link)) <= 4096,
                    'private cf link must remain bounded and relative')
            resolved = path.resolve(strict=True)
            require(resolved.is_relative_to(PRIVATE_MIRROR),
                    'private cf link resolved outside mirror')
            value.update({'linkTarget': link, 'resolvedPath': str(resolved)})
        else:
            require(path.resolve(strict=True) == path and
                    path.is_relative_to(PRIVATE_MIRROR),
                    'private cf file route differs')
        after = path.lstat()
        require(all(getattr(before, field) == getattr(after, field) for field in
                    ('st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid',
                     'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')) and
                (kind != 'symlink' or (os.readlink(path) == value['linkTarget'] and
                 str(path.resolve(strict=True)) == value['resolvedPath'])),
                'private cf layout entry changed while observing')
        observed[str(path)] = value
    require(set(observed) == set(expected) and observed == expected,
            'private cf full layout metadata/link route differs')

def main():
    settings = load_config()  # First guard precedes observations/outputs/exec.
    for key in settings['directories']:
        checked_directory(settings, key)
    deadline = time.monotonic() + 60
    require(digest(TOOLS, deadline) == TOOLS_SHA256, 'fixed private cf closure input index differs')
    manifest = json.loads(TOOLS.read_text())
    require(manifest['privateRoot'] == str(PRIVATE_ROOT) and
            manifest['privateMirror'] == str(PRIVATE_MIRROR),
            'fixed private cf layout roots differ')
    private_layout_snapshot(manifest['layout'], deadline)
    expected = manifest['tools']
    require(len(expected) == PRIVATE_CF_ROLE_COUNT and
            {str(p): tool_identity(pathlib.Path(p), deadline) for p in expected} == expected,
            'private cf closure configured/resolved metadata or bodies differ')
    adapter = ROOT / 'adapters/cloudflare-workers'
    cwd = pathlib.Path.cwd().resolve()
    argv = sys.argv[1:]
    raw_output = None
    if argv == ['--version']:
        require(cwd == adapter, 'cf version cwd differs')
    elif argv == ['workers', 'types', '--include-runtime=false']:
        require(cwd in {adapter / 'profiles' / name for name in
                        ('ingress', 'validator', 'certified', 'sql', 'contract')},
                'cf types profile cwd differs')
        raw_output = cwd / '.cloudflare'
        if not raw_output.exists():
            raw_output.mkdir(mode=0o700)
        metadata = raw_output.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid() and
                not metadata.st_mode & 0o022 and raw_output.resolve() == raw_output,
                'profile raw output directory differs')
    else:
        raise RuntimeError('only exact cf version and five-profile types commands are admitted')
    # Reuse the actual CF4 installed-module view. An empty private HOME/XDG and
    # exact read-only version/types command carry no account/API operation.
    # The original317 pins are entrypoint/body provenance, not a claim that
    # config's external zod/runtime-types dependency closure fits those317.
    command = ['/usr/bin/bwrap', '--die-with-parent', '--new-session', '--unshare-net',
               '--unshare-pid', '--ro-bind', '/', '/',
               '--tmpfs', '/tmp', '--tmpfs', '/home/yu/.cargo',
               '--tmpfs', '/home/yu/.local/share/pnpm',
               '--proc', '/proc', '--dev', '/dev', '--dir', '/tmp/cf-required-home']
    if raw_output is not None:
        command += ['--bind', str(raw_output), str(raw_output)]
    environment = {'PATH': str(NODE.parent) + ':/usr/bin:/bin',
                   'HOME': '/tmp/cf-required-home',
                   'XDG_CONFIG_HOME': '/tmp/cf-required-home/config',
                   'XDG_CACHE_HOME': '/tmp/cf-required-home/cache',
                   'TMPDIR': '/tmp', 'LANG': 'C.UTF-8', 'CI': 'true', 'NO_COLOR': '1',
                   'CF_SEND_TELEMETRY': 'false', 'DO_NOT_TRACK': '1'}
    command += ['--chdir', str(cwd), '--', str(NODE), str(CF_PACKAGE / 'bin/cf')] + argv
    os.execve(command[0], command, environment)

if __name__ == '__main__':
    main()
