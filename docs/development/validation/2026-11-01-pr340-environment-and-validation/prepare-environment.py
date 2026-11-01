#!/usr/bin/python3.14 -I -B
"""Create only a new ordinary-validation namespace after strict read-only admission."""
import ast
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

BASE = Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013')
SOURCE = Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-m2-m3-followup-1021')
PREFIX = 'm2-signing-env-1101'
HEAD = '2e2c10fe0c360f99400be79ee50cad18f5e2336f'
OLD_CORE = BASE / 'maintenance-six-1028-wrapper-core.json'
OLD_CF = BASE / 'maintenance-dedup-1027-cf-closure-device52.json'
OLD_DRIVER = BASE / 'm2-signing-map-1031-driver.py'
OLD_BIN = BASE / 'maintenance-six-1028-bin'
END = time.monotonic() + 600
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def bounded():
    require(time.monotonic() < END, 'finite preparation deadline')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    bounded()
    return path.read_bytes()


def write(path, data, executable=False):
    require(path.parent == BASE or path.parent == BASE / (PREFIX + '-bin'), 'new namespace parent required')
    require(path.name.startswith(PREFIX) or path.parent.name == PREFIX + '-bin', 'new namespace name required')
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o700 if executable else 0o600)
    return {'path': str(path), 'sha256': sha(data), 'bytes': len(data)}


def write_json(path, value):
    return write(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def metadata(value, kind=False):
    row = {'device': value.st_dev, 'inode': value.st_ino, 'uid': value.st_uid, 'gid': value.st_gid,
           'mode': stat.S_IMODE(value.st_mode), 'nlink': value.st_nlink, 'length': value.st_size,
           'mtimeNs': value.st_mtime_ns, 'ctimeNs': value.st_ctime_ns}
    if kind:
        row['type'] = 'symlink' if stat.S_ISLNK(value.st_mode) else 'directory' if stat.S_ISDIR(value.st_mode) else 'file' if stat.S_ISREG(value.st_mode) else 'unsupported'
    return row


def file_identity(path):
    bounded()
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= 512 * 1024**2, 'bounded regular input required: ' + str(path))
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while True:
            bounded()
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    after = path.lstat()
    require(all(getattr(before, key) == getattr(after, key) for key in FIELDS), 'input changed during hashing: ' + str(path))
    return {**metadata(before), 'sha256': digest.hexdigest()}


def tool_identity(path):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode), 'ordinary tool entry required')
    link = os.readlink(path) if path.is_symlink() else None
    resolved = path.resolve(strict=True)
    value = {'configured': metadata(before, True), 'linkTarget': link,
             'resolvedPath': str(resolved), 'resolved': file_identity(resolved)}
    after = path.lstat()
    require(all(getattr(before, key) == getattr(after, key) for key in FIELDS) and
            path.resolve(strict=True) == resolved and (link is None or os.readlink(path) == link), 'tool entry changed while hashing')
    return value


def device_only(expected, actual, label, old_device, current_device):
    adjusted = copy.deepcopy(expected)
    count = 0
    def walk(value):
        nonlocal count
        if isinstance(value, dict):
            for key, child in value.items():
                if key == 'device':
                    if child == old_device:
                        value[key] = current_device
                        count += 1
                else:
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(adjusted)
    require(adjusted == actual, 'non-device metadata/content/route difference: ' + label)
    return count


def layout_snapshot(expected, private_root, private_mirror):
    observed = {}
    pending = [private_root]
    while pending:
        bounded()
        path = pending.pop()
        require(str(path) in expected and str(path) not in observed, 'unexpected private closure layout entry')
        before = path.lstat()
        value = metadata(before, True)
        kind = value['type']
        require(kind != 'unsupported', 'unsupported private closure entry')
        if kind == 'directory':
            require(path.resolve(strict=True) == path and (path == private_root or path.is_relative_to(private_mirror)), 'private directory route differs')
            with os.scandir(path) as entries:
                for entry in entries:
                    require(len(observed) + len(pending) < len(expected), 'private closure layout count bound')
                    pending.append(Path(entry.path))
        elif kind == 'symlink':
            link = os.readlink(path)
            require(not os.path.isabs(link) and len(os.fsencode(link)) <= 4096, 'closed relative link required')
            resolved = path.resolve(strict=True)
            require(resolved.is_relative_to(private_mirror), 'private link escaped closed mirror')
            value.update({'linkTarget': link, 'resolvedPath': str(resolved)})
        else:
            require(path.resolve(strict=True) == path and path.is_relative_to(private_mirror), 'private file route differs')
        after = path.lstat()
        require(all(getattr(before, key) == getattr(after, key) for key in FIELDS) and
                (kind != 'symlink' or os.readlink(path) == value['linkTarget']), 'layout entry changed during observation')
        observed[str(path)] = value
    require(set(observed) == set(expected), 'private closure inventory differs')
    return observed


def git(args):
    bounded()
    result = subprocess.run(['/usr/bin/git', '-C', str(SOURCE)] + args, check=True, capture_output=True,
                            timeout=min(30, END - time.monotonic()),
                            env={'HOME': '/home/yu', 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
    require(len(result.stdout) <= 8 * 1024**2 and len(result.stderr) <= 1024**2, 'git metadata output bound')
    return result.stdout


def source_snapshot():
    head = git(['rev-parse', 'HEAD']).decode().strip()
    tree = git(['rev-parse', 'HEAD^{tree}']).decode().strip()
    require(head == HEAD and git(['status', '--porcelain=v1', '--untracked-files=normal']) == b'', 'expected clean final PR source required')
    files = {}
    total = 0
    for row in git(['ls-files', '--stage', '-z']).split(b'\0'):
        if not row:
            continue
        header, raw = row.split(b'\t', 1)
        mode, blob, stage = header.decode().split()
        relative = os.fsdecode(raw)
        require(stage == '0' and len(files) < 8192 and len(raw) <= 4096 and relative not in files and
                not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'ordinary bounded tracked inventory required')
        path = SOURCE / relative
        if mode == '120000':
            require(path.is_symlink(), 'tracked link differs')
            data = os.fsencode(os.readlink(path))
            value = {'sha256': sha(data), 'size': len(data)}
        else:
            require(mode in ('100644', '100755') and not path.is_symlink(), 'tracked file mode differs')
            identity = file_identity(path)
            value = {'sha256': identity['sha256'], 'size': identity['length']}
        s = path.lstat()
        value['metadata'] = [s.st_dev, s.st_ino, stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
        total += value['size']
        require(total <= 1024**3, 'tracked source byte bound')
        files[relative] = {'mode': mode, 'gitBlob': blob, **value}
    return {'head': head, 'tree': tree, 'clean': True, 'trackedFileCount': len(files), 'files': files}


def main():
    os.umask(0o077)
    require(not any(p.name.startswith(PREFIX) and p.name != PREFIX + '-prepare.py' and
                    not p.name.startswith(PREFIX + '-root-') and not p.name.startswith(PREFIX + '-ci-')
                    for p in BASE.iterdir()), 'exclusive new namespace required')
    parent_paths = [OLD_CORE, OLD_CF, OLD_DRIVER, BASE / 'm2-signing-map-1031-run-v1-verified.json']
    root_state = BASE / (PREFIX + '-root-state-before.json')
    require(sha(read(root_state)) == '8dab7c923ac5ca0c1105eea774f63cf0dabf655ef81097a682fbe0ef87fbd47d', 'root independent state receipt differs')
    parent_paths.append(root_state)
    old_core = json.loads(read(OLD_CORE))
    old_runtime_path = Path(old_core['runtimeInputsPath'])
    parent_paths.append(old_runtime_path)
    parent_paths += [OLD_BIN / name for name in ('node', 'npm', 'npx', 'cargo', 'cf', 'python3')]
    parents = {str(p): {'sha256': sha(read(p)), 'bytes': p.stat().st_size} for p in parent_paths}
    require(parents[str(OLD_CORE)]['sha256'] == '97ef73687d2ed11a692418ed45be447a09d2f1fb926c687900daff2c8b03e4c1', 'retained core hash differs')
    require(parents[str(OLD_CF)]['sha256'] == '8ceee07cbd07993a808edba96aba91d6974f1f1d8b9e823f27c19c886b86bd6c', 'retained CF closure hash differs')
    require(parents[str(old_runtime_path)]['sha256'] == old_core['runtimeInputsSha256'], 'retained runtime manifest differs')
    old_device = old_core['directories']['target']['pin'][0]
    current_device = (SOURCE / 'target').lstat().st_dev
    require(old_device != current_device, 'explicit device transition expected')
    directories = copy.deepcopy(old_core['directories'])
    directory_deltas = {}
    for key, row in directories.items():
        path = Path(row['path']); s = path.lstat()
        actual = [s.st_dev, s.st_ino, s.st_uid, stat.S_IMODE(s.st_mode)]
        require(row['pin'][0] == old_device and actual[0] == current_device and row['pin'][1:] == actual[1:] and
                stat.S_ISDIR(s.st_mode) and path.resolve() == path, 'non-device retained directory mismatch: ' + key)
        directory_deltas[key] = {'path': str(path), 'parentPin': row['pin'], 'currentPin': actual}
        row['pin'] = actual
    mount = subprocess.run(['/usr/bin/findmnt', '-J', '-T', str(SOURCE), '-o', 'TARGET,SOURCE,FSTYPE,MAJ:MIN,FSROOT,UUID,OPTIONS'],
                           check=True, capture_output=True, timeout=30).stdout
    mount_value = json.loads(mount)
    source = source_snapshot()
    old_cf = json.loads(read(OLD_CF))
    private_root = Path(old_cf['privateRoot']); private_mirror = Path(old_cf['privateMirror'])
    require(len(old_cf['tools']) == 2347 and len(old_cf['layout']) == 2725, 'retained exact CF inventory counts differ')
    def verify_cf():
        layout = layout_snapshot(old_cf['layout'], private_root, private_mirror)
        layout_deltas = sum(device_only(old_cf['layout'][p], value, p, old_device, current_device) for p, value in layout.items())
        tools = {p: tool_identity(Path(p)) for p in old_cf['tools']}
        tool_deltas = sum(device_only(old_cf['tools'][p], value, p, old_device, current_device) for p, value in tools.items())
        covered = {value['resolvedPath'] for value in tools.values()}
        regular = {p for p, value in layout.items() if value['type'] == 'file'}
        require(len(regular) == 2335 and regular.issubset(covered), 'every private regular file must actually be rehashed')
        return layout, tools, {'layoutDeviceLeaves': layout_deltas, 'toolDeviceLeaves': tool_deltas,
                               'privateRegularFilesRehashed': len(regular), 'toolRolesRehashed': len(tools)}
    layout, tools, counts = verify_cf()
    old_runtime = json.loads(read(old_runtime_path))
    runtime = copy.deepcopy(old_runtime)
    for row in runtime['tools']:
        if row['name'] == 'cf-closure-manifest':
            continue
        actual = tool_identity(Path(row['path']))
        require(actual['resolvedPath'] == row['resolvedPath'] and actual['resolved']['sha256'] == row['sha256'], 'retained runtime resolution/body differs: ' + row['name'])
        row['admittedIdentity'] = actual
    # A second complete CF hash+layout pass closes the observed transition.
    layout_again, tools_again, counts_again = verify_cf()
    require(layout == layout_again and tools == tools_again and counts == counts_again, 'CF closure changed across complete admission passes')
    require(source == source_snapshot(), 'source changed during environment admission')
    for path, expected in parents.items():
        require(sha(read(Path(path))) == expected['sha256'], 'retained parent changed during preparation: ' + path)
    transition = {'schema': 1, 'state': 'VERIFIED_DEVICE_ONLY_TRANSITION', 'observedUtc': datetime.datetime.now(datetime.UTC).isoformat(),
                  'parentDevice': old_device, 'currentDevice': current_device, 'mount': mount_value,
                  'directoryDeltas': directory_deltas, 'cfParent': {'path': str(OLD_CF), **parents[str(OLD_CF)]},
                  'cfAllowedDelta': 'Only layout.device, tools.configured.device and tools.resolved.device leaves equal to parentDevice change to currentDevice; other devices remain exact. Every other key/value, body hash, size, UID/GID, mode, inode, timestamps, link and route compared equal.',
                  'cfVerification': {**counts, 'completeHashAndLayoutPasses': 2, 'allOtherFieldsEqual': True},
                  'historicalFilesystemUuidNotPresentInParentManifest': True, 'sourceHead': HEAD}
    artifacts = {}
    def put(label, suffix, value):
        artifacts[label] = write_json(BASE / (PREFIX + suffix), value)
        return artifacts[label]
    transition_ref = put('transition', '-device-transition.json', transition)
    cf = copy.deepcopy(old_cf)
    cf['layout'] = layout; cf['tools'] = tools; cf['sourceRoot'] = str(SOURCE)
    cf['state'] = 'CURRENT_SOURCE_DEVICE_TRANSITION_FULLY_REHASHED'
    cf['provenance']['currentDeviceTransition'] = transition_ref
    cf_ref = put('cfManifest', '-cf-closure.json', cf)
    for row in runtime['tools']:
        if row['name'] == 'cf-closure-manifest':
            row.update({'path': cf_ref['path'], 'resolvedPath': cf_ref['path'], 'sha256': cf_ref['sha256'],
                        'admittedIdentity': tool_identity(Path(cf_ref['path']))})
    runtime['note'] = 'Every retained executable resolution/body hash verified; current entry/resolved identities recorded. Only CF-manifest path/hash points to the new fully rehashed device-transition manifest. Version execution is delegated to root; no runtime or test was launched by preparation.'
    runtime_ref = put('runtimeInputs', '-runtime-inputs.json', runtime)
    source_ref = put('sourceIndex', '-source-index.json', source)
    core = copy.deepcopy(old_core)
    core.update({'sourceHead': HEAD, 'sourceTree': source['tree'], 'sourceIndexPath': source_ref['path'],
                 'sourceIndexSha256': source_ref['sha256'], 'trackedFileCount': source['trackedFileCount'],
                 'runtimeInputsPath': runtime_ref['path'], 'runtimeInputsSha256': runtime_ref['sha256'], 'directories': directories})
    core_ref = put('core', '-wrapper-core.json', core)
    new_bin = BASE / (PREFIX + '-bin'); new_bin.mkdir(mode=0o700)
    replacements = [(str(OLD_CORE), core_ref['path']), (parents[str(OLD_CORE)]['sha256'], core_ref['sha256'])]
    wrapper_changes = {}
    for name in ('node', 'npm', 'npx', 'cargo', 'cf', 'python3'):
        original = read(OLD_BIN / name)
        data = original.decode()
        if name in ('cargo', 'cf'):
            for old, new in replacements:
                require(data.count(old) == 1, 'exact wrapper declaration replacement required: ' + name)
                data = data.replace(old, new)
        if name == 'cf':
            for old, new in [(str(OLD_CF), cf_ref['path']), (parents[str(OLD_CF)]['sha256'], cf_ref['sha256'])]:
                require(data.count(old) == 1, 'exact CF declaration replacement required')
                data = data.replace(old, new)
        if name in ('cargo', 'cf'):
            ast.parse(data, filename=str(new_bin / name))
        artifacts['wrapper-' + name] = write(new_bin / name, data.encode(), True)
        wrapper_changes[name] = {'parentSha256': sha(original), 'newSha256': sha(data.encode()),
                                 'allowedDelta': 'Only fixed core path/hash' + (' and CF-manifest path/hash' if name == 'cf' else '') if name in ('cargo', 'cf') else 'byte-identical copy'}
    admission = {'schema': 1, 'state': 'PREPARED_REHASHED_ENVIRONMENT_ROOT_LAUNCH_PENDING', 'sourceHead': HEAD,
                 'sourceTree': source['tree'], 'parents': parents, 'artifacts': artifacts, 'wrapperChanges': wrapper_changes,
                 'exactAllowedDeltas': {'core': ['sourceHead', 'sourceTree', 'sourceIndexPath', 'sourceIndexSha256', 'trackedFileCount', 'runtimeInputsPath', 'runtimeInputsSha256', 'directories.*.pin[0]'],
                    'cfManifest': ['layout.*.device', 'tools.*.configured.device', 'tools.*.resolved.device', 'sourceRoot', 'state', 'provenance.currentDeviceTransition'],
                    'runtimeInputs': ['note', 'tools.*.admittedIdentity additions', 'cf-closure-manifest path/resolvedPath/sha256 only'],
                    'driver': ['new namespace paths/pins', 'enforce prepared source and runtime identities before/after; preserve all selectors/env/budgets']},
                 'noTestsCompilersInstallsNetworkOrCredentialOperations': True, 'rootIndependentFilesystemAndToolValidationRequired': True}
    admission_ref = put('admission', '-admission.json', admission)
    driver = read(OLD_DRIVER).decode()
    driver = driver.replace("BIN = BASE / 'maintenance-six-1028-bin'", "BIN = BASE / '" + PREFIX + "-bin'")
    driver = driver.replace('m2-signing-map-1031-run-', PREFIX + '-run-').replace('m2-signing-map-1031-[A-Za-z0-9_.-]+', PREFIX + '-[A-Za-z0-9_.-]+')
    for name, delta in wrapper_changes.items():
        if delta['parentSha256'] != delta['newSha256']:
            require(driver.count(delta['parentSha256']) == 1, 'one old driver wrapper pin required')
            driver = driver.replace(delta['parentSha256'], delta['newSha256'])
    constants = '\nADMITTED_HEAD = ' + repr(HEAD) + '\nINPUT_PINS = ' + repr({ref['path']: ref['sha256'] for key, ref in artifacts.items() if not key.startswith('wrapper-')}) + '\n'
    driver = driver.replace('\nSTOP_SIGNAL = None\n', '\nSTOP_SIGNAL = None\n' + constants)
    driver = driver.replace("self.head = args.head\n", "self.head = args.head\n        require(self.head == ADMITTED_HEAD, '--head differs from admitted final source')\n")
    old_setup = "        paths = [SOURCE / 'target', SOURCE / 'target/recipe-tmp', CACHE]\n"
    extra_setup = """        self.result['inputsBefore'] = self.admitted_inputs()
        core = json.loads(Path(""" + repr(core_ref['path']) + """).read_text())
        for key, row in core['directories'].items():
            path = Path(row['path']); s = path.lstat()
            require(row['pin'] == [s.st_dev, s.st_ino, s.st_uid, stat.S_IMODE(s.st_mode)] and path.resolve() == path,
                    'admitted directory identity differs: ' + key)
""" + old_setup
    require(driver.count(old_setup) == 1, 'driver setup insertion point differs')
    driver = driver.replace(old_setup, extra_setup)
    method = """    def admitted_inputs(self, final=False):
        end = self.hard_end if final else self.work_end
        values = {}
        for path, expected in INPUT_PINS.items():
            value = self.file_digest(Path(path), end)
            require(value['sha256'] == expected, 'admitted metadata file differs: ' + path)
            values[path] = value
        core = json.loads(Path(""" + repr(core_ref['path']) + """).read_text())
        for key, row in core['directories'].items():
            path = Path(row['path']); s = path.lstat()
            pin = [s.st_dev, s.st_ino, s.st_uid, stat.S_IMODE(s.st_mode)]
            require(row['pin'] == pin and stat.S_ISDIR(s.st_mode) and path.resolve() == path,
                    'admitted directory identity differs: ' + key)
            values['directory:' + key] = pin
        runtime = json.loads(Path(""" + repr(runtime_ref['path']) + """).read_text())
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

"""
    driver = driver.replace('    def snapshot(self, label, final=False):\n', method + '    def snapshot(self, label, final=False):\n')
    driver = driver.replace('before.st_size <= 256 * 1024**2', 'before.st_size <= 512 * 1024**2')
    driver = driver.replace("            files[relative] = {'mode': mode, 'gitBlob': blob, **value}\n", "            s = path.lstat()\n            value['metadata'] = [s.st_dev, s.st_ino, stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]\n            files[relative] = {'mode': mode, 'gitBlob': blob, **value}\n")
    driver = driver.replace("        self.result[label] = save(self.output / (label + '.json'), value)\n", "        require(value == json.loads(Path(" + repr(source_ref['path']) + ").read_text()), 'source differs from admitted complete source index')\n        self.result[label] = save(self.output / (label + '.json'), value)\n")
    driver = driver.replace("            self.result['wrappersAfter'] = self.wrappers(True)\n", "            self.result['inputsAfter'] = self.admitted_inputs(True)\n            require(self.result['inputsBefore'] == self.result['inputsAfter'], 'admitted inputs changed during validation')\n            self.result['wrappersAfter'] = self.wrappers(True)\n")
    ast.parse(driver, filename=PREFIX + '-driver.py')
    artifacts['driver'] = write(BASE / (PREFIX + '-driver.py'), driver.encode(), True)
    require(source == source_snapshot(), 'source changed before preparation closed')
    require(all(sha(read(Path(p))) == value['sha256'] for p, value in parents.items()), 'old artifact changed before preparation closed')
    bundle = {'schema': 1, 'preparedUtc': datetime.datetime.now(datetime.UTC).isoformat(), 'sourceHead': HEAD,
              'sourceTree': source['tree'], 'state': 'PREPARED_ONLY_NOT_EXECUTED', 'artifacts': artifacts,
              'preparer': {'path': str(Path(__file__)), 'sha256': sha(read(Path(__file__)))},
              'verifiedDifferences': {**counts, 'directoryPins': len(directories), 'deviceTransition': [old_device, current_device]},
              'writerClosed': True, 'remainingGate': 'Root independent review/admission, then new full-required execution; no prior success inherited.'}
    bundle_ref = write_json(BASE / (PREFIX + '-bundle.json'), bundle)
    print(json.dumps({'bundle': bundle_ref, 'driver': artifacts['driver'], 'sourceHead': HEAD, 'verifiedDifferences': bundle['verifiedDifferences']}, indent=2))


if __name__ == '__main__':
    main()
