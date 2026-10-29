#!/usr/bin/python3
"""Prepare a separate fixed-tool profile; never launch product commands."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import time

B = Path('/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013')
OLD = 'm2-m3-next-final-full-required-1022'
NEW = 'm2-m3-stable-full-required-1022'
BIN = B / ('bin-' + NEW)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def put(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def record(path):
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}


def write(path, text, mode=0o600):
    with path.open('x') as stream:
        stream.write(text)
    path.chmod(mode)


def main():
    os.umask(0o077)
    prior = json.loads((B / (OLD + '-closed-proof.json')).read_text())
    assert prior['state'] == 'CLOSED_FAILED_NO_GATE_ACCEPTANCE'
    assert prior['sourceBodyPhaseClosed'] and prior['resourcePhaseClosed']
    assert not prior['cgroupMembers'] and prior['mainPidAbsent']
    assert not Path(prior['cgroupPathObserved']).exists()
    assert not BIN.exists() and not list(B.glob(NEW + '-*'))
    old_plan_path = B / (OLD + '-prelaunch-plan.json')
    old_config_path = B / (OLD + '-config.json')
    assert sha(old_plan_path) == '590f0ae770347225b0cf04064d68743005992f61786a65a448ebcc1b83cb2c0e'
    assert sha(old_config_path) == 'c3aaf457e4131762f7e66407eff65d56ebed8cde93ceabb3296650851ffff71f'
    assert sha(B / (OLD + '-parent-prelaunch.json')) == 'adbcd268690858da1c10b47f7e3e18fbe916cb045483509a7c803eb49a08aa27'
    assert sha(B / (OLD + '-terminal.json')) == '39bcc74d8d8b67e683a189e4410ef85f2c0007237f2020664fc23c85ed1079bd'
    old_plan = json.loads(old_plan_path.read_text())
    for path, wanted in old_plan['artifacts'].items():
        assert record(Path(path)) == wanted, path
    old_terminal = json.loads((B / (OLD + '-terminal.json')).read_text())
    for name, wanted in old_terminal['wrapperSha256Before'].items():
        assert sha(B / ('bin-' + OLD) / name) == wanted, name
    old_owner_path = B / (OLD + '-owner.py')
    old_owner = runpy.run_path(str(old_owner_path))
    old_config = json.loads(old_config_path.read_text())
    for key in ('sourceIndex', 'sourceBridge', 'runtimeInputs', 'deviceRebindingProof',
                'privateCfManifest', 'archiveMap'):
        assert sha(Path(old_config[key + 'Path'])) == old_config[key + 'Sha256'], key
    old_owner['source_inputs'](old_config)
    assert old_owner['git']('rev-parse', 'HEAD') == old_config['sourceHead']
    assert not old_owner['git']('status', '--porcelain')
    deno = B / 'm2-m3-stable-runtime-1022/deno'
    preparation = json.loads((deno.parent / 'prepare-receipt.json').read_text())
    assert preparation['state'] == 'completed'
    assert preparation['zipSha256Actual'] == 'c24f955d9fbfe0ea5ae2b501c8e71ae76e31e4c9782390a54a284b3364fda725'
    assert sha(deno) == preparation['binarySha256'] == '1d97ecaf9e6bbb2a99e991caaf64ba9d62bf98759e8ef9938b9005855772b017'
    BIN.mkdir(mode=0o700)
    for name in ('node', 'npm', 'npx'):
        write(BIN / name, (B / ('bin-' + OLD) / name).read_text(), 0o700)
    (BIN / 'deno').symlink_to(deno)
    (BIN / 'python3.14').symlink_to('/usr/bin/python3.14')
    (BIN / 'python3').symlink_to('/usr/bin/python3.14')
    replacements = {
        '/home/linuxbrew/.linuxbrew/Cellar/deno/2.9.5/bin/deno': str(deno),
        '/home/linuxbrew/.linuxbrew/bin/deno': str(BIN / 'deno'),
        '/home/linuxbrew/.linuxbrew/Cellar/python@3.14/3.14.7/bin/python3.14': str(BIN / 'python3.14'),
        '/home/linuxbrew/.linuxbrew/bin/python3': str(BIN / 'python3'),
    }
    runtime = json.loads(Path(old_config['runtimeInputsPath']).read_text())
    assert len(runtime['tools']) == 2390 and len(runtime['strictNonCfTools']) == 67
    end = time.monotonic() + 180
    unchanged = 0
    for path, wanted in runtime['strictNonCfTools'].items():
        if path not in replacements:
            assert old_owner['fixed_tool_record'](Path(path), end) == wanted, path
            unchanged += 1
    assert unchanged == 63
    before_runtime = copy.deepcopy(runtime)
    changed_roles = []
    for before, after in replacements.items():
        assert before in runtime['tools'] and before in runtime['strictNonCfTools']
        assert after not in runtime['tools'] and after not in runtime['strictNonCfTools']
        old_hash = runtime['tools'].pop(before)
        old_identity = runtime['strictNonCfTools'].pop(before)
        current = old_owner['fixed_tool_record'](Path(after), end)
        runtime['tools'][after] = current['sha256']
        runtime['strictNonCfTools'][after] = current
        changed_roles.append({'oldPath': before, 'oldSha256': old_hash,
                              'oldIdentity': old_identity, 'newPath': after,
                              'newIdentity': current})
    runtime['aliasBindings'] = {
        str(BIN / name): old_owner['tool_identity'](BIN / name, end)
        for name in ('node', 'npm', 'npx')
    }
    runtime['state'] = 'EXPLICIT_NEW_DENO_2_9_4_SYSTEM_PYTHON_PROFILE_PRIOR_FAILURE_RETAINED'
    runtime['attribution']['sourceBridgeSha256'] = old_config['sourceBridgeSha256']
    runtime['attribution']['embeddedPythonTransportBytes'] = 246128
    runtime['attribution']['embeddedPythonTransportRemaining'] = 16016
    runtime['attribution']['runtimeRepair'] = 'Four explicit one-to-one tool-role replacements; all other roles unchanged.'
    assert len(runtime['tools']) == 2390 and len(runtime['strictNonCfTools']) == 67
    assert runtime['counts'] == before_runtime['counts']
    repair_path = B / (NEW + '-runtime-repair.json')
    put(repair_path, {'state': 'NEW_PROFILE_NOT_RETROACTIVE_OLD_RUN_ACCEPTANCE',
        'priorFailedReceipt': record(B / (OLD + '-terminal.json')),
        'priorClosedProof': record(B / (OLD + '-closed-proof.json')),
        'priorRuntimeInputs': record(Path(old_config['runtimeInputsPath'])),
        'historicalDeviceRebindingProof': record(Path(old_config['deviceRebindingProofPath'])),
        'historicalProofScope': 'Historical device mapping only; not evidence for the four new tool-role bindings.',
        'replacements': changed_roles, 'unchangedStrictRoles': unchanged,
        'preservedCounts': runtime['counts'], 'officialDenoPreparation': record(deno.parent / 'prepare-receipt.json'),
        'sourceHead': old_config['sourceHead'], 'sourceTree': old_config['sourceTree'],
        'sourceIndexSha256': old_config['sourceIndexSha256'],
        'noGlobalToolChanges': True, 'noWorktreeOrCacheCopy': True,
        'priorGuardWaived': False, 'fullGateAcceptance': False})
    runtime['deviceRebindingProofSha256'] = sha(repair_path)
    runtime_path = B / (NEW + '-runtime-inputs.json')
    put(runtime_path, runtime)
    config = copy.deepcopy(old_config)
    config.update({'state': 'NEW_STABLE_LOCAL_PROFILE_AFTER_FAILED_TOOL_INVARIANCE',
        'runtimeInputsPath': str(runtime_path), 'runtimeInputsSha256': sha(runtime_path),
        'deviceRebindingProofPath': str(repair_path), 'deviceRebindingProofSha256': sha(repair_path),
        'runtimeRepairProofPath': str(repair_path), 'runtimeRepairProofSha256': sha(repair_path)})
    config_path = B / (NEW + '-config.json')
    put(config_path, config)
    owner_text = old_owner_path.read_text().replace("FAMILY = '" + OLD + "'", "FAMILY = '" + NEW + "'")
    hash_pattern = r"(CONFIG_SHA256\s*=\s*)['\"][0-9a-f]{64}['\"]"
    owner_text, count = re.subn(hash_pattern, lambda m: m[1] + repr(sha(config_path)), owner_text)
    assert count == 1
    owner_path = B / (NEW + '-owner.py')
    ast.parse(owner_text)
    write(owner_path, owner_text)
    for name in ('cargo', 'cf'):
        text = (B / ('bin-' + OLD) / name).read_text().replace(OLD + '-config.json', NEW + '-config.json')
        text, count = re.subn(hash_pattern, lambda m: m[1] + repr(sha(config_path)), text)
        assert count == 1
        ast.parse(text)
        write(BIN / name, text, 0o700)
    new_owner = runpy.run_path(str(owner_path))
    assert new_owner['source_inputs'](config) == old_owner['source_inputs'](old_config)
    runtime_preflight = new_owner['private_inputs'](config, end)
    assert runtime_preflight['toolAndSeedHashesVerified'] == 2396
    assert len(new_owner['archive_snapshot'](config, end)) == 311
    for key in config['directories']:
        new_owner['checked_directory'](config, key)
    # Reuse the exact finite resource properties and two literal commands.
    argv = [item.replace(OLD, NEW) for item in old_plan['futureLaunchArgvForParentOnly']]
    paths = [owner_path, config_path, runtime_path, repair_path,
             Path(config['sourceIndexPath']), Path(config['sourceBridgePath']),
             Path(config['privateCfManifestPath']), Path(config['archiveMapPath'])]
    paths.extend(BIN / name for name in ('cargo', 'cf', 'node', 'npm', 'npx'))
    plan = {'state': 'ROOT_PREPARED_NOT_LAUNCHED',
        'sourceHead': config['sourceHead'], 'sourceTree': config['sourceTree'],
        'trackedFiles': config['trackedFileCount'], 'runtimePreflight': runtime_preflight,
        'artifacts': {str(path): record(path) for path in paths},
        'futureLaunchArgvForParentOnly': argv,
        'literalCommands': new_owner['COMMANDS'],
        'bounds': {'workSeconds': 26000, 'cleanupSeconds': 300, 'unitSeconds': 26300,
                   'memoryBytes': 12884901888, 'swapBytes': 0, 'cpu': 4, 'tasks': 512},
        'sourceAndCacheReuse': 'Same b389 source and existing target/cache, no copies.',
        'noAutomaticRetry': True, 'oldFailedOwnerPreserved': True,
        'bodyReadOrder': 'After launch, only the sole local owner reads source/cache/target/tool bodies until physical closure.',
        'excludedScopesUnchanged': True, 'parentM2M3Acceptance': False}
    plan_path = B / (NEW + '-prelaunch-plan.json')
    put(plan_path, plan)
    approval_path = B / (NEW + '-parent-prelaunch.json')
    put(approval_path, {'state': 'ROOT_PREPARED_FOR_SEPARATE_REVIEW_BEFORE_LAUNCH',
        'planSha256': sha(plan_path), 'coreArtifacts': plan['artifacts'],
        'sourceHead': config['sourceHead'], 'sourceTree': config['sourceTree'],
        'runtimeRepairProofSha256': sha(repair_path), 'bounds': plan['bounds'],
        'literalCommands': new_owner['COMMANDS'], 'automaticRetry': False,
        'oldFailedOwnerPreserved': True})
    for kind in ('capture', 'close'):
        text = (B / (OLD + '-' + kind + '.py')).read_text().replace(OLD, NEW)
        text, count = re.subn(r"(PARENT_PRELAUNCH_SHA256=)'[0-9a-f]{64}'",
                             lambda m: m[1] + repr(sha(approval_path)), text)
        assert count == 1
        if kind == 'capture':
            line = "    plan=json.loads((BASE/(FAMILY+'-prelaunch-plan.json')).read_text())"
            assert text.count(line) == 1
            text = text.replace(line,
                "    approved=json.loads(approval.read_text())\n"
                "    if sha(BASE/(FAMILY+'-prelaunch-plan.json'))!=approved['planSha256']: raise RuntimeError('reviewed plan changed')\n" + line)
        ast.parse(text)
        write(B / (NEW + '-' + kind + '.py'), text)
    print(json.dumps({'family': NEW, 'state': plan['state'], 'plan': record(plan_path),
                      'config': record(config_path), 'runtimePreflight': runtime_preflight,
                      'noProductCommandsExecuted': True}, sort_keys=True))


if __name__ == '__main__':
    main()
