#!/usr/bin/env node
// DR-0284/0285: run an original ignored owner under disposable UIDs.
// This controller performs no build, download, host user change, or fixture assertion.
// Inputs are exact paths from clean-head Cargo JSON no-run/build receipts:
//   --target-debug ABS --harness ABS --operator-cargo-json ABS --cli-cargo-json ABS
//   --evidence-dir ABS_PRIVATE_DIR --expected-head 40_HEX
//   --tmpfs-mib N --memory-mib N --outer-seconds N [--profile readiness|recurring]
// The eight operator ELFs are copied by the existing Rust owner; the CLI ELF is
// executed directly beside the harness and is separately checked, not copied.

import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  lstatSync, readFileSync, realpathSync, statSync, writeFileSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const IMAGE = 'python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea';
const IMAGE_ID = 'sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea';
const BINARIES = [
  'business_cut', 'business_import', 'business_recovery', 'conditional_readiness',
  'ordered_seal', 'successor_activation', 'successor_host', 'sqlite_source_host',
];
const TESTS = {
  readiness: 'compiled_conditional_readiness_real_retention_restart_and_distinct_certificate',
  recurring: 'compiled_registered_replacement_and_recurring_successor_hosts',
};
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OWNER = randomUUID();
const NAME = `sunrise-readiness-1103-${OWNER}`;
const LABEL = 'sunrise-edge.readiness-fixture-owner';
const MAX_OUTPUT = 1024 * 1024;
const DOCKER_ENV = { ...process.env, DOCKER_HOST: 'unix:///var/run/docker.sock' };
for (const key of ['DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) {
  delete DOCKER_ENV[key];
}

function requirePath(value, label) {
  if (!value || !isAbsolute(value) || /[,'"\s\n\r]/.test(value)) {
    throw new Error(`${label} requires an absolute mount-safe path`);
  }
  return value;
}

function number(value, minimum, maximum, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return parsed;
}

function argumentsOf(argv) {
  const values = new Map();
  const allowed = new Set([
    '--target-debug', '--harness', '--operator-cargo-json', '--cli-cargo-json', '--evidence-dir',
    '--expected-head', '--tmpfs-mib', '--memory-mib', '--outer-seconds', '--profile',
  ]);
  if (argv.length !== 18 && argv.length !== 20) throw new Error('nine required controller inputs and one optional profile are allowed');
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    if (!allowed.has(key) || values.has(key) || argv[index + 1] === undefined) {
      throw new Error(`unknown, duplicate, or incomplete controller input: ${key}`);
    }
    values.set(key, argv[index + 1]);
  }
  for (const key of allowed) {
    if (key !== '--profile' && !values.has(key)) throw new Error(`missing controller input: ${key}`);
  }
  const profile = values.get('--profile') ?? 'readiness';
  if (!Object.hasOwn(TESTS, profile)) throw new Error('profile must be readiness or recurring');
  return {
    targetDebug: requirePath(values.get('--target-debug'), '--target-debug'),
    harness: requirePath(values.get('--harness'), '--harness'),
    operatorCargoJson: requirePath(values.get('--operator-cargo-json'), '--operator-cargo-json'),
    cliCargoJson: requirePath(values.get('--cli-cargo-json'), '--cli-cargo-json'),
    evidenceDir: requirePath(values.get('--evidence-dir'), '--evidence-dir'),
    expectedHead: values.get('--expected-head'),
    tmpfsMiB: number(values.get('--tmpfs-mib'), 128, 6144, '--tmpfs-mib'),
    memoryMiB: number(values.get('--memory-mib'), 512, 8192, '--memory-mib'),
    outerSeconds: number(values.get('--outer-seconds'), 60, 21600, '--outer-seconds'),
    profile,
  };
}

function command(name, args, { environment = process.env, timeoutMs = 10000, maxBytes = 65536 } = {}) {
  const result = spawnSync(name, args, {
    env: environment, encoding: 'utf8', timeout: timeoutMs, maxBuffer: maxBytes,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${name} ${args[0] ?? ''} failed: ${result.error?.message ?? (result.stderr ?? '').slice(0, 1024)}`);
  }
  return (result.stdout ?? '').trim();
}

function sha256(path) {
  const output = command('sha256sum', [path], { timeoutMs: 30000, maxBytes: 4096 });
  const hash = output.split(/\s+/)[0];
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`invalid sha256sum output for ${path}`);
  return hash;
}

function executable(path, label) {
  requirePath(path, label);
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || (before.mode & 0o111) === 0) {
    throw new Error(`${label} is not a regular executable`);
  }
  const hash = sha256(path);
  const after = lstatSync(path);
  if (!after.isFile() || after.isSymbolicLink() || after.dev !== before.dev
      || after.ino !== before.ino || after.size !== before.size
      || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs
      || after.mode !== before.mode || after.uid !== before.uid || after.gid !== before.gid) {
    throw new Error(`${label} changed while hashing`);
  }
  return {
    path, sha256: hash, bytes: before.size,
    uid: before.uid, gid: before.gid, mode: before.mode & 0o7777,
    device: before.dev, inode: before.ino,
  };
}

function closure(paths) {
  let interpreter;
  const libraries = new Map();
  for (const path of paths) {
    const output = command('ldd', [path], { timeoutMs: 10000, maxBytes: 65536 });
    if (output.includes('not found')) throw new Error(`missing ELF dependency for ${path}`);
    for (const line of output.split('\n')) {
      const match = line.match(/=>\s*(\/\S+)\s+\(0x/) ?? line.match(/^\s*(\/\S+)\s+\(0x/);
      if (!match) continue;
      const linked = requirePath(match[1], `ELF dependency of ${path}`);
      const source = realpathSync(linked);
      const name = basename(linked);
      if (name.startsWith('ld-linux') || name === 'ld.so') {
        if (interpreter && interpreter.target !== linked) throw new Error('ELF interpreter paths differ');
        interpreter = { source, target: linked };
      } else {
        const previous = libraries.get(name);
        if (previous && previous !== source) throw new Error(`ELF basename collision: ${name}`);
        libraries.set(name, source);
      }
    }
  }
  if (!interpreter) throw new Error('ELF interpreter not found');
  return { interpreter, libraries };
}

function cargoArtifacts(path, expected) {
  const stat = statSync(path);
  if (!stat.isFile() || stat.size > 64 * 1024 * 1024) throw new Error('Cargo JSON receipt is absent or too large');
  const raw = readFileSync(path, 'utf8');
  const artifacts = new Set();
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    let message;
    try { message = JSON.parse(line); } catch { throw new Error('Cargo receipt contains non-JSON output'); }
    if (message.reason === 'compiler-artifact' && typeof message.executable === 'string') {
      artifacts.add(resolve(message.executable));
    }
  }
  for (const binary of expected) {
    if (!artifacts.has(binary)) throw new Error(`Cargo receipt omits exact executable ${binary}`);
  }
  return createHash('sha256').update(raw).digest('hex');
}

function evidenceRoot(path) {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()
      || (stat.mode & 0o077) !== 0) {
    throw new Error('evidence directory must be an owned private directory');
  }
}

function dockerInspect(format, target, allowMissing = false) {
  const result = spawnSync('docker', ['inspect', '--format', format, target], {
    env: DOCKER_ENV, encoding: 'utf8', timeout: 10000, maxBuffer: 65536,
  });
  if (allowMissing && result.status !== 0 && !result.error
      && /No such (object|container)/i.test(result.stderr ?? '')) return null;
  if (result.error || result.status !== 0) throw new Error(`docker inspect failed: ${result.error?.message ?? result.stderr}`);
  return result.stdout.trim();
}

function cleanupContainer() {
  const inspected = dockerInspect('{{json .Config.Labels}}', NAME, true);
  if (inspected === null) return 'already-removed';
  const labels = JSON.parse(inspected);
  if (labels?.[LABEL] !== OWNER) throw new Error('owned container label mismatch; refusing removal');
  const image = dockerInspect('{{.Image}}', NAME);
  if (image !== IMAGE_ID) throw new Error('owned container image mismatch; refusing removal');
  command('docker', ['rm', '-f', NAME], { environment: DOCKER_ENV, timeoutMs: 15000 });
  if (dockerInspect('{{.Id}}', NAME, true) !== null) throw new Error('owned container remains after removal');
  return 'removed';
}

async function runContainer(args, outerSeconds) {
  const child = spawn('docker', args, { env: DOCKER_ENV, stdio: ['ignore', 'pipe', 'pipe'] });
  const stdout = [];
  const stderr = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let abortReason = null;
  const receive = (parts, chunk, channel) => {
    if (channel === 'stdout') stdoutBytes += chunk.length;
    else stderrBytes += chunk.length;
    if ((channel === 'stdout' ? stdoutBytes : stderrBytes) <= MAX_OUTPUT) parts.push(chunk);
    else if (!abortReason) {
      abortReason = `container ${channel} output exceeded ${MAX_OUTPUT} bytes`;
      child.kill('SIGTERM');
    }
  };
  child.stdout.on('data', (chunk) => receive(stdout, chunk, 'stdout'));
  child.stderr.on('data', (chunk) => receive(stderr, chunk, 'stderr'));
  const deadline = setTimeout(() => {
    abortReason ??= `container exceeded ${outerSeconds} seconds`;
    child.kill('SIGTERM');
  }, outerSeconds * 1000);
  const force = setTimeout(() => {
    if (abortReason) child.kill('SIGKILL');
  }, outerSeconds * 1000 + 5000);
  const result = await new Promise((resolveRun, rejectRun) => {
    child.on('error', rejectRun);
    child.on('close', (code, signal) => resolveRun({ code, signal }));
  }).finally(() => { clearTimeout(deadline); clearTimeout(force); });
  return {
    ...result, abortReason, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr),
    stdoutBytes, stderrBytes,
  };
}

let inputs;
let receipt;
let rawOut = Buffer.alloc(0);
let rawErr = Buffer.alloc(0);
let failure = null;
let cleanup = null;
try {
  inputs = argumentsOf(process.argv.slice(2));
  evidenceRoot(inputs.evidenceDir);
  if (!/^[0-9a-f]{40}$/.test(inputs.expectedHead)) throw new Error('--expected-head must be a 40-digit commit ID');
  const head = command('git', ['-C', REPO, 'rev-parse', 'HEAD']);
  const tree = command('git', ['-C', REPO, 'rev-parse', 'HEAD^{tree}']);
  if (head !== inputs.expectedHead || command('git', ['-C', REPO, 'status', '--porcelain']) !== '') {
    throw new Error('source is not the expected clean commit');
  }
  const debug = realpathSync(inputs.targetDebug);
  if (debug !== inputs.targetDebug) throw new Error('target debug path must be canonical');
  if (dirname(inputs.harness) !== join(debug, 'deps') || !basename(inputs.harness).startsWith('conditional_readiness_sqlite-')) {
    throw new Error('harness is outside the exact target/debug/deps profile');
  }
  const operatorPaths = [...BINARIES.map((name) => join(debug, name)), inputs.harness];
  const cliPath = join(debug, 'sunrise-edge-cli');
  // The existing successor acceptance helper signals its owned host through
  // this executable. Keep the tool in the fixture instead of changing that
  // shared test's process lifecycle for this protected-readiness addition.
  const killPath = '/usr/bin/kill';
  const paths = [...operatorPaths, cliPath, killPath];
  const artifacts = paths.map((path) => executable(path, basename(path)));
  const operatorCargoJsonSha256 = cargoArtifacts(inputs.operatorCargoJson, operatorPaths);
  const cliCargoJsonSha256 = cargoArtifacts(inputs.cliCargoJson, [cliPath]);
  const totalSnapshotBytes = artifacts.slice(0, BINARIES.length).reduce((sum, item) => sum + item.bytes, 0);
  const tmpfsBytes = inputs.tmpfsMiB * 1024 * 1024;
  if (tmpfsBytes < totalSnapshotBytes + 128 * 1024 * 1024 || inputs.memoryMiB < inputs.tmpfsMiB + 512) {
    throw new Error('selected tmpfs/memory cap is below exact ELF snapshots plus fixture reserve');
  }
  const linked = closure(paths);
  const image = command('docker', ['image', 'inspect', '--format', '{{.Id}}', IMAGE], {
    environment: DOCKER_ENV, timeoutMs: 10000,
  });
  if (image !== IMAGE_ID) throw new Error('pinned Docker image is absent or differs');
  receipt = {
    owner: OWNER, name: NAME, sourceHead: head, sourceTree: tree,
    operatorCargoJsonSha256, cliCargoJsonSha256,
    image: IMAGE, imageId: image, artifacts, tmpfsMiB: inputs.tmpfsMiB,
    memoryMiB: inputs.memoryMiB, outerSeconds: inputs.outerSeconds,
    profile: inputs.profile, selector: TESTS[inputs.profile],
    startedAt: new Date().toISOString(),
  };
  const mounts = [
    `type=bind,source=${debug},target=${debug},readonly`,
    `type=bind,source=${killPath},target=${killPath},readonly`,
    `type=bind,source=${linked.interpreter.source},target=${linked.interpreter.target},readonly`,
    ...[...linked.libraries].map(([name, source]) => `type=bind,source=${source},target=/mnt/libs/${name},readonly`),
  ];
  const dockerArgs = [
    'run', '--rm', '--pull=never', '--name', NAME, '--label', `${LABEL}=${OWNER}`,
    '--network=none', '--read-only', '--security-opt=no-new-privileges',
    '--cap-drop=ALL', '--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE',
    '--cap-add=SETUID', '--cap-add=SETGID', '--cap-add=KILL',
    '--cap-add=FOWNER',
    '--pids-limit=128', '--cpus=2',
    `--memory=${inputs.memoryMiB}m`, `--memory-swap=${inputs.memoryMiB}m`,
    '--log-driver=none', '--user=0:0',
    '--tmpfs', `/tmp:rw,nosuid,nodev,exec,size=${inputs.tmpfsMiB}m,nr_inodes=65536,mode=1777`,
    '-e', inputs.profile === 'recurring'
      ? 'SUNRISE_SUCCESSOR_MULTIUID_FIXTURE=1'
      : 'SUNRISE_READINESS_MULTIUID_FIXTURE=1',
    '-e', 'RUST_TEST_THREADS=1',
    '-e', 'RUST_BACKTRACE=1',
    '-e', 'LD_LIBRARY_PATH=/mnt/libs',
    ...mounts.flatMap((mount) => ['--mount', mount]),
    '--entrypoint', inputs.harness,
    IMAGE, '--ignored', '--exact', TESTS[inputs.profile], '--nocapture',
  ];
  receipt.mounts = mounts;
  const result = await runContainer(dockerArgs, inputs.outerSeconds);
  rawOut = result.stdout;
  rawErr = result.stderr;
  receipt.run = {
    code: result.code, signal: result.signal, abortReason: result.abortReason,
    stdoutBytes: result.stdoutBytes, stderrBytes: result.stderrBytes,
  };
  if (result.code !== 0 || result.abortReason) throw new Error('Docker owner did not exit successfully');
  if (!rawOut.toString('utf8').includes('1 passed')) throw new Error('exact ignored owner did not complete');
  if (inputs.profile === 'recurring' && !rawOut.toString('utf8').includes('successor_protected=distinct-uid')) {
    throw new Error('real protected successor role was not observed');
  }
} catch (error) {
  failure = String(error?.stack ?? error);
} finally {
  try { cleanup = cleanupContainer(); } catch (error) {
    cleanup = `failed: ${String(error?.stack ?? error)}`;
    failure ??= 'owned container cleanup failed';
  }
  if (inputs?.evidenceDir) {
    const prefix = join(inputs.evidenceDir, `${inputs.profile}-multiuid-${OWNER}`);
    const final = {
      ...(receipt ?? { owner: OWNER, name: NAME }),
      finishedAt: new Date().toISOString(), cleanup,
      failure,
    };
    writeFileSync(`${prefix}.stdout`, rawOut, { flag: 'wx', mode: 0o600 });
    writeFileSync(`${prefix}.stderr`, rawErr, { flag: 'wx', mode: 0o600 });
    writeFileSync(`${prefix}.json`, `${JSON.stringify(final, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    process.stdout.write(`${prefix}.json\n`);
  }
}
if (failure) {
  process.stderr.write(`${failure}\n`);
  process.exitCode = 1;
}
