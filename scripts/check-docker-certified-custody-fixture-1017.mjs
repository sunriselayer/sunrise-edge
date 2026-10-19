#!/usr/bin/env node
// ADR0271 selected certified FastVote component fixture. No build, download,
// host user/service change or networked Docker profile. All inputs are explicit.
// See docs/architecture/local-certified-protocol-custody-fixture.md for provenance schema.
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { createReadStream, lstatSync, readFileSync, realpathSync } from 'node:fs';
import { basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { deflateSync, inflateSync } from 'node:zlib';

const image = 'python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea';
const imageId = 'sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea';
const endpoint = 'unix:///var/run/docker.sock';
const owner = randomUUID();
const name = `sunrise-edge-certified-custody-1017-${owner}`;
const label = 'sunrise-edge.certified-custody-1017-owner';
const volumeName = `${name}-memory`;
const volumeOptions = 'rw,nosuid,nodev,noexec,size=64m,nr_inodes=16384,mode=0755,uid=0,gid=0,noswap';
const deadline = performance.now() + 280_000;
const outputLimit = 65_536;
const cleanupReserve = 16_384;
const pendingClients = new Set();
const clientRecords = [];
const clientMetadataBytesPerRecord = 512;
let clientMetadataBytes = 0;
const dockerEnvironment = { ...process.env };
for (const key of ['DOCKER_CONTEXT', 'DOCKER_HOST', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete dockerEnvironment[key];
let outputBytes = 0;
let containerId;
let volumeExpected = false;
let volumeMountpoint;
let volumeCreateAttempted = false;
let containerCreateAttempted = false;
let volumeCreateAmbiguous = false;
let containerCreateAmbiguous = false;
let primaryError;
let result;
let cleanupVerified = false;
let sourcePin;
let failureCapture;
let inventoryOnly = false;
let resultTransport;

function require_(condition, message) { if (!condition) throw new Error(message); }
function mountSafe(path) {
  require_(path.startsWith('/') && !/["',\s\0]/u.test(path), 'input path is not safe for an exact mount');
  require_(realpathSync(path) === path, 'input path must be its exact resolved path');
  return path;
}
function boundedText(path, cap) {
  const info = lstatSync(path);
  require_(info.isFile() && !info.isSymbolicLink() && info.size <= cap, 'bounded regular input required');
  const bytes = readFileSync(path);
  require_(bytes.length <= cap, 'input grew beyond bound');
  return bytes;
}
async function inventory(path, executable = false) {
  path = mountSafe(path);
  const info = lstatSync(path, { bigint: true });
  require_(info.isFile() && info.size <= 512n * 1024n * 1024n, 'regular immutable input exceeds512MiB');
  const mode = Number(info.mode & 0o7777n);
  if (executable) require_(mode === 0o755 && info.uid === BigInt(process.geteuid()) && info.nlink === 1n,
    'retained compiled ELF must keep normal0755/current effective UID/single-link ownership');
  else require_((mode & 0o444) !== 0, 'library input is not readable');
  const hash = createHash('sha256');
  let bytes = 0;
  for await (const chunk of createReadStream(path, { highWaterMark: 32 * 1024 })) {
    bytes += chunk.length;
    require_(performance.now() < deadline - 25_000, 'input hashing exceeded shared work deadline');
    require_(BigInt(bytes) <= info.size && bytes <= 512 * 1024 * 1024, 'input grew while hashing');
    hash.update(chunk);
  }
  require_(BigInt(bytes) === info.size, 'input size changed while hashing');
  return { path, sha256: hash.digest('hex'), length: bytes, mode, uid: Number(info.uid), gid: Number(info.gid), nlink: Number(info.nlink),
    device: info.dev.toString(), inode: info.ino.toString(), mtimeNs: info.mtimeNs.toString(), ctimeNs: info.ctimeNs.toString() };
}
function local(command, argv, workdir) {
  return execFileSync(command, argv, { cwd: workdir, encoding: 'utf8', timeout: 5000, maxBuffer: 65536, env: { ...process.env, LC_ALL: 'C' } }).trim();
}
function args(values) {
  inventoryOnly = values[0] === '--inventory-only';
  if (inventoryOnly) values = values.slice(1);
  const accepted = new Set(['--source-root', '--source-head', '--build-receipt', '--build-receipt-sha256',
    '--author-binary', '--inspect-binary', '--genesis-binary', '--host-binary', '--test-binary']);
  const out = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index]; const value = values[index + 1];
    require_(accepted.has(key) && typeof value === 'string' && !Object.hasOwn(out, key), 'unknown/duplicate/incomplete fixture argument');
    out[key] = value;
  }
  require_(Object.keys(out).length === accepted.size, 'all nine explicit fixture inputs are required');
  require_(/^[0-9a-f]{40}$/u.test(out['--source-head']) && /^[0-9a-f]{64}$/u.test(out['--build-receipt-sha256']), 'immutable source/receipt pins required');
  return out;
}
function closure(path) {
  const lines = local('/usr/bin/ldd', [path]).split('\n');
  const libraries = new Map(); let interpreter;
  for (const line of lines) {
    require_(!line.includes('not found'), 'missing ELF library');
    const match = line.match(/=>\s*(\/\S+)\s+\(0x/u) ?? line.match(/^\s*(\/\S+)\s+\(0x/u);
    if (!match) continue;
    const resolved = realpathSync(match[1]); mountSafe(resolved);
    const name = basename(resolved);
    if (name.startsWith('ld-linux') || name === 'ld.so') {
      require_(interpreter === undefined || interpreter === resolved, 'ambiguous ELF loader'); interpreter = resolved;
    } else {
      require_(!libraries.has(name) || libraries.get(name) === resolved, 'library basename collision'); libraries.set(name, resolved);
    }
  }
  require_(interpreter !== undefined, 'actual ELF loader missing');
  return { interpreter, libraries };
}
function probeCommand(source) {
  require_(source.length <= 256 * 1024, 'fixture program exceeds256KiB transport cap');
  const packed = deflateSync(source).toString('base64');
  const sha = createHash('sha256').update(source).digest('hex');
  const command = [
    'import base64,hashlib,zlib', '__decoder=zlib.decompressobj()',
    `__source=__decoder.decompress(base64.b64decode(${JSON.stringify(packed)},validate=True),${source.length + 1})`,
    `if len(__source)!=${source.length} or not __decoder.eof or __decoder.unused_data or __decoder.unconsumed_tail: raise RuntimeError('fixture transport length differs')`,
    `if hashlib.sha256(__source).hexdigest()!=${JSON.stringify(sha)}: raise RuntimeError('fixture source hash differs')`,
    "exec(compile(__source,'<certified-fastvote-fixture>','exec'))",
  ].join('\n');
  require_(Buffer.byteLength(command) <= 64 * 1024, 'fixture bootstrap exceeds64KiB');
  return command;
}

// Complete-output transport only: no controller dispatch or role work here.
function decodeEvidence(wire) {
  const decodedCap = 512 * 1024;
  const wireBytes = Buffer.byteLength(wire);
  require_(wireBytes <= outputLimit && wire.endsWith('\n'), 'complete evidence wire bound/framing differs');
  const envelope = JSON.parse(wire);
  require_(envelope && !Array.isArray(envelope) && typeof envelope === 'object' &&
    JSON.stringify(Object.keys(envelope).sort()) === '["decoded_bytes","decoded_sha256","encoding","payload"]' &&
    envelope.encoding === 'zlib-base64-json-v1' && Number.isInteger(envelope.decoded_bytes) &&
    envelope.decoded_bytes > 0 && envelope.decoded_bytes <= decodedCap &&
    typeof envelope.decoded_sha256 === 'string' && /^[0-9a-f]{64}$/u.test(envelope.decoded_sha256) &&
    typeof envelope.payload === 'string' && envelope.payload.length > 0 && envelope.payload.length % 4 === 0 &&
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(envelope.payload),
  'complete evidence transport envelope differs');
  const packed = Buffer.from(envelope.payload, 'base64');
  require_(packed.toString('base64') === envelope.payload, 'complete evidence base64 is not canonical');
  // Node24 inflateSync uses complete-stream Z_FINISH by default. info exposes
  // actual consumed input: equality also refuses trailing/concatenated streams.
  const inflated = inflateSync(packed, { maxOutputLength: decodedCap, info: true });
  const decoded = inflated.buffer;
  require_(inflated.engine.bytesWritten === packed.length && decoded.length === envelope.decoded_bytes &&
    createHash('sha256').update(decoded).digest('hex') === envelope.decoded_sha256,
  'complete evidence zlib EOF/length/hash differs');
  const text = decoded.toString('utf8');
  require_(Buffer.from(text, 'utf8').equals(decoded), 'complete evidence JSON is not lossless UTF8');
  return { result: JSON.parse(text), transport: { encoding: envelope.encoding, wire, wire_bytes: wireBytes,
    wire_sha256: createHash('sha256').update(wire).digest('hex'), compressed_bytes: packed.length,
    decoded_bytes: decoded.length, decoded_sha256: envelope.decoded_sha256, decoded_cap: decodedCap } };
}

async function docker(args, cleanup = false) {
  const allowance = Math.floor(deadline - performance.now() - (cleanup ? 0 : 25_000));
  const remaining = cleanup ? Math.min(5_000, allowance) : allowance;
  if (remaining <= 0) throw new Error('fixture deadline expired');
  const commandEnd = performance.now() + remaining;
  const activeLimit = cleanup ? outputLimit : outputLimit - cleanupReserve;
  require_(clientRecords.length < 96 && outputBytes + clientMetadataBytes + clientMetadataBytesPerRecord <= activeLimit,
    'Docker completion metadata exceeds existing evidence cap');
  clientMetadataBytes += clientMetadataBytesPerRecord;
  const operation = ['container', 'volume', 'image'].includes(args[0]) ? `${args[0]} ${args[1]}` : args[0];
  const emptySha = createHash('sha256').digest('hex');
  const record = { operation, cleanup, pid: null, exit: null, signal: null, waitCompleted: false, closeObserved: false,
    stdoutEof: false, stderrEof: false, stdoutBytes: 0, stderrBytes: 0, stdoutSha256: emptySha, stderrSha256: emptySha, captureComplete: false };
  clientRecords.push(record);
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/local/bin/docker', ['--host', endpoint, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'], env: dockerEnvironment,
    });
    record.pid = child.pid ?? null;
    pendingClients.add(child);
    const stdout = []; const stderr = [];
    const hashes = { stdout: createHash('sha256'), stderr: createHash('sha256') };
    let capturedBytes = 0;
    let failure; let settled = false; let reapTimer;
    function snapshotRecord() {
      record.stdoutSha256 = hashes.stdout.copy().digest('hex');
      record.stderrSha256 = hashes.stderr.copy().digest('hex');
      record.captureComplete = record.stdoutEof && record.stderrEof && capturedBytes === record.stdoutBytes + record.stderrBytes;
      require_(Buffer.byteLength(JSON.stringify(record)) <= clientMetadataBytesPerRecord, 'Docker record metadata reservation exceeded');
    }
    function rejectOnce(error) {
      if (settled) return;
      settled = true;
      snapshotRecord();
      error.capture ??= { stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8'),
        stdoutEof: record.stdoutEof, stderrEof: record.stderrEof };
      reject(error);
    }
    function abort(error) {
      failure ??= error;
      // SIGKILL is uncatchable by the client, so it is not proxied to the
      // container. Only exact owned-container cleanup below targets that role.
      child.kill('SIGKILL');
      if (reapTimer) return;
      reapTimer = setTimeout(() => {
        child.unref(); child.stdout.destroy(); child.stderr.destroy();
        rejectOnce(new Error(`${failure.message}; Docker client reap/EOF unresolved, pid=${child.pid ?? 'unknown'}`));
      }, Math.max(1, Math.min(1_000, Math.floor(deadline - performance.now()))));
    }
    const timer = setTimeout(() => { abort(new Error('Docker operation exceeded its deadline')); }, remaining);
    function collect(name, target, chunk) {
      record[`${name}Bytes`] += chunk.length; hashes[name].update(chunk);
      if (failure) return;
      if (chunk.length > activeLimit - outputBytes - clientMetadataBytes) {
        abort(new Error('complete output exceeds capability evidence allocation')); return;
      }
      outputBytes += chunk.length; capturedBytes += chunk.length; target.push(chunk);
    }
    child.stdout.on('data', (chunk) => collect('stdout', stdout, chunk));
    child.stderr.on('data', (chunk) => collect('stderr', stderr, chunk));
    child.stdout.on('end', () => { record.stdoutEof = true; });
    child.stderr.on('end', () => { record.stderrEof = true; });
    child.stdout.on('error', abort); child.stderr.on('error', abort); child.on('error', abort);
    child.on('exit', (code, signal) => { record.exit = code; record.signal = signal; record.waitCompleted = true; });
    child.on('close', (code, signal) => {
      pendingClients.delete(child); clearTimeout(timer); if (reapTimer) clearTimeout(reapTimer);
      record.closeObserved = true; snapshotRecord();
      if (settled) return;
      if (performance.now() > commandEnd) failure ??= new Error('Docker completion was observed after its deadline');
      if (failure) return rejectOnce(failure);
      if (!record.waitCompleted || !record.stdoutEof || !record.stderrEof || !record.captureComplete)
        return rejectOnce(new Error('Docker output lacks physical wait/close/EOF completion'));
      const answer = { code, signal, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') };
      if (code !== 0 || signal !== null) {
        const diagnostic = answer.stderr.trim() || answer.stdout.trim();
        const error = new Error(`Docker refused ${operation}: ${diagnostic}`);
        error.command = args[0]; error.capture = { ...answer, stdoutEof: record.stdoutEof, stderrEof: record.stderrEof };
        return rejectOnce(error);
      }
      settled = true; resolve(answer);
    });
  });
}

// Only the fields these checks actually consume; `Config.Env` is never
// requested or inspected.
const identityFormat = '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"State":{{json .State}},"Config":{"Labels":{{json .Config.Labels}}}}';
const configurationFormat = '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"State":{{json .State}},"Config":{"Labels":{{json .Config.Labels}},"User":{{json .Config.User}},"Entrypoint":{{json .Config.Entrypoint}}},"Mounts":{{json .Mounts}},"HostConfig":{"Memory":{{json .HostConfig.Memory}},"MemorySwap":{{json .HostConfig.MemorySwap}},"PidsLimit":{{json .HostConfig.PidsLimit}},"NanoCpus":{{json .HostConfig.NanoCpus}},"NetworkMode":{{json .HostConfig.NetworkMode}},"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},"LogConfig":{{json .HostConfig.LogConfig}},"CapAdd":{{json .HostConfig.CapAdd}},"CapDrop":{{json .HostConfig.CapDrop}},"SecurityOpt":{{json .HostConfig.SecurityOpt}},"Tmpfs":{{json (index .HostConfig "Tmpfs")}},"Binds":{{json (index .HostConfig "Binds")}}}}';

async function inspect(reference, cleanup = false, withConfiguration = false) {
  const format = withConfiguration ? configurationFormat : identityFormat;
  const captured = await docker(['container', 'inspect', '--format', format, reference], cleanup);
  const state = JSON.parse(captured.stdout);
  if (state === null || Array.isArray(state) || typeof state !== 'object') {
    throw new Error('container inspection is not unique');
  }
  if (state.Name !== `/${name}` || state.Config.Labels?.[label] !== owner || state.Image !== imageId) {
    throw new Error('container is not the exact owned custody fixture');
  }
  return state;
}

async function findVolume(cleanup = false) {
  const captured = await docker(['volume', 'ls', '-q', '--filter', `name=^${volumeName}$`], cleanup);
  const found = captured.stdout.trim();
  if (found && found !== volumeName) throw new Error('volume lookup is not exact');
  return found === volumeName;
}

async function inspectVolume(cleanup = false) {
  const captured = await docker(['volume', 'inspect', volumeName], cleanup);
  const rows = JSON.parse(captured.stdout);
  if (!Array.isArray(rows) || rows.length !== 1) throw new Error('volume inspection is not unique');
  const volume = rows[0];
  if (volume.Name !== volumeName || volume.Driver !== 'local' || volume.Scope !== 'local' ||
      volume.Labels?.[label] !== owner ||
      JSON.stringify(Object.keys(volume.Options ?? {}).sort()) !== '["device","o","type"]' ||
      volume.Options.type !== 'tmpfs' || volume.Options.device !== 'tmpfs' ||
      volume.Options.o !== volumeOptions || typeof volume.Mountpoint !== 'string' ||
      !volume.Mountpoint.startsWith('/') || volume.Mountpoint.includes('\0')) {
    throw new Error('volume is not the exact owned noswap allocation');
  }
  if (volumeMountpoint !== undefined && volume.Mountpoint !== volumeMountpoint) {
    throw new Error('owned volume attachment changed');
  }
  volumeMountpoint = volume.Mountpoint;
  return volume;
}


let sourceInventory;
let elfInventory;
let libraryInventory;
let buildReceiptPin;
try {
  require_(process.versions.node === '24.19.0', 'select existing nvm Node24.19.0 without fallback');
  const input = args(process.argv.slice(2));
  const root = mountSafe(input['--source-root']);
  require_(local('/usr/bin/git', ['rev-parse', 'HEAD'], root) === input['--source-head'], 'source head differs');
  require_(local('/usr/bin/git', ['status', '--porcelain'], root) === '', 'source must be committed and clean');
  const tree = local('/usr/bin/git', ['rev-parse', 'HEAD^{tree}'], root);
  sourcePin = { root, head: input['--source-head'], tree, nodeVersion: process.versions.node, componentOnly: true };
  const ownScript = fileURLToPath(import.meta.url);
  require_(ownScript === `${root}/scripts/check-docker-certified-custody-fixture-1017.mjs`, 'controller is not from pinned source root');
  const sourcePaths = ['scripts/check-docker-certified-custody-fixture-1017.mjs', 'scripts/fixtures/certified-fastvote-custody-1017.py', 'apps/operator/tests/certified_protocol_custody_fixture.rs', 'apps/operator/src/protocol_custody.rs', 'apps/operator/src/protocol_custody/linux.rs', 'apps/operator/src/sqlite_source_host.rs', 'crates/native-http/src/certified_custody.rs', 'crates/native-http/src/certified_custody/verification.rs', 'crates/native-http/src/fastvote.rs', 'crates/native-http/src/fastvote/drain.rs', 'crates/native-http/src/ordered_custody.rs', 'crates/native-http/src/ordered_economics.rs', 'apps/operator/tests/support/sqlite_durable_image.rs', 'apps/operator/tests/support/offline_genesis_fixture.rs', 'apps/operator/tests/support/https_relay.rs', 'clients/rust/src/fastvote_client.rs', 'clients/rust/src/fastvote_publication_client.rs', 'clients/rust/src/fastvote_frontier_client.rs', 'clients/rust/src/fastvote_drain_client.rs', 'clients/rust/src/fastvote_drain_driver.rs', 'clients/rust/src/ordered_economics_client.rs', 'Cargo.lock'];
  sourceInventory = [];
  for (const path of sourcePaths) sourceInventory.push(await inventory(`${root}/${path}`));
  const receiptPath = mountSafe(input['--build-receipt']);
  const receiptBytes = boundedText(receiptPath, 65536);
  buildReceiptPin = createHash('sha256').update(receiptBytes).digest('hex');
  require_(buildReceiptPin === input['--build-receipt-sha256'], 'build receipt hash differs');
  const receipt = JSON.parse(receiptBytes.toString('utf8'));
  require_(receipt.schema === 1 && receipt.sourceHead === input['--source-head'] && receipt.sourceTree === tree &&
    receipt.nodeVersion === '24.19.0' && Array.isArray(receipt.commands) && receipt.commands.length >= 1 && receipt.commands.length <= 8,
  'actual build receipt source/profile fields differ');
  require_(receipt.sourceFiles && Object.keys(receipt.sourceFiles).length === sourceInventory.length && sourceInventory.every((entry) =>
    receipt.sourceFiles[entry.path.slice(root.length + 1)] === entry.sha256), 'build receipt source hashes differ');
  for (const command of receipt.commands) {
    require_(Array.isArray(command.argv) && command.argv.length >= 2 && command.argv.length <= 64 && command.argv.every((value) => typeof value === 'string') &&
      command.exit === 0 && command.stdoutEof === true && command.stderrEof === true && /^[0-9a-f]{64}$/u.test(command.logSha256), 'actual complete build command receipt missing');
    require_((await inventory(mountSafe(command.logPath))).sha256 === command.logSha256, 'actual build output log differs');
  }
  const targets = [
    ['author', '--author-binary', 'standard_asset_genesis'], ['inspect', '--inspect-binary', 'genesis_inspect'],
    ['genesis', '--genesis-binary', 'sqlite_genesis'], ['host', '--host-binary', 'sqlite_source_host'],
    ['harness', '--test-binary', 'certified_protocol_custody_fixture'],
  ];
  require_(receipt.inputs && Object.keys(receipt.inputs).length === 5, 'five explicit compiled build targets required');
  elfInventory = [];
  let merged;
  for (const [role, flag, target] of targets) {
    const actual = await inventory(input[flag], true);
    const prior = receipt.inputs[role];
    require_(prior && prior.path === actual.path && prior.sha256 === actual.sha256 && prior.length === actual.length && prior.mode === 0o755 && prior.uid === actual.uid && prior.nlink === actual.nlink &&
      prior.package === 'sunrise-edge-operator' && prior.target === target && Number.isInteger(prior.commandIndex) &&
      prior.commandIndex >= 0 && prior.commandIndex < receipt.commands.length &&
      (role === 'harness' ? prior.profile === 'test' : ['dev', 'release'].includes(prior.profile)), 'ELF target/provenance receipt differs');
    actual.role = role; actual.target = target; actual.profile = prior.profile; elfInventory.push(actual);
    const required = closure(actual.path);
    if (!merged) merged = required;
    else {
      require_(merged.interpreter === required.interpreter, 'compiled inputs require different loaders');
      for (const [name, path] of required.libraries) {
        require_(!merged.libraries.has(name) || merged.libraries.get(name) === path, 'merged library basename collision');
        merged.libraries.set(name, path);
      }
    }
  }
  require_(merged.libraries.size <= 64, 'exact library inventory exceeds64 entries');
  libraryInventory = [await inventory(merged.interpreter)];
  for (const path of merged.libraries.values()) libraryInventory.push(await inventory(path));
  require_(elfInventory.reduce((sum, row) => sum + row.length, 0) <= 2 * 1024 * 1024 * 1024 &&
    libraryInventory.reduce((sum, row) => sum + row.length, 0) <= 256 * 1024 * 1024, 'read-only compiled input allocation bound exceeded');
  const binds = [
    ...elfInventory.map((row) => `type=bind,source=${row.path},target=/mnt/bin/${row.role},readonly`),
    `type=bind,source=${merged.interpreter},target=/mnt/libs/ld.so,readonly`,
    ...[...merged.libraries.values()].map((path) => `type=bind,source=${path},target=/mnt/libs/${basename(path)},readonly`),
  ];
  const source = boundedText(`${root}/scripts/fixtures/certified-fastvote-custody-1017.py`, 256 * 1024);
  if (inventoryOnly) {
    result = { mode: 'inventory-only', execution: false, script_bytes: source.length, bootstrap_bytes: Buffer.byteLength(probeCommand(source)) };
  } else {
  const localImage = await docker(['image', 'inspect', '--format', '{{.Id}}', image]);
  require_(localImage.stdout.trim() === imageId, 'pinned existing local image differs');
  require_(!(await findVolume()), 'fresh owned allocation already exists');
  volumeExpected = true;
  volumeCreateAttempted = true; volumeCreateAmbiguous = true;
  const createdVolume = await docker(['volume', 'create', '--driver', 'local', '--name', volumeName, '--label', `${label}=${owner}`,
    '--opt', 'type=tmpfs', '--opt', 'device=tmpfs', '--opt', `o=${volumeOptions}`]);
  require_(createdVolume.stdout.trim() === volumeName, 'owned allocation creation differs');
  await inspectVolume();
  volumeCreateAmbiguous = false;
  containerCreateAttempted = true; containerCreateAmbiguous = true;
  const created = await docker(['create', '--pull=never', '--name', name, '--label', `${label}=${owner}`,
    '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE',
    '--cap-add', 'SETUID', '--cap-add', 'SETGID', '--security-opt', 'no-new-privileges', '--user', '0:0',
    '--memory', '512m', '--memory-swap', '512m', '--cpus', '1', '--pids-limit', '64', '--log-driver', 'none',
    '--mount', `type=volume,source=${volumeName},target=/work,volume-nocopy`, ...binds.flatMap((bind) => ['--mount', bind]),
    '--entrypoint', '/usr/local/bin/python3', image, '-I', '-B', '-c', probeCommand(source)]);
  containerId = created.stdout.trim(); require_(/^[0-9a-f]{64}$/u.test(containerId), 'exact owned container ID missing');
  const initial = await inspect(containerId, false, true);
  const config = initial.HostConfig;
  const allocations = initial.Mounts.filter((mount) => mount.Type === 'volume');
  const readonly = initial.Mounts.filter((mount) => mount.Type === 'bind');
  require_(allocations.length === 1 && allocations[0].Name === volumeName && allocations[0].Destination === '/work' &&
    allocations[0].RW === true && allocations[0].Source === volumeMountpoint && readonly.length === binds.length &&
    initial.Mounts.length === binds.length + 1 && readonly.every((mount) => mount.RW === false), 'actual mount inventory differs');
  const expectedBinds = new Map([
    ...elfInventory.map((row) => [`/mnt/bin/${row.role}`, row.path]), ['/mnt/libs/ld.so', merged.interpreter],
    ...[...merged.libraries.values()].map((path) => [`/mnt/libs/${basename(path)}`, path]),
  ]);
  for (const mount of readonly) require_(expectedBinds.get(mount.Destination) === mount.Source, 'read-only exact input attachment differs');
  const sorted = (values) => [...values].map((value) => value.replace(/^CAP_/u, '')).sort();
  require_(config.Memory === 536870912 && config.MemorySwap === 536870912 && config.PidsLimit === 64 && config.NanoCpus === 1000000000 &&
    config.NetworkMode === 'none' && config.ReadonlyRootfs === true && config.LogConfig?.Type === 'none' &&
    JSON.stringify(sorted(config.CapDrop ?? [])) === '["ALL"]' && JSON.stringify(sorted(config.CapAdd ?? [])) === '["CHOWN","DAC_OVERRIDE","SETGID","SETUID"]' &&
    (config.SecurityOpt ?? []).some((value) => value === 'no-new-privileges' || value === 'no-new-privileges:true') &&
    Object.keys(config.Tmpfs ?? {}).length === 0 && (config.Binds ?? []).length === 0 && initial.Config.User === '0:0' &&
    JSON.stringify(initial.Config.Entrypoint) === '["/usr/local/bin/python3"]', 'effective Docker profile differs');
  containerCreateAmbiguous = false;
  // One supported start --attach call establishes output capture before any
  // container execution. Use start's default signal proxy; this owner forwards
  // no signals and only uses uncatchable client SIGKILL for timeout abort.
  const attached = await docker(['start', '--attach', containerId]);
  // Retain the exact wire even when decoding refuses malformed evidence.
  resultTransport = { wire: attached.stdout, stderr: attached.stderr,
    wire_bytes: Buffer.byteLength(attached.stdout), wire_sha256: createHash('sha256').update(attached.stdout).digest('hex') };
  require_(attached.stderr === '', 'controller stderr was not empty');
  const decoded = decodeEvidence(attached.stdout);
  result = decoded.result; resultTransport = decoded.transport;
  const waited = await docker(['wait', containerId]); require_(waited.stdout.trim() === '0', 'actual container wait did not exit0');
  const terminal = await inspect(containerId);
  require_(terminal.State.Running === false && terminal.State.Pid === 0 && terminal.State.ExitCode === 0 && terminal.State.OOMKilled === false &&
    terminal.State.Dead === false, 'actual terminal Docker state differs');
  require_(result.passed === true && result.error === null && result.all_children_waited === true && result.final_fence === 6 &&
    result.freeze_height === 1 && result.paid_applied === 2 && result.final_nonce === 2 && result.retained_only_c_unapplied === true &&
    result.actual_fastvotes_per_operation === 4 && result.actual_acks_a_b === 4 && result.actual_frontiers === 4 &&
    result.local_union_members === 3 && result.positive_drain_member_application === false &&
    result.no_validator_key_in_frontend === true && result.captured_output_bytes <= 262144 &&
    result.allocation.bytes <= 67108864 && result.allocation.inodes <= 16384 && Array.isArray(result.child_records) &&
    result.child_records.length > 80 && result.child_records.length <= 160 && result.child_records.every((row) =>
      row.waited === true && row.stdout_eof === true && row.stderr_eof === true && Number.isInteger(row.exit) && [12001, 12002, 12003].includes(row.uid)) &&
    Array.isArray(result.phase_requests) && result.phase_requests.length <= 32 && result.phase_requests.every((phase) =>
      Array.isArray(phase.counts) && phase.counts.length === 4 && phase.counts.every((count) => Number.isSafeInteger(count) && count >= 0 && count <= 96)) &&
    result.request_budget_verified === true && result.oracle_phase_count <= 64,
  'actual certified role/component evidence is incomplete');
  const recovery = result.stopped_key_recovery;
  require_(recovery?.worker_count === 4 && recovery.helper_uid === 12001 && recovery.operator_uid === 12002 &&
    recovery.old_pid_socket_absent_before_copy === true && recovery.old_key_paths_absent === true &&
    recovery.private_directory_mode === 0o700 && recovery.private_file_mode === 0o600 &&
    recovery.only_signing_key_config_changed === true && recovery.public_identities_unchanged === true &&
    recovery.operator_cannot_read_restored_seeds === true && Array.isArray(recovery.stopped_worker_pids) &&
    recovery.stopped_worker_pids.length === 4 && recovery.stopped_worker_pids.every((pid) => Number.isSafeInteger(pid) && pid > 0) &&
    new Set(recovery.stopped_worker_pids).size === 4, 'actual stopped same-identity key recovery evidence is incomplete');
  for (const [pid, uid, label, marker] of [
    [recovery.helper_pid, 12001, 'stopped-key-recovery', 'stopped_key_recovery complete=true workers=4 configs=8 old_paths_absent=true'],
    [recovery.operator_refusal_pid, 12002, 'restored-key-filesystem-refusals', 'restored_key_filesystem_refusals complete=true operator_uid=12002 seeds=8'],
  ]) {
    const records = result.child_records.filter((row) => row.pid === pid);
    require_(records.length === 1 && records[0].label === label && records[0].uid === uid && records[0].gid === uid &&
      records[0].exit === 0 && records[0].stderr === '' &&
      records[0].stdout === `role_checked uid=${uid} gid=${uid} caps=0\n${marker}\n`,
    'actual capability-free recovery/refusal child receipt differs');
  }
  const generationModes = ['certified', 'certified', 'ordered', 'certified', 'certified'];
  require_(Array.isArray(result.worker_key_generations) && result.worker_key_generations.length === generationModes.length,
    'actual worker key generations are incomplete');
  for (const [generationIndex, generation] of result.worker_key_generations.entries()) {
    const mode = generationModes[generationIndex];
    require_(generation.mode === mode && ['config_paths', 'key_paths', 'worker_pids'].every((field) =>
      Array.isArray(generation[field]) && generation[field].length === 4), 'actual worker key generation shape differs');
    for (let index = 0; index < 4; index += 1) {
      const root = `/work/worker/v${index}`;
      const suffix = generationIndex === 0 ? 'config' : mode === 'ordered' ? 'recovered.ordered.config' : 'recovered.config';
      const key = generationIndex === 0 ? `${root}/validator.key` : `${root}/key-recovery/validator.restored.key`;
      const records = result.child_records.filter((row) => row.pid === generation.worker_pids[index]);
      require_(generation.config_paths[index] === `${root}/${suffix}` && generation.key_paths[index] === key &&
        records.length === 1 && records[0].uid === 12001 &&
        records[0].label === `${mode === 'ordered' ? 'protocol' : 'certified'}-worker-${index}` &&
        (generationIndex !== 0 || recovery.stopped_worker_pids[index] === generation.worker_pids[index]),
      'actual certified/ordered restart did not select the exact restored key/config');
    }
  }
  for (const phase of ['filesystem-refusals', 'intruder-before-body', 'authenticated-stalled-body-deadline', 'frontend-refuses-impostor-before-body',
    'missing-anchor-checkpoint-and-competing-lease', 'wrong-profile-before-dispatch', 'wrong-output-refusals', 'tls-refusals',
    'a-prepare', 'a-retain', 'a-repeat', 'bad-input', 'a-apply', 'a-apply-replay', 'b-fresh', 'c-retained', 'worker-down',
    'freeze', 'frontier-first', 'frontier-replay', 'drain-first', 'drain-replay', 'no-drain-set', 'closed-after-freeze', 'queries',
    'oracle-fence-2', 'oracle-fence-3', 'oracle-fence-4', 'oracle-fence-5', 'oracle-fence-6',
    'oracle-a-prepared', 'oracle-a-retained', 'oracle-a-applied', 'oracle-b-applied', 'oracle-c-retained', 'oracle-frozen', 'oracle-frontier', 'oracle-drained', 'oracle-finish',
    'stopped-key-recovery', 'restored-key-filesystem-refusals']) {
    require_(result.phases.includes(phase), 'actual certified phase receipt missing');
  }
  }

} catch (error) {
  primaryError = error;
  failureCapture = error.capture;
} finally {
  try {
    if (!inventoryOnly) {
    let owned;
    if (containerId) owned = await inspect(containerId, true);
    else {
      const lookup = await docker(['container', 'ls', '-aq', '--no-trunc', '--filter', `name=^/${name}$`], true);
      if (lookup.stdout.trim()) owned = await inspect(lookup.stdout.trim(), true);
    }
    if (owned) {
      if (owned.State.Running) await docker(['kill', owned.Id], true);
      const stopped = await inspect(owned.Id, true);
      require_(stopped.State.Running === false && stopped.State.Pid === 0, 'owned controller did not stop');
      await docker(['rm', owned.Id], true);
    }
    const residue = await docker(['container', 'ls', '-aq', '--no-trunc', '--filter', `label=${label}=${owner}`], true);
    require_(residue.stdout.trim() === '', 'owned container residue remains');
    if (volumeExpected && await findVolume(true)) { await inspectVolume(true); await docker(['volume', 'rm', volumeName], true); }
    const volumes = await docker(['volume', 'ls', '-q', '--filter', `label=${label}=${owner}`], true);
    require_(volumes.stdout.trim() === '', 'owned allocation residue remains');
    cleanupVerified = !containerCreateAmbiguous && !volumeCreateAmbiguous;
    require_(cleanupVerified, `creation outcome remains ambiguous; manual reconciliation required for container=${name} volume=${volumeName} owner=${owner}`);
    }
  } catch (error) {
    primaryError = new Error(`${primaryError?.message ?? 'fixture'}; cleanup unresolved: ${error.message}; owned name=${name}`);
  }
}
try {
  if (sourcePin) {
    require_(local('/usr/bin/git', ['rev-parse', 'HEAD'], sourcePin.root) === sourcePin.head &&
      local('/usr/bin/git', ['rev-parse', 'HEAD^{tree}'], sourcePin.root) === sourcePin.tree &&
      local('/usr/bin/git', ['status', '--porcelain'], sourcePin.root) === '', 'pinned source head/tree/clean state changed');
  }
  for (const previous of [...(sourceInventory ?? []), ...(elfInventory ?? []), ...(libraryInventory ?? [])]) {
    const current = await inventory(previous.path, Object.hasOwn(previous, 'role'));
    const { role, target, profile, ...identity } = previous;
    require_(JSON.stringify(current) === JSON.stringify(identity), 'read-only source/ELF/library input changed during fixture');
  }
} catch (error) {
  primaryError = new Error(`${primaryError?.message ?? 'fixture'}; input attachment verification failed: ${error.message}`);
}
if (pendingClients.size !== 0 || performance.now() > deadline) primaryError = new Error(`${primaryError?.message ?? 'fixture'}; end/owned Docker client unresolved`);
const evidence = { mode: inventoryOnly ? 'inventory-only' : 'actual-component-execution', passed: !primaryError, error: primaryError?.message ?? null, capture: primaryError?.capture ?? failureCapture, result,
  resultTransport,
  resources: { endpoint, owner, label, containerName: name, containerId: containerId ?? null, volumeName, volumeMountpoint: volumeMountpoint ?? null,
    containerCreateAttempted, volumeCreateAttempted, containerCreateAmbiguous, volumeCreateAmbiguous,
    manualReconciliationRequired: containerCreateAmbiguous || volumeCreateAmbiguous || (!inventoryOnly && !cleanupVerified),
    startAttachSignalPolicy: 'supported start --attach default proxy; owner forwards no signals; client-only SIGKILL abort' },
  clientRecords, client_metadata_reserved_bytes: clientMetadataBytes,
  image, container_removed: inventoryOnly ? null : cleanupVerified, volume_removed: inventoryOnly ? null : cleanupVerified, sourcePin, sourceInventory, elfInventory, libraryInventory, buildReceiptPin, evidence_bytes: outputBytes };
console.log(JSON.stringify(evidence));
if (primaryError) process.exitCode = 1;
