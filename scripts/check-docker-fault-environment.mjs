#!/usr/bin/env node
// Docker-only capability evidence, not a Rust/SQLite acceptance test.
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';

const image = 'sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea';
const endpoint = 'unix:///var/run/docker.sock';
const arguments_ = process.argv.slice(2);
if (arguments_.length > 1 || (arguments_.length === 1 && arguments_[0] !== '--managed-volume')) {
  throw new Error('only the explicit --managed-volume capability mode is supported');
}
const managedVolume = arguments_.length === 1;
const owner = randomUUID();
const name = `sunrise-edge-fault-cap-${owner}`;
const volumeName = `${name}-memory`;
const label = 'sunrise-edge.fault-capability-owner';
const mountOptions = 'rw,nosuid,nodev,noexec,size=8m,mode=0700,uid=65534,gid=65534,noswap';
const deadline = performance.now() + 45_000;
const outputLimit = 65_536;
const cleanupReserve = 32_768;
const dockerEnvironment = { ...process.env };
for (const variable of ['DOCKER_CONTEXT', 'DOCKER_HOST', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) {
  delete dockerEnvironment[variable];
}
const pendingClients = new Set();
let outputBytes = 0;
let containerId;
let volumeMountpoint;
let primaryError;
let result;

const probe = String.raw`
import errno, json, os

def read_small(path):
    with open(path, "rb") as source:
        value = source.read(65537)
    if len(value) > 65536:
        raise RuntimeError("capability input exceeds bound")
    return value.decode("ascii")

def identity():
    lines = read_small("/proc/self/mountinfo").splitlines()
    matches = [line.split() for line in lines if line.split()[4] == "/fault"]
    if len(matches) != 1:
        raise RuntimeError("fault mount is not unique")
    row = matches[0]
    separator = row.index("-")
    if row[separator + 1] != "tmpfs":
        raise RuntimeError("fault mount is not tmpfs")
    options = set(row[5].split(",")) | set(row[separator + 3].split(","))
    if not {"noswap", "nosuid", "nodev", "noexec"}.issubset(options):
        raise RuntimeError("required tmpfs flags are unavailable")
    if read_small("/sys/fs/cgroup/memory.max").strip() != "67108864":
        raise RuntimeError("memory bound differs")
    if read_small("/sys/fs/cgroup/memory.swap.max").strip() != "0":
        raise RuntimeError("container swap is not prohibited")
    volume = os.statvfs("/fault")
    if volume.f_frsize * volume.f_blocks != 8388608:
        raise RuntimeError("fault filesystem is not exactly eight MiB")
    return (row[0], row[2], row[3], row[4], row[separator + 2], tuple(sorted(options)))

before = identity()
descriptor = None
created = None
written = 0
enospc = False
try:
    descriptor = os.open("/fault/filler", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    created = os.fstat(descriptor)
    block = b"x" * 1048576
    attempted = 0
    while attempted < 10485760:
        size = min(len(block), 10485760 - attempted)
        attempted += size
        try:
            count = os.write(descriptor, block[:size])
        except OSError as error:
            if error.errno != errno.ENOSPC:
                raise
            enospc = True
            break
        if count <= 0:
            raise RuntimeError("filler write made no progress")
        written += count
    if not enospc or written <= 0 or written > 8388608:
        raise RuntimeError("real bounded ENOSPC was not observed")
    if identity() != before:
        raise RuntimeError("fault mount identity changed")
finally:
    if descriptor is not None:
        os.close(descriptor)
    if created is not None:
        named = os.stat("/fault/filler", follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (created.st_dev, created.st_ino):
            raise RuntimeError("owned filler identity changed")
        os.unlink("/fault/filler")
if identity() != before or os.listdir("/fault"):
    raise RuntimeError("fault cleanup is incomplete")
print(json.dumps({"scope":"docker_environment_only","noswap":True,"memory_bytes":67108864,"swap_bytes":0,"filesystem_bytes":8388608,"written_bytes":written,"errno":errno.ENOSPC,"filler_removed":True}, sort_keys=True))
`;

async function docker(args, cleanup = false) {
  const allowance = Math.floor(deadline - performance.now() - (cleanup ? 0 : 25_000));
  const remaining = cleanup ? Math.min(5_000, allowance) : allowance;
  if (remaining <= 0) throw new Error('capability deadline expired');
  const commandEnd = performance.now() + remaining;
  const activeLimit = cleanup ? outputLimit : outputLimit - cleanupReserve;
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/local/bin/docker', ['--host', endpoint, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: dockerEnvironment,
    });
    pendingClients.add(child);
    const stdout = [];
    const stderr = [];
    let stdoutEof = false;
    let stderrEof = false;
    let failure;
    let settled = false;
    let reapTimer;
    function rejectOnce(error) {
      if (settled) return;
      settled = true;
      reject(error);
    }
    function abort(error) {
      failure ??= error;
      child.kill('SIGKILL');
      if (reapTimer) return;
      reapTimer = setTimeout(() => {
        child.unref();
        child.stdout.destroy();
        child.stderr.destroy();
        rejectOnce(new Error(`${failure.message}; Docker client reap/EOF unresolved, pid=${child.pid ?? 'unknown'}`));
      }, Math.max(1, Math.min(1_000, Math.floor(deadline - performance.now()))));
    }
    const timer = setTimeout(() => {
      abort(new Error('Docker operation exceeded its deadline'));
    }, remaining);
    function collect(target, chunk) {
      if (failure) return;
      if (chunk.length > activeLimit - outputBytes) {
        // An overflow is failure, never a truncated successful result. Retain
        // the independent cleanup allocation for exact ownership inspection.
        abort(new Error('complete output exceeds capability evidence allocation'));
        return;
      }
      outputBytes += chunk.length;
      target.push(chunk);
    }
    child.stdout.on('data', (chunk) => collect(stdout, chunk));
    child.stderr.on('data', (chunk) => collect(stderr, chunk));
    child.stdout.on('end', () => { stdoutEof = true; });
    child.stderr.on('end', () => { stderrEof = true; });
    child.stdout.on('error', abort);
    child.stderr.on('error', abort);
    child.on('error', abort);
    child.on('close', (code, signal) => {
      pendingClients.delete(child);
      clearTimeout(timer);
      if (reapTimer) clearTimeout(reapTimer);
      if (settled) return;
      if (performance.now() > commandEnd) failure ??= new Error('Docker completion was observed after its deadline');
      if (failure) return rejectOnce(failure);
      if (!stdoutEof || !stderrEof) return rejectOnce(new Error('Docker output lacks both physical EOFs'));
      const answer = {
        code, signal,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      };
      if (code !== 0 || signal !== null) {
        const error = new Error(`Docker refused ${args[0]}: ${answer.stderr.trim()}`);
        error.command = args[0];
        return rejectOnce(error);
      }
      settled = true;
      resolve(answer);
    });
  });
}

// Request the complete fields the checks actually consume. Repeated full
// Docker inspection also repeats the Python command and unrelated metadata;
// it can exhaust the cleanup allocation without adding ownership evidence.
const identityFormat = '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"State":{{json .State}},"Config":{"Labels":{{json .Config.Labels}}}}';
const configurationFormat = '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"State":{{json .State}},"Config":{"Labels":{{json .Config.Labels}},"User":{{json .Config.User}},"Entrypoint":{{json .Config.Entrypoint}},"Cmd":{{json .Config.Cmd}}},"Mounts":{{json .Mounts}},"HostConfig":{"Memory":{{json .HostConfig.Memory}},"MemorySwap":{{json .HostConfig.MemorySwap}},"PidsLimit":{{json .HostConfig.PidsLimit}},"NanoCpus":{{json .HostConfig.NanoCpus}},"NetworkMode":{{json .HostConfig.NetworkMode}},"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},"LogConfig":{{json .HostConfig.LogConfig}},"CapDrop":{{json .HostConfig.CapDrop}},"SecurityOpt":{{json .HostConfig.SecurityOpt}},"Mounts":{{json .HostConfig.Mounts}},"Tmpfs":{{json (index .HostConfig "Tmpfs")}},"Binds":{{json (index .HostConfig "Binds")}}}}';

async function inspect(reference, cleanup = false, withConfiguration = false) {
  const format = withConfiguration ? configurationFormat : identityFormat;
  const captured = await docker(['container', 'inspect', '--format', format, reference], cleanup);
  const state = JSON.parse(captured.stdout);
  if (state === null || Array.isArray(state) || typeof state !== 'object') {
    throw new Error('container inspection is not unique');
  }
  if (state.Name !== `/${name}` || state.Config.Labels?.[label] !== owner || state.Image !== image) {
    throw new Error('container is not the exact owned capability probe');
  }
  return state;
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
      volume.Options.o !== mountOptions || typeof volume.Mountpoint !== 'string' ||
      !volume.Mountpoint.startsWith('/') || volume.Mountpoint.includes('\0')) {
    throw new Error('volume is not the exact owned bounded tmpfs allocation');
  }
  if (volumeMountpoint !== undefined && volume.Mountpoint !== volumeMountpoint) {
    throw new Error('owned volume mountpoint changed');
  }
  volumeMountpoint = volume.Mountpoint;
  return volume;
}

async function findVolume(cleanup = false) {
  const captured = await docker(['volume', 'ls', '-q', '--filter', `name=^${volumeName}$`], cleanup);
  const names = captured.stdout.trim();
  if (names === '') return false;
  if (names !== volumeName) throw new Error('volume name lookup is not exact');
  return true;
}

try {
  if (managedVolume) {
    if (await findVolume()) throw new Error('fresh capability volume already exists');
    const createdVolume = await docker([
      'volume', 'create', '--driver', 'local', '--name', volumeName,
      '--label', `${label}=${owner}`, '--opt', 'type=tmpfs', '--opt', 'device=tmpfs',
      '--opt', `o=${mountOptions}`,
    ]);
    if (createdVolume.stdout !== `${volumeName}\n`) throw new Error('volume creation identity differs');
    await inspectVolume();
  }
  const storage = managedVolume
    ? ['--mount', `type=volume,source=${volumeName},target=/fault,volume-nocopy`]
    : ['--tmpfs', `/fault:${mountOptions}`];
  const created = await docker([
    'create', '--pull=never', '--name', name, '--label', `${label}=${owner}`,
    '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--user', '65534:65534',
    '--memory', '64m', '--memory-swap', '64m', '--cpus', '0.5',
    '--pids-limit', '32', '--log-driver', 'none',
    ...storage,
    '--entrypoint', '/usr/local/bin/python3', image, '-I', '-B', '-c', probe,
  ]);
  containerId = created.stdout.trim();
  if (!/^[0-9a-f]{64}$/.test(containerId)) throw new Error('invalid exact container identity');
  const initial = await inspect(containerId, false, true);
  const config = initial.HostConfig;
  const mounts = initial.Mounts;
  const requestedMounts = config.Mounts;
  const storageMatches = managedVolume
    ? Array.isArray(mounts) && mounts.length === 1 &&
      mounts[0].Type === 'volume' && mounts[0].Name === volumeName &&
      mounts[0].Destination === '/fault' && mounts[0].Source === volumeMountpoint &&
      mounts[0].Driver === 'local' && mounts[0].RW === true &&
      Array.isArray(requestedMounts) && requestedMounts.length === 1 &&
      requestedMounts[0].Type === 'volume' && requestedMounts[0].Source === volumeName &&
      requestedMounts[0].Target === '/fault' &&
      (requestedMounts[0].ReadOnly === undefined || requestedMounts[0].ReadOnly === false) &&
      requestedMounts[0].VolumeOptions?.NoCopy === true &&
      Object.keys(config.Tmpfs ?? {}).length === 0 && (config.Binds ?? []).length === 0
    : Array.isArray(mounts) && mounts.length === 0;
  if (config.Memory !== 67_108_864 || config.MemorySwap !== 67_108_864 ||
      config.PidsLimit !== 32 || config.NanoCpus !== 500_000_000 ||
      config.NetworkMode !== 'none' || config.ReadonlyRootfs !== true ||
      config.LogConfig.Type !== 'none' || initial.Config.User !== '65534:65534' ||
      JSON.stringify(config.CapDrop) !== '["ALL"]' ||
      !config.SecurityOpt.includes('no-new-privileges') || !storageMatches ||
      JSON.stringify(initial.Config.Entrypoint) !== '["/usr/local/bin/python3"]' ||
      JSON.stringify(initial.Config.Cmd) !== JSON.stringify(['-I', '-B', '-c', probe])) {
    throw new Error('effective Docker container configuration differs');
  }
  const completed = await docker(['start', '--attach', containerId]);
  if (completed.stderr !== '') throw new Error('capability probe produced stderr');
  const terminal = await inspect(containerId);
  if (terminal.State.Running || terminal.State.OOMKilled || terminal.State.Dead ||
      terminal.State.Pid !== 0 || terminal.State.ExitCode !== 0) {
    throw new Error('capability probe lacks a clean terminal state');
  }
  const lines = completed.stdout.split('\n');
  if (lines.length !== 2 || lines[1] !== '') throw new Error('capability result framing differs');
  result = JSON.parse(lines[0]);
  if (result.scope !== 'docker_environment_only' || result.noswap !== true ||
      result.memory_bytes !== 67_108_864 || result.swap_bytes !== 0 ||
      result.filesystem_bytes !== 8_388_608 || result.errno !== 28 ||
      result.filler_removed !== true || !Number.isSafeInteger(result.written_bytes) ||
      result.written_bytes <= 0 || result.written_bytes > 8_388_608) {
    throw new Error('capability result is incomplete');
  }
} catch (error) {
  primaryError = error;
} finally {
  try {
    let owned;
    if (containerId) {
      owned = await inspect(containerId, true);
    } else {
      const lookup = await docker(['container', 'ls', '-aq', '--no-trunc', '--filter', `name=^/${name}$`], true);
      const found = lookup.stdout.trim();
      if (found) owned = await inspect(found, true);
    }
    if (owned) {
      if (owned.State.Running) await docker(['kill', owned.Id], true);
      const stopped = await inspect(owned.Id, true);
      if (stopped.State.Running || stopped.State.Pid !== 0) throw new Error('owned probe did not stop');
      await docker(managedVolume ? ['rm', owned.Id] : ['rm', '--volumes', owned.Id], true);
    }
    const remaining = await docker(['container', 'ls', '-aq', '--no-trunc', '--filter', `label=${label}=${owner}`], true);
    if (remaining.stdout.trim()) throw new Error('owned probe container remains');
    if (managedVolume) {
      if (await findVolume(true)) {
        await inspectVolume(true);
        await docker(['volume', 'rm', volumeName], true);
      }
      const volumes = await docker(['volume', 'ls', '-q', '--filter', `label=${label}=${owner}`], true);
      if (volumes.stdout.trim()) throw new Error('owned capability volume remains');
    }
  } catch (error) {
    primaryError = new Error(`${primaryError?.message ?? 'probe'}; cleanup unresolved: ${error.message}; owned name=${name}`);
  }
}

if (pendingClients.size !== 0 || performance.now() > deadline) {
  primaryError = new Error(`${primaryError?.message ?? 'probe'}; end/owned client release unresolved`);
}

if (primaryError) {
  console.error(primaryError.message);
  process.exitCode = primaryError.command === 'create' ? 78 : 1;
} else {
  console.log(JSON.stringify({ ...result, image, storage_mode: managedVolume ? 'managed_tmpfs_volume' : 'direct_tmpfs', container_removed: true, ...(managedVolume ? { volume_removed: true } : {}), evidence_bytes: outputBytes }));
}
