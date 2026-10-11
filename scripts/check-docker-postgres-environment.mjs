#!/usr/bin/env node
// Disposable Docker ENV evidence; not the Sunrise Edge PostgreSQL suite.
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';

if (process.argv.length !== 2) throw new Error('this fixed ENV probe takes no arguments');
const pythonImage = 'sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea';
const postgresImage = 'sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2';
const endpoint = 'unix:///var/run/docker.sock';
const owner = randomUUID();
const prefix = 'sunrise-edge-pg-env-' + owner;
const label = 'sunrise-edge.pg-environment-owner';
const volumeName = prefix + '-memory';
const volumeOptions = 'rw,nosuid,nodev,noexec,size=512m,nr_inodes=16384,mode=0700,uid=70,gid=70,noswap';
const deadline = performance.now() + 90_000;
const captureLimit = 65_536;
const cleanupReserve = 32_768;
const pendingClients = new Set();
const containers = [];
const environment = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) {
  delete environment[key];
}
let captureBytes = 0;
let volumeMountpoint;
let primaryError;
let result;

const settings = [
  ['shared_memory_type', 'mmap'], ['dynamic_shared_memory_type', 'mmap'],
  ['huge_pages', 'off'], ['shared_buffers', '16MB'], ['max_connections', '10'],
  ['work_mem', '1MB'], ['maintenance_work_mem', '16MB'],
  ['min_dynamic_shared_memory', '0'], ['io_method', 'sync'],
  ['max_parallel_workers_per_gather', '0'],
  ['unix_socket_directories', '/var/run/postgresql'],
  ['listen_addresses', 'localhost'], ['port', '5432'],
  ['min_wal_size', '32MB'], ['max_wal_size', '64MB'],
  ['fsync', 'on'], ['synchronous_commit', 'on'],
  ['logging_collector', 'off'], ['log_destination', 'stderr'],
];
const serverCommand = ['postgres', ...settings.flatMap(([key, value]) => ['-c', key + '=' + value])];
const initArguments = ['--locale=C', '--encoding=UTF8', '--auth-local=trust', '--auth-host=scram-sha-256',
  ...settings.map(([key, value]) => '--set=' + key + '=' + value)].join(' ');
const postgresEnvironment = [
  'PGDATA=/var/lib/postgresql/18/docker', 'TMPDIR=/var/lib/postgresql/tmp',
  'POSTGRES_USER=postgres', 'POSTGRES_DB=sunrise_edge_test',
  'POSTGRES_PASSWORD=disposable-docker-environment-only',
  'POSTGRES_INITDB_ARGS=' + initArguments,
];
const probe = String.raw`
import json, os, stat

def read_small(path):
    with open(path, "rb") as source:
        body = source.read(65537)
    if len(body) > 65536:
        raise RuntimeError("bounded kernel evidence exceeded")
    return body.decode("ascii")

rows = [line.split() for line in read_small("/proc/self/mountinfo").splitlines()]
selected = [row for row in rows if row[4] == "/retained"]
if len(selected) != 1:
    raise RuntimeError("retained mount is not unique")
row = selected[0]
separator = row.index("-")
options = set(row[5].split(",")) | set(row[separator + 3].split(","))
if row[separator + 1] != "tmpfs" or not {"nosuid", "nodev", "noexec", "noswap"}.issubset(options):
    raise RuntimeError("retained filesystem is not qualified tmpfs")
named = os.stat("/retained", follow_symlinks=False)
capacity = os.statvfs("/retained")
if not stat.S_ISDIR(named.st_mode) or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (70, 70, 0o700):
    raise RuntimeError("retained root ownership differs")
if capacity.f_frsize * capacity.f_blocks != 536870912 or capacity.f_files != 16384:
    raise RuntimeError("retained byte/inode ceilings differ")
for path, expected in [("memory.max", "67108864"), ("memory.swap.max", "0"), ("pids.max", "32"), ("cpu.max", "25000 100000")]:
    if read_small("/sys/fs/cgroup/" + path).strip() != expected:
        raise RuntimeError("effective keeper resource bound differs")
status = dict(line.split(":", 1) for line in read_small("/proc/self/status").splitlines() if ":" in line)
if status.get("NoNewPrivs", "").strip() != "1" or status.get("Seccomp", "").strip() != "2":
    raise RuntimeError("keeper protection differs")
print(json.dumps({"mount_id":row[0], "device":row[2], "root":row[3], "inode":named.st_ino,
    "stat_device":named.st_dev, "options":sorted(options), "bytes":536870912, "inodes":16384}, sort_keys=True))
`;
const keeperProgram = String.raw`
import os, signal, time
directory = os.open("/retained", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
original = os.fstat(directory)
stopping = False
def stop(signum, frame):
    global stopping
    stopping = True
signal.signal(signal.SIGTERM, stop)
end = time.monotonic() + 120
try:
    while not stopping and time.monotonic() < end:
        held = os.fstat(directory)
        named = os.stat("/retained", follow_symlinks=False)
        if (held.st_dev, held.st_ino) != (original.st_dev, original.st_ino) or (named.st_dev, named.st_ino) != (original.st_dev, original.st_ino):
            raise RuntimeError("keeper root identity changed")
        time.sleep(0.2)
finally:
    os.close(directory)
`;
const initializerProgram = String.raw`
import os, stat
directory = os.open("/retained", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    original = os.fstat(directory)
    if os.listdir(directory):
        raise RuntimeError("fresh retained root is not empty")
    for name in ["socket", "tmp"]:
        os.mkdir(name, 0o700, dir_fd=directory)
        child = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISDIR(child.st_mode) or child.st_dev != original.st_dev or (child.st_uid, child.st_gid, stat.S_IMODE(child.st_mode)) != (70, 70, 0o700):
            raise RuntimeError("initializer directory identity differs")
    named = os.stat("/retained", follow_symlinks=False)
    if (named.st_dev, named.st_ino) != (original.st_dev, original.st_ino) or sorted(os.listdir(directory)) != ["socket", "tmp"]:
        raise RuntimeError("initializer changed retained root")
finally:
    os.close(directory)
`;

async function docker(args, cleanup = false, acceptedCodes = [0]) {
  const available = Math.floor(deadline - performance.now() - (cleanup ? 0 : 30_000));
  const allowance = Math.min(cleanup ? 5_000 : 10_000, available);
  if (allowance <= 0) throw new Error('ENV deadline expired');
  const commandEnd = performance.now() + allowance;
  const activeLimit = cleanup ? captureLimit : captureLimit - cleanupReserve;
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/local/bin/docker', ['--host', endpoint, ...args], {
      env: environment, stdio: ['ignore', 'pipe', 'pipe'],
    });
    pendingClients.add(child);
    const stdout = [];
    const stderr = [];
    let stdoutEof = false;
    let stderrEof = false;
    let failure;
    let settled = false;
    let reapTimer;
    const rejectOnce = (error) => { if (!settled) { settled = true; reject(error); } };
    function abort(error) {
      failure ??= error;
      child.kill('SIGKILL');
      if (reapTimer) return;
      reapTimer = setTimeout(() => {
        child.unref();
        child.stdout.destroy();
        child.stderr.destroy();
        rejectOnce(new Error(failure.message + '; Docker client reap/EOF unresolved, pid=' + (child.pid ?? 'unknown')));
      }, Math.max(1, Math.min(1_000, Math.floor(deadline - performance.now()))));
    }
    const timer = setTimeout(() => abort(new Error('Docker command deadline expired')), allowance);
    function collect(target, chunk) {
      if (failure) return;
      if (chunk.length > activeLimit - captureBytes) {
        const executable = args[0] === 'exec' ? ', executable=' + args[2] : '';
        abort(new Error('complete ENV evidence exceeds allocation: operation=' + args[0] +
          executable + ', captured=' + captureBytes + ', next_chunk=' + chunk.length +
          ', active_limit=' + activeLimit));
        return;
      }
      captureBytes += chunk.length;
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
      if (performance.now() > commandEnd) failure ??= new Error('Docker completion observed after deadline');
      if (failure) return rejectOnce(failure);
      if (!stdoutEof || !stderrEof) return rejectOnce(new Error('Docker output lacks both physical EOFs'));
      const answer = { code, signal, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') };
      if (!acceptedCodes.includes(code) || signal !== null) {
        const executable = args[0] === 'exec' ? ' executable=' + args[2] : '';
        return rejectOnce(new Error('Docker ' + args[0] + ' exit=' + String(code) + ' signal=' + String(signal) +
          executable + ' refused: ' + answer.stderr.trim()));
      }
      settled = true;
      resolve(answer);
    });
  });
}

const identityFormat = '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"State":{{json .State}},"RestartCount":{{json .RestartCount}},"Config":{"Labels":{{json .Config.Labels}}}}';
const configurationKeys = ['Labels', 'User', 'Cmd', 'Healthcheck', 'Entrypoint', 'Env'];
const hostConfigurationKeys = [
  'Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit', 'NetworkMode', 'IpcMode',
  'CgroupnsMode', 'PidMode', 'UTSMode', 'UsernsMode', 'ReadonlyRootfs', 'Privileged',
  'AutoRemove', 'RestartPolicy', 'LogConfig', 'CapDrop', 'SecurityOpt', 'CapAdd',
  'Binds', 'Tmpfs', 'Mounts',
];
const inspectObjectFormat = (scope, keys) => '{' + keys
  .map((key) => '"' + key + '":{{json (index .' + scope + ' "' + key + '")}}')
  .join(',') + '}';
const configurationFormat = '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"State":{{json .State}},"RestartCount":{{json .RestartCount}},"Config":' +
  inspectObjectFormat('Config', configurationKeys) + ',"Mounts":{{json .Mounts}},"HostConfig":' +
  inspectObjectFormat('HostConfig', hostConfigurationKeys) + '}';
async function inspect(record, cleanup = false, configuration = false) {
  const answer = await docker(['container', 'inspect', '--format', configuration ? configurationFormat : identityFormat, record.id ?? record.name], cleanup);
  const row = JSON.parse(answer.stdout);
  if (row === null || Array.isArray(row) || row.Id !== record.id || row.Name !== '/' + record.name ||
      row.Image !== record.image || row.Config.Labels?.[label] !== owner) {
    throw new Error('container exact ownership differs: ' + record.name);
  }
  return row;
}
function requireRunning(row) {
  if (!row.State.Running || row.State.Pid <= 0 || row.State.OOMKilled || row.State.Dead ||
      row.RestartCount !== 0 || row.State.StartedAt === '0001-01-01T00:00:00Z') {
    throw new Error('owned container is not continuously live');
  }
}
async function inspectVolume(cleanup = false) {
  const answer = await docker(['volume', 'inspect', volumeName], cleanup);
  const rows = JSON.parse(answer.stdout);
  if (!Array.isArray(rows) || rows.length !== 1) throw new Error('volume inspection is not unique');
  const volume = rows[0];
  if (volume.Name !== volumeName || volume.Driver !== 'local' || volume.Scope !== 'local' ||
      volume.Labels?.[label] !== owner || JSON.stringify(Object.keys(volume.Options ?? {}).sort()) !== '["device","o","type"]' ||
      volume.Options.type !== 'tmpfs' || volume.Options.device !== 'tmpfs' || volume.Options.o !== volumeOptions ||
      typeof volume.Mountpoint !== 'string' || !volume.Mountpoint.startsWith('/') || volume.Mountpoint.includes('\0') ||
      (volumeMountpoint !== undefined && volumeMountpoint !== volume.Mountpoint)) {
    throw new Error('exact bounded volume identity differs');
  }
  volumeMountpoint = volume.Mountpoint;
  return volume;
}
async function findVolume(cleanup = false) {
  const answer = await docker(['volume', 'ls', '-q', '--filter', 'name=^' + volumeName + '$'], cleanup);
  if (answer.stdout.trim() === '') return false;
  if (answer.stdout !== volumeName + '\n') throw new Error('volume lookup is not exact');
  return true;
}
async function create(role, image, command, mounts, memory, cpu, pids, extra = []) {
  const record = { name: prefix + '-' + role, image };
  containers.push(record);
  const common = ['create', '--pull=never', '--name', record.name, '--label', label + '=' + owner,
    '--user', '70:70', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true',
    '--security-opt', 'seccomp=builtin', '--restart', 'no', '--network', 'none', '--ipc', 'none', '--cgroupns', 'private',
    '--log-driver', 'none', '--no-healthcheck', '--memory', memory + 'm', '--memory-swap', memory + 'm',
    '--cpus', String(cpu), '--pids-limit', String(pids)];
  const answer = await docker([...common, ...mounts.flatMap((mount) => ['--mount', mount]), ...extra, image, ...command]);
  const candidateId = answer.stdout.trim();
  if (!/^[0-9a-f]{64}$/.test(candidateId)) throw new Error('exact creation id invalid');
  record.id = candidateId;
  const initial = await inspect(record, false, true);
  const config = initial.HostConfig;
  if (config.Memory !== memory * 1_048_576 || config.MemorySwap !== memory * 1_048_576 ||
      config.NanoCpus !== cpu * 1_000_000_000 || config.PidsLimit !== pids ||
      config.NetworkMode !== 'none' || config.IpcMode !== 'none' || config.CgroupnsMode !== 'private' ||
      config.PidMode !== '' || config.UTSMode !== '' || config.UsernsMode !== '' || config.ReadonlyRootfs !== true ||
      config.Privileged !== false || config.AutoRemove !== false || config.RestartPolicy.Name !== 'no' ||
      config.LogConfig.Type !== 'none' || initial.Config.User !== '70:70' ||
      JSON.stringify(config.CapDrop) !== '["ALL"]' || !config.SecurityOpt.includes('no-new-privileges=true') ||
      !config.SecurityOpt.includes('seccomp=builtin') || (config.CapAdd ?? []).length !== 0 || (config.Binds ?? []).length !== 0 ||
      Object.keys(config.Tmpfs ?? {}).length !== 0 || initial.State.Running || initial.State.Pid !== 0 ||
      JSON.stringify(initial.Config.Cmd) !== JSON.stringify(command) ||
      initial.Config.Healthcheck?.Test?.[0] !== 'NONE') {
    throw new Error('effective container configuration differs: ' + role);
  }
  const expectedEntrypoint = image === pythonImage ? ['/usr/local/bin/python3'] : ['docker-entrypoint.sh'];
  if (JSON.stringify(initial.Config.Entrypoint) !== JSON.stringify(expectedEntrypoint) ||
      !Array.isArray(initial.Mounts) || initial.Mounts.length !== mounts.length ||
      !Array.isArray(config.Mounts) || config.Mounts.length !== mounts.length) {
    throw new Error('container entrypoint or mount count differs');
  }
  const expectedTargets = role === 'primary' ? ['/var/lib/postgresql', '/var/run/postgresql'] : ['/retained'];
  const requestedTargets = config.Mounts.map((mount) => mount.Target);
  const actualTargets = initial.Mounts.map((mount) => mount.Destination);
  for (const targets of [requestedTargets, actualTargets]) {
    if (targets.length !== expectedTargets.length || new Set(targets).size !== expectedTargets.length ||
        targets.some((target) => !expectedTargets.includes(target))) {
      throw new Error('container mount targets are not a complete unique set');
    }
  }
  for (const mount of initial.Mounts) {
    const allowedSources = mount.Destination === '/var/run/postgresql'
      ? [volumeMountpoint, volumeMountpoint + '/socket'] : [volumeMountpoint];
    if (mount.Type !== 'volume' || mount.Name !== volumeName || mount.Driver !== 'local' ||
        !allowedSources.includes(mount.Source)) {
      throw new Error('container uses a foreign or anonymous mount');
    }
  }
  for (let index = 0; index < config.Mounts.length; index += 1) {
    const requested = config.Mounts[index];
    const actual = initial.Mounts.find((mount) => mount.Destination === requested.Target);
    const subpath = requested.VolumeOptions?.Subpath;
    const expectedReadonly = role === 'keeper';
    if (requested.Type !== 'volume' || requested.Source !== volumeName || !expectedTargets.includes(requested.Target) ||
        (requested.ReadOnly ?? false) !== expectedReadonly || requested.VolumeOptions?.NoCopy !== true ||
        (subpath ?? '') !== (requested.Target === '/var/run/postgresql' ? 'socket' : '') ||
        actual?.RW !== !expectedReadonly) throw new Error('effective requested mount differs');
  }
  if (image === postgresImage) {
    for (const value of postgresEnvironment) {
      if (!initial.Config.Env.includes(value)) throw new Error('literal PostgreSQL environment differs');
    }
    if (initial.Config.Env.some((value) => value.split('=')[0].endsWith('_FILE'))) throw new Error('unselected file-based input');
  }
  return record;
}
async function start(record, attached = false) {
  const answer = await docker(['start', ...(attached ? ['--attach'] : []), record.id]);
  if (!attached && answer.stdout !== record.id + '\n') throw new Error('start identity differs');
  return answer;
}
async function keeperObservation(keeper, original) {
  const row = await inspect(keeper);
  requireRunning(row);
  const answer = await docker(['exec', keeper.id, '/usr/local/bin/python3', '-I', '-B', '-c', probe]);
  if (answer.stderr !== '' || answer.stdout.split('\n').length !== 2) throw new Error('keeper evidence framing differs');
  const identity = JSON.parse(answer.stdout);
  const observation = { pid: row.State.Pid, started: row.State.StartedAt, identity };
  if (original !== undefined && JSON.stringify(observation) !== JSON.stringify(original)) {
    throw new Error('keeper continuity or retained mount identity changed');
  }
  return observation;
}
const pause = () => new Promise((resolve) => setTimeout(resolve, 200));
async function finalServerReady(primary) {
  while (performance.now() < deadline - 30_000) {
    const row = await inspect(primary);
    requireRunning(row);
    const executable = await docker(['exec', primary.id, '/usr/bin/readlink', '/proc/1/exe']);
    const command = await docker(['exec', primary.id, '/bin/cat', '/proc/1/cmdline']);
    const expected = serverCommand.join('\0') + '\0';
    if (executable.stdout === '/usr/local/bin/postgres\n' && command.stdout === expected) {
      const ready = await docker(['exec', primary.id, 'pg_isready', '-q', '-h', '/var/run/postgresql',
        '-U', 'postgres', '-d', 'sunrise_edge_test'], false, [0, 1, 2]);
      if (ready.code === 0 && ready.stdout === '' && ready.stderr === '') return row;
    }
    await pause();
  }
  throw new Error('final PostgreSQL server readiness deadline');
}
async function sql(primary, statement) {
  const answer = await docker(['exec', primary.id, 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-qAt',
    '-h', '/var/run/postgresql', '-U', 'postgres', '-d', 'sunrise_edge_test',
    '-c', "SET statement_timeout='1500ms'; SET lock_timeout='500ms'; SET idle_in_transaction_session_timeout='1500ms'; " + statement]);
  if (answer.stderr !== '') throw new Error('SQL produced unexpected stderr');
  return answer.stdout;
}
const settingsQuery = settings.map(([key]) => "'" + key + "',current_setting('" + key + "')").join(',');
// Read once with an overflow byte. Remove exactly the required terminal LF,
// never trim a line; retain every complete match, including duplicates and shm.
const snapshotQuery = "WITH mount_source AS MATERIALIZED (" +
  "SELECT pg_read_file('/proc/self/mountinfo',0,65537) AS body)," +
  "mount_lines AS MATERIALIZED (SELECT raw.ordinal::integer AS ordinal,raw.line," +
  "string_to_array(raw.line,' ') AS fields FROM mount_source," +
  "LATERAL unnest(string_to_array(left(body,-1),E'\\n')) WITH ORDINALITY AS raw(line,ordinal))," +
  "mount_shape AS MATERIALIZED (SELECT octet_length(body) AS source_bytes," +
  "CASE WHEN octet_length(body)>65536 THEN 'oversize' WHEN body='' OR right(body,1)<>E'\\n'" +
  " OR body ~ E'[^ -~\\n]' OR EXISTS(SELECT 1 FROM mount_lines WHERE line=''" +
  " OR left(line,1)=' ' OR right(line,1)=' ' OR position('  ' IN line)>0" +
  " OR cardinality(fields)<10 OR array_position(fields,'-') IS NULL" +
  " OR array_position(fields,'-')<7 OR cardinality(fields)<>array_position(fields,'-')+3)" +
  " THEN 'malformed' ELSE 'complete' END AS framing FROM mount_source)" +
  " SELECT json_build_object('cluster',(SELECT system_identifier::text FROM pg_control_system())," +
  "'start_us',((extract(epoch FROM pg_postmaster_start_time())*1000000)::bigint)::text," +
  "'database',current_database(),'data_directory',current_setting('data_directory'),'version',current_setting('server_version_num')," +
  "'settings',json_build_object(" + settingsQuery + "),'rows',(SELECT json_agg(json_build_object('id',id,'payload',encode(payload,'hex')) ORDER BY id) FROM environment_probe)," +
  "'mounts',(SELECT json_build_object('version',1,'read_limit',65537,'source_bytes',source_bytes," +
  "'source_rows',(SELECT count(*) FROM mount_lines),'framing',framing," +
  "'selected',(SELECT COALESCE(json_agg(json_build_object('ordinal',ordinal,'line',line) ORDER BY ordinal),'[]'::json)" +
  " FROM mount_lines WHERE fields[5] IN ('/var/lib/postgresql','/run/postgresql','/dev/shm'))) FROM mount_shape)," +
  "'memory',pg_read_file('/sys/fs/cgroup/memory.max',0,64),'swap',pg_read_file('/sys/fs/cgroup/memory.swap.max',0,64)," +
  "'pids',pg_read_file('/sys/fs/cgroup/pids.max',0,64),'cpu',pg_read_file('/sys/fs/cgroup/cpu.max',0,64))";
async function snapshot(primary, retained) {
  const output = await sql(primary, snapshotQuery);
  if (output.split('\n').length !== 2) throw new Error('SQL snapshot framing differs');
  const value = JSON.parse(output);
  if (value.database !== 'sunrise_edge_test' || value.data_directory !== '/var/lib/postgresql/18/docker' ||
      value.version !== '180006' || !/^[0-9]+$/.test(value.cluster) || !/^[0-9]+$/.test(value.start_us) ||
      JSON.stringify(value.rows) !== '[{"id":1,"payload":"53554e524953452d50472d454e56"}]' ||
      value.memory.trim() !== '536870912' || value.swap.trim() !== '0' ||
      value.pids.trim() !== '128' || value.cpu.trim() !== '100000 100000' ||
      Object.keys(value.settings).length !== settings.length) throw new Error('complete PG identity/fixture/resource oracle differs');
  for (const [key, expected] of settings) {
    if (value.settings[key] !== expected) throw new Error('effective PostgreSQL setting differs: ' + key);
  }
  const mounts = value.mounts;
  if (mounts === null || typeof mounts !== 'object' || Array.isArray(mounts) ||
      JSON.stringify(Object.keys(mounts).sort()) !== '["framing","read_limit","selected","source_bytes","source_rows","version"]' ||
      mounts.version !== 1 || mounts.read_limit !== 65537 || mounts.framing !== 'complete' ||
      !Number.isInteger(mounts.source_bytes) || mounts.source_bytes <= 0 || mounts.source_bytes > 65536 ||
      !Number.isInteger(mounts.source_rows) || mounts.source_rows <= 0 || mounts.source_rows > mounts.source_bytes ||
      !Array.isArray(mounts.selected) || mounts.selected.length > mounts.source_rows) {
    throw new Error('complete PG mount subset framing differs');
  }
  const mountRows = [];
  let previousOrdinal = 0;
  let selectedBytes = 0;
  for (const entry of mounts.selected) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry) ||
        JSON.stringify(Object.keys(entry).sort()) !== '["line","ordinal"]' ||
        !Number.isInteger(entry.ordinal) || entry.ordinal <= previousOrdinal || entry.ordinal > mounts.source_rows ||
        typeof entry.line !== 'string' || entry.line.length === 0 || /[^\x20-\x7e]/.test(entry.line) ||
        entry.line.startsWith(' ') || entry.line.endsWith(' ') || entry.line.includes('  ')) {
      throw new Error('complete PG mount subset row differs');
    }
    const row = entry.line.split(' ');
    const separator = row.indexOf('-');
    selectedBytes += Buffer.byteLength(entry.line, 'ascii') + 1;
    if (row.length < 10 || separator < 6 || row.length !== separator + 4 ||
        !['/var/lib/postgresql', '/run/postgresql', '/dev/shm'].includes(row[4]) ||
        selectedBytes > mounts.source_bytes) throw new Error('complete PG mount subset provenance differs');
    previousOrdinal = entry.ordinal;
    mountRows.push(row);
  }
  if (mountRows.some((row) => row[4] === '/dev/shm')) throw new Error('unselected dedicated shared-memory mount');
  // The pinned Alpine image aliases /var/run to ../run; check its kernel path.
  for (const [path, root] of [['/var/lib/postgresql', '/'], ['/run/postgresql', '/socket']]) {
    const matches = mountRows.filter((row) => row[4] === path);
    if (matches.length !== 1) throw new Error('PG selected mount not unique');
    const row = matches[0];
    const separator = row.indexOf('-');
    const flags = new Set([...row[5].split(','), ...row[separator + 3].split(',')]);
    if (row[2] !== retained.identity.device || row[3] !== root || row[separator + 1] !== 'tmpfs' ||
        !['rw', 'nosuid', 'nodev', 'noexec', 'noswap'].every((flag) => flags.has(flag))) {
      throw new Error('PG mount differs from the retained allocation');
    }
  }
  const stamp = await docker(['exec', primary.id, '/bin/stat', '-c', '%d:%i:%u:%g:%a',
    '/var/lib/postgresql', '/var/lib/postgresql/socket', '/var/run/postgresql']);
  const rows = stamp.stdout.trim().split('\n');
  if (rows.length !== 3 || rows[0] !== retained.identity.stat_device + ':' + retained.identity.inode + ':70:70:700' ||
      rows[1] !== rows[2] || !/^[0-9]+:[0-9]+:70:70:3775$/.test(rows[1]) || stamp.stderr !== '') {
    throw new Error('PG root/socket inode identity differs');
  }
  return value;
}
async function removeContainer(record) {
  if (record.removed) return;
  if (record.id === undefined) {
    const found = await docker(['container', 'ls', '-aq', '--no-trunc', '--filter', 'name=^/' + record.name + '$'], true);
    if (!found.stdout.trim()) { record.removed = true; return; }
    record.id = found.stdout.trim();
    if (!/^[0-9a-f]{64}$/.test(record.id)) throw new Error('ambiguous container lookup');
  }
  const before = await inspect(record, true);
  if (before.State.Running) await docker(['kill', record.id], true);
  const after = await inspect(record, true);
  if (after.State.Running || after.State.Pid !== 0) throw new Error('owned container failed to stop');
  await docker(['rm', record.id], true);
  record.removed = true;
}

try {
  if (await findVolume()) throw new Error('fresh ENV volume already exists');
  const made = await docker(['volume', 'create', '--driver', 'local', '--name', volumeName,
    '--label', label + '=' + owner, '--opt', 'type=tmpfs', '--opt', 'device=tmpfs', '--opt', 'o=' + volumeOptions]);
  if (made.stdout !== volumeName + '\n') throw new Error('created volume identity differs');
  await inspectVolume();
  const rootMount = 'type=volume,source=' + volumeName + ',target=/retained,volume-nocopy';
  const keeper = await create('keeper', pythonImage, ['-I', '-B', '-c', keeperProgram], [rootMount + ',readonly'],
    64, 0.25, 32, ['--entrypoint', '/usr/local/bin/python3']);
  await start(keeper);
  const retained = await keeperObservation(keeper);
  const initializer = await create('initializer', pythonImage, ['-I', '-B', '-c', initializerProgram], [rootMount],
    64, 0.25, 32, ['--entrypoint', '/usr/local/bin/python3']);
  const initialized = await start(initializer, true);
  const initializedState = await inspect(initializer);
  if (initialized.stdout !== '' || initialized.stderr !== '' || initializedState.State.Running ||
      initializedState.State.Pid !== 0 || initializedState.State.ExitCode !== 0 ||
      initializedState.State.OOMKilled || initializedState.State.Dead) throw new Error('directory initializer incomplete');
  await removeContainer(initializer);
  await keeperObservation(keeper, retained);
  const primary = await create('primary', postgresImage, serverCommand,
    ['type=volume,source=' + volumeName + ',target=/var/lib/postgresql,volume-nocopy',
      'type=volume,source=' + volumeName + ',target=/var/run/postgresql,volume-subpath=socket,volume-nocopy'],
    512, 1, 128, postgresEnvironment.flatMap((value) => ['--env', value]));
  await start(primary);
  const liveBefore = await finalServerReady(primary);
  const mutated = await sql(primary, "BEGIN; CREATE TABLE environment_probe(id integer PRIMARY KEY,payload bytea NOT NULL);" +
    " INSERT INTO environment_probe VALUES(1,decode('53554e524953452d50472d454e56','hex')); COMMIT;");
  if (mutated !== '') throw new Error('fixture mutation acknowledgement differs');
  const before = await snapshot(primary, retained);
  await keeperObservation(keeper, retained);
  const current = await inspect(primary);
  requireRunning(current);
  if (current.State.Pid !== liveBefore.State.Pid || current.State.StartedAt !== liveBefore.State.StartedAt) {
    throw new Error('primary changed before the selected SIGKILL');
  }
  await docker(['kill', '--signal', 'SIGKILL', primary.id]);
  const killed = await inspect(primary);
  if (killed.State.Running || killed.State.Pid !== 0 || killed.State.ExitCode !== 137 ||
      killed.State.OOMKilled || killed.State.Dead) throw new Error('selected SIGKILL terminal differs');
  await keeperObservation(keeper, retained);
  await start(primary);
  await finalServerReady(primary);
  const after = await snapshot(primary, retained);
  if (after.cluster !== before.cluster || BigInt(after.start_us) <= BigInt(before.start_us) ||
      JSON.stringify(after.rows) !== JSON.stringify(before.rows)) throw new Error('same-cluster retained fixture differs after SIGKILL');
  await keeperObservation(keeper, retained);
  await inspectVolume();
  result = { scope: 'docker_postgres_environment_only', image: postgresImage, owner,
    storage: volumeName, filesystem_bytes: 536_870_912, inode_ceiling: 16_384, noswap: true,
    primary_memory_bytes: 536_870_912, primary_swap_bytes: 0, same_container_id: primary.id,
    cluster: after.cluster, before_start_us: before.start_us, after_start_us: after.start_us,
    fixture: after.rows, sigkill_exit: killed.State.ExitCode, keeper_continuous: true,
    host_url_or_full_suite: false, physical_durability: false };
} catch (error) {
  primaryError = error;
} finally {
  try {
    // Do not release the retained allocation while any owned database/init
    // process may still be using it. A failure preserves exact targets.
    for (const record of containers.filter((record) => !record.name.endsWith('-keeper'))) await removeContainer(record);
    for (const record of containers.filter((record) => record.name.endsWith('-keeper'))) await removeContainer(record);
    const left = await docker(['container', 'ls', '-aq', '--no-trunc', '--filter', 'label=' + label + '=' + owner], true);
    if (left.stdout.trim()) throw new Error('owned ENV container remains');
    if (await findVolume(true)) {
      await inspectVolume(true);
      await docker(['volume', 'rm', volumeName], true);
    }
    const volumes = await docker(['volume', 'ls', '-q', '--filter', 'label=' + label + '=' + owner], true);
    if (volumes.stdout.trim()) throw new Error('owned ENV volume remains');
  } catch (error) {
    primaryError = new Error((primaryError?.message ?? 'ENV') + '; cleanup unresolved: ' + error.message +
      '; exact owner=' + owner + '; volume=' + volumeName);
  }
}
if (pendingClients.size !== 0 || performance.now() > deadline) {
  primaryError = new Error((primaryError?.message ?? 'ENV') + '; client release/end deadline unresolved');
}
if (primaryError) {
  console.error(primaryError.message);
  process.exitCode = 1;
} else {
  const final = JSON.stringify({ ...result, containers_removed: true, volume_removed: true, evidence_bytes: captureBytes });
  if (captureBytes + Buffer.byteLength(final) + 1 > captureLimit) {
    console.error('complete ENV terminal serialization exceeds evidence bound');
    process.exitCode = 1;
  } else {
    console.log(final);
  }
}
