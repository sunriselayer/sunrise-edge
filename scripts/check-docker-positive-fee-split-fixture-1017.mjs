#!/usr/bin/env node
// Selected original-successor positive Split only. No compiler, image pull,
// generic frame signing, private export or alternate authority (DR-0270).
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { performance } from 'node:perf_hooks';
import { existsSync, statSync, lstatSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { basename, dirname, resolve, join } from 'node:path';
const image = 'python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea';
const imageId = 'sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea';
const endpoint = 'unix:///var/run/docker.sock';
const owner = randomUUID();
const name = `sunrise-positive-split-1017-${owner}`;
const label = 'sunrise-edge.positive-split-fixture-1017-owner';
const volumeName = `${name}-memory`;
const volumeOptions = 'rw,nosuid,nodev,noexec,size=64m,nr_inodes=16384,mode=0711,uid=0,gid=0,noswap';
const deadline = performance.now() + 280_000;
const outputLimit = 65_536;
const cleanupReserve = 16_384;
const dockerEnvironment = { ...process.env };
for (const variable of ['DOCKER_CONTEXT', 'DOCKER_HOST', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete dockerEnvironment[variable];
const pendingClients = new Set();
let outputBytes = 0, operationCount = 0;
let containerId, primaryError, result, volumeExpected = false, volumeMountpoint;
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
function assertMountSafePath(label_, path) {
  if (!path.startsWith('/') || /["',\s]/.test(path)) throw new Error(`${label_}: unsafe absolute mount path`);
}
const flags = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  const key = process.argv[i], value = process.argv[i + 1];
  if (!['--public-index', '--public-index-sha256', '--provenance-index', '--provenance-index-sha256'].includes(key) || flags.has(key) || value === undefined) throw new Error('explicit unique selected input flags required');
  flags.set(key, value);
}
if (flags.size !== 4) throw new Error('all four selected input pins required');
const publicIndex = flags.get('--public-index'), publicRoot = dirname(publicIndex);
const provenancePath = flags.get('--provenance-index');
for (const path of [publicIndex, provenancePath]) assertMountSafePath('input', path);
for (const [path, expected] of [[publicIndex, flags.get('--public-index-sha256')], [provenancePath, flags.get('--provenance-index-sha256')]]) {
  if (!/^[0-9a-f]{64}$/.test(expected) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink() || lstatSync(path).size > 262144 || hash(readFileSync(path)) !== expected) throw new Error('actual selected input index differs');
}
if (basename(publicIndex) !== 'files.tsv') throw new Error('fixed public index filename required');
const provenance = JSON.parse(readFileSync(provenancePath, 'utf8'));
if (!/^[0-9a-f]{40}$/.test(provenance.sourceHead) || !/^[0-9a-f]{40}$/.test(provenance.sourceTree)) throw new Error('source pins remain PENDING');
const cliBinary = provenance.cliBinary, testBinary = provenance.testBinary;
for (const [path, expected] of [[cliBinary, provenance.cliSha256], [testBinary, provenance.testSha256], [process.execPath, provenance.nodeSha256], [resolve(process.argv[1]), provenance.scriptSha256]]) {
  assertMountSafePath('actual binary/tool', path);
  const m = lstatSync(path);
  if (!m.isFile() || m.isSymbolicLink() || m.size > 268435456 || hash(readFileSync(path)) !== expected) throw new Error('actual binary/tool hash differs');
}
const evidenceRoot = publicRoot + '.uid-evidence';
if (existsSync(evidenceRoot)) throw new Error('create-only UID evidence destination exists');
mkdirSync(evidenceRoot, { mode: 0o700 });
const hostOperations = [];

const probe = String.raw`
# Embedded only by the selected Node owner (DR-0270).
import errno, hashlib, json, os, pty, select, signal, socket, stat, struct, subprocess, time
ROOT='/work'
CUSTODY_UID,CUSTODY_GID=12001,12001
OPERATOR_UID,OPERATOR_GID=12002,12002
INTRUDER_UID,INTRUDER_GID=12003,12003
LD='/mnt/libs/ld.so'; LIB='/mnt/libs'; CLI='/mnt/bin/cli'; HARNESS='/mnt/bin/harness'
END=time.monotonic()+230
RAW_CAP=262144
children=[]; operations=[]; services=[]; peer_controls=[]; approval_evidence=[]; raw_used=0; uncaptured_observed=0
raw_fd=None

def left():
    value=END-time.monotonic()
    if value<=0: raise RuntimeError('positive fixture global deadline exceeded')
    return value

def frame(meta,data=b''):
    global raw_used,uncaptured_observed
    header=json.dumps(meta,sort_keys=True,separators=(',',':')).encode()
    packet=struct.pack('>I',len(header))+header+struct.pack('>I',len(data))+data
    if raw_used+len(packet)>RAW_CAP:
        uncaptured_observed+=len(packet);raise RuntimeError('complete positive child/PTY raw cap exceeded; capture incomplete')
    view=memoryview(packet)
    while view:
        n=os.write(raw_fd,view)
        if n<=0: raise RuntimeError('raw evidence write did not advance')
        view=view[n:]
    raw_used+=len(packet)

def before(argv,uid,groups,kind):
    if len(operations)>=128: raise RuntimeError('positive child count exceeded')
    item={'index':len(operations),'argv':argv,'uid':uid,'groups':groups,'kind':kind,
          'stdoutEof':False,'stderrEof':False,'waitCompleted':False,'pidAbsent':False}
    operations.append(item); frame({'operation':item['index'],'stream':'command','uid':uid,'kind':kind},json.dumps(argv).encode())
    return item

def demote(uid,groups):
    def action():
        os.setgroups(groups);os.setgid(uid);os.setuid(uid)
    return action

def launch(argv,uid,groups,env=None):
    if sum(p.poll() is None for p in children)>=8: raise RuntimeError('positive concurrent child cap exceeded')
    item=before(argv,uid,groups,'pipes')
    p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                       preexec_fn=demote(uid,groups),env=env or {},cwd='/')
    children.append(p);item['pid']=p.pid
    return p,item

def finish(p,item,timeout=20):
    deadline=time.monotonic()+min(timeout,left())
    pipes={p.stdout.fileno():('stdout',bytearray()),p.stderr.fileno():('stderr',bytearray())}
    buffers={name:buf for name,buf in pipes.values()}
    for fd in pipes:os.set_blocking(fd,False)
    failure=None;kill_end=None
    while pipes or p.poll() is None:
        if failure is None and time.monotonic()>=deadline:
            failure='owned child deadline';p.kill();kill_end=time.monotonic()+5
        if kill_end is not None and time.monotonic()>=kill_end:raise RuntimeError('owned child reap/EOF unresolved')
        for fd in select.select(list(pipes),[],[],0.02)[0]:
            name,buf=pipes[fd];data=os.read(fd,4096)
            if data:
                frame({'operation':item['index'],'stream':name},data);buf.extend(data)
            else:
                item[name+'Eof']=True;del pipes[fd]
    p.wait(timeout=1);item['waitCompleted']=True;item['exit']=p.returncode
    item['pidAbsent']=not os.path.exists('/proc/'+str(p.pid))
    for name,buf in buffers.items():item[name+'Bytes']=len(buf);item[name+'Sha256']=hashlib.sha256(buf).hexdigest()
    p.stdout.close();p.stderr.close()
    frame({'operation':item['index'],'stream':'result'},json.dumps(item,sort_keys=True).encode())
    if failure:raise RuntimeError(failure)
    if not item['pidAbsent']:raise RuntimeError('owned PID remains after wait')
    return p.returncode,bytes(buffers['stdout']),bytes(buffers['stderr'])

def run(argv,uid,groups,env=None,success=True):
    p,item=launch(argv,uid,groups,env);rc,out,err=finish(p,item)
    if success and rc:raise RuntimeError('positive command refused: '+err.decode(errors='replace'))
    if not success and not rc:raise RuntimeError('expected positive fixture refusal succeeded')
    return out,err

def cli(*args):return [LD,'--library-path',LIB,CLI,*args]
def probe(mode,root,**more):
    env={'POSITIVE_SPLIT_MODE':mode,'POSITIVE_SPLIT_ROOT':root};env.update(more)
    return [LD,'--library-path',LIB,HARNESS,'custody::positive_fee_split_fixture::distinct_uid_positive_fee_split_probe','--exact','--ignored','--nocapture','--test-threads=1'],env

def put(path,data,uid,mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        view=memoryview(data)
        while view:
            n=os.write(fd,view)
            if n<=0:raise RuntimeError('public write did not advance')
            view=view[n:]
        os.fsync(fd)
    finally:os.close(fd)
    os.chown(path,uid,uid)

def mkdir(path,uid,mode=0o700):
    os.mkdir(path,mode);os.chown(path,uid,uid)

def bounded(path,cap=1048576):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size>cap:raise RuntimeError('public evidence file exceeds bound/type')
        data=bytearray()
        while len(data)<=cap:
            chunk=os.read(fd,min(65536,cap+1-len(data)))
            if not chunk:break
            data.extend(chunk)
        if len(data)>cap or len(data)!=s.st_size:raise RuntimeError('public evidence length changed')
        return bytes(data)
    finally:os.close(fd)

def fields(path):
    result={};suites=[]
    for line in bounded(path,262144).decode('ascii').splitlines():
        k,v=line.split('=',1)
        if k=='suite':suites.append(v)
        elif k in result:raise RuntimeError('duplicate public pin')
        else:result[k]=v
    result['suites']=suites;return result

def own_copy(source,dest,uid,cap=65536,replace=False):
    # Key material, when selected, remains entirely in this custody UID child.
    code="""import os,stat,sys
s,d,cap,replace=sys.argv[1],sys.argv[2],int(sys.argv[3]),sys.argv[4]=='1'
f=os.open(s,os.O_RDONLY|os.O_NOFOLLOW)
m=os.fstat(f)
assert stat.S_ISREG(m.st_mode) and stat.S_IMODE(m.st_mode)==0o600 and m.st_uid==os.geteuid()
b=bytearray()
while len(b)<=cap:
 c=os.read(f,cap+1-len(b))
 if not c:break
 b.extend(c)
os.close(f)
assert 0<len(b)<=cap
p=os.lstat(os.path.dirname(d));assert stat.S_ISDIR(p.st_mode) and stat.S_IMODE(p.st_mode)==0o700 and p.st_uid==os.geteuid()
if replace:os.unlink(d)
f=os.open(d,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
v=memoryview(b)
while v:
 n=os.write(f,v);assert n>0;v=v[n:]
os.fsync(f);os.close(f)
f=os.open(os.path.dirname(d),os.O_RDONLY|os.O_DIRECTORY);os.fsync(f);os.close(f)
"""
    run(['/usr/local/bin/python3','-I','-B','-c',code,source,dest,str(cap),'1' if replace else '0'],uid,[uid])

def args_for(root,pins):
    args=['--config',root+'/config','--genesis-manifest-file',root+'/manifest.bin','--genesis-digest',pins['genesis_digest'],
          '--certificate-epoch',pins['certificate_epoch'],'--validator-id',pins['validator'],
          '--successor-genesis-epoch',pins['genesis_epoch'],'--successor-max-links','1']
    for flag,role in [('plan-history','plan-history'),('cut','cut'),('manifest-history','manifest-history'),('certificate','certificate')]:args+=['--successor-'+flag+'-dir',root+'/'+role]
    for suite in pins['suites']:args+=['--suite',suite]
    return args

def record_path(case,phase):return CROOT+'/approvals/'+params[case]['request']+'.positive-fee-split.'+phase

def approve(case,phase,ttl=600,success=True):
    argv=cli('custody','approve-fee-split-'+phase,*CARGS,'--request',CROOT+'/cases/'+case+'/'+phase+'.request',
             '--approvals-dir',CROOT+'/approvals','--expires-in-seconds',str(ttl))
    item=before(argv,CUSTODY_UID,[CUSTODY_GID],'pty')
    if sum(x.get('kind')=='pty' for x in operations)>16:raise RuntimeError('PTY count cap')
    pid,fd=pty.fork()
    if pid==0:
        try:demote(CUSTODY_UID,[CUSTODY_GID])();os.execve(argv[0],argv,{})
        finally:os._exit(127)
    item['pid']=pid;pty_pids.add(pid);os.set_blocking(fd,False)
    data=bytearray();sent=False;eof=False;status=None;error=None;end=time.monotonic()+min(20,left())
    try:
        while not eof or status is None:
            if time.monotonic()>=end:raise RuntimeError('PTY deadline')
            if not eof and select.select([fd],[],[],0.02)[0]:
                try:chunk=os.read(fd,4096)
                except OSError as e:
                    if e.errno!=errno.EIO:raise
                    chunk=b''
                if not chunk:eof=True
                else:
                    frame({'operation':item['index'],'stream':'pty'},chunk);data.extend(chunk)
                    if len(data)>16384:raise RuntimeError('complete PTY review exceeds16KiB')
                    text=data.decode('utf8').replace('\r\n','\n');marker='Type exactly to approve:\n'
                    if not sent and marker in text and '\n' in text.split(marker,1)[1]:
                        line=text.split(marker,1)[1].split('\n',1)[0]
                        expected='APPROVE-POSITIVE-FEE-SPLIT phase='+phase.title()+' request='+params[case]['request']+' claimant='+pins['claimant']+' not_after='
                        if not line.startswith(expected):raise RuntimeError('unexpected exact PTY review identity')
                        expiry=int(line[len(expected):]);os.write(fd,(line+'\n').encode('ascii'));sent=True
            if status is None:
                got,status_value=os.waitpid(pid,os.WNOHANG)
                if got:status=status_value
    except BaseException as e:
        error=e
    finally:
        if status is None:
            os.kill(pid,signal.SIGKILL);cleanup_end=time.monotonic()+5
            while status is None and time.monotonic()<cleanup_end:
                got,value=os.waitpid(pid,os.WNOHANG)
                if got:status=value
                else:time.sleep(.01)
        os.close(fd)
        if status is not None:pty_pids.discard(pid)
        item.update(ptyEof=eof,waitCompleted=status is not None,pidAbsent=not os.path.exists('/proc/'+str(pid)),
                    ptyBytes=len(data),ptySha256=hashlib.sha256(data).hexdigest(),exit=os.waitstatus_to_exitcode(status) if status is not None else None)
        frame({'operation':item['index'],'stream':'result'},json.dumps(item,sort_keys=True).encode())
    if error:raise error
    if not sent or not eof or not item['pidAbsent']:raise RuntimeError('PTY completion lacks full EOF/wait')
    if not success:
        if status==0 or not (b'File exists' in data or b'already exists' in data):raise RuntimeError('duplicate approval did not reach create-only refusal')
        return expiry
    if status!=0:raise RuntimeError('PTY approval exited unsuccessfully')
    s=os.lstat(record_path(case,phase))
    if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o600 or s.st_uid!=CUSTODY_UID:raise RuntimeError('phase approval owner/mode')
    record=bounded(record_path(case,phase),65536)
    approval_evidence.append({'case':case,'phase':phase,'expires':expiry,'bytes':len(record),'sha256':hashlib.sha256(record).hexdigest(),'canonicalHex':record.hex()})
    return expiry

def start(count,key=None):
    if os.path.lexists(SOCKET):raise RuntimeError('old custody socket remains')
    argv=cli('custody','serve-fee-split',*CARGS,'--key-file',key or KEY,'--socket',SOCKET,'--approvals-dir',CROOT+'/approvals',
             '--max-connections',str(count),'--max-requests',str(count),'--total-deadline-secs','30')
    p,item=launch(argv,CUSTODY_UID,[CUSTODY_GID]);end=time.monotonic()+min(5,left())
    while not os.path.exists(SOCKET):
        if p.poll() is not None or time.monotonic()>end:raise RuntimeError('positive serve did not bind')
        time.sleep(.02)
    s=os.lstat(SOCKET)
    if not stat.S_ISSOCK(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o660 or s.st_uid!=CUSTODY_UID:raise RuntimeError('socket identity/mode')
    return p,item

def stop(service,expected,control=False):
    p,item=service;rc,out,err=finish(p,item,10)
    if rc or err:raise RuntimeError('positive serve terminal failure')
    counts=[int(line.split('=',1)[1]) for line in out.decode().splitlines()]
    if counts!=expected:raise RuntimeError('positive exact service counts differ')
    if os.path.lexists(SOCKET):raise RuntimeError('stopped custody socket remains')
    (peer_controls if control else services).append(counts)

def sign(case,phase,label,success=True):
    path=OROOT+'/cases/'+case+'/'+label+('.leg' if phase=='leg' else '.candidate')
    if os.path.lexists(path):raise RuntimeError('sign destination exists')
    argv=cli('custody','sign-fee-split-'+phase,*OARGS,'--request',OROOT+'/cases/'+case+'/'+phase+'.request',
             '--custody-socket',SOCKET,'--custody-uid',str(CUSTODY_UID),'--custody-expected-public-key',pins['claimant'],'--out',path)
    if phase=='claim':argv+=['--created-checkpoint',pins['checkpoint']]
    out,err=run(argv,OPERATOR_UID,[OPERATOR_GID,CUSTODY_GID],success=success)
    if success:
        expected=OROOT+'/cases/'+case+('/signed-leg.bin' if phase=='leg' else '/candidate.bin')
        if bounded(path)!=bounded(expected):raise RuntimeError('protected signature/candidate differs from original oracle')
    else:
        if os.path.lexists(path) or b'NoApproval' not in err:raise RuntimeError('sign refusal missing expected status/absent output')
    return path

def revoke(case):
    path=CROOT+'/approvals/'+params[case]['request']+'.revoked'
    expected=b'\x01'+bytes.fromhex(params[case]['request'])
    for _ in range(2):
        run(cli('custody','revoke','--approvals-dir',CROOT+'/approvals','--request-id',params[case]['request']),CUSTODY_UID,[CUSTODY_GID])
        if bounded(path,33)!=expected:raise RuntimeError('permanent tombstone bytes differ')

def verify(case):
    argv,env=probe('verify',OROOT,POSITIVE_SPLIT_CASE=case)
    out,err=run(argv,OPERATOR_UID,[OPERATOR_GID],env)
    if b'1 passed; 0 failed; 0 ignored' not in out:raise RuntimeError('positive ignored verifier did not run')

def main():
    global raw_fd,CROOT,OROOT,CARGS,OARGS,KEY,SOCKET,pins,params
    for path,value in [('/sys/fs/cgroup/memory.max','536870912'),('/sys/fs/cgroup/memory.swap.max','0'),('/sys/fs/cgroup/pids.max','64'),('/sys/fs/cgroup/cpu.max','100000 100000')]:
        with open(path) as source:
            if source.read(128).strip()!=value:raise RuntimeError('actual container cgroup bound differs')
    with open('/proc/self/mountinfo') as source:mounts=source.read(65537)
    if len(mounts)>65536:raise RuntimeError('mount inventory bound')
    rows=[line.split() for line in mounts.splitlines() if line.split()[4]==ROOT]
    if len(rows)!=1:raise RuntimeError('one literal work allocation required')
    row=rows[0];sep=row.index('-');options=set(row[5].split(','))|set(row[sep+3].split(','))
    if row[sep+1]!='tmpfs' or not {'rw','noswap','nosuid','nodev','noexec'}.issubset(options):raise RuntimeError('effective volume mount options differ')
    allocation=os.statvfs(ROOT)
    if allocation.f_frsize*allocation.f_blocks!=67108864:raise RuntimeError('actual volume size differs')
    mkdir(ROOT+'/evidence',0);raw_fd=os.open(ROOT+'/evidence/raw.bin',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    inventory=bounded('/mnt/public/files.tsv',262144).decode('ascii').splitlines()
    if not 1<=len(inventory)<=256:raise RuntimeError('public inventory count')
    records=[];total=0;names=set()
    for line in inventory:
        name,length,digest=line.split('\t');length=int(length)
        if name in names or len(name)>251 or any(x in ('','..','.') for x in name.split('/')):raise RuntimeError('public archive path')
        if name.startswith('/') or '\\' in name or length>1048576 or length<0:raise RuntimeError('public archive bounds')
        parts=name.split('/')
        if not (name in ('manifest.bin','pins.txt') or (len(parts)==2 and parts[0] in ('plan-history','cut','manifest-history','certificate')) or (len(parts)==3 and parts[0]=='cases' and parts[1] in ('A','B','C','D') and parts[2] in ('params.txt','fee-object.bin','fee-ref.bin','signed-leg.bin','host-request.bin','host-intent.bin','signed-outer.bin','candidate.bin'))):raise RuntimeError('unknown public role/path')
        if name.endswith(('.key','.seed','.db')):raise RuntimeError('private/database archive entry refused')
        names.add(name);total+=length
        if total>16777216:raise RuntimeError('public aggregate cap')
        data=bounded('/mnt/public/'+name)
        if len(data)!=length or hashlib.sha256(data).hexdigest()!=digest:raise RuntimeError('public archive expected digest differs')
        records.append((name,data))
    CROOT=ROOT+'/custody';OROOT=ROOT+'/operator';mkdir(CROOT,CUSTODY_UID);mkdir(OROOT,OPERATOR_UID)
    for root,uid in [(CROOT,CUSTODY_UID),(OROOT,OPERATOR_UID)]:
        for name,data in records:
            path=root+'/'+name
            current=root
            for component in name.split('/')[:-1]:
                current+='/'+component
                if not os.path.exists(current):mkdir(current,uid)
            put(path,data,uid)
    pins=fields(CROOT+'/pins.txt')
    if pins['profile']!='positive-first-successor-v1' or pins['checkpoint']!='1000':raise RuntimeError('wrong selected public profile')
    params={case:fields(CROOT+'/cases/'+case+'/params.txt') for case in 'ABCD'}
    for root,uid in [(CROOT,CUSTODY_UID),(OROOT,OPERATOR_UID)]:
        config=('chain_id='+pins['chain']+'\nprotocol_version='+pins['protocol']+'\nepoch='+pins['execution_epoch']+'\nhash_suite_id='+pins['hash_suite_id']+'\ndomain='+pins['domain']+'\npublisher_public_key='+pins['claimant']+'\noperator_uid='+str(OPERATOR_UID)+'\n').encode()
        put(root+'/config',config,uid);args=args_for(root,pins);put(root+'/trust.args',('\n'.join(args)+'\n').encode(),uid)
        for case in 'ABCD':
            d=root+'/cases/'+case;p=params[case]
            leg=cli('custody','prepare-fee-split-leg',*args,'--fee-object',d+'/fee-object.bin','--fee-ref',d+'/fee-ref.bin',
                    '--fee-object-hash-epoch',p['hash_epoch'],'--escrow-request-id',p['escrow'],'--request-id',p['request'],'--amount',p['amount'],'--recipient',p['recipient'],'--nonce',p['nonce'],'--gas-limit',p['gas'],'--out',d+'/leg.request')
            run(leg,uid,[uid])
            run(cli('custody','prepare-fee-split-claim',*args,'--request',d+'/leg.request','--signed-leg',d+'/signed-leg.bin',
                    '--host-request',d+'/host-request.bin','--host-intent',d+'/host-intent.bin','--out',d+'/claim.request'),uid,[uid])
        argv,env=probe('inspect',root);out,err=run(argv,uid,[uid],env)
        if b'1 passed; 0 failed; 0 ignored' not in out:raise RuntimeError('public ignored inspector did not execute')
    for case in 'ABCD':
        for suffix in ['leg.request','claim.request','leg.frame','claim.frame','leg.meaning','claim.meaning']:
            if bounded(CROOT+'/cases/'+case+'/'+suffix)!=bounded(OROOT+'/cases/'+case+'/'+suffix):raise RuntimeError('independent role complete bytes differ')
    mkdir(CROOT+'/keys',CUSTODY_UID);mkdir(CROOT+'/approvals',CUSTODY_UID);mkdir(CROOT+'/backups',CUSTODY_UID)
    mkdir(ROOT+'/run',CUSTODY_UID,0o750);KEY=CROOT+'/keys/historical.seed';SOCKET=ROOT+'/run/positive.sock';CARGS=args_for(CROOT,pins);OARGS=args_for(OROOT,pins)
    argv,env=probe('provision',CROOT,POSITIVE_SPLIT_KEY_DESTINATION=KEY);out,err=run(argv,CUSTODY_UID,[CUSTODY_GID],env)
    if b'1 passed; 0 failed; 0 ignored' not in out:raise RuntimeError('custody provision probe did not execute')
    # Exact UID gate closes before body; the intruder has socket group access.
    svc=start(1)
    intruder="import socket,sys\ns=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(sys.argv[1]);assert s.recv(1)==b'';s.close()\n"
    run(['/usr/local/bin/python3','-I','-B','-c',intruder,SOCKET],INTRUDER_UID,[INTRUDER_GID,CUSTODY_GID])
    stop(svc,[1,0,0,0],True)
    # Impostor accepts a connection but must receive zero request-body bytes.
    mkdir(ROOT+'/impostor',INTRUDER_UID,0o755);impostor=ROOT+'/impostor/peer.sock'
    listener="import os,socket,sys\ns=socket.socket(socket.AF_UNIX);s.settimeout(5);s.bind(sys.argv[1]);os.chmod(sys.argv[1],0o666);s.listen(1);c,_=s.accept();c.settimeout(3);assert c.recv(1)==b'';c.close();s.close();os.unlink(sys.argv[1])\n"
    listener_process,listener_item=launch(['/usr/local/bin/python3','-I','-B','-c',listener,impostor],INTRUDER_UID,[INTRUDER_GID])
    ready=time.monotonic()+min(3,left())
    while not os.path.exists(impostor):
        if listener_process.poll() is not None or time.monotonic()>ready:raise RuntimeError('impostor listener did not bind')
        time.sleep(.01)
    bad=OROOT+'/cases/A/impostor.leg'
    _out,err=run(cli('custody','sign-fee-split-leg',*OARGS,'--request',OROOT+'/cases/A/leg.request','--custody-socket',impostor,'--custody-uid',str(CUSTODY_UID),'--custody-expected-public-key',pins['claimant'],'--out',bad),OPERATOR_UID,[OPERATOR_GID],success=False)
    if os.path.lexists(bad) or b'UID' not in err:raise RuntimeError('client impostor UID refusal did not occur')
    rc,_out,_err=finish(listener_process,listener_item,5)
    if rc:raise RuntimeError('impostor received request bytes or failed')
    # Only these child argv/env fields cross to the operator. No key path or seed.
    for case in ['A','B']:
        phase='leg' if case=='A' else 'claim'
        run(cli('custody','approve-fee-split-'+phase,*CARGS,'--request',CROOT+'/cases/A/'+phase+'.request','--approvals-dir',CROOT+'/approvals','--expires-in-seconds','600'),CUSTODY_UID,[CUSTODY_GID],success=False)
    argv,env=probe('operator-permissions',OROOT)
    out,err=run(argv,OPERATOR_UID,[OPERATOR_GID,CUSTODY_GID],env)
    if b'1 passed; 0 failed; 0 ignored' not in out:raise RuntimeError('operator permission probe did not execute')
    run(cli('custody','revoke','--approvals-dir',CROOT+'/approvals','--request-id',params['A']['request']),OPERATOR_UID,[OPERATOR_GID,CUSTODY_GID],success=False)
    # A: both phases sign only after their exact approvals.
    svc=start(4);sign('A','leg','missing-leg',False);approve('A','leg');sign('A','leg','protected')
    old=bounded(record_path('A','leg'),65536);approve('A','leg',success=False)
    if bounded(record_path('A','leg'),65536)!=old:raise RuntimeError('duplicate phase write changed bytes')
    argv,env=probe('operator-permissions',OROOT);run(argv,OPERATOR_UID,[OPERATOR_GID,CUSTODY_GID],env)
    _out,err=run(cli('custody','approve-fee-split-claim',*CARGS,'--request',CROOT+'/cases/A/claim.request','--approvals-dir',CROOT+'/approvals','--expires-in-seconds','600'),CUSTODY_UID,[CUSTODY_GID],success=False)
    if b'terminal' not in err:raise RuntimeError('Claim nonterminal approval missed terminal gate')
    sign('A','claim','missing-claim',False);approve('A','claim')
    old=bounded(record_path('A','claim'),65536);approve('A','claim',success=False)
    if bounded(record_path('A','claim'),65536)!=old:raise RuntimeError('duplicate Claim write changed bytes')
    sign('A','claim','protected');stop(svc,[4,4,2,2]);verify('A')
    # Rebuild main Claim from the actual protected Leg, then require exact bytes.
    run(cli('custody','prepare-fee-split-claim',*OARGS,'--request',OROOT+'/cases/A/leg.request','--signed-leg',OROOT+'/cases/A/protected.leg','--host-request',OROOT+'/cases/A/host-request.bin','--host-intent',OROOT+'/cases/A/host-intent.bin','--out',OROOT+'/cases/A/claim.actual.request'),OPERATOR_UID,[OPERATOR_GID])
    if bounded(OROOT+'/cases/A/claim.actual.request')!=bounded(OROOT+'/cases/A/claim.request'):raise RuntimeError('actual protected Leg changes Claim')
    svc=start(2);sign('A','leg','restart');sign('A','claim','restart');stop(svc,[2,2,2,0])
    # B: permanent cancellation between released Leg and outer Claim signature.
    approve('B','leg');svc=start(3);sign('B','leg','protected');approve('B','claim')
    for phase in ['leg','claim']:own_copy(record_path('B',phase),CROOT+'/backups/B.'+phase,CUSTODY_UID)
    revoke('B');sign('B','leg','revoked',False);sign('B','claim','revoked',False);stop(svc,[3,3,1,2])
    for phase in ['leg','claim']:own_copy(CROOT+'/backups/B.'+phase,record_path('B',phase),CUSTODY_UID,replace=True)
    svc=start(2);sign('B','leg','restored-refused',False);sign('B','claim','restored-refused',False);stop(svc,[2,2,0,2])
    for phase in ['leg','claim']:
        _out,err=run(cli('custody','approve-fee-split-'+phase,*CARGS,'--request',CROOT+'/cases/B/'+phase+'.request','--approvals-dir',CROOT+'/approvals','--expires-in-seconds','600'),CUSTODY_UID,[CUSTODY_GID],success=False)
        if b'revoked' not in err:raise RuntimeError('restored revoked reapproval did not fail before PTY')
    # C: identical requests under original and privately recovered key.
    approve('C','leg');approve('C','claim');svc=start(2);sign('C','leg','protected');sign('C','claim','protected');stop(svc,[2,2,2,0]);verify('C')
    own_copy(KEY,CROOT+'/keys/backup.seed',CUSTODY_UID,256);own_copy(CROOT+'/keys/backup.seed',CROOT+'/keys/restored.seed',CUSTODY_UID,256)
    svc=start(6,CROOT+'/keys/restored.seed');sign('C','leg','recovered');sign('C','claim','recovered');sign('B','leg','recovery-old-refused',False);sign('B','claim','recovery-old-refused',False);revoke('C');sign('C','leg','recovery-new-refused',False);sign('C','claim','recovery-new-refused',False);stop(svc,[6,6,2,4])
    svc=start(4,CROOT+'/keys/restored.seed')
    for case in ['B','C']:
        for phase in ['leg','claim']:sign(case,phase,'recovery-restart-refused',False)
    stop(svc,[4,4,0,4])
    # Both phase approvals have exclusive expiry; no manual intent rewriting.
    expires=[approve('D','leg',4),approve('D','claim',4)]
    while time.time()<max(expires):time.sleep(min(.05,left()))
    svc=start(2)
    for phase in ['leg','claim']:sign('D',phase,'expired',False)
    stop(svc,[2,2,0,2])
    corrupted=bytearray(bounded(OROOT+'/cases/A/signed-leg.bin'));corrupted[-1]^=1
    put(OROOT+'/cases/A/corrupt-leg.bin',corrupted,OPERATOR_UID)
    refused=OROOT+'/cases/A/corrupt-claim.request'
    run(cli('custody','prepare-fee-split-claim',*OARGS,'--request',OROOT+'/cases/A/leg.request','--signed-leg',OROOT+'/cases/A/corrupt-leg.bin','--host-request',OROOT+'/cases/A/host-request.bin','--host-intent',OROOT+'/cases/A/host-intent.bin','--out',refused),OPERATOR_UID,[OPERATOR_GID],success=False)
    if os.path.lexists(refused):raise RuntimeError('bad signed leg emitted Claim output')
    # A genuinely new key has no authority in the old historical committee.
    new_public,_err=run(cli('custody','keygen','--key-file',CROOT+'/keys/rotation.seed'),CUSTODY_UID,[CUSTODY_GID])
    run(cli('custody','serve-fee-split',*CARGS,'--key-file',CROOT+'/keys/rotation.seed','--socket',SOCKET,'--approvals-dir',CROOT+'/approvals','--max-connections','1','--max-requests','1','--total-deadline-secs','5'),CUSTODY_UID,[CUSTODY_GID],success=False)
    if os.path.lexists(SOCKET):raise RuntimeError('rotation mismatch bound a socket')
    identity=[line.split('=',1)[1] for line in new_public.decode().splitlines() if line.startswith('public_key=')]
    if len(identity)!=1 or identity[0]==pins['claimant']:raise RuntimeError('rotation did not create a different public identity')
    changed=bounded(CROOT+'/config').replace(('publisher_public_key='+pins['claimant']).encode(),('publisher_public_key='+identity[0]).encode())
    put(CROOT+'/rotation.config',changed,CUSTODY_UID)
    rotated=list(CARGS);rotated[rotated.index('--config')+1]=CROOT+'/rotation.config'
    run(cli('custody','serve-fee-split',*rotated,'--key-file',KEY,'--socket',SOCKET,'--approvals-dir',CROOT+'/approvals','--max-connections','1','--max-requests','1','--total-deadline-secs','5'),CUSTODY_UID,[CUSTODY_GID],success=False)
    if os.path.lexists(SOCKET):raise RuntimeError('unrecognized historical claimant bound a socket')
    for name,data in records:
        if bounded('/mnt/public/'+name)!=data:raise RuntimeError('public read-only source changed')
        for root in [CROOT,OROOT]:
            if bounded(root+'/'+name)!=data:raise RuntimeError('retained public role input changed')
    expected=[[4,4,2,2],[2,2,2,0],[3,3,1,2],[2,2,0,2],[2,2,2,0],[6,6,2,4],[4,4,0,4],[2,2,0,2]]
    if services!=expected:raise RuntimeError('complete service matrix differs')
    generated=0;entries=0
    for directory,dirs,files in os.walk(ROOT,followlinks=False):
        entries+=len(dirs)+len(files)
        if entries>16384:raise RuntimeError('owned volume entry count exceeded')
        for name in dirs:
            if not stat.S_ISDIR(os.lstat(directory+'/'+name).st_mode):raise RuntimeError('generated unexpected directory type')
        for name in files:
            s=os.lstat(directory+'/'+name)
            if not stat.S_ISREG(s.st_mode):raise RuntimeError('generated unexpected file type')
            generated+=s.st_size
    if generated>67108864 or entries>16384:raise RuntimeError('owned volume aggregate bounds')
    put(ROOT+'/evidence/main.candidate',bounded(OROOT+'/cases/A/protected.candidate',65536),0)
    return {'ok':True,'scope':'positive_split_uid_lifecycle_1017','services':services,'generatedBytes':generated,'entries':entries,'operationCount':len(operations),'peerControls':peer_controls,'approvalCount':len(approval_evidence)}

pty_pids=set();result=None;failure=None
try:
    result=main()
except BaseException as error:
    failure=repr(error)
finally:
    cleanup_end=time.monotonic()+5
    for process in children:
        if process.poll() is None:process.kill()
        try:process.wait(timeout=max(.001,cleanup_end-time.monotonic()))
        except BaseException as error:failure=(failure or '')+'; child cleanup unresolved '+repr(error)
    for pid in list(pty_pids):
        try:
            os.kill(pid,signal.SIGKILL)
            while time.monotonic()<cleanup_end:
                got,_status=os.waitpid(pid,os.WNOHANG)
                if got:break
                time.sleep(.01)
        except OSError:pass
        failure=(failure or '')+'; PTY cleanup required'
    if raw_fd is not None:
        os.fsync(raw_fd);os.close(raw_fd)
        metadata={'ok':failure is None,'error':failure,'operations':operations,'services':services,'peerControls':peer_controls,'approvals':approval_evidence,'rawBytes':raw_used,'uncapturedObservedBytes':uncaptured_observed}
        try:
            encoded=json.dumps(metadata,sort_keys=True).encode()
            if len(encoded)>262144:raise RuntimeError('complete evidence metadata exceeds256KiB')
            put(ROOT+'/evidence/meta.json',encoded,0)
        except BaseException as error:failure=(failure or '')+'; evidence metadata '+repr(error)
if not failure:
    try:
        generated=0;entries=0
        for directory,dirs,files in os.walk(ROOT,followlinks=False):
            entries+=len(dirs)+len(files)
            if entries>16384:raise RuntimeError('final volume entry cap')
            for name in dirs:
                if not stat.S_ISDIR(os.lstat(directory+'/'+name).st_mode):raise RuntimeError('final non-directory')
            for name in files:
                metadata=os.lstat(directory+'/'+name)
                if not stat.S_ISREG(metadata.st_mode):raise RuntimeError('final unexpected file type')
                generated+=metadata.st_size
                if generated>67108864:raise RuntimeError('final volume byte cap')
        live=[p for p in os.listdir('/proc') if p.isdigit() and int(p)!=os.getpid()]
        if live:raise RuntimeError('unexpected surviving container processes')
        result.update(generatedBytes=generated,entries=entries,allChildrenAbsent=True)
        for path,key in [('memory.peak','memoryPeak'),('memory.swap.current','swapCurrent'),('memory.events','memoryEvents')]:
            with open('/sys/fs/cgroup/'+path) as source:result[key]=source.read(4096).strip()
        if result['swapCurrent']!='0' or any(int(line.split()[1]) for line in result['memoryEvents'].splitlines()):raise RuntimeError('swap or memory-limit event observed')
    except BaseException as error:failure=repr(error)
if failure:
    print(json.dumps({'ok':False,'error':failure}),flush=True);raise SystemExit(1)
print(json.dumps(result,sort_keys=True),flush=True)
`;
function probeCommand() {
  const source = Buffer.from(probe, 'utf8');
  if (source.length > 256 * 1024) throw new Error('fixture program exceeds its transport bound');
  const packed = deflateSync(source).toString('base64');
  const digest = createHash('sha256').update(source).digest('hex');
  // Keep one argv below Linux's per-argument limit without changing the
  // program, mounts, standard input, privileges or fixture resource bounds.
  const command = [
    'import base64,hashlib,zlib',
    '__custody_decoder=zlib.decompressobj()',
    `__custody_probe=__custody_decoder.decompress(base64.b64decode(${JSON.stringify(packed)},validate=True),${source.length + 1})`,
    `if len(__custody_probe)!=${source.length} or not __custody_decoder.eof or __custody_decoder.unused_data or __custody_decoder.unconsumed_tail: raise RuntimeError('fixture program transport length differs')`,
    `if hashlib.sha256(__custody_probe).hexdigest()!=${JSON.stringify(digest)}: raise RuntimeError('fixture program transport digest differs')`,
    "exec(compile(__custody_probe,'<custody-fixture>','exec'))",
  ].join('\n');
  if (Buffer.byteLength(command, 'utf8') > 64 * 1024) throw new Error('fixture bootstrap exceeds its argument bound');
  return command;
}

async function docker(args, cleanup = false) {
  if (++operationCount > 32) throw new Error('fixed Docker/host operation count exceeded');
  const operationId = operationCount, operationStart = performance.now();
  const allowance = Math.floor(deadline - performance.now() - (cleanup ? 0 : 25_000));
  const remaining = cleanup ? Math.min(5_000, allowance) : allowance;
  if (remaining <= 0) throw new Error('fixture deadline expired');
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
    let uncapturedBytes = 0;
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
      if (failure) { uncapturedBytes += chunk.length; return; }
      if (chunk.length > activeLimit - outputBytes) {
        uncapturedBytes += chunk.length;
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
      const actualOut = Buffer.concat(stdout), actualErr = Buffer.concat(stderr);
      for (const [stream, bytes] of [['stdout', actualOut], ['stderr', actualErr]]) writeFileSync(join(evidenceRoot, `host-${operationId}.${stream}`), bytes, { flag: 'wx', mode: 0o600 });
      hostOperations.push({ operationId, executable: '/usr/local/bin/docker', args: ['--host', endpoint, ...args], pid: child.pid, code, signal, stdoutEof, stderrEof, waitCompleted: true, uncapturedBytes, stdoutBytes: actualOut.length, stderrBytes: actualErr.length, stdoutSha256: hash(actualOut), stderrSha256: hash(actualErr), seconds: (performance.now() - operationStart) / 1000 });
      writeFileSync(join(evidenceRoot, `host-${operationId}.json`), JSON.stringify(hostOperations.at(-1), null, 2) + '\n', { flag: 'wx', mode: 0o600 });
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
        const diagnostic = answer.stderr.trim() || answer.stdout.trim();
        const error = new Error(`Docker refused ${args[0]}: ${diagnostic}`);
        error.command = args[0];
        return rejectOnce(error);
      }
      settled = true;
      resolve(answer);
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



async function lddClosure(binaryPath) {
  const captured = await hostCommand('/usr/bin/ldd', [binaryPath], 65536);
  let interpreter;
  const libs = new Map();
  for (const rawLine of captured.stdout.toString('utf8').split('\n')) {
    const line = rawLine.trim();
    const match = line.match(/=>\s*(\/\S+)\s+\(0x/) ?? line.match(/^(\/\S+)\s+\(0x/);
    if (!match) continue;
    const path = match[1]; assertMountSafePath('library', path);
    if (basename(path).startsWith('ld-linux') || basename(path) === 'ld.so') { if (interpreter && interpreter !== path) throw new Error('different linker'); interpreter = path; }
    else { const previous = libs.get(basename(path)); if (previous && previous !== path) throw new Error('ambiguous library basename'); libs.set(basename(path), path); }
  }
  if (!interpreter) throw new Error('actual dynamic linker absent');
  return { interpreter, libs };
}
function mergeClosures(a, b) {
  if (a.interpreter !== b.interpreter) throw new Error('different actual dynamic linkers');
  const libs = new Map(a.libs);
  for (const [name_, path] of b.libs) { if (libs.has(name_) && libs.get(name_) !== path) throw new Error('different actual library'); libs.set(name_, path); }
  return { interpreter: a.interpreter, libs };
}
async function hostCommand(executable, args, cap) {
  if (++operationCount > 32) throw new Error('host operation count exceeded');
  const operationId = operationCount, start = performance.now();
  return await new Promise((resolve_, reject) => {
    const child = spawn(executable, args, { env: dockerEnvironment, stdio: ['ignore', 'pipe', 'pipe'] });
    pendingClients.add(child);
    const out = [], err = []; let size = 0, stdoutEof = false, stderrEof = false, failed, settled = false, reapTimer;
    const rejectOnce = (error) => { if (!settled) { settled = true; reject(error); } };
    const abort = (error) => {
      failed ??= error; child.kill('SIGKILL');
      if (!reapTimer) reapTimer = setTimeout(() => { child.unref(); child.stdout.destroy(); child.stderr.destroy(); rejectOnce(new Error(`${failed.message}; physical EOF/wait unresolved`)); }, Math.max(1, Math.min(1000, deadline - performance.now())));
    };
    const timer = setTimeout(() => abort(new Error('bounded host child deadline')), Math.max(1, Math.min(20_000, deadline - performance.now())));
    const collect = (items, bytes) => { size += bytes.length; if (size > cap) abort(new Error('complete host binary output cap exceeded')); else items.push(bytes); };
    child.stdout.on('data', (bytes) => collect(out, bytes)); child.stderr.on('data', (bytes) => collect(err, bytes));
    child.stdout.on('end', () => { stdoutEof = true; }); child.stderr.on('end', () => { stderrEof = true; });
    child.stdout.on('error', abort); child.stderr.on('error', abort); child.on('error', abort);
    child.on('close', (code, signal_) => {
      clearTimeout(timer); if (reapTimer) clearTimeout(reapTimer); pendingClients.delete(child);
      const stdout = Buffer.concat(out), stderr = Buffer.concat(err);
      for (const [stream, bytes] of [['stdout', stdout], ['stderr', stderr]]) writeFileSync(join(evidenceRoot, `host-${operationId}.${stream}`), bytes, { flag: 'wx', mode: 0o600 });
      hostOperations.push({ operationId, executable, args, pid: child.pid, code, signal: signal_, stdoutEof, stderrEof, waitCompleted: true,
        stdoutBytes: stdout.length, stderrBytes: stderr.length, observedBytes: size, uncapturedBytes: size - stdout.length - stderr.length,
        stdoutSha256: hash(stdout), stderrSha256: hash(stderr), seconds: (performance.now() - start) / 1000 });
      writeFileSync(join(evidenceRoot, `host-${operationId}.json`), JSON.stringify(hostOperations.at(-1), null, 2) + '\n', { flag: 'wx', mode: 0o600 });
      if (failed || code !== 0 || signal_ !== null || !stdoutEof || !stderrEof) rejectOnce(failed ?? new Error('host child lacks successful wait/both EOF'));
      else if (!settled) { settled = true; resolve_({ stdout, stderr }); }
    });
  });
}
function extractEvidence(tar) {
  if (tar.length > 1048576 || tar.length % 512 !== 0) throw new Error('binary evidence exceeds1MiB or lacks complete blocks');
  let offset = 0, ended = false; const files = new Map();
  while (offset + 512 <= tar.length) {
    const block = tar.subarray(offset, offset + 512); offset += 512;
    if (block.every((v) => v === 0)) { if (!tar.subarray(offset).every((v) => v === 0)) throw new Error('nonzero trailing evidence tar'); ended = true; break; }
    const declaredChecksum = Number.parseInt(block.subarray(148, 156).toString('ascii').replace(/\0/g, '').trim(), 8);
    const checksum = block.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    if (declaredChecksum !== checksum) throw new Error('evidence tar checksum differs');
    const name_ = block.subarray(0, 100).toString('utf8').split('\0')[0].replace(/^\.\//, '');
    const type = block[156], size = Number.parseInt(block.subarray(124, 136).toString('ascii').replace(/\0/g, '').trim(), 8);
    if (type === 120) {
      if (!Number.isSafeInteger(size) || size < 0 || size > 16384 || offset + size > tar.length) throw new Error('bounded PAX metadata differs');
      const pax = tar.subarray(offset, offset + size); let cursor = 0;
      while (cursor < pax.length) {
        const space = pax.indexOf(32, cursor); if (space < 0 || space - cursor > 8) throw new Error('PAX length absent');
        const length = Number(pax.subarray(cursor, space).toString('ascii'));
        if (!Number.isInteger(length) || length <= space - cursor + 2 || cursor + length > pax.length) throw new Error('PAX record length differs');
        const record = pax.subarray(space + 1, cursor + length).toString('ascii');
        if (!/^(mtime|atime|ctime)=[0-9]+(\.[0-9]+)?\n$/.test(record)) throw new Error('PAX alias/unknown metadata refused');
        cursor += length;
      }
      offset += Math.ceil(size / 512) * 512; if (offset > tar.length) throw new Error('PAX padding incomplete'); continue;
    }
    if (type === 53 && (name_ === '' || name_ === '.' || name_ === './')) { if (size !== 0) throw new Error('tar root directory has bytes'); continue; }
    if (![0, 48].includes(type) || !['raw.bin', 'meta.json', 'main.candidate'].includes(name_) || files.has(name_) || !Number.isSafeInteger(size) || size < 0 || size > 1048576 || offset + size > tar.length) throw new Error('fixed evidence tar layout differs');
    if (!block.subarray(157, 257).every((v) => v === 0) || !block.subarray(345, 500).every((v) => v === 0)) throw new Error('evidence link/prefix refused');
    const mode = Number.parseInt(block.subarray(100, 108).toString('ascii').replace(/\0/g, '').trim(), 8);
    if (mode !== 0o600) throw new Error('fixed public evidence file mode differs');
    const bytes = tar.subarray(offset, offset + size); files.set(name_, Buffer.from(bytes)); offset += Math.ceil(size / 512) * 512;
    if (offset > tar.length) throw new Error('evidence padding incomplete');
  }
  if (!ended || !files.has('raw.bin') || !files.has('meta.json')) throw new Error('complete raw evidence absent');
  for (const [name_, data] of files) writeFileSync(join(evidenceRoot, name_), data, { flag: 'wx', mode: 0o600 });
  return files;
}

let protectedCandidate;
const closure = mergeClosures(await lddClosure(cliBinary), await lddClosure(testBinary));
const libraryPins = new Map(provenance.libraries.map((entry) => [entry.path, entry.sha256]));
for (const path of [closure.interpreter, ...closure.libs.values()]) if (libraryPins.get(path) !== hash(readFileSync(path))) throw new Error('actual linker/library closure provenance differs');
if (libraryPins.size !== closure.libs.size + 1) throw new Error('extra library provenance');
const binds = [
  `type=bind,source=${cliBinary},target=/mnt/bin/cli,readonly`,
  `type=bind,source=${testBinary},target=/mnt/bin/harness,readonly`,
  `type=bind,source=${closure.interpreter},target=/mnt/libs/ld.so,readonly`,
  `type=bind,source=${publicRoot},target=/mnt/public,readonly`,
  ...[...closure.libs.values()].map((path) => `type=bind,source=${path},target=/mnt/libs/${basename(path)},readonly`),
];
try {
  const localImage = await docker(['image', 'inspect', '--format', '{{.Id}}', image]);
  if (localImage.stdout.trim() !== imageId) throw new Error('pinned local image attachment differs');
  if (await findVolume()) throw new Error('fresh custody volume already exists');
  volumeExpected = true;
  const createdVolume = await docker([
    'volume', 'create', '--driver', 'local', '--name', volumeName,
    '--label', `${label}=${owner}`, '--opt', 'type=tmpfs', '--opt', 'device=tmpfs',
    '--opt', `o=${volumeOptions}`,
  ]);
  if (createdVolume.stdout.trim() !== volumeName) throw new Error('volume creation identity differs');
  await inspectVolume();
  const created = await docker([
    'create', '--pull=never', '--name', name, '--label', `${label}=${owner}`,
    '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE', '--cap-add', 'SETUID', '--cap-add', 'SETGID',
    '--security-opt', 'no-new-privileges', '--user', '0:0',
    '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
    '--pids-limit', '64', '--log-driver', 'none',
    '--mount', `type=volume,source=${volumeName},target=/work,volume-nocopy`,
    ...binds.flatMap((bind) => ['--mount', bind]),
    '--entrypoint', '/usr/local/bin/python3', image, '-I', '-B', '-c', probeCommand(),
  ]);
  containerId = created.stdout.trim();
  if (!/^[0-9a-f]{64}$/.test(containerId)) throw new Error('invalid exact container identity');

  const initial = await inspect(containerId, false, true);
  const config = initial.HostConfig;
  const mounts = initial.Mounts;
  const allocations = mounts.filter((mount) => mount.Type === 'volume');
  if (allocations.length !== 1 || allocations[0].Name !== volumeName ||
      allocations[0].Destination !== '/work' || allocations[0].RW !== true ||
      allocations[0].Source !== volumeMountpoint) throw new Error('owned allocation attachment differs');
  const readonlyMounts = mounts.filter((mount) => mount.Type === 'bind');
  const expectedMountCount = 4 + closure.libs.size; // cli + harness + ld.so + each shared library
  if (!Array.isArray(mounts) || mounts.length !== expectedMountCount + 1 ||
      readonlyMounts.length !== expectedMountCount || !readonlyMounts.every((mount) => mount.RW === false)) {
    throw new Error('bind mounts are not exactly the owned read-only custody/library closure');
  }
  if (config.Memory !== 512 * 1024 * 1024 || config.MemorySwap !== 512 * 1024 * 1024 ||
      config.PidsLimit !== 64 || config.NanoCpus !== 1_000_000_000 ||
      config.NetworkMode !== 'none' || config.ReadonlyRootfs !== true ||
      config.LogConfig.Type !== 'none' || initial.Config.User !== '0:0' ||
      JSON.stringify(config.CapDrop) !== '["ALL"]' ||
      JSON.stringify([...config.CapAdd].sort()) !== JSON.stringify(['CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_SETGID', 'CAP_SETUID']) ||
      !config.SecurityOpt.includes('no-new-privileges') ||
      JSON.stringify(initial.Config.Entrypoint) !== '["/usr/local/bin/python3"]' ||
      Object.keys(config.Tmpfs ?? {}).length !== 0 ||
      (config.Binds ?? []).length !== 0) {
    throw new Error(`effective Docker configuration differs: ${JSON.stringify({
      memory: config.Memory, swap: config.MemorySwap, pids: config.PidsLimit,
      cpu: config.NanoCpus, network: config.NetworkMode, readonly: config.ReadonlyRootfs,
      log: config.LogConfig.Type, user: initial.Config.User, capAdd: config.CapAdd,
      capDrop: config.CapDrop, security: config.SecurityOpt, entrypoint: initial.Config.Entrypoint,
      tmpfs: config.Tmpfs, binds: config.Binds,
    })}`);
  }

  const completed = await docker(['start', '--attach', containerId]);
  const terminal = await inspect(containerId);
  if (terminal.State.Running || terminal.State.OOMKilled || terminal.State.Dead || terminal.State.Pid !== 0) {
    throw new Error('the fixture container lacks a clean terminal state');
  }

  const lines = completed.stdout.trim().split('\n').filter((line) => line.length > 0);
  if (lines.length !== 1) throw new Error('selected fixture must emit one complete public summary');
  result = JSON.parse(lines[0]);
  const expected = [[4,4,2,2],[2,2,2,0],[3,3,1,2],[2,2,0,2],[2,2,2,0],[6,6,2,4],[4,4,0,4],[2,2,0,2]];
  if (!result.ok || result.scope !== 'positive_split_uid_lifecycle_1017' || JSON.stringify(result.services) !== JSON.stringify(expected) || result.generatedBytes > 67108864 || result.entries > 16384 || result.operationCount > 128 || result.allChildrenAbsent !== true || result.swapCurrent !== '0' || result.approvalCount !== 8 || JSON.stringify(result.peerControls) !== '[[1,0,0,0]]') throw new Error('selected positive lifecycle counts/volume evidence differ');
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
      if (stopped.State.Running || stopped.State.Pid !== 0) throw new Error('owned fixture container did not stop');
      // Capture full inside raw before exact owned removal, also on failure.
      try {
        const captured = await hostCommand('/usr/local/bin/docker', ['--host', endpoint, 'cp', owned.Id + ':/work/evidence/.', '-'], 1048576);
        writeFileSync(join(evidenceRoot, 'inside.tar'), captured.stdout, { flag: 'wx', mode: 0o600 });
        const files = extractEvidence(captured.stdout);
        const metadata = JSON.parse(files.get('meta.json').toString('utf8'));
        if (files.get('raw.bin').length !== metadata.rawBytes) throw new Error('actual inside raw length differs');
        if (!primaryError && (metadata.approvals.length !== 8 || JSON.stringify(metadata.peerControls) !== '[[1,0,0,0]]' || metadata.operations.some((op) => !op.waitCompleted || !op.pidAbsent || (op.kind === 'pty' ? !op.ptyEof : !op.stdoutEof || !op.stderrEof)))) throw new Error('inside physical EOF/wait/phase reviews incomplete');
        if (!primaryError && (!metadata.ok || metadata.uncapturedObservedBytes !== 0 || !files.has('main.candidate'))) throw new Error('inside lifecycle not complete');
        protectedCandidate = files.get('main.candidate');
      } catch (error) { primaryError = new Error(`${primaryError?.message ?? 'fixture'}; complete inside evidence unresolved: ${error.message}`); }
      await docker(['rm', owned.Id], true);
    }
    const remaining = await docker(['container', 'ls', '-aq', '--no-trunc', '--filter', `label=${label}=${owner}`], true);
    if (remaining.stdout.trim()) throw new Error('owned fixture container residue remains');
    if (volumeExpected && await findVolume(true)) {
      await inspectVolume(true);
      await docker(['volume', 'rm', volumeName], true);
    }
    const volumes = await docker(['volume', 'ls', '-q', '--filter', `label=${label}=${owner}`], true);
    if (volumes.stdout.trim()) throw new Error('owned fixture volume residue remains');
  } catch (error) {
    primaryError = new Error(`${primaryError?.message ?? 'fixture'}; cleanup unresolved: ${error.message}; owned name=${name}`);
  }
}

if (pendingClients.size !== 0 || performance.now() > deadline) primaryError = new Error(`${primaryError?.message ?? 'fixture'}; owned clients/deadline unresolved`);
writeFileSync(join(evidenceRoot, 'host-operations.json'), JSON.stringify({ operations: hostOperations, controlOutputBytes: outputBytes, error: primaryError?.message ?? null }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
if (primaryError) { console.error(primaryError.message); process.exitCode = 1; }
else { console.log(JSON.stringify({ ...result, image, container_removed: true, volume_removed: true, evidenceRoot })); console.log('positive_fee_split_uid_lifecycle=passed'); console.log('positive_fee_split_candidate=' + protectedCandidate.toString('hex')); }
