//! Explicit, ignored real-process qualification for the opt-in bond source
//! observer. Run only inside the pinned, root-in-container multi-UID sandbox.
//! All identities and storage are disposable; no signing or bond submission.

#[path = "support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[path = "support/compiled_source_host_process.rs"]
mod compiled_source_host_process;
#[allow(dead_code)]
#[path = "business_cut/fixture.rs"]
mod fixture;
#[path = "support/genesis_fixture.rs"]
pub mod genesis_fixture;
#[path = "support/hex.rs"]
mod hex;

use compiled_source_host_process::{
    ChildGuard, compiled_host_startup_line_limit, spawn_bounded_output, spawn_bounded_status_line,
};
use fixture::Fixture;
use hex::hex;
use objects::{ObjectRef, decode_object_ref, encode_object, encode_object_ref};
use protocol_types::{Digest32, HashAlgorithmId};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};
use sunrise_edge_operator::business_snapshot::capture_source_business_snapshot;

const HOST_UID: u32 = 12001;
const CLIENT_UID: u32 = 12002;
const WRONG_UID: u32 = 12003;
const GROUP: u32 = HOST_UID;
const REQUEST_MAGIC: &[u8; 8] = b"SRBREAD1";
const RESPONSE_MAGIC: &[u8; 8] = b"SRBOBS01";
const CLIENT: &str = r#"
import os,socket,struct,sys
uid=int(sys.argv[1]); socket_path=sys.argv[2]; mode=sys.argv[3]
assert os.geteuid()==uid and os.getegid()==12001 and os.getgroups()==[]
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.settimeout(3.0); s.connect(socket_path)
peer=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
assert peer[1]==12001
if mode=='wrong':
    assert s.recv(1)==b''
    sys.stdout.buffer.write(b'wrong-uid-refused-before-body')
else:
    body=bytes.fromhex(sys.argv[4]); assert 0<len(body)<16384
    s.sendall(struct.pack('>I',len(body))+body); s.shutdown(socket.SHUT_WR)
    def exact(n):
        out=b''
        while len(out)<n:
            part=s.recv(n-len(out))
            assert part
            out+=part
        return out
    size=struct.unpack('>I',exact(4))[0]; assert 0<size<=1024
    response=exact(size); assert s.recv(1)==b''
    sys.stdout.buffer.write(response)
s.close()
"#;

fn require_sandbox() {
    assert_eq!(
        std::env::var("SUNRISE_BOND_MULTIUID_FIXTURE").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let uid: u32 = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("Uid:")?
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()
        })
        .unwrap();
    assert_eq!(uid, 0);
    assert!(std::env::temp_dir().starts_with("/tmp"));
}

fn owned(path: &Path, mode: u32, uid: u32, gid: u32) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(
        (
            metadata.uid(),
            metadata.gid(),
            metadata.permissions().mode() & 0o7777
        ),
        (uid, gid, mode)
    );
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> &'a [u8] {
    assert!(bytes.len() >= count);
    let (head, tail) = bytes.split_at(count);
    *bytes = tail;
    head
}

fn u16be(bytes: &mut &[u8]) -> u16 {
    u16::from_be_bytes(take(bytes, 2).try_into().unwrap())
}
fn u32be(bytes: &mut &[u8]) -> u32 {
    u32::from_be_bytes(take(bytes, 4).try_into().unwrap())
}
fn u64be(bytes: &mut &[u8]) -> u64 {
    u64::from_be_bytes(take(bytes, 8).try_into().unwrap())
}
fn digest(bytes: &mut &[u8]) -> Digest32 {
    let algorithm = HashAlgorithmId::try_from(u16be(bytes)).unwrap();
    Digest32::new(algorithm, take(bytes, 32).try_into().unwrap())
}

fn assert_observation(mut bytes: &[u8], fixture: &Fixture, reviewed: &ObjectRef, fence: u64) {
    assert_eq!(take(&mut bytes, 8), RESPONSE_MAGIC);
    assert_eq!(take(&mut bytes, 1), [0]); // chain_state_proof=false
    assert_eq!(
        take(&mut bytes, 32),
        fixture.network.validators[0].validator_id.as_bytes()
    );
    let chain_len = usize::from(u16be(&mut bytes));
    assert_eq!(
        take(&mut bytes, chain_len),
        fixture.network.chain_id.as_str().as_bytes()
    );
    assert_eq!(u32be(&mut bytes), fixture.network.protocol_version.get());
    assert_eq!(take(&mut bytes, 32), fixture.network.domain.as_bytes());
    let namespace_len = usize::from(u16be(&mut bytes));
    assert!((1..=256).contains(&namespace_len));
    let namespace = take(&mut bytes, namespace_len);
    assert!(!namespace.is_empty());
    assert_eq!(u64be(&mut bytes), fence);
    assert!(u64be(&mut bytes) > 0); // local mutation sequence
    assert_eq!(u64be(&mut bytes), 0); // committed epoch
    assert_eq!(
        digest(&mut bytes),
        fixture
            .root
            .genesis_committee()
            .digest(&fixture.network.resolver)
            .unwrap()
    );
    assert_eq!(digest(&mut bytes), fixture.policy.genesis_digest());
    let anchor = digest(&mut bytes);
    assert_eq!(anchor, fixture.policy.anchor());
    assert_eq!(u64be(&mut bytes), 0); // applied original tip height
    assert_eq!(u64be(&mut bytes), 0); // applied original tip view
    assert_eq!(digest(&mut bytes), anchor);
    let reference_len = usize::from(u16be(&mut bytes));
    assert_eq!(
        decode_object_ref(take(&mut bytes, reference_len)).unwrap(),
        *reviewed
    );
    assert!(bytes.is_empty());
}

fn status_200(address: SocketAddr) {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(
            format!(
                "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                node_wire::ordered_economics::ORDERED_ECONOMICS_STATUS_PATH
            )
            .as_bytes(),
        )
        .unwrap();
    let mut response = Vec::new();
    stream.take(8193).read_to_end(&mut response).unwrap();
    assert!(response.len() <= 8192);
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
}

fn client(socket: &Path, uid: u32, request: Option<&[u8]>) -> Output {
    let mut command = Command::new("/usr/bin/setpriv");
    command.args([
        "--reuid",
        &uid.to_string(),
        "--regid",
        &GROUP.to_string(),
        "--clear-groups",
        "/usr/bin/python3",
        "-I",
        "-B",
        "-c",
        CLIENT,
        &uid.to_string(),
    ]);
    command.arg(socket);
    match request {
        Some(bytes) => {
            assert!(bytes.len() <= 8192);
            command.arg("query").arg(hex(bytes));
        }
        None => {
            command.arg("wrong");
        }
    }
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", "/tmp");
    spawn_bounded_output(command, Duration::from_secs(6))
}

fn start_host(
    fixture: &Fixture,
    config: &Path,
    genesis: &Path,
    key: &Path,
) -> (ChildGuard, SocketAddr, u64) {
    let mut command = Command::new("/usr/bin/setpriv");
    command.args([
        "--reuid",
        "12001",
        "--regid",
        "12001",
        "--clear-groups",
        env!("CARGO_BIN_EXE_sqlite_source_host"),
    ]);
    command.args([
        "--chain-id",
        fixture.network.chain_id.as_str(),
        "--validator-id",
        &hex(fixture.network.validators[0].validator_id.as_bytes()),
        "--domain",
        &hex(fixture.network.domain.as_bytes()),
        "--protocol-version",
        &fixture.network.protocol_version.get().to_string(),
        "--epoch",
        &fixture.network.epoch.get().to_string(),
        "--suite",
        "0:1:1:1:1:1:1:1",
        "--genesis-manifest",
        genesis.to_str().unwrap(),
        "--expected-genesis-digest",
        &hex(&fixture.network.manifest_digest),
        "--signing-key-file",
        key.to_str().unwrap(),
        "--state-db",
        fixture.directory.0.join("state-0.sqlite").to_str().unwrap(),
        "--blob-db",
        fixture.directory.0.join("blobs.sqlite").to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--created-checkpoint",
        "10",
        "--timeout-seconds",
        "30",
        "--max-concurrent",
        "2",
        "--bond-currentness-config",
        config.to_str().unwrap(),
        "--confirm-offline-fence-advance",
    ]);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", "/tmp")
        .stderr(Stdio::piped());
    let (guard, line) = spawn_bounded_status_line(
        command,
        Duration::from_secs(20),
        compiled_host_startup_line_limit(fixture.network.chain_id.as_str()),
    );
    assert!(line.contains("complete=true mode=serving"));
    let address = line
        .split_whitespace()
        .find_map(|value| value.strip_prefix("listen="))
        .unwrap()
        .parse()
        .unwrap();
    let generation = line
        .split_whitespace()
        .find_map(|value| value.strip_prefix("writer_generation="))
        .unwrap()
        .parse()
        .unwrap();
    (guard, address, generation)
}

#[test]
#[ignore = "run only in pinned, no-network Docker multi-UID sandbox"]
fn compiled_original_host_currentness_distinct_uid_expiry_and_quota_degrade_only_route() {
    require_sandbox();
    let mut fixture = Fixture::new();
    let directory: PathBuf = fixture.directory.0.clone();
    let genesis = directory.join("genesis.bin");
    let key = directory.join("validator.key");
    let config_dir = directory.join("config");
    let socket_dir = directory.join("socket");
    fs::create_dir(&config_dir).unwrap();
    fs::create_dir(&socket_dir).unwrap();
    let config = config_dir.join("currentness.conf");
    let socket = socket_dir.join("currentness.sock");
    fs::write(&genesis, &fixture.network.manifest_bytes).unwrap();
    fs::write(&key, fixture.network.validators[0].seed).unwrap();
    fs::write(&config, format!("socket={}\nallowed-uid={CLIENT_UID}\nmax-connections=8\nmax-requests=8\ntotal-deadline-seconds=6\n", socket.display())).unwrap();
    let coin = fixture
        .root
        .manifest()
        .objects
        .iter()
        .find(|entry| entry.object.id == fixture.network.fee_coin)
        .unwrap();
    let body = encode_object(&coin.object).unwrap();
    let reviewed = ObjectRef {
        id: coin.object.id,
        version: coin.object.version,
        digest: fixture
            .network
            .resolver
            .hash_for_purpose(
                fixture.network.epoch,
                protocol_types::HashPurpose::Object,
                &body,
            )
            .unwrap(),
    };
    let reference = encode_object_ref(&reviewed).unwrap();
    let mut request = Vec::new();
    request.extend_from_slice(REQUEST_MAGIC);
    request.extend_from_slice(&u16::try_from(reference.len()).unwrap().to_be_bytes());
    request.extend_from_slice(&reference);
    request.extend_from_slice(&body);
    fixture.close_source_owners();
    let mut chown = Command::new("/usr/bin/chown");
    chown.args(["-R", "12001:12001"]).arg(&directory);
    assert!(
        spawn_bounded_output(chown, Duration::from_secs(5))
            .status
            .success()
    );
    for (path, mode) in [
        (&directory, 0o750),
        (&config_dir, 0o700),
        (&socket_dir, 0o750),
        (&config, 0o600),
        (&key, 0o600),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        owned(path, mode, HOST_UID, GROUP);
    }
    let (mut first, address, generation) = start_host(&fixture, &config, &genesis, &key);
    assert_eq!(generation, 2);
    owned(&socket, 0o660, HOST_UID, GROUP);
    let wrong = client(&socket, WRONG_UID, None);
    assert!(
        wrong.status.success(),
        "{}",
        String::from_utf8_lossy(&wrong.stderr)
    );
    assert_eq!(wrong.stdout, b"wrong-uid-refused-before-body");
    let allowed = client(&socket, CLIENT_UID, Some(&request));
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert_observation(&allowed.stdout, &fixture, &reviewed, generation);
    let end = Instant::now() + Duration::from_secs(8);
    while socket.exists() {
        assert!(
            first.try_wait().unwrap().is_none(),
            "whole host exited on optional listener expiry"
        );
        assert!(
            Instant::now() < end,
            "local socket did not expire and unlink"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    status_200(address);
    assert!(first.try_wait().unwrap().is_none());
    let terminal = first.stop_orderly_terminate(Duration::from_secs(5));
    assert!(String::from_utf8_lossy(&terminal).contains("bond_currentness_unavailable=true"));
    assert!(!socket.exists());

    // The second, fresh-fence host exhausts one admitted connection instead
    // of waiting for the listener deadline. The ordinary HTTP host must stay.
    fs::write(
        &config,
        format!("socket={}\nallowed-uid={CLIENT_UID}\nmax-connections=1\nmax-requests=8\ntotal-deadline-seconds=6\n", socket.display()),
    ).unwrap();
    owned(&config, 0o600, HOST_UID, GROUP);
    let (mut second, second_address, next_generation) =
        start_host(&fixture, &config, &genesis, &key);
    assert_eq!(next_generation, 3);
    owned(&socket, 0o660, HOST_UID, GROUP);
    let restarted = client(&socket, CLIENT_UID, Some(&request));
    assert!(
        restarted.status.success(),
        "{}",
        String::from_utf8_lossy(&restarted.stderr)
    );
    assert_observation(&restarted.stdout, &fixture, &reviewed, next_generation);
    let quota_end = Instant::now() + Duration::from_secs(2);
    while socket.exists() {
        assert!(
            second.try_wait().unwrap().is_none(),
            "whole host exited on listener quota"
        );
        assert!(
            Instant::now() < quota_end,
            "quota-exhausted socket remained bound"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    status_200(second_address);
    assert!(second.try_wait().unwrap().is_none());
    second.stop_orderly_terminate(Duration::from_secs(5));
    assert!(!socket.exists());
}
