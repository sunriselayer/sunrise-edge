//! Opt-in, host-owned Unix observation route. One connection and one query at
//! a time; no signer, second store opener, or caller-provided host authority.

use super::{OriginalBondCurrentnessObservation, OriginalBondCurrentnessReader};
use crate::local_custody_transport::{self, SocketOwner};
use objects::{ObjectRef, decode_object_ref, encode_object_ref};
use protocol_types::{Digest32, ValidatorId};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::watch,
    time::{Instant, timeout_at},
};

pub(in crate::sqlite_source_host) const FLAG: &str = "--bond-currentness-config";
const MAX_CONFIG: u64 = 4096;
const MAX_REQUESTS: u64 = 4096;
const MAX_SECONDS: u64 = 3600;
const REQUEST_MAGIC: &[u8; 8] = b"SRBREAD1";
const RESPONSE_MAGIC: &[u8; 8] = b"SRBOBS01";
const MAX_FRAME: usize = node_core::MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 4096;
const MAX_RESPONSE: usize = 1024;

fn refused() -> io::Error {
    io::Error::other("original bond currentness listener refused")
}

/// Closed private file; each allowed peer UID differs from the host.
pub(in crate::sqlite_source_host) struct Config {
    socket: PathBuf,
    allowed_uids: BTreeSet<u32>,
    max_connections: u64,
    max_requests: u64,
    total_deadline: Duration,
}

impl Config {
    pub(in crate::sqlite_source_host) fn load(path: &Path) -> io::Result<Self> {
        let input = local_custody_transport::config_file(path, MAX_CONFIG, refused)?;
        let mut values: BTreeMap<&str, &str> = BTreeMap::new();
        let mut allowed: Vec<&str> = Vec::new();
        for line in input.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(refused)?;
            if !matches!(
                key,
                "socket"
                    | "allowed-uid"
                    | "max-connections"
                    | "max-requests"
                    | "total-deadline-seconds"
            ) || value.is_empty()
                || value.trim() != value
            {
                return Err(refused());
            }
            if key == "allowed-uid" {
                if allowed.len() >= 8 {
                    return Err(refused());
                }
                allowed.push(value);
            } else if values.insert(key, value).is_some() {
                return Err(refused());
            }
        }
        let mut take = |key: &str| values.remove(key).ok_or_else(refused);
        let socket: PathBuf = take("socket")?.into();
        local_custody_transport::absolute(&socket, refused)?;
        if socket.as_os_str().len() > 100 {
            return Err(refused());
        }
        let own = local_custody_transport::own_uid(refused)?;
        let mut allowed_uids = BTreeSet::new();
        for raw in allowed {
            let uid: u32 = raw.parse().map_err(|_| refused())?;
            if uid == own || !allowed_uids.insert(uid) {
                return Err(refused());
            }
        }
        if allowed_uids.is_empty() {
            return Err(refused());
        }
        let number = |value: &str, max: u64| -> io::Result<u64> {
            let parsed: u64 = value.parse().map_err(|_| refused())?;
            if !(1..=max).contains(&parsed) {
                return Err(refused());
            }
            Ok(parsed)
        };
        let max_connections = number(take("max-connections")?, MAX_REQUESTS)?;
        let max_requests = number(take("max-requests")?, MAX_REQUESTS)?;
        let seconds = number(take("total-deadline-seconds")?, MAX_SECONDS)?;
        if !values.is_empty() {
            return Err(refused());
        }
        Ok(Self {
            socket,
            allowed_uids,
            max_connections,
            max_requests,
            total_deadline: Duration::from_secs(seconds),
        })
    }

    pub(in crate::sqlite_source_host) fn bind(&self) -> io::Result<(SocketOwner, UnixListener)> {
        SocketOwner::bind(&self.socket, refused)
    }
}

/// The request is magic, u16 canonical ObjectRef length, ObjectRef, and exact
/// reviewed canonical Coin body. There is one request per connection.
fn decode_request(bytes: &[u8]) -> io::Result<(ObjectRef, &[u8])> {
    if bytes.len() < 8 + 2 + 1 || &bytes[..8] != REQUEST_MAGIC {
        return Err(refused());
    }
    let length = usize::from(u16::from_be_bytes([bytes[8], bytes[9]]));
    let end = 10usize.checked_add(length).ok_or_else(refused)?;
    if length == 0 || end >= bytes.len() || length > 1024 {
        return Err(refused());
    }
    let reference = decode_object_ref(&bytes[10..end]).map_err(|_| refused())?;
    if encode_object_ref(&reference).map_err(|_| refused())? != bytes[10..end] {
        return Err(refused());
    }
    Ok((reference, &bytes[end..]))
}

fn digest(bytes: &mut Vec<u8>, value: Digest32) {
    bytes.extend_from_slice(&value.algorithm().as_u16().to_be_bytes());
    bytes.extend_from_slice(&value.bytes());
}

/// Success only. `chain_state_proof=false` is a literal zero byte. Fields are
/// ordered and length-prefixed to preserve the entire local token and tip.
fn encode_response(
    observation: &OriginalBondCurrentnessObservation,
    validator: ValidatorId,
) -> io::Result<Vec<u8>> {
    let token = &observation.token;
    let tip = &observation.ordered_tip;
    let chain = tip.context.chain_id().as_str().as_bytes();
    let coin = encode_object_ref(&observation.coin).map_err(|_| refused())?;
    let mut bytes = Vec::with_capacity(MAX_RESPONSE);
    bytes.extend_from_slice(RESPONSE_MAGIC);
    bytes.push(0); // chain_state_proof=false; not current at delivery.
    bytes.extend_from_slice(&validator.as_bytes()[..]);
    bytes.extend_from_slice(
        &u16::try_from(chain.len())
            .map_err(|_| refused())?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(chain);
    bytes.extend_from_slice(&tip.context.protocol_version().get().to_be_bytes());
    bytes.extend_from_slice(&token.domain().as_bytes()[..]);
    bytes.extend_from_slice(
        &u16::try_from(token.namespace().len())
            .map_err(|_| refused())?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(token.namespace());
    bytes.extend_from_slice(&token.writer_fence().get().to_be_bytes());
    bytes.extend_from_slice(&token.mutation_sequence().to_be_bytes());
    bytes.extend_from_slice(&observation.epoch.get().to_be_bytes());
    digest(&mut bytes, observation.validator_set_digest);
    digest(&mut bytes, tip.genesis_digest);
    digest(&mut bytes, tip.anchor);
    bytes.extend_from_slice(&tip.through_height.to_be_bytes());
    bytes.extend_from_slice(&tip.through_view.to_be_bytes());
    digest(&mut bytes, tip.through_digest);
    bytes.extend_from_slice(
        &u16::try_from(coin.len())
            .map_err(|_| refused())?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&coin);
    if bytes.len() > MAX_RESPONSE {
        return Err(refused());
    }
    Ok(bytes)
}

async fn changed(stop: &mut watch::Receiver<bool>) {
    if !*stop.borrow() {
        let _ = stop.changed().await;
    }
}

/// Every blocking query is joined before this returns, even if the socket
/// client disconnects or a stop arrives during SQLite work. The query's own
/// fresh context carries a finite host timeout.
pub(in crate::sqlite_source_host) async fn serve(
    listener: UnixListener,
    reader: Arc<OriginalBondCurrentnessReader>,
    validator: ValidatorId,
    config: Config,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let end = Instant::now()
        .checked_add(config.total_deadline)
        .ok_or_else(refused)?;
    let mut connections = 0u64;
    let mut requests = 0u64;
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        if connections >= config.max_connections || requests >= config.max_requests {
            return Err(refused()); // quota exhaustion closes only this route.
        }
        let accepted = tokio::select! {
            biased;
            () = changed(&mut stop) => return Ok(()),
            result = timeout_at(end, listener.accept()) => result,
        };
        let (mut stream, _address): (UnixStream, _) = match accepted {
            Ok(result) => result?,
            Err(_) => return Err(refused()),
        };
        connections += 1;
        // No request byte is consumed before this credential check.
        if stream
            .peer_cred()
            .map(|cred| cred.uid())
            .ok()
            .filter(|uid| config.allowed_uids.contains(uid))
            .is_none()
        {
            continue;
        }
        requests += 1;
        let request_end = end.min(
            Instant::now()
                .checked_add(Duration::from_secs(30))
                .ok_or_else(refused)?,
        );
        let received = tokio::select! {
            biased;
            () = changed(&mut stop) => return Ok(()),
            result = timeout_at(request_end, native_http::local_custody_transport::read_frame(&mut stream, MAX_FRAME, refused)) => result,
        };
        let bytes = match received {
            Ok(Ok(bytes)) => bytes,
            _ => continue,
        };
        if *stop.borrow() {
            return Ok(());
        }
        let request_reader = Arc::clone(&reader);
        let queried = tokio::task::spawn_blocking(move || -> io::Result<Vec<u8>> {
            let (reference, body) = decode_request(&bytes)?;
            let observation = request_reader
                .observe(&reference, body)
                .map_err(|_| refused())?;
            encode_response(&observation, validator)
        })
        .await
        .map_err(|_| refused())?;
        let response = match queried {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        if *stop.borrow() {
            return Ok(());
        }
        let response_end = end.min(
            Instant::now()
                .checked_add(Duration::from_secs(30))
                .ok_or_else(refused)?,
        );
        let _ = tokio::select! {
            biased;
            () = changed(&mut stop) => return Ok(()),
            result = timeout_at(response_end, native_http::local_custody_transport::write_frame(&mut stream, &response, refused)) => result,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite_source_host::currentness::tests::Installed;
    use std::{fs, os::unix::fs::PermissionsExt};
    use tokio::{io::AsyncReadExt, time::timeout};

    const TEST_BOUND: Duration = Duration::from_secs(10);

    fn socket(installed: &Installed, name: &str) -> PathBuf {
        let parent = installed.path().join(name);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o750)).unwrap();
        parent.join("observe.sock")
    }

    fn config(socket: PathBuf, allowed_uid: u32) -> Config {
        Config {
            socket,
            allowed_uids: BTreeSet::from([allowed_uid]),
            max_connections: 8,
            max_requests: 8,
            total_deadline: TEST_BOUND,
        }
    }

    fn request(installed: &Installed) -> Vec<u8> {
        let reference = encode_object_ref(&installed.reviewed).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&u16::try_from(reference.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&reference);
        bytes.extend_from_slice(&installed.body);
        bytes
    }

    async fn exchange(path: &Path, bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut stream = UnixStream::connect(path).await?;
        native_http::local_custody_transport::write_frame(&mut stream, bytes, refused).await?;
        native_http::local_custody_transport::read_frame(&mut stream, MAX_RESPONSE, refused).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_uid_is_refused_before_any_request_byte_and_socket_is_removed_after_stop() {
        let installed = Installed::new();
        let own = local_custody_transport::own_uid(refused).unwrap();
        let config = config(socket(&installed, "wrong-uid"), own.checked_add(1).unwrap());
        let path = config.socket.clone();
        let (owner, listener) = config.bind().unwrap();
        let (stop, receiver) = watch::channel(false);
        let reader = Arc::new(installed.reader());
        let validator = installed.network.validators[0].validator_id;
        let task = tokio::spawn(async move {
            let result = serve(listener, reader, validator, config, receiver).await;
            owner.close()?;
            result
        });
        let mut stream = UnixStream::connect(&path).await.unwrap();
        let mut first = [0u8; 1];
        // No frame or EOF is sent by the peer. A server that reads before
        // authenticating would hang at this point.
        assert_eq!(
            timeout(Duration::from_secs(2), stream.read(&mut first))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        stop.send(true).unwrap();
        timeout(TEST_BOUND, task).await.unwrap().unwrap().unwrap();
        assert!(!path.exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_ipc_reports_exact_coin_and_tip_then_refuses_stale_fence() {
        let installed = Installed::new();
        let own = local_custody_transport::own_uid(refused).unwrap();
        // Test-only peer equivalence exercises the wire; Config::load rejects
        // same-UID deployment and is tested separately below.
        let config = config(socket(&installed, "exact-coin"), own);
        let path = config.socket.clone();
        let (owner, listener) = config.bind().unwrap();
        let (stop, receiver) = watch::channel(false);
        let reader = Arc::new(installed.reader());
        let store = Arc::clone(&installed.store);
        let claimed = installed.claimed;
        let validator = installed.network.validators[0].validator_id;
        let expected = encode_response(
            &reader
                .observe(&installed.reviewed, &installed.body)
                .unwrap(),
            validator,
        )
        .unwrap();
        let request = request(&installed);
        let task = tokio::spawn(async move {
            let result = serve(listener, reader, validator, config, receiver).await;
            owner.close()?;
            result
        });
        let response = timeout(TEST_BOUND, exchange(&path, &request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, expected);
        assert_eq!(&response[..8], RESPONSE_MAGIC);
        assert_eq!(response[8], 0); // no chain-state proof
        // A changed writer generation makes this same live IPC route refuse.
        store
            .advance_writer_fence(claimed, claimed.checked_next().unwrap())
            .unwrap();
        assert!(
            timeout(TEST_BOUND, exchange(&path, &request))
                .await
                .unwrap()
                .is_err()
        );
        stop.send(true).unwrap();
        timeout(TEST_BOUND, task).await.unwrap().unwrap().unwrap();
        assert!(!path.exists());

        // A fresh host generation can bind the same path only after old
        // admissions and socket ownership have ended.
        let new_fence = claimed.checked_next().unwrap();
        let fresh_reader = Arc::new(
            OriginalBondCurrentnessReader::new(
                Arc::clone(&installed.store),
                Arc::clone(&installed.blobs),
                installed.root.clone(),
                installed.network.domain,
                validator,
                installed.public_key,
                new_fence,
                Duration::from_secs(30),
            )
            .unwrap(),
        );
        let fresh_config = self::config(path.clone(), own);
        let (fresh_owner, fresh_socket) = fresh_config.bind().unwrap();
        let (fresh_stop, fresh_receiver) = watch::channel(false);
        let fresh_task = tokio::spawn(async move {
            let result = serve(
                fresh_socket,
                fresh_reader,
                validator,
                fresh_config,
                fresh_receiver,
            )
            .await;
            fresh_owner.close()?;
            result
        });
        let fresh = timeout(TEST_BOUND, exchange(&path, &request))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(fresh, expected);
        fresh_stop.send(true).unwrap();
        timeout(TEST_BOUND, fresh_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn production_config_refuses_same_uid_and_unknown_fields() {
        let installed = Installed::new();
        let directory = installed.path().join("private-config");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("listener.conf");
        let own = local_custody_transport::own_uid(refused).unwrap();
        fs::write(&path, format!("socket=/tmp/observe.sock\nallowed-uid={own}\nmax-connections=2\nmax-requests=2\ntotal-deadline-seconds=10\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Config::load(&path).is_err());
        fs::write(&path, format!("socket=/tmp/observe.sock\nallowed-uid={}\nmax-connections=2\nmax-requests=2\ntotal-deadline-seconds=10\nunknown=yes\n", own + 1)).unwrap();
        assert!(Config::load(&path).is_err());
        fs::write(&path, format!("socket=/tmp/observe.sock\nallowed-uid={}\nallowed-uid={}\nmax-connections=2\nmax-requests=2\ntotal-deadline-seconds=10\n", own + 1, own + 2)).unwrap();
        assert_eq!(
            Config::load(&path).unwrap().allowed_uids,
            BTreeSet::from([own + 1, own + 2])
        );
        fs::write(&path, format!("socket=/tmp/observe.sock\nallowed-uid={}\nallowed-uid={}\nmax-connections=2\nmax-requests=2\ntotal-deadline-seconds=10\n", own + 1, own + 1)).unwrap();
        assert!(Config::load(&path).is_err());
    }
}
