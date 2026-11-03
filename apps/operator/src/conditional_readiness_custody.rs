//! DR-0284 readiness-only local worker. No raw signature or successor route.

use crate::{
    business_pins::{BusinessPinInputs, bounded, hex},
    common::{FlagSet, parse_hex_32},
    conditional_readiness::{PreparedVote, load_vote_public},
    immutable_archive::ImmutableArchive,
    local_anchor,
    local_custody_transport::{self, SocketOwner},
    successor_artifacts::SuccessorChainInputs,
};
use consensus::readiness::MAX_READINESS_VOTE_BYTES;
use protocol_types::ValidatorId;
use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    time::{Instant, timeout_at},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_CONFIG: u64 = 16 * 1024;
const MAX_SECONDS: u64 = 3600;
const MAX_REQUESTS: u64 = 4096;
const REQUEST: &[u8; 8] = b"SRDVOTE1";
const RESPONSE: &[u8; 8] = b"SRDRESP1";
const MAX_RESPONSE: usize = RESPONSE.len() + MAX_READINESS_VOTE_BYTES;
const PUBLIC_FLAGS: &[&str] = &[
    "--chain-id",
    "--protocol-version",
    "--epoch",
    "--domain",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--ordered-history-dir",
    "--cut-dir",
    "--next-set",
    "--successor-max-links",
    "--successor-plan-history-dir",
    "--successor-cut-dir",
    "--successor-manifest-history-dir",
    "--successor-certificate-dir",
];
const WORKER_FLAGS: &[&str] = &[
    "--state-db",
    "--blob-db",
    "--validator-id",
    "--signer-key-file",
    local_anchor::FLAG,
    "--timeout-seconds",
];
const FRONTEND_FLAGS: &[&str] = &["--out-dir", "--validator-id"];

fn refused() -> io::Error {
    io::Error::other("conditional readiness custody refused")
}

struct Config {
    values: BTreeMap<String, Vec<String>>,
}

impl Config {
    fn parse(input: &str, worker: bool) -> io::Result<Self> {
        let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in input.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value): (&str, &str) = line.split_once('=').ok_or_else(refused)?;
            let flag: String = format!("--{key}");
            let control: bool = matches!(key, "socket" | "total-deadline-seconds")
                || if worker {
                    matches!(key, "frontend-uid" | "max-connections" | "max-requests")
                } else {
                    key == "worker-uid"
                };
            if !(control
                || PUBLIC_FLAGS.contains(&flag.as_str())
                || if worker {
                    WORKER_FLAGS.contains(&flag.as_str())
                } else {
                    FRONTEND_FLAGS.contains(&flag.as_str())
                })
                || value.is_empty()
                || value.trim() != value
                || value.len() > 4096
            {
                return Err(refused());
            }
            let repeated: bool = matches!(
                key,
                "suite"
                    | "successor-plan-history-dir"
                    | "successor-cut-dir"
                    | "successor-manifest-history-dir"
                    | "successor-certificate-dir"
            );
            let entries: &mut Vec<String> = values.entry(key.into()).or_default();
            if (!repeated && !entries.is_empty()) || entries.len() >= 64 {
                return Err(refused());
            }
            entries.push(value.into());
        }
        Ok(Self { values })
    }

    fn take(&mut self, key: &str) -> io::Result<String> {
        let mut entries: Vec<String> = self.values.remove(key).ok_or_else(refused)?;
        if entries.len() != 1 {
            return Err(refused());
        }
        entries.pop().ok_or_else(refused)
    }

    fn number(&mut self, key: &str, maximum: u64) -> io::Result<u64> {
        let value: u64 = self.take(key)?.parse().map_err(|_| refused())?;
        if value == 0 || value > maximum {
            return Err(refused());
        }
        Ok(value)
    }

    fn vote_args(self) -> Vec<OsString> {
        let mut args: Vec<OsString> = Vec::new();
        for (key, entries) in self.values {
            for value in entries {
                args.push(format!("--{key}").into());
                args.push(value.into());
            }
        }
        args
    }
}

struct Startup {
    socket: PathBuf,
    peer_uid: u32,
    max_connections: u64,
    max_requests: u64,
    deadline: Duration,
    vote_args: Vec<OsString>,
}

impl Startup {
    fn parse(mut config: Config, worker: bool) -> Result<Self> {
        let socket: PathBuf = config.take("socket")?.into();
        local_custody_transport::absolute(&socket, refused)?;
        if socket.as_os_str().len() > 100 {
            return Err(refused().into());
        }
        let peer_uid: u32 = config
            .take(if worker { "frontend-uid" } else { "worker-uid" })?
            .parse()?;
        if peer_uid == local_custody_transport::own_uid(refused)? {
            return Err(refused().into());
        }
        let max_connections: u64 = if worker {
            config.number("max-connections", MAX_REQUESTS)?
        } else {
            1
        };
        let max_requests: u64 = if worker {
            config.number("max-requests", MAX_REQUESTS)?
        } else {
            1
        };
        let deadline: Duration =
            Duration::from_secs(config.number("total-deadline-seconds", MAX_SECONDS)?);
        if worker {
            for key in ["signer-key-file", "state-db", "blob-db"] {
                let path: PathBuf = config
                    .values
                    .get(key)
                    .and_then(|entries: &Vec<String>| entries.first())
                    .ok_or_else(refused)?
                    .into();
                local_custody_transport::private_file(&path, refused)?;
            }
            if let Some(path) = config.values.get("independent-anchor-db") {
                let path: PathBuf = path.first().ok_or_else(refused)?.into();
                local_custody_transport::private_file(&path, refused)?;
            }
        }
        Ok(Self {
            socket,
            peer_uid,
            max_connections,
            max_requests,
            deadline,
            vote_args: config.vote_args(),
        })
    }
}

pub(crate) fn run(worker: bool, tokens: Vec<OsString>) -> Result<()> {
    let mut flags: FlagSet = FlagSet::parse(tokens, &["--config"], &[])?;
    let path: PathBuf = flags.one("--config")?.into();
    flags.finish()?;
    let input: String = local_custody_transport::config_file(&path, MAX_CONFIG, refused)?;
    let startup: Startup = Startup::parse(Config::parse(&input, worker)?, worker)?;
    if worker {
        run_worker(startup)
    } else {
        run_frontend(startup)
    }
}

fn public_inputs(
    flags: &mut FlagSet,
) -> Result<(
    Option<SuccessorChainInputs>,
    BusinessPinInputs,
    PathBuf,
    PathBuf,
)> {
    let chain: Option<SuccessorChainInputs> = SuccessorChainInputs::parse_optional(flags)?;
    let pins: BusinessPinInputs = BusinessPinInputs::parse(flags)?;
    let cut: PathBuf = flags.one("--cut-dir")?.into();
    let next: PathBuf = flags.one("--next-set")?.into();
    Ok((chain, pins, cut, next))
}

fn worker_vote(tokens: Vec<OsString>) -> Result<Vec<u8>> {
    let mut accepted: Vec<&'static str> = PUBLIC_FLAGS.to_vec();
    accepted.extend_from_slice(WORKER_FLAGS);
    let mut flags: FlagSet = FlagSet::parse(tokens, &accepted, &[])?;
    let anchor: Option<PathBuf> = local_anchor::parse(&mut flags)?;
    let (chain, pins, cut, next): (
        Option<SuccessorChainInputs>,
        BusinessPinInputs,
        PathBuf,
        PathBuf,
    ) = public_inputs(&mut flags)?;
    let timeout: u64 = bounded(
        &flags
            .optional_one("--timeout-seconds")?
            .unwrap_or_else(|| "300".into()),
        1,
        MAX_SECONDS,
    )?;
    let state: PathBuf = flags.one("--state-db")?.into();
    let blobs: PathBuf = flags.one("--blob-db")?.into();
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(
        &flags.one("--validator-id")?,
        "--validator-id",
    )?);
    let key: PathBuf = flags.one("--signer-key-file")?.into();
    flags.finish()?;
    for path in [&state, &blobs, &key] {
        local_custody_transport::private_file(path, refused)?;
    }
    if let Some(path) = &anchor {
        local_custody_transport::private_file(path, refused)?;
    }
    let prepared: PreparedVote =
        load_vote_public(chain, pins, &cut, &next, None, Some((&state, &blobs)))?;
    prepared.produce_worker_vote((state, blobs, validator, key), anchor.as_deref(), timeout)
}

fn frontend_vote_inputs(
    tokens: Vec<OsString>,
) -> Result<(PreparedVote, ImmutableArchive, ValidatorId)> {
    let mut accepted: Vec<&'static str> = PUBLIC_FLAGS.to_vec();
    accepted.extend_from_slice(FRONTEND_FLAGS);
    let mut flags: FlagSet = FlagSet::parse(tokens, &accepted, &[])?;
    let (chain, pins, cut, next): (
        Option<SuccessorChainInputs>,
        BusinessPinInputs,
        PathBuf,
        PathBuf,
    ) = public_inputs(&mut flags)?;
    let output_directory: PathBuf = flags.one("--out-dir")?.into();
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(
        &flags.one("--validator-id")?,
        "--validator-id",
    )?);
    flags.finish()?;
    let output_path: PathBuf = output_directory.join("vote.bin");
    let prepared: PreparedVote =
        load_vote_public(chain, pins, &cut, &next, Some(&output_path), None)?;
    for source in [&prepared.history, &prepared.cut] {
        source.require_output_outside(&output_path)?;
    }
    if let Some(artifacts) = &prepared.chain_artifacts {
        artifacts.require_output_outside(&output_path)?;
    }
    let output: ImmutableArchive = ImmutableArchive::open(&output_directory)?;
    if output.names()?.iter().any(|name| name != "vote.bin") {
        return Err("output directory contains another artifact role".into());
    }
    if output.contains("vote.bin")? {
        let bytes: Vec<u8> = output.read("vote.bin", MAX_READINESS_VOTE_BYTES)?;
        prepared.verify_worker_vote(&bytes, validator)?;
    }
    Ok((prepared, output, validator))
}

fn run_worker(startup: Startup) -> Result<()> {
    let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let (owner, listener): (SocketOwner, UnixListener) =
            SocketOwner::bind(&startup.socket, refused)?;
        let end: Instant = Instant::now()
            .checked_add(startup.deadline)
            .ok_or_else(refused)?;
        let mut terminate: tokio::signal::unix::Signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut interrupt: tokio::signal::unix::Signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut connections: u64 = 0;
        let mut requests: u64 = 0;
        println!("complete=true mode=readiness-worker transport=unix admission=transport-only");
        io::stdout().flush()?;
        while connections < startup.max_connections && requests < startup.max_requests {
            let accepted = tokio::select! {
                result = timeout_at(end, listener.accept()) => result,
                _ = terminate.recv() => break,
                _ = interrupt.recv() => break,
            };
            let (mut stream, _address): (UnixStream, _) = match accepted {
                Ok(Ok(pair)) => pair,
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => break,
            };
            connections = connections.checked_add(1).ok_or_else(refused)?;
            if native_http::local_custody_transport::authenticate(
                &stream,
                startup.peer_uid,
                refused,
            )
            .is_err()
            {
                continue;
            }
            requests = requests.checked_add(1).ok_or_else(refused)?;
            let request_end: Instant = end.min(
                Instant::now()
                    .checked_add(Duration::from_secs(30))
                    .ok_or_else(refused)?,
            );
            let request: Vec<u8> = match timeout_at(
                request_end,
                native_http::local_custody_transport::read_frame(
                    &mut stream,
                    REQUEST.len(),
                    refused,
                ),
            )
            .await
            {
                Ok(Ok(bytes)) => bytes,
                _ => continue,
            };
            if request != REQUEST {
                continue;
            }
            let vote_args: Vec<OsString> = startup.vote_args.clone();
            // A disconnected frontend never cancels started retention. Wait for
            // this single blocking owner before accepting or closing the socket.
            let produced: io::Result<Vec<u8>> =
                tokio::task::spawn_blocking(move || worker_vote(vote_args).map_err(|_| refused()))
                    .await
                    .map_err(|_| refused())?;
            let Ok(vote) = produced else {
                continue;
            };
            let mut response: Vec<u8> = Vec::with_capacity(RESPONSE.len() + vote.len());
            response.extend_from_slice(RESPONSE);
            response.extend_from_slice(&vote);
            if response.len() > MAX_RESPONSE {
                continue;
            }
            println!("readiness_worker=retained-vote bytes={}", vote.len());
            io::stdout().flush()?;
            let response_end: Instant = end.min(
                Instant::now()
                    .checked_add(Duration::from_secs(30))
                    .ok_or_else(refused)?,
            );
            let _sent = timeout_at(
                response_end,
                native_http::local_custody_transport::write_frame(&mut stream, &response, refused),
            )
            .await;
        }
        owner.close()?;
        Ok(())
    })
}

fn run_frontend(startup: Startup) -> Result<()> {
    let (prepared, output, validator): (PreparedVote, ImmutableArchive, ValidatorId) =
        frontend_vote_inputs(startup.vote_args)
            .map_err(|error| format!("readiness frontend public input refused: {error}"))?;
    let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let vote: Vec<u8> = runtime
        .block_on(async move {
            let end: Instant = Instant::now()
                .checked_add(startup.deadline)
                .ok_or_else(refused)?;
            let mut stream: UnixStream =
                timeout_at(end, UnixStream::connect(&startup.socket)).await??;
            native_http::local_custody_transport::authenticate(&stream, startup.peer_uid, refused)?;
            timeout_at(
                end,
                native_http::local_custody_transport::write_frame(&mut stream, REQUEST, refused),
            )
            .await??;
            let bytes: Vec<u8> = timeout_at(
                end,
                native_http::local_custody_transport::read_frame(
                    &mut stream,
                    MAX_RESPONSE,
                    refused,
                ),
            )
            .await??;
            let vote: &[u8] = bytes.strip_prefix(RESPONSE).ok_or_else(refused)?;
            if vote.is_empty() || vote.len() > MAX_READINESS_VOTE_BYTES {
                return Err(refused().into());
            }
            Ok::<Vec<u8>, Box<dyn Error>>(vote.to_vec())
        })
        .map_err(|error| format!("readiness frontend transport refused: {error}"))?;
    prepared
        .verify_worker_vote(&vote, validator)
        .map_err(|error| format!("readiness frontend vote refused: {error}"))?;
    output
        .publish("vote.bin", &vote)
        .map_err(|error| format!("readiness frontend publication refused: {error}"))?;
    println!(
        "conditional_readiness=retained-vote cut={} next_epoch={} meaning=not-seal-activation-or-serving",
        hex(&prepared.subject.cut_digest.bytes()),
        prepared.subject.next_epoch.get()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_has_only_the_fixed_readiness_roles() {
        for (line, worker) in [
            ("sign-frame=anything\n", true),
            ("signer-key-file=/tmp/key\n", false),
            ("state-db=/tmp/state\n", false),
            ("out-dir=/tmp/output\n", true),
            ("independent-anchor-db=/tmp/anchor\n", false),
            ("successor-host=/tmp/host\n", true),
            ("frontend-uid=1\nfrontend-uid=2\n", true),
        ] {
            assert!(Config::parse(line, worker).is_err());
        }
        let own: u32 = local_custody_transport::own_uid(refused).unwrap();
        let same_uid: String = format!(
            "socket=/tmp/readiness.sock\nfrontend-uid={own}\nmax-connections=1\nmax-requests=1\ntotal-deadline-seconds=1\n"
        );
        assert!(Startup::parse(Config::parse(&same_uid, true).unwrap(), true).is_err());
    }
}
