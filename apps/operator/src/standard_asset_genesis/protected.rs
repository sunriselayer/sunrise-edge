//! Finite, genesis-only local review and protected key use. No caller supplies
//! a signing frame, key path, committee, economics or output to the worker.
use super::{
    build,
    input::{Allocation, Config, Validator},
};
use crate::{
    common::{hex_lower as hex, load_signing_key_file, parse_hash_suite, parse_hex_32},
    genesis_inspection::render::render_review,
    genesis_output::{FreshGenesisOutput, PublishedGenesis},
    local_custody_transport as local,
    original_genesis_install::validate_original_genesis_in_memory,
};
use crypto::{Ed25519Verifier, SignatureVerifier};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::{
    local_execution::local_execution_signing_frame,
    publication::publication_submission_signing_frame,
};
use native_http::local_custody_transport as ipc;
use node_core::genesis::{
    GenesisManifest, VerifiedGenesisRoot, decode_genesis_manifest, encode_genesis_manifest,
    genesis_manifest_commitment, genesis_manifest_signing_frame,
};
use protocol_types::{Digest32, HashSuiteSchedule};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::UnixStream;

const MAX_CONFIG: u64 = 64 * 1024;
const MAX_REVIEW: usize = 4 * node_core::MAX_GENESIS_MANIFEST_BYTES + 8192;
// One accepted connection ends after a finite human review window.
const REVIEW_SECONDS: u64 = 900;
const MAX_EXPIRY_SECONDS: u64 = 3600;
const STATE_MAGIC: &[u8; 5] = b"SNEG1";
const STATE_BYTES: usize = 5 + 32 + 32 + 8 + 4;

fn refused() -> io::Error {
    io::Error::other("protected Standard Asset genesis refused")
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Nested,
    Manifest,
    Revoke,
}

impl Phase {
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "nested" => Ok(Self::Nested),
            "manifest" => Ok(Self::Manifest),
            "revoke" => Ok(Self::Revoke),
            _ => Err(refused()),
        }
    }

    fn byte(self) -> u8 {
        match self {
            Self::Nested => 1,
            Self::Manifest => 2,
            Self::Revoke => 3,
        }
    }
}

struct Invocation {
    phase: Phase,
    config_file: PathBuf,
    socket: PathBuf,
    state_file: PathBuf,
    reviewer_uid: u32,
    expiry: u64,
}

impl Invocation {
    fn parse(tokens: impl IntoIterator<Item = OsString>, worker: bool) -> io::Result<Self> {
        let values: Vec<OsString> = tokens.into_iter().collect();
        if values.len() != 6 {
            return Err(refused());
        }
        let text =
            |index: usize| -> io::Result<&str> { values[index].to_str().ok_or_else(refused) };
        let phase: Phase = Phase::parse(text(0)?)?;
        let config_file: PathBuf = PathBuf::from(&values[1]);
        let socket: PathBuf = PathBuf::from(&values[2]);
        let state_file: PathBuf = PathBuf::from(&values[3]);
        let reviewer_uid: u32 = text(4)?.parse().map_err(|_| refused())?;
        let expiry: u64 = text(5)?.parse().map_err(|_| refused())?;
        local::absolute(&config_file, refused)?;
        local::absolute(&socket, refused)?;
        local::absolute(&state_file, refused)?;
        if socket.as_os_str().len() > 100 || socket == state_file {
            return Err(refused());
        }
        if worker {
            if reviewer_uid == local::own_uid(refused)? {
                return Err(refused());
            }
            local::owned(socket.parent().ok_or_else(refused)?, 0o750, true, refused)?;
            local::owned(
                state_file.parent().ok_or_else(refused)?,
                0o700,
                true,
                refused,
            )?;
            if phase == Phase::Nested {
                let now: u64 = now()?;
                if expiry <= now || expiry > now.saturating_add(MAX_EXPIRY_SECONDS) {
                    return Err(refused());
                }
            } else if expiry != 0 {
                return Err(refused());
            }
        }
        Ok(Self {
            phase,
            config_file,
            socket,
            state_file,
            reviewer_uid,
            expiry,
        })
    }
}

fn now() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| refused())?
        .as_secs())
}

fn config(path: &Path) -> Result<(Config, [u8; 32]), Box<dyn Error>> {
    let content: String = local::config_file(path, MAX_CONFIG, refused)?;
    let digest: [u8; 32] = Sha256::digest(content.as_bytes()).into();
    let mut tokens: Vec<OsString> = Vec::new();
    for line in content.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (flag, value): (&str, &str) = line.split_once('=').ok_or_else(refused)?;
        if !flag.starts_with("--") || value.is_empty() || value.contains(['\n', '\r', '\0']) {
            return Err(refused().into());
        }
        tokens.push(flag.into());
        tokens.push(value.into());
    }
    Ok((Config::parse(tokens.into_iter())?, digest))
}

struct Review {
    phase: Phase,
    manifest: GenesisManifest,
    frames: [Vec<u8>; 3],
    schedules: Vec<HashSuiteSchedule>,
}

impl Review {
    fn build(
        config: &Config,
        validators: &[Validator],
        allocations: &[Allocation],
        phase: Phase,
        key: Option<&SigningKey>,
    ) -> Result<Self, Box<dyn Error>> {
        let mut frames: [Vec<u8>; 3] = std::array::from_fn(|_| Vec::new());
        let manifest: GenesisManifest = build::build_with_signer(
            config,
            validators,
            allocations,
            &mut |purpose: build::SigningPurpose, frame: &[u8]| {
                let index: usize = match purpose {
                    build::SigningPurpose::Publication => 0,
                    build::SigningPurpose::Initialization => 1,
                    build::SigningPurpose::Manifest => 2,
                };
                frames[index] = frame.to_vec();
                if phase == Phase::Manifest && index < 2 {
                    Ok(key.ok_or_else(refused)?.sign(frame).into())
                } else {
                    Ok([0; 64])
                }
            },
        )?;
        Ok(Self {
            phase,
            manifest,
            frames,
            schedules: config.resolver.schedules().to_vec(),
        })
    }

    fn encode(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let manifest: Vec<u8> = encode_genesis_manifest(&self.manifest)?;
        let mut schedules: String = String::new();
        for entry in &self.schedules {
            let suite = &entry.suite;
            schedules.push_str(&format!(
                "{}:{}:{}:{}:{}:{}:{}:{}\n",
                entry.activation_epoch.get(),
                suite.id.get(),
                suite.transaction_hash.as_u16(),
                suite.object_digest.as_u16(),
                suite.effects_hash.as_u16(),
                suite.code_hash.as_u16(),
                suite.config_hash.as_u16(),
                suite.certificate_hash.as_u16(),
            ));
        }
        let mut body: Vec<u8> = vec![self.phase.byte()];
        for part in [
            &manifest,
            &self.frames[0],
            &self.frames[1],
            &self.frames[2],
            &schedules.into_bytes(),
        ] {
            body.extend_from_slice(&u32::try_from(part.len())?.to_be_bytes());
            body.extend_from_slice(part);
        }
        if body.len() > MAX_REVIEW {
            return Err(refused().into());
        }
        Ok(body)
    }

    fn decode(bytes: &[u8], expected: Phase) -> Result<Self, Box<dyn Error>> {
        if bytes.len() > MAX_REVIEW || bytes.first() != Some(&expected.byte()) {
            return Err(refused().into());
        }
        let mut offset: usize = 1;
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(5);
        for _ in 0..5 {
            let end: usize = offset.checked_add(4).ok_or_else(refused)?;
            let len_bytes: [u8; 4] = bytes.get(offset..end).ok_or_else(refused)?.try_into()?;
            let len: usize = usize::try_from(u32::from_be_bytes(len_bytes))?;
            offset = end;
            let end: usize = offset.checked_add(len).ok_or_else(refused)?;
            parts.push(bytes.get(offset..end).ok_or_else(refused)?.to_vec());
            offset = end;
        }
        if offset != bytes.len() {
            return Err(refused().into());
        }
        let manifest_bytes: Vec<u8> = parts.remove(0);
        let manifest: GenesisManifest = decode_genesis_manifest(&manifest_bytes)?;
        if manifest.signature != [0; 64] || encode_genesis_manifest(&manifest)? != manifest_bytes {
            return Err(refused().into());
        }
        let schedule_bytes: Vec<u8> = parts.pop().ok_or_else(refused)?;
        let schedule_text: &str = std::str::from_utf8(&schedule_bytes)?;
        let schedules: Vec<HashSuiteSchedule> = schedule_text
            .lines()
            .map(parse_hash_suite)
            .collect::<Result<Vec<HashSuiteSchedule>, String>>(
        )?;
        if schedules.is_empty() || schedules.len() > 64 {
            return Err(refused().into());
        }
        let frames: [Vec<u8>; 3] = parts.try_into().map_err(|_| refused())?;
        Ok(Self {
            phase: expected,
            manifest,
            frames,
            schedules,
        })
    }

    fn digest(&self) -> Result<[u8; 32], Box<dyn Error>> {
        Ok(Sha256::digest(self.encode()?).into())
    }
}

struct State {
    config_digest: [u8; 32],
    draft_digest: [u8; 32],
    expiry: u64,
    reviewer_uid: u32,
}

impl State {
    fn create(&self, path: &Path) -> io::Result<()> {
        let mut file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(STATE_MAGIC)?;
        file.write_all(&self.config_digest)?;
        file.write_all(&self.draft_digest)?;
        file.write_all(&self.expiry.to_be_bytes())?;
        file.write_all(&self.reviewer_uid.to_be_bytes())?;
        file.sync_all()?;
        File::open(path.parent().ok_or_else(refused)?)?.sync_all()
    }

    fn read(path: &Path) -> io::Result<Self> {
        let metadata: fs::Metadata = local::private_file(path, refused)?;
        if metadata.len() != STATE_BYTES as u64 {
            return Err(refused());
        }
        let mut bytes: [u8; STATE_BYTES] = [0; STATE_BYTES];
        File::open(path)?.read_exact(&mut bytes)?;
        if &bytes[..5] != STATE_MAGIC {
            return Err(refused());
        }
        Ok(Self {
            config_digest: bytes[5..37].try_into().map_err(|_| refused())?,
            draft_digest: bytes[37..69].try_into().map_err(|_| refused())?,
            expiry: u64::from_be_bytes(bytes[69..77].try_into().map_err(|_| refused())?),
            reviewer_uid: u32::from_be_bytes(bytes[77..81].try_into().map_err(|_| refused())?),
        })
    }

    fn live(
        &self,
        config_digest: [u8; 32],
        draft_digest: [u8; 32],
        state: &Path,
        reviewer_uid: u32,
    ) -> io::Result<()> {
        if self.config_digest != config_digest
            || self.draft_digest != draft_digest
            || self.reviewer_uid != reviewer_uid
            || now()? >= self.expiry
            || revoked(state)?
        {
            return Err(refused());
        }
        Ok(())
    }
}

fn revocation_path(state: &Path) -> io::Result<PathBuf> {
    let name: &str = state
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(refused)?;
    Ok(state.with_file_name(format!("{name}.revoked")))
}

fn revoked(state: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(revocation_path(state)?) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn expected_key(config: &Config) -> Result<SigningKey, Box<dyn Error>> {
    local::private_file(&config.key_file, refused)?;
    let key: SigningKey = load_signing_key_file(&config.key_file)?;
    let public: [u8; 32] = VerificationKey::from(&key).into();
    if public != config.authority {
        return Err(refused().into());
    }
    Ok(key)
}

fn publish(
    config: &Config,
    output: FreshGenesisOutput,
    review: &Review,
    key: &SigningKey,
) -> Result<(), Box<dyn Error>> {
    let mut manifest: GenesisManifest = review.manifest.clone();
    manifest.signature = key.sign(&review.frames[2]).into();
    let bytes: Vec<u8> = encode_genesis_manifest(&manifest)?;
    let digest: Digest32 = genesis_manifest_commitment(&config.resolver, &manifest)?;
    let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
        &config.resolver,
        &bytes,
        digest.bytes(),
        &config.context,
    )?;
    validate_original_genesis_in_memory(
        &root,
        config.validation_domain,
        config.validation_checkpoint,
        config.timeout_millis,
    )?;
    let published: PublishedGenesis = output.publish(&bytes)?;
    published.ensure_attached()?;
    println!(
        "complete=true mode=protected-author manifest_digest={} genesis_authority={}",
        hex(&digest.bytes()),
        hex(&config.authority)
    );
    io::stdout().flush()?;
    Ok(())
}

async fn exchange(invocation: &Invocation, review: &Review) -> Result<[u8; 32], Box<dyn Error>> {
    let (owner, listener) = local::SocketOwner::bind(&invocation.socket, refused)?;
    let deadline: Duration = Duration::from_secs(REVIEW_SECONDS);
    let (mut stream, _address): (UnixStream, _) =
        tokio::time::timeout(deadline, listener.accept()).await??;
    ipc::authenticate(&stream, invocation.reviewer_uid, refused)?;
    tokio::time::timeout(
        deadline,
        ipc::write_frame(&mut stream, &review.encode()?, refused),
    )
    .await??;
    let received: Vec<u8> =
        tokio::time::timeout(deadline, ipc::read_frame(&mut stream, 32, refused)).await??;
    owner.close()?;
    received.try_into().map_err(|_| refused().into())
}

async fn exchange_revoke(invocation: &Invocation, digest: [u8; 32]) -> Result<(), Box<dyn Error>> {
    let (owner, listener) = local::SocketOwner::bind(&invocation.socket, refused)?;
    let deadline: Duration = Duration::from_secs(REVIEW_SECONDS);
    let (mut stream, _address): (UnixStream, _) =
        tokio::time::timeout(deadline, listener.accept()).await??;
    ipc::authenticate(&stream, invocation.reviewer_uid, refused)?;
    let mut message: Vec<u8> = vec![Phase::Revoke.byte()];
    message.extend_from_slice(&digest);
    tokio::time::timeout(deadline, ipc::write_frame(&mut stream, &message, refused)).await??;
    let received: Vec<u8> =
        tokio::time::timeout(deadline, ipc::read_frame(&mut stream, 32, refused)).await??;
    if received != digest {
        return Err(refused().into());
    }
    owner.close()?;
    Ok(())
}

pub(super) fn worker(tokens: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let invocation: Invocation = Invocation::parse(tokens, true)?;
    let (config, config_digest): (Config, [u8; 32]) = config(&invocation.config_file)?;
    for path in [
        &config.key_file,
        &config.validators_file,
        &config.allocations_file,
        &config.output,
    ] {
        local::absolute(path, refused)?;
    }
    if config.output == invocation.socket
        || config.output == revocation_path(&invocation.state_file)?
    {
        return Err(refused().into());
    }
    let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    if invocation.phase == Phase::Revoke {
        let state: State = State::read(&invocation.state_file)?;
        if state.config_digest != config_digest
            || state.reviewer_uid != invocation.reviewer_uid
            || now()? >= state.expiry
        {
            return Err(refused().into());
        }
        runtime.block_on(exchange_revoke(&invocation, state.draft_digest))?;
        let path: PathBuf = revocation_path(&invocation.state_file)?;
        let mut file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&state.draft_digest)?;
        file.sync_all()?;
        File::open(path.parent().ok_or_else(refused)?)?.sync_all()?;
        return Ok(());
    }
    let (validators, allocations): (Vec<Validator>, Vec<Allocation>) = config.tables()?;
    let draft: Review = Review::build(&config, &validators, &allocations, Phase::Nested, None)?;
    let draft_digest: [u8; 32] = draft.digest()?;
    match invocation.phase {
        Phase::Nested => {
            if fs::symlink_metadata(&invocation.state_file).is_ok()
                || revoked(&invocation.state_file)?
            {
                return Err(refused().into());
            }
            let approval: [u8; 32] = runtime.block_on(exchange(&invocation, &draft))?;
            if approval != draft_digest || now()? >= invocation.expiry {
                return Err(refused().into());
            }
            State {
                config_digest,
                draft_digest,
                expiry: invocation.expiry,
                reviewer_uid: invocation.reviewer_uid,
            }
            .create(&invocation.state_file)?;
            println!(
                "complete=true mode=genesis-nested-review approval_digest={}",
                hex(&draft_digest)
            );
            io::stdout().flush()?;
        }
        Phase::Manifest => {
            let state: State = State::read(&invocation.state_file)?;
            state.live(
                config_digest,
                draft_digest,
                &invocation.state_file,
                invocation.reviewer_uid,
            )?;
            let output: FreshGenesisOutput = FreshGenesisOutput::plan(
                &config.output,
                &[
                    &config.key_file,
                    &config.validators_file,
                    &config.allocations_file,
                    &invocation.config_file,
                    &invocation.state_file,
                ],
            )?;
            let key: SigningKey = expected_key(&config)?;
            let candidate: Review = Review::build(
                &config,
                &validators,
                &allocations,
                Phase::Manifest,
                Some(&key),
            )?;
            let candidate_digest: [u8; 32] = candidate.digest()?;
            let approval: [u8; 32] = runtime.block_on(exchange(&invocation, &candidate))?;
            if approval != candidate_digest {
                return Err(refused().into());
            }
            state.live(
                config_digest,
                draft_digest,
                &invocation.state_file,
                invocation.reviewer_uid,
            )?;
            publish(&config, output, &candidate, &key)?;
        }
        Phase::Revoke => return Err(refused().into()),
    }
    Ok(())
}

fn verify_review(review: &Review, expected_authority: [u8; 32]) -> Result<(), Box<dyn Error>> {
    let manifest: &GenesisManifest = &review.manifest;
    if manifest.genesis_authority != expected_authority || manifest.signature != [0; 64] {
        return Err(refused().into());
    }
    let publication = manifest.publication.request();
    // Recompute exact nested frames from decoded canonical content. The
    // reviewer never approves worker-advertised frame bytes alone.
    let resolver: hashing::HashSuiteResolver = hashing::HashSuiteResolver::new(
        manifest.context().chain_id().clone(),
        manifest.context().protocol_version(),
        review.schedules.clone(),
    )?;
    let publication_frame: Vec<u8> = publication_submission_signing_frame(
        &resolver,
        manifest.context(),
        publication.artifact(),
        publication.nonce(),
        *manifest.publication.request_id(),
    )?;
    let initialization_frame: Vec<u8> =
        local_execution_signing_frame(manifest.context(), &manifest.initialization.intent)?;
    let outer_frame: Vec<u8> = genesis_manifest_signing_frame(manifest)?;
    if review.frames[0] != publication_frame
        || review.frames[1] != initialization_frame
        || (review.phase == Phase::Manifest && review.frames[2] != outer_frame)
        || (review.phase == Phase::Nested && review.frames[2] != outer_frame)
    {
        return Err(refused().into());
    }
    if review.phase == Phase::Nested {
        if publication.signature() != &[0; 64] || manifest.initialization.signature != [0; 64] {
            return Err(refused().into());
        }
    } else {
        let verifier: Ed25519Verifier =
            Ed25519Verifier::from_verifying_key_bytes(&expected_authority)?;
        if !verifier.verify_framed(&publication_frame, publication.signature())?
            || !verifier.verify_framed(&initialization_frame, &manifest.initialization.signature)?
        {
            return Err(refused().into());
        }
    }
    Ok(())
}

pub(super) fn review(tokens: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let values: Vec<OsString> = tokens.into_iter().collect();
    if values.len() != 4 {
        return Err(refused().into());
    }
    let phase: Phase = Phase::parse(values[0].to_str().ok_or_else(refused)?)?;
    let socket: PathBuf = PathBuf::from(&values[1]);
    local::absolute(&socket, refused)?;
    let worker_uid: u32 = values[2].to_str().ok_or_else(refused)?.parse()?;
    if worker_uid == local::own_uid(refused)? {
        return Err(refused().into());
    }
    let authority: [u8; 32] = parse_hex_32(values[3].to_str().ok_or_else(refused)?, "authority")?;
    let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let deadline: Duration = Duration::from_secs(REVIEW_SECONDS);
        let mut stream: UnixStream =
            tokio::time::timeout(deadline, UnixStream::connect(socket)).await??;
        ipc::authenticate(&stream, worker_uid, refused)?;
        let bytes: Vec<u8> =
            tokio::time::timeout(deadline, ipc::read_frame(&mut stream, MAX_REVIEW, refused))
                .await??;
        let digest: [u8; 32] = if phase == Phase::Revoke {
            if bytes.len() != 33 || bytes[0] != Phase::Revoke.byte() {
                return Err(refused().into());
            }
            let digest: [u8; 32] = bytes[1..].try_into().map_err(|_| refused())?;
            println!("revoking_nested_approval_digest={}", hex(&digest));
            digest
        } else {
            let candidate: Review = Review::decode(&bytes, phase)?;
            verify_review(&candidate, authority)?;
            let summary: String = render_review(&candidate.manifest, candidate.manifest.context())?;
            print!("{summary}");
            for (index, entry) in candidate.schedules.iter().enumerate() {
                let suite = &entry.suite;
                println!(
                    "hash_schedule_{index}={}:{}:{}:{}:{}:{}:{}:{}",
                    entry.activation_epoch.get(),
                    suite.id.get(),
                    suite.transaction_hash.as_u16(),
                    suite.object_digest.as_u16(),
                    suite.effects_hash.as_u16(),
                    suite.code_hash.as_u16(),
                    suite.config_hash.as_u16(),
                    suite.certificate_hash.as_u16(),
                );
            }
            println!("publication_signing_frame={}", hex(&candidate.frames[0]));
            println!("initialization_signing_frame={}", hex(&candidate.frames[1]));
            if phase == Phase::Manifest {
                println!("manifest_signing_frame={}", hex(&candidate.frames[2]));
            }
            candidate.digest()?
        };
        println!("review_digest={}", hex(&digest));
        println!(
            "type exactly: {} {}",
            if phase == Phase::Revoke {
                "revoke"
            } else {
                "approve"
            },
            hex(&digest)
        );
        io::stdout().flush()?;
        let mut line: String = String::new();
        io::stdin().lock().take(128).read_line(&mut line)?;
        let expected: String = format!(
            "{} {}",
            if phase == Phase::Revoke {
                "revoke"
            } else {
                "approve"
            },
            hex(&digest)
        );
        if line.trim_end_matches(['\r', '\n']) != expected {
            return Err(refused().into());
        }
        tokio::time::timeout(deadline, ipc::write_frame(&mut stream, &digest, refused)).await??;
        println!(
            "approval_sent=true mode=genesis-{}",
            if phase == Phase::Revoke {
                "revoke"
            } else {
                "review"
            }
        );
        io::stdout().flush()?;
        Ok(())
    })
}
