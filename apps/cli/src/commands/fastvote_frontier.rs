//! Bounded local Freeze recovery, not DrainSet, application, or activation.
//! Each page is saved separately and reverified on resume. A signed vote is
//! provisional until every consecutive page recomputes its complete root.

use super::fastvote_network::{build_frontier_endpoints, parse_deadline, parse_network_config};
use crate::{
    args::{ParsedArgs, parse_flags, scalar},
    error::CliError,
    hex::{decode_hex_32, encode_hex},
    net::{BudgetedTransport, CliTransport, OperationBudget},
    parse::parse_u64,
};
use std::{
    error::Error,
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use sunrise_edge_client::{
    AtomicityDomainId, ChainId, Client, Epoch, FastPathEd25519Verifier, FastVoteEndpoint,
    FrozenFrontierCertifier, FrozenFrontierPage, FrozenFrontierPageRequest,
    FrozenFrontierPageResponse, FrozenFrontierPageVerifier, FrozenFrontierVote, HashSuite,
    HashSuiteResolver, HashSuiteSchedule, MAX_FRONTIER_PAGE_LIMIT,
    MAX_FRONTIER_PAGE_RESPONSE_BYTES, MAX_FRONTIER_VOTE_BYTES, ProtocolVersion, ValidatorId,
    decode_frozen_frontier_page, decode_frozen_frontier_vote, encode_frozen_frontier_page,
    encode_frozen_frontier_vote, load_trusted_fastvote_genesis_with_profile,
    publication::PublicationContext, validate_fastvote_endpoints,
};

fn failure(error: impl Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}
fn invalid(reason: impl Into<String>) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        reason.into(),
    ))
}

struct Inputs {
    endpoint: FastVoteEndpoint<CliTransport>,
    resolver: HashSuiteResolver,
    certifier: FrozenFrontierCertifier,
    context: PublicationContext,
    domain: AtomicityDomainId,
    freeze_request: [u8; 32],
    freeze_height: u64,
    budget: OperationBudget,
}

fn flags(action: &str) -> Vec<crate::args::FlagSpec> {
    let mut specs: Vec<crate::args::FlagSpec> = [
        "--fastvote-network",
        "--fastvote-genesis-manifest",
        "--fastvote-expected-genesis-digest",
        "--expected-chain-id",
        "--expected-protocol-version",
        "--expected-epoch",
        "--expected-domain",
        "--freeze-request-id",
        "--freeze-height",
        "--validator-id",
        "--fastvote-deadline-seconds",
        "--fastvote-per-request-cap-seconds",
    ]
    .into_iter()
    .map(scalar)
    .collect();
    let extra: &[&'static str] = if action == "fastvote-frontier-advance" {
        &["--max-steps", "--vote-out"]
    } else {
        &["--output-dir", "--page-limit", "--max-pages"]
    };
    specs.extend(extra.iter().map(|flag| scalar(flag)));
    specs
}

fn load(parsed: &ParsedArgs) -> Result<Inputs, CliError> {
    let chain: ChainId =
        ChainId::new(parsed.require("--expected-chain-id")?.to_owned()).map_err(failure)?;
    let version: u32 = u32::try_from(parse_u64(
        "--expected-protocol-version",
        parsed.require("--expected-protocol-version")?,
    )?)
    .map_err(|_| invalid("protocol version exceeds u32"))?;
    let context: PublicationContext = PublicationContext::new(
        chain.clone(),
        ProtocolVersion::new(version),
        Epoch::new(parse_u64(
            "--expected-epoch",
            parsed.require("--expected-epoch")?,
        )?),
    )
    .map_err(failure)?;
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain,
        context.protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .map_err(failure)?;
    let digest: [u8; 32] = decode_hex_32(
        "--fastvote-expected-genesis-digest",
        parsed.require("--fastvote-expected-genesis-digest")?,
    )?;
    let trusted = load_trusted_fastvote_genesis_with_profile(
        Path::new(parsed.require("--fastvote-genesis-manifest")?),
        &resolver,
        digest,
        &context,
    )
    .map_err(failure)?;
    if !trusted.commitment_profile.is_logical() || trusted.minimum_freeze_block_height == 0 {
        return Err(invalid(
            "frozen frontier requires locally pinned signed genesis authorizing Freeze",
        ));
    }
    let peers = parse_network_config(parsed.require("--fastvote-network")?)?;
    let mut endpoints: Vec<FastVoteEndpoint<CliTransport>> = build_frontier_endpoints(&peers)?;
    validate_fastvote_endpoints(&endpoints, &trusted.certifier).map_err(failure)?;
    let validator: ValidatorId = ValidatorId::new(decode_hex_32(
        "--validator-id",
        parsed.require("--validator-id")?,
    )?);
    let index: usize = endpoints
        .iter()
        .position(|endpoint| endpoint.validator_id == validator)
        .ok_or_else(|| invalid("--validator-id is not in the locally pinned endpoint cohort"))?;
    let endpoint: FastVoteEndpoint<CliTransport> = endpoints.swap_remove(index);
    let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        context.chain_id().clone(),
        context.protocol_version(),
        context.epoch(),
        trusted.certifier.validator_set().clone(),
    )
    .map_err(failure)?;
    let domain: AtomicityDomainId = AtomicityDomainId::new(decode_hex_32(
        "--expected-domain",
        parsed.require("--expected-domain")?,
    )?)
    .map_err(failure)?;
    let freeze_request: [u8; 32] = decode_hex_32(
        "--freeze-request-id",
        parsed.require("--freeze-request-id")?,
    )?;
    let freeze_height: u64 = parse_u64("--freeze-height", parsed.require("--freeze-height")?)?;
    if freeze_request == [0; 32] || freeze_height < trusted.minimum_freeze_block_height {
        return Err(invalid(
            "Freeze pin must name a nonzero request and an eligible actual block height",
        ));
    }
    Ok(Inputs {
        endpoint,
        resolver,
        certifier,
        context,
        domain,
        freeze_request,
        freeze_height,
        budget: parse_deadline(parsed)?,
    })
}

fn verify_pin(inputs: &Inputs, vote: &FrozenFrontierVote) -> Result<(), CliError> {
    inputs
        .certifier
        .verify_vote(vote, &FastPathEd25519Verifier)
        .map_err(failure)?;
    if vote.validator != inputs.endpoint.validator_id
        || vote.identity.domain != inputs.domain
        || vote.identity.closure_request_id != inputs.freeze_request
        || vote.identity.closure_height != inputs.freeze_height
    {
        return Err(invalid(
            "signed frontier differs from the local endpoint/domain/actual Freeze pin",
        ));
    }
    Ok(())
}

fn limit(
    parsed: &ParsedArgs,
    flag: &'static str,
    default: u64,
    maximum: u64,
) -> Result<u64, CliError> {
    let count: u64 = parsed
        .get(flag)
        .map(|value| parse_u64(flag, value))
        .transpose()?
        .unwrap_or(default);
    if count == 0 || count > maximum {
        return Err(invalid(format!("{flag} must be in 1..={maximum}")));
    }
    Ok(count)
}

/// Retains the original directory handle and publishes synchronized files by
/// no-overwrite hard-link, so a killed write leaves at most a provisional
/// .pending file, never a truncated final vote/page. Existing final bytes are
/// immutable and are independently decoded and verified on every resume.
struct ExportDirectory {
    path: PathBuf,
    handle: File,
}
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl ExportDirectory {
    fn open(path: &Path) -> Result<Self, CliError> {
        std::fs::create_dir_all(path).map_err(failure)?;
        let path: PathBuf = path.canonicalize().map_err(failure)?;
        let handle: File = File::open(&path).map_err(failure)?;
        handle.sync_all().map_err(failure)?;
        Ok(Self { path, handle })
    }
    fn ensure_attached(&self) -> Result<(), CliError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let actual: std::fs::Metadata = std::fs::metadata(&self.path).map_err(failure)?;
            let held: std::fs::Metadata = self.handle.metadata().map_err(failure)?;
            if (actual.dev(), actual.ino()) != (held.dev(), held.ino()) {
                return Err(invalid("export directory was replaced"));
            }
        }
        Ok(())
    }
    fn read(&self, name: &str, maximum: usize) -> Result<Option<Vec<u8>>, CliError> {
        self.ensure_attached()?;
        let path: PathBuf = self.path.join(name);
        let metadata: std::fs::Metadata = match std::fs::symlink_metadata(&path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(failure(error)),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid("export artifact is not a regular immutable file"));
        }
        let bound: u64 = u64::try_from(maximum)
            .map_err(|_| invalid("artifact bound exceeds u64"))?
            .checked_add(1)
            .ok_or_else(|| invalid("artifact bound overflow"))?;
        let mut bytes: Vec<u8> = Vec::new();
        File::open(&path)
            .map_err(failure)?
            .take(bound)
            .read_to_end(&mut bytes)
            .map_err(failure)?;
        if bytes.len() > maximum {
            return Err(invalid("export artifact exceeds its canonical frame bound"));
        }
        self.ensure_attached()?;
        Ok(Some(bytes))
    }
    fn persist(&self, name: &str, bytes: &[u8], maximum: usize) -> Result<(), CliError> {
        if bytes.len() > maximum {
            return Err(invalid("export artifact exceeds its frame bound"));
        }
        if let Some(existing) = self.read(name, maximum)? {
            return if existing == bytes {
                Ok(())
            } else {
                Err(invalid(
                    "existing export artifact differs; refusing overwrite",
                ))
            };
        }
        self.ensure_attached()?;
        let sequence: u64 = TEMP_COUNTER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| invalid("export temporary sequence exhausted"))?;
        let pending: PathBuf = self
            .path
            .join(format!(".pending-{}-{sequence}-{name}", std::process::id()));
        let mut file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)
            .map_err(failure)?;
        file.write_all(bytes).map_err(failure)?;
        file.sync_all().map_err(failure)?;
        self.ensure_attached()?;
        match std::fs::hard_link(&pending, self.path.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if self.read(name, maximum)?.as_deref() != Some(bytes) {
                    return Err(invalid("concurrent export differs; refusing overwrite"));
                }
            }
            Err(error) => return Err(failure(error)),
        }
        self.handle.sync_all().map_err(failure)?;
        std::fs::remove_file(&pending).map_err(failure)?;
        self.handle.sync_all().map_err(failure)?;
        self.ensure_attached()
    }
}

fn advance(parsed: &ParsedArgs, inputs: &Inputs) -> Result<(), CliError> {
    let maximum: u64 = limit(parsed, "--max-steps", 128, 4096)?;
    let client = Client::new(BudgetedTransport {
        inner: inputs.endpoint.client.transport(),
        budget: Some(inputs.budget),
    });
    for _ in 0..maximum {
        inputs.budget.ensure_live().map_err(failure)?;
        if let Some(vote) = client
            .advance_frozen_frontier(
                &inputs.certifier,
                inputs.endpoint.validator_id,
                Some(inputs.budget.deadline),
            )
            .map_err(failure)?
        {
            verify_pin(inputs, &vote)?;
            if let Some(path) = parsed.get("--vote-out") {
                let supplied: &Path = Path::new(path);
                let parent: &Path = supplied
                    .parent()
                    .filter(|value| !value.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                let name: &str = supplied
                    .file_name()
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| invalid("--vote-out requires a UTF-8 filename"))?;
                ExportDirectory::open(parent)?.persist(
                    name,
                    &encode_frozen_frontier_vote(&vote).map_err(failure)?,
                    MAX_FRONTIER_VOTE_BYTES,
                )?;
            }
            println!(
                "frontier=finalized entry_count={} validator_id={}",
                vote.identity.entry_count,
                encode_hex(vote.validator.as_bytes())
            );
            return Ok(());
        }
    }
    println!("frontier=partial steps={maximum}");
    Ok(())
}

fn decode_response(
    bytes: &[u8],
) -> Result<(Vec<u8>, FrozenFrontierVote, FrozenFrontierPage), CliError> {
    let envelope: FrozenFrontierPageResponse =
        FrozenFrontierPageResponse::decode(bytes).map_err(failure)?;
    let vote: FrozenFrontierVote = decode_frozen_frontier_vote(&envelope.vote).map_err(failure)?;
    let page: FrozenFrontierPage = decode_frozen_frontier_page(&envelope.page).map_err(failure)?;
    Ok((envelope.vote, vote, page))
}

fn export(parsed: &ParsedArgs, inputs: &Inputs) -> Result<(), CliError> {
    let maximum: u64 = limit(parsed, "--max-pages", 128, 4096)?;
    let page_limit: u16 = u16::try_from(limit(
        parsed,
        "--page-limit",
        u64::from(MAX_FRONTIER_PAGE_LIMIT),
        u64::from(MAX_FRONTIER_PAGE_LIMIT),
    )?)
    .map_err(|_| invalid("page limit exceeds u16"))?;
    let directory: ExportDirectory =
        ExportDirectory::open(Path::new(parsed.require("--output-dir")?))?;
    let client = Client::new(BudgetedTransport {
        inner: inputs.endpoint.client.transport(),
        budget: Some(inputs.budget),
    });
    let mut vote_bytes: Option<Vec<u8>> =
        directory.read("frontier.vote", MAX_FRONTIER_VOTE_BYTES)?;
    let mut verifier: Option<FrozenFrontierPageVerifier> = match &vote_bytes {
        Some(bytes) => {
            let vote: FrozenFrontierVote = decode_frozen_frontier_vote(bytes).map_err(failure)?;
            verify_pin(inputs, &vote)?;
            Some(
                FrozenFrontierPageVerifier::new(
                    &inputs.resolver,
                    &inputs.certifier,
                    vote,
                    &FastPathEd25519Verifier,
                )
                .map_err(failure)?,
            )
        }
        None => None,
    };
    let mut index: u64 = 0;
    let mut fetched: u64 = 0;
    let mut cursor: Option<[u8; 32]> = None;
    loop {
        inputs.budget.ensure_live().map_err(failure)?;
        let name: String = format!("page-{index:020}.response");
        let saved: Option<Vec<u8>> = directory.read(&name, MAX_FRONTIER_PAGE_RESPONSE_BYTES)?;
        let bytes: Vec<u8> = match saved {
            Some(bytes) => bytes,
            None => {
                if fetched == maximum {
                    if directory
                        .read("complete", MAX_FRONTIER_VOTE_BYTES)?
                        .is_some()
                    {
                        return Err(invalid("completion marker lacks its complete page stream"));
                    }
                    println!("frontier=partial next_page={index} new_pages={fetched}");
                    return Ok(());
                }
                let request: FrozenFrontierPageRequest = FrozenFrontierPageRequest {
                    epoch: inputs.context.epoch(),
                    after_request_id: cursor,
                    limit: page_limit,
                };
                let (vote, page) = client
                    .fetch_signed_frozen_frontier_page(
                        &request,
                        &inputs.certifier,
                        inputs.endpoint.validator_id,
                        Some(inputs.budget.deadline),
                    )
                    .map_err(failure)?;
                verify_pin(inputs, &vote)?;
                fetched = fetched
                    .checked_add(1)
                    .ok_or_else(|| invalid("page counter overflow"))?;
                FrozenFrontierPageResponse {
                    vote: encode_frozen_frontier_vote(&vote).map_err(failure)?,
                    page: encode_frozen_frontier_page(&page).map_err(failure)?,
                }
                .encode()
                .map_err(failure)?
            }
        };
        let (page_vote_bytes, page_vote, page) = decode_response(&bytes)?;
        verify_pin(inputs, &page_vote)?;
        if let Some(retained) = &vote_bytes {
            if retained != &page_vote_bytes {
                return Err(invalid("frontier vote changed across pages or restart"));
            }
        } else {
            verifier = Some(
                FrozenFrontierPageVerifier::new(
                    &inputs.resolver,
                    &inputs.certifier,
                    page_vote,
                    &FastPathEd25519Verifier,
                )
                .map_err(failure)?,
            );
            directory.persist("frontier.vote", &page_vote_bytes, MAX_FRONTIER_VOTE_BYTES)?;
            vote_bytes = Some(page_vote_bytes);
        }
        let active: &mut FrozenFrontierPageVerifier = verifier
            .as_mut()
            .ok_or_else(|| invalid("missing frontier verifier"))?;
        active.push_page(&inputs.resolver, &page).map_err(failure)?;
        directory.persist(&name, &bytes, MAX_FRONTIER_PAGE_RESPONSE_BYTES)?;
        index = index
            .checked_add(1)
            .ok_or_else(|| invalid("page index overflow"))?;
        if page.terminal {
            if directory
                .read(
                    &format!("page-{index:020}.response"),
                    MAX_FRONTIER_PAGE_RESPONSE_BYTES,
                )?
                .is_some()
            {
                return Err(invalid("saved page follows the terminal page"));
            }
            let verified: FrozenFrontierVote = verifier
                .take()
                .ok_or_else(|| invalid("missing complete frontier verifier"))?
                .finish()
                .map_err(failure)?;
            let exact: Vec<u8> = encode_frozen_frontier_vote(&verified).map_err(failure)?;
            directory.persist("complete", &exact, MAX_FRONTIER_VOTE_BYTES)?;
            println!(
                "frontier=complete entry_count={} pages={index} new_pages={fetched}",
                verified.identity.entry_count
            );
            return Ok(());
        }
        cursor = page.entries.last().map(|entry| entry.request_id);
    }
}

pub(super) fn run<I: IntoIterator<Item = OsString>>(action: &str, args: I) -> Result<(), CliError> {
    let parsed: ParsedArgs = parse_flags(args, &flags(action))?;
    let inputs: Inputs = load(&parsed)?;
    if action == "fastvote-frontier-advance" {
        advance(&parsed, &inputs)
    } else {
        export(&parsed, &inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_saved_artifacts_survive_restart_and_refuse_overwrite() {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-frontier-cli-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let directory: ExportDirectory = ExportDirectory::open(&path).unwrap();
        directory.persist("frontier.vote", &[1, 2, 3], 16).unwrap();
        drop(directory);
        let reopened: ExportDirectory = ExportDirectory::open(&path).unwrap();
        assert_eq!(
            reopened.read("frontier.vote", 16).unwrap(),
            Some(vec![1, 2, 3])
        );
        reopened.persist("frontier.vote", &[1, 2, 3], 16).unwrap();
        assert!(reopened.persist("frontier.vote", &[4, 5, 6], 16).is_err());
        assert!(reopened.read("frontier.vote", 2).is_err());
        assert_eq!(reopened.read("complete", 16).unwrap(), None);
        std::fs::remove_file(path.join("frontier.vote")).unwrap();
        std::fs::remove_dir(path).unwrap();
    }
}
