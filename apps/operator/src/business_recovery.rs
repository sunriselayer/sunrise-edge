//! Opt-in LOCAL encrypted saved closure. This never opens a SQL destination,
//! network transport, signer or activation owner. Imported proof authority is
//! still created only by the existing node-core factories (DR-0221).
#![forbid(unsafe_code)]

mod envelope;
mod files;
#[cfg(test)]
mod tests;
mod transport;

use crate::{
    business_pins::{BusinessPinInputs, BusinessPins, private_operation},
    common::{FlagSet, parse_hex_32},
    successor_artifacts::{CHAIN_FLAGS, SuccessorChainInputs},
};
use envelope::{Manifest, Role};
use files::{AbsentOutput, CipherPublication, PrivateStage, SourceRole};
use node_core::{
    business_reconstruction::{
        BusinessReconstructionPlan,
        cut::SavedBusinessCut,
        inactive_import::{
            VerifiedImportPlan, verify_saved_business_import, verify_saved_business_import_chain,
        },
    },
    serving_authority::SuccessorChainBudget,
};
use std::{
    error::Error,
    ffi::OsString,
    fmt,
    io::Write,
    num::NonZeroU32,
    path::{Path, PathBuf},
    time::Duration,
};
use sunrise_edge_client::{
    business_cut_archive::read_business_cut_archive,
    immutable_archive::{
        ArchiveReadBudget, ArchiveReadLimits, AttachedFilePolicy, AttachedRegularFile,
        ImmutableArchiveReader,
    },
    successor_artifacts::SuccessorChainArtifactFiles,
};
use transport::{CipherPhase, CipherReader, CipherWriter, LoadedIdentity, PlainReader};

/// Fieldless errors deliberately retain no provider/IO/age text, secret buffer
/// or source chain. Debug is as opaque as Display, including in test failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    InvalidInput,
    Quota,
    Inventory,
    Transport,
    Attachment,
    Proof,
    Publication,
    Unsupported,
}
impl RecoveryError {
    fn message(self) -> &'static str {
        match self {
            Self::InvalidInput => "recovery invalid input",
            Self::Quota => "recovery quota refused",
            Self::Inventory => "recovery inventory refused",
            Self::Transport => "recovery transport refused",
            Self::Attachment => "recovery attachment refused",
            Self::Proof => "recovery proof refused",
            Self::Publication => "recovery publication refused",
            Self::Unsupported => "recovery platform unsupported",
        }
    }
}
impl fmt::Display for RecoveryError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(self.message())
    }
}
impl fmt::Debug for RecoveryError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(self.message())
    }
}
impl Error for RecoveryError {}

#[derive(Clone)]
struct RecoveryLimits {
    files: usize,
    observations: u64,
    heights: u64,
    components: u64,
    file_bytes: u64,
    control_bytes: u64,
    plaintext_bytes: u64,
    ciphertext_bytes: u64,
    header_bytes: u64,
    timeout: Duration,
}
impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            files: 32768,
            observations: ArchiveReadLimits::default().observations,
            heights: 4096,
            components: 32768,
            file_bytes: 32 * 1024 * 1024,
            control_bytes: 4 * 1024 * 1024,
            plaintext_bytes: 256 * 1024 * 1024,
            ciphertext_bytes: 272 * 1024 * 1024,
            header_bytes: 64 * 1024,
            timeout: Duration::from_secs(300),
        }
    }
}
impl RecoveryLimits {
    fn parse(flags: &mut FlagSet) -> Result<Self, RecoveryError> {
        let mut value: Self = Self::default();
        value.files = usize::try_from(downward(flags, "--max-files", value.files as u64)?)
            .map_err(|_| RecoveryError::InvalidInput)?;
        value.observations = downward(flags, "--max-observations", value.observations)?;
        value.heights = downward(flags, "--max-heights", value.heights)?;
        value.components = downward(flags, "--max-components", value.components)?;
        value.file_bytes = downward(flags, "--max-file-bytes", value.file_bytes)?;
        value.control_bytes = downward(flags, "--max-control-bytes", value.control_bytes)?;
        value.plaintext_bytes = downward(flags, "--max-plaintext-bytes", value.plaintext_bytes)?;
        value.ciphertext_bytes = downward(flags, "--max-ciphertext-bytes", value.ciphertext_bytes)?;
        value.header_bytes =
            downward(flags, "--max-header-bytes", value.header_bytes)?.min(value.ciphertext_bytes);
        value.timeout = Duration::from_secs(downward(flags, "--timeout-seconds", 300)?);
        Ok(value)
    }
    fn budget(&self) -> Result<ArchiveReadBudget, RecoveryError> {
        ArchiveReadBudget::new(ArchiveReadLimits {
            observations: self.observations,
            heights: self.heights,
            components: self.components,
            file_bytes: self.file_bytes,
            deadline: self.timeout,
        })
        .map_err(|_| RecoveryError::Quota)
    }
}
fn downward(flags: &mut FlagSet, name: &str, maximum: u64) -> Result<u64, RecoveryError> {
    let Some(raw) = flags
        .optional_one(name)
        .map_err(|_| RecoveryError::InvalidInput)?
    else {
        return Ok(maximum);
    };
    let value: u64 = raw.parse().map_err(|_| RecoveryError::InvalidInput)?;
    if value == 0 || value > maximum {
        return Err(RecoveryError::InvalidInput);
    }
    Ok(value)
}

const TRUST: &[&str] = &[
    "--chain-id",
    "--protocol-version",
    "--epoch",
    "--domain",
    "--suite",
    "--expected-genesis-digest",
    "--expected-cut-digest",
    "--expected-package-digest",
    "--recipient",
    "--expected-links",
];
const LIMITS: &[&str] = &[
    "--max-files",
    "--max-observations",
    "--max-heights",
    "--max-components",
    "--max-file-bytes",
    "--max-control-bytes",
    "--max-plaintext-bytes",
    "--max-ciphertext-bytes",
    "--max-header-bytes",
    "--timeout-seconds",
];
const HELP: &str = "LOCAL encrypted saved business closure only; no SQL installation, signing or activation. Modes: pack-saved | open-saved. Require independently configured --chain-id --protocol-version --epoch --domain --suite --expected-genesis-digest --expected-cut-digest --expected-package-digest --recipient (one public age X25519 recipient) --expected-links 0..16. Pack requires --genesis-manifest --ordered-history-dir --cut-dir --capture-root --ciphertext-out; predecessor roles use the existing complete repeated successor flags and explicit --successor-max-links. Open requires only --ciphertext-file --identity-file --out-dir and public trust pins; nonzero links additionally require --successor-max-links. No key line, SQL path, endpoint, plugins, armor, passphrase or fallback is accepted. Output paths must be absent, private and outside all input roles. Optional downward limits: --max-files --max-observations --max-heights --max-components --max-file-bytes --max-control-bytes --max-plaintext-bytes --max-ciphertext-bytes --max-header-bytes --timeout-seconds (1..300). Failure leaves unqualified owned residue; no automatic retry/adoption/cleanup. Completion diagnostic is never proof authority; create/resume independently reverify.";

struct PublicPins {
    cut: [u8; 32],
    package: [u8; 32],
}
struct Request {
    pins: BusinessPinInputs,
    chain: Option<SuccessorChainInputs>,
    chain_budget: Option<SuccessorChainBudget>,
    public: PublicPins,
    recipient: age::x25519::Recipient,
    links: u16,
    limits: RecoveryLimits,
    mode: Mode,
}
enum Mode {
    Pack {
        cut: PathBuf,
        capture: PathBuf,
        cipher: PathBuf,
    },
    Open {
        cipher: PathBuf,
        identity: PathBuf,
        output: PathBuf,
    },
}

impl Request {
    fn parse(mut values: Vec<OsString>) -> Result<Self, RecoveryError> {
        if values.is_empty() {
            return Err(RecoveryError::InvalidInput);
        }
        let packing: bool = match values.remove(0).to_str() {
            Some("pack-saved") => true,
            Some("open-saved") => false,
            _ => return Err(RecoveryError::InvalidInput),
        };
        let mut accepted: Vec<&'static str> = TRUST.to_vec();
        accepted.extend_from_slice(LIMITS);
        if packing {
            accepted.extend_from_slice(&[
                "--genesis-manifest",
                "--ordered-history-dir",
                "--cut-dir",
                "--capture-root",
                "--ciphertext-out",
            ]);
            accepted.extend_from_slice(CHAIN_FLAGS);
        } else {
            accepted.extend_from_slice(&[
                "--ciphertext-file",
                "--identity-file",
                "--out-dir",
                "--successor-max-links",
            ]);
        }
        let mut flags: FlagSet =
            FlagSet::parse(values, &accepted, &[]).map_err(|_| RecoveryError::InvalidInput)?;
        let links: u16 = flags
            .one("--expected-links")
            .map_err(|_| RecoveryError::InvalidInput)?
            .parse()
            .map_err(|_| RecoveryError::InvalidInput)?;
        if links > 16 {
            return Err(RecoveryError::InvalidInput);
        }
        let recipient: age::x25519::Recipient = transport::parse_recipient(
            &flags
                .one("--recipient")
                .map_err(|_| RecoveryError::InvalidInput)?,
        )?;
        let public: PublicPins = PublicPins {
            cut: parse_hex_32(
                &flags
                    .one("--expected-cut-digest")
                    .map_err(|_| RecoveryError::InvalidInput)?,
                "cut",
            )
            .map_err(|_| RecoveryError::InvalidInput)?,
            package: parse_hex_32(
                &flags
                    .one("--expected-package-digest")
                    .map_err(|_| RecoveryError::InvalidInput)?,
                "package",
            )
            .map_err(|_| RecoveryError::InvalidInput)?,
        };
        let limits: RecoveryLimits = RecoveryLimits::parse(&mut flags)?;
        let (pins, chain, chain_budget, mode) = if packing {
            let chain: Option<SuccessorChainInputs> =
                SuccessorChainInputs::parse_optional(&mut flags)
                    .map_err(|_| RecoveryError::InvalidInput)?;
            if chain
                .as_ref()
                .map_or(0, |value: &SuccessorChainInputs| value.links().len())
                != usize::from(links)
            {
                return Err(RecoveryError::InvalidInput);
            }
            let chain_budget: Option<SuccessorChainBudget> = chain
                .as_ref()
                .map(|value: &SuccessorChainInputs| value.budget);
            let pins: BusinessPinInputs =
                BusinessPinInputs::parse(&mut flags).map_err(|_| RecoveryError::InvalidInput)?;
            let mode: Mode = Mode::Pack {
                cut: flags
                    .one("--cut-dir")
                    .map_err(|_| RecoveryError::InvalidInput)?
                    .into(),
                capture: flags
                    .one("--capture-root")
                    .map_err(|_| RecoveryError::InvalidInput)?
                    .into(),
                cipher: flags
                    .one("--ciphertext-out")
                    .map_err(|_| RecoveryError::InvalidInput)?
                    .into(),
            };
            (pins, chain, chain_budget, mode)
        } else {
            let output: PathBuf = flags
                .one("--out-dir")
                .map_err(|_| RecoveryError::InvalidInput)?
                .into();
            let maximum: Option<String> = flags
                .optional_one("--successor-max-links")
                .map_err(|_| RecoveryError::InvalidInput)?;
            let chain_budget: Option<SuccessorChainBudget> = match (links, maximum) {
                (0, None) => None,
                (1..=16, Some(value)) => {
                    let number: u32 = value.parse().map_err(|_| RecoveryError::InvalidInput)?;
                    if number < u32::from(links) || number > 16 {
                        return Err(RecoveryError::InvalidInput);
                    }
                    Some(SuccessorChainBudget::new(
                        NonZeroU32::new(number).ok_or(RecoveryError::InvalidInput)?,
                    ))
                }
                _ => return Err(RecoveryError::InvalidInput),
            };
            let pins: BusinessPinInputs = BusinessPinInputs::parse_saved(
                &mut flags,
                output.join("genesis/genesis.bin"),
                output.join("current/history"),
            )
            .map_err(|_| RecoveryError::InvalidInput)?;
            let mode: Mode = Mode::Open {
                cipher: flags
                    .one("--ciphertext-file")
                    .map_err(|_| RecoveryError::InvalidInput)?
                    .into(),
                identity: flags
                    .one("--identity-file")
                    .map_err(|_| RecoveryError::InvalidInput)?
                    .into(),
                output,
            };
            (pins, None, chain_budget, mode)
        };
        flags.finish().map_err(|_| RecoveryError::InvalidInput)?;
        Ok(Self {
            pins,
            chain,
            chain_budget,
            public,
            recipient,
            links,
            limits,
            mode,
        })
    }
}

pub fn run(values: impl IntoIterator<Item = OsString>) -> Result<(), RecoveryError> {
    let mut arguments: Vec<OsString> = Vec::new();
    for value in values {
        if arguments.len() >= 384 {
            return Err(RecoveryError::InvalidInput);
        }
        arguments.push(value);
    }
    if arguments.as_slice() == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    let request: Request = Request::parse(arguments)?;
    // This precedes EVERY SDK root/leaf constructor, including destination
    // parents, repeated staged-role verification and capture inventories.
    let budget: ArchiveReadBudget = request.limits.budget()?;
    budget
        .check_roles(usize::from(3 + 4 * request.links))
        .map_err(|_| RecoveryError::Quota)?;
    let result: Result<(), RecoveryError> = if matches!(&request.mode, Mode::Pack { .. }) {
        pack(request, &budget)
    } else {
        open(request, &budget)
    };
    result.map_err(|error: RecoveryError| classify_failure(error, &budget))
}

fn classify_failure(error: RecoveryError, budget: &ArchiveReadBudget) -> RecoveryError {
    // Filesystem/decoder adapters intentionally discard secret-bearing IO
    // text. A refused ORIGINAL budget must not masquerade as file detachment.
    if budget.check().is_err() {
        RecoveryError::Quota
    } else {
        error
    }
}

struct Verification<'a> {
    pins: BusinessPinInputs,
    chain_budget: Option<SuccessorChainBudget>,
    public: &'a PublicPins,
    stage: &'a Path,
    links: u16,
    budget: &'a ArchiveReadBudget,
}
fn verify(value: Verification<'_>) -> Result<runtime::ImportBinding, RecoveryError> {
    value.budget.check().map_err(|_| RecoveryError::Quota)?;
    let pins: BusinessPinInputs = value.pins.with_saved_paths(
        value.stage.join("genesis/genesis.bin"),
        value.stage.join("current/history"),
    );
    let pins: BusinessPins = if let Some(chain_budget) = value.chain_budget {
        let inputs: SuccessorChainInputs =
            SuccessorChainInputs::saved(value.stage, usize::from(value.links), chain_budget)
                .map_err(|_| RecoveryError::Proof)?;
        let mut artifacts: SuccessorChainArtifactFiles = inputs
            .open_bounded(value.budget)
            .map_err(|_| RecoveryError::Proof)?;
        pins.load_with_successor_bounded(&mut artifacts, chain_budget, value.budget)
            .map_err(|_| RecoveryError::Proof)?
    } else {
        if value.links != 0 {
            return Err(RecoveryError::Proof);
        }
        pins.load_bounded(value.budget)
            .map_err(|_| RecoveryError::Proof)?
    };
    let archive: ImmutableArchiveReader =
        ImmutableArchiveReader::open_bounded(&value.stage.join("current/cut"), value.budget)
            .map_err(|_| RecoveryError::Proof)?;
    let plan: BusinessReconstructionPlan<'_> =
        pins.plan(private_operation().map_err(|_| RecoveryError::Proof)?);
    let saved: SavedBusinessCut =
        read_business_cut_archive(&plan, &archive).map_err(|_| RecoveryError::Proof)?;
    let verified: VerifiedImportPlan = match pins.successor_authority() {
        Some(authority) => {
            verify_saved_business_import_chain(plan, authority, pins.cut_identity(), &saved)
        }
        None => verify_saved_business_import(plan, &saved),
    }
    .map_err(|_| RecoveryError::Proof)?;
    value.budget.check().map_err(|_| RecoveryError::Quota)?;
    if verified.binding().cut_digest.bytes() != value.public.cut
        || verified.binding().package_digest.bytes() != value.public.package
    {
        return Err(RecoveryError::Proof);
    }
    Ok(verified.binding().clone())
}

// Printable public counts only; this is not a proof or import capability.
struct PackedDiagnosticCounts {
    links: u16,
    files: usize,
}

fn finish_pack_publication(
    finished: Result<(u64, [u8; 32]), RecoveryError>,
    stage: &mut PrivateStage,
    publication: CipherPublication,
    manifest: &Manifest,
    footer: &[u8; 49],
    maximum: u64,
    budget: &ArchiveReadBudget,
) -> Result<PackedDiagnosticCounts, RecoveryError> {
    let (length, hash): (u64, [u8; 32]) = finished?;
    stage.check(manifest)?;
    publication.publish(length, hash, maximum)?;
    stage.complete(manifest, footer)?;
    budget.check().map_err(|_| RecoveryError::Quota)?;
    Ok(PackedDiagnosticCounts {
        // capture forwards the request's links unchanged to Manifest::encode.
        links: manifest.links,
        files: manifest.entries.len(),
    })
}

fn pack(request: Request, budget: &ArchiveReadBudget) -> Result<(), RecoveryError> {
    let Request {
        pins,
        chain,
        chain_budget,
        public,
        recipient,
        links,
        limits,
        mode,
    } = request;
    let Mode::Pack {
        cut,
        capture,
        cipher,
    } = mode
    else {
        return Err(RecoveryError::InvalidInput);
    };
    let mut sources: Vec<SourceRole> = Vec::with_capacity(usize::from(3 + 4 * links));
    sources.push(SourceRole::genesis(pins.genesis_file(), budget)?);
    sources.push(SourceRole::archive(
        Role {
            tag: 2,
            link: u16::MAX,
        },
        pins.history_root(),
        budget,
    )?);
    sources.push(SourceRole::archive(
        Role {
            tag: 3,
            link: u16::MAX,
        },
        &cut,
        budget,
    )?);
    for tag in 4..=7 {
        if let Some(chain) = &chain {
            for (index, paths) in chain.links().iter().enumerate() {
                let path: &Path = match tag {
                    4 => &paths.0,
                    5 => &paths.1,
                    6 => &paths.2,
                    7 => &paths.3,
                    _ => return Err(RecoveryError::InvalidInput),
                };
                sources.push(SourceRole::archive(
                    Role {
                        tag,
                        link: u16::try_from(index).map_err(|_| RecoveryError::Quota)?,
                    },
                    path,
                    budget,
                )?);
            }
        }
    }
    let capture: AbsentOutput = AbsentOutput::new(&capture, budget)?;
    let cipher: AbsentOutput = AbsentOutput::new(&cipher, budget)?;
    let pending: AbsentOutput =
        AbsentOutput::new(&CipherPublication::pending_path(cipher.path())?, budget)?;
    files::distinct(&capture, &cipher)?;
    files::distinct(&capture, &pending)?;
    for source in &sources {
        for output in [&capture, &cipher, &pending] {
            source.outside(output)?;
        }
    }
    capture.headroom(budget)?;
    cipher.headroom(budget)?;
    let mut stage: PrivateStage = PrivateStage::create(&capture, budget)?;
    let manifest: Manifest = stage.capture(&sources, links, &limits)?;
    stage.check(&manifest)?;
    let _binding: runtime::ImportBinding = verify(Verification {
        pins,
        chain_budget,
        public: &public,
        stage: stage.root(),
        links,
        budget,
    })?;
    stage.check(&manifest)?;
    // No source file is reopened for encryption: only the SAME full-stamped,
    // hash-bound private stage which passed the existing proof factories.
    let mut publication: CipherPublication = CipherPublication::create(cipher, budget)?;
    let counted: CipherWriter<'_, &mut std::fs::File> =
        CipherWriter::new(publication.writer(), budget, limits.ciphertext_bytes);
    let mut encrypted: age::stream::StreamWriter<CipherWriter<'_, &mut std::fs::File>> =
        transport::encryptor(&recipient)?
            .wrap_output(counted)
            .map_err(|_| RecoveryError::Transport)?;
    manifest.write_prefix(&mut encrypted)?;
    for (index, entry) in manifest.entries.iter().enumerate() {
        encrypted
            .write_all(&envelope::file_header(index, entry)?)
            .map_err(|_| RecoveryError::Transport)?;
        stage.write_body(&mut encrypted, entry)?;
    }
    let footer: [u8; 49] = manifest.footer()?;
    encrypted
        .write_all(&footer)
        .map_err(|_| RecoveryError::Transport)?;
    // Consume the successful writer observation before moving publication;
    // an actual age finish error carries no writer borrow or provider error.
    let finished: Result<(u64, [u8; 32]), RecoveryError> = encrypted
        .finish()
        .map(|counted: CipherWriter<'_, &mut std::fs::File>| counted.observation())
        .map_err(|_| RecoveryError::Transport);
    let counts: PackedDiagnosticCounts = finish_pack_publication(
        finished,
        &mut stage,
        publication,
        &manifest,
        &footer,
        limits.ciphertext_bytes,
        budget,
    )?;
    println!(
        "business_recovery=packed links={} files={} meaning=local-encrypted-saved-closure-not-import-or-custody",
        counts.links, counts.files
    );
    Ok(())
}

fn open(request: Request, budget: &ArchiveReadBudget) -> Result<(), RecoveryError> {
    let Request {
        pins,
        chain: _,
        chain_budget,
        public,
        recipient,
        links,
        limits,
        mode,
    } = request;
    let Mode::Open {
        cipher: cipher_path,
        identity: identity_path,
        output,
    } = mode
    else {
        return Err(RecoveryError::InvalidInput);
    };
    let output: AbsentOutput = AbsentOutput::new(&output, budget)?;
    let cipher_path: PathBuf = input_placement(&cipher_path, &output, budget)?;
    let identity_path: PathBuf = input_placement(&identity_path, &output, budget)?;
    if cipher_path == identity_path {
        return Err(RecoveryError::InvalidInput);
    }
    let identity: LoadedIdentity = transport::read_identity(&identity_path, &recipient, budget)?;
    let input: AttachedRegularFile = AttachedRegularFile::open(
        &cipher_path,
        limits.ciphertext_bytes,
        budget,
        AttachedFilePolicy::public(),
    )
    .map_err(|_| RecoveryError::Attachment)?;
    let physical_length: u64 = input.stamp().length;
    output.headroom(budget)?;
    let phase: CipherPhase = CipherPhase::header();
    let mut cipher: CipherReader<'_, AttachedRegularFile> =
        CipherReader::new(input, &phase, budget, &limits);
    let mut stage: PrivateStage = PrivateStage::create(&output, budget)?;
    let manifest: Manifest;
    let footer: [u8; 49];
    {
        let decrypted: age::stream::StreamReader<&mut CipherReader<'_, AttachedRegularFile>> =
            transport::decrypt(&mut cipher, &phase, &identity.identity)?;
        let mut plain: PlainReader<
            '_,
            age::stream::StreamReader<&mut CipherReader<'_, AttachedRegularFile>>,
        > = PlainReader::new(decrypted, limits.plaintext_bytes, budget);
        (manifest, footer) = envelope::receive(&mut plain, &mut stage, links, &limits)?;
        if plain.observed() != manifest.plaintext {
            return Err(RecoveryError::Inventory);
        }
        // NONEMPTY read requests successful final age authentication, even at
        // the exact plaintext cap. Dropping the reader is never completion.
        plain.authenticated_eof()?;
    }
    cipher.physical_eof()?; // Later explicit SAME held physical cursor probe.
    if cipher.observed() != physical_length || cipher.inner.observed_bytes() != physical_length {
        return Err(RecoveryError::Transport);
    }
    cipher
        .inner
        .ensure_attached()
        .map_err(|_| RecoveryError::Attachment)?;
    identity.ensure_attached()?;
    stage.check(&manifest)?;
    let _binding: runtime::ImportBinding = verify(Verification {
        pins,
        chain_budget,
        public: &public,
        stage: stage.root(),
        links,
        budget,
    })?;
    stage.check(&manifest)?;
    cipher
        .inner
        .ensure_attached()
        .map_err(|_| RecoveryError::Attachment)?;
    identity.ensure_attached()?;
    budget.check().map_err(|_| RecoveryError::Quota)?;
    stage.complete(&manifest, &footer)?;
    println!(
        "business_recovery=opened links={} files={} meaning=verified-saved-closure-inactive-import-still-separate",
        links,
        manifest.entries.len()
    );
    Ok(())
}

fn input_placement(
    path: &Path,
    output: &AbsentOutput,
    budget: &ArchiveReadBudget,
) -> Result<PathBuf, RecoveryError> {
    let name = path.file_name().ok_or(RecoveryError::InvalidInput)?;
    let parent: ImmutableArchiveReader = ImmutableArchiveReader::open_bounded(
        path.parent()
            .filter(|value: &&Path| !value.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
        budget,
    )
    .map_err(|_| RecoveryError::Attachment)?;
    let absolute: PathBuf = parent.root().join(name);
    if absolute.starts_with(output.path()) || output.path() == absolute {
        return Err(RecoveryError::InvalidInput);
    }
    output.check()?;
    parent
        .ensure_attached()
        .map_err(|_| RecoveryError::Attachment)?;
    Ok(absolute)
}
