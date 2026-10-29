//! Same-layout selected local-store continuation, with existing authority kept
//! outside the encrypted archive. This does not create public proof authority.
use super::*;
use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
use runtime_sqlite::{
    ConfiguredCheckpointAuthority, LocalSnapshotLimits, LocalStoreCheckpoint, SqliteDurableStore,
    SqliteNamespace,
};
use std::time::{SystemTime, UNIX_EPOCH};
mod envelope;
#[cfg(all(test, target_os = "linux"))]
mod tests;

struct Request {
    namespace: SqliteNamespace,
    anchor: PathBuf,
    recipient: age::x25519::Recipient,
    limits: RecoveryLimits,
    native: LocalSnapshotLimits,
    mode: Mode,
}
enum Mode {
    Pack {
        state: PathBuf,
        blobs: PathBuf,
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
    fn parse(mut arguments: Vec<OsString>) -> Result<Self, RecoveryError> {
        if arguments.is_empty() {
            return Err(RecoveryError::InvalidInput);
        }
        let packing: bool = match arguments.remove(0).to_str() {
            Some("pack-checkpoint") => true,
            Some("open-checkpoint") => false,
            _ => return Err(RecoveryError::InvalidInput),
        };
        let mut accepted: Vec<&'static str> = vec![
            "--chain-id",
            "--validator-id",
            "--domain",
            "--independent-anchor-db",
            "--recipient",
            "--state-db",
            "--blob-db",
            "--capture-root",
            "--ciphertext-out",
            "--ciphertext-file",
            "--identity-file",
            "--out-dir",
        ];
        accepted.extend_from_slice(LIMITS);
        let mut flags: FlagSet =
            FlagSet::parse(arguments, &accepted, &[]).map_err(|_| RecoveryError::InvalidInput)?;
        let chain: ChainId = ChainId::new(
            flags
                .one("--chain-id")
                .map_err(|_| RecoveryError::InvalidInput)?,
        )
        .map_err(|_| RecoveryError::InvalidInput)?;
        let validator: ValidatorId = ValidatorId::new(
            parse_hex_32(
                &flags
                    .one("--validator-id")
                    .map_err(|_| RecoveryError::InvalidInput)?,
                "--validator-id",
            )
            .map_err(|_| RecoveryError::InvalidInput)?,
        );
        let domain: AtomicityDomainId = AtomicityDomainId::new(
            parse_hex_32(
                &flags
                    .one("--domain")
                    .map_err(|_| RecoveryError::InvalidInput)?,
                "--domain",
            )
            .map_err(|_| RecoveryError::InvalidInput)?,
        )
        .map_err(|_| RecoveryError::InvalidInput)?;
        let anchor: PathBuf = flags
            .one("--independent-anchor-db")
            .map_err(|_| RecoveryError::InvalidInput)?
            .into();
        if !anchor.is_absolute() {
            return Err(RecoveryError::InvalidInput);
        }
        let recipient = transport::parse_recipient(
            &flags
                .one("--recipient")
                .map_err(|_| RecoveryError::InvalidInput)?,
        )?;
        let mode: Mode = if packing {
            Mode::Pack {
                state: path(&mut flags, "--state-db")?,
                blobs: path(&mut flags, "--blob-db")?,
                capture: path(&mut flags, "--capture-root")?,
                cipher: path(&mut flags, "--ciphertext-out")?,
            }
        } else {
            Mode::Open {
                cipher: path(&mut flags, "--ciphertext-file")?,
                identity: path(&mut flags, "--identity-file")?,
                output: path(&mut flags, "--out-dir")?,
            }
        };
        let limits: RecoveryLimits = RecoveryLimits::parse(&mut flags)?;
        flags.finish().map_err(|_| RecoveryError::InvalidInput)?;
        if limits.files < 4 {
            return Err(RecoveryError::Quota);
        }
        let now: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RecoveryError::Quota)?
            .as_millis();
        let deadline: u64 = u64::try_from(
            now.checked_add(limits.timeout.as_millis())
                .ok_or(RecoveryError::Quota)?,
        )
        .map_err(|_| RecoveryError::Quota)?;
        let native = LocalSnapshotLimits {
            max_database_bytes: limits.file_bytes,
            deadline_unix_millis: Some(deadline),
        };
        Ok(Self {
            namespace: SqliteNamespace::new(chain, validator, domain),
            anchor,
            recipient,
            limits,
            native,
            mode,
        })
    }
}
fn path(flags: &mut FlagSet, name: &str) -> Result<PathBuf, RecoveryError> {
    flags
        .one(name)
        .map(PathBuf::from)
        .map_err(|_| RecoveryError::InvalidInput)
}
fn native_budget(budget: &ArchiveReadBudget) -> Result<(), runtime_sqlite::IndependentAnchorError> {
    budget
        .charge_observations(1)
        .map_err(|_| runtime_sqlite::IndependentAnchorError)?;
    budget
        .check()
        .map_err(|_| runtime_sqlite::IndependentAnchorError)
}

pub(super) fn run(arguments: Vec<OsString>) -> Result<(), RecoveryError> {
    let request: Request = Request::parse(arguments)?;
    let budget: ArchiveReadBudget = request.limits.budget()?;
    budget.check_roles(1).map_err(|_| RecoveryError::Quota)?;
    let result = match request.mode {
        Mode::Pack { .. } => pack(request, &budget),
        Mode::Open { .. } => open(request, &budget),
    };
    result.map_err(|error| classify_failure(error, &budget))
}
fn complete(stage: &mut PrivateStage, manifest: &envelope::Manifest) -> Result<(), RecoveryError> {
    stage.checkpoint_check(&manifest.bodies, 0)?;
    stage.checkpoint_control(envelope::MANIFEST, manifest.control())?;
    stage.checkpoint_check(&manifest.bodies, 1)?;
    stage.checkpoint_control(envelope::COMPLETE, &manifest.footer())?;
    stage.checkpoint_check(&manifest.bodies, 2)
}
fn pack(request: Request, budget: &ArchiveReadBudget) -> Result<(), RecoveryError> {
    let Mode::Pack {
        state,
        blobs,
        capture,
        cipher,
    } = request.mode
    else {
        return Err(RecoveryError::InvalidInput);
    };
    let capture: AbsentOutput = AbsentOutput::new(&capture, budget)?;
    let cipher: AbsentOutput = AbsentOutput::new(&cipher, budget)?;
    files::distinct(&capture, &cipher)?;
    let pending: AbsentOutput =
        AbsentOutput::new(&CipherPublication::pending_path(cipher.path())?, budget)?;
    files::distinct(&capture, &pending)?;
    for input in [&state, &blobs, &request.anchor] {
        input_placement(input, &capture, budget)?;
        input_placement(input, &cipher, budget)?;
        input_placement(input, &pending, budget)?;
    }
    capture.headroom(budget)?;
    cipher.headroom(budget)?;
    let store: SqliteDurableStore = SqliteDurableStore::open_historical_anchored(
        &state,
        &blobs,
        &request.anchor,
        request.namespace,
    )
    .map_err(|_| RecoveryError::Proof)?;
    let mut stage: PrivateStage = PrivateStage::create(&capture, budget)?;
    let point: LocalStoreCheckpoint = store
        .create_independent_checkpoint_snapshot(
            &stage.checkpoint_path("state.sqlite")?,
            &stage.checkpoint_path("blobs.sqlite")?,
            request.native,
            || native_budget(budget),
        )
        .map_err(|_| RecoveryError::Proof)?;
    let mut bodies: [(u64, [u8; 32]); 2] = [(0, [0; 32]); 2];
    for (index, name) in envelope::NAMES.into_iter().enumerate() {
        bodies[index] = stage.checkpoint_adopt(name, request.limits.file_bytes)?;
    }
    let manifest: envelope::Manifest = envelope::Manifest::new(point, bodies, &request.limits)?;
    stage.checkpoint_check(&manifest.bodies, 0)?;
    let mut publication: CipherPublication = CipherPublication::create(cipher, budget)?;
    let counted: CipherWriter<'_, &mut std::fs::File> = CipherWriter::new(
        publication.writer(),
        budget,
        request.limits.ciphertext_bytes,
    );
    let mut encrypted = transport::encryptor(&request.recipient)?
        .wrap_output(counted)
        .map_err(|_| RecoveryError::Transport)?;
    manifest.prefix(&mut encrypted)?;
    for (index, name) in envelope::NAMES.into_iter().enumerate() {
        encrypted
            .write_all(&manifest.file_header(index)?)
            .map_err(|_| RecoveryError::Transport)?;
        let (length, hash) = manifest.bodies[index];
        stage.checkpoint_write(name, &mut encrypted, length, hash)?;
    }
    encrypted
        .write_all(&manifest.footer())
        .map_err(|_| RecoveryError::Transport)?;
    let (length, hash) = encrypted
        .finish()
        .map(|writer| writer.observation())
        .map_err(|_| RecoveryError::Transport)?;
    stage.checkpoint_check(&manifest.bodies, 0)?;
    if store
        .independent_anchor_checkpoint()
        .map_err(|_| RecoveryError::Proof)?
        != manifest.point.checkpoint
    {
        return Err(RecoveryError::Proof);
    }
    publication.publish(length, hash, request.limits.ciphertext_bytes)?;
    complete(&mut stage, &manifest)?;
    println!(
        "business_recovery=checkpoint-packed files=2 meaning=local-current-store-no-activation"
    );
    Ok(())
}
fn open(request: Request, budget: &ArchiveReadBudget) -> Result<(), RecoveryError> {
    let Mode::Open {
        cipher: input,
        identity,
        output,
    } = request.mode
    else {
        return Err(RecoveryError::InvalidInput);
    };
    let output: AbsentOutput = AbsentOutput::new(&output, budget)?;
    let input: PathBuf = input_placement(&input, &output, budget)?;
    let identity: PathBuf = input_placement(&identity, &output, budget)?;
    input_placement(&request.anchor, &output, budget)?;
    if input == identity || input == request.anchor || identity == request.anchor {
        return Err(RecoveryError::InvalidInput);
    }
    // Acquire before receiving untrusted bytes, and retain through completion.
    let authority: ConfiguredCheckpointAuthority = ConfiguredCheckpointAuthority::open_bounded(
        &request.anchor,
        request.namespace,
        request.native,
        || native_budget(budget),
    )
    .map_err(|_| RecoveryError::Proof)?;
    let identity: LoadedIdentity = transport::read_identity(&identity, &request.recipient, budget)?;
    let input: AttachedRegularFile = AttachedRegularFile::open(
        &input,
        request.limits.ciphertext_bytes,
        budget,
        AttachedFilePolicy::public(),
    )
    .map_err(|_| RecoveryError::Attachment)?;
    let physical_length: u64 = input.stamp().length;
    output.headroom(budget)?;
    let mut stage: PrivateStage = PrivateStage::create(&output, budget)?;
    let phase: CipherPhase = CipherPhase::header();
    let mut cipher: CipherReader<'_, AttachedRegularFile> =
        CipherReader::new(input, &phase, budget, &request.limits);
    let manifest: envelope::Manifest;
    {
        let decrypted = transport::decrypt(&mut cipher, &phase, &identity.identity)?;
        let mut plain = PlainReader::new(decrypted, request.limits.plaintext_bytes, budget);
        manifest = envelope::receive(&mut plain, &mut stage, &request.limits)?;
        if plain.observed() != manifest.plaintext {
            return Err(RecoveryError::Inventory);
        }
        plain.authenticated_eof()?;
    }
    cipher.physical_eof()?;
    if cipher.observed() != physical_length || cipher.inner.observed_bytes() != physical_length {
        return Err(RecoveryError::Transport);
    }
    cipher
        .inner
        .ensure_attached()
        .map_err(|_| RecoveryError::Attachment)?;
    identity.ensure_attached()?;
    stage.checkpoint_check(&manifest.bodies, 0)?;
    authority
        .verify_snapshot(
            &stage.checkpoint_path("state.sqlite")?,
            &stage.checkpoint_path("blobs.sqlite")?,
            &manifest.point,
            request.native,
            || native_budget(budget),
        )
        .map_err(|_| RecoveryError::Proof)?;
    stage.checkpoint_check(&manifest.bodies, 0)?;
    cipher
        .inner
        .ensure_attached()
        .map_err(|_| RecoveryError::Attachment)?;
    identity.ensure_attached()?;
    budget.check().map_err(|_| RecoveryError::Quota)?;
    complete(&mut stage, &manifest)?;
    println!(
        "business_recovery=checkpoint-opened files=2 meaning=current-local-store-next-fence-and-serving-pins-still-required"
    );
    Ok(())
}
