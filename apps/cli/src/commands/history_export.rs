//! Bounded immutable export of authenticated ordered history. This verifies
//! candidate order and source-companion linkage; it does not verify business
//! execution results or establish cut/import readiness.

use std::{
    error::Error,
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use protocol_types::{Digest32, ValidatorId};
use sunrise_edge_client::ordered_economics_core::{
    OrderedHistoryComponentKind, OrderedHistoryHeightDescriptor, OrderedHistoryHeightMaterial,
    OrderedHistoryIdentity, OrderedHistoryVerifier, decode_ordered_history_height_descriptor,
    decode_ordered_history_identity, encode_ordered_history_height_descriptor,
    encode_ordered_history_identity, ordered_history_component_digest,
    ordered_history_descriptor_digest,
};
use sunrise_edge_client::{
    Client, ordered_economics_core,
    ordered_economics_core::{OrderedHistoryComponentRef, OrderedHistorySummary},
    ordered_history_client::OrderedHistoryComponentRead,
};

use crate::{
    args::{ParsedArgs, scalar},
    error::CliError,
    hex::{decode_hex_32, encode_hex},
    net::{BudgetedTransport, OperationBudget},
    parse::parse_u64,
};

use super::{LoadedPolicyInputs, load_policy_and_endpoints, parse_budget};

fn failure(error: impl Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}
fn invalid(reason: impl Into<String>) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        reason.into(),
    ))
}

fn flag_specs() -> Vec<crate::args::FlagSpec> {
    let mut specs: Vec<crate::args::FlagSpec> = [
        "--ordered-network",
        "--ordered-genesis-manifest",
        "--ordered-expected-genesis-digest",
        "--expected-chain-id",
        "--expected-protocol-version",
        "--expected-epoch",
        "--domain",
        "--target-validator-id",
        "--out-dir",
        "--history-max-heights",
        "--history-chunk-bytes",
        "--history-through-height",
        "--history-through-digest",
        "--deadline-seconds",
        "--per-request-cap-seconds",
    ]
    .into_iter()
    .map(scalar)
    .collect();
    specs.extend(super::super::successor_pins::successor_flag_specs(false));
    specs
}

// The client borrows transport from the selected endpoint, so construct and
// drive it inside `run` while the endpoint vector remains alive.
fn run<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let args: Vec<OsString> = args.into_iter().collect();
    if args.as_slice() == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    let (parsed, schedules) =
        super::super::hash_suite_pins::parse_pinned_flags(args, &flag_specs())?;
    let (deadline, per_request_cap) = parse_budget(&parsed)?;
    let inputs: LoadedPolicyInputs = load_policy_and_endpoints(&parsed, schedules)?;
    let target_validator: ValidatorId = ValidatorId::new(decode_hex_32(
        "--target-validator-id",
        parsed.require("--target-validator-id")?,
    )?);
    let endpoint = inputs
        .endpoints
        .iter()
        .find(|item| item.validator_id == target_validator)
        .ok_or_else(|| {
            invalid("--target-validator-id is not in the locally pinned ordered validator set")
        })?;
    let transport = endpoint.client.transport().clone();
    let client: Client<BudgetedTransport<'_, crate::net::CliTransport>> =
        Client::new(BudgetedTransport {
            inner: &transport,
            budget: Some(OperationBudget {
                deadline,
                per_request_cap,
            }),
        });
    let maximum_heights: u64 = parse_bounded(&parsed, "--history-max-heights", 64, 4096)?;
    let chunk_bytes: u32 = u32::try_from(parse_bounded(
        &parsed,
        "--history-chunk-bytes",
        1024 * 1024,
        1024 * 1024,
    )?)
    .map_err(|_| invalid("history chunk size exceeds u32"))?;
    let supplied_height = parsed.get("--history-through-height");
    let supplied_digest = parsed.get("--history-through-digest");
    if supplied_height.is_some() != supplied_digest.is_some() {
        return Err(invalid(
            "--history-through-height and --history-through-digest must be supplied together",
        ));
    }
    let requested_target = supplied_height
        .map(|height| {
            Ok::<(u64, [u8; 32]), CliError>((
                parse_u64("--history-through-height", height)?,
                decode_hex_32(
                    "--history-through-digest",
                    supplied_digest.unwrap_or_default(),
                )?,
            ))
        })
        .transpose()?;
    let directory = ExportDirectory::open(Path::new(parsed.require("--out-dir")?))?;
    let settings = chunk_bytes.to_be_bytes();
    if let Some(saved) = directory.read("chunk-size.bin", 4)? {
        if saved.as_slice() != settings {
            return Err(invalid(
                "saved chunk size differs; resume with the original --history-chunk-bytes",
            ));
        }
    } else {
        directory.persist("chunk-size.bin", &settings, 4)?;
    }
    let identity: OrderedHistoryIdentity = match directory.read(
        "identity.bin",
        ordered_economics_core::MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
    )? {
        Some(bytes) => {
            let identity = decode_ordered_history_identity(&bytes).map_err(failure)?;
            validate_identity(&identity, &inputs.policy)?;
            if let Some((height, digest)) = requested_target
                && (identity.through_height != height || identity.through_digest.bytes() != digest)
            {
                return Err(invalid("saved target differs from explicit history target"));
            }
            identity
        }
        None => {
            let summary: OrderedHistorySummary = client
                .query_ordered_history_summary(Some(deadline))
                .map_err(failure)?;
            validate_identity(&summary.identity, &inputs.policy)?;
            if let Some((height, digest)) = requested_target
                && (summary.identity.through_height != height
                    || summary.identity.through_digest.bytes() != digest)
            {
                return Err(invalid(
                    "requested target is not the source's currently advertised applied tip",
                ));
            }
            let encoded = encode_ordered_history_identity(&summary.identity).map_err(failure)?;
            directory.persist(
                "identity.bin",
                &encoded,
                ordered_economics_core::MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
            )?;
            summary.identity
        }
    };
    let mut verifier =
        OrderedHistoryVerifier::new(inputs.policy.clone(), identity.clone()).map_err(failure)?;
    let mut new_heights: u64 = 0;
    let mut height: u64 = 1;
    while height <= identity.through_height {
        budget_live(deadline)?;
        let paths = HeightPaths::new(&directory, height);
        let descriptor_bytes = match directory.read(
            &paths.descriptor,
            ordered_economics_core::MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
        )? {
            Some(bytes) => bytes,
            None => {
                if new_heights >= maximum_heights {
                    println!(
                        "history=partial verified_heights={} next_height={} target_height={}",
                        height - 1,
                        height,
                        identity.through_height
                    );
                    return Ok(());
                }
                let descriptor = client
                    .fetch_ordered_history_height_descriptor(&identity, height, Some(deadline))
                    .map_err(failure)?;
                let bytes =
                    encode_ordered_history_height_descriptor(&descriptor).map_err(failure)?;
                directory.persist(
                    &paths.descriptor,
                    &bytes,
                    ordered_economics_core::MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
                )?;
                new_heights = new_heights
                    .checked_add(1)
                    .ok_or_else(|| invalid("height counter overflow"))?;
                bytes
            }
        };
        let descriptor: OrderedHistoryHeightDescriptor =
            decode_ordered_history_height_descriptor(&descriptor_bytes).map_err(failure)?;
        if descriptor.identity != identity || descriptor.height != height {
            return Err(invalid(
                "saved descriptor differs from fixed identity or contiguous height",
            ));
        }
        let descriptor_digest =
            ordered_history_descriptor_digest(&inputs.policy, &descriptor).map_err(failure)?;
        let mut components: Vec<(OrderedHistoryComponentKind, Vec<u8>)> =
            Vec::with_capacity(descriptor.components.len());
        for reference in &descriptor.components {
            budget_live(deadline)?;
            let bytes = load_or_fetch_component(
                &directory,
                &client,
                ComponentReadPlan {
                    identity: &identity,
                    height,
                    descriptor_digest,
                    reference,
                    chunk_bytes,
                    deadline,
                },
            )?;
            if ordered_history_component_digest(&inputs.policy, &bytes).map_err(failure)?
                != reference.digest
                || bytes.len() as u64 != reference.length
            {
                return Err(invalid(
                    "assembled component differs from saved descriptor digest or length",
                ));
            }
            components.push((reference.kind, bytes));
        }
        verifier
            .verify_next_height(&OrderedHistoryHeightMaterial {
                descriptor,
                components,
            })
            .map_err(failure)?;
        height = height
            .checked_add(1)
            .ok_or_else(|| invalid("height overflow"))?;
    }
    let verified = verifier.finish().map_err(failure)?;
    let final_identity = verified.identity();
    if final_identity != &identity {
        return Err(invalid("verified prefix identity changed"));
    }
    budget_live(deadline)?;
    let completion: Vec<u8> = encode_ordered_history_identity(&identity).map_err(failure)?;
    directory.persist(
        "complete",
        &completion,
        ordered_economics_core::MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
    )?;
    println!(
        "history=ordered-prefix-verified through_height={} through_view={} through_digest={} validator_id={} note=ordering-and-companion-linkage-only",
        identity.through_height,
        identity.through_view,
        encode_hex(&identity.through_digest.bytes()),
        encode_hex(target_validator.as_bytes())
    );
    Ok(())
}

fn parse_bounded(
    parsed: &ParsedArgs,
    flag: &'static str,
    default: u64,
    maximum: u64,
) -> Result<u64, CliError> {
    let value = parsed
        .get(flag)
        .map(|value| parse_u64(flag, value))
        .transpose()?
        .unwrap_or(default);
    if value == 0 || value > maximum {
        return Err(invalid(format!("{flag} must be in 1..={maximum}")));
    }
    Ok(value)
}
fn budget_live(deadline: Instant) -> Result<(), CliError> {
    if Instant::now() >= deadline {
        return Err(failure(
            sunrise_edge_client::TransportError::RequestDeadlineExceeded,
        ));
    }
    Ok(())
}
fn validate_identity(
    identity: &OrderedHistoryIdentity,
    policy: &ordered_economics_core::OrderedEconomicsPolicy,
) -> Result<(), CliError> {
    if identity.context != *policy.context()
        || identity.domain != policy.domain()
        || identity.genesis_digest != policy.genesis_digest()
        || identity.anchor != policy.anchor()
    {
        return Err(invalid(
            "history identity differs from locally trusted signed genesis and domain",
        ));
    }
    Ok(())
}

struct HeightPaths {
    directory: PathBuf,
    descriptor: String,
}
impl HeightPaths {
    fn new(root: &ExportDirectory, height: u64) -> Self {
        let name = format!("height-{height:020}");
        Self {
            directory: root.path.join(name),
            descriptor: format!("height-{height:020}/descriptor.bin"),
        }
    }
    fn chunk(kind: OrderedHistoryComponentKind, offset: u64) -> String {
        format!("component-{:02}/chunk-{offset:020}.bin", kind as u16)
    }
}

struct ComponentReadPlan<'a> {
    identity: &'a OrderedHistoryIdentity,
    height: u64,
    descriptor_digest: Digest32,
    reference: &'a OrderedHistoryComponentRef,
    chunk_bytes: u32,
    deadline: Instant,
}

fn load_or_fetch_component<T: sunrise_edge_client::Transport>(
    directory: &ExportDirectory,
    client: &Client<T>,
    plan: ComponentReadPlan<'_>,
) -> Result<Vec<u8>, CliError> {
    let ComponentReadPlan {
        identity,
        height,
        descriptor_digest,
        reference,
        chunk_bytes,
        deadline,
    } = plan;
    let paths = HeightPaths::new(directory, height);
    let mut assembled: Vec<u8> =
        Vec::with_capacity(usize::try_from(reference.length).map_err(failure)?);
    let mut offset: u64 = 0;
    while offset < reference.length {
        budget_live(deadline)?;
        let filename = format!(
            "{}/{}",
            paths
                .directory
                .strip_prefix(&directory.path)
                .map_err(failure)?
                .display(),
            HeightPaths::chunk(reference.kind, offset)
        );
        let requested = u32::try_from(u64::from(chunk_bytes).min(reference.length - offset))
            .map_err(failure)?;
        let chunk = match directory.read(&filename, requested as usize)? {
            Some(bytes) => bytes,
            None => {
                let bytes = client
                    .fetch_ordered_history_component_chunk(
                        &OrderedHistoryComponentRead {
                            identity: identity.clone(),
                            height,
                            descriptor_digest,
                            kind: reference.kind,
                            offset,
                            limit: requested,
                            expected_total_length: reference.length,
                        },
                        Some(deadline),
                    )
                    .map_err(failure)?;
                directory.persist(&filename, &bytes, requested as usize)?;
                bytes
            }
        };
        if chunk.len() != requested as usize {
            return Err(invalid(
                "saved history chunk length differs from requested range",
            ));
        }
        assembled.extend_from_slice(&chunk);
        offset = offset
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| invalid("chunk offset overflow"))?;
    }
    Ok(assembled)
}

struct ExportDirectory {
    path: PathBuf,
    handle: File,
}
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
impl ExportDirectory {
    fn open(path: &Path) -> Result<Self, CliError> {
        std::fs::create_dir_all(path).map_err(failure)?;
        let path = path.canonicalize().map_err(failure)?;
        let handle = File::open(&path).map_err(failure)?;
        let result = Self { path, handle };
        result.sync_directory_chain(&result.path, None)?;
        Ok(result)
    }
    fn ensure_attached(&self) -> Result<(), CliError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let actual = std::fs::metadata(&self.path).map_err(failure)?;
            let held = self.handle.metadata().map_err(failure)?;
            if (actual.dev(), actual.ino()) != (held.dev(), held.ino()) {
                return Err(invalid("history export directory was replaced"));
            }
        }
        Ok(())
    }
    fn read(&self, name: &str, maximum: usize) -> Result<Option<Vec<u8>>, CliError> {
        self.ensure_attached()?;
        let path = self.checked_path(name, false)?;
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(failure(error)),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid("history export artifact is not a regular file"));
        }
        let mut bytes = Vec::new();
        let bound = u64::try_from(maximum)
            .map_err(failure)?
            .checked_add(1)
            .ok_or_else(|| invalid("history artifact size overflow"))?;
        let file = File::open(&path).map_err(failure)?;
        let opened = file.metadata().map_err(failure)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (metadata.dev(), metadata.ino()) != (opened.dev(), opened.ino()) {
                return Err(invalid("history export artifact was replaced during open"));
            }
        }
        if !opened.is_file() {
            return Err(invalid(
                "opened history export artifact is not a regular file",
            ));
        }
        file.take(bound).read_to_end(&mut bytes).map_err(failure)?;
        if bytes.len() > maximum {
            return Err(invalid("history export artifact exceeds its bound"));
        }
        self.ensure_attached()?;
        Ok(Some(bytes))
    }
    fn persist(&self, name: &str, bytes: &[u8], maximum: usize) -> Result<(), CliError> {
        if bytes.len() > maximum {
            return Err(invalid("history artifact exceeds its bound"));
        }
        if let Some(existing) = self.read(name, maximum)? {
            return if existing == bytes {
                Ok(())
            } else {
                Err(invalid(
                    "saved history artifact differs; refusing overwrite",
                ))
            };
        }
        self.ensure_attached()?;
        let destination = self.checked_path(name, true)?;
        self.sync_ancestor_directories(&destination)?;
        let n = TEMP_COUNTER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| invalid("history temporary sequence exhausted"))?;
        let path = self
            .path
            .join(format!(".pending-{}-{n}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(failure)?;
        file.write_all(bytes).map_err(failure)?;
        file.sync_all().map_err(failure)?;
        self.ensure_attached()?;
        match std::fs::hard_link(&path, &destination) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if self.read(name, maximum)?.as_deref() != Some(bytes) {
                    return Err(invalid(
                        "concurrent history export differs; refusing overwrite",
                    ));
                }
            }
            Err(error) => return Err(failure(error)),
        }
        self.sync_ancestor_directories(&destination)?;
        std::fs::remove_file(path).map_err(failure)?;
        self.sync_ancestor_directories(&destination)?;
        self.ensure_attached()
    }

    /// Resolves only relative normal components, creating missing child
    /// directories one at a time and refusing symlink/non-directory ancestors.
    fn checked_path(&self, name: &str, create_parents: bool) -> Result<PathBuf, CliError> {
        use std::path::Component;
        let relative = Path::new(name);
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|item| !matches!(item, Component::Normal(_)))
        {
            return Err(invalid("history artifact path is not a safe relative path"));
        }
        self.ensure_attached()?;
        let destination = self.path.join(relative);
        let mut current = self.path.clone();
        let components: Vec<Component<'_>> = relative.components().collect();
        for segment in components.iter().take(components.len().saturating_sub(1)) {
            let Component::Normal(segment) = segment else {
                return Err(invalid("history artifact path is not normal"));
            };
            current.push(segment);
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Ok(_) => return Err(invalid("history export ancestor is not a real directory")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && create_parents => {
                    std::fs::create_dir(&current).map_err(failure)?;
                    let metadata = std::fs::symlink_metadata(&current).map_err(failure)?;
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        return Err(invalid("created history ancestor is not a real directory"));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(destination);
                }
                Err(error) => return Err(failure(error)),
            }
        }
        self.ensure_attached()?;
        Ok(destination)
    }

    fn sync_ancestor_directories(&self, destination: &Path) -> Result<(), CliError> {
        let parent = destination
            .parent()
            .ok_or_else(|| invalid("history artifact has no parent"))?;
        self.sync_directory_chain(parent, Some(&self.path))
    }

    fn sync_directory_chain(&self, starting: &Path, stop: Option<&Path>) -> Result<(), CliError> {
        let mut current = starting.to_path_buf();
        loop {
            let metadata = std::fs::symlink_metadata(&current).map_err(failure)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(invalid(
                    "history export sync ancestor is not a real directory",
                ));
            }
            File::open(&current)
                .map_err(failure)?
                .sync_all()
                .map_err(failure)?;
            if stop.is_some_and(|root| current == root) {
                break;
            }
            let Some(parent) = current.parent() else {
                break;
            };
            if stop.is_some_and(|root| !current.starts_with(root)) {
                break;
            }
            if stop.is_some()
                && !parent.starts_with(stop.unwrap_or(&self.path))
                && parent != stop.unwrap_or(&self.path)
            {
                break;
            }
            if stop.is_none() && parent == current {
                break;
            }
            current = parent.to_path_buf();
        }
        self.ensure_attached()
    }
}

const HELP: &str = "Authenticated ordered-history export (ordering and companion linkage only; not business execution or cut readiness).\n\nRequired flags: --ordered-network --ordered-genesis-manifest --ordered-expected-genesis-digest --expected-chain-id --expected-protocol-version --expected-epoch --domain --target-validator-id --out-dir.\nOptional: --history-max-heights N (default 64 per invocation), --history-chunk-bytes N (default 1048576), --history-through-height N --history-through-digest DIGEST (both or neither), --deadline-seconds N --per-request-cap-seconds N.\n\nSaved identity fixes the target across restarts. Each height is saved as a descriptor and individually immutable raw component chunks. Completion is written only after the whole contiguous prefix verifies. The source is read-only; source-advertised tip is not freshness authority.";

pub(super) fn dispatch<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    run(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ordered-history-export-{}-{nonce}",
                std::process::id()
            ));
            Self(path)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn immutable_nested_artifacts_create_and_sync_their_parent_chain() {
        let temporary = TempRoot::new();
        let directory = ExportDirectory::open(&temporary.0.join("export")).unwrap();
        directory
            .persist("chunk-size.bin", &1024_u32.to_be_bytes(), 4)
            .unwrap();
        directory
            .persist(
                "height-00000000000000000001/component-01/chunk-00000000000000000000.bin",
                b"abc",
                3,
            )
            .unwrap();
        assert_eq!(
            directory.read("chunk-size.bin", 4).unwrap().unwrap(),
            1024_u32.to_be_bytes()
        );
        assert_eq!(
            directory
                .read(
                    "height-00000000000000000001/component-01/chunk-00000000000000000000.bin",
                    3
                )
                .unwrap()
                .unwrap(),
            b"abc"
        );
        assert!(
            directory
                .persist(
                    "height-00000000000000000001/component-01/chunk-00000000000000000000.bin",
                    b"xyz",
                    3
                )
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_export_ancestors_and_files() {
        use std::os::unix::fs::symlink;
        let temporary = TempRoot::new();
        let outside = temporary.0.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let directory = ExportDirectory::open(&temporary.0.join("export")).unwrap();
        symlink(&outside, directory.path.join("height-00000000000000000001")).unwrap();
        assert!(
            directory
                .persist(
                    "height-00000000000000000001/descriptor.bin",
                    b"descriptor",
                    32
                )
                .is_err()
        );
        assert!(!outside.join("descriptor.bin").exists());
        symlink(outside.join("missing"), directory.path.join("linked.bin")).unwrap();
        assert!(directory.read("linked.bin", 32).is_err());
    }
}
