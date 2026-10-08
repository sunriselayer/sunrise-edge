//! Independent, read-only verification of saved `history-export` files.
//! A completion marker or saved cursor is never accepted instead of replaying
//! the complete pinned prefix. This API authenticates ordering, not effects.

use crate::immutable_archive::{ArchiveReadBudget, ImmutableArchiveReader};
use node_core::ordered_economics::{
    MAX_ORDERED_HISTORY_CHUNK_BYTES, MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES, OrderedEconomicsPolicy,
    OrderedHistoryComponentKind, OrderedHistoryHeightDescriptor, OrderedHistoryHeightMaterial,
    OrderedHistoryIdentity, OrderedHistoryVerifier, decode_ordered_history_height_descriptor,
    decode_ordered_history_height_descriptor_bounded, decode_ordered_history_identity,
    ordered_history_component_digest,
};
use std::collections::BTreeSet;
use std::{
    error::Error,
    fs::File,
    io::{self, Read},
    path::Path,
};

fn invalid(reason: &'static str) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidData, reason))
}

/// Reads only existing regular files below a caller-selected archive root.
/// The root may be selected locally, but all protocol identities are separately
/// pinned and verified. No filename confers protocol authority.
pub fn read_regular_archive_file(
    root: &Path,
    name: &Path,
    maximum: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let root_metadata = std::fs::symlink_metadata(root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(invalid("archive directory is not a regular directory"));
    }
    let mut path = root.to_path_buf();
    for part in name.components() {
        let std::path::Component::Normal(part) = part else {
            return Err(invalid("archive filename is not a relative normal path"));
        };
        path.push(part);
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("archive component is a symlink"));
        }
    }
    let before = std::fs::symlink_metadata(&path)?;
    if !before.is_file() {
        return Err(invalid("archive artifact is not a regular file"));
    }
    let mut file: File = File::open(&path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() > u64::try_from(maximum)? {
        return Err(invalid("archive artifact exceeds its bounded file size"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err(invalid("archive artifact changed while opening"));
        }
    }
    let mut bytes: Vec<u8> = Vec::new();
    file.by_ref()
        .take(
            u64::try_from(maximum)?
                .checked_add(1)
                .ok_or_else(|| invalid("archive file bound overflow"))?,
        )
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(invalid("archive artifact exceeds its file bound"));
    }
    Ok(bytes)
}

/// One complete fixed-target prefix, with bounded individual files/chunks.
/// The caller may provision a linear history index; no total-height protocol
/// ceiling is imposed. Missing saved chunks refuse, rather than fetching a
/// changed tip or treating a partial export as complete.
pub fn read_verified_ordered_history_archive(
    policy: &OrderedEconomicsPolicy,
    root: &Path,
) -> Result<(OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>), Box<dyn Error>> {
    let root = root.canonicalize()?;
    if !root.is_dir() {
        return Err(invalid("ordered archive root is not a directory"));
    }
    let identity_bytes = read_regular_archive_file(
        &root,
        Path::new("identity.bin"),
        MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
    )?;
    let identity: OrderedHistoryIdentity = decode_ordered_history_identity(&identity_bytes)?;
    let chunk_size: u32 = read_chunk_size(&root)?;
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(policy.clone(), identity.clone())?;
    let mut heights: Vec<OrderedHistoryHeightMaterial> = Vec::new();
    let mut height: u64 = 1;
    while height <= identity.through_height {
        let material = read_height_material(&root, chunk_size, policy, &identity, height)?;
        verifier.verify_next_height(&material)?;
        heights.push(material);
        height = height
            .checked_add(1)
            .ok_or_else(|| invalid("ordered archive height overflow"))?;
    }
    if verifier.finish()?.identity() != &identity {
        return Err(invalid("verified ordered target differs"));
    }
    let complete_bytes = read_regular_archive_file(
        &root,
        Path::new("complete"),
        MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
    )?;
    if complete_bytes != identity_bytes {
        return Err(invalid(
            "saved completion marker differs from the verified target",
        ));
    }
    Ok((identity, heights))
}

fn read_chunk_size(root: &Path) -> Result<u32, Box<dyn Error>> {
    let chunk_size_bytes = read_regular_archive_file(root, Path::new("chunk-size.bin"), 4)?;
    let chunk_size: u32 = u32::from_be_bytes(
        chunk_size_bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid("ordered archive chunk size is not four bytes"))?,
    );
    if chunk_size == 0 || chunk_size as usize > MAX_ORDERED_HISTORY_CHUNK_BYTES {
        return Err(invalid("ordered archive chunk size exceeds its bound"));
    }
    Ok(chunk_size)
}

fn read_height_material(
    root: &Path,
    chunk_size: u32,
    policy: &OrderedEconomicsPolicy,
    identity: &OrderedHistoryIdentity,
    height: u64,
) -> Result<OrderedHistoryHeightMaterial, Box<dyn Error>> {
    let height_root = root.join(format!("height-{height:020}"));
    let descriptor_bytes = read_regular_archive_file(
        root,
        Path::new(&format!("height-{height:020}/descriptor.bin")),
        MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
    )?;
    let descriptor = decode_ordered_history_height_descriptor(&descriptor_bytes)?;
    if descriptor.identity != *identity || descriptor.height != height {
        return Err(invalid(
            "saved height descriptor changed its fixed target or position",
        ));
    }
    let mut components: Vec<(OrderedHistoryComponentKind, Vec<u8>)> = Vec::new();
    for reference in &descriptor.components {
        let mut bytes: Vec<u8> = Vec::new();
        let mut offset: u64 = 0;
        while offset < reference.length {
            let count: usize =
                usize::try_from(u64::from(chunk_size).min(reference.length - offset))?;
            let relative = format!(
                "component-{:02}/chunk-{offset:020}.bin",
                reference.kind as u16
            );
            let chunk = read_regular_archive_file(&height_root, Path::new(&relative), count)?;
            if chunk.len() != count {
                return Err(invalid("saved ordered component chunk is truncated"));
            }
            bytes.extend_from_slice(&chunk);
            offset = offset
                .checked_add(u64::try_from(chunk.len())?)
                .ok_or_else(|| invalid("ordered archive chunk cursor overflow"))?;
        }
        if bytes.len() as u64 != reference.length
            || ordered_history_component_digest(policy, &bytes)? != reference.digest
        {
            return Err(invalid("saved component differs from its exact descriptor"));
        }
        components.push((reference.kind, bytes));
    }
    Ok(OrderedHistoryHeightMaterial {
        descriptor,
        components,
    })
}

/// Reads and structurally checks one fixed height material against its own
/// descriptor, without the cumulative [`OrderedHistoryVerifier`] state that
/// [`read_verified_ordered_history_archive`] maintains across the whole
/// prefix: the caller (an independent verifier run over the full claimed
/// target) performs that ordering/signature check itself. `identity` is the
/// caller's claimed target, checked only against this saved height descriptor,
/// never locally trusted by this function.
pub fn read_ordered_history_height(
    policy: &OrderedEconomicsPolicy,
    root: &Path,
    identity: &OrderedHistoryIdentity,
    height: u64,
) -> Result<OrderedHistoryHeightMaterial, Box<dyn Error>> {
    let root = root.canonicalize()?;
    if !root.is_dir() {
        return Err(invalid("ordered archive root is not a directory"));
    }
    if height == 0 || height > identity.through_height {
        return Err(invalid(
            "ordered archive height is outside its fixed target",
        ));
    }
    let chunk_size: u32 = read_chunk_size(&root)?;
    read_height_material(&root, chunk_size, policy, identity, height)
}

fn height_number(value: &str) -> Option<u64> {
    let height: u64 = value.strip_prefix("height-")?.parse().ok()?;
    (height != 0 && value == format!("height-{height:020}")).then_some(height)
}

fn component_kind(value: &str) -> Option<OrderedHistoryComponentKind> {
    let kind: u16 = value.strip_prefix("component-")?.parse().ok()?;
    let kind: OrderedHistoryComponentKind = OrderedHistoryComponentKind::from_wire(kind).ok()?;
    (value == format!("component-{:02}", kind as u16)).then_some(kind)
}

/// The defining saved-history FILE names and per-file bounds. No permissive glob
/// or caller normalization is used by the local recovery envelope.
#[must_use]
pub fn relative_file_limit(name: &str) -> Option<usize> {
    ImmutableArchiveReader::relative_filename(name).ok()?;
    match name {
        "identity.bin" | "complete" => return Some(MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES),
        "chunk-size.bin" => return Some(4),
        _ => {}
    }
    let mut parts = name.split('/');
    height_number(parts.next()?)?;
    let next: &str = parts.next()?;
    if next == "descriptor.bin" && parts.next().is_none() {
        return Some(MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES);
    }
    let kind: OrderedHistoryComponentKind = component_kind(next)?;
    let chunk: &str = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let offset: u64 = chunk
        .strip_prefix("chunk-")?
        .strip_suffix(".bin")?
        .parse()
        .ok()?;
    (chunk == format!("chunk-{offset:020}.bin") && offset < kind.max_bytes() as u64)
        .then_some(MAX_ORDERED_HISTORY_CHUNK_BYTES)
}

/// Exact generated intermediate DIRECTORY markers, as returned by names_recursive.
#[must_use]
pub fn generated_directory(name: &str) -> bool {
    let Some(name) = name.strip_suffix('/') else {
        return false;
    };
    let mut parts = name.split('/');
    if parts.next().and_then(height_number).is_none() {
        return false;
    }
    match parts.next() {
        None => true,
        Some(component) => component_kind(component).is_some() && parts.next().is_none(),
    }
}

fn bounded_budget(archive: &ImmutableArchiveReader) -> Result<&ArchiveReadBudget, Box<dyn Error>> {
    archive
        .read_budget()
        .ok_or_else(|| invalid("bounded history requires an installed budget"))
}

fn insert_expected(
    budget: &ArchiveReadBudget,
    expected: &mut BTreeSet<String>,
    name: String,
) -> Result<(), Box<dyn Error>> {
    budget.charge_observations(1)?;
    expected.insert(name);
    Ok(())
}

fn check_inventory_layout(
    identity: &OrderedHistoryIdentity,
    names: &BTreeSet<String>,
    budget: &ArchiveReadBudget,
) -> Result<(), Box<dyn Error>> {
    budget.check_height_target(identity.through_height)?;
    for name in names {
        budget.check()?;
        if !(generated_directory(name) || relative_file_limit(name).is_some()) {
            return Err(invalid("saved history has a foreign file or directory"));
        }
        if let Some(first) = name.split('/').next()
            && let Some(height) = height_number(first)
            && height > identity.through_height
        {
            return Err(invalid(
                "saved history contains material beyond its fixed target",
            ));
        }
    }
    for fixed in ["identity.bin", "chunk-size.bin", "complete"] {
        if !names.contains(fixed) {
            return Err(invalid("saved history is missing a fixed file"));
        }
    }
    for height in 1..=identity.through_height {
        budget.charge_observations(1)?;
        if !names.contains(&format!("height-{height:020}/"))
            || !names.contains(&format!("height-{height:020}/descriptor.bin"))
        {
            return Err(invalid("saved history is missing a height descriptor"));
        }
    }
    Ok(())
}

fn bounded_chunk_size(archive: &ImmutableArchiveReader) -> Result<u32, Box<dyn Error>> {
    let bytes: Vec<u8> = archive.read("chunk-size.bin", 4)?;
    let chunk_size: u32 = u32::from_be_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid("ordered archive chunk size is not four bytes"))?,
    );
    if chunk_size == 0 || chunk_size as usize > MAX_ORDERED_HISTORY_CHUNK_BYTES {
        return Err(invalid("ordered archive chunk size exceeds its bound"));
    }
    Ok(chunk_size)
}

fn bounded_height_material(
    archive: &ImmutableArchiveReader,
    chunk_size: u32,
    policy: &OrderedEconomicsPolicy,
    identity: &OrderedHistoryIdentity,
    height: u64,
    expected: &mut BTreeSet<String>,
) -> Result<OrderedHistoryHeightMaterial, Box<dyn Error>> {
    let budget: &ArchiveReadBudget = bounded_budget(archive)?;
    budget.charge_heights(1)?;
    budget.charge_observations(1)?;
    let prefix: String = format!("height-{height:020}");
    insert_expected(budget, expected, format!("{prefix}/"))?;
    let descriptor_name: String = format!("{prefix}/descriptor.bin");
    let descriptor_bytes: Vec<u8> =
        archive.read_relative(&descriptor_name, MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES)?;
    insert_expected(budget, expected, descriptor_name)?;
    let descriptor: OrderedHistoryHeightDescriptor =
        decode_bounded_descriptor(&descriptor_bytes, budget)?;
    if descriptor.identity != *identity || descriptor.height != height {
        return Err(invalid(
            "saved height descriptor changed its fixed target or position",
        ));
    }
    let mut components: Vec<(OrderedHistoryComponentKind, Vec<u8>)> = Vec::new();
    components
        .try_reserve_exact(descriptor.components.len())
        .map_err(|_| budget.refuse())?;
    for reference in &descriptor.components {
        budget.check_component_bytes(reference.length, reference.kind.max_bytes())?;
        budget.charge_observations(1)?;
        let component_prefix: String = format!("{prefix}/component-{:02}", reference.kind as u16);
        insert_expected(budget, expected, format!("{component_prefix}/"))?;
        let mut bytes: Vec<u8> = Vec::new();
        let mut offset: u64 = 0;
        while offset < reference.length {
            budget.charge_observations(1)?;
            let count: usize =
                usize::try_from(u64::from(chunk_size).min(reference.length - offset))?;
            let name: String = format!("{component_prefix}/chunk-{offset:020}.bin");
            let chunk: Vec<u8> = archive.read_relative(&name, count)?;
            insert_expected(budget, expected, name)?;
            if chunk.len() != count {
                return Err(invalid("saved ordered component chunk is truncated"));
            }
            let next: usize = bytes
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| budget.refuse())?;
            if u64::try_from(next)? > reference.length {
                return Err(budget.refuse().into());
            }
            bytes
                .try_reserve_exact(chunk.len())
                .map_err(|_| budget.refuse())?;
            bytes.extend_from_slice(&chunk);
            offset = offset
                .checked_add(u64::try_from(chunk.len())?)
                .ok_or_else(|| budget.refuse())?;
        }
        budget.check()?;
        if bytes.len() as u64 != reference.length
            || ordered_history_component_digest(policy, &bytes)? != reference.digest
        {
            return Err(invalid("saved component differs from its exact descriptor"));
        }
        budget.check()?;
        components.push((reference.kind, bytes));
    }
    Ok(OrderedHistoryHeightMaterial {
        descriptor,
        components,
    })
}

fn decode_bounded_descriptor(
    bytes: &[u8],
    budget: &ArchiveReadBudget,
) -> io::Result<OrderedHistoryHeightDescriptor> {
    let remaining: usize = budget.remaining_components()?;
    decode_ordered_history_height_descriptor_bounded(
        bytes,
        remaining,
        &mut |count: usize| -> bool {
            u64::try_from(count)
                .ok()
                .is_some_and(|count: u64| budget.charge_components(count).is_ok())
        },
    )
    .map_err(|_| budget.refuse())
}

fn close_height_inventory(
    names: &BTreeSet<String>,
    expected: &BTreeSet<String>,
    height: u64,
    budget: &ArchiveReadBudget,
) -> Result<(), Box<dyn Error>> {
    budget.charge_observations(1)?;
    let prefix: String = format!("height-{height:020}/");
    for name in names {
        budget.check()?;
        if name.starts_with(&prefix) && !expected.contains(name) {
            return Err(invalid("saved height has a surplus file or directory"));
        }
    }
    for name in expected {
        if !names.contains(name) {
            return Err(invalid("saved height is missing a required attachment"));
        }
    }
    Ok(())
}

/// Opt-in full prefix: held nested reads and exact files/directories, under one
/// invocation budget installed BEFORE construction. The original verifier owns proof.
pub fn read_verified_ordered_history_archive_bounded(
    policy: &OrderedEconomicsPolicy,
    archive: &ImmutableArchiveReader,
) -> Result<(OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>), Box<dyn Error>> {
    let budget: &ArchiveReadBudget = bounded_budget(archive)?;
    let identity_bytes: Vec<u8> =
        archive.read("identity.bin", MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES)?;
    let identity: OrderedHistoryIdentity = decode_ordered_history_identity(&identity_bytes)?;
    budget.require_heights(identity.through_height)?;
    let names: BTreeSet<String> = archive.names_recursive()?;
    check_inventory_layout(&identity, &names, budget)?;
    let chunk_size: u32 = bounded_chunk_size(archive)?;
    let mut expected: BTreeSet<String> = BTreeSet::new();
    for fixed in ["identity.bin", "chunk-size.bin", "complete"] {
        budget.charge_observations(1)?;
        expected.insert(fixed.to_owned());
    }
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(policy.clone(), identity.clone())?;
    budget.check()?;
    let mut heights: Vec<OrderedHistoryHeightMaterial> = Vec::new();
    for height in 1..=identity.through_height {
        let material: OrderedHistoryHeightMaterial = bounded_height_material(
            archive,
            chunk_size,
            policy,
            &identity,
            height,
            &mut expected,
        )?;
        budget.check()?;
        verifier.verify_next_height(&material)?;
        budget.check()?;
        heights.try_reserve_exact(1).map_err(|_| budget.refuse())?;
        heights.push(material);
    }
    if archive.names_recursive()? != expected || names != expected {
        return Err(invalid(
            "saved history has missing, surplus or foreign attachments",
        ));
    }
    budget.check()?;
    if verifier.finish()?.identity() != &identity {
        return Err(invalid("verified ordered target differs"));
    }
    budget.check()?;
    if archive.read("complete", MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES)? != identity_bytes {
        return Err(invalid(
            "saved completion marker differs from the verified target",
        ));
    }
    Ok((identity, heights))
}

/// Opt-in single height, not an independently verified full history. Every call
/// re-walks the complete layout and closes this height's exact subset. The owning
/// full-prefix core traversal visits EVERY height, jointly closing all subsets.
pub fn read_ordered_history_height_bounded(
    policy: &OrderedEconomicsPolicy,
    archive: &ImmutableArchiveReader,
    identity: &OrderedHistoryIdentity,
    height: u64,
) -> Result<OrderedHistoryHeightMaterial, Box<dyn Error>> {
    let budget: &ArchiveReadBudget = bounded_budget(archive)?;
    budget.check_height_target(identity.through_height)?;
    if height == 0 || height > identity.through_height {
        return Err(invalid(
            "ordered archive height is outside its fixed target",
        ));
    }
    let identity_bytes: Vec<u8> =
        archive.read("identity.bin", MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES)?;
    if decode_ordered_history_identity(&identity_bytes)? != *identity {
        return Err(invalid("saved ordered identity differs"));
    }
    if archive.read("complete", MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES)? != identity_bytes {
        return Err(invalid(
            "saved completion marker differs from the fixed target",
        ));
    }
    let names: BTreeSet<String> = archive.names_recursive()?;
    check_inventory_layout(identity, &names, budget)?;
    let mut expected: BTreeSet<String> = BTreeSet::new();
    let material: OrderedHistoryHeightMaterial = bounded_height_material(
        archive,
        bounded_chunk_size(archive)?,
        policy,
        identity,
        height,
        &mut expected,
    )?;
    close_height_inventory(&names, &expected, height, budget)?;
    if archive.names_recursive()? != names {
        return Err(invalid("saved history inventory changed"));
    }
    Ok(material)
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use crate::immutable_archive::ArchiveReadLimits;
    use execution::publication::PublicationContext;
    use node_core::ordered_economics::{
        OrderedHistoryComponentRef, encode_ordered_history_height_descriptor,
    };
    use protocol_types::{
        AtomicityDomainId, ChainId, Digest32, Epoch, HashAlgorithmId, ProtocolVersion,
    };

    fn descriptor_claim(height: u64) -> OrderedHistoryHeightDescriptor {
        let digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]);
        OrderedHistoryHeightDescriptor {
            identity: OrderedHistoryIdentity {
                context: PublicationContext::new(
                    ChainId::new("bounded-layout-only").unwrap(),
                    ProtocolVersion::new(1),
                    Epoch::new(2),
                )
                .unwrap(),
                domain: AtomicityDomainId::new([1; 32]).unwrap(),
                genesis_digest: digest,
                anchor: digest,
                through_height: height,
                through_view: 1,
                through_digest: digest,
            },
            height: 1,
            view: 1,
            block_digest: digest,
            components: vec![OrderedHistoryComponentRef {
                kind: OrderedHistoryComponentKind::CommitProof,
                length: 1,
                digest,
            }],
        }
    }

    #[test]
    fn declared_height_limit_precedes_inventory_loop_or_material_allocation() {
        let budget: ArchiveReadBudget = ArchiveReadBudget::new(Default::default()).unwrap();
        let mut identity: OrderedHistoryIdentity = descriptor_claim(1).identity;
        identity.through_height = u64::MAX;
        assert!(check_inventory_layout(&identity, &BTreeSet::new(), &budget).is_err());
        assert!(budget.clone().check().is_err());
    }

    #[test]
    fn actual_descriptor_decodes_charge_shared_repeats_before_allocation() {
        let bytes: Vec<u8> =
            encode_ordered_history_height_descriptor(&descriptor_claim(1)).unwrap();
        let budget: ArchiveReadBudget = ArchiveReadBudget::new(ArchiveReadLimits {
            components: 1,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            decode_bounded_descriptor(&bytes, &budget).unwrap(),
            decode_ordered_history_height_descriptor(&bytes).unwrap()
        );
        assert!(decode_bounded_descriptor(&bytes, &budget.clone()).is_err());
        assert!(budget.check().is_err());
        assert!(decode_bounded_descriptor(&bytes, &budget).is_err());
    }

    #[test]
    fn generated_names_and_full_prefix_subsets_do_not_hide_unrelated_or_empty_surplus() {
        assert_eq!(
            relative_file_limit(
                "height-00000000000000000001/component-01/chunk-00000000000000000000.bin"
            ),
            Some(MAX_ORDERED_HISTORY_CHUNK_BYTES)
        );
        for name in [
            "height-1/descriptor.bin",
            "height-00000000000000000000/descriptor.bin",
            "height-00000000000000000001/component-99/chunk-00000000000000000000.bin",
            "../identity.bin",
        ] {
            assert!(relative_file_limit(name).is_none());
        }
        let budget: ArchiveReadBudget = ArchiveReadBudget::new(Default::default()).unwrap();
        let first: BTreeSet<String> = [
            "height-00000000000000000001/",
            "height-00000000000000000001/descriptor.bin",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let second: BTreeSet<String> = [
            "height-00000000000000000002/",
            "height-00000000000000000002/descriptor.bin",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let mut names: BTreeSet<String> = first.union(&second).cloned().collect();
        // A selected-height transport does NOT claim all unrelated bodies verified.
        close_height_inventory(&names, &first, 1, &budget).unwrap();
        close_height_inventory(&names, &second, 2, &budget).unwrap();
        names.insert("height-00000000000000000002/component-01/".to_owned());
        close_height_inventory(&names, &first, 1, &budget).unwrap();
        assert!(close_height_inventory(&names, &second, 2, &budget).is_err());
        names.insert("foreign-empty/".to_owned());
        assert!(check_inventory_layout(&descriptor_claim(2).identity, &names, &budget).is_err());
    }
}
