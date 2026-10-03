//! Independent, read-only verification of saved `history-export` files.
//! A completion marker or saved cursor is never accepted instead of replaying
//! the complete pinned prefix. This API authenticates ordering, not effects.

use node_core::ordered_economics::{
    MAX_ORDERED_HISTORY_CHUNK_BYTES, MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES, OrderedEconomicsPolicy,
    OrderedHistoryComponentKind, OrderedHistoryHeightMaterial, OrderedHistoryIdentity,
    OrderedHistoryVerifier, decode_ordered_history_height_descriptor,
    decode_ordered_history_identity, ordered_history_component_digest,
};
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
