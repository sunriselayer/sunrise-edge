//! Saved pre-Seal business-cut archive layout and bounded reader, shared by
//! the operator writer and successor clients.
//!
//! Filenames, continuation files and completion markers are never
//! authority. The reader parses exact bounded transport and checks the
//! complete inventory; the owning node-core verifier re-executes the proof
//! closure under the caller pins. The operator publication writer uses the
//! same layout functions; nothing here writes.

use crate::immutable_archive::ImmutableArchiveReader;
use node_core::business_reconstruction::{
    BusinessReconstructionPlan,
    cut::{
        BUSINESS_CUT_STREAMS, BusinessCutCollection, BusinessCutError, BusinessCutIdentity,
        BusinessCutPackageIdentity, BusinessCutPage, BusinessCutPageVerifier,
        MAX_BUSINESS_CUT_CHUNK_BYTES, MAX_BUSINESS_CUT_DESCRIPTOR_BYTES,
        MAX_BUSINESS_CUT_PAGE_BYTES, MAX_BUSINESS_CUT_PAGE_ENTRIES, SavedBusinessCut,
        SavedBusinessCutComponent, VerifiedBusinessCut, decode_business_cut_chunk,
        decode_business_cut_identity, decode_business_cut_package, decode_business_cut_page,
        encode_business_cut_package, verify_saved_business_cut,
    },
};
use protocol_types::AtomicityDomainId;
use runtime::WriterFenceGeneration;
use runtime::portable::{
    MAX_PORTABLE_SNAPSHOT_NAMESPACE_BYTES, PortableSnapshotError, PortableSnapshotToken,
};
use std::{collections::BTreeSet, error::Error, fmt, io, num::NonZeroUsize};

const SOURCE_MAGIC: &[u8] = b"sunrise-business-cut-source-v1\0";
/// Exact saved transfer-settings length.
pub const TRANSFER_BYTES: usize = 6;
/// Bound on the saved source-token file.
pub const MAX_SOURCE_BYTES: usize =
    SOURCE_MAGIC.len() + 2 + MAX_PORTABLE_SNAPSHOT_NAMESPACE_BYTES + 32 + 16;
/// A canonical chunk also includes a bounded descriptor and framing fields.
pub const MAX_SAVED_CHUNK_BYTES: usize =
    MAX_BUSINESS_CUT_CHUNK_BYTES + MAX_BUSINESS_CUT_DESCRIPTOR_BYTES + 1024;

/// Invocation-local publication bound, not a total history/component ceiling.
#[derive(Clone, Copy, Debug)]
pub struct CutArchiveLimits {
    page_entries: NonZeroUsize,
    chunk_bytes: NonZeroUsize,
    maximum_new_files: NonZeroUsize,
}

impl CutArchiveLimits {
    /// Every newly saved file counts, including pins, pages and the marker.
    pub fn new(
        page_entries: usize,
        chunk_bytes: usize,
        maximum_new_files: usize,
    ) -> Result<Self, CutArchiveError> {
        if !(1..=MAX_BUSINESS_CUT_PAGE_ENTRIES).contains(&page_entries)
            || !(1..=MAX_BUSINESS_CUT_CHUNK_BYTES).contains(&chunk_bytes)
            || !(1..=4096).contains(&maximum_new_files)
        {
            return Err(invalid("cut archive invocation bounds are invalid"));
        }
        Ok(Self {
            page_entries: NonZeroUsize::new(page_entries)
                .ok_or_else(|| invalid("zero page bound"))?,
            chunk_bytes: NonZeroUsize::new(chunk_bytes)
                .ok_or_else(|| invalid("zero chunk bound"))?,
            maximum_new_files: NonZeroUsize::new(maximum_new_files)
                .ok_or_else(|| invalid("zero publication bound"))?,
        })
    }

    /// Entries per saved page.
    #[must_use]
    pub const fn page_entries(self) -> NonZeroUsize {
        self.page_entries
    }
    /// Payload bytes per saved chunk.
    #[must_use]
    pub const fn chunk_bytes(self) -> NonZeroUsize {
        self.chunk_bytes
    }
    /// New files one publication invocation may save.
    #[must_use]
    pub const fn maximum_new_files(self) -> NonZeroUsize {
        self.maximum_new_files
    }

    /// Exact saved transfer-settings bytes.
    pub fn transfer_bytes(self) -> Result<Vec<u8>, CutArchiveError> {
        let page: u16 =
            u16::try_from(self.page_entries.get()).map_err(|_| invalid("page bound overflow"))?;
        let chunk: u32 =
            u32::try_from(self.chunk_bytes.get()).map_err(|_| invalid("chunk bound overflow"))?;
        let mut bytes: Vec<u8> = page.to_be_bytes().to_vec();
        bytes.extend_from_slice(&chunk.to_be_bytes());
        Ok(bytes)
    }

    /// Parses saved transfer settings under the same invocation bounds.
    pub fn from_transfer_bytes(bytes: &[u8]) -> Result<Self, CutArchiveError> {
        if bytes.len() != TRANSFER_BYTES {
            return Err(invalid("saved transfer settings have wrong length"));
        }
        let page: u16 = u16::from_be_bytes([bytes[0], bytes[1]]);
        let chunk: u32 = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        Self::new(
            usize::from(page),
            usize::try_from(chunk).map_err(|_| invalid("saved chunk bound overflow"))?,
            1,
        )
    }
}

/// Closed saved-cut archive failure.
#[derive(Debug)]
pub enum CutArchiveError {
    Invalid(&'static str),
    Io(io::Error),
    Core(BusinessCutError),
    Source(PortableSnapshotError),
}
impl fmt::Display for CutArchiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(formatter, "business cut archive refused: {reason}"),
            Self::Io(error) => error.fmt(formatter),
            Self::Core(error) => error.fmt(formatter),
            Self::Source(error) => error.fmt(formatter),
        }
    }
}
impl Error for CutArchiveError {}
impl From<io::Error> for CutArchiveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<BusinessCutError> for CutArchiveError {
    fn from(error: BusinessCutError) -> Self {
        Self::Core(error)
    }
}
impl From<PortableSnapshotError> for CutArchiveError {
    fn from(error: PortableSnapshotError) -> Self {
        Self::Source(error)
    }
}
fn invalid(reason: &'static str) -> CutArchiveError {
    CutArchiveError::Invalid(reason)
}

/// Exact saved local source-token frame.
pub fn encode_saved_source_token(token: &PortableSnapshotToken) -> Result<Vec<u8>, CutArchiveError> {
    let mut bytes: Vec<u8> = SOURCE_MAGIC.to_vec();
    bytes.extend_from_slice(
        &u16::try_from(token.namespace().len())
            .map_err(|_| invalid("source namespace overflow"))?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(token.namespace());
    bytes.extend_from_slice(token.domain().as_bytes());
    bytes.extend_from_slice(&token.writer_fence().get().to_be_bytes());
    bytes.extend_from_slice(&token.mutation_sequence().to_be_bytes());
    Ok(bytes)
}

/// Parses one exact saved source-token frame. Never authority.
pub fn decode_saved_source_token(bytes: &[u8]) -> Result<PortableSnapshotToken, CutArchiveError> {
    if !bytes.starts_with(SOURCE_MAGIC) || bytes.len() < SOURCE_MAGIC.len() + 2 {
        return Err(invalid("saved source token frame differs"));
    }
    let position: usize = SOURCE_MAGIC.len();
    let namespace_length: usize =
        usize::from(u16::from_be_bytes([bytes[position], bytes[position + 1]]));
    let position: usize = position + 2;
    let end: usize = position
        .checked_add(namespace_length)
        .ok_or_else(|| invalid("source namespace range overflow"))?;
    if namespace_length == 0
        || namespace_length > MAX_PORTABLE_SNAPSHOT_NAMESPACE_BYTES
        || bytes.len() != end + 48
    {
        return Err(invalid("saved source token length differs"));
    }
    let domain: AtomicityDomainId = AtomicityDomainId::new(
        bytes[end..end + 32]
            .try_into()
            .map_err(|_| invalid("saved source domain length differs"))?,
    )
    .map_err(|_| invalid("saved source domain invalid"))?;
    let fence: u64 = u64::from_be_bytes(
        bytes[end + 32..end + 40]
            .try_into()
            .map_err(|_| invalid("saved source fence length differs"))?,
    );
    let sequence: u64 = u64::from_be_bytes(
        bytes[end + 40..end + 48]
            .try_into()
            .map_err(|_| invalid("saved source sequence length differs"))?,
    );
    let fence: WriterFenceGeneration =
        WriterFenceGeneration::new(fence).ok_or_else(|| invalid("saved source fence invalid"))?;
    PortableSnapshotToken::new(bytes[position..end].to_vec(), domain, fence, sequence)
        .map_err(|_| invalid("saved source token invalid"))
}

/// Saved page filename.
#[must_use]
pub fn page_name(collection: BusinessCutCollection, index: u64) -> String {
    format!("page-{:02}-{index:020}.bin", collection as u16)
}

/// Saved chunk filename.
#[must_use]
pub fn chunk_name(collection: BusinessCutCollection, component: u64, offset: u64) -> String {
    format!("chunk-{:02}-{component:020}-{offset:020}.bin", collection as u16)
}

/// Independently verifies a complete immutable saved cut under local pins.
/// Neither the local source token nor the marker can authorize reconstruction.
pub fn verify_business_cut_archive(
    plan: BusinessReconstructionPlan<'_>,
    archive: &ImmutableArchiveReader,
) -> Result<VerifiedBusinessCut, CutArchiveError> {
    let saved: SavedBusinessCut = read_business_cut_archive(&plan, archive)?;
    verify_saved_business_cut(plan, &saved).map_err(CutArchiveError::from)
}

/// Parses and verifies exact bounded transport, not business authority.
/// Import must independently execute it through its opaque core plan factory.
pub fn read_business_cut_archive(
    plan: &BusinessReconstructionPlan<'_>,
    archive: &ImmutableArchiveReader,
) -> Result<SavedBusinessCut, CutArchiveError> {
    let identity: BusinessCutIdentity = decode_business_cut_identity(
        &archive.read("identity.bin", MAX_BUSINESS_CUT_DESCRIPTOR_BYTES)?,
    )?;
    let package: BusinessCutPackageIdentity = decode_business_cut_package(
        &archive.read("package.bin", MAX_BUSINESS_CUT_DESCRIPTOR_BYTES)?,
    )?;
    let limits: CutArchiveLimits =
        CutArchiveLimits::from_transfer_bytes(&archive.read("transfer.bin", TRANSFER_BYTES)?)?;
    let token: PortableSnapshotToken =
        decode_saved_source_token(&archive.read("source-token.bin", MAX_SOURCE_BYTES)?)?;
    if token.domain() != plan.domain {
        return Err(invalid("saved source token belongs to a foreign domain"));
    }
    let mut expected: BTreeSet<String> = [
        "identity.bin",
        "package.bin",
        "transfer.bin",
        "source-token.bin",
        "complete",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    let mut components: Vec<SavedBusinessCutComponent> = Vec::new();
    for collection in BUSINESS_CUT_STREAMS {
        let mut page_verifier: BusinessCutPageVerifier = BusinessCutPageVerifier::new(
            plan.genesis_root.genesis_resolver(),
            &identity,
            &package,
            collection,
        )?;
        let mut page_index: u64 = 0;
        let mut component_index: u64 = 0;
        loop {
            let name: String = page_name(collection, page_index);
            let page: BusinessCutPage =
                decode_business_cut_page(&archive.read(&name, MAX_BUSINESS_CUT_PAGE_BYTES)?)?;
            expected.insert(name);
            if page.collection != collection || page.descriptors.len() > limits.page_entries.get() {
                return Err(invalid("saved cut page has foreign collection or sizing"));
            }
            page_verifier.push_page(plan.genesis_root.genesis_resolver(), &page)?;
            for descriptor in &page.descriptors {
                let mut bytes: Vec<u8> = Vec::new();
                let mut offset: u64 = 0;
                while offset < descriptor.length {
                    let name: String = chunk_name(collection, component_index, offset);
                    let chunk =
                        decode_business_cut_chunk(&archive.read(&name, MAX_SAVED_CHUNK_BYTES)?)?;
                    expected.insert(name);
                    let count: u64 = u64::from(
                        u32::try_from(limits.chunk_bytes.get())
                            .map_err(|_| invalid("saved chunk bound overflow"))?,
                    )
                    .min(descriptor.length - offset);
                    if chunk.cut_digest != page.cut_digest
                        || chunk.package_digest != page.package_digest
                        || chunk.descriptor != *descriptor
                        || chunk.offset != offset
                        || chunk.total_length != descriptor.length
                        || chunk.bytes.len() as u64 != count
                    {
                        return Err(invalid(
                            "saved cut chunk is foreign, reordered, substituted or truncated",
                        ));
                    }
                    bytes.extend_from_slice(&chunk.bytes);
                    offset = offset
                        .checked_add(count)
                        .ok_or_else(|| invalid("saved chunk cursor overflow"))?;
                }
                components.push(SavedBusinessCutComponent {
                    descriptor: descriptor.clone(),
                    bytes,
                });
                component_index = component_index
                    .checked_add(1)
                    .ok_or_else(|| invalid("saved component index overflow"))?;
            }
            if page.terminal {
                break;
            }
            page_index = page_index
                .checked_add(1)
                .ok_or_else(|| invalid("saved page cursor overflow"))?;
        }
        page_verifier.finish()?;
    }
    if archive.names()? != expected {
        return Err(invalid("saved cut has missing, surplus or foreign files"));
    }
    if archive.read("complete", MAX_BUSINESS_CUT_DESCRIPTOR_BYTES)?
        != encode_business_cut_package(&package)?
    {
        return Err(invalid("saved cut completion marker differs"));
    }
    let saved: SavedBusinessCut = SavedBusinessCut {
        identity,
        package,
        components,
    };
    Ok(saved)
}
