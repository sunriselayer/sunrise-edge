//! Bounded immutable pre-Seal cut export and independent saved verification.
//!
//! Filenames, continuation files and completion markers are never authority.
//! Source export derives one opaque capability through the core single
//! capture facade. The saved layout, bounded reader and saved verification
//! are owned by the SDK business_cut_archive module and re-exported here;
//! this module owns only publication.

use crate::immutable_archive::ImmutableArchive;
use hashing::HashSuiteResolver;
#[cfg(test)]
use node_core::business_reconstruction::cut::{
    BusinessCutCollection, MAX_BUSINESS_CUT_CHUNK_BYTES, decode_business_cut_chunk,
};
use node_core::business_reconstruction::{
    BusinessReconstructionPlan,
    cut::{
        BUSINESS_CUT_STREAMS, BusinessCutPage, MAX_BUSINESS_CUT_DESCRIPTOR_BYTES,
        VerifiedBusinessCut, derive_source_business_cut, derive_successor_source_business_cut,
        encode_business_cut_chunk, encode_business_cut_identity, encode_business_cut_package,
        encode_business_cut_page,
    },
};
use node_core::ordered_economics::OrderedHistoryHeightMaterial;
use node_core::serving_authority::LiveWarrant;
use protocol_types::{AtomicityDomainId, Digest32};
use runtime::DurableOperationContext;
#[cfg(test)]
use runtime::WriterFenceGeneration;
use runtime::portable::{
    DurablePortableSnapshotRepository, PortableBlobRepository, PortableSnapshotToken,
};
use std::collections::BTreeSet;
pub use sunrise_edge_client::business_cut_archive::{
    CutArchiveError, CutArchiveLimits, read_business_cut_archive, verify_business_cut_archive,
};
#[cfg(test)]
use sunrise_edge_client::business_cut_archive::{
    MAX_SAVED_CHUNK_BYTES, decode_saved_source_token as read_source_token,
};
use sunrise_edge_client::business_cut_archive::{
    chunk_name, encode_saved_source_token as source_bytes, page_name,
};

mod command;
pub use command::run;

/// Partial means only immutable material was saved; it is not a cut permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CutExportProgress {
    pub cut_digest: Digest32,
    pub package_digest: Digest32,
    pub newly_saved_files: usize,
    pub complete: bool,
}

fn invalid(reason: &'static str) -> CutArchiveError {
    CutArchiveError::Invalid(reason)
}

/// Walks bounded frames in fixed order. Returning false stops publication only;
/// a separate complete walk always revalidates the existing archive first.
fn visit_cut_files(
    cut: &VerifiedBusinessCut,
    resolver: &HashSuiteResolver,
    limits: CutArchiveLimits,
    mut visit: impl FnMut(String, &[u8]) -> Result<bool, CutArchiveError>,
) -> Result<bool, CutArchiveError> {
    let token: &PortableSnapshotToken = cut
        .source_token()
        .ok_or_else(|| invalid("source cut capability has no source token"))?;
    for (name, bytes) in [
        ("source-token.bin", source_bytes(token)?),
        (
            "identity.bin",
            encode_business_cut_identity(cut.identity())?,
        ),
        (
            "package.bin",
            encode_business_cut_package(cut.package_identity())?,
        ),
        ("transfer.bin", limits.transfer_bytes()?),
    ] {
        if !visit(name.to_string(), &bytes)? {
            return Ok(false);
        }
    }
    for collection in BUSINESS_CUT_STREAMS {
        let mut after: Option<Vec<u8>> = None;
        let mut page_index: u64 = 0;
        let mut component_index: u64 = 0;
        loop {
            let page: BusinessCutPage = cut.read_page(
                resolver,
                collection,
                after.as_deref(),
                limits.page_entries(),
            )?;
            let bytes: Vec<u8> = encode_business_cut_page(&page)?;
            if !visit(page_name(collection, page_index), &bytes)? {
                return Ok(false);
            }
            for descriptor in &page.descriptors {
                let mut offset: u64 = 0;
                while offset < descriptor.length {
                    let chunk = cut.read_chunk(descriptor, offset, limits.chunk_bytes())?;
                    let count: u64 = u64::try_from(chunk.bytes.len())
                        .map_err(|_| invalid("chunk range overflow"))?;
                    if count == 0 {
                        return Err(invalid("cut chunk made no progress"));
                    }
                    let bytes: Vec<u8> = encode_business_cut_chunk(&chunk)?;
                    if !visit(chunk_name(collection, component_index, offset), &bytes)? {
                        return Ok(false);
                    }
                    offset = offset
                        .checked_add(count)
                        .ok_or_else(|| invalid("cut chunk offset overflow"))?;
                }
                component_index = component_index
                    .checked_add(1)
                    .ok_or_else(|| invalid("component index overflow"))?;
            }
            if page.terminal {
                break;
            }
            after = Some(
                page.descriptors
                    .last()
                    .ok_or_else(|| invalid("nonterminal cut page is empty"))?
                    .key
                    .clone(),
            );
            page_index = page_index
                .checked_add(1)
                .ok_or_else(|| invalid("cut page index overflow"))?;
        }
    }
    Ok(true)
}

/// Derives one exact source observation and saves at most the configured new
/// work. Every existing byte and the full inventory are checked before writes.
pub fn export_source_business_cut<
    S: DurablePortableSnapshotRepository,
    B: PortableBlobRepository,
>(
    plan: BusinessReconstructionPlan<'_>,
    source: &S,
    source_blobs: &B,
    ordered: &[OrderedHistoryHeightMaterial],
    archive: &ImmutableArchive,
    limits: CutArchiveLimits,
) -> Result<CutExportProgress, CutArchiveError> {
    let operation: DurableOperationContext = plan.operation_context;
    let domain: AtomicityDomainId = plan.domain;
    let resolver: &HashSuiteResolver = plan.genesis_root.genesis_resolver();
    let cut: VerifiedBusinessCut = derive_source_business_cut(plan, source, source_blobs, ordered)?;
    publish_source_cut(&cut, resolver, archive, limits, || {
        let token: &PortableSnapshotToken = cut
            .source_token()
            .ok_or_else(|| invalid("missing source token"))?;
        source.check_portable_outbox_empty_at(&operation, domain, token)?;
        Ok(())
    })
}

/// The same immutable exporter over a current-epoch cut derived by the
/// core's warrant-bound successor source owner. Existing original capture
/// remains in [export_source_business_cut].
pub fn export_successor_source_business_cut<S, B>(
    plan: BusinessReconstructionPlan<'_>,
    warrant: &LiveWarrant<'_>,
    source: &S,
    source_blobs: &B,
    ordered: &[OrderedHistoryHeightMaterial],
    archive: &ImmutableArchive,
    limits: CutArchiveLimits,
) -> Result<CutExportProgress, CutArchiveError>
where
    S: DurablePortableSnapshotRepository + runtime::StructuredStateReader,
    B: PortableBlobRepository,
{
    let operation: DurableOperationContext = plan.operation_context;
    let domain: AtomicityDomainId = plan.domain;
    let resolver: &HashSuiteResolver = plan.genesis_root.genesis_resolver();
    let cut: VerifiedBusinessCut =
        derive_successor_source_business_cut(plan, warrant, source, source_blobs, ordered)?;
    publish_source_cut(&cut, resolver, archive, limits, || {
        let token: &PortableSnapshotToken = cut
            .source_token()
            .ok_or_else(|| invalid("missing successor source token"))?;
        source.check_portable_outbox_empty_at(&operation, domain, token)?;
        Ok(())
    })
}

fn publish_source_cut(
    cut: &VerifiedBusinessCut,
    resolver: &HashSuiteResolver,
    archive: &ImmutableArchive,
    limits: CutArchiveLimits,
    final_source_check: impl FnOnce() -> Result<(), CutArchiveError>,
) -> Result<CutExportProgress, CutArchiveError> {
    let existing: BTreeSet<String> = archive.names()?;
    let mut expected: BTreeSet<String> = BTreeSet::new();
    let mut missing: bool = false;
    visit_cut_files(cut, resolver, limits, |name: String, bytes: &[u8]| {
        if existing.contains(&name) {
            if archive.read(&name, bytes.len())? != bytes {
                return Err(invalid(
                    "saved cut material differs from exact fixed source",
                ));
            }
        } else {
            missing = true;
        }
        expected.insert(name);
        Ok(true)
    })?;
    let complete: Vec<u8> = encode_business_cut_package(cut.package_identity())?;
    expected.insert("complete".to_string());
    if !existing.is_subset(&expected) {
        return Err(invalid("archive contains surplus or foreign components"));
    }
    if existing.contains("complete")
        && (missing || archive.read("complete", MAX_BUSINESS_CUT_DESCRIPTOR_BYTES)? != complete)
    {
        return Err(invalid(
            "saved completion marker differs or hides incomplete material",
        ));
    }
    let maximum_new_files: usize = limits.maximum_new_files().get();
    let mut newly_saved_files: usize = 0;
    let saved_all: bool = visit_cut_files(cut, resolver, limits, |name: String, bytes: &[u8]| {
        if !archive.contains(&name)? && newly_saved_files == maximum_new_files {
            return Ok(false);
        }
        if archive.publish(&name, bytes)? {
            newly_saved_files = newly_saved_files
                .checked_add(1)
                .ok_or_else(|| invalid("publication count overflow"))?;
        }
        Ok(true)
    })?;
    let mut progress: CutExportProgress = CutExportProgress {
        cut_digest: cut.cut_digest(),
        package_digest: cut.package_digest(),
        newly_saved_files,
        complete: false,
    };
    let published: BTreeSet<String> = archive.names()?;
    if !published.is_subset(&expected) {
        return Err(invalid(
            "archive acquired surplus or foreign components during publication",
        ));
    }
    if !saved_all {
        return Ok(progress);
    }
    let mut expected_present: BTreeSet<String> = expected.clone();
    if !published.contains("complete") {
        expected_present.remove("complete");
    }
    if published != expected_present {
        return Err(invalid("archive lost required material during publication"));
    }
    visit_cut_files(cut, resolver, limits, |name: String, bytes: &[u8]| {
        if archive.read(&name, bytes.len())? != bytes {
            return Err(invalid("archive changed before final source check"));
        }
        Ok(true)
    })?;
    // The source token is checked after all payload files, on every invocation,
    // even when a previous marker is present. A marker is never a short circuit.
    final_source_check()?;
    if !archive.contains("complete")? && newly_saved_files == maximum_new_files {
        return Ok(progress);
    }
    if archive.publish("complete", &complete)? {
        newly_saved_files = newly_saved_files
            .checked_add(1)
            .ok_or_else(|| invalid("publication count overflow"))?;
    }
    if archive.names()? != expected {
        return Err(invalid("archive inventory changed while finalizing"));
    }
    progress.newly_saved_files = newly_saved_files;
    progress.complete = true;
    Ok(progress)
}

#[cfg(test)]
mod tests;
