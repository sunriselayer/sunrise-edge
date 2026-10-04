//! DR-0175 first-outgoing-epoch pre-Seal candidate cut.
//!
//! Only private deterministic reconstruction can create a verified capability.
//! Encoded identities, pages, descriptors and saved bytes are untrusted claims.
//! There is deliberately no installation, signing, readiness or activation API.
//! In-memory verification has linear history/material cost; every transfer
//! component, page and chunk is individually bounded, not the total history.

use super::{
    BusinessReconstructionError, BusinessReconstructionOverlay, BusinessReconstructionPlan,
    DrainSetControlMaterial, OwnedPublicationMaterial,
};
use crate::fast_path::records::FastPathValidatorEntry;
use crate::ordered_economics::{
    OrderedCandidate, OrderedHistoryHeightMaterial, OrderedHistoryIdentity,
};
use canonical_encoding::{CanonicalStruct, decode_digest32, encode_digest32};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use protocol_types::{AtomicityDomainId, Digest32, ExecutionGeneration, HashPurpose};
use runtime::portable::{
    DurablePortableSnapshotRepository, PortableBlobRepository, PortableSnapshotToken,
};
use std::{collections::BTreeMap, error::Error, fmt, num::NonZeroUsize};

mod codec;
mod derive;
pub(super) mod proof;
mod source;
#[cfg(test)]
mod tests;
mod transfer;
pub use codec::{
    decode_business_cut_chunk, decode_business_cut_descriptor, decode_business_cut_identity,
    decode_business_cut_package, decode_business_cut_page, encode_business_cut_chunk,
    encode_business_cut_descriptor, encode_business_cut_identity, encode_business_cut_package,
    encode_business_cut_page,
};
pub use transfer::BusinessCutPageVerifier;

/// Bound for an identity, package summary or one component descriptor.
pub const MAX_BUSINESS_CUT_DESCRIPTOR_BYTES: usize = 16 * 1024;
/// Maximum descriptors in one page, independent of total history size.
pub const MAX_BUSINESS_CUT_PAGE_ENTRIES: usize = 128;
/// Maximum complete canonical page bytes.
pub const MAX_BUSINESS_CUT_PAGE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum payload bytes in one chunk.
pub const MAX_BUSINESS_CUT_CHUNK_BYTES: usize = 1024 * 1024;
/// Closed transfer streams, including empty terminal streams.
pub const BUSINESS_CUT_STREAMS: [BusinessCutCollection; 7] = [
    BusinessCutCollection::State,
    BusinessCutCollection::Receipts,
    BusinessCutCollection::ObjectHeads,
    BusinessCutCollection::ObjectVersions,
    BusinessCutCollection::AuthorityCompanions,
    BusinessCutCollection::Artifacts,
    BusinessCutCollection::Proofs,
];

/// Explicit canonical collection order. The last three are not business rows
/// that an importer may restore; no importer exists in this capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum BusinessCutCollection {
    State = 1,
    Receipts = 2,
    ObjectHeads = 3,
    ObjectVersions = 4,
    AuthorityCompanions = 5,
    Artifacts = 6,
    Proofs = 7,
}

impl BusinessCutCollection {
    /// Refuses an unknown stream before body allocation or source I/O.
    pub fn from_wire(value: u16) -> Result<Self, BusinessCutError> {
        BUSINESS_CUT_STREAMS
            .into_iter()
            .find(|kind| *kind as u16 == value)
            .ok_or(invalid("unknown business cut collection"))
    }
}

/// A count and terminal accumulator. A root by itself is not authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessCutCollectionRoot {
    pub collection: BusinessCutCollection,
    pub count: u64,
    pub root: Digest32,
}

/// Semantic candidate identity, not a finalized global cut decision. Public
/// fields are transport claims until independently re-derived under local pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessCutIdentity {
    pub context: PublicationContext,
    pub domain: AtomicityDomainId,
    pub genesis_digest: Digest32,
    pub validator_set_digest: Digest32,
    pub ordered_history: OrderedHistoryIdentity,
    pub drain_request_id: [u8; 32],
    pub drain_block_height: u64,
    pub drain_candidate_digest: Digest32,
    pub drain_union: consensus::DrainUnionIdentity,
    pub generation_floor: ExecutionGeneration,
    /// Exactly State, Receipts, ObjectHeads, ObjectVersions, in that order.
    pub business: [BusinessCutCollectionRoot; 4],
    pub artifacts: BusinessCutCollectionRoot,
}

/// Exact package integrity is intentionally distinct from semantic identity.
/// The final manifest is not an entry in its own accumulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessCutPackageIdentity {
    pub cut_digest: Digest32,
    /// All seven terminal stream roots, including exact companion/proof bytes.
    pub streams: [BusinessCutCollectionRoot; 7],
    pub component_count: u64,
    pub accumulator: Digest32,
}

/// No large body is nested in this small descriptor. Metadata is one closed
/// DR-0175 frame, never a raw portable descriptor carrying physical revisions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessCutComponentDescriptor {
    pub collection: BusinessCutCollection,
    /// Natural byte key within the explicit collection; numeric suffixes are BE.
    pub key: Vec<u8>,
    pub metadata: Vec<u8>,
    pub length: u64,
    pub digest: Digest32,
}

/// Bounded, consecutive descriptors for one of the seven streams.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessCutPage {
    pub cut_digest: Digest32,
    pub package_digest: Digest32,
    pub collection: BusinessCutCollection,
    pub after_key: Option<Vec<u8>>,
    pub previous_accumulator: Digest32,
    pub descriptors: Vec<BusinessCutComponentDescriptor>,
    pub accumulator: Digest32,
    pub terminal: bool,
}

/// One exact bounded byte range. Partial chunk integrity does not authenticate
/// business execution; complete saved verification reconstructs independently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessCutChunk {
    pub cut_digest: Digest32,
    pub package_digest: Digest32,
    pub descriptor: BusinessCutComponentDescriptor,
    pub offset: u64,
    pub total_length: u64,
    pub bytes: Vec<u8>,
}

/// Untrusted saved transport material; no verified constructor from this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedBusinessCutComponent {
    pub descriptor: BusinessCutComponentDescriptor,
    pub bytes: Vec<u8>,
}

/// Linear assembled material for local verification, never a wire superframe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedBusinessCut {
    pub identity: BusinessCutIdentity,
    pub package: BusinessCutPackageIdentity,
    /// Strict stream/key order, no duplicates or omitted empty stream roots.
    pub components: Vec<SavedBusinessCutComponent>,
}

/// Opaque private-derivation capability. It cannot authorize live mutations.
pub struct VerifiedBusinessCut {
    identity: BusinessCutIdentity,
    package: BusinessCutPackageIdentity,
    cut_digest: Digest32,
    package_digest: Digest32,
    source_token: Option<PortableSnapshotToken>,
    components: BTreeMap<(BusinessCutCollection, Vec<u8>), SavedBusinessCutComponent>,
    /// Verified prefix index; each read page folds only its bounded entries.
    prefix_accumulators: BTreeMap<(BusinessCutCollection, Vec<u8>), Digest32>,
}

impl VerifiedBusinessCut {
    #[must_use]
    pub const fn identity(&self) -> &BusinessCutIdentity {
        &self.identity
    }
    #[must_use]
    pub const fn package_identity(&self) -> &BusinessCutPackageIdentity {
        &self.package
    }
    #[must_use]
    pub const fn cut_digest(&self) -> Digest32 {
        self.cut_digest
    }
    #[must_use]
    pub const fn package_digest(&self) -> Digest32 {
        self.package_digest
    }
    /// Source-local continuity only, deliberately outside both cross-node roots.
    #[must_use]
    pub const fn source_token(&self) -> Option<&PortableSnapshotToken> {
        self.source_token.as_ref()
    }
    /// Exact immutable lookup, not an arbitrary claimed descriptor permission.
    pub fn descriptor(
        &self,
        collection: BusinessCutCollection,
        key: &[u8],
    ) -> Result<&BusinessCutComponentDescriptor, BusinessCutError> {
        self.components
            .get(&(collection, key.to_vec()))
            .map(|item| &item.descriptor)
            .ok_or(invalid("business cut component key is absent"))
    }
    pub fn read_page(
        &self,
        resolver: &HashSuiteResolver,
        collection: BusinessCutCollection,
        after_key: Option<&[u8]>,
        limit: NonZeroUsize,
    ) -> Result<BusinessCutPage, BusinessCutError> {
        transfer::read_page(self, resolver, collection, after_key, limit)
    }
    pub fn read_chunk(
        &self,
        descriptor: &BusinessCutComponentDescriptor,
        offset: u64,
        limit: NonZeroUsize,
    ) -> Result<BusinessCutChunk, BusinessCutError> {
        transfer::read_chunk(self, descriptor, offset, limit)
    }
}

/// Captures exactly once under the backend token, privately derives every
/// prerequisite, compares the complete source, and rechecks that original token.
pub fn derive_source_business_cut<
    S: DurablePortableSnapshotRepository + ?Sized,
    B: PortableBlobRepository + ?Sized,
>(
    plan: BusinessReconstructionPlan<'_>,
    source: &S,
    source_blobs: &B,
    ordered: &[OrderedHistoryHeightMaterial],
) -> Result<VerifiedBusinessCut, BusinessCutError> {
    let base: crate::serving_authority::ReconstructionBase<'_> =
        crate::serving_authority::ReconstructionBase::genesis(plan.genesis_root);
    derive_source_cut_with_base(plan, base, source, source_blobs, ordered, None, None)
}

/// Source cut for the current epoch of a freshly resolved issuer-bound
/// warrant. The base and current policies come only from its verified chain.
pub fn derive_successor_source_business_cut<S, B>(
    plan: BusinessReconstructionPlan<'_>,
    warrant: &crate::serving_authority::LiveWarrant<'_>,
    source: &S,
    source_blobs: &B,
    ordered: &[OrderedHistoryHeightMaterial],
) -> Result<VerifiedBusinessCut, BusinessCutError>
where
    S: DurablePortableSnapshotRepository + runtime::StructuredStateReader + ?Sized,
    B: PortableBlobRepository + ?Sized,
{
    warrant
        .require_reader(source, &plan.operation_context, plan.domain)
        .map_err(|_| invalid("successor source differs from warrant issuer"))?;
    let inputs: crate::serving_authority::ReconstructionInputs = warrant
        .reconstruction_inputs(&plan)
        .map_err(|_| invalid("source plan differs from verified chain"))?;
    let base: crate::serving_authority::ReconstructionBase<'_> = warrant
        .reconstruction_base(plan.genesis_root)
        .map_err(|_| invalid("source base differs from verified chain"))?;
    let identity: OrderedHistoryIdentity = plan.ordered_history_identity.clone();
    derive_source_cut_with_base(
        inputs.plan(plan, &identity),
        base,
        source,
        source_blobs,
        ordered,
        None,
        None,
    )
}

/// Seal signing retains the ordinary empty-three-chain terminal while
/// additionally deciding successor eligibility on that exact private replay.
pub(crate) fn derive_source_business_cut_for_seal_signing<
    'p,
    S: DurablePortableSnapshotRepository + ?Sized,
    B: PortableBlobRepository + ?Sized,
>(
    plan: BusinessReconstructionPlan<'p>,
    base: crate::serving_authority::ReconstructionBase<'p>,
    source: &S,
    source_blobs: &B,
    ordered: &[OrderedHistoryHeightMaterial],
    next_members: &[FastPathValidatorEntry],
) -> Result<VerifiedBusinessCut, BusinessCutError> {
    derive_source_cut_with_base(
        plan,
        base,
        source,
        source_blobs,
        ordered,
        Some(next_members),
        None,
    )
}

/// One source capture and one independent reconstruction for every source
/// cut consumer. Eligibility and the acceptance terminal remain private.
fn derive_source_cut_with_base<
    'p,
    S: DurablePortableSnapshotRepository + ?Sized,
    B: PortableBlobRepository + ?Sized,
>(
    plan: BusinessReconstructionPlan<'p>,
    base: crate::serving_authority::ReconstructionBase<'p>,
    source: &S,
    source_blobs: &B,
    ordered: &[OrderedHistoryHeightMaterial],
    next_members: Option<&[FastPathValidatorEntry]>,
    seal: Option<derive::SealAcceptanceCandidate<'_>>,
) -> Result<VerifiedBusinessCut, BusinessCutError> {
    let verified_scopes: Vec<crate::ordered_economics::OrderedKeyScope> = base
        .scopes(plan.domain)
        .map_err(|_| invalid("source scopes differ from verified chain"))?;
    let scopes: source::CaptureScopes<'_> = source::CaptureScopes {
        chain: base.context().chain_id(),
        verified: &verified_scopes,
    };
    let snapshot: super::SourceBusinessSnapshot = source::capture_scoped(
        source,
        source_blobs,
        &plan.operation_context,
        plan.domain,
        Some(&scopes),
    )?;
    let operation = plan.operation_context;
    let domain: AtomicityDomainId = plan.domain;
    let mut overlay: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new_with_base(plan, base)?;
    let current: super::SourceBusinessSnapshot = overlay.current_snapshot(&snapshot)?;
    let owned: Vec<OwnedPublicationMaterial> =
        super::owned_material_from_source_snapshot(&current, &overlay.plan)?;
    let controls: Vec<DrainSetControlMaterial> =
        super::drain_control_material_from_source_snapshot(&current, &overlay.plan, ordered)
            .map_err(|_| invalid("source control closure could not be authenticated"))?;
    overlay.reconstruct_with_control_material(&owned, ordered, &controls)?;
    overlay.compare_source(&snapshot)?;
    if let Some(next_members) = next_members {
        super::projection::check_reconstructed_next_set_eligibility(&overlay, next_members)?;
    }
    let carriers = proof::source_application_carriers(&overlay, &snapshot)?;
    let mut cut: VerifiedBusinessCut = match seal {
        None => derive::from_overlay(&overlay, &owned, ordered, &controls, &carriers, None)?,
        Some(seal) => derive::from_overlay_for_seal_acceptance(
            &overlay, &owned, ordered, &controls, &carriers, seal,
        )?,
    };
    source
        .check_portable_outbox_empty_at(&operation, domain, &snapshot.token)
        .map_err(|_| invalid("source snapshot changed before cut derivation finished"))?;
    cut.source_token = Some(snapshot.token);
    Ok(cut)
}

/// DR-0187 private acceptance-only business closure. Reuses the exact same
/// token-covered source capture, independent execution, source comparison,
/// drain/body closure, generation floor and business/artifact root
/// derivations as `derive_source_business_cut`; it substitutes only the
/// terminal rule: the authenticated prior tip at the fixed target of
/// `ordered` must be committed empty, its direct child must be exactly
/// `seal_candidate` as its sole transaction, and its grandchild must be
/// empty. A lagging source must first apply the authenticated h+1
/// certificate through existing ordinary recovery; this verifier cannot
/// skip that prerequisite.
///
/// This is private read-only preparation, not a new public cut/import
/// producer: ordinary source export, saved cut, import and readiness keep
/// their original empty-three-chain check unchanged. The owning original
/// completion supplies the exact authenticated block being accepted.
#[cfg(test)]
pub(crate) fn verify_live_seal_closure<
    S: DurablePortableSnapshotRepository + ?Sized,
    B: PortableBlobRepository + ?Sized,
>(
    plan: BusinessReconstructionPlan<'_>,
    source: &S,
    source_blobs: &B,
    ordered: &[OrderedHistoryHeightMaterial],
    seal_candidate: &OrderedCandidate,
    seal_block_digest: Digest32,
    next_members: &[FastPathValidatorEntry],
) -> Result<VerifiedBusinessCut, BusinessCutError> {
    let base: crate::serving_authority::ReconstructionBase<'_> =
        crate::serving_authority::ReconstructionBase::genesis(plan.genesis_root);
    verify_live_seal_closure_with_base(
        plan,
        base,
        source,
        source_blobs,
        ordered,
        seal_candidate,
        seal_block_digest,
        next_members,
    )
}

pub(crate) fn verify_live_seal_closure_with_base<
    'p,
    S: DurablePortableSnapshotRepository + ?Sized,
    B: PortableBlobRepository + ?Sized,
>(
    plan: BusinessReconstructionPlan<'p>,
    base: crate::serving_authority::ReconstructionBase<'p>,
    source: &S,
    source_blobs: &B,
    ordered: &[OrderedHistoryHeightMaterial],
    seal_candidate: &OrderedCandidate,
    seal_block_digest: Digest32,
    next_members: &[FastPathValidatorEntry],
) -> Result<VerifiedBusinessCut, BusinessCutError> {
    let seal_candidate_digest: Digest32 = plan
        .ordered_policy
        .candidate_digest(seal_candidate)
        .map_err(|_| invalid("seal acceptance candidate digest"))?;
    derive_source_cut_with_base(
        plan,
        base,
        source,
        source_blobs,
        ordered,
        Some(next_members),
        Some(derive::SealAcceptanceCandidate {
            candidate: seal_candidate,
            candidate_digest: seal_candidate_digest,
            block_digest: seal_block_digest,
        }),
    )
}
/// Independent immutable saved verification. Only the supplied locally pinned
/// plan chooses genesis/context/domain/history. Saved outcome/receipt companions
/// are checked against actual private execution, never installed as effects.
pub fn verify_saved_business_cut(
    plan: BusinessReconstructionPlan<'_>,
    saved: &SavedBusinessCut,
) -> Result<VerifiedBusinessCut, BusinessCutError> {
    proof::verify_saved(plan, saved)
}

/// DR-0191 scope-aware capture seam for the private reconstruction-base
/// postcondition: rows of exactly the verified successor scopes are
/// admitted, every other epoch-scoped row refuses.
pub(crate) fn capture_scoped_target<
    S: DurablePortableSnapshotRepository + ?Sized,
    B: PortableBlobRepository + ?Sized,
>(
    store: &S,
    blobs: &B,
    operation: &runtime::DurableOperationContext,
    domain: AtomicityDomainId,
    scopes: &source::CaptureScopes<'_>,
) -> Result<super::SourceBusinessSnapshot, BusinessCutError> {
    source::capture_scoped(store, blobs, operation, domain, Some(scopes))
}

pub(crate) use source::CaptureScopes;

/// NodeEvent-purpose digest under the pinned committed suite. This authenticates
/// neither a supplied identity nor a response; it is exact transfer integrity.
pub fn business_cut_identity_digest(
    resolver: &HashSuiteResolver,
    identity: &BusinessCutIdentity,
) -> Result<Digest32, BusinessCutError> {
    hash(
        resolver,
        &identity.context,
        &encode_business_cut_identity(identity)?,
    )
}
pub fn business_cut_package_digest(
    resolver: &HashSuiteResolver,
    identity: &BusinessCutIdentity,
    package: &BusinessCutPackageIdentity,
) -> Result<Digest32, BusinessCutError> {
    if package.cut_digest != business_cut_identity_digest(resolver, identity)? {
        return Err(invalid("package differs from semantic cut identity"));
    }
    hash(
        resolver,
        &identity.context,
        &encode_business_cut_package(package)?,
    )
}

/// Exact body integrity, framed in fixed 1 MiB ranges so a legal 32 MiB body
/// never requires an oversized enclosing canonical frame. Digest segmentation
/// is fixed and independent of the operator's chosen transfer chunk size.
pub fn business_cut_component_digest(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    bytes: &[u8],
) -> Result<Digest32, BusinessCutError> {
    let mut seed: CanonicalStruct = CanonicalStruct::new(0x64BC, 1);
    seed.field_u64(
        1,
        u64::try_from(bytes.len()).map_err(|_| invalid("cut body length overflow"))?,
    )?;
    let mut accumulator: Digest32 = hash(resolver, context, &seed.finish()?)?;
    let mut offset: u64 = 0;
    for chunk in bytes.chunks(MAX_BUSINESS_CUT_CHUNK_BYTES) {
        let mut frame: CanonicalStruct = CanonicalStruct::new(0x64BB, 1);
        frame.field_bytes(1, encode_digest32(&accumulator)?)?;
        frame.field_u64(2, offset)?;
        frame.field_bytes(3, chunk.to_vec())?;
        accumulator = hash(resolver, context, &frame.finish()?)?;
        offset = offset
            .checked_add(
                u64::try_from(chunk.len())
                    .map_err(|_| invalid("cut body chunk length overflow"))?,
            )
            .ok_or(invalid("cut body digest range overflow"))?;
    }
    Ok(accumulator)
}

/// Closed-profile, transfer or source-continuity refusal.
#[derive(Debug)]
pub enum BusinessCutError {
    Invalid(&'static str),
    Reconstruction(Box<BusinessReconstructionError>),
    Encoding(canonical_encoding::CanonicalEncodingError),
    Decoding(canonical_encoding::CanonicalDecodingError),
}
impl fmt::Display for BusinessCutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "business cut refused: {reason}"),
            Self::Reconstruction(error) => error.fmt(f),
            Self::Encoding(error) => error.fmt(f),
            Self::Decoding(error) => error.fmt(f),
        }
    }
}
impl Error for BusinessCutError {}
impl From<BusinessReconstructionError> for BusinessCutError {
    fn from(error: BusinessReconstructionError) -> Self {
        Self::Reconstruction(Box::new(error))
    }
}
impl From<canonical_encoding::CanonicalEncodingError> for BusinessCutError {
    fn from(error: canonical_encoding::CanonicalEncodingError) -> Self {
        Self::Encoding(error)
    }
}
impl From<canonical_encoding::CanonicalDecodingError> for BusinessCutError {
    fn from(error: canonical_encoding::CanonicalDecodingError) -> Self {
        Self::Decoding(error)
    }
}
fn invalid(reason: &'static str) -> BusinessCutError {
    BusinessCutError::Invalid(reason)
}
fn hash(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    bytes: &[u8],
) -> Result<Digest32, BusinessCutError> {
    if resolver.chain_id() != context.chain_id()
        || resolver.protocol_version() != context.protocol_version()
    {
        return Err(invalid("business cut hash context differs"));
    }
    resolver
        .hash_for_purpose(context.epoch(), HashPurpose::NodeEvent, bytes)
        .map_err(|_| invalid("business cut committed hash suite unavailable"))
}
