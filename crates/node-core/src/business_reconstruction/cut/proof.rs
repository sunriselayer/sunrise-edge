//! Exact proof bytes stay in individually bounded components, never a bundle
//! of all history. Every saved proof is reauthenticated and privately executed.
use super::super::DrainSetSignerFrontierMaterial;
use super::*;
use crate::ordered_economics::{
    OrderedHistoryComponentKind, OrderedOperationKind, decode_ordered_candidate,
    decode_ordered_history_height_descriptor, encode_ordered_history_height_descriptor,
};
use consensus::bundle::{decode_publication_bundle, encode_publication_bundle};
use consensus::{FrozenFrontierPage, FrozenFrontierVote};
use protocol_types::ValidatorId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum ProofKind {
    Genesis = 1,
    OwnedBundle = 2,
    OwnedAvailability = 3,
    OwnedApplication = 4,
    HistoryDescriptor = 5,
    HistoryComponent = 6,
    ControlVote = 7,
    ControlPage = 8,
    AppliedFastCertificate = 9,
}
impl ProofKind {
    pub(super) fn from_wire(tag: u16) -> Result<Self, BusinessCutError> {
        match tag {
            1 => Ok(Self::Genesis),
            2 => Ok(Self::OwnedBundle),
            3 => Ok(Self::OwnedAvailability),
            4 => Ok(Self::OwnedApplication),
            5 => Ok(Self::HistoryDescriptor),
            6 => Ok(Self::HistoryComponent),
            7 => Ok(Self::ControlVote),
            8 => Ok(Self::ControlPage),
            9 => Ok(Self::AppliedFastCertificate),
            _ => Err(invalid("unknown business cut proof kind")),
        }
    }
    pub(super) const fn max_bytes(self) -> usize {
        match self {
            Self::Genesis => crate::genesis::MAX_GENESIS_MANIFEST_BYTES,
            Self::OwnedBundle => consensus::bundle::MAX_ENCODED_BUNDLE_BYTES,
            Self::OwnedAvailability | Self::HistoryComponent | Self::AppliedFastCertificate => {
                canonical_encoding::MAX_CANONICAL_FRAME_BYTES
            }
            Self::OwnedApplication | Self::HistoryDescriptor => MAX_BUSINESS_CUT_DESCRIPTOR_BYTES,
            Self::ControlVote => 8 * 1024,
            Self::ControlPage => consensus::MAX_FROZEN_FRONTIER_PAGE_BYTES,
        }
    }
}

pub(super) fn validate_key(key: &[u8], metadata: &[u8]) -> Result<ProofKind, BusinessCutError> {
    let frame = canonical_encoding::decode_canonical_frame(metadata)?;
    let kind: ProofKind = ProofKind::from_wire(frame.required_u16(2)?)?;
    if key.first() != Some(&(kind as u8)) {
        return Err(invalid("cut proof key kind differs"));
    }
    let length: usize = match kind {
        ProofKind::Genesis => 1,
        ProofKind::OwnedBundle
        | ProofKind::OwnedAvailability
        | ProofKind::OwnedApplication
        | ProofKind::AppliedFastCertificate => 33,
        ProofKind::HistoryDescriptor => 9,
        ProofKind::HistoryComponent => 11,
        ProofKind::ControlVote => 65,
        ProofKind::ControlPage => 73,
    };
    if key.len() != length {
        return Err(invalid("cut proof key exact length"));
    }
    if matches!(
        kind,
        ProofKind::HistoryDescriptor | ProofKind::HistoryComponent
    ) && u64::from_be_bytes(
        key[1..9]
            .try_into()
            .map_err(|_| invalid("cut proof height length"))?,
    ) == 0
    {
        return Err(invalid("cut proof height is zero"));
    }
    if kind == ProofKind::HistoryComponent {
        OrderedHistoryComponentKind::from_wire(u16::from_be_bytes(
            key[9..11]
                .try_into()
                .map_err(|_| invalid("cut proof kind length"))?,
        ))
        .map_err(|_| invalid("unknown cut ordered history component"))?;
    }
    Ok(kind)
}
fn key(kind: ProofKind, suffix: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = vec![kind as u8];
    result.extend_from_slice(suffix);
    result
}
fn add(
    overlay: &BusinessReconstructionOverlay<'_>,
    output: &mut BTreeMap<(BusinessCutCollection, Vec<u8>), SavedBusinessCutComponent>,
    kind: ProofKind,
    suffix: &[u8],
    bytes: Vec<u8>,
) -> Result<(), BusinessCutError> {
    let mut metadata: CanonicalStruct = CanonicalStruct::new(0x64B9, 1);
    metadata.field_u16(1, 6)?;
    metadata.field_u16(2, kind as u16)?;
    derive::insert(
        overlay,
        output,
        BusinessCutCollection::Proofs,
        key(kind, suffix),
        metadata.finish()?,
        bytes,
    )
}
pub(super) fn add_material(
    overlay: &BusinessReconstructionOverlay<'_>,
    output: &mut BTreeMap<(BusinessCutCollection, Vec<u8>), SavedBusinessCutComponent>,
    owned: &[OwnedPublicationMaterial],
    ordered: &[OrderedHistoryHeightMaterial],
    controls: &[DrainSetControlMaterial],
    carriers: &BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<(), BusinessCutError> {
    add(
        overlay,
        output,
        ProofKind::Genesis,
        &[],
        crate::genesis::encode_genesis_manifest(overlay.plan.genesis)
            .map_err(|_| invalid("cut signed genesis encoding"))?,
    )?;
    for item in owned {
        add(
            overlay,
            output,
            ProofKind::OwnedBundle,
            &item.bundle.request_id,
            encode_publication_bundle(&item.bundle)
                .map_err(|_| invalid("cut full owned bundle encoding"))?,
        )?;
        if let Some(bytes) = &item.availability_certificate {
            add(
                overlay,
                output,
                ProofKind::OwnedAvailability,
                &item.bundle.request_id,
                bytes.clone(),
            )?;
        }
        let mut status: CanonicalStruct = CanonicalStruct::new(0x64BA, 1);
        status.field_u16(1, u16::from(item.source_application_present))?;
        status.field_u64(2, item.recovery_created_checkpoint)?;
        add(
            overlay,
            output,
            ProofKind::OwnedApplication,
            &item.bundle.request_id,
            status.finish()?,
        )?;
    }
    for (request, bytes) in carriers {
        add(
            overlay,
            output,
            ProofKind::AppliedFastCertificate,
            request,
            bytes.clone(),
        )?;
    }
    for height in ordered {
        let suffix: [u8; 8] = height.descriptor.height.to_be_bytes();
        add(
            overlay,
            output,
            ProofKind::HistoryDescriptor,
            &suffix,
            encode_ordered_history_height_descriptor(&height.descriptor)
                .map_err(|_| invalid("cut archived history descriptor encoding"))?,
        )?;
        for (kind, bytes) in &height.components {
            let mut component: Vec<u8> = suffix.to_vec();
            component.extend_from_slice(&(*kind as u16).to_be_bytes());
            add(
                overlay,
                output,
                ProofKind::HistoryComponent,
                &component,
                bytes.clone(),
            )?;
        }
    }
    for control in controls {
        for (vote, frontier) in control.selected_votes.iter().zip(&control.signer_frontiers) {
            let mut suffix: Vec<u8> = control.candidate_digest.bytes().to_vec();
            suffix.extend_from_slice(vote.validator.as_bytes());
            add(
                overlay,
                output,
                ProofKind::ControlVote,
                &suffix,
                consensus::encode_frozen_frontier_vote(vote)
                    .map_err(|_| invalid("cut selected vote encoding"))?,
            )?;
            for (index, page) in frontier.pages.iter().enumerate() {
                let mut page_suffix: Vec<u8> = suffix.clone();
                page_suffix.extend_from_slice(
                    &u64::try_from(index)
                        .map_err(|_| invalid("cut page index overflow"))?
                        .to_be_bytes(),
                );
                add(
                    overlay,
                    output,
                    ProofKind::ControlPage,
                    &page_suffix,
                    consensus::encode_frozen_frontier_page(page)
                        .map_err(|_| invalid("cut selected page encoding"))?,
                )?;
            }
        }
    }
    Ok(())
}

struct OwnedParts {
    bundle: Option<consensus::bundle::PublicationBundle>,
    availability: Option<Vec<u8>>,
    application: Option<(bool, u64)>,
}
struct HeightParts {
    descriptor: Option<crate::ordered_economics::OrderedHistoryHeightDescriptor>,
    components: BTreeMap<OrderedHistoryComponentKind, Vec<u8>>,
}
type ControlParts = BTreeMap<
    [u8; 32],
    BTreeMap<
        ValidatorId,
        (
            Option<FrozenFrontierVote>,
            BTreeMap<u64, FrozenFrontierPage>,
        ),
    >,
>;
type ParsedMaterial = (
    Vec<OwnedPublicationMaterial>,
    Vec<OrderedHistoryHeightMaterial>,
    Vec<DrainSetControlMaterial>,
    BTreeMap<[u8; 32], Vec<u8>>,
);

fn parsed(
    plan: &BusinessReconstructionPlan<'_>,
    saved: &SavedBusinessCut,
) -> Result<ParsedMaterial, BusinessCutError> {
    let mut genesis_seen: bool = false;
    let mut owned: BTreeMap<[u8; 32], OwnedParts> = BTreeMap::new();
    let mut heights: BTreeMap<u64, HeightParts> = BTreeMap::new();
    let mut controls: ControlParts = BTreeMap::new();
    let mut carriers: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for component in &saved.components {
        if component.descriptor.collection != BusinessCutCollection::Proofs {
            continue;
        }
        let descriptor = &component.descriptor;
        let kind: ProofKind = validate_key(&descriptor.key, &descriptor.metadata)?;
        let bytes: &[u8] = &component.bytes;
        match kind {
            ProofKind::AppliedFastCertificate => {
                let request: [u8; 32] = descriptor.key[1..]
                    .try_into()
                    .map_err(|_| invalid("saved applied certificate key"))?;
                carriers.insert(request, bytes.to_vec());
            }
            ProofKind::Genesis => {
                let manifest = crate::genesis::decode_genesis_manifest(bytes)
                    .map_err(|_| invalid("saved cut genesis schema"))?;
                if genesis_seen || &manifest != plan.genesis {
                    return Err(invalid("saved cut signed genesis differs from local pin"));
                }
                genesis_seen = true;
            }
            ProofKind::OwnedBundle | ProofKind::OwnedAvailability | ProofKind::OwnedApplication => {
                let request: [u8; 32] = descriptor.key[1..]
                    .try_into()
                    .map_err(|_| invalid("saved cut owned key"))?;
                let entry: &mut OwnedParts = owned.entry(request).or_insert(OwnedParts {
                    bundle: None,
                    availability: None,
                    application: None,
                });
                match kind {
                    ProofKind::OwnedBundle => {
                        let bundle = decode_publication_bundle(bytes)
                            .map_err(|_| invalid("saved cut owned bundle schema"))?;
                        if bundle.request_id != request {
                            return Err(invalid("saved cut owned bundle request differs"));
                        }
                        entry.bundle = Some(bundle);
                    }
                    ProofKind::OwnedAvailability => {
                        entry.availability = Some(bytes.to_vec());
                    }
                    ProofKind::OwnedApplication => {
                        let status = canonical_encoding::decode_canonical_frame(bytes)?;
                        status.require_type(0x64BA)?;
                        status.require_version(1)?;
                        status.require_only_fields(&[1, 2])?;
                        entry.application =
                            Some((codec::boolean(&status, 1)?, status.required_u64(2)?));
                    }
                    _ => return Err(invalid("saved cut owned role")),
                }
            }
            ProofKind::HistoryDescriptor | ProofKind::HistoryComponent => {
                let height: u64 = u64::from_be_bytes(
                    descriptor.key[1..9]
                        .try_into()
                        .map_err(|_| invalid("saved cut height key"))?,
                );
                let entry: &mut HeightParts = heights.entry(height).or_insert(HeightParts {
                    descriptor: None,
                    components: BTreeMap::new(),
                });
                if kind == ProofKind::HistoryDescriptor {
                    let value = decode_ordered_history_height_descriptor(bytes)
                        .map_err(|_| invalid("saved cut height descriptor schema"))?;
                    if value.height != height || value.identity != *plan.ordered_history_identity {
                        return Err(invalid(
                            "saved cut history differs from locally pinned target",
                        ));
                    }
                    entry.descriptor = Some(value);
                } else {
                    let component_kind: OrderedHistoryComponentKind =
                        OrderedHistoryComponentKind::from_wire(u16::from_be_bytes(
                            descriptor.key[9..11]
                                .try_into()
                                .map_err(|_| invalid("saved cut height component key"))?,
                        ))
                        .map_err(|_| invalid("saved cut height component kind"))?;
                    if bytes.len() > component_kind.max_bytes() {
                        return Err(invalid("saved cut ordered component owning bound"));
                    }
                    entry.components.insert(component_kind, bytes.to_vec());
                }
            }
            ProofKind::ControlVote | ProofKind::ControlPage => {
                let digest: [u8; 32] = descriptor.key[1..33]
                    .try_into()
                    .map_err(|_| invalid("saved cut control digest key"))?;
                let signer: ValidatorId = ValidatorId::new(
                    descriptor.key[33..65]
                        .try_into()
                        .map_err(|_| invalid("saved cut control signer key"))?,
                );
                let entry = controls
                    .entry(digest)
                    .or_default()
                    .entry(signer)
                    .or_insert((None, BTreeMap::new()));
                if kind == ProofKind::ControlVote {
                    let vote = consensus::decode_frozen_frontier_vote(bytes)
                        .map_err(|_| invalid("saved cut control vote schema"))?;
                    if vote.validator != signer {
                        return Err(invalid("saved cut control vote signer differs"));
                    }
                    entry.0 = Some(vote);
                } else {
                    let index: u64 = u64::from_be_bytes(
                        descriptor.key[65..73]
                            .try_into()
                            .map_err(|_| invalid("saved cut control page index"))?,
                    );
                    entry.1.insert(
                        index,
                        consensus::decode_frozen_frontier_page(bytes)
                            .map_err(|_| invalid("saved cut control page schema"))?,
                    );
                }
            }
        }
    }
    if !genesis_seen {
        return Err(invalid("saved cut signed genesis component missing"));
    }
    let mut owned_material: Vec<OwnedPublicationMaterial> = Vec::new();
    for entry in owned.into_values() {
        let (applied, checkpoint) = entry
            .application
            .ok_or(invalid("saved cut owned target hint absent"))?;
        owned_material.push(OwnedPublicationMaterial {
            bundle: entry
                .bundle
                .ok_or(invalid("saved cut owned full bundle absent"))?,
            availability_certificate: entry.availability,
            source_application_present: applied,
            recovery_created_checkpoint: checkpoint,
        });
    }
    let mut history: Vec<OrderedHistoryHeightMaterial> = Vec::new();
    for entry in heights.into_values() {
        history.push(OrderedHistoryHeightMaterial {
            descriptor: entry
                .descriptor
                .ok_or(invalid("saved cut history descriptor absent"))?,
            components: entry.components.into_iter().collect(),
        });
    }
    let mut control_material: Vec<DrainSetControlMaterial> = Vec::new();
    for (digest, signers) in controls {
        let candidate = history
            .iter()
            .flat_map(|height| &height.components)
            .filter(|(kind, _)| *kind == OrderedHistoryComponentKind::Candidate)
            .filter_map(|(_, bytes)| decode_ordered_candidate(bytes).ok())
            .find(|candidate| {
                candidate.kind == OrderedOperationKind::DrainSet
                    && plan
                        .ordered_policy
                        .candidate_digest(candidate)
                        .is_ok_and(|value| value.bytes() == digest)
            })
            .ok_or(invalid(
                "saved cut control does not name an authenticated history candidate",
            ))?;
        let candidate_digest: Digest32 = plan
            .ordered_policy
            .candidate_digest(&candidate)
            .map_err(|_| invalid("saved cut control candidate digest"))?;
        let mut votes: Vec<FrozenFrontierVote> = Vec::new();
        let mut frontiers: Vec<DrainSetSignerFrontierMaterial> = Vec::new();
        for (signer, (vote, pages)) in signers {
            let mut next: u64 = 0;
            let mut stream: Vec<FrozenFrontierPage> = Vec::new();
            for (index, page) in pages {
                if index != next {
                    return Err(invalid("saved cut selected page index is not consecutive"));
                }
                next = next
                    .checked_add(1)
                    .ok_or(invalid("saved cut selected page index overflow"))?;
                stream.push(page);
            }
            votes.push(vote.ok_or(invalid("saved cut selected signer vote absent"))?);
            frontiers.push(DrainSetSignerFrontierMaterial {
                signer,
                pages: stream,
            });
        }
        control_material.push(DrainSetControlMaterial {
            candidate_digest,
            selected_votes: votes,
            signer_frontiers: frontiers,
        });
    }
    Ok((owned_material, history, control_material, carriers))
}

pub(super) fn verify_saved(
    plan: BusinessReconstructionPlan<'_>,
    saved: &SavedBusinessCut,
) -> Result<VerifiedBusinessCut, BusinessCutError> {
    verify_saved_with_overlay(plan, saved).map(|(cut, _, _)| cut)
}

/// The only raw installation source: an independently executed private store
/// retained after complete cut and exact package equality, never decoded
/// SemanticRecord comparison bytes or caller-supplied rows.
pub(in crate::business_reconstruction) type VerifiedSavedReconstruction<'a> = (
    VerifiedBusinessCut,
    BusinessReconstructionOverlay<'a>,
    BTreeMap<[u8; 32], Vec<u8>>,
);

pub(in crate::business_reconstruction) fn verify_saved_with_overlay<'a>(
    plan: BusinessReconstructionPlan<'a>,
    saved: &SavedBusinessCut,
) -> Result<VerifiedSavedReconstruction<'a>, BusinessCutError> {
    encode_business_cut_identity(&saved.identity)?;
    encode_business_cut_package(&saved.package)?;
    if saved.identity.context != *plan.genesis.context()
        || saved.identity.domain != plan.domain
        || saved.identity.genesis_digest != plan.pinned_genesis_digest
        || saved.identity.ordered_history != *plan.ordered_history_identity
    {
        return Err(invalid("saved cut differs from local reconstruction pins"));
    }
    let mut previous: Option<(BusinessCutCollection, &[u8])> = None;
    for item in &saved.components {
        encode_business_cut_descriptor(&item.descriptor)?;
        let locator: (BusinessCutCollection, &[u8]) =
            (item.descriptor.collection, &item.descriptor.key);
        if previous.is_some_and(|before| locator <= before)
            || u64::try_from(item.bytes.len())
                .map_err(|_| invalid("saved cut body length overflow"))?
                != item.descriptor.length
            || business_cut_component_digest(plan.resolver, plan.genesis.context(), &item.bytes)?
                != item.descriptor.digest
        {
            return Err(invalid(
                "saved cut component order/length/content digest differs",
            ));
        }
        previous = Some(locator);
    }
    let (owned, ordered, controls, carriers) = parsed(&plan, saved)?;
    let mut overlay: BusinessReconstructionOverlay<'_> = BusinessReconstructionOverlay::new(plan)?;
    overlay.reconstruct_with_control_material(&owned, &ordered, &controls)?;
    let expected: VerifiedBusinessCut =
        derive::from_overlay(&overlay, &owned, &ordered, &controls, &carriers)?;
    if expected.identity != saved.identity
        || expected.package != saved.package
        || expected.components.len() != saved.components.len()
        || !expected
            .components
            .values()
            .zip(&saved.components)
            .all(|(expected, actual)| expected == actual)
    {
        return Err(invalid(
            "saved complete export differs from independently derived business cut",
        ));
    }
    Ok((expected, overlay, carriers))
}

/// Preserve the actual application's proof subset separately from the
/// retainer's full bundle. This never seeds business effects in private memory.
pub(super) fn source_application_carriers(
    overlay: &BusinessReconstructionOverlay<'_>,
    snapshot: &super::super::SourceBusinessSnapshot,
) -> Result<BTreeMap<[u8; 32], Vec<u8>>, BusinessCutError> {
    let mut result: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for producer in overlay
        .publication_catalog
        .as_deref()
        .ok_or(invalid("cut applied carrier catalog absent"))?
        .iter()
        .filter(|item| item.applied)
    {
        let key: Vec<u8> = crate::local_instance_state::fastpath_certificate_key(
            overlay.plan.genesis.context().chain_id(),
            &producer.request_id,
        )
        .map_err(|_| invalid("cut original applied certificate key"))?;
        let bytes: Vec<u8> = snapshot
            .records
            .iter()
            .find(|row| {
                row.descriptor.key() == &runtime::portable::DurableRecordKey::State(key.clone())
            })
            .and_then(|row| row.value.clone())
            .ok_or(invalid("cut original applied certificate carrier absent"))?;
        result.insert(producer.request_id, bytes);
    }
    verify_application_carriers(overlay, &result)?;
    Ok(result)
}

pub(super) fn verify_application_carriers(
    overlay: &BusinessReconstructionOverlay<'_>,
    carriers: &BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<(), BusinessCutError> {
    let context = overlay.plan.genesis.context();
    let certifier = consensus::FastPathCertifier::new(
        context.chain_id().clone(),
        context.protocol_version(),
        context.epoch(),
        overlay.plan.ordered_policy.engine().validator_set().clone(),
    )
    .map_err(|_| invalid("cut application certificate authority"))?;
    let catalog = overlay
        .publication_catalog
        .as_deref()
        .ok_or(invalid("cut applied certificate catalog absent"))?;
    if carriers.len() != catalog.iter().filter(|producer| producer.applied).count() {
        return Err(invalid(
            "cut exact applied certificate proof closure differs",
        ));
    }
    for (request, bytes) in carriers {
        let producer = catalog
            .iter()
            .find(|producer| &producer.request_id == request && producer.applied)
            .ok_or(invalid(
                "cut application certificate has no independently applied producer",
            ))?;
        let record = crate::fast_path::records::decode_fastpath_certificate_record(bytes)
            .map_err(|_| invalid("cut original application certificate record schema"))?;
        let certificate = consensus::decode_fast_certificate(&record.certificate)
            .map_err(|_| invalid("cut original application certificate schema"))?;
        certifier
            .verify_certificate(&certificate, &super::super::ReconstructionEd25519Verifier)
            .map_err(|_| invalid("cut original application certificate lacks quorum"))?;
        if record.request_id != *request
            || certificate.tx_hash != producer.tx_hash
            || certificate.execution_effects_hash != producer.execution_effects_hash
            || certificate.locked_objects_digest != producer.locked_objects_digest
        {
            return Err(invalid(
                "cut original application certificate subject differs",
            ));
        }
    }
    Ok(())
}
