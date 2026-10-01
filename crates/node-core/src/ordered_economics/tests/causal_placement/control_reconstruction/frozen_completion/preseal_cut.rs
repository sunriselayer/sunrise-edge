//! Genuine two-member no-AV completion, cut transfer and independent saved
//! verification. No positive certificate, result, receipt or business row is
//! fabricated; all source effects come from current owning handlers.
use super::*;
use crate::business_reconstruction::cut::{
    BUSINESS_CUT_STREAMS, BusinessCutCollection, BusinessCutError, BusinessCutPage,
    BusinessCutPageVerifier, SavedBusinessCut, SavedBusinessCutComponent, VerifiedBusinessCut,
    business_cut_component_digest, business_cut_identity_digest, business_cut_package_digest,
    decode_business_cut_chunk, decode_business_cut_page, derive_source_business_cut,
    encode_business_cut_chunk, encode_business_cut_page, verify_saved_business_cut,
};

pub(super) fn completed_source() -> FrozenCompletionSource {
    finish_source(frozen_completion_source(DrainScenario::Accepted))
}

pub(super) fn completed_source_with_generic_prefix() -> FrozenCompletionSource {
    finish_source(frozen_completion_source_with_prefix(
        DrainScenario::Accepted,
        true,
    ))
}

fn finish_source(source: FrozenCompletionSource) -> FrozenCompletionSource {
    let network: &Network = &source.fixture.network;
    for replica in 0..REPLICAS {
        let result: NodeOutput = crate::fast_path::drain_apply::apply_drain_member(
            &network.stores[replica],
            &network.blobs,
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &network.leg_policy,
            &source.fixture.manifest.fee_policy,
            &network.engine,
            UNAPPLIED_REQUEST,
            12,
        )
        .unwrap();
        assert_eq!(result.responses().len(), 1);
        assert!(receipt(network, replica, UNAPPLIED_REQUEST).is_some());
    }
    for view in 7..=9 {
        network.round(view, None);
    }
    source
}

pub(super) fn transfer(
    cut: &VerifiedBusinessCut,
    resolver: &HashSuiteResolver,
) -> SavedBusinessCut {
    let mut saved: SavedBusinessCut = SavedBusinessCut {
        identity: cut.identity().clone(),
        package: cut.package_identity().clone(),
        components: Vec::new(),
    };
    for collection in BUSINESS_CUT_STREAMS {
        let mut after: Option<Vec<u8>> = None;
        let mut verifier: BusinessCutPageVerifier = BusinessCutPageVerifier::new(
            resolver,
            cut.identity(),
            cut.package_identity(),
            collection,
        )
        .unwrap();
        loop {
            let page: BusinessCutPage = cut
                .read_page(
                    resolver,
                    collection,
                    after.as_deref(),
                    NonZeroUsize::new(1).unwrap(),
                )
                .unwrap();
            let page: BusinessCutPage =
                decode_business_cut_page(&encode_business_cut_page(&page).unwrap()).unwrap();
            verifier.push_page(resolver, &page).unwrap();
            for descriptor in &page.descriptors {
                assert_eq!(
                    cut.descriptor(collection, &descriptor.key).unwrap(),
                    descriptor
                );
                let mut bytes: Vec<u8> = Vec::new();
                let mut offset: u64 = 0;
                loop {
                    let chunk = cut
                        .read_chunk(descriptor, offset, NonZeroUsize::new(97).unwrap())
                        .unwrap();
                    let chunk =
                        decode_business_cut_chunk(&encode_business_cut_chunk(&chunk).unwrap())
                            .unwrap();
                    assert_eq!(chunk.cut_digest, cut.cut_digest());
                    assert_eq!(chunk.package_digest, cut.package_digest());
                    assert_eq!(chunk.descriptor, *descriptor);
                    assert_eq!(chunk.offset, offset);
                    assert_eq!(chunk.total_length, descriptor.length);
                    bytes.extend_from_slice(&chunk.bytes);
                    offset = offset.checked_add(chunk.bytes.len() as u64).unwrap();
                    if offset == descriptor.length {
                        break;
                    }
                }
                assert_eq!(
                    business_cut_component_digest(resolver, &cut.identity().context, &bytes)
                        .unwrap(),
                    descriptor.digest
                );
                saved.components.push(SavedBusinessCutComponent {
                    descriptor: descriptor.clone(),
                    bytes,
                });
                after = Some(descriptor.key.clone());
            }
            if page.terminal {
                break;
            }
        }
        verifier.finish().unwrap();
    }
    saved
}

/// Recompute only untrusted transfer claims, never execution. This makes the
/// corruption controls stronger than a stale checksum alone: private replay
/// still rejects a mutually internally consistent altered saved package.
pub(super) fn refresh_package(saved: &mut SavedBusinessCut, resolver: &HashSuiteResolver) {
    use canonical_encoding::{CanonicalStruct, encode_digest32};
    use execution::publication::encode_publication_context;
    use protocol_types::HashPurpose;
    let identity = &saved.identity;
    let hash = |bytes: &[u8]| {
        resolver
            .hash_for_purpose(identity.context.epoch(), HashPurpose::NodeEvent, bytes)
            .unwrap()
    };
    for stream in &mut saved.package.streams {
        let mut seed: CanonicalStruct = CanonicalStruct::new(0x64B6, 1);
        seed.field_bytes(1, encode_publication_context(&identity.context).unwrap())
            .unwrap();
        seed.field_bytes(2, encode_digest32(&identity.genesis_digest).unwrap())
            .unwrap();
        seed.field_bytes(3, identity.domain.as_bytes().to_vec())
            .unwrap();
        seed.field_u16(4, stream.collection as u16).unwrap();
        seed.field_bytes(5, Vec::new()).unwrap();
        let mut accumulator: Digest32 = hash(&seed.finish().unwrap());
        let mut count: u64 = 0;
        for item in saved
            .components
            .iter()
            .filter(|item| item.descriptor.collection == stream.collection)
        {
            let mut fold: CanonicalStruct = CanonicalStruct::new(0x64B7, 1);
            fold.field_bytes(1, encode_digest32(&accumulator).unwrap())
                .unwrap();
            fold.field_bytes(
                2,
                crate::business_reconstruction::cut::encode_business_cut_descriptor(
                    &item.descriptor,
                )
                .unwrap(),
            )
            .unwrap();
            accumulator = hash(&fold.finish().unwrap());
            count += 1;
        }
        stream.count = count;
        stream.root = accumulator;
    }
    saved.package.cut_digest = business_cut_identity_digest(resolver, &saved.identity).unwrap();
    let mut seed: CanonicalStruct = CanonicalStruct::new(0x64B6, 1);
    seed.field_bytes(1, encode_publication_context(&identity.context).unwrap())
        .unwrap();
    seed.field_bytes(2, encode_digest32(&identity.genesis_digest).unwrap())
        .unwrap();
    seed.field_bytes(3, identity.domain.as_bytes().to_vec())
        .unwrap();
    seed.field_u16(4, 8).unwrap();
    seed.field_bytes(5, encode_digest32(&saved.package.cut_digest).unwrap())
        .unwrap();
    let mut accumulator: Digest32 = hash(&seed.finish().unwrap());
    for item in &saved.components {
        let mut fold: CanonicalStruct = CanonicalStruct::new(0x64B7, 1);
        fold.field_bytes(1, encode_digest32(&accumulator).unwrap())
            .unwrap();
        fold.field_bytes(
            2,
            crate::business_reconstruction::cut::encode_business_cut_descriptor(&item.descriptor)
                .unwrap(),
        )
        .unwrap();
        accumulator = hash(&fold.finish().unwrap());
    }
    saved.package.component_count = saved.components.len() as u64;
    saved.package.accumulator = accumulator;
}

#[test]
fn preseal_cut_genuine_complete_no_av_union_exports_and_reverifies_exact_originals() {
    let source: FrozenCompletionSource = completed_source();
    let network: &Network = &source.fixture.network;
    let before: SourceBusinessSnapshot = snapshot(network);
    let (identity, history) = complete_history(network);
    let cut: VerifiedBusinessCut = derive_source_business_cut(
        reconstruction_plan(&source.fixture, &identity),
        &network.stores[0],
        &network.blobs,
        &history,
    )
    .unwrap();
    assert_eq!(
        snapshot(network),
        before,
        "all source bytes/revisions/receipts are unchanged by derivation"
    );
    assert_eq!(cut.identity().drain_union.member_count, 2);
    assert!(cut.identity().generation_floor.get() > 0);
    assert!(cut.source_token().is_some());
    let saved: SavedBusinessCut = transfer(&cut, &network.resolver);
    assert!(
        saved
            .components
            .iter()
            .filter(|item| item.descriptor.collection == BusinessCutCollection::Receipts)
            .any(|item| item.descriptor.key == PAID_REQUEST)
    );
    assert!(
        saved
            .components
            .iter()
            .filter(|item| item.descriptor.collection == BusinessCutCollection::Receipts)
            .any(|item| item.descriptor.key == UNAPPLIED_REQUEST)
    );
    for request in [FREEZE_REQUEST, DRAIN_REQUEST] {
        assert!(
            !saved
                .components
                .iter()
                .any(
                    |item| item.descriptor.collection == BusinessCutCollection::Receipts
                        && item.descriptor.key == request
                )
        );
        let mut key: Vec<u8> = vec![2];
        key.extend_from_slice(&request);
        assert!(
            saved
                .components
                .iter()
                .any(|item| item.descriptor.collection
                    == BusinessCutCollection::AuthorityCompanions
                    && item.descriptor.key == key),
            "exact original control receipts remain authority companions, not synthetic/excluded"
        );
    }
    for request in [PAID_REQUEST, UNAPPLIED_REQUEST] {
        let carrier: Vec<u8> = fastpath_certificate_key(&fixture::chain(), &request).unwrap();
        assert!(
            cut.descriptor(BusinessCutCollection::State, &carrier)
                .is_err(),
            "comparison-only proof subjects must not be business State"
        );
        let mut companion: Vec<u8> = vec![1];
        companion.extend_from_slice(&carrier);
        assert!(
            cut.descriptor(BusinessCutCollection::AuthorityCompanions, &companion)
                .is_ok()
        );
    }
    let verified: VerifiedBusinessCut =
        verify_saved_business_cut(reconstruction_plan(&source.fixture, &identity), &saved).unwrap();
    assert_eq!(verified.cut_digest(), cut.cut_digest());
    assert_eq!(verified.package_digest(), cut.package_digest());
    assert!(
        verified.source_token().is_none(),
        "saved reconstruction cannot manufacture a source freshness token"
    );
    assert_eq!(snapshot(network), before);
}

#[test]
fn preseal_cut_genuine_incomplete_drain_and_nonempty_terminal_refuse() {
    let source: FrozenCompletionSource = frozen_completion_source(DrainScenario::Accepted);
    let network = &source.fixture.network;
    let (identity, history) = complete_history(network);
    assert!(matches!(
        derive_source_business_cut(
            reconstruction_plan(&source.fixture, &identity),
            &network.stores[0],
            &network.blobs,
            &history
        ),
        Err(BusinessCutError::Invalid(
            "cut fixed target three-chain still contains a candidate"
        ))
    ));
    for view in 7..=9 {
        network.round(view, None);
    }
    let (identity, history) = complete_history(network);
    let before: SourceBusinessSnapshot = snapshot(network);
    assert!(matches!(
        derive_source_business_cut(
            reconstruction_plan(&source.fixture, &identity),
            &network.stores[0],
            &network.blobs,
            &history
        ),
        Err(BusinessCutError::Invalid(
            "cut selected member original is not independently complete"
        ))
    ));
    assert_eq!(snapshot(network), before);
    assert!(receipt(network, 0, UNAPPLIED_REQUEST).is_none());
}

#[test]
fn preseal_cut_saved_internally_consistent_corruption_and_closure_omission_refuse() {
    let source: FrozenCompletionSource = completed_source();
    let network = &source.fixture.network;
    let (identity, history) = complete_history(network);
    let cut: VerifiedBusinessCut = derive_source_business_cut(
        reconstruction_plan(&source.fixture, &identity),
        &network.stores[0],
        &network.blobs,
        &history,
    )
    .unwrap();
    let original: SavedBusinessCut = transfer(&cut, &network.resolver);
    let mut missing: SavedBusinessCut = original.clone();
    missing.components.retain(|item| {
        !(item.descriptor.collection == BusinessCutCollection::Proofs
            && item.descriptor.key.first() == Some(&2)
            && item.descriptor.key[1..] == PAID_REQUEST)
    });
    refresh_package(&mut missing, &network.resolver);
    assert!(
        verify_saved_business_cut(reconstruction_plan(&source.fixture, &identity), &missing)
            .is_err()
    );
    let mut altered: SavedBusinessCut = original.clone();
    let item: &mut SavedBusinessCutComponent = altered
        .components
        .iter_mut()
        .find(|item| {
            item.descriptor.collection == BusinessCutCollection::Receipts
                && item.descriptor.key == PAID_REQUEST
        })
        .unwrap();
    item.bytes[0] ^= 1;
    item.descriptor.digest =
        business_cut_component_digest(&network.resolver, &altered.identity.context, &item.bytes)
            .unwrap();
    refresh_package(&mut altered, &network.resolver);
    assert!(
        verify_saved_business_cut(reconstruction_plan(&source.fixture, &identity), &altered)
            .is_err(),
        "internally matching descriptor/package hashes are not effects authority"
    );
    let mut reordered: SavedBusinessCut = original.clone();
    reordered.components.swap(0, 1);
    assert!(
        verify_saved_business_cut(reconstruction_plan(&source.fixture, &identity), &reordered)
            .is_err()
    );
    let mut duplicate: SavedBusinessCut = original.clone();
    duplicate
        .components
        .insert(0, duplicate.components[0].clone());
    assert!(
        verify_saved_business_cut(reconstruction_plan(&source.fixture, &identity), &duplicate)
            .is_err()
    );
    let mut altered_floor: SavedBusinessCut = original.clone();
    altered_floor.identity.generation_floor = protocol_types::ExecutionGeneration::new(u64::MAX);
    refresh_package(&mut altered_floor, &network.resolver);
    assert!(
        verify_saved_business_cut(
            reconstruction_plan(&source.fixture, &identity),
            &altered_floor
        )
        .is_err()
    );
    let mut wrong_pin: OrderedHistoryIdentity = identity.clone();
    wrong_pin.through_height = wrong_pin.through_height.checked_add(1).unwrap();
    assert!(
        verify_saved_business_cut(reconstruction_plan(&source.fixture, &wrong_pin), &original)
            .is_err()
    );
    assert!(
        cut.read_page(
            &network.resolver,
            BusinessCutCollection::State,
            Some(b"not-an-exact-cursor"),
            NonZeroUsize::new(1).unwrap()
        )
        .is_err()
    );
    let descriptor = &original.components[0].descriptor;
    let mut changed = descriptor.clone();
    changed.length = changed.length.checked_add(1).unwrap();
    assert!(
        cut.read_chunk(&changed, 0, NonZeroUsize::new(1).unwrap())
            .is_err()
    );
}

#[test]
fn preseal_cut_genuine_fast_certificate_subsets_share_semantic_cut_not_exact_package() {
    let source: FrozenCompletionSource = completed_source();
    let network = &source.fixture.network;
    let (identity, history) = complete_history(network);
    let cut: VerifiedBusinessCut = derive_source_business_cut(
        reconstruction_plan(&source.fixture, &identity),
        &network.stores[0],
        &network.blobs,
        &history,
    )
    .unwrap();
    let mut saved: SavedBusinessCut = transfer(&cut, &network.resolver);
    let proof: &SavedBusinessCutComponent = saved
        .components
        .iter()
        .find(|item| {
            item.descriptor.collection == BusinessCutCollection::Proofs
                && item.descriptor.key.first() == Some(&2)
                && item.descriptor.key[1..] == PAID_REQUEST
        })
        .unwrap();
    let bundle: PublicationBundle =
        consensus::bundle::decode_publication_bundle(&proof.bytes).unwrap();
    let alternate: Vec<u8> = crate::fast_path::records::encode_fastpath_certificate_record(
        &crate::fast_path::records::FastPathCertificateRecord {
            request_id: PAID_REQUEST,
            certificate: consensus::encode_fast_certificate(&bundle.certificate).unwrap(),
        },
    )
    .unwrap();
    let actual: &mut SavedBusinessCutComponent = saved
        .components
        .iter_mut()
        .find(|item| {
            item.descriptor.collection == BusinessCutCollection::Proofs
                && item.descriptor.key.first() == Some(&9)
                && item.descriptor.key[1..] == PAID_REQUEST
        })
        .unwrap();
    assert_ne!(
        actual.bytes, alternate,
        "fixture really uses genuine 1/2/3 application proof vs 0/1/2 retention proof"
    );
    actual.bytes = alternate;
    actual.descriptor.length = actual.bytes.len() as u64;
    actual.descriptor.digest =
        business_cut_component_digest(&network.resolver, &saved.identity.context, &actual.bytes)
            .unwrap();
    refresh_package(&mut saved, &network.resolver);
    let verified: VerifiedBusinessCut =
        verify_saved_business_cut(reconstruction_plan(&source.fixture, &identity), &saved).unwrap();
    assert_eq!(verified.cut_digest(), cut.cut_digest());
    assert_ne!(verified.package_digest(), cut.package_digest());
    assert_ne!(
        business_cut_package_digest(&network.resolver, &saved.identity, &saved.package).unwrap(),
        cut.package_digest()
    );
}
