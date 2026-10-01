//! Full-cut evidence for generic paid contracts, charged traps, ordinary asset
//! effects and ordered economics. The only initial state is genuine signed-v4
//! genesis; every later effect/result/certificate comes from an owning handler.
use super::preseal_cut::{refresh_package, transfer};
use super::*;
use crate::business_reconstruction::cut::{
    BusinessCutCollection, SavedBusinessCut, VerifiedBusinessCut, business_cut_component_digest,
    derive_source_business_cut, verify_saved_business_cut,
};
use crate::logical_generation::{
    decode_logical_profile_record, decode_logical_provenance_record, is_logical_profile_key,
    is_logical_provenance_key, logical_profile_key,
};
use abi::call_values::{CallAbi, ValueLayout};
use abi::executable_abi::{ExecutableAbi, encode_executable_abi};
use abi::package_types::PackageOrigin;
use abi::public_abi::{EntrypointDeclaration, PackageAbi};
use execution::local_execution::generic_object_result_semantics;
use execution::paid_execution::PaidResultTarget;
use execution::publication::{
    ArtifactParts, CodeArtifact, UnverifiedDependencyRef, artifact_commitment,
};
use protocol_types::ExecutionGeneration;

const PUBLISH: [u8; 32] = [0x30; 32];
const INSTANTIATE: [u8; 32] = [0x31; 32];
const CALL: [u8; 32] = [0x32; 32];
const TRAP: [u8; 32] = [0x33; 32];
const ASSET: [u8; 32] = [0x34; 32];
const PRODUCER: [u8; 32] = [0x35; 32];
const MERGE: [u8; 32] = [0x36; 32];
const CLAIM: [u8; 32] = [0xdd; 32];
const STALE: [u8; 32] = [0xde; 32];

fn generic_artifact(fixture: &CausalFixture) -> CodeArtifact {
    let network: &Network = &fixture.network;
    let origin: PackageOrigin = PackageOrigin::unverified(
        fixture::chain(),
        *network.signers[0].id.as_bytes(),
        [0x70; 32],
    )
    .unwrap();
    let names: [&str; 3] = ["call", "init", "trap"];
    let abi: ExecutableAbi = ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin: origin.clone(),
                constructors: Vec::new(),
                entrypoints: names
                    .iter()
                    .map(|name: &&str| EntrypointDeclaration {
                        name: (*name).into(),
                        type_parameters: Vec::new(),
                        objects: Vec::new(),
                    })
                    .collect(),
            },
            arguments: vec![ValueLayout::Tuple(Vec::new()); names.len()],
            bodies: Vec::new(),
        },
        initializer: Some("init".into()),
        transferable_constructors: Vec::new(),
        results: vec![Vec::new(); names.len()],
    };
    // This is an ordinary user contract, not Standard Asset or a native/mock
    // engine. Its trap is deterministic real WASM execution; fees are still
    // reserved and settled by the separate public fee-module contract.
    CodeArtifact::new(ArtifactParts {
        context: fixture::protocol(),
        origin,
        revision: 1,
        wasm_profile: 4,
        semantics: generic_object_result_semantics(&network.resolver, &fixture::protocol()).unwrap(),
        wasm: wat::parse_str(
            "(module (memory (export \"memory\") 1 2) (func (export \"call\")) (func (export \"init\")) (func (export \"trap\") unreachable))",
        )
        .unwrap(),
        unverified_abi: encode_executable_abi(&abi).unwrap(),
        exports: names.iter().map(|name: &&str| (*name).into()).collect(),
        // A real exact immutable reference, verified through the ordinary
        // loader. No copied source row serves as a dependency authority.
        unverified_dependencies: vec![fixture.instance.code.clone()],
    })
    .unwrap()
}

fn paid_application(
    fixture: &CausalFixture,
    request_id: [u8; 32],
    nonce: u64,
    source: &Object,
    application: PaidApplication,
) -> Vec<u8> {
    let network: &Network = &fixture.network;
    let sender: [u8; 32] = *network.signers[0].id.as_bytes();
    let intent: PaidIntent = PaidIntent {
        context: fixture::protocol(),
        request_id,
        sender,
        nonce,
        fee_policy_digest: paid_fee_policy_digest(&network.resolver, &fixture.manifest.fee_policy)
            .unwrap(),
        consent: FeeSourceConsent {
            source: object_ref(network, source),
            access: ReservationAccessKind::Write,
            max_fee: fees::Amount::new(1_000_000),
            refund_recipient: sender,
        },
        application,
        gas_limit: 100_000,
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = paid_intent_signing_frame(&fixture::protocol(), &intent).unwrap();
    encode_signed_paid_intent(&SignedPaidIntent {
        signature: network.signers[0].key.sign(&frame).into(),
        intent,
    })
    .unwrap()
}

fn contract_call(
    fixture: &CausalFixture,
    instance: &InstanceRecord,
    request_id: [u8; 32],
    nonce: u64,
    entrypoint: &str,
) -> CallIntent {
    CallIntent {
        context: fixture::protocol(),
        request_id,
        sender: *fixture.network.signers[0].id.as_bytes(),
        nonce,
        code: instance.code.clone(),
        instance: instance_target(&fixture.network.resolver, instance).unwrap(),
        entrypoint: entrypoint.into(),
        type_arguments: Vec::new(),
        access: abi::AccessManifest {
            entries: Vec::new(),
        },
        arguments: public_standard_asset::no_arguments().unwrap(),
        gas_limit: 100_000,
    }
}

fn refund_source(fixture: &CausalFixture, material: &CertifiedPaidMaterial) -> Object {
    current_object(
        &fixture.network,
        0,
        material
            .result
            .charged
            .as_ref()
            .unwrap()
            .refund_output
            .as_ref()
            .unwrap()
            .id,
    )
}

fn remaining_fee_source(fixture: &CausalFixture) -> Object {
    // Write reservation preserves the original Coin with balance - reserved.
    // The separate settle refund is only reserved - actual and cannot fund
    // another full quote. Resolve the genuine updated head/version instead.
    current_object(&fixture.network, 0, fixture.manifest.objects[1].object.id)
}

/// Three additional genuine normal-AV producers for the bounded inactive
/// import/resume fixture. No supplied effect, receipt or producer row is used.
pub(super) fn generic_import_prefix(fixture: &CausalFixture) -> Vec<CertifiedPaidMaterial> {
    let network: &Network = &fixture.network;
    let artifact: CodeArtifact = generic_artifact(fixture);
    let code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        1,
        fixture::protocol(),
        artifact_commitment(&network.resolver, &fixture::protocol(), &artifact).unwrap(),
    )
    .unwrap();
    let publish: Vec<u8> = paid_application(
        fixture,
        [0x63; 32],
        0,
        &remaining_fee_source(fixture),
        PaidApplication::Publish(artifact),
    );
    let published: CertifiedPaidMaterial = certify_and_apply_paid(fixture, &publish, 11);
    let instance: InstanceRecord = InstanceRecord {
        context: fixture::protocol(),
        creator: *network.signers[0].id.as_bytes(),
        seed: [0x71; 32],
        code,
        revision: 1,
        initializer: "init".into(),
    };
    let instantiate: Vec<u8> = paid_application(
        fixture,
        [0x64; 32],
        1,
        &remaining_fee_source(fixture),
        PaidApplication::Instantiate(contract_call(fixture, &instance, [0x64; 32], 1, "init")),
    );
    let instantiated: CertifiedPaidMaterial = certify_and_apply_paid(fixture, &instantiate, 12);
    let call: Vec<u8> = paid_application(
        fixture,
        [0x65; 32],
        2,
        &remaining_fee_source(fixture),
        PaidApplication::Call(contract_call(fixture, &instance, [0x65; 32], 2, "call")),
    );
    let called: CertifiedPaidMaterial = certify_and_apply_paid(fixture, &call, 13);
    vec![published, instantiated, called]
}

fn freeze_and_drain(fixture: &CausalFixture, materials: &[CertifiedPaidMaterial]) {
    let network: &Network = &fixture.network;
    let freeze: OrderedCandidate = freeze_candidate(FREEZE_REQUEST);
    for view in 7..=9 {
        network.round(view, (view == 7).then_some(&freeze));
    }
    let mut selected: Vec<(FrozenFrontierVote, FrozenFrontierPage)> = Vec::new();
    for replica in 0..3 {
        let mut finalized: bool = false;
        for _ in 0..=materials.len() {
            if matches!(
                advance_frozen_frontier(
                    &network.stores[replica],
                    &network.context,
                    network.domain(),
                    &network.resolver,
                    &network.history,
                    &fixture::protocol(),
                    &network.signers[replica],
                )
                .unwrap(),
                FrozenFrontierStep::Finalized(_)
            ) {
                finalized = true;
                break;
            }
        }
        assert!(finalized);
        let pair: (FrozenFrontierVote, FrozenFrontierPage) = read_frozen_frontier_page(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            network.signers[replica].id,
            None,
            NonZeroUsize::new(materials.len() + 1).unwrap(),
        )
        .unwrap();
        assert!(pair.1.terminal);
        assert_eq!(pair.1.entries.len(), materials.len());
        selected.push(pair);
    }
    selected.sort_by_key(|(vote, _)| vote.validator);
    let bundles: Vec<&[u8]> = materials
        .iter()
        .map(|item| item.bundle.as_slice())
        .collect();
    let mut union: Option<DrainUnionIdentity> = None;
    for replica in 0..REPLICAS {
        let current: DrainUnionIdentity = derive_ready(network, replica, &selected, &bundles);
        if let Some(expected) = &union {
            assert_eq!(&current, expected);
        } else {
            union = Some(current);
        }
    }
    let intent: DrainSetIntent = DrainSetIntent {
        context: fixture::protocol(),
        request_id: DRAIN_REQUEST,
        selected_votes: selected.iter().map(|(vote, _)| vote.clone()).collect(),
        drain_union_identity: union.unwrap(),
    };
    let drain: OrderedCandidate = OrderedCandidate {
        context: fixture::protocol(),
        request_id: DRAIN_REQUEST,
        kind: OrderedOperationKind::DrainSet,
        intent: encode_drain_set_intent(&intent).unwrap(),
        created_checkpoint: 30,
    };
    for view in 10..=12 {
        network.round(view, (view == 10).then_some(&drain));
    }
    for view in 13..=15 {
        network.round(view, None);
    }
}

#[test]
fn preseal_cut_genuine_generic_contract_charged_trap_assets_and_economics_reverify() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    let artifact: CodeArtifact = generic_artifact(&fixture);
    let origin: PackageOrigin = artifact.origin().clone();
    let code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        origin.clone(),
        1,
        fixture::protocol(),
        artifact_commitment(&network.resolver, &fixture::protocol(), &artifact).unwrap(),
    )
    .unwrap();
    let publish: Vec<u8> = paid_application(
        &fixture,
        PUBLISH,
        0,
        &fixture.manifest.objects[1].object,
        PaidApplication::Publish(artifact),
    );
    let published: CertifiedPaidMaterial = certify_and_apply_paid(&fixture, &publish, 11);
    let instance: InstanceRecord = InstanceRecord {
        context: fixture::protocol(),
        creator: *network.signers[0].id.as_bytes(),
        seed: [0x71; 32],
        code,
        revision: 1,
        initializer: "init".into(),
    };
    let instantiate: Vec<u8> = paid_application(
        &fixture,
        INSTANTIATE,
        1,
        &remaining_fee_source(&fixture),
        PaidApplication::Instantiate(contract_call(&fixture, &instance, INSTANTIATE, 1, "init")),
    );
    let instantiated: CertifiedPaidMaterial = certify_and_apply_paid(&fixture, &instantiate, 12);
    assert_eq!(
        instantiated.result.target,
        PaidResultTarget::Instance(instance.clone())
    );
    let call: Vec<u8> = paid_application(
        &fixture,
        CALL,
        2,
        &remaining_fee_source(&fixture),
        PaidApplication::Call(contract_call(&fixture, &instance, CALL, 2, "call")),
    );
    let called: CertifiedPaidMaterial = certify_and_apply_paid(&fixture, &call, 13);
    let trap: Vec<u8> = paid_application(
        &fixture,
        TRAP,
        3,
        &remaining_fee_source(&fixture),
        PaidApplication::Call(contract_call(&fixture, &instance, TRAP, 3, "trap")),
    );
    let trapped: CertifiedPaidMaterial = certify_paid_with_expected_status(
        &fixture,
        &trap,
        14,
        &[0, 1, 2, 3],
        &[0, 1, 2, 3],
        &[0, 1, 2, 3],
        true,
        PaidExecutionStatus::ApplicationFailed,
    );
    assert!(trapped.result.charged.as_ref().unwrap().actual.get() > 0);
    assert_eq!(
        query_sender_next_nonce(
            &network.stores[0],
            &network.context,
            network.domain(),
            fixture::chain(),
            fixture::protocol().protocol_version(),
            fixture::protocol().epoch(),
            *network.signers[0].id.as_bytes(),
        )
        .unwrap(),
        4,
        "a charged trap is an original nonce-consuming completion"
    );
    let remaining: Object = remaining_fee_source(&fixture);
    let refund: Object = refund_source(&fixture, &trapped);
    assert!(public_standard_asset::coin_amount(&remaining.data).unwrap() > 100_000);
    assert!(public_standard_asset::coin_amount(&refund.data).unwrap() > 0);
    let merge_call: CallIntent = CallIntent {
        context: fixture::protocol(),
        request_id: MERGE,
        sender: *network.signers[0].id.as_bytes(),
        nonce: 4,
        code: fixture.instance.code.clone(),
        instance: instance_target(&network.resolver, &fixture.instance).unwrap(),
        entrypoint: "merge".into(),
        type_arguments: fixture.manifest.fee_policy.type_arguments.clone(),
        access: abi::AccessManifest {
            entries: vec![
                abi::AccessEntry {
                    object_ref: object_ref(network, &remaining),
                    mode: AccessMode::Write,
                },
                abi::AccessEntry {
                    object_ref: object_ref(network, &refund),
                    mode: AccessMode::Consume,
                },
            ],
        },
        arguments: public_standard_asset::no_arguments().unwrap(),
        gas_limit: 100_000,
    };
    let merge: Vec<u8> = paid_application(
        &fixture,
        MERGE,
        4,
        &remaining,
        PaidApplication::Call(merge_call),
    );
    let merged: CertifiedPaidMaterial = certify_and_apply_paid(&fixture, &merge, 15);
    let asset: Vec<u8> = paid_transfer(&fixture, 0, &remaining_fee_source(&fixture), ASSET, 5);
    let asset_material: CertifiedPaidMaterial = certify_and_apply_paid(&fixture, &asset, 16);
    let producer: Vec<u8> = paid_transfer(&fixture, 1, &fixture.claimant_coin, PRODUCER, 0);
    let producer_material: CertifiedPaidMaterial = certify_and_apply_paid(&fixture, &producer, 17);
    let (claim, expected): (OrderedCandidate, FastPathSettlementRecord) =
        positive_claim(&fixture, ASSET, CLAIM);
    let (stale, _): (OrderedCandidate, FastPathSettlementRecord) =
        positive_claim_for(&fixture, ASSET, STALE, 2, 0);
    for view in 1..=3 {
        network.round(view, (view == 1).then_some(&claim));
    }
    for view in 4..=6 {
        let (outputs, _, _) = network.round(view, (view == 4).then_some(&stale));
        if view == 6 {
            for output in &outputs {
                assert_eq!(
                    refusal_of(&output.committed[0]),
                    OrderedRefusal::StaleGeneration
                );
            }
        }
    }
    assert_eq!(settlement(network, 0, ASSET), expected);
    assert_eq!(nonce(network, 0), 2);
    let materials: Vec<CertifiedPaidMaterial> = vec![
        published,
        instantiated,
        called,
        trapped,
        merged,
        asset_material,
        producer_material,
    ];
    freeze_and_drain(&fixture, &materials);
    let before: SourceBusinessSnapshot = snapshot(network);
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let cut: VerifiedBusinessCut = derive_source_business_cut(
        reconstruction_plan(&fixture, &identity),
        &network.stores[0],
        &network.blobs,
        &history,
    )
    .unwrap();
    assert_eq!(
        cut.identity().drain_union.member_count,
        materials.len() as u64
    );
    assert_eq!(snapshot(network), before);
    let saved: SavedBusinessCut = transfer(&cut, &network.resolver);
    for request in [
        PUBLISH,
        INSTANTIATE,
        CALL,
        TRAP,
        MERGE,
        ASSET,
        PRODUCER,
        CLAIM,
        STALE,
    ] {
        let original: DurableRequestReceipt = receipt(network, 0, request).unwrap();
        let saved_receipt = saved
            .components
            .iter()
            .find(|item| {
                item.descriptor.collection == BusinessCutCollection::Receipts
                    && item.descriptor.key == request
            })
            .unwrap();
        assert_eq!(
            saved_receipt.bytes,
            original.canonical_bytes(),
            "full original success/refusal/trap receipt, never a synthetic digest"
        );
    }
    for key in [
        crate::publication::publication_record_key(&origin).unwrap(),
        crate::local_instance_state::instance_record_key(
            &fixture::chain(),
            &instance.creator,
            &instance.seed,
        )
        .unwrap(),
    ] {
        let actual = network.stores[0]
            .get_versioned_durable(&network.context, network.domain(), &key)
            .unwrap();
        let component = saved
            .components
            .iter()
            .find(|item| {
                item.descriptor.collection == BusinessCutCollection::State
                    && item.descriptor.key == key
            })
            .unwrap();
        assert_eq!(component.bytes.as_slice(), actual.value().unwrap());
    }
    let versions: Vec<&SourceSnapshotRecord> = before
        .records
        .iter()
        .filter(|row| matches!(row.descriptor.key(), DurableRecordKey::ObjectVersion(..)))
        .collect();
    assert!(versions.len() > fixture.manifest.objects.len());
    for row in versions {
        let DurableRecordKey::ObjectVersion(id, version) = row.descriptor.key() else {
            unreachable!()
        };
        let mut key: Vec<u8> = id.as_bytes().to_vec();
        key.extend_from_slice(&version.get().to_be_bytes());
        assert!(
            cut.descriptor(BusinessCutCollection::ObjectVersions, &key)
                .is_ok(),
            "every immutable historical version is retained"
        );
    }
    assert!(
        saved
            .components
            .iter()
            .any(
                |item| item.descriptor.collection == BusinessCutCollection::ObjectHeads
                    && decode_canonical_frame(&item.descriptor.metadata)
                        .unwrap()
                        .required_u16(2)
                        .unwrap()
                        == 0
            ),
        "the genuinely consumed refund Coin retains its authenticated deleted head"
    );
    let profile_key: Vec<u8> = logical_profile_key(&fixture::chain()).unwrap();
    let profile_bytes = network.stores[0]
        .get_versioned_durable(&network.context, network.domain(), &profile_key)
        .unwrap();
    let mut expected_floor: ExecutionGeneration =
        decode_logical_profile_record(profile_bytes.value().unwrap())
            .unwrap()
            .genesis_floor;
    for row in &before.records {
        if let DurableRecordKey::State(key) = row.descriptor.key()
            && is_logical_provenance_key(key)
            && !is_logical_profile_key(key)
        {
            expected_floor = expected_floor.max(
                decode_logical_provenance_record(row.value.as_deref().unwrap())
                    .unwrap()
                    .generation,
            );
        }
    }
    for material in &materials {
        let bundle: PublicationBundle =
            consensus::bundle::decode_publication_bundle(&material.bundle).unwrap();
        expected_floor = expected_floor.max(ExecutionGeneration::new(
            decode_canonical_frame(&bundle.witness)
                .unwrap()
                .required_u64(11)
                .unwrap(),
        ));
    }
    assert_eq!(
        cut.identity().generation_floor,
        expected_floor,
        "the authenticated maximum includes deleted/control subjects and applied witnesses, not local installation coordinates"
    );
    let verified: VerifiedBusinessCut =
        verify_saved_business_cut(reconstruction_plan(&fixture, &identity), &saved).unwrap();
    assert_eq!(verified.cut_digest(), cut.cut_digest());
    assert_eq!(verified.package_digest(), cut.package_digest());
    // An internally consistent transfer claim missing code-reference artifact
    // bytes is not complete. The independent executor/package comparison must
    // refuse it even after all untrusted checksums have been refreshed.
    let mut missing: SavedBusinessCut = saved.clone();
    let code_key: Vec<u8> = crate::publication::publication_record_key(&origin).unwrap();
    let code_value = network.stores[0]
        .get_versioned_durable(&network.context, network.domain(), &code_key)
        .unwrap();
    let artifact_index: usize = missing
        .components
        .iter()
        .position(|item| {
            item.descriptor.collection == BusinessCutCollection::Artifacts
                && item.bytes.as_slice() == code_value.value().unwrap()
        })
        .expect("the actual code-reference artifact must be in the semantic artifact stream");
    missing.components.remove(artifact_index);
    refresh_package(&mut missing, &network.resolver);
    assert!(verify_saved_business_cut(reconstruction_plan(&fixture, &identity), &missing).is_err());
    let mut corrupt: SavedBusinessCut = saved.clone();
    let item = corrupt
        .components
        .iter_mut()
        .find(|item| {
            item.descriptor.collection == BusinessCutCollection::Artifacts && !item.bytes.is_empty()
        })
        .unwrap();
    item.bytes[0] ^= 1;
    item.descriptor.digest =
        business_cut_component_digest(&network.resolver, &fixture::protocol(), &item.bytes)
            .unwrap();
    refresh_package(&mut corrupt, &network.resolver);
    assert!(verify_saved_business_cut(reconstruction_plan(&fixture, &identity), &corrupt).is_err());
    let mut corrupt_closure: SavedBusinessCut = saved;
    let mut bundle_key: Vec<u8> = vec![2];
    bundle_key.extend_from_slice(&INSTANTIATE);
    let bundle = corrupt_closure
        .components
        .iter_mut()
        .find(|item| {
            item.descriptor.collection == BusinessCutCollection::Proofs
                && item.descriptor.key == bundle_key
        })
        .unwrap();
    let position: usize = bundle
        .bytes
        .windows(code_value.value().unwrap().len())
        .position(|bytes| bytes == code_value.value().unwrap())
        .expect("the retained Instantiate proof carries the exact code-reference artifact closure");
    bundle.bytes[position] ^= 1;
    bundle.descriptor.digest =
        business_cut_component_digest(&network.resolver, &fixture::protocol(), &bundle.bytes)
            .unwrap();
    refresh_package(&mut corrupt_closure, &network.resolver);
    assert!(
        verify_saved_business_cut(reconstruction_plan(&fixture, &identity), &corrupt_closure)
            .is_err(),
        "refreshing transfer digests does not authenticate altered code closure bytes"
    );
    assert_eq!(snapshot(network), before);
}
