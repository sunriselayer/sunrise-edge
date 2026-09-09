//! Real-WASM integration test for `PaidContractEngine` (DR-0124
//! "Authenticated durable integration", 2026-09-08). Runs the actual public
//! Standard Asset WASM through the production store/host/frame validator;
//! no native balance backdoor and no fake authenticated witness.
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::*;
use execution::paid_execution::*;
use execution::publication::*;
use execution::{ExecutionStatus, LocalWasmExecutionEngine, ObjectEffect};

/// The only in-crate [`PaidContractEngine`] implementation. Using the trait
/// here is what proves the boundary is injectable rather than a concrete
/// unit struct, and that `execute_paid` does not collide with the zero-fee
/// `LocalContractEngine::execute` on the same type.
fn paid_engine() -> impl PaidContractEngine {
    LocalWasmExecutionEngine::new()
}
use fees::{Amount, GasSchedule};
use hashing::HashSuiteResolver;
use objects::{AccessMode, Object, ObjectId};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashPurpose, HashSuite, HashSuiteId,
    HashSuiteSchedule, ProtocolVersion,
};
use public_standard_asset::{StandardAssetPackage, build_package};
/// Locates one decoded field's payload byte range inside its original
/// encoded frame, for targeted corruption in the codec regressions below.
fn field_range(bytes: &[u8], field_id: u16) -> std::ops::Range<usize> {
    let frame = canonical_encoding::decode_canonical_frame(bytes).unwrap();
    let slice = frame.required_field(field_id).unwrap();
    let start = slice.as_ptr() as usize - bytes.as_ptr() as usize;
    start..start + slice.len()
}

#[test]
fn paid_contract_engine_rejects_a_forged_fee_source_digest() {
    // Item 1: the fee source comparison must use the complete canonical
    // `ObjectRef`, including its content digest, not merely id/version.
    let asset: Asset = asset(32, 32, 1_000);
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);
    let policy_digest = paid_fee_policy_digest(&resolver(), &policy).unwrap();

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    // Same id and version as the actually supplied object, but a forged
    // digest: this must never be accepted as a match.
    let forged_source_ref = objects::ObjectRef {
        id: coin_source.resolved.object.id,
        version: coin_source.resolved.object.version,
        digest: resolver()
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, b"forged-object-body")
            .unwrap(),
    };

    let application = CallIntent {
        context: context(),
        request_id: [9; 32],
        sender: sender(),
        nonce: 3,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "transfer".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest { entries: vec![] },
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        gas_limit: 100_000,
    };
    let intent = PaidIntent {
        context: context(),
        request_id: [9; 32],
        sender: sender(),
        nonce: 3,
        fee_policy_digest: policy_digest,
        consent: FeeSourceConsent {
            source: forged_source_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    };
    let frame = paid_intent_signing_frame(&context(), &intent).unwrap();
    let signature: [u8; 64] = key().sign(&frame).into();
    let signed = SignedPaidIntent { intent, signature };
    let bytes = encode_signed_paid_intent(&signed).unwrap();
    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();

    let request = PaidExecutionRequest {
        authenticated: &authenticated,
        resolver: &resolver(),
        base_policy: &base_policy,
        fee_policy: &policy,
        scopes: &scopes,
        source: coin_source,
        application: PaidApplicationScopes::Call {
            scope: 0,
            inputs: &[],
        },
    };
    assert!(paid_engine().execute_paid(request).is_err());
}

// ── Historical references across a real hash-suite rotation ─────────────
//
// Every fixture above is created at epoch zero. The tests below execute a
// paid invocation at epoch one, after the trusted schedule really switched
// the active algorithm, so an object, instance or code reference committed
// before the rotation can only be verified under its own recorded
// algorithm. That is the historical-compatibility case, not an attack.

/// The invocation epoch used by the rotation tests: one epoch after every
/// fixture object, instance record and artifact was committed.
fn later_context() -> PublicationContext {
    PublicationContext::new(
        context().chain_id().clone(),
        context().protocol_version(),
        Epoch::new(1),
    )
    .unwrap()
}

/// A trusted resolver whose schedule switches from the genesis SHA-2 suite
/// to a SHA-3 suite at epoch one. Evaluated at epoch zero it is identical
/// to [`resolver`], so the epoch-zero fixtures are unchanged.
fn rotating_resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        context().chain_id().clone(),
        context().protocol_version(),
        vec![
            HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            },
            HashSuiteSchedule {
                activation_epoch: Epoch::new(1),
                suite: HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
            },
        ],
    )
    .unwrap()
}

/// The same pinned fee implementation, committed for the later epoch.
fn later_fee_policy(asset: &Asset) -> PaidFeePolicy {
    let mut policy: PaidFeePolicy = fee_policy(asset);
    policy.context = later_context();
    policy.base_policy_digest = LocalExecutionPolicy::generic_object_results(later_context())
        .digest(&rotating_resolver())
        .unwrap();
    policy
}

/// Runs one authenticated paid `transfer` at the later epoch against
/// fixtures committed before the rotation. `forged_source_digest` replaces
/// only the consent's content digest, leaving its id and version genuine.
fn later_transfer_attempt(
    asset: &Asset,
    forged_source_digest: Option<Digest32>,
    request_id: [u8; 32],
    nonce: u64,
) -> TransferAttempt {
    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(later_context());
    let policy: PaidFeePolicy = later_fee_policy(asset);
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    // The genuine reference is self-describing and was committed under the
    // pre-rotation algorithm. A forged digest replaces it in *both* the
    // consent and the application access entry, so the two signed
    // references stay identical and the rejection under test is the
    // engine's digest verification, not the wire-level overlap rule.
    let genuine = object_ref_of(&coin_source.resolved.object);
    let source_ref = objects::ObjectRef {
        id: genuine.id,
        version: genuine.version,
        digest: forged_source_digest.unwrap_or(genuine.digest),
    };

    let application = CallIntent {
        context: later_context(),
        request_id,
        sender: sender(),
        nonce,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "transfer".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: source_ref.clone(),
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        gas_limit: 100_000,
    };
    let intent = PaidIntent {
        context: later_context(),
        request_id,
        sender: sender(),
        nonce,
        fee_policy_digest: paid_fee_policy_digest(&rotating_resolver(), &policy).unwrap(),
        consent: FeeSourceConsent {
            source: source_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    };
    let frame = paid_intent_signing_frame(&later_context(), &intent).unwrap();
    let signature: [u8; 64] = key().sign(&frame).into();
    let signed = SignedPaidIntent { intent, signature };
    let bytes = encode_signed_paid_intent(&signed).unwrap();
    let authenticated =
        authenticate_paid_intent(&rotating_resolver(), &later_context(), &bytes).unwrap();
    let outcome = paid_engine().execute_paid(PaidExecutionRequest {
        authenticated: &authenticated,
        resolver: &rotating_resolver(),
        base_policy: &base_policy,
        fee_policy: &policy,
        scopes: &scopes,
        source: coin_source.clone(),
        application: PaidApplicationScopes::Call {
            scope: 0,
            inputs: std::slice::from_ref(&coin_source),
        },
    });
    TransferAttempt {
        outcome,
        authenticated,
        policy,
    }
}

#[test]
fn a_pre_rotation_fee_source_reference_still_executes_after_a_hash_suite_switch() {
    // Existing references are self-describing: rehashing the supplied body
    // under the *active* suite would reject a perfectly valid historical
    // input. The engine must verify the signed digest under the algorithm
    // recorded in the digest itself.
    let asset: Asset = asset(55, 55, 1_000);
    let signed_ref = object_ref_of(&asset.coin.resolved.object);
    let rehashed = rotating_resolver()
        .hash_for_purpose(
            Epoch::new(1),
            HashPurpose::Object,
            &objects::encode_object(&asset.coin.resolved.object).unwrap(),
        )
        .unwrap();
    assert_ne!(
        rehashed, signed_ref.digest,
        "the rotation must actually change the active object algorithm"
    );

    let attempt = later_transfer_attempt(&asset, None, [60; 32], 60);
    let outcome: PaidExecutionOutcome = attempt
        .outcome
        .expect("a pre-rotation fee source must still be spendable");
    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);
    let charged = outcome.result.charged.as_ref().unwrap();
    assert!(charged.actual.get() > 0);

    // The fee instance was created before the rotation, so its outputs'
    // authority rows record that older original context, never the current
    // policy context. Independent verification must still accept them.
    assert_ne!(asset.scope.instance.context, later_context());
    verify_paid_execution_result(
        &outcome,
        &attempt.authenticated,
        &rotating_resolver(),
        &LocalExecutionPolicy::generic_object_results(later_context()),
        &attempt.policy,
        &asset.scope.instance,
        &[],
    )
    .expect("a later-epoch charged receipt must verify independently");
}

#[test]
fn a_forged_pre_rotation_fee_source_digest_is_still_rejected() {
    // Verifying under the digest's own recorded algorithm is not a licence
    // to accept any digest carrying a legitimate algorithm tag: the body
    // must actually hash to it.
    let asset: Asset = asset(56, 56, 1_000);
    let forged: Digest32 = resolver()
        .hash_for_purpose(
            Epoch::new(0),
            HashPurpose::Object,
            b"forged-pre-rotation-body",
        )
        .unwrap();
    let error = later_transfer_attempt(&asset, Some(forged), [61; 32], 61)
        .outcome
        .expect_err("a forged consent digest must be rejected");
    assert!(
        format!("{error}").contains("fee source reference mismatch"),
        "{error}"
    );
}

#[test]
fn independent_verification_pins_the_trusted_fee_instance_and_its_context() {
    let asset: Asset = asset(57, 57, 1_000);
    let attempt = later_transfer_attempt(&asset, None, [62; 32], 62);
    let outcome: PaidExecutionOutcome = attempt.outcome.expect("later-epoch transfer");
    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(later_context());
    let check = |candidate: &PaidExecutionOutcome, record: &InstanceRecord| {
        verify_paid_execution_result(
            candidate,
            &attempt.authenticated,
            &rotating_resolver(),
            &base_policy,
            &attempt.policy,
            record,
            &[],
        )
    };
    check(&outcome, &asset.scope.instance).expect("the genuine receipt verifies");

    // The supplied fee instance is pinned to the policy by an independently
    // derived instance target, so an unrelated record is rejected before
    // any output is checked.
    let mut forged_record: InstanceRecord = asset.scope.instance.clone();
    forged_record.seed = [0xAB; 32];
    assert_message(
        check(&outcome, &forged_record),
        "paid result fee instance authority",
    );

    // Restamping the record's original context to the current policy
    // context changes its derived target, and is rejected too: the context
    // is a consequence of the checked record, never a caller claim.
    let mut restamped: InstanceRecord = asset.scope.instance.clone();
    restamped.context = later_context();
    assert_message(
        check(&outcome, &restamped),
        "paid result fee instance authority",
    );

    // A settlement output whose authority row claims the *current* policy
    // context rather than the fee instance's own original context is
    // rejected, even though that value equals the policy field.
    let fee_id: ObjectId = outcome.result.charged.as_ref().unwrap().fee_output.id;
    let mut tampered: PaidExecutionOutcome = outcome.clone();
    for created in &mut tampered.created_authorities {
        if created.authority.object_id == fee_id {
            created.authority.instance_context = later_context();
        }
    }
    assert_message(
        check(&tampered, &asset.scope.instance),
        "paid result fee output authority",
    );
}

/// Rewrites the created object behind a receipt's fee output and recomputes
/// that output's canonical `ObjectRef`, so only the property under test
/// differs from a genuine receipt.
fn edit_fee_output(outcome: &mut PaidExecutionOutcome, edit: impl FnOnce(&mut Object)) {
    let id: ObjectId = outcome.result.charged.as_ref().unwrap().fee_output.id;
    for effect in &mut outcome.result.effects.object_effects {
        if let ObjectEffect::Created(object) = effect
            && object.id == id
        {
            edit(object);
            outcome.result.charged.as_mut().unwrap().fee_output = object_ref_of(object);
            return;
        }
    }
    panic!("the receipt has no created fee output");
}

#[test]
fn independent_verification_checks_settlement_output_identity_not_only_its_authority_row() {
    // The sidecar authority's `ty` field is a claim about the object; the
    // object's own stored `type_hash`, version and host-derived identity
    // are the commitments. All of them must reproduce.
    let asset: Asset = asset(58, 58, 1_000);
    let attempt = transfer_attempt(
        &asset,
        std::slice::from_ref(&asset.scope),
        AccessMode::Write,
        [63; 32],
        63,
    );
    let outcome: PaidExecutionOutcome = attempt.outcome.expect("transfer");
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let check = |candidate: &PaidExecutionOutcome| {
        verify_paid_execution_result(
            candidate,
            &attempt.authenticated,
            &resolver(),
            &base_policy,
            &attempt.policy,
            &asset.scope.instance,
            &[],
        )
    };
    check(&outcome).expect("the genuine receipt verifies");

    // A stored `type_hash` committing to the reservation type instead of
    // the pinned asset type, with the authority row and the recomputed
    // reference both left consistent.
    let mut tampered: PaidExecutionOutcome = outcome.clone();
    let reservation_type_hash = abi::package_types::derive_scoped_type_id(
        &resolver(),
        Epoch::new(0),
        &attempt.policy.reservation_type,
    )
    .unwrap();
    edit_fee_output(&mut tampered, |object| {
        object.type_hash = reservation_type_hash;
    });
    assert_message(check(&tampered), "paid result fee output identity");

    // A settlement output is always freshly created, so any version other
    // than one is not a fresh creation.
    let mut tampered = outcome.clone();
    edit_fee_output(&mut tampered, |object| object.version = 2);
    assert_message(check(&tampered), "paid result fee output identity");

    // A creation ordinal that no longer reproduces the host-derived
    // creation identity of the object it claims to describe.
    let fee_id: ObjectId = outcome.result.charged.as_ref().unwrap().fee_output.id;
    let mut tampered = outcome.clone();
    for created in &mut tampered.created_authorities {
        if created.authority.object_id == fee_id {
            created.creation_ordinal = 7;
        }
    }
    assert_message(check(&tampered), "paid result fee output identity");

    // The same created object listed twice: a set-based comparison would
    // silently deduplicate it.
    let mut tampered = outcome.clone();
    let duplicate: ObjectEffect = tampered
        .result
        .effects
        .object_effects
        .iter()
        .find(|effect| matches!(effect, ObjectEffect::Created(_)))
        .cloned()
        .expect("a created effect");
    tampered.result.effects.object_effects.push(duplicate);
    assert_message(check(&tampered), "paid result duplicate created effect");
}

#[test]
fn a_post_execution_version_overflow_is_a_real_host_rejected_receipt() {
    // A genuine post-execution deterministic host failure, not an injected
    // fault: the fee source is already at the maximum representable
    // version, so the reserve phase's in-place debit and the application's
    // transfer both commit, and only the final effect collection fails its
    // checked version increment. Everything must then be discarded, while
    // the future durable admission layer must commit the consumed nonce and
    // this receipt atomically (this engine test does not exercise storage).
    let asset: Asset = asset(59, 59, 1_000);
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    coin_source.resolved.object.version = u64::MAX;
    // The signed references describe the object actually supplied.
    let source_ref = object_ref_of(&coin_source.resolved.object);

    let application = CallIntent {
        context: context(),
        request_id: [64; 32],
        sender: sender(),
        nonce: 64,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "transfer".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: source_ref.clone(),
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        gas_limit: 100_000,
    };
    let authenticated = authenticate(PaidIntent {
        context: context(),
        request_id: [64; 32],
        sender: sender(),
        nonce: 64,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &policy).unwrap(),
        consent: FeeSourceConsent {
            source: source_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    });
    let outcome: PaidExecutionOutcome = paid_engine()
        .execute_paid(PaidExecutionRequest {
            authenticated: &authenticated,
            resolver: &resolver(),
            base_policy: &base_policy,
            fee_policy: &policy,
            scopes: &scopes,
            source: coin_source.clone(),
            application: PaidApplicationScopes::Call {
                scope: 0,
                inputs: std::slice::from_ref(&coin_source),
            },
        })
        .expect("a post-reserve host failure is a receipt, never a bare error");

    assert_eq!(outcome.result.status, PaidExecutionStatus::HostRejected);
    assert!(outcome.result.charged.is_none());
    assert!(outcome.result.effects.object_effects.is_empty());
    assert!(outcome.result.effects.events.is_empty());
    assert!(outcome.created_authorities.is_empty());
    assert!(
        matches!(
            outcome.result.effects.status,
            ExecutionStatus::Failure { .. }
        ),
        "a host-rejected receipt is a normalized failure"
    );
    // The invocation really executed: the reported gas is the fuel the
    // phases measured, not zero.
    assert!(
        outcome.result.effects.gas_used > 0,
        "the phases must report their measured fuel"
    );
    verify_paid_execution_result(
        &outcome,
        &authenticated,
        &resolver(),
        &base_policy,
        &policy,
        &asset.scope.instance,
        &[],
    )
    .expect("the zero-charge host-rejected receipt verifies independently");
}

#[test]
fn paid_contract_engine_runs_a_real_mint_call_that_traps_and_still_settles_the_fee() {
    // Call/apptrap: `mint` writes the TreasuryCap supply and only then
    // fails at the host create boundary because the all-zero recipient is
    // not a decodable owner address, exactly as the coordinator-level
    // fault test exercises, but here through the complete authenticated
    // paid `PaidContractEngine` entry point.
    let asset: Asset = asset(33, 33, 1_000);
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);
    let policy_digest = paid_fee_policy_digest(&resolver(), &policy).unwrap();

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let source_ref = objects::ObjectRef {
        id: coin_source.resolved.object.id,
        version: coin_source.resolved.object.version,
        digest: resolver()
            .hash_for_purpose(
                Epoch::new(0),
                HashPurpose::Object,
                &objects::encode_object(&coin_source.resolved.object).unwrap(),
            )
            .unwrap(),
    };
    let mut cap_input = asset.scope.clone();
    let _ = &mut cap_input;
    let cap = {
        // Re-derive the cap's `ScopedResolvedObject` the same way `asset()`
        // built it: mint against the TreasuryCap created by `init`.
        let init_scopes = vec![asset.scope.clone()];
        let init = call(
            &init_scopes,
            "init",
            public_standard_asset::no_arguments().unwrap(),
            &[],
            vec![],
        );
        created(&init, 1, AccessMode::Write)
    };

    let application = CallIntent {
        context: context(),
        request_id: [10; 32],
        sender: sender(),
        nonce: 4,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "mint".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: objects::ObjectRef {
                    id: cap.resolved.object.id,
                    version: cap.resolved.object.version,
                    digest: resolver()
                        .hash_for_purpose(
                            Epoch::new(0),
                            HashPurpose::Object,
                            &objects::encode_object(&cap.resolved.object).unwrap(),
                        )
                        .unwrap(),
                },
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::mint_arguments(5, &[0u8; 32]).unwrap(),
        gas_limit: 100_000,
    };
    let intent = PaidIntent {
        context: context(),
        request_id: [10; 32],
        sender: sender(),
        nonce: 4,
        fee_policy_digest: policy_digest,
        consent: FeeSourceConsent {
            source: source_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    };
    let frame = paid_intent_signing_frame(&context(), &intent).unwrap();
    let signature: [u8; 64] = key().sign(&frame).into();
    let signed = SignedPaidIntent { intent, signature };
    let bytes = encode_signed_paid_intent(&signed).unwrap();
    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();

    let request = PaidExecutionRequest {
        authenticated: &authenticated,
        resolver: &resolver(),
        base_policy: &base_policy,
        fee_policy: &policy,
        scopes: &scopes,
        source: coin_source,
        application: PaidApplicationScopes::Call {
            scope: 0,
            inputs: std::slice::from_ref(&cap),
        },
    };
    let outcome = paid_engine().execute_paid(request).unwrap();
    assert_eq!(
        outcome.result.status,
        PaidExecutionStatus::ApplicationFailed
    );
    let charged = outcome.result.charged.as_ref().unwrap();
    assert!(charged.actual.get() > 0);
    assert_eq!(outcome.result.effects.events.len(), 0);
    // The charged failure receipt still verifies independently.
    verify_paid_execution_result(
        &outcome,
        &authenticated,
        &resolver(),
        &base_policy,
        &policy,
        &asset.scope.instance,
        &[],
    )
    .expect("independent verification");
}

#[test]
fn paid_contract_engine_treats_an_application_created_reservation_survivor_as_application_failed() {
    // Call/self-reserve: the application calls the pinned public `reserve`
    // entrypoint on its own remainder, minting a second live object of the
    // exact pinned reservation type that nothing settles. Before this fix
    // the coordinator scanned the whole arena only after settle, so this
    // survivor forced a zero-charge `SettlementFailed` outcome. It must now
    // be classified as an application failure -- discarding the
    // application's own effects, never gas -- while the host's own private
    // reservation still settles normally, exactly as the coordinator-level
    // regression proves for the internal phase plan.
    let asset: Asset = asset(65, 65, 1_000);
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);
    let policy_digest = paid_fee_policy_digest(&resolver(), &policy).unwrap();

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let source_ref = object_ref_of(&coin_source.resolved.object);
    let mut application_input = coin_source.clone();
    application_input.resolved.mode = AccessMode::Write;
    // The exact pre-execution balance and identity of the fee source, so the
    // asserted conservation below is anchored to a decoded body rather than
    // to the receipt's own reported amounts.
    let source_id: ObjectId = coin_source.resolved.object.id;
    let initial: u64 =
        public_standard_asset::coin_amount(&coin_source.resolved.object.data).unwrap();

    let application = CallIntent {
        context: context(),
        request_id: [65; 32],
        sender: sender(),
        nonce: 65,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "reserve".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: source_ref.clone(),
                mode: AccessMode::Write,
            }],
        },
        // The application's own self-issued reservation attests arbitrary
        // continuity fields: the guest cannot verify the current invocation
        // or policy, and only settlement checks stored commitment equality.
        arguments: public_standard_asset::reserve_arguments(
            1,
            &policy_digest,
            &policy_digest,
            &treasury(),
            &refund_account(),
        )
        .unwrap(),
        gas_limit: 100_000,
    };
    let authenticated = authenticate(PaidIntent {
        context: context(),
        request_id: [65; 32],
        sender: sender(),
        nonce: 65,
        fee_policy_digest: policy_digest,
        consent: FeeSourceConsent {
            source: source_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    });

    let outcome = paid_engine()
        .execute_paid(PaidExecutionRequest {
            authenticated: &authenticated,
            resolver: &resolver(),
            base_policy: &base_policy,
            fee_policy: &policy,
            scopes: &scopes,
            source: coin_source,
            application: PaidApplicationScopes::Call {
                scope: 0,
                inputs: std::slice::from_ref(&application_input),
            },
        })
        .expect("paid self-reserve call");

    assert_eq!(
        outcome.result.status,
        PaidExecutionStatus::ApplicationFailed
    );
    let charged = outcome.result.charged.as_ref().unwrap();
    assert!(charged.actual.get() > 0);
    // Reservation/source/refund conservation still holds exactly as for any
    // other charged outcome.
    assert_eq!(
        charged.actual.get() + charged.refund.get(),
        charged.reserved.get()
    );
    // The application really ran and really burned metered application fuel
    // before it was discarded: the charge is not a zero-work artefact.
    assert!(charged.application_gas_units > 0);
    // The application's own effects are gone entirely: no event survives the
    // rollback, and every decoded balance below is a settlement balance.
    assert!(outcome.result.effects.events.is_empty());

    // Bodies are decoded with the public asset package's own client-side
    // decoder; the host itself never decodes an asset body natively.
    let coin_body = |id: ObjectId| -> u64 {
        outcome
            .result
            .effects
            .object_effects
            .iter()
            .find_map(|effect| match effect {
                ObjectEffect::Created(object) if object.id == id => Some(&object.data),
                _ => None,
            })
            .map(|body| public_standard_asset::coin_amount(body).unwrap())
            .expect("a settlement output must be created")
    };
    // The fee source's final body is exactly the initial balance minus the
    // host's own reservation. The application had already deducted one more
    // unit for its self-issued reservation, so `initial - reserved - 1` here
    // would prove the rollback silently kept the application's write.
    let source_final: u64 = outcome
        .result
        .effects
        .object_effects
        .iter()
        .find_map(|effect| match effect {
            ObjectEffect::Mutated { new_object, .. } if new_object.id == source_id => {
                Some(public_standard_asset::coin_amount(&new_object.data).unwrap())
            }
            _ => None,
        })
        .expect("the fee source must survive as a mutation");
    assert_eq!(source_final, initial - charged.reserved.get());
    assert_ne!(source_final, initial - charged.reserved.get() - 1);
    // The settlement outputs carry exactly the charged and refunded units.
    assert_eq!(coin_body(charged.fee_output.id), charged.actual.get());
    let refunded: u64 = match &charged.refund_output {
        Some(refund) => coin_body(refund.id),
        None => 0,
    };
    assert_eq!(refunded, charged.refund.get());
    // Total supply is conserved across the whole invocation: the remainder
    // plus the fee plus the refund is exactly the original balance, so the
    // discarded application phase neither minted nor destroyed a unit.
    assert_eq!(source_final + charged.actual.get() + refunded, initial);
    // No application-created reservation-type object survives: only the
    // fee (and, if positive, refund) settlement outputs are created, never
    // a second live reservation.
    let reservation_type_hash = abi::package_types::derive_scoped_type_id(
        &resolver(),
        Epoch::new(0),
        &policy.reservation_type,
    )
    .unwrap();
    for effect in &outcome.result.effects.object_effects {
        if let ObjectEffect::Created(object) = effect {
            assert_ne!(
                object.type_hash, reservation_type_hash,
                "an application-created reservation must never survive"
            );
        }
    }
    for created in &outcome.created_authorities {
        assert_ne!(created.authority.ty, policy.reservation_type);
    }
    // The independent verifier still accepts this charged receipt.
    verify_paid_execution_result(
        &outcome,
        &authenticated,
        &resolver(),
        &base_policy,
        &policy,
        &asset.scope.instance,
        &[],
    )
    .expect("independent verification");
}

#[test]
fn paid_contract_engine_rejects_a_genuine_preexisting_reservation_application_input() {
    // A genuine `Reservation<A>`, minted by an ordinary earlier unpaid
    // `reserve` call on this very coin, is offered back as the paid
    // application's sole input. Everything else about the request is
    // impeccable: the signed application is a `settle` Call with exactly the
    // pinned entrypoint's ABI shape (one Consume reservation input), the
    // correct bound type argument, and continuity arguments byte-identical
    // to the commitments stored in the reservation itself -- so the guest
    // would settle it happily and mint a second fee/refund pair out of a
    // reservation this invocation never made. The updated coin, a distinct
    // object, is the fee source, so the refusal cannot be a fee-source
    // reference or access-mode failure in disguise. The host must reject the
    // input on its pinned typed authority alone, before reserve is ever
    // attempted.
    let asset: Asset = asset(83, 83, 1_000);
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);
    let policy_digest = paid_fee_policy_digest(&resolver(), &policy).unwrap();

    // A real WASM reserve: the coin is debited and one real reservation of
    // the exact pinned reservation type is created, owned by the sender.
    let reserved_units: u64 = 250;
    let reserve: LocalExecutionOutcome = call(
        &scopes,
        "reserve",
        public_standard_asset::reserve_arguments(
            reserved_units,
            &policy_digest,
            &policy_digest,
            &treasury(),
            &refund_account(),
        )
        .unwrap(),
        std::slice::from_ref(&asset.coin),
        vec![public_standard_asset::asset_type_argument(&asset.id)],
    );
    assert_eq!(reserve.effects.status, ExecutionStatus::Success);
    let reservation: ScopedResolvedObject = created(&reserve, 0, AccessMode::Consume);
    assert_eq!(reservation.authority.ty, policy.reservation_type);
    let original: Vec<u8> = objects::encode_object(&reservation.resolved.object).unwrap();

    // The *updated* coin -- a separate object from the reservation -- funds
    // this invocation's own fee.
    let mut coin_source: ScopedResolvedObject = mutated(&reserve, &asset.coin);
    coin_source.resolved.mode = AccessMode::Write;
    assert_ne!(
        coin_source.resolved.object.id,
        reservation.resolved.object.id
    );

    let application = CallIntent {
        context: context(),
        request_id: [83; 32],
        sender: sender(),
        nonce: 83,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "settle".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: object_ref_of(&reservation.resolved.object),
                mode: AccessMode::Consume,
            }],
        },
        // Exactly the commitments stored in the reservation body, so the
        // guest's own equality checks would pass: only the host's typed
        // guard stands between this request and a settled leftover.
        arguments: public_standard_asset::settle_arguments(
            reserved_units - 50,
            &policy_digest,
            &policy_digest,
        )
        .unwrap(),
        gas_limit: 100_000,
    };
    let authenticated = authenticate(PaidIntent {
        context: context(),
        request_id: [83; 32],
        sender: sender(),
        nonce: 83,
        fee_policy_digest: policy_digest,
        consent: FeeSourceConsent {
            source: object_ref_of(&coin_source.resolved.object),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    });

    let error = paid_engine()
        .execute_paid(PaidExecutionRequest {
            authenticated: &authenticated,
            resolver: &resolver(),
            base_policy: &base_policy,
            fee_policy: &policy,
            scopes: &scopes,
            source: coin_source,
            application: PaidApplicationScopes::Call {
                scope: 0,
                inputs: std::slice::from_ref(&reservation),
            },
        })
        .expect_err("a preexisting reservation input must be rejected before reserve");
    // The precise pre-reserve rejection, not some unrelated precondition:
    // an `Err` at all already means nothing executed and no nonce was spent.
    assert!(
        format!("{error}").contains("reservation input not permitted"),
        "{error}"
    );
    // The reservation the caller offered is untouched: its canonical bytes
    // are exactly what the earlier unpaid call committed.
    assert_eq!(
        objects::encode_object(&reservation.resolved.object).unwrap(),
        original
    );
}

#[test]
fn the_zero_charge_host_rejected_fallback_receipt_is_bounded_and_verifiable() {
    // The engine pre-validates this exact skeleton before any phase runs, so
    // a deterministic host failure discovered after the VM finished always
    // has a committable receipt inside the complete 16 MiB result bound.
    // Its only variable field is the measured gas, which is a fixed-width
    // `u64`, so its encoded length does not depend on the measurement.
    let asset: Asset = asset(52, 52, 1_000);
    let attempt = transfer_attempt(
        &asset,
        std::slice::from_ref(&asset.scope),
        AccessMode::Write,
        [32; 32],
        32,
    );
    let real: PaidExecutionOutcome = attempt.outcome.expect("transfer");
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());

    let fallback = |gas_used: u64| PaidExecutionOutcome {
        result: PaidExecutionResult {
            request_id: real.result.request_id,
            kind: real.result.kind,
            target: real.result.target.clone(),
            status: PaidExecutionStatus::HostRejected,
            effects: execution::ExecutionEffects {
                tx_hash: real.result.effects.tx_hash,
                status: ExecutionStatus::Failure {
                    reason: "local contract trapped".into(),
                },
                object_effects: vec![],
                events: vec![],
                gas_used,
            },
            charged: None,
        },
        created_authorities: vec![],
    };

    let measured: u64 = real.result.effects.gas_used;
    let empty: Vec<u8> = encode_paid_execution_result(&fallback(0).result).unwrap();
    let filled: Vec<u8> = encode_paid_execution_result(&fallback(measured).result).unwrap();
    assert_eq!(empty.len(), filled.len());
    assert!(filled.len() < MAX_PAID_EXECUTION_RESULT_BYTES);
    verify_paid_execution_result(
        &fallback(measured),
        &attempt.authenticated,
        &resolver(),
        &base_policy,
        &attempt.policy,
        &asset.scope.instance,
        &[],
    )
    .expect("the zero-charge fallback verifies independently");
}

#[test]
fn paid_execution_result_codec_regressions() {
    // Codec validity alone is never sufficient: see
    // `independent_result_verification_rejects_adversarial_receipts` for the
    // checks a party that did not run the invocation must still perform.
    // Exercises `decode_paid_execution_result` fail-closed behavior against
    // Exercises `decode_paid_execution_result` fail-closed behavior against
    // a genuine charged wire result, not a hand-built approximation.
    let asset: Asset = asset(34, 34, 1_000);
    let outcome: PaidExecutionOutcome = run_transfer_call(&asset, [12; 32], 5);
    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);
    let original: Vec<u8> = encode_paid_execution_result(&outcome.result).unwrap();
    assert!(decode_paid_execution_result(&original).is_ok());

    // Unknown trailing field.
    let mut unknown_field: Vec<u8> = original.clone();
    let count: u16 = u16::from_le_bytes([original[8], original[9]]);
    unknown_field[8..10].copy_from_slice(&count.checked_add(1).unwrap().to_le_bytes());
    unknown_field.extend_from_slice(&u16::MAX.to_le_bytes());
    unknown_field.extend_from_slice(&0u32.to_le_bytes());
    assert!(decode_paid_execution_result(&unknown_field).is_err());

    // Missing field 12 (application_gas_units): it is the last canonical
    // field for a charged result, so removing it is exactly its trailing
    // 6-byte header plus 8-byte `u64` payload, with the field count
    // decremented to match.
    let mut missing_twelve: Vec<u8> = original.clone();
    let new_count: u16 = count.checked_sub(1).unwrap();
    missing_twelve[8..10].copy_from_slice(&new_count.to_le_bytes());
    missing_twelve.truncate(missing_twelve.len() - (6 + 8));
    assert!(decode_paid_execution_result(&missing_twelve).is_err());

    // Zero/unknown status code in field 4.
    let mut zero_status: Vec<u8> = original.clone();
    let range = field_range(&original, 4);
    zero_status[range].copy_from_slice(&0u16.to_le_bytes());
    assert!(decode_paid_execution_result(&zero_status).is_err());

    // Non-canonical (unnormalized) failure reason string: forge a
    // `SettlementFailed` zero-charge result and corrupt its trap reason.
    let zero_charge = PaidExecutionResult {
        request_id: [1; 32],
        kind: outcome.result.kind,
        target: outcome.result.target.clone(),
        status: PaidExecutionStatus::SettlementFailed,
        effects: execution::ExecutionEffects {
            tx_hash: outcome.result.effects.tx_hash,
            status: execution::ExecutionStatus::Failure {
                reason: "local contract trapped".into(),
            },
            object_effects: vec![],
            events: vec![],
            gas_used: 1,
        },
        charged: None,
    };
    let zero_charge_bytes = encode_paid_execution_result(&zero_charge).unwrap();
    let mut bad_reason = zero_charge.clone();
    bad_reason.effects.status = execution::ExecutionStatus::Failure {
        reason: "a different message".into(),
    };
    assert!(encode_paid_execution_result(&bad_reason).is_err());
    assert!(decode_paid_execution_result(&zero_charge_bytes).is_ok());
}
fn key() -> SigningKey {
    SigningKey::from([7; 32])
}

/// Lowercase hexadecimal, for the stable wire vector below.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The stable encoded bytes of frame `0x6415/v1` for the fixed receipt built
/// in `paid_execution_result_stable_vector`.
const PAID_EXECUTION_RESULT_VECTOR_0X6415_V1: &str = "534e5245156401000c00010020000000040404040404040404040404040404040404040404040404040404040404040402000200000002000300de010000534e5245046401000600010042000000534e524501630100030001001a000000706169642d657865637574696f6e2d656e67696e652d74657374020004000000030000000300080000000000000000000000020020000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0300200000000303030303030303030303030303030303030303030303030303030303030303040022010000534e524502630100040001007e000000534e524501520100040001001a000000706169642d657865637574696f6e2d656e67696e652d746573740200020000000100030020000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c04002000000001010101010101010101010101010101010101010101010101010101010101010200080000000100000000000000030042000000534e524501630100030001001a000000706169642d657865637574696f6e2d656e67696e652d74657374020004000000030000000300080000000000000000000000040038000000534e52450301010002000100020000000100020020000000dd06cd618c7574f07fa1598daf5a7db4ee41fed5d0473a45720101dc6a0c2c460500080000000100000000000000060004000000696e69740400020000000100050008000000f4010000000000000600080000004001000000000000070008000000b40000000000000008008c000000534e5245044001000300010030000000534e524501400100010001002000000005050505050505050505050505050505050505050505050505050505050505050200080000000100000000000000030038000000534e524503010100020001000200000001000200200000003a509583e0670e464197248f35bea979569653753577c0221f9a4da4ac0b679709008c000000534e5245044001000300010030000000534e524501400100010001002000000006060606060606060606060606060606060606060606060606060606060606060200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000a4de00feed47951df5fece70dbbe22808ed19ab38b2797f4c30e913cf5a001740a0030000000534e524501400100010001002000000007070707070707070707070707070707070707070707070707070707070707070b0091000000534e5245046001000500010038000000534e52450301010002000100020000000100020020000000f23cd8edb53d865af9fded23828d91ae5256a9347bf7756326360e6c132f5530020001000000010400080000009210000000000000050014000000534e524505600100010001000400000000000000060014000000534e5245066001000100010004000000000000000c0008000000e803000000000000";

/// Stable encoding vector for the new `PaidExecutionResult` frame
/// `0x6415/v1`.
///
/// Every input is fixed: the chain context, the signing key behind `sender`,
/// the package origin seed, and digests derived from constant labels under
/// the genesis hash suite. Changing these bytes changes a wire type and is a
/// protocol-critical change, not a test fixup.
#[test]
fn paid_execution_result_stable_vector() {
    let digest = |label: &[u8]| {
        resolver()
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, label)
            .unwrap()
    };
    let code =
        UnverifiedDependencyRef::new(origin(1), 1, context(), digest(b"vector-code")).unwrap();
    let record = InstanceRecord {
        context: context(),
        creator: sender(),
        seed: [3; 32],
        code,
        revision: 1,
        initializer: "init".into(),
    };
    let reference = |tag: u8, version: u64| objects::ObjectRef {
        id: ObjectId::new([tag; 32]),
        version,
        digest: digest(&[tag]),
    };
    let result = PaidExecutionResult {
        request_id: [4; 32],
        kind: PaidResultKind::Call,
        target: PaidResultTarget::Instance(record),
        status: PaidExecutionStatus::Success,
        effects: execution::ExecutionEffects {
            tx_hash: digest(b"vector-event"),
            status: ExecutionStatus::Success,
            object_effects: vec![],
            events: vec![],
            gas_used: 4242,
        },
        charged: Some(PaidChargedOutcome {
            reserved: Amount::new(500),
            actual: Amount::new(320),
            refund: Amount::new(180),
            fee_output: reference(5, 1),
            refund_output: Some(reference(6, 1)),
            reservation: ObjectId::new([7; 32]),
            application_gas_units: 1_000,
        }),
    };
    let bytes: Vec<u8> = encode_paid_execution_result(&result).unwrap();
    assert_eq!(hex(&bytes), PAID_EXECUTION_RESULT_VECTOR_0X6415_V1);
    assert_eq!(decode_paid_execution_result(&bytes).unwrap(), result);
}

/// Requires one independent verification failure to carry its exact
/// canonical message, not merely to be an error.
fn assert_message(result: Result<(), PaidExecutionError>, expected: &str) {
    let error: PaidExecutionError = result.expect_err(expected);
    assert_eq!(
        format!("{error}"),
        format!("invalid paid execution wire: {expected}")
    );
}

#[test]
fn independent_result_verification_rejects_adversarial_receipts() {
    // A canonical, self-consistent receipt can still name the wrong request,
    // the wrong invocation, a charge that does not follow from the quote, an
    // output owned by the wrong recipient or a surviving reservation.
    let asset: Asset = asset(50, 50, 1_000);
    let attempt = transfer_attempt(
        &asset,
        std::slice::from_ref(&asset.scope),
        AccessMode::Write,
        [30; 32],
        30,
    );
    let outcome: PaidExecutionOutcome = attempt.outcome.expect("transfer");
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let check = |candidate: &PaidExecutionOutcome| {
        verify_paid_execution_result(
            candidate,
            &attempt.authenticated,
            &resolver(),
            &base_policy,
            &attempt.policy,
            &asset.scope.instance,
            &[],
        )
    };
    check(&outcome).expect("the genuine receipt verifies");
    let charged = outcome.result.charged.clone().expect("charged");
    assert!(charged.refund.get() > 1, "the case below moves one unit");
    let refund_ref = charged.refund_output.clone().expect("refund output");

    // Wrong request identity.
    let mut tampered: PaidExecutionOutcome = outcome.clone();
    tampered.result.request_id = [0xAA; 32];
    assert_message(check(&tampered), "paid result request id");

    // Wrong invocation/event digest.
    let mut tampered = outcome.clone();
    tampered.result.effects.tx_hash = resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::NodeEvent, b"forged-event")
        .unwrap();
    assert_message(check(&tampered), "paid result event digest");

    // A charge that still satisfies `actual + refund == reserved` but does
    // not follow from the immutable quote at the reported `A`.
    let mut tampered = outcome.clone();
    {
        let charge = tampered.result.charged.as_mut().unwrap();
        charge.actual = Amount::new(charge.actual.get() + 1);
        charge.refund = Amount::new(charge.refund.get() - 1);
    }
    assert_message(
        check(&tampered),
        "paid result actual does not match the quote",
    );

    // Metered application gas above the signed limit `L`.
    let mut tampered = outcome.clone();
    tampered.result.effects.gas_used = 100_001;
    tampered
        .result
        .charged
        .as_mut()
        .unwrap()
        .application_gas_units = 100_001;
    assert_message(
        check(&tampered),
        "paid result application gas exceeds signed limit",
    );

    // Total measured gas above `L + R + S`.
    let mut tampered = outcome.clone();
    tampered.result.effects.gas_used = 100_000 + 200_000 + 200_000 + 1;
    assert_message(check(&tampered), "paid result gas exceeds total caps");

    // A fee output that is not a surviving created object at all.
    let mut tampered = outcome.clone();
    tampered.result.charged.as_mut().unwrap().fee_output.id = ObjectId::new([0xEE; 32]);
    assert_message(check(&tampered), "paid result fee output not created");

    // Fee and refund outputs swapped: both exist and are distinct, but the
    // fee coin is then owned by the refund recipient, not the pinned fee
    // recipient.
    let mut tampered = outcome.clone();
    {
        let charge = tampered.result.charged.as_mut().unwrap();
        let fee = charge.fee_output.clone();
        charge.fee_output = refund_ref.clone();
        charge.refund_output = Some(fee);
    }
    assert_message(check(&tampered), "paid result fee output authority");

    // A reservation that survived the commit as a created object.
    let mut tampered = outcome.clone();
    tampered.result.charged.as_mut().unwrap().reservation = charged.fee_output.id;
    assert_message(check(&tampered), "paid result reservation survives");

    // Creation authority that does not describe the created effects.
    let mut tampered = outcome.clone();
    tampered.created_authorities.pop();
    assert_message(check(&tampered), "paid result creation authority mismatch");

    // A receipt for a different signed intent: same shape, different sender
    // signature and therefore a different invocation digest and request.
    let other = transfer_attempt(
        &asset,
        std::slice::from_ref(&asset.scope),
        AccessMode::Write,
        [31; 32],
        31,
    );
    let error = verify_paid_execution_result(
        &outcome,
        &other.authenticated,
        &resolver(),
        &base_policy,
        &other.policy,
        &asset.scope.instance,
        &[],
    )
    .expect_err("a receipt for another intent must not verify");
    assert_eq!(
        format!("{error}"),
        "invalid paid execution wire: paid result request id"
    );
}

/// Signs and authenticates one [`PaidIntent`] exactly as a sender would.
/// Every test below goes through this: no test ever fabricates an
/// `AuthenticatedPaidIntent` or a signature.
fn authenticate(intent: PaidIntent) -> AuthenticatedPaidIntent {
    let frame = paid_intent_signing_frame(&context(), &intent).unwrap();
    let signature: [u8; 64] = key().sign(&frame).into();
    let signed = SignedPaidIntent { intent, signature };
    let bytes = encode_signed_paid_intent(&signed).unwrap();
    authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap()
}

/// The complete canonical `ObjectRef` of one resolved object, including its
/// content digest.
fn object_ref_of(object: &Object) -> objects::ObjectRef {
    objects::ObjectRef {
        id: object.id,
        version: object.version,
        digest: resolver()
            .hash_for_purpose(
                Epoch::new(0),
                HashPurpose::Object,
                &objects::encode_object(object).unwrap(),
            )
            .unwrap(),
    }
}
fn sender() -> [u8; 32] {
    VerificationKey::from(&key()).into()
}
fn treasury() -> [u8; 32] {
    VerificationKey::from(&SigningKey::from([9; 32])).into()
}
fn refund_account() -> [u8; 32] {
    VerificationKey::from(&SigningKey::from([11; 32])).into()
}
fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("paid-execution-engine-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(0),
    )
    .unwrap()
}
fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        context().chain_id().clone(),
        context().protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn origin(seed: u8) -> abi::package_types::PackageOrigin {
    abi::package_types::PackageOrigin::unverified(
        context().chain_id().clone(),
        sender(),
        [seed; 32],
    )
    .unwrap()
}

fn publish_asset(seed: u8) -> AuthenticatedPublicationCandidate {
    let package: StandardAssetPackage = build_package(&origin(seed)).unwrap();
    let semantics = generic_object_result_semantics(&resolver(), &context()).unwrap();
    let artifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: origin(seed),
        revision: 1,
        wasm_profile: 4,
        semantics,
        wasm: package.wasm,
        unverified_abi: package.encoded_abi,
        exports: package.exports,
        unverified_dependencies: vec![],
    })
    .unwrap();
    let commitment = artifact_commitment(&resolver(), &context(), &artifact).unwrap();
    let frame =
        publication_submission_signing_frame(&resolver(), &context(), &artifact, 0, [1; 32])
            .unwrap();
    authenticate_publication_submission(
        &resolver(),
        &context(),
        &semantics,
        PublicationSubmission::new(
            [1; 32],
            PublicationRequest::new(artifact, 0, commitment, key().sign(&frame).into()),
        )
        .unwrap(),
    )
    .unwrap()
}

fn dependency_ref(candidate: &AuthenticatedPublicationCandidate) -> UnverifiedDependencyRef {
    let artifact = candidate.artifact();
    UnverifiedDependencyRef::new(artifact.origin().clone(), 1, context(), *candidate.digest())
        .unwrap()
}

fn asset_scope(seed: u8, instance_seed: u8) -> ResolvedExecutionScope {
    let candidate = publish_asset(seed);
    let code = dependency_ref(&candidate);
    let instance = InstanceRecord {
        context: context(),
        creator: sender(),
        seed: [instance_seed; 32],
        code,
        revision: 1,
        initializer: "init".into(),
    };
    ResolvedExecutionScope {
        target: instance_target(&resolver(), &instance).unwrap(),
        instance,
        interface: verify_publication_interface(candidate, vec![]).unwrap(),
    }
}

/// One ordinary authenticated zero-fee root call, exactly as the production
/// `execute` path does, used only to seed real objects (init/mint).
fn call(
    scopes: &[ResolvedExecutionScope],
    entry: &str,
    arguments: Vec<u8>,
    inputs: &[ScopedResolvedObject],
    types: Vec<abi::package_types::ScopedTypeArg>,
) -> LocalExecutionOutcome {
    let resolver: HashSuiteResolver = resolver();
    let policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let root: &ResolvedExecutionScope = &scopes[0];
    let access = abi::AccessManifest {
        entries: inputs
            .iter()
            .map(|input| abi::AccessEntry {
                mode: input.resolved.mode,
                object_ref: objects::ObjectRef {
                    id: input.resolved.object.id,
                    version: input.resolved.object.version,
                    digest: resolver
                        .hash_for_purpose(
                            Epoch::new(0),
                            HashPurpose::Object,
                            &objects::encode_object(&input.resolved.object).unwrap(),
                        )
                        .unwrap(),
                },
            })
            .collect(),
    };
    let call = CallIntent {
        context: context(),
        request_id: [5; 32],
        sender: sender(),
        nonce: 0,
        code: root.instance.code.clone(),
        instance: root.target.clone(),
        entrypoint: entry.into(),
        type_arguments: types,
        access,
        arguments,
        gas_limit: MAX_LOCAL_EXECUTION_GAS,
    };
    let intent = LocalExecutionIntent {
        mode: if entry == root.instance.initializer {
            LocalExecutionMode::Instantiate
        } else {
            LocalExecutionMode::Call
        },
        policy_digest: policy.digest(&resolver).unwrap(),
        call,
        authorizations: vec![],
    };
    let signature = key()
        .sign(&local_execution_signing_frame(&context(), &intent).unwrap())
        .into();
    let signed = SignedLocalExecutionIntent { intent, signature };
    let encoded = encode_signed_local_execution(&signed).unwrap();
    let authenticated = authenticate_local_execution(&resolver, &policy, &encoded).unwrap();
    LocalWasmExecutionEngine::new()
        .execute(LocalExecutionRequest {
            scopes,
            intent: &authenticated,
            resolver: &resolver,
            policy: &policy,
            event_digest: local_execution_event_digest(&resolver, &signed).unwrap(),
            inputs,
        })
        .unwrap()
}

fn created(
    outcome: &LocalExecutionOutcome,
    index: usize,
    mode: AccessMode,
) -> ScopedResolvedObject {
    let object: Object = outcome
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Created(object) => Some(object),
            _ => None,
        })
        .nth(index)
        .unwrap()
        .clone();
    let authority = outcome
        .created_authorities
        .iter()
        .find(|created| created.authority.object_id == object.id)
        .unwrap()
        .authority
        .clone();
    ScopedResolvedObject {
        resolved: execution::ResolvedObject { object, mode },
        authority,
    }
}

fn mutated(outcome: &LocalExecutionOutcome, prior: &ScopedResolvedObject) -> ScopedResolvedObject {
    let mut next: ScopedResolvedObject = prior.clone();
    next.resolved.object = outcome
        .effects
        .object_effects
        .iter()
        .find_map(|effect| match effect {
            ObjectEffect::Mutated { new_object, .. }
                if new_object.id == prior.resolved.object.id =>
            {
                Some(new_object.clone())
            }
            _ => None,
        })
        .unwrap();
    next
}

struct Asset {
    scope: ResolvedExecutionScope,
    id: ObjectId,
    coin: ScopedResolvedObject,
}

fn asset(seed: u8, instance_seed: u8, amount: u64) -> Asset {
    let scope: ResolvedExecutionScope = asset_scope(seed, instance_seed);
    let scopes: Vec<ResolvedExecutionScope> = vec![scope.clone()];
    let init = call(
        &scopes,
        "init",
        public_standard_asset::no_arguments().unwrap(),
        &[],
        vec![],
    );
    assert_eq!(init.effects.status, ExecutionStatus::Success);
    let definition = created(&init, 0, AccessMode::Read);
    let id: ObjectId = definition.resolved.object.id;
    let cap = created(&init, 1, AccessMode::Write);
    let mint = call(
        &scopes,
        "mint",
        public_standard_asset::mint_arguments(amount, &sender()).unwrap(),
        std::slice::from_ref(&cap),
        vec![public_standard_asset::asset_type_argument(&id)],
    );
    assert_eq!(mint.effects.status, ExecutionStatus::Success);
    let coin = created(&mint, 0, AccessMode::Write);
    Asset { scope, id, coin }
}

fn fee_policy(asset: &Asset) -> PaidFeePolicy {
    let origin: abi::package_types::PackageOrigin = asset.scope.instance.code.origin().clone();
    PaidFeePolicy {
        context: context(),
        base_policy_digest: LocalExecutionPolicy::generic_object_results(context())
            .digest(&resolver())
            .unwrap(),
        instance: asset.scope.target.clone(),
        code: asset.scope.instance.code.clone(),
        reserve_entrypoint: "reserve".into(),
        reserve_all_entrypoint: "reserve_all".into(),
        settle_entrypoint: "settle".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        asset_type: public_standard_asset::coin_type_tag(&origin, &asset.id).unwrap(),
        reservation_type: public_standard_asset::reservation_type_tag(&origin, &asset.id).unwrap(),
        schema: public_standard_asset::SCHEMA_VERSION,
        fee_recipient: treasury(),
        gas_schedule: GasSchedule {
            base_fee: 100,
            execution_price: 1,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        },
        conversion_divisor: 1_000,
        reserve_allowance: 200_000,
        settle_allowance: 200_000,
        calls: 8,
        handles: 16,
        creations: 4,
        events: 16,
        memory_bytes: 8 * 1024 * 1024,
        output_bytes: 1024 * 1024,
        publish_artifact_byte_price: 1,
        publish_closure_node_price: 1,
    }
}

/// Builds and runs one real authenticated paid `transfer` Call, exactly as
/// production admission would after its own object/policy/nonce checks.
/// Shared by the positive Call test and the result-codec regression tests
/// below, so those regressions exercise a genuine charged wire result
/// rather than a hand-assembled one.
fn run_transfer_call(asset: &Asset, request_id: [u8; 32], nonce: u64) -> PaidExecutionOutcome {
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(asset);
    let policy_digest = paid_fee_policy_digest(&resolver(), &policy).unwrap();

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let source_ref = objects::ObjectRef {
        id: coin_source.resolved.object.id,
        version: coin_source.resolved.object.version,
        digest: resolver()
            .hash_for_purpose(
                Epoch::new(0),
                HashPurpose::Object,
                &objects::encode_object(&coin_source.resolved.object).unwrap(),
            )
            .unwrap(),
    };

    let application = CallIntent {
        context: context(),
        request_id,
        sender: sender(),
        nonce,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "transfer".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: source_ref.clone(),
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        gas_limit: 100_000,
    };

    let intent = PaidIntent {
        context: context(),
        request_id,
        sender: sender(),
        nonce,
        fee_policy_digest: policy_digest,
        consent: FeeSourceConsent {
            source: source_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    };
    let frame = paid_intent_signing_frame(&context(), &intent).unwrap();
    let signature: [u8; 64] = key().sign(&frame).into();
    let signed = SignedPaidIntent { intent, signature };
    let bytes = encode_signed_paid_intent(&signed).unwrap();
    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();

    let request = PaidExecutionRequest {
        authenticated: &authenticated,
        resolver: &resolver(),
        base_policy: &base_policy,
        fee_policy: &policy,
        scopes: &scopes,
        source: coin_source.clone(),
        application: PaidApplicationScopes::Call {
            scope: 0,
            inputs: std::slice::from_ref(&coin_source),
        },
    };

    let outcome: PaidExecutionOutcome = paid_engine()
        .execute_paid(request)
        .expect("paid transfer call");
    // Every real charged receipt this file produces is also checked by the
    // independent verifier, so the positive path exercises both.
    verify_paid_execution_result(
        &outcome,
        &authenticated,
        &resolver(),
        &base_policy,
        &policy,
        &asset.scope.instance,
        &[],
    )
    .expect("independent verification");
    outcome
}

#[test]
fn paid_contract_engine_runs_a_real_transfer_call_and_settles_the_fee() {
    let asset: Asset = asset(30, 30, 1_000);
    let outcome: PaidExecutionOutcome = run_transfer_call(&asset, [7; 32], 1);
    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);
    let charged = outcome.result.charged.as_ref().unwrap();
    assert!(charged.actual.get() > 0);
    assert_eq!(
        charged.actual.get() + charged.refund.get(),
        charged.reserved.get()
    );
    assert!(!outcome.created_authorities.is_empty());
    let _ = mutated(
        &LocalExecutionOutcome {
            effects: outcome.result.effects.clone(),
            created_authorities: outcome.created_authorities.clone(),
        },
        &{
            let mut coin_source = asset.coin.clone();
            coin_source.resolved.mode = AccessMode::Write;
            coin_source
        },
    );
}

#[test]
fn paid_contract_engine_runs_a_real_instantiate_and_settles_the_fee() {
    // Instantiate: the application creates a brand new instance of the same
    // published code while the fee source lives in an older instance. Two
    // distinct scopes are therefore required, and the application scope must
    // be the root scope.
    let asset: Asset = asset(40, 40, 1_000);
    let fresh: ResolvedExecutionScope = asset_scope(40, 41);
    let scopes: Vec<ResolvedExecutionScope> = vec![fresh.clone(), asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let source_ref = object_ref_of(&coin_source.resolved.object);

    let application = CallIntent {
        context: context(),
        request_id: [20; 32],
        sender: sender(),
        nonce: 20,
        code: fresh.instance.code.clone(),
        instance: fresh.target.clone(),
        entrypoint: "init".into(),
        type_arguments: vec![],
        access: abi::AccessManifest { entries: vec![] },
        arguments: public_standard_asset::no_arguments().unwrap(),
        gas_limit: 400_000,
    };
    let authenticated = authenticate(PaidIntent {
        context: context(),
        request_id: [20; 32],
        sender: sender(),
        nonce: 20,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &policy).unwrap(),
        consent: FeeSourceConsent {
            source: source_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Instantiate(application),
        gas_limit: 400_000,
        authorizations: vec![],
    });

    let outcome = paid_engine()
        .execute_paid(PaidExecutionRequest {
            authenticated: &authenticated,
            resolver: &resolver(),
            base_policy: &base_policy,
            fee_policy: &policy,
            scopes: &scopes,
            source: coin_source,
            application: PaidApplicationScopes::Instantiate { scope: 0 },
        })
        .expect("paid instantiate");
    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);
    assert_eq!(outcome.result.kind, PaidResultKind::Instantiate);
    assert!(matches!(
        outcome.result.target,
        PaidResultTarget::Instance(_)
    ));
    let charged = outcome.result.charged.as_ref().unwrap();
    assert!(charged.actual.get() > 0);
    // `init` creates the Definition and the TreasuryCap; settlement adds the
    // fee coin and, here, the refund coin.
    assert!(outcome.created_authorities.len() >= 4);
    verify_paid_execution_result(
        &outcome,
        &authenticated,
        &resolver(),
        &base_policy,
        &policy,
        &asset.scope.instance,
        &[],
    )
    .expect("independent verification");
}

/// The exact deterministic Publish application units DR-0124 pins:
/// `artifact_encoded_bytes * byte_price + closure_nodes * node_price`, with
/// the candidate counting as one node in addition to `dependency_count`
/// already-published dependency candidates.
fn publish_units(artifact: &CodeArtifact, policy: &PaidFeePolicy, dependency_count: usize) -> u64 {
    encode_code_artifact(artifact).unwrap().len() as u64 * policy.publish_artifact_byte_price
        + (1 + dependency_count as u64) * policy.publish_closure_node_price
}

/// Publishes the public Standard Asset package under a fresh origin,
/// declaring the exact given already-published dependency candidates as its
/// unverified dependency edges.
fn publish_asset_with_dependencies(
    seed: u8,
    dependencies: &[AuthenticatedPublicationCandidate],
) -> AuthenticatedPublicationCandidate {
    let package: StandardAssetPackage = build_package(&origin(seed)).unwrap();
    let semantics = generic_object_result_semantics(&resolver(), &context()).unwrap();
    let artifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: origin(seed),
        revision: 1,
        wasm_profile: 4,
        semantics,
        wasm: package.wasm,
        unverified_abi: package.encoded_abi,
        exports: package.exports,
        unverified_dependencies: dependencies.iter().map(dependency_ref).collect(),
    })
    .unwrap();
    let commitment = artifact_commitment(&resolver(), &context(), &artifact).unwrap();
    let frame =
        publication_submission_signing_frame(&resolver(), &context(), &artifact, 0, [1; 32])
            .unwrap();
    authenticate_publication_submission(
        &resolver(),
        &context(),
        &semantics,
        PublicationSubmission::new(
            [1; 32],
            PublicationRequest::new(artifact, 0, commitment, key().sign(&frame).into()),
        )
        .unwrap(),
    )
    .unwrap()
}

/// Builds and runs one real authenticated paid Publish under the supplied
/// signed application limit `L`.
fn run_publish(
    asset: &Asset,
    artifact_seed: u8,
    dependencies: Vec<AuthenticatedPublicationCandidate>,
    request_id: [u8; 32],
    nonce: u64,
    gas_limit: u64,
) -> (
    PaidExecutionOutcome,
    AuthenticatedPaidIntent,
    PaidFeePolicy,
    u64,
) {
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(asset);
    let artifact: CodeArtifact = publish_asset_with_dependencies(artifact_seed, &dependencies)
        .artifact()
        .clone();
    let units: u64 = publish_units(&artifact, &policy, dependencies.len());

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let authenticated = authenticate(PaidIntent {
        context: context(),
        request_id,
        sender: sender(),
        nonce,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &policy).unwrap(),
        consent: FeeSourceConsent {
            source: object_ref_of(&coin_source.resolved.object),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Publish(artifact),
        gas_limit,
        authorizations: vec![],
    });
    let outcome = paid_engine()
        .execute_paid(PaidExecutionRequest {
            authenticated: &authenticated,
            resolver: &resolver(),
            base_policy: &base_policy,
            fee_policy: &policy,
            scopes: &scopes,
            source: coin_source,
            application: PaidApplicationScopes::Publish {
                dependencies: dependencies.clone(),
            },
        })
        .expect("paid publish");
    verify_paid_execution_result(
        &outcome,
        &authenticated,
        &resolver(),
        &base_policy,
        &policy,
        &asset.scope.instance,
        &dependencies,
    )
    .expect("independent verification");
    (outcome, authenticated, policy, units)
}

#[test]
fn paid_contract_engine_charges_a_real_publish_deterministically() {
    let asset: Asset = asset(42, 42, 1_000);
    // Sized above the artifact's own deterministic units so the publication
    // is admitted rather than exhausted.
    let artifact: CodeArtifact = publish_asset(43).artifact().clone();
    let units: u64 = publish_units(&artifact, &fee_policy(&asset), 0);
    let gas_limit: u64 = units + 10_000;
    let (outcome, _, _, measured) = run_publish(&asset, 43, vec![], [21; 32], 21, gas_limit);

    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);
    assert_eq!(outcome.result.kind, PaidResultKind::Publish);
    assert!(matches!(
        outcome.result.target,
        PaidResultTarget::Package(_)
    ));
    let charged = outcome.result.charged.as_ref().unwrap();
    // Publish never enters an application WASM frame: `A` is exactly its
    // deterministic metered unit count.
    assert_eq!(charged.application_gas_units, measured);
    assert!(charged.actual.get() > 0);
    assert_eq!(
        charged.actual.get() + charged.refund.get(),
        charged.reserved.get()
    );
}

#[test]
fn paid_publish_exhaustion_charges_the_whole_application_limit() {
    let asset: Asset = asset(44, 44, 1_000);
    let artifact: CodeArtifact = publish_asset(45).artifact().clone();
    let units: u64 = publish_units(&artifact, &fee_policy(&asset), 0);
    // Deliberately below the artifact's deterministic units.
    let gas_limit: u64 = 1_000;
    assert!(units > gas_limit, "the artifact must exceed the limit");
    let (outcome, _, _, _) = run_publish(&asset, 45, vec![], [22; 32], 22, gas_limit);

    assert_eq!(
        outcome.result.status,
        PaidExecutionStatus::ApplicationFailed
    );
    let charged = outcome.result.charged.as_ref().unwrap();
    // Exhaustion charges exactly the admitted limit `L`, never more, and
    // settlement still commits the fee.
    assert_eq!(charged.application_gas_units, gas_limit);
    assert!(charged.actual.get() > 0);
    assert!(outcome.result.effects.object_effects.iter().all(|effect| {
        !matches!(effect, ObjectEffect::Created(object) if object.data.len() > 4096)
    }));
}

#[test]
fn independent_publish_verification_rejects_a_forged_lower_application_gas() {
    // The receipt's own reported `A` is never sufficient evidence: it must
    // equal the units independently recomputed from the authenticated
    // artifact and closure, not merely satisfy `A <= L`. Here the charge and
    // refund are honestly recomputed from a forged, smaller `A`, so only the
    // new recomputed-units check -- not the ordinary quote check -- can
    // catch the forgery.
    let asset: Asset = asset(66, 66, 1_000);
    let artifact: CodeArtifact = publish_asset(67).artifact().clone();
    let units: u64 = publish_units(&artifact, &fee_policy(&asset), 0);
    let gas_limit: u64 = units + 10_000;
    let (outcome, authenticated, policy, measured) =
        run_publish(&asset, 67, vec![], [71; 32], 71, gas_limit);
    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);
    assert_eq!(measured, units);
    assert!(
        units > 1,
        "there must be room for a strictly lower forged A"
    );

    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let admission = quote_paid_intent(&authenticated, &resolver(), &base_policy, &policy).unwrap();
    let forged_units: u64 = units - 1;
    let settlement = admission.settle(forged_units).unwrap();

    let mut tampered: PaidExecutionOutcome = outcome.clone();
    {
        let charged = tampered.result.charged.as_mut().unwrap();
        charged.application_gas_units = forged_units;
        charged.actual = settlement.actual;
        charged.refund = settlement.refund;
    }
    let error = verify_paid_execution_result(
        &tampered,
        &authenticated,
        &resolver(),
        &base_policy,
        &policy,
        &asset.scope.instance,
        &[],
    )
    .expect_err("a forged lower A, even with honestly recomputed charge/refund, must be rejected");
    assert!(format!("{error}").contains("recomputed units"), "{error}");
}

#[test]
fn independent_publish_verification_rejects_a_forged_status() {
    // A genuine `Success` receipt (units <= L) whose status is forced to
    // `ApplicationFailed` while `A` is left at the genuine, admitted unit
    // count: the recomputed units still say `Success` is the only
    // admissible status at that `A`, so the mismatch must be rejected.
    let asset: Asset = asset(68, 68, 1_000);
    let artifact: CodeArtifact = publish_asset(69).artifact().clone();
    let units: u64 = publish_units(&artifact, &fee_policy(&asset), 0);
    let gas_limit: u64 = units + 10_000;
    let (outcome, authenticated, policy, _) =
        run_publish(&asset, 69, vec![], [72; 32], 72, gas_limit);
    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);

    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let mut tampered: PaidExecutionOutcome = outcome.clone();
    tampered.result.status = PaidExecutionStatus::ApplicationFailed;
    tampered.result.effects.status = ExecutionStatus::Failure {
        reason: LOCAL_EXECUTION_TRAP_REASON.into(),
    };
    let error = verify_paid_execution_result(
        &tampered,
        &authenticated,
        &resolver(),
        &base_policy,
        &policy,
        &asset.scope.instance,
        &[],
    )
    .expect_err("a forged status inconsistent with the recomputed units must be rejected");
    assert!(format!("{error}").contains("recomputed units"), "{error}");
}

#[test]
fn paid_publish_recomputes_units_across_a_multi_node_dependency_closure() {
    // A two-node closure: the published artifact under test declares one
    // real dependency edge. The engine and the independent verifier must
    // both recompute the identical `1 + 1` node count from the actual
    // authenticated closure, never from a caller-supplied count, and
    // omitting the dependency from the verifier's bounded input must fail
    // closed rather than silently accept an incomplete closure.
    let asset: Asset = asset(70, 70, 1_000);
    let leaf: AuthenticatedPublicationCandidate = publish_asset(71);
    let artifact: CodeArtifact = publish_asset_with_dependencies(72, std::slice::from_ref(&leaf))
        .artifact()
        .clone();
    let expected_units: u64 = publish_units(&artifact, &fee_policy(&asset), 1);
    let gas_limit: u64 = expected_units + 10_000;
    let (outcome, authenticated, policy, measured) =
        run_publish(&asset, 72, vec![leaf.clone()], [73; 32], 73, gas_limit);
    assert_eq!(measured, expected_units);
    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);
    let charged = outcome.result.charged.as_ref().unwrap();
    assert_eq!(charged.application_gas_units, expected_units);

    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    assert!(
        verify_paid_execution_result(
            &outcome,
            &authenticated,
            &resolver(),
            &base_policy,
            &policy,
            &asset.scope.instance,
            &[],
        )
        .is_err(),
        "an incomplete dependency closure must fail closed, not verify"
    );
}

#[test]
fn independent_publish_verification_rejects_a_tampered_dependency_closure() {
    // Same genuine two-node closure as the omission case above, but here the
    // verifier's bounded input is structurally wrong in three distinct ways
    // instead of merely incomplete: an unrelated extra candidate appended
    // alongside the real one, the real dependency duplicated, and the real
    // dependency entirely replaced by an unrelated candidate. Each must fail
    // closed exactly like the omission case, never silently accept a closure
    // that does not match the artifact's own signed dependency edges.
    let asset: Asset = asset(74, 74, 1_000);
    let leaf: AuthenticatedPublicationCandidate = publish_asset(75);
    let unrelated: AuthenticatedPublicationCandidate = publish_asset(76);
    let artifact: CodeArtifact = publish_asset_with_dependencies(77, std::slice::from_ref(&leaf))
        .artifact()
        .clone();
    let expected_units: u64 = publish_units(&artifact, &fee_policy(&asset), 1);
    let gas_limit: u64 = expected_units + 10_000;
    let (outcome, authenticated, policy, measured) =
        run_publish(&asset, 77, vec![leaf.clone()], [78; 32], 78, gas_limit);
    assert_eq!(measured, expected_units);
    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);

    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    for (label, tampered_dependencies) in [
        ("extra", vec![leaf.clone(), unrelated.clone()]),
        ("duplicate", vec![leaf.clone(), leaf.clone()]),
        ("replaced", vec![unrelated.clone()]),
    ] {
        assert!(
            verify_paid_execution_result(
                &outcome,
                &authenticated,
                &resolver(),
                &base_policy,
                &policy,
                &asset.scope.instance,
                &tampered_dependencies,
            )
            .is_err(),
            "a {label} dependency closure must fail closed, not verify"
        );
    }
}

#[test]
fn independent_publish_verification_rejects_a_forged_higher_application_gas_within_limit() {
    // The forged-lower-A case above shows a shrunk charge is rejected; this
    // covers the opposite, fee-inflation direction: a forged `A` strictly
    // greater than the genuine recomputed units, but still admitted (`<=
    // L`), so `Success` remains the expected status and only the
    // recomputed-units equality check -- not the status/limit check -- can
    // catch it.
    let asset: Asset = asset(79, 79, 1_000);
    let leaf: AuthenticatedPublicationCandidate = publish_asset(80);
    let artifact: CodeArtifact = publish_asset_with_dependencies(81, std::slice::from_ref(&leaf))
        .artifact()
        .clone();
    let expected_units: u64 = publish_units(&artifact, &fee_policy(&asset), 1);
    let gas_limit: u64 = expected_units + 10_000;
    let (outcome, authenticated, policy, measured) =
        run_publish(&asset, 81, vec![leaf.clone()], [82; 32], 82, gas_limit);
    assert_eq!(measured, expected_units);
    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);

    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let admission = quote_paid_intent(&authenticated, &resolver(), &base_policy, &policy).unwrap();
    let forged_units: u64 = expected_units + 1;
    assert!(forged_units <= gas_limit, "forged A must remain admitted");
    let settlement = admission.settle(forged_units).unwrap();

    let mut tampered: PaidExecutionOutcome = outcome.clone();
    {
        let charged = tampered.result.charged.as_mut().unwrap();
        charged.application_gas_units = forged_units;
        charged.actual = settlement.actual;
        charged.refund = settlement.refund;
    }
    let error = verify_paid_execution_result(
        &tampered,
        &authenticated,
        &resolver(),
        &base_policy,
        &policy,
        &asset.scope.instance,
        &[leaf],
    )
    .expect_err("a forged higher A, even still within L, must be rejected");
    assert!(format!("{error}").contains("recomputed units"), "{error}");
}

#[test]
fn paid_publish_rejects_an_overlimit_dependency_closure_before_authenticating_it() {
    // The offered closure is one candidate repeated to the node ceiling, so
    // it is both overlimit (`1 + MAX_INTERFACE_NODES` nodes) and, further
    // in, structurally impossible (every node shares one origin). The cheap
    // exact count guard runs *before* the candidate is authenticated and
    // before the dependency slice is cloned into closure verification, so
    // the reported failure must be the node-limit one, never the duplicate
    // origin that closure verification would have found afterwards.
    let asset: Asset = asset(85, 85, 1_000);
    let leaf: AuthenticatedPublicationCandidate = publish_asset(86);
    let dependencies: Vec<AuthenticatedPublicationCandidate> = vec![leaf; MAX_INTERFACE_NODES];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);
    let artifact: CodeArtifact = publish_asset(87).artifact().clone();

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let authenticated = authenticate(PaidIntent {
        context: context(),
        request_id: [85; 32],
        sender: sender(),
        nonce: 85,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &policy).unwrap(),
        consent: FeeSourceConsent {
            source: object_ref_of(&coin_source.resolved.object),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Publish(artifact),
        gas_limit: 100_000,
        authorizations: vec![],
    });
    let error = paid_engine()
        .execute_paid(PaidExecutionRequest {
            authenticated: &authenticated,
            resolver: &resolver(),
            base_policy: &base_policy,
            fee_policy: &policy,
            scopes: std::slice::from_ref(&asset.scope),
            source: coin_source,
            application: PaidApplicationScopes::Publish { dependencies },
        })
        .expect_err("an overlimit dependency closure must be rejected before reserve");
    let message: String = format!("{error}");
    assert!(message.contains("publish closure size"), "{message}");
    assert!(
        !message.to_lowercase().contains("duplicate"),
        "the node limit must be reported, not the duplicate origin: {message}"
    );
}

#[test]
fn independent_publish_verification_rejects_a_forged_exhaustion_success() {
    // The opposite direction of the forged-status case above: a genuine
    // exhausted receipt (`units > L`, `ApplicationFailed`, `A == L`) forced
    // to `Success` on the wire, with the effects status moved with it so the
    // receipt stays internally consistent and re-encodes. `A` is left at the
    // honest, admitted `L`, so nothing in the quote or limit checks is
    // violated: only recomputing the units can reveal that `Success` was
    // never an admissible status at this limit.
    let asset: Asset = asset(88, 88, 1_000);
    let artifact: CodeArtifact = publish_asset(89).artifact().clone();
    let units: u64 = publish_units(&artifact, &fee_policy(&asset), 0);
    let gas_limit: u64 = 1_000;
    assert!(units > gas_limit, "the artifact must exceed the limit");
    let (outcome, authenticated, policy, _) =
        run_publish(&asset, 89, vec![], [88; 32], 88, gas_limit);
    assert_eq!(
        outcome.result.status,
        PaidExecutionStatus::ApplicationFailed
    );
    assert_eq!(
        outcome
            .result
            .charged
            .as_ref()
            .unwrap()
            .application_gas_units,
        gas_limit
    );

    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let mut tampered: PaidExecutionOutcome = outcome.clone();
    tampered.result.status = PaidExecutionStatus::Success;
    tampered.result.effects.status = ExecutionStatus::Success;
    let error = verify_paid_execution_result(
        &tampered,
        &authenticated,
        &resolver(),
        &base_policy,
        &policy,
        &asset.scope.instance,
        &[],
    )
    .expect_err("a forged exhaustion success must be rejected");
    assert!(format!("{error}").contains("recomputed units"), "{error}");
}

/// Builds and runs one real authenticated paid `transfer` Call while varying
/// exactly the pieces the adversarial cases below need: the supplied scope
/// set, the signed application access mode on the source, and the signed
/// application `ObjectRef`.
struct TransferAttempt {
    outcome: Result<PaidExecutionOutcome, PaidExecutionError>,
    authenticated: AuthenticatedPaidIntent,
    policy: PaidFeePolicy,
}

fn transfer_attempt(
    asset: &Asset,
    scopes: &[ResolvedExecutionScope],
    application_mode: AccessMode,
    request_id: [u8; 32],
    nonce: u64,
) -> TransferAttempt {
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(asset);
    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let source_ref = object_ref_of(&coin_source.resolved.object);
    let mut application_input = coin_source.clone();
    application_input.resolved.mode = application_mode;

    let application = CallIntent {
        context: context(),
        request_id,
        sender: sender(),
        nonce,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "transfer".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: source_ref.clone(),
                mode: application_mode,
            }],
        },
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        gas_limit: 100_000,
    };
    let authenticated = authenticate(PaidIntent {
        context: context(),
        request_id,
        sender: sender(),
        nonce,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &policy).unwrap(),
        consent: FeeSourceConsent {
            source: source_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    });
    let outcome = paid_engine().execute_paid(PaidExecutionRequest {
        authenticated: &authenticated,
        resolver: &resolver(),
        base_policy: &base_policy,
        fee_policy: &policy,
        scopes,
        source: coin_source,
        application: PaidApplicationScopes::Call {
            scope: 0,
            inputs: std::slice::from_ref(&application_input),
        },
    });
    TransferAttempt {
        outcome,
        authenticated,
        policy,
    }
}

#[test]
fn paid_contract_engine_validates_the_entire_supplied_scope_set() {
    // Comparing a recomputed target at one selector is not complete
    // validation: the whole supplied set must equal the required union of
    // the fee instance plus the application and authorization instances.
    let asset: Asset = asset(46, 46, 1_000);
    let unrelated: ResolvedExecutionScope = asset_scope(46, 47);

    // Baseline: exactly the required set succeeds.
    let ok = transfer_attempt(
        &asset,
        std::slice::from_ref(&asset.scope),
        AccessMode::Write,
        [23; 32],
        23,
    )
    .outcome
    .expect("baseline transfer");
    assert_eq!(ok.result.status, PaidExecutionStatus::Success);

    // An extra scope that no signed field requires is rejected, not ignored.
    let extra: Vec<ResolvedExecutionScope> = vec![asset.scope.clone(), unrelated];
    let error = transfer_attempt(&asset, &extra, AccessMode::Write, [24; 32], 24)
        .outcome
        .expect_err("an unneeded scope must be rejected");
    assert!(
        format!("{error}").contains("execution scope instance authority"),
        "{error}"
    );

    // A duplicate of the required scope is rejected.
    let duplicate: Vec<ResolvedExecutionScope> = vec![asset.scope.clone(), asset.scope.clone()];
    let error = transfer_attempt(&asset, &duplicate, AccessMode::Write, [25; 32], 25)
        .outcome
        .expect_err("a duplicate scope must be rejected");
    assert!(
        format!("{error}").contains("execution scope instance authority"),
        "{error}"
    );

    // A scope whose caller-supplied `target` disagrees with the independently
    // derived target of its own record is rejected, even though the selector
    // would still find it.
    let mut forged: ResolvedExecutionScope = asset.scope.clone();
    forged.target.revision += 1;
    let error = transfer_attempt(
        &asset,
        std::slice::from_ref(&forged),
        AccessMode::Write,
        [26; 32],
        26,
    )
    .outcome
    .expect_err("a forged scope target must be rejected");
    assert!(
        format!("{error}").contains("execution scope instance authority"),
        "{error}"
    );
}

#[test]
fn a_write_reservation_never_strengthens_a_signed_read_application_access() {
    // The consent reserves the source with Write, but the application signed
    // Read on that same object. The application keeps exactly its signed
    // Read: it can never satisfy `transfer`'s declared Coin Write parameter
    // by borrowing the reservation's stronger access.
    let asset: Asset = asset(48, 48, 1_000);
    let error = transfer_attempt(
        &asset,
        std::slice::from_ref(&asset.scope),
        AccessMode::Read,
        [27; 32],
        27,
    )
    .outcome
    .expect_err("a signed Read must not be strengthened to Write");
    assert!(
        format!("{error}").contains("access manifest mode"),
        "{error}"
    );
}

#[test]
fn paid_contract_engine_rejects_a_malformed_application_input_reference() {
    // The supplied resolved application input must match its signed
    // `AccessEntry` by the complete canonical `ObjectRef`, including the
    // content digest, not merely by id and version.
    let asset: Asset = asset(49, 49, 1_000);
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let cap = {
        let init = call(
            &scopes,
            "init",
            public_standard_asset::no_arguments().unwrap(),
            &[],
            vec![],
        );
        created(&init, 1, AccessMode::Write)
    };
    // Same id and version as the object actually supplied below, forged digest.
    let forged_entry = objects::ObjectRef {
        id: cap.resolved.object.id,
        version: cap.resolved.object.version,
        digest: resolver()
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, b"forged-cap-body")
            .unwrap(),
    };

    let application = CallIntent {
        context: context(),
        request_id: [28; 32],
        sender: sender(),
        nonce: 28,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "mint".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: forged_entry,
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::mint_arguments(5, &refund_account()).unwrap(),
        gas_limit: 100_000,
    };
    let authenticated = authenticate(PaidIntent {
        context: context(),
        request_id: [28; 32],
        sender: sender(),
        nonce: 28,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &policy).unwrap(),
        consent: FeeSourceConsent {
            source: object_ref_of(&coin_source.resolved.object),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    });
    let error = paid_engine()
        .execute_paid(PaidExecutionRequest {
            authenticated: &authenticated,
            resolver: &resolver(),
            base_policy: &base_policy,
            fee_policy: &policy,
            scopes: &scopes,
            source: coin_source,
            application: PaidApplicationScopes::Call {
                scope: 0,
                inputs: std::slice::from_ref(&cap),
            },
        })
        .expect_err("a forged application input digest must be rejected");
    assert!(
        format!("{error}").contains("application input authority"),
        "{error}"
    );
}

#[test]
fn paid_contract_engine_rejects_a_fee_source_reference_mismatch() {
    let asset: Asset = asset(31, 31, 1_000);
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);
    let policy_digest = paid_fee_policy_digest(&resolver(), &policy).unwrap();

    let mut wrong_source_ref = objects::ObjectRef {
        id: asset.coin.resolved.object.id,
        version: asset.coin.resolved.object.version,
        digest: resolver()
            .hash_for_purpose(
                Epoch::new(0),
                HashPurpose::Object,
                &objects::encode_object(&asset.coin.resolved.object).unwrap(),
            )
            .unwrap(),
    };
    // A version that does not match the actually supplied resolved source.
    wrong_source_ref.version += 1;

    let application = CallIntent {
        context: context(),
        request_id: [8; 32],
        sender: sender(),
        nonce: 2,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "transfer".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest { entries: vec![] },
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        gas_limit: 100_000,
    };
    let mut intent = PaidIntent {
        context: context(),
        request_id: [8; 32],
        sender: sender(),
        nonce: 2,
        fee_policy_digest: policy_digest,
        consent: FeeSourceConsent {
            source: wrong_source_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    };
    intent.fee_policy_digest = policy_digest;
    let frame = paid_intent_signing_frame(&context(), &intent).unwrap();
    let signature: [u8; 64] = key().sign(&frame).into();
    let signed = SignedPaidIntent { intent, signature };
    let bytes = encode_signed_paid_intent(&signed).unwrap();
    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let request = PaidExecutionRequest {
        authenticated: &authenticated,
        resolver: &resolver(),
        base_policy: &base_policy,
        fee_policy: &policy,
        scopes: &scopes,
        source: coin_source,
        application: PaidApplicationScopes::Call {
            scope: 0,
            inputs: &[],
        },
    };
    assert!(paid_engine().execute_paid(request).is_err());
}
