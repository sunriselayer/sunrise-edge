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
