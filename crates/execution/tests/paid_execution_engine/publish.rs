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
