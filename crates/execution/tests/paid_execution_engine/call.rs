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
