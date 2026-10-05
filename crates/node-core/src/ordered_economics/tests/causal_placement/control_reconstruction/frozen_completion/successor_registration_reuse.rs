//! Current-context Admit refusals for independently signed historical owners.
//! The exact same builder is checked against G's genuine positive preparation.
use super::*;
use crate::bond_lifecycle::registration::{
    BondRegistrationError, BondRegistrationIntent, BondRegistrationPreparationRequest,
    SignedBondRegistrationIntent, bond_registration_anchor_key, bond_registration_intent_digest,
    bond_registration_signing_frame, encode_signed_bond_registration_intent,
    prepare_bond_registration_successor, verify_signed_bond_registration_successor,
};
use crate::business_reconstruction::SourceBusinessSnapshot;
use crate::serving_authority::VerifiedSuccessorAuthority;
use protocol_types::Epoch;

pub(super) struct RegistrationAttempt {
    pub(super) request: BondRegistrationPreparationRequest,
    pub(super) intent: BondRegistrationIntent,
    pub(super) signing_frame: Vec<u8>,
    pub(super) candidate: OrderedCandidate,
}

/// Builds an untrusted, fully signed current-context claim. This does not
/// call preparation: Admit must be able to refuse an already verified owner.
#[allow(clippy::too_many_arguments)]
pub(super) fn registration_attempt(
    root: &crate::genesis::VerifiedGenesisRoot,
    authority: &VerifiedSuccessorAuthority,
    resolver: &HashSuiteResolver,
    base: &LocalExecutionPolicy,
    signer: &TestSigner,
    source: Object,
    reference: ObjectRef,
    object_authority: execution::local_execution::ObjectAuthority,
    request_id: [u8; 32],
    nonce: u64,
    checkpoint: u64,
) -> RegistrationAttempt {
    let live: PublicationContext = authority.policy_inputs().context().clone();
    assert_eq!(
        base,
        &LocalExecutionPolicy::generic_object_results(live.clone())
    );
    let resource: &crate::economics::FastPathEconomicsResourcePolicy =
        &root.manifest().economics_policy.resources[0];
    let amount: u64 = match abi::call_values::decode_call_value(
        &public_standard_asset::coin_body_layout(),
        &source.data,
    )
    .unwrap()
    {
        abi::call_values::CallValue::U64(amount) => amount,
        _ => panic!("the genuine collateral has its installed U64 layout"),
    };
    let scope: objects::ProtocolCustodyScope = objects::ProtocolCustodyScope {
        purpose: objects::ProtocolCustodyPurpose::BondCollateral,
        chain_id: live.chain_id().clone(),
        subject: *signer.id.as_bytes(),
        resource: *resource.resource_id.value(),
    };
    let token: [u8; 32] =
        execution::protocol_custody::derive_deposit_owner_token(resolver, &live, source.id, &scope)
            .unwrap();
    let leg: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: base.digest(resolver).unwrap(),
        call: CallIntent {
            context: live.clone(),
            request_id,
            sender: *signer.id.as_bytes(),
            nonce,
            code: resource.code.clone(),
            instance: resource.instance.clone(),
            entrypoint: resource.transfer_entrypoint.clone(),
            type_arguments: root.manifest().fee_policy.type_arguments.clone(),
            access: abi::AccessManifest {
                entries: vec![abi::AccessEntry {
                    object_ref: reference,
                    mode: AccessMode::Write,
                }],
            },
            arguments: public_standard_asset::transfer_arguments(&token).unwrap(),
            gas_limit: 500_000,
        },
        authorizations: Vec::new(),
    };
    let leg_frame: Vec<u8> = local_execution_signing_frame(&live, &leg).unwrap();
    let signed_leg: Vec<u8> = encode_signed_local_execution(&SignedLocalExecutionIntent {
        signature: signer.key.sign(&leg_frame).into(),
        intent: leg,
    })
    .unwrap();
    let mut predicted: Object = source;
    predicted.version = predicted.version.checked_add(1).unwrap();
    predicted.owner = Owner::ProtocolCustody(scope);
    let row: FastPathBondRecord = FastPathBondRecord {
        context: resource.context.clone(),
        validator_id: signer.id,
        resource_domain: resource.resource_id.domain(),
        resource: *resource.resource_id.value(),
        custody_object: ObjectRef {
            id: predicted.id,
            version: predicted.version,
            digest: resolver
                .hash_for_purpose(
                    live.epoch(),
                    HashPurpose::Object,
                    &objects::encode_object(&predicted).unwrap(),
                )
                .unwrap(),
        },
        custody_object_epoch: live.epoch(),
        authority: object_authority,
        amount,
        committed_at_checkpoint: checkpoint,
        generation: 1,
        lifecycle_epoch: live.epoch(),
        slashable_from_epoch: Epoch::new(live.epoch().get().checked_add(1).unwrap()),
        required_minimum: resource.bond.as_ref().unwrap().min_bond.get(),
        state: FastPathBondState::Active,
        authorization_scheme: SignatureSchemeId::Ed25519,
        authorization_key: *signer.id.as_bytes(),
    };
    let intent: BondRegistrationIntent = BondRegistrationIntent {
        context: live.clone(),
        request_id,
        validator_id: signer.id,
        authorization_scheme: SignatureSchemeId::Ed25519,
        authorization_key: *signer.id.as_bytes(),
        resource_context: resource.context.clone(),
        resource: resource.resource_id,
        leg: signed_leg.clone(),
        expected_initial_row_digest: crate::bond_lifecycle::bond_row_digest(
            resolver,
            row.lifecycle_epoch,
            &crate::fast_path::records::encode_fastpath_bond_record(&row).unwrap(),
        )
        .unwrap(),
        pinned_genesis_digest: root.digest(),
    };
    let signing_frame: Vec<u8> = bond_registration_signing_frame(
        &live,
        bond_registration_intent_digest(resolver, &intent).unwrap(),
    )
    .unwrap();
    let signed: SignedBondRegistrationIntent = SignedBondRegistrationIntent {
        intent: intent.clone(),
        signature: signer.key.sign(&signing_frame).into(),
    };
    RegistrationAttempt {
        request: BondRegistrationPreparationRequest {
            context: live.clone(),
            request_id,
            authorization_key: *signer.id.as_bytes(),
            resource_context: resource.context.clone(),
            resource: resource.resource_id,
            leg: signed_leg,
            predicted_initial_row: row,
        },
        intent,
        signing_frame,
        candidate: OrderedCandidate {
            context: live,
            request_id,
            kind: OrderedOperationKind::BondRegistration,
            intent: encode_signed_bond_registration_intent(&signed).unwrap(),
            created_checkpoint: checkpoint,
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn assert_owner_reuse_refused(
    root: &crate::genesis::VerifiedGenesisRoot,
    authority: &VerifiedSuccessorAuthority,
    attempt: &RegistrationAttempt,
    targets: &[(SqliteImportTarget, SqliteBlobStore)],
    operation: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    checkpoint: u64,
) {
    let owner: ValidatorId = attempt.intent.validator_id;
    let context: &PublicationContext = env.policy.context();
    assert_eq!(attempt.intent.context, *context);
    assert!(authority.validator_set().get(owner).is_none());
    assert!(authority.owners().owner(owner).is_some());
    let keys: [Vec<u8>; 4] = [
        fastpath_bond_record_key(context.chain_id(), &owner).unwrap(),
        bond_registration_anchor_key(context.chain_id(), &owner).unwrap(),
        runtime::PersistenceLayout::new(context.chain_id().clone(), context.protocol_version())
            .sender_nonce_key(*owner.as_bytes(), context.epoch()),
        crate::local_instance_state::fastpath_nonce_lock_key(
            context.chain_id(),
            owner.as_bytes(),
            context.epoch(),
        )
        .unwrap(),
    ];
    let before: Vec<SourceBusinessSnapshot> = targets
        .iter()
        .map(|(store, blobs): &(SqliteImportTarget, SqliteBlobStore)| {
            crate::test_support::capture::captured_source(
                store,
                blobs,
                operation,
                env.policy.domain(),
            )
        })
        .collect();
    let rows_before: Vec<Vec<VersionedStateValue>> = targets
        .iter()
        .map(|(store, _): &(SqliteImportTarget, SqliteBlobStore)| {
            keys.iter()
                .map(|key: &Vec<u8>| {
                    store
                        .get_versioned_durable(operation, env.policy.domain(), key)
                        .unwrap()
                })
                .collect()
        })
        .collect();
    assert!(matches!(
        verify_signed_bond_registration_successor(root, authority, &attempt.candidate.intent),
        Err(BondRegistrationError::Invalid(
            "registration reuses a verified owner identity or key"
        ))
    ));
    assert!(matches!(
        prepare_bond_registration_successor(root, authority, attempt.request.clone()),
        Err(BondRegistrationError::Invalid(
            "registration reuses a verified owner identity or key"
        ))
    ));
    assert!(matches!(
        env.policy.authenticate_candidate(&attempt.candidate),
        Err(OrderedEconomicsError::Unauthenticated(
            "invalid initial bond registration authentication"
        ))
    ));
    for (index, (store, blobs)) in targets.iter().enumerate() {
        let local_env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
            policy: env.policy,
            history: env.history,
            leg_policy: env.leg_policy,
            engine: env.engine,
            blobs,
            seal: None,
        };
        assert!(matches!(
            crate::ordered_economics::preflight::preflight(
                store,
                operation,
                &local_env,
                &attempt.candidate,
                checkpoint,
            ),
            Err(OrderedEconomicsError::Prerequisite(
                crate::ordered_economics::HANDLER_STOP
            ))
        ));
        for (key, expected) in keys.iter().zip(&rows_before[index]) {
            assert_eq!(
                store
                    .get_versioned_durable(operation, env.policy.domain(), key)
                    .unwrap(),
                *expected,
                "owner reuse changes no bond, anchor, nonce or lock revision"
            );
        }
        assert_eq!(
            crate::test_support::capture::captured_source(
                store,
                blobs,
                operation,
                env.policy.domain(),
            ),
            before[index],
            "owner-reuse refusals leave every physical row, token, receipt and body unchanged"
        );
    }
}
