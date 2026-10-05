//! Original-epoch registration prerequisite for changed-committee process
//! acceptance. Funding is ordinary signed genesis; all anchors, custody,
//! bond state and receipts are produced by the actual ordered quorum.
use super::super::genesis_fixture::FastVoteValidator;
use super::Fixture;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::{
    LocalExecutionIntent, LocalExecutionMode, SignedLocalExecutionIntent,
    encode_signed_local_execution, local_execution_signing_frame,
};
use node_core::bond_lifecycle::registration::{
    BondRegistrationPreparationRequest, PreparedBondRegistration, SignedBondRegistrationIntent,
    bond_registration_anchor_key, encode_signed_bond_registration_intent,
    prepare_bond_registration,
};
use node_core::fast_path::records::{FastPathBondRecord, FastPathBondState};
use node_core::ordered_economics::{OrderedCandidate, OrderedOperationKind, query_status};
use objects::{
    AccessMode, Address, Object, ObjectId, ObjectRef, Owner, ProtocolCustodyPurpose,
    ProtocolCustodyScope,
};
use protocol_types::{Epoch, HashPurpose, SignatureSchemeId, ValidatorId};
use runtime::VersionedStateReader;

pub(super) fn member(seed: [u8; 32]) -> FastVoteValidator {
    let signing_key: SigningKey = SigningKey::from(seed);
    let validator_id: ValidatorId = ValidatorId::new(VerificationKey::from(&signing_key).into());
    FastVoteValidator {
        seed,
        signing_key,
        validator_id,
    }
}

impl Fixture {
    pub fn original_members(&self) -> Vec<FastVoteValidator> {
        self.network
            .validators
            .iter()
            .map(|validator| member(validator.seed))
            .collect()
    }

    /// Actual A/B/C/E identities, not a relabelled original committee.
    pub fn replacement_members(&self) -> Vec<FastVoteValidator> {
        let mut members: Vec<FastVoteValidator> = self
            .network
            .validators
            .iter()
            .filter(|validator| validator.seed != [0xa4; 32])
            .map(|validator| member(validator.seed))
            .collect();
        assert_eq!(members.len(), 3);
        members.push(member([0xe5; 32]));
        members.sort_by_key(|validator| validator.validator_id);
        members
    }

    pub fn register_incoming_e(&self) {
        let e: FastVoteValidator = member([0xe5; 32]);
        assert!(
            !self
                .network
                .validators
                .iter()
                .any(|old| old.validator_id == e.validator_id)
        );
        let entry: &node_core::GenesisObjectEntry = self
            .root
            .manifest()
            .objects
            .iter()
            .find(|entry| entry.object.id == ObjectId::new([0x17; 32]))
            .unwrap();
        assert_eq!(
            entry.object.owner,
            Owner::Address(Address::new(*e.validator_id.as_bytes()))
        );
        let resource: &node_core::economics::FastPathEconomicsResourcePolicy =
            &self.root.manifest().economics_policy.resources[0];
        let request_id: [u8; 32] = [0xe7; 32];
        let scope: ProtocolCustodyScope = ProtocolCustodyScope {
            purpose: ProtocolCustodyPurpose::BondCollateral,
            chain_id: self.network.chain_id.clone(),
            subject: *e.validator_id.as_bytes(),
            resource: *resource.resource_id.value(),
        };
        let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
            &self.network.resolver,
            &self.network.context,
            entry.object.id,
            &scope,
        )
        .unwrap();
        let original_ref: ObjectRef = ObjectRef {
            id: entry.object.id,
            version: entry.object.version,
            digest: self
                .network
                .resolver
                .hash_for_purpose(
                    self.network.epoch,
                    HashPurpose::Object,
                    &objects::encode_object(&entry.object).unwrap(),
                )
                .unwrap(),
        };
        let leg: LocalExecutionIntent = LocalExecutionIntent {
            mode: LocalExecutionMode::Call,
            policy_digest: self.local_policy.digest(&self.network.resolver).unwrap(),
            call: CallIntent {
                context: self.network.context.clone(),
                request_id,
                sender: *e.validator_id.as_bytes(),
                nonce: 0,
                code: resource.code.clone(),
                instance: resource.instance.clone(),
                entrypoint: resource.transfer_entrypoint.clone(),
                type_arguments: self.root.manifest().fee_policy.type_arguments.clone(),
                access: abi::AccessManifest {
                    entries: vec![abi::AccessEntry {
                        object_ref: original_ref,
                        mode: AccessMode::Write,
                    }],
                },
                arguments: public_standard_asset::transfer_arguments(&token).unwrap(),
                gas_limit: 500_000,
            },
            authorizations: Vec::new(),
        };
        let frame: Vec<u8> = local_execution_signing_frame(&self.network.context, &leg).unwrap();
        let signed_leg: Vec<u8> = encode_signed_local_execution(&SignedLocalExecutionIntent {
            signature: e.signing_key.sign(&frame).into(),
            intent: leg,
        })
        .unwrap();
        let mut predicted: Object = entry.object.clone();
        predicted.version = predicted.version.checked_add(1).unwrap();
        predicted.owner = Owner::ProtocolCustody(scope);
        let initial: FastPathBondRecord = FastPathBondRecord {
            context: resource.context.clone(),
            validator_id: e.validator_id,
            resource_domain: resource.resource_id.domain(),
            resource: *resource.resource_id.value(),
            custody_object: ObjectRef {
                id: predicted.id,
                version: predicted.version,
                digest: self
                    .network
                    .resolver
                    .hash_for_purpose(
                        self.network.epoch,
                        HashPurpose::Object,
                        &objects::encode_object(&predicted).unwrap(),
                    )
                    .unwrap(),
            },
            custody_object_epoch: self.network.epoch,
            authority: entry.authority.clone(),
            amount: 10_000,
            committed_at_checkpoint: 20,
            generation: 1,
            lifecycle_epoch: self.network.epoch,
            slashable_from_epoch: Epoch::new(1),
            required_minimum: resource.bond.as_ref().unwrap().min_bond.get(),
            state: FastPathBondState::Active,
            authorization_scheme: SignatureSchemeId::Ed25519,
            authorization_key: *e.validator_id.as_bytes(),
        };
        let prepared: PreparedBondRegistration = prepare_bond_registration(
            &self.root,
            BondRegistrationPreparationRequest {
                context: self.network.context.clone(),
                request_id,
                authorization_key: *e.validator_id.as_bytes(),
                resource_context: resource.context.clone(),
                resource: resource.resource_id,
                leg: signed_leg,
                predicted_initial_row: initial.clone(),
            },
        )
        .unwrap();
        let candidate: OrderedCandidate = OrderedCandidate {
            context: self.network.context.clone(),
            request_id,
            kind: OrderedOperationKind::BondRegistration,
            intent: encode_signed_bond_registration_intent(&SignedBondRegistrationIntent {
                signature: e.signing_key.sign(&prepared.signing_frame).into(),
                intent: prepared.intent,
            })
            .unwrap(),
            created_checkpoint: 20,
        };
        let anchor: Vec<u8> =
            bond_registration_anchor_key(&self.network.chain_id, &e.validator_id).unwrap();
        let row_key: Vec<u8> = node_core::local_instance_state::fastpath_bond_record_key(
            &self.network.chain_id,
            &e.validator_id,
        )
        .unwrap();
        for store in &self.stores {
            assert!(
                store
                    .read_versioned_state(&self.operation, self.network.domain, &anchor)
                    .unwrap()
                    .value()
                    .is_none()
            );
        }
        let first: u64 = query_status(&self.stores[0], &self.operation, &self.environment())
            .unwrap()
            .current_view;
        for offset in 0..3 {
            self.round(
                first.checked_add(offset).unwrap(),
                (offset == 0).then_some(&candidate),
            );
        }
        for store in &self.stores {
            assert!(
                store
                    .read_versioned_state(&self.operation, self.network.domain, &anchor)
                    .unwrap()
                    .value()
                    .is_some()
            );
            let row: Vec<u8> = store
                .read_versioned_state(&self.operation, self.network.domain, &row_key)
                .unwrap()
                .value()
                .unwrap()
                .to_vec();
            assert_eq!(
                node_core::fast_path::records::decode_fastpath_bond_record(&row).unwrap(),
                initial
            );
        }
        // Signing alone is not a permit: E was never used as an outgoing quorum member.
        assert!(
            !self
                .policy
                .engine()
                .validator_set()
                .validators()
                .iter()
                .any(|old| old.id == e.validator_id)
        );
    }
}
