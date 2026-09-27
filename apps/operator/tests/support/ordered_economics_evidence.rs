//! Real signed proof and generic WASM forfeiture builders, not imported
//! evidence/bond rows or privileged Standard Asset runtime operations.
use super::*;
use consensus::{
    ConsensusSigner, EpochTransitionCertifier, FastPathCertifier, LockedObjectSetPreimage,
};
use node_core::ordered_economics::{OrderedEvidenceSubmission, encode_ordered_evidence_submission};
use protocol_types::{Digest32, HashPurpose, SignatureSchemeId};
use validator_set::{ValidatorInfo, ValidatorSet};

struct Signer<'a> {
    validator: ValidatorId,
    key: &'a SigningKey,
}

impl ConsensusSigner for Signer<'_> {
    fn validator_id(&self) -> ValidatorId {
        self.validator
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        let signature: [u8; 64] = self.key.sign(framed).into();
        Ok(signature.to_vec())
    }
}

pub(super) struct Proof {
    pub candidate: OrderedCandidate,
    pub evidence_bytes: Vec<u8>,
    pub identity: Digest32,
}

/// Three independent signed statement families, all at the pinned active
/// epoch. Epoch-transition evidence is NOT epoch activation.
pub(super) fn proofs(fixture: &FastVoteGenesisFixture, validator: ValidatorId) -> Vec<Proof> {
    let set: ValidatorSet = ValidatorSet::new(
        fixture.epoch,
        fixture
            .validators
            .iter()
            .map(|v| {
                let public: [u8; 32] = VerificationKey::from(&v.signing_key).into();
                ValidatorInfo {
                    id: v.validator_id,
                    voting_power: 1,
                    signature_scheme: SignatureSchemeId::Ed25519,
                    public_key: public.to_vec(),
                }
            })
            .collect(),
    )
    .unwrap();
    let signer: Signer<'_> = Signer {
        validator,
        key: &fixture
            .validators
            .iter()
            .find(|v| v.validator_id == validator)
            .unwrap()
            .signing_key,
    };
    let digest = |tag: u8| -> Digest32 {
        fixture
            .resolver
            .hash_for_purpose(fixture.epoch, HashPurpose::NodeEvent, &[tag])
            .unwrap()
    };
    let fast: FastPathCertifier = FastPathCertifier::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        set.clone(),
    )
    .unwrap();
    let a = fast
        .cast_vote(digest(1), digest(2), digest(3), &signer)
        .unwrap();
    let b = fast
        .cast_vote(digest(1), digest(4), digest(3), &signer)
        .unwrap();
    let same = consensus::build_fast_vote_equivocation_evidence(&a, &b).unwrap();
    let preimage: LockedObjectSetPreimage = LockedObjectSetPreimage {
        chain_id: fixture.chain_id.clone(),
        protocol_version: fixture.protocol_version,
        epoch: fixture.epoch,
        entries: vec![fixture.fee_coin_ref()],
    };
    let preimage_bytes: Vec<u8> = consensus::encode_locked_object_set_preimage(&preimage).unwrap();
    let locked: Digest32 = fixture
        .resolver
        .hash_for_purpose(
            fixture.epoch,
            HashPurpose::ExecutionEffects,
            &preimage_bytes,
        )
        .unwrap();
    let c = fast
        .cast_vote(digest(5), digest(6), locked, &signer)
        .unwrap();
    let d = fast
        .cast_vote(digest(7), digest(8), locked, &signer)
        .unwrap();
    let overlap =
        consensus::build_fast_vote_object_conflict_evidence(&c, &d, &preimage, &preimage).unwrap();
    let epoch: EpochTransitionCertifier = EpochTransitionCertifier::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        set.clone(),
    )
    .unwrap();
    let next_epoch = protocol_types::Epoch::new(fixture.epoch.get().checked_add(1).unwrap());
    let current: Digest32 = set.digest(&fixture.resolver).unwrap();
    let e = epoch
        .cast_vote(next_epoch, current, digest(9), digest(10), &signer)
        .unwrap();
    let f = epoch
        .cast_vote(next_epoch, current, digest(11), digest(12), &signer)
        .unwrap();
    let transition = consensus::build_epoch_transition_equivocation_evidence(&e, &f).unwrap();
    vec![
        (
            OrderedEvidenceSubmission::FastVote {
                statement_a: consensus::encode_fast_vote(&a).unwrap(),
                statement_b: consensus::encode_fast_vote(&b).unwrap(),
                checkpoint: 2,
            },
            consensus::encode_fast_vote_equivocation_evidence(&same).unwrap(),
        ),
        (
            OrderedEvidenceSubmission::ObjectConflict {
                statement_a: consensus::encode_fast_vote(&c).unwrap(),
                statement_b: consensus::encode_fast_vote(&d).unwrap(),
                preimage_a: preimage_bytes.clone(),
                preimage_b: preimage_bytes,
                checkpoint: 2,
            },
            consensus::encode_fast_vote_object_conflict_evidence(&overlap).unwrap(),
        ),
        (
            OrderedEvidenceSubmission::EpochTransition {
                statement_a: consensus::encode_epoch_transition_vote(&e).unwrap(),
                statement_b: consensus::encode_epoch_transition_vote(&f).unwrap(),
                checkpoint: 2,
            },
            consensus::encode_epoch_transition_equivocation_evidence(&transition).unwrap(),
        ),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (submission, evidence_bytes))| {
        let identity: Digest32 =
            node_core::equivocation::evidence_identity_digest(&fixture.resolver, &evidence_bytes)
                .unwrap();
        Proof {
            candidate: OrderedCandidate {
                context: fixture.context.clone(),
                request_id: [0xD1 + u8::try_from(index).unwrap(); 32],
                kind: OrderedOperationKind::Evidence,
                intent: encode_ordered_evidence_submission(&submission).unwrap(),
                created_checkpoint: 2,
            },
            evidence_bytes,
            identity,
        }
    })
    .collect()
}

pub(super) fn prepare_slash(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    validator: ValidatorId,
    conflict_digest: Digest32,
) -> OrderedCandidate {
    let durable: Store = store(pool, namespace);
    let context: runtime::DurableOperationContext = cli::read_context(pool, namespace);
    let key: Vec<u8> =
        node_core::local_instance_state::fastpath_bond_record_key(&fixture.chain_id, &validator)
            .unwrap();
    let observed = durable
        .get_versioned_durable(&context, fixture.domain, &key)
        .unwrap();
    let bond =
        node_core::fast_path::records::decode_fastpath_bond_record(observed.value().unwrap())
            .unwrap();
    let manifest = node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let resource = manifest
        .economics_policy
        .resources
        .iter()
        .find(|r| {
            r.resource_id.domain() == bond.resource_domain
                && r.resource_id.value() == &bond.resource
        })
        .unwrap();
    let scope = objects::ProtocolCustodyScope {
        purpose: objects::ProtocolCustodyPurpose::ForfeitedCollateral,
        chain_id: bond.context.chain_id().clone(),
        subject: *validator.as_bytes(),
        resource: bond.resource,
    };
    let operand: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &fixture.resolver,
        &fixture.context,
        bond.custody_object.id,
        &scope,
    )
    .unwrap();
    let publication = manifest.publication.request().artifact();
    let authenticated = execution::publication::authenticate_publication_submission(
        &fixture.resolver,
        &fixture.context,
        publication.semantics(),
        manifest.publication.clone(),
    )
    .unwrap();
    let interface =
        execution::publication::verify_publication_interface(authenticated, Vec::new()).unwrap();
    let arguments: Vec<u8> = encode_call_value(
        interface
            .argument_layout(&resource.transfer_entrypoint)
            .unwrap(),
        &CallValue::Tuple(vec![CallValue::Bytes(operand.to_vec())]),
    )
    .unwrap();
    // Anyone may submit evidence-authorized forfeiture; the slash does NOT
    // depend on the malicious validator signing its own punishment.
    let key: SigningKey = SigningKey::from([0x88; 32]);
    let sender: [u8; 32] = VerificationKey::from(&key).into();
    let next_nonce: u64 = node_core::query_sender_next_nonce(
        &durable,
        &context,
        fixture.domain,
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        sender,
    )
    .unwrap();
    let policy = LocalExecutionPolicy::generic_object_results(fixture.context.clone());
    let request_id: [u8; 32] = [0xD4; 32];
    let intent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&fixture.resolver).unwrap(),
        call: CallIntent {
            context: fixture.context.clone(),
            request_id,
            sender,
            nonce: next_nonce,
            code: resource.code.clone(),
            instance: resource.instance.clone(),
            entrypoint: resource.transfer_entrypoint.clone(),
            type_arguments: resource.ty.args().to_vec(),
            access: AccessManifest {
                entries: vec![AccessEntry {
                    object_ref: bond.custody_object.clone(),
                    mode: AccessMode::Write,
                }],
            },
            arguments,
            gas_limit: 500_000,
        },
        authorizations: Vec::new(),
    };
    let frame = local_execution_signing_frame(&fixture.context, &intent).unwrap();
    let leg: Vec<u8> = encode_signed_local_execution(&SignedLocalExecutionIntent {
        intent,
        signature: key.sign(&frame).into(),
    })
    .unwrap();
    let slash = node_core::bond_lifecycle::slash::SlashIntent {
        context: fixture.context.clone(),
        request_id,
        validator_id: validator,
        resource_id: resource.resource_id,
        expected_generation: bond.generation,
        evidence_epoch: fixture.epoch,
        conflict_digest,
        leg,
    };
    OrderedCandidate {
        context: fixture.context.clone(),
        request_id,
        kind: OrderedOperationKind::BondSlash,
        intent: node_core::bond_lifecycle::slash::encode_slash_intent(&slash).unwrap(),
        created_checkpoint: 2,
    }
}
