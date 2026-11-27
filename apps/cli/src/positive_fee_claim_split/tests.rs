//! Pure recognized-leg controls. Genuine successor/history parity is separately
//! exercised in the original compiled successor acceptance helper; these tests
//! do not manufacture a verified successor authority or certify a current row.
use super::*;
use crypto::SignatureSigner;
use sunrise_edge_client::local_execution::{LocalExecutionIntent, local_execution_signing_frame};
use sunrise_edge_client::{AtomicityDomainId, ChainId, LocalSigner};

struct Fixture {
    known: KnownStandardAsset,
    root_digest: Digest32,
    resolver: HashSuiteResolver,
    context: PublicationContext,
    domain: AtomicityDomainId,
    claimant: HistoricalClaimantPin,
    signer: LocalSigner,
    terms: PositiveSplitTerms,
    object: RetainedFeeObject,
}
impl Fixture {
    fn new() -> Self {
        let signer: LocalSigner = LocalSigner::from_seed([0xb1; 32]);
        let protocol = sunrise_edge_devnet::build_devnet_protocol_context(
            ChainId::new("positive-split-meaning-test").unwrap(),
            Epoch::new(0),
        )
        .unwrap();
        let original: PublicationContext = PublicationContext::new(
            protocol.chain_id().clone(),
            protocol.resolver().protocol_version(),
            Epoch::new(0),
        )
        .unwrap();
        let (manifest, metadata) = sunrise_edge_devnet::build_paid_genesis_manifest(
            protocol.resolver(),
            &original,
            &[sunrise_edge_devnet::DevOwner::new(
                *signer.address().as_bytes(),
            )],
            sunrise_edge_devnet::DevOwner::new(
                *LocalSigner::from_seed([0xb2; 32]).address().as_bytes(),
            ),
        )
        .unwrap();
        let bytes: Vec<u8> = node_core::genesis::encode_genesis_manifest(&manifest).unwrap();
        let digest: Digest32 =
            node_core::genesis::genesis_manifest_commitment(protocol.resolver(), &manifest)
                .unwrap();
        let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
            protocol.resolver(),
            &bytes,
            digest.bytes(),
            &original,
        )
        .unwrap();
        let known: KnownStandardAsset = KnownStandardAsset::from_root(&root).unwrap();
        let context: PublicationContext = PublicationContext::new(
            original.chain_id().clone(),
            original.protocol_version(),
            Epoch::new(1),
        )
        .unwrap();
        let terms: PositiveSplitTerms = PositiveSplitTerms {
            escrow_request_id: [0xb3; 32],
            request_id: [0xb4; 32],
            amount: 17,
            recipient: LocalSigner::from_seed([0xb5; 32]).address(),
            nonce: 9,
            gas_limit: 500_000,
        };
        let mut object: Object = manifest
            .objects
            .iter()
            .find(|entry| entry.object.id == metadata.owner_coins[0].spend_coin)
            .unwrap()
            .object
            .clone();
        object.version = 3;
        object.owner = Owner::ProtocolCustody(ProtocolCustodyScope {
            purpose: ProtocolCustodyPurpose::FeeEscrow,
            chain_id: context.chain_id().clone(),
            subject: terms.escrow_request_id,
            resource: *known.asset.as_bytes(),
        });
        object.data = encode_call_value(
            &public_standard_asset::coin_body_layout(),
            &CallValue::U64(100),
        )
        .unwrap();
        let canonical_bytes: Vec<u8> = encode_object(&object).unwrap();
        let reference: ObjectRef = ObjectRef {
            id: object.id,
            version: object.version,
            digest: protocol
                .resolver()
                .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_bytes)
                .unwrap(),
        };
        Self {
            known,
            root_digest: root.digest(),
            resolver: protocol.resolver().clone(),
            context,
            domain: protocol.domain(),
            claimant: HistoricalClaimantPin {
                certificate_epoch: Epoch::new(0),
                validator: ValidatorId::new([0xb6; 32]),
                public_key: signer.address(),
            },
            signer,
            terms,
            object: RetainedFeeObject {
                canonical_bytes,
                reference,
                hash_epoch: Epoch::new(0),
            },
        }
    }
    fn prepare(
        &self,
        terms: &PositiveSplitTerms,
        object: &RetainedFeeObject,
    ) -> Result<PreparedLocalExecution, PositiveSplitError> {
        prepare_recognized_leg(
            &self.known,
            &self.resolver,
            &self.context,
            self.domain,
            self.claimant,
            terms,
            object,
            RecognizedLegKind::StrictSplit,
        )
    }
    fn reencode(&self, object: Object) -> RetainedFeeObject {
        let canonical_bytes: Vec<u8> = encode_object(&object).unwrap();
        let reference: ObjectRef = ObjectRef {
            id: object.id,
            version: object.version,
            digest: self
                .resolver
                .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_bytes)
                .unwrap(),
        };
        RetainedFeeObject {
            canonical_bytes,
            reference,
            hash_epoch: Epoch::new(0),
        }
    }
}

/// Source-verified original genesis plus a deliberately synthetic successor
/// claim envelope. This feeds the disposable UID/PTY approval primitive test;
/// it is not a verified historical committee or live host preparation.
pub(crate) struct SyntheticFinalTransferMaterial {
    pub(crate) terms: PositiveSplitTerms,
    pub(crate) object: RetainedFeeObject,
    pub(crate) claimant: HistoricalClaimantPin,
    pub(crate) root_digest: Digest32,
    pub(crate) leg_frame: Vec<u8>,
    pub(crate) signed_leg: Vec<u8>,
    pub(crate) leg_review: String,
    pub(crate) outer_frame: Vec<u8>,
    pub(crate) signed_outer: Vec<u8>,
    pub(crate) request_bytes: Vec<u8>,
    pub(crate) intent_bytes: Vec<u8>,
    pub(crate) outer_review: String,
}

pub(crate) fn synthetic_final_transfer_material() -> SyntheticFinalTransferMaterial {
    use sunrise_edge_client::bond_registration::BondResourceId;
    use sunrise_edge_client::{FeeClaimPrepareRequest, HashAlgorithmId};

    let f = Fixture::new();
    let mut terms: PositiveSplitTerms = f.terms.clone();
    terms.amount = 100;
    let prepared: PreparedLocalExecution = prepare_recognized_leg(
        &f.known,
        &f.resolver,
        &f.context,
        f.domain,
        f.claimant,
        &terms,
        &f.object,
        RecognizedLegKind::FinalTransfer,
    )
    .unwrap();
    let leg_frame: Vec<u8> = prepared.signable_frame().to_vec();
    let leg_review: String = FinalTransferMeaning::build(
        f.claimant,
        f.context.clone(),
        f.root_digest,
        *f.known.code.artifact_digest(),
        &f.known,
        &terms,
        &f.object,
        &leg_frame,
    )
    .unwrap()
    .render_text()
    .to_owned();
    let leg_signature: Vec<u8> = f.signer.sign_framed(&leg_frame).unwrap();
    let signed_leg: Vec<u8> =
        encode_signed_local_execution(&prepared.finalize(leg_signature).unwrap()).unwrap();
    let request = FeeClaimPrepareRequest {
        context: f.context.clone(),
        escrow_request_id: terms.escrow_request_id,
        request_id: terms.request_id,
        validator_id: f.claimant.validator,
        claimant_public_key: *f.claimant.public_key.as_bytes(),
        recipient: terms.recipient,
        signed_leg: Some(signed_leg.clone()),
    };
    let intent = FeeClaimIntent {
        context: f.context.clone(),
        request_id: terms.request_id,
        escrow_request_id: terms.escrow_request_id,
        certificate_epoch: f.claimant.certificate_epoch,
        validator_id: f.claimant.validator,
        resource_id: BondResourceId::new(
            public_standard_asset::ASSET_OPAQUE_DOMAIN,
            *f.known.asset.as_bytes(),
        )
        .unwrap(),
        expected_generation: 1,
        expected_fee_output: f.object.reference.clone(),
        expected_previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xc1; 32]),
        expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xc2; 32]),
        share_amount: terms.amount,
        recipient: terms.recipient,
        operation: FeeClaimOperation::FinalTransfer {
            leg: signed_leg.clone(),
        },
    };
    let request_bytes: Vec<u8> = request.encode().unwrap();
    let intent_bytes: Vec<u8> = encode_fee_claim_intent(&intent).unwrap();
    let digest: Digest32 =
        node_core::fee_claims::fee_claim_intent_digest(&f.resolver, &intent).unwrap();
    let outer_frame: Vec<u8> =
        node_core::fee_claims::fee_claim_signing_frame(&f.context, digest).unwrap();
    let outer_signature: Vec<u8> = f.signer.sign_framed(&outer_frame).unwrap();
    let signed_outer: Vec<u8> = node_core::fee_claims::codec::encode_signed_fee_claim_intent(
        &node_core::fee_claims::codec::SignedFeeClaimIntent {
            intent,
            signature: outer_signature.try_into().unwrap(),
        },
    )
    .unwrap();
    let outer_review = format!(
        "review_kind=synthetic_final_transfer_outer_approval_primitive\nverified_original_genesis={}\nsuccessor_committee_and_host=synthetic_not_verified\nclaimant={}\nrequest={}\namount={}\nrecipient={}\ncanonical_intent={}\nouter_frame={}\n",
        f.root_digest,
        f.claimant.public_key,
        crate::hex::encode_hex(&terms.request_id),
        terms.amount,
        terms.recipient,
        crate::hex::encode_hex(&intent_bytes),
        crate::hex::encode_hex(&outer_frame),
    );
    SyntheticFinalTransferMaterial {
        terms,
        object: f.object,
        claimant: f.claimant,
        root_digest: f.root_digest,
        leg_frame,
        signed_leg,
        leg_review,
        outer_frame,
        signed_outer,
        request_bytes,
        intent_bytes,
        outer_review,
    }
}

#[test]
fn recognized_leg_retains_independent_legacy_frame_and_signature_bytes() {
    let f: Fixture = Fixture::new();
    let prepared: PreparedLocalExecution = f.prepare(&f.terms, &f.object).unwrap();
    let policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(f.context.clone());
    let legacy: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&f.resolver).unwrap(),
        call: CallIntent {
            context: f.context.clone(),
            request_id: f.terms.request_id,
            sender: *f.claimant.public_key.as_bytes(),
            nonce: 9,
            code: f.known.code.clone(),
            instance: f.known.scope.target.clone(),
            entrypoint: "split".into(),
            type_arguments: f.known.coin.args().to_vec(),
            access: AccessManifest {
                entries: vec![AccessEntry {
                    object_ref: f.object.reference.clone(),
                    mode: AccessMode::Write,
                }],
            },
            arguments: public_standard_asset::split_arguments(17, f.terms.recipient.as_bytes())
                .unwrap(),
            gas_limit: 500_000,
        },
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = local_execution_signing_frame(&f.context, &legacy).unwrap();
    assert_eq!(prepared.signable_frame(), frame);
    let signature: Vec<u8> = f.signer.sign_framed(&frame).unwrap();
    let signed: SignedLocalExecutionIntent = prepared.finalize(signature.clone()).unwrap();
    let expected: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
        intent: legacy,
        signature: signature.as_slice().try_into().unwrap(),
    };
    assert_eq!(
        encode_signed_local_execution(&signed).unwrap(),
        encode_signed_local_execution(&expected).unwrap()
    );
    let original_object: RetainedFeeObject = f.object.clone();
    let review: PositiveSplitMeaning = PositiveSplitMeaning::build(
        f.claimant,
        f.context.clone(),
        *f.known.code.artifact_digest(),
        *f.known.code.artifact_digest(),
        &f.known,
        &f.terms,
        &f.object,
        &frame,
    )
    .unwrap();
    assert_eq!(review.amount(), 17);
    assert_eq!(review.retained_remainder(), 83);
    assert!(
        review
            .render_text()
            .contains("claim_entitlement=not_proven")
    );
    assert!(
        review
            .render_text()
            .contains("escrow_and_nonce_freshness=not_proven")
    );
    assert!(
        review
            .render_text()
            .contains(&crate::hex::encode_hex(&frame))
    );
    assert_eq!(f.object, original_object);
}

#[test]
fn positive_amount_nonce_gas_recipient_and_object_refusals_leave_inputs_intact() {
    let f: Fixture = Fixture::new();
    let original: RetainedFeeObject = f.object.clone();
    for amount in [0, 100, u64::MAX] {
        let mut changed: PositiveSplitTerms = f.terms.clone();
        changed.amount = amount;
        assert!(f.prepare(&changed, &f.object).is_err());
    }
    for gas in [
        0,
        sunrise_edge_client::local_execution::MAX_LOCAL_EXECUTION_GAS + 1,
    ] {
        let mut changed: PositiveSplitTerms = f.terms.clone();
        changed.gas_limit = gas;
        assert!(f.prepare(&changed, &f.object).is_err());
    }
    let mut changed: PositiveSplitTerms = f.terms.clone();
    changed.nonce = u64::MAX;
    assert!(f.prepare(&changed, &f.object).is_err());
    changed = f.terms.clone();
    changed.recipient = Address::new([0; 32]);
    assert!(f.prepare(&changed, &f.object).is_err());
    let mut retained: RetainedFeeObject = f.object.clone();
    retained.reference.version += 1;
    assert!(f.prepare(&f.terms, &retained).is_err());
    retained = f.object.clone();
    retained.hash_epoch = Epoch::new(2);
    assert!(f.prepare(&f.terms, &retained).is_err());
    retained = f.object.clone();
    retained.canonical_bytes.push(0);
    assert!(f.prepare(&f.terms, &retained).is_err());
    retained.canonical_bytes = vec![0; MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1];
    assert!(f.prepare(&f.terms, &retained).is_err());
    assert_eq!(f.object, original);
}

#[test]
fn final_transfer_requires_whole_coin_and_retains_independent_transfer_frame() {
    let f: Fixture = Fixture::new();
    let mut terms: PositiveSplitTerms = f.terms.clone();
    terms.amount = 100;
    let prepared: PreparedLocalExecution = prepare_recognized_leg(
        &f.known,
        &f.resolver,
        &f.context,
        f.domain,
        f.claimant,
        &terms,
        &f.object,
        RecognizedLegKind::FinalTransfer,
    )
    .unwrap();
    let policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(f.context.clone());
    let legacy: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&f.resolver).unwrap(),
        call: CallIntent {
            context: f.context.clone(),
            request_id: terms.request_id,
            sender: *f.claimant.public_key.as_bytes(),
            nonce: terms.nonce,
            code: f.known.code.clone(),
            instance: f.known.scope.target.clone(),
            entrypoint: "transfer".into(),
            type_arguments: f.known.coin.args().to_vec(),
            access: AccessManifest {
                entries: vec![AccessEntry {
                    object_ref: f.object.reference.clone(),
                    mode: AccessMode::Write,
                }],
            },
            arguments: public_standard_asset::transfer_arguments(terms.recipient.as_bytes())
                .unwrap(),
            gas_limit: terms.gas_limit,
        },
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = local_execution_signing_frame(&f.context, &legacy).unwrap();
    assert_eq!(prepared.signable_frame(), frame);
    let signature: Vec<u8> = f.signer.sign_framed(&frame).unwrap();
    let signed: SignedLocalExecutionIntent = prepared.finalize(signature.clone()).unwrap();
    assert_eq!(signed.intent, legacy);
    assert_eq!(signed.signature.as_slice(), signature);
    let review: FinalTransferMeaning = FinalTransferMeaning::build(
        f.claimant,
        f.context.clone(),
        *f.known.code.artifact_digest(),
        *f.known.code.artifact_digest(),
        &f.known,
        &terms,
        &f.object,
        &frame,
    )
    .unwrap();
    assert!(review.render_text().contains("entrypoint=transfer"));
    assert!(review.render_text().contains("retained_remainder=0"));
    assert!(
        review
            .render_text()
            .contains(&crate::hex::encode_hex(&frame))
    );

    for amount in [0, 17, 99, 101] {
        terms.amount = amount;
        assert!(
            prepare_recognized_leg(
                &f.known,
                &f.resolver,
                &f.context,
                f.domain,
                f.claimant,
                &terms,
                &f.object,
                RecognizedLegKind::FinalTransfer,
            )
            .is_err()
        );
    }
    terms.amount = 100;
    let mut changed: RetainedFeeObject = f.object.clone();
    changed.reference.version += 1;
    assert!(
        prepare_recognized_leg(
            &f.known,
            &f.resolver,
            &f.context,
            f.domain,
            f.claimant,
            &terms,
            &changed,
            RecognizedLegKind::FinalTransfer,
        )
        .is_err()
    );
}

#[test]
fn exact_custody_owner_resource_type_and_scope_are_required() {
    let f: Fixture = Fixture::new();
    let source: Object = decode_object(&f.object.canonical_bytes).unwrap();
    let mut changed: Object = source.clone();
    changed.owner = Owner::Address(f.signer.address());
    assert!(f.prepare(&f.terms, &f.reencode(changed)).is_err());
    changed = source.clone();
    changed.schema_version += 1;
    assert!(f.prepare(&f.terms, &f.reencode(changed)).is_err());
    changed = source.clone();
    changed.type_hash = f.object.reference.digest;
    assert!(f.prepare(&f.terms, &f.reencode(changed)).is_err());
    changed = source;
    let Owner::ProtocolCustody(scope) = &mut changed.owner else {
        panic!("fixture custody owner")
    };
    scope.subject = [0xd1; 32];
    assert!(f.prepare(&f.terms, &f.reencode(changed)).is_err());
    let mut wrong: KnownStandardAsset = f.known.clone();
    wrong.code = UnverifiedDependencyRef::new(
        wrong.code.origin().clone(),
        2,
        wrong.context.clone(),
        *wrong.code.artifact_digest(),
    )
    .unwrap();
    assert!(
        prepare_recognized_leg(
            &wrong,
            &f.resolver,
            &f.context,
            f.domain,
            f.claimant,
            &f.terms,
            &f.object,
            RecognizedLegKind::StrictSplit,
        )
        .is_err()
    );
}

#[test]
fn unsafe_context_and_wrong_leg_signature_refuse() {
    let f: Fixture = Fixture::new();
    let bad_context: PublicationContext = PublicationContext::new(
        ChainId::new("unsafe\u{1}chain").unwrap(),
        f.context.protocol_version(),
        f.context.epoch(),
    )
    .unwrap();
    assert!(
        PositiveSplitMeaning::build(
            f.claimant,
            bad_context,
            *f.known.code.artifact_digest(),
            *f.known.code.artifact_digest(),
            &f.known,
            &f.terms,
            &f.object,
            b"frame"
        )
        .is_err()
    );
    assert!(
        f.prepare(&f.terms, &f.object)
            .unwrap()
            .finalize(vec![0; 64])
            .is_err()
    );
    assert!(
        f.prepare(&f.terms, &f.object)
            .unwrap()
            .finalize(vec![0; 63])
            .is_err()
    );
    let long: Vec<u8> = vec![0; MAX_POSITIVE_SPLIT_REVIEW_BYTES / 4 + 1];
    assert!(
        PositiveSplitMeaning::build(
            f.claimant,
            f.context.clone(),
            *f.known.code.artifact_digest(),
            *f.known.code.artifact_digest(),
            &f.known,
            &f.terms,
            &f.object,
            &long
        )
        .is_err()
    );
}
