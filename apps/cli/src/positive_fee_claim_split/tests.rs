//! Pure recognized-leg controls. Genuine successor/history parity is separately
//! exercised in the original compiled successor acceptance helper; these tests
//! do not manufacture a verified successor authority or certify a current row.
use super::*;
use crypto::SignatureSigner;
use sunrise_edge_client::local_execution::{LocalExecutionIntent, local_execution_signing_frame};
use sunrise_edge_client::{AtomicityDomainId, ChainId, LocalSigner};

struct Fixture {
    known: KnownStandardAsset,
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
            &f.object
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
