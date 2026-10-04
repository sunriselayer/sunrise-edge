//! Cross-language DR-0191 Section 9 tag-2 vectors for synthetic codec
//! claims, not authority. The independent encoder is
//! scripts/ordered-seal-successor-vectors.mjs. Every tag-1 vector stays in
//! ordered_seal_vectors.rs unchanged.
use consensus::{
    DrainUnionIdentity,
    readiness::{ReadinessSubject, readiness_schedule_digest},
};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::business_reconstruction::cut::{
    BusinessCutCollection, BusinessCutCollectionRoot, BusinessCutIdentity,
    business_cut_identity_digest, encode_business_cut_identity,
};
use node_core::ordered_economics::{
    OrderedHistoryIdentity, SEAL_PREDECESSOR_TAG_GENESIS, SEAL_PREDECESSOR_TAG_SUCCESSOR,
    SealIntent, decode_seal_intent, encode_seal_intent, seal_certificate_digest, seal_request_id,
    seal_target_digest,
};
use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, Epoch, ExecutionGeneration, HashAlgorithmId, HashPurpose,
    HashSuite, HashSuiteSchedule, ProtocolVersion,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn seal_successor_predecessor_matches_independent_fixed_vectors() {
    let chain: ChainId = ChainId::new("cut-vector").unwrap();
    let protocol: ProtocolVersion = ProtocolVersion::new(1);
    let epoch: Epoch = Epoch::new(2);
    let context: PublicationContext =
        PublicationContext::new(chain.clone(), protocol, epoch).unwrap();
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x11; 32]).unwrap();
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain.clone(),
        protocol,
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let d: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]);
    // Synthetic stand-in for the private 0xD054 subject digest of the link
    // that activated the sealing epoch.
    let subject_link: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x54; 32]);
    let root = |collection: BusinessCutCollection| BusinessCutCollectionRoot {
        collection,
        count: 0,
        root: d,
    };
    let cut: BusinessCutIdentity = BusinessCutIdentity {
        context: context.clone(),
        domain,
        genesis_digest: d,
        validator_set_digest: d,
        ordered_history: OrderedHistoryIdentity {
            context: context.clone(),
            domain,
            genesis_digest: d,
            anchor: d,
            through_height: 9,
            through_view: 11,
            through_digest: d,
        },
        drain_request_id: [0x80; 32],
        drain_block_height: 4,
        drain_candidate_digest: d,
        drain_union: DrainUnionIdentity {
            chain_id: chain.clone(),
            protocol_version: protocol,
            epoch,
            domain,
            closure_request_id: [0x81; 32],
            closure_height: 1,
            signer_count: 3,
            member_count: 0,
            entries_digest: d,
        },
        generation_floor: ExecutionGeneration::new(7),
        business: [
            root(BusinessCutCollection::State),
            root(BusinessCutCollection::Receipts),
            root(BusinessCutCollection::ObjectHeads),
            root(BusinessCutCollection::ObjectVersions),
        ],
        artifacts: root(BusinessCutCollection::Artifacts),
    };
    let subject: ReadinessSubject = ReadinessSubject {
        chain_id: chain,
        protocol_version: protocol,
        epoch,
        genesis_digest: d,
        domain,
        outgoing_set_digest: d,
        cut_digest: business_cut_identity_digest(&resolver, &cut).unwrap(),
        next_epoch: Epoch::new(3),
        next_set_digest: d,
        schedule_digest: readiness_schedule_digest(&resolver, epoch).unwrap(),
    };
    let subject_identity: Digest32 = subject.identity(&resolver).unwrap();
    let certificate: &[u8] = b"certificate-fixture";
    let certificate_digest: Digest32 =
        seal_certificate_digest(&resolver, epoch, certificate).unwrap();
    let target: Digest32 = seal_target_digest(
        &resolver,
        &context,
        subject_identity,
        SEAL_PREDECESSOR_TAG_SUCCESSOR,
        subject_link,
    )
    .unwrap();
    assert_eq!(
        hex(&target.bytes()),
        "c5260ad21b48607668afe8d1ac7b1de1575de88f72abb0d61bb3bb716b09a809"
    );
    // The tag is committed: tag 1 over the same digest is another target,
    // and the unchanged tag-1 fixture target is still exactly the old one.
    assert_ne!(
        seal_target_digest(
            &resolver,
            &context,
            subject_identity,
            SEAL_PREDECESSOR_TAG_GENESIS,
            subject_link,
        )
        .unwrap(),
        target
    );
    assert_eq!(
        hex(&seal_target_digest(
            &resolver,
            &context,
            subject_identity,
            SEAL_PREDECESSOR_TAG_GENESIS,
            d,
        )
        .unwrap()
        .bytes()),
        "439bdfeb68aec0fb9dd993db769dbd4b610ca46364e00472575b42a0e6250ee7"
    );
    let request: [u8; 32] =
        seal_request_id(&resolver, &context, target, certificate_digest).unwrap();
    assert_eq!(request[0] & 0x80, 0x80);
    assert_eq!(
        hex(&request),
        "83b1b959db205a890f26fb00f7016d946b88483fa6310c9fc8ea156192a719fb"
    );
    let intent: SealIntent = SealIntent {
        readiness_subject: subject,
        cut_identity_bytes: encode_business_cut_identity(&cut).unwrap(),
        predecessor_tag: SEAL_PREDECESSOR_TAG_SUCCESSOR,
        predecessor_digest: subject_link,
        certificate_digest,
        certificate_length: u32::try_from(certificate.len()).unwrap(),
    };
    let intent_bytes: Vec<u8> = encode_seal_intent(&intent).unwrap();
    assert_eq!(decode_seal_intent(&intent_bytes).unwrap(), intent);
    assert_eq!(
        hex(&resolver
            .hash_for_purpose(epoch, HashPurpose::NodeEvent, &intent_bytes)
            .unwrap()
            .bytes()),
        "8607924ae2c2940610c22e6b0d527179d2950c4ac067e53f050c5f6d3df710eb"
    );
    for unknown in [0u16, 3, u16::MAX] {
        let mut refused: SealIntent = intent.clone();
        refused.predecessor_tag = unknown;
        assert!(encode_seal_intent(&refused).is_err());
        assert!(
            seal_target_digest(&resolver, &context, subject_identity, unknown, subject_link)
                .is_err()
        );
    }
}
