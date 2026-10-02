//! Cross-language DR-0187 vectors for synthetic codec claims, not authority.
//! The independent encoder is scripts/ordered-seal-vectors.mjs.
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
    OrderedHistoryIdentity, SealIntent, SealOutcome, decode_seal_intent, decode_seal_outcome,
    encode_seal_intent, encode_seal_outcome, seal_certificate_digest, seal_request_id,
    seal_target_digest,
};
use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, Epoch, ExecutionGeneration, HashAlgorithmId, HashPurpose,
    HashSuite, HashSuiteSchedule, ProtocolVersion,
};
use runtime::{
    OutgoingBarrier, SealBarrier, TransitionHistoryState, decode_outgoing_barrier,
    encode_outgoing_barrier, encode_seal_barrier,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn seal_and_protected_barrier_match_independent_fixed_vectors() {
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
    let certificate: &[u8] = b"certificate-fixture";
    let certificate_digest: Digest32 =
        seal_certificate_digest(&resolver, epoch, certificate).unwrap();
    assert_eq!(
        hex(&certificate_digest.bytes()),
        "1bf62e49f63071b9ebfdb8ef9f73e0d92b775c9d9a5325c8d6614fb463018631"
    );
    assert_ne!(
        certificate_digest,
        resolver
            .hash_for_purpose(epoch, HashPurpose::NodeEvent, certificate)
            .unwrap()
    );
    let target: Digest32 = seal_target_digest(
        &resolver,
        &context,
        subject.identity(&resolver).unwrap(),
        1,
        d,
    )
    .unwrap();
    assert_eq!(
        hex(&target.bytes()),
        "439bdfeb68aec0fb9dd993db769dbd4b610ca46364e00472575b42a0e6250ee7"
    );
    let request: [u8; 32] =
        seal_request_id(&resolver, &context, target, certificate_digest).unwrap();
    assert_eq!(
        hex(&request),
        "c9e8068fc0020717b6f3a73251a3b3f62a393f604b992dea4d5c2779f53feb04"
    );
    let intent: SealIntent = SealIntent {
        readiness_subject: subject,
        cut_identity_bytes: encode_business_cut_identity(&cut).unwrap(),
        predecessor_tag: 1,
        predecessor_digest: d,
        certificate_digest,
        certificate_length: u32::try_from(certificate.len()).unwrap(),
    };
    let intent_bytes: Vec<u8> = encode_seal_intent(&intent).unwrap();
    assert_eq!(decode_seal_intent(&intent_bytes).unwrap(), intent);
    let outcome: SealOutcome = SealOutcome {
        target,
        request,
        seal_block_height: 10,
        seal_block_digest: d,
    };
    let outcome_bytes: Vec<u8> = encode_seal_outcome(&outcome).unwrap();
    assert_eq!(decode_seal_outcome(&outcome_bytes).unwrap(), outcome);
    let sealed: SealBarrier = SealBarrier {
        outgoing_epoch: epoch,
        request,
        height: 10,
        block_digest: d,
        target_digest: target,
        transition_history: TransitionHistoryState::Virgin,
    };
    let barrier: OutgoingBarrier = OutgoingBarrier::Sealed(sealed);
    let barrier_bytes: Vec<u8> = encode_outgoing_barrier(&barrier).unwrap();
    assert_eq!(decode_outgoing_barrier(&barrier_bytes).unwrap(), barrier);
    for (bytes, expected) in [
        (
            intent_bytes,
            "e47c09063bd15e8d87e7dc4158dc5714aa915d1f9ea29b9a8688fae6509589bd",
        ),
        (
            outcome_bytes,
            "4920c814adabaa25b6e108d024241422a05690569275f6d8a347f9fc50686cad",
        ),
        (
            encode_seal_barrier(&sealed).unwrap(),
            "9f7eeacfdf2bcc8c90c7b66e4f30fac7f59b742d27af054087ec4e78ee4e8281",
        ),
        (
            encode_outgoing_barrier(&OutgoingBarrier::Unsealed).unwrap(),
            "307838011aaba8fd31736b15dfe0bb1e33a8f017e9cfd678273a151594d77ca7",
        ),
        (
            barrier_bytes,
            "6c56af402d180bd3e6ed3313ddb10e2c705aebd128ca24e786930a76c7ed82b8",
        ),
    ] {
        let actual: Digest32 = resolver
            .hash_for_purpose(epoch, HashPurpose::NodeEvent, &bytes)
            .unwrap();
        assert_eq!(hex(&actual.bytes()), expected);
    }
}
