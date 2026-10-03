//! Independent fixed wire claims, not a valid activation or membership fixture.
//! The expected values come from scripts/successor-serving-vectors.mjs.

use super::*;
use protocol_types::{ChainId, HashSuite, HashSuiteSchedule, ProtocolVersion};
use runtime::inactive_import::{ImportBinding, ImportContext, ImportProgress};
use runtime::portable::PortableSnapshotToken;
use runtime::{
    SuccessorServingObservation, SuccessorServingRecord, SuccessorServingSlot,
    WriterFenceGeneration, decode_successor_serving_record, decode_successor_serving_slot,
    encode_successor_serving_record, encode_successor_serving_slot,
};

fn digest_hex(hex: &str) -> Digest32 {
    assert_eq!(hex.len(), 64);
    let bytes: [u8; 32] = std::array::from_fn(|offset: usize| {
        u8::from_str_radix(&hex[offset * 2..offset * 2 + 2], 16).unwrap()
    });
    Digest32::new(HashAlgorithmId::Sha2_256, bytes)
}

fn assert_vector(
    resolver: &hashing::HashSuiteResolver,
    purpose: HashPurpose,
    bytes: &[u8],
    length: usize,
    hex: &str,
) {
    assert_eq!(bytes.len(), length);
    assert_eq!(
        resolver
            .hash_for_purpose(Epoch::new(2), purpose, bytes)
            .unwrap(),
        digest_hex(hex),
    );
}

#[test]
fn production_successor_codecs_match_independent_fixed_vectors() {
    let chain: ChainId = ChainId::new("cut-vector").unwrap();
    let protocol: ProtocolVersion = ProtocolVersion::new(1);
    let resolver: hashing::HashSuiteResolver = hashing::HashSuiteResolver::new(
        chain.clone(),
        protocol,
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x11; 32]).unwrap();
    let d: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]);
    let e: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]);
    let subject: SuccessorActivationSubject = SuccessorActivationSubject {
        chain_id: chain.clone(),
        protocol_version: protocol,
        outgoing_epoch: Epoch::new(2),
        genesis_digest: d,
        domain,
        seal_target: d,
        seal_request: [0x80; 32],
        seal_height: 10,
        seal_block_digest: d,
        successor_epoch: Epoch::new(3),
        successor_set_digest: e,
        schedule_digest: d,
        cut_digest: d,
    };
    let manifest: SuccessorActivationManifest = SuccessorActivationManifest {
        subject: subject.clone(),
        certificate_digest: d,
        certificate_length: 19,
        history: OrderedHistoryIdentity {
            context: PublicationContext::new(chain.clone(), protocol, Epoch::new(2)).unwrap(),
            domain,
            genesis_digest: d,
            anchor: d,
            through_height: 10,
            through_view: 12,
            through_digest: d,
        },
        seal_proof_digest: e,
        seal_proof_length: 37,
        package_digest: d,
        plan_digest: e,
    };
    let subject_bytes: Vec<u8> = encode_successor_activation_subject(&subject).unwrap();
    let manifest_bytes: Vec<u8> = encode_successor_activation_manifest(&manifest).unwrap();
    assert_vector(
        &resolver,
        HashPurpose::NodeEvent,
        &subject_bytes,
        542,
        "a7b0e8c259b833400f234ca940e7d9132b3d303ca5b0970185892c369b3e0111",
    );
    assert_vector(
        &resolver,
        HashPurpose::NodeEvent,
        &manifest_bytes,
        1150,
        "59eba06a21b3cf4af8f75aefe353f317af426b58408931d88d0e9b99f957b38d",
    );
    let subject_digest: Digest32 =
        successor_activation_subject_digest(&resolver, &subject).unwrap();
    let manifest_digest: Digest32 =
        successor_activation_manifest_digest(&resolver, &manifest).unwrap();
    assert_eq!(
        subject_digest,
        digest_hex("a7b0e8c259b833400f234ca940e7d9132b3d303ca5b0970185892c369b3e0111")
    );
    assert_eq!(
        manifest_digest,
        digest_hex("59eba06a21b3cf4af8f75aefe353f317af426b58408931d88d0e9b99f957b38d")
    );
    assert_eq!(
        decode_successor_activation_subject(&subject_bytes).unwrap(),
        subject
    );
    assert_eq!(
        decode_successor_activation_manifest(&manifest_bytes).unwrap(),
        manifest
    );

    let binding: ImportBinding = ImportBinding {
        context: ImportContext {
            chain_id: chain.clone(),
            protocol_version: protocol,
            epoch: Epoch::new(2),
        },
        domain,
        genesis_digest: d,
        validator_set_digest: d,
        cut_digest: d,
        package_digest: d,
        plan_digest: d,
        row_count: 3,
        blob_count: 2,
        generation_floor: ExecutionGeneration::new(7),
    };
    let progress: ImportProgress = ImportProgress {
        next_ordinal: 5,
        last_batch_digest: Some(e),
        accumulator: d,
    };
    let token: PortableSnapshotToken = PortableSnapshotToken::new(
        b"successor-vector-namespace".to_vec(),
        domain,
        WriterFenceGeneration::new(17).unwrap(),
        41,
    )
    .unwrap();
    let binding_bytes: Vec<u8> = runtime::inactive_import::encode_import_binding(&binding).unwrap();
    let progress_bytes: Vec<u8> =
        runtime::inactive_import::encode_import_progress(&progress).unwrap();
    let token_bytes: Vec<u8> =
        runtime::conditional_readiness::encode_readiness_creation_token(&token).unwrap();
    assert_vector(
        &resolver,
        HashPurpose::NodeEvent,
        &binding_bytes,
        456,
        "10d26677f6bb5df07aa0f3f69982b69abfba650c1e367ce6491e6a5cae4f0039",
    );
    assert_vector(
        &resolver,
        HashPurpose::NodeEvent,
        &progress_bytes,
        148,
        "14043d720478cfdafb546ce8f272387d0575516cda993f15fa52db7d849e9a15",
    );
    assert_vector(
        &resolver,
        HashPurpose::NodeEvent,
        &token_bytes,
        108,
        "36012406cf90974910c47aabedef363d2e46e08f4ad20c5702866b04a0c9fb44",
    );
    let mut genesis_floor_binding: ImportBinding = binding.clone();
    genesis_floor_binding.generation_floor = ExecutionGeneration::new(2);
    let genesis_bytes: Vec<u8> =
        runtime::inactive_import::encode_import_binding(&genesis_floor_binding).unwrap();
    assert_vector(
        &resolver,
        HashPurpose::NodeEvent,
        &genesis_bytes,
        456,
        "a2d6004806b8b94c89e4d99b13793425b2378793906d9c5d1b61c80ee4d3a9fc",
    );
    assert_ne!(genesis_bytes, binding_bytes);

    // The synthetic set digest is not an eligible set. This is the closed
    // anchor preimage vector; the production anchor/set test is separate.
    let successor_context: PublicationContext =
        PublicationContext::new(chain, protocol, Epoch::new(3)).unwrap();
    let mut anchor_frame: CanonicalStruct =
        CanonicalStruct::new(ORDERED_ECONOMICS_ANCHOR_FRAME_TYPE, 3);
    anchor_frame
        .field_bytes(1, b"se/ordered-economics/anchor/v3-successor".to_vec())
        .unwrap();
    anchor_frame
        .field_bytes(2, encode_publication_context(&successor_context).unwrap())
        .unwrap();
    anchor_frame
        .field_bytes(3, domain.as_bytes().to_vec())
        .unwrap();
    anchor_frame
        .field_bytes(4, encode_digest32(&d).unwrap())
        .unwrap();
    anchor_frame
        .field_bytes(5, encode_digest32(&e).unwrap())
        .unwrap();
    anchor_frame.field_u16(6, 1).unwrap();
    anchor_frame.field_u32(7, 1024).unwrap();
    anchor_frame.field_u64(8, 10000).unwrap();
    anchor_frame.field_u64(9, 4).unwrap();
    anchor_frame
        .field_bytes(10, encode_digest32(&subject_digest).unwrap())
        .unwrap();
    let anchor_bytes: Vec<u8> = anchor_frame.finish().unwrap();
    assert_vector(
        &resolver,
        HashPurpose::ProtocolConfig,
        &anchor_bytes,
        382,
        "00e8bdc94fb69d8bce8af76b45e333aaeb4ab36a928207761079841007ea7b28",
    );
    let record: SuccessorServingRecord = SuccessorServingRecord {
        subject: subject_digest,
        manifest: manifest_digest,
        binding,
        progress,
        activation_token: token,
        anchor: digest_hex("00e8bdc94fb69d8bce8af76b45e333aaeb4ab36a928207761079841007ea7b28"),
        validator: protocol_types::ValidatorId::new([0x44; 32]),
        public_key: [0x55; 32],
    };
    let record_bytes: Vec<u8> = encode_successor_serving_record(&record).unwrap();
    assert_vector(
        &resolver,
        HashPurpose::NodeEvent,
        &record_bytes,
        1002,
        "aa31fa7457bbb4719d945347f411931bc6fd544a4316b54143fc6582aac25585",
    );
    assert_eq!(
        decode_successor_serving_record(&record_bytes).unwrap(),
        record
    );
    let inactive_bytes: Vec<u8> =
        encode_successor_serving_slot(&SuccessorServingSlot::Inactive).unwrap();
    assert_vector(
        &resolver,
        HashPurpose::NodeEvent,
        &inactive_bytes,
        24,
        "aead91b30a178ecade9219318a660dd7e9bc3482ba44cd9faba8ffc8fbc8e8ed",
    );
    let slot: SuccessorServingSlot = SuccessorServingSlot::Serving(SuccessorServingObservation {
        record: record_bytes,
        binding: record.binding,
        progress: record.progress,
    });
    let slot_bytes: Vec<u8> = encode_successor_serving_slot(&slot).unwrap();
    assert_vector(
        &resolver,
        HashPurpose::NodeEvent,
        &slot_bytes,
        1026,
        "24d11cd840a5dca6021903f8c3543b9b29ec70bd3975bef68b83fa8ae2a435e1",
    );
    assert_eq!(decode_successor_serving_slot(&slot_bytes).unwrap(), slot);
}
