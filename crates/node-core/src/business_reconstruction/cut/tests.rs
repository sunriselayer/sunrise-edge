//! Encoding fixtures are explicitly untrusted claims, not fabricated positive
//! consensus/business proofs. Genuine handler tests live with their real fixture.
use super::*;
use canonical_encoding::decode_canonical_frame;
use execution::publication::encode_publication_context;
use protocol_types::{
    ChainId, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
};

fn digest() -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32])
}
fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("cut-vector").unwrap(),
        ProtocolVersion::new(1),
        Epoch::new(2),
    )
    .unwrap()
}
fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        context().chain_id().clone(),
        ProtocolVersion::new(1),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn root(collection: BusinessCutCollection) -> BusinessCutCollectionRoot {
    BusinessCutCollectionRoot {
        collection,
        count: 0,
        root: digest(),
    }
}
fn claim() -> BusinessCutIdentity {
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x11; 32]).unwrap();
    BusinessCutIdentity {
        context: context(),
        domain,
        genesis_digest: digest(),
        validator_set_digest: digest(),
        ordered_history: OrderedHistoryIdentity {
            context: context(),
            domain,
            genesis_digest: digest(),
            anchor: digest(),
            through_height: 9,
            through_view: 11,
            through_digest: digest(),
        },
        drain_request_id: [0x80; 32],
        drain_block_height: 4,
        drain_candidate_digest: digest(),
        drain_union: consensus::DrainUnionIdentity {
            chain_id: context().chain_id().clone(),
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(2),
            domain,
            closure_request_id: [0x81; 32],
            closure_height: 1,
            signer_count: 3,
            member_count: 0,
            entries_digest: digest(),
        },
        generation_floor: ExecutionGeneration::new(7),
        business: [
            root(BusinessCutCollection::State),
            root(BusinessCutCollection::Receipts),
            root(BusinessCutCollection::ObjectHeads),
            root(BusinessCutCollection::ObjectVersions),
        ],
        artifacts: root(BusinessCutCollection::Artifacts),
    }
}
fn root_vector(collection: BusinessCutCollection) -> Vec<u8> {
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64B1, 1);
    expected.field_u16(1, collection as u16).unwrap();
    expected.field_u64(2, 0).unwrap();
    expected
        .field_bytes(3, encode_digest32(&digest()).unwrap())
        .unwrap();
    expected.finish().unwrap()
}
fn identity_vector(value: &BusinessCutIdentity) -> Vec<u8> {
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64B0, 1);
    expected
        .field_bytes(1, encode_publication_context(&context()).unwrap())
        .unwrap();
    expected.field_bytes(2, vec![0x11; 32]).unwrap();
    expected
        .field_bytes(3, encode_digest32(&digest()).unwrap())
        .unwrap();
    expected
        .field_bytes(4, encode_digest32(&digest()).unwrap())
        .unwrap();
    expected
        .field_bytes(
            5,
            crate::ordered_economics::encode_ordered_history_identity(&value.ordered_history)
                .unwrap(),
        )
        .unwrap();
    expected.field_bytes(6, vec![0x80; 32]).unwrap();
    expected.field_u64(7, 4).unwrap();
    expected
        .field_bytes(8, encode_digest32(&digest()).unwrap())
        .unwrap();
    expected
        .field_bytes(
            9,
            consensus::encode_drain_union_identity(&value.drain_union).unwrap(),
        )
        .unwrap();
    expected.field_u64(10, 7).unwrap();
    for (index, kind) in BUSINESS_CUT_STREAMS[..4].iter().enumerate() {
        expected
            .field_bytes(u16::try_from(11 + index).unwrap(), root_vector(*kind))
            .unwrap();
    }
    expected
        .field_bytes(15, root_vector(BusinessCutCollection::Artifacts))
        .unwrap();
    expected.finish().unwrap()
}
fn package() -> BusinessCutPackageIdentity {
    BusinessCutPackageIdentity {
        cut_digest: digest(),
        streams: BUSINESS_CUT_STREAMS.map(root),
        component_count: 0,
        accumulator: digest(),
    }
}
fn package_vector() -> Vec<u8> {
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64B2, 1);
    expected
        .field_bytes(1, encode_digest32(&digest()).unwrap())
        .unwrap();
    expected.field_u64(2, 0).unwrap();
    expected
        .field_bytes(3, encode_digest32(&digest()).unwrap())
        .unwrap();
    for (index, kind) in BUSINESS_CUT_STREAMS.iter().enumerate() {
        expected
            .field_bytes(u16::try_from(4 + index).unwrap(), root_vector(*kind))
            .unwrap();
    }
    expected.finish().unwrap()
}
fn state_metadata(present: bool) -> Vec<u8> {
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64B9, 1);
    expected.field_u16(1, 1).unwrap();
    expected.field_u16(2, u16::from(present)).unwrap();
    expected.finish().unwrap()
}
fn descriptor() -> BusinessCutComponentDescriptor {
    BusinessCutComponentDescriptor {
        collection: BusinessCutCollection::State,
        key: b"k".to_vec(),
        metadata: state_metadata(true),
        length: 3,
        digest: digest(),
    }
}
fn descriptor_vector() -> Vec<u8> {
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64B3, 1);
    expected.field_u16(1, 1).unwrap();
    expected.field_bytes(2, b"k".to_vec()).unwrap();
    expected.field_bytes(3, state_metadata(true)).unwrap();
    expected.field_u64(4, 3).unwrap();
    expected
        .field_bytes(5, encode_digest32(&digest()).unwrap())
        .unwrap();
    expected.finish().unwrap()
}
fn page() -> BusinessCutPage {
    BusinessCutPage {
        cut_digest: digest(),
        package_digest: digest(),
        collection: BusinessCutCollection::State,
        after_key: None,
        previous_accumulator: digest(),
        descriptors: vec![descriptor()],
        accumulator: digest(),
        terminal: true,
    }
}
fn page_vector() -> Vec<u8> {
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64B4, 1);
    expected
        .field_bytes(1, encode_digest32(&digest()).unwrap())
        .unwrap();
    expected
        .field_bytes(2, encode_digest32(&digest()).unwrap())
        .unwrap();
    expected.field_u16(3, 1).unwrap();
    expected.field_bytes(4, Vec::new()).unwrap();
    expected
        .field_bytes(5, encode_digest32(&digest()).unwrap())
        .unwrap();
    expected
        .field_bytes(6, encode_digest32(&digest()).unwrap())
        .unwrap();
    expected.field_u16(7, 1).unwrap();
    expected.field_u16(8, 1).unwrap();
    expected.field_bytes(9, descriptor_vector()).unwrap();
    expected.finish().unwrap()
}
fn chunk() -> BusinessCutChunk {
    BusinessCutChunk {
        cut_digest: digest(),
        package_digest: digest(),
        descriptor: descriptor(),
        offset: 0,
        total_length: 3,
        bytes: b"abc".to_vec(),
    }
}
fn chunk_vector() -> Vec<u8> {
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64B5, 1);
    expected
        .field_bytes(1, encode_digest32(&digest()).unwrap())
        .unwrap();
    expected
        .field_bytes(2, encode_digest32(&digest()).unwrap())
        .unwrap();
    expected.field_bytes(3, descriptor_vector()).unwrap();
    expected.field_u64(4, 0).unwrap();
    expected.field_u64(5, 3).unwrap();
    expected.field_bytes(6, b"abc".to_vec()).unwrap();
    expected.finish().unwrap()
}
fn closed<T>(
    bytes: &[u8],
    type_id: u16,
    fields: &[u16],
    decode: fn(&[u8]) -> Result<T, BusinessCutError>,
) {
    assert!(decode(&bytes[..bytes.len() - 1]).is_err());
    for offset in [4usize, 6] {
        let mut changed: Vec<u8> = bytes.to_vec();
        changed[offset] ^= 1;
        assert!(decode(&changed).is_err());
    }
    let original = decode_canonical_frame(bytes).unwrap();
    let mut extra: CanonicalStruct = CanonicalStruct::new(type_id, 1);
    for id in fields {
        extra
            .field_bytes(*id, original.required_field(*id).unwrap().to_vec())
            .unwrap();
    }
    extra.field_u16(99, 1).unwrap();
    assert!(decode(&extra.finish().unwrap()).is_err());
}

fn pinned_digest(hex: &str) -> Digest32 {
    assert_eq!(hex.len(), 64);
    let mut bytes: [u8; 32] = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    Digest32::new(HashAlgorithmId::Sha2_256, bytes)
}

#[test]
fn business_cut_frames_and_segmented_bodies_match_independent_node_pins() {
    // These constants are independently reconstructed from primitive canonical
    // framing by scripts/business-cut-vectors.mjs, not generated by this codec.
    // The frames below are deliberately untrusted schema claims.
    let resolver: HashSuiteResolver = resolver();
    let vectors: [(Vec<u8>, &str); 5] = [
        (
            identity_vector(&claim()),
            "d98a4e4f181632fa7de62b12e69c20e3b2eeb3fa01bc151ed6c92dfac15f194f",
        ),
        (
            package_vector(),
            "4e63e573084c1f570e75746cf8c119978c0a7c595a4d433c62b0b488c6f359f1",
        ),
        (
            descriptor_vector(),
            "a7e5613295ddbeda9d88b6993e63682162030cf070fe6c3a94722f7ad79ba197",
        ),
        (
            page_vector(),
            "1ffcc4060c2ff8abc5d00890f473b4b41bd554ac6645f1dfd085f34fe97e4a77",
        ),
        (
            chunk_vector(),
            "ab2f5d750793a3f37cd4636b07a9d966dd2cae141bd2d714e66078394feca46d",
        ),
    ];
    for (bytes, expected) in vectors {
        assert_eq!(
            hash(&resolver, &context(), &bytes).unwrap(),
            pinned_digest(expected)
        );
    }
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x11; 32]).unwrap();
    assert_eq!(
        transfer::seed(&resolver, &context(), digest(), domain, 1, None).unwrap(),
        pinned_digest("1049f70d333c8c572d8eb676100dd0f771931489ac892f1b3195b3695a2ca683")
    );
    assert_eq!(
        transfer::seed(&resolver, &context(), digest(), domain, 8, Some(digest())).unwrap(),
        pinned_digest("e7229e03a0c7e55c282aa2d0d62126a930b29f4607979915f18d5ad54721827d")
    );
    assert_eq!(
        transfer::fold(&resolver, &context(), digest(), &descriptor()).unwrap(),
        pinned_digest("b5262c3e5f8050bf0b317e814a3885104b5066b70d8e55e5e5c42b057b472d22")
    );
    for (body, expected) in [
        (
            Vec::new(),
            "e449fe52d46ba214503082ac5c92bb9d0c41b7c532172f7397a07a4080118bbb",
        ),
        (
            b"abc".to_vec(),
            "32706e7347881d30903f439367789fe8aeec251c232585231911faa0fa8a5916",
        ),
        (
            {
                let mut bytes: Vec<u8> = vec![0x31; 1_048_576];
                bytes.extend_from_slice(b"abc");
                bytes
            },
            "459a27dadfc8151a27c4609aff40885c0d9024fa2ec1875339f078b3a586eb47",
        ),
    ] {
        assert_eq!(
            business_cut_component_digest(&resolver, &context(), &body).unwrap(),
            pinned_digest(expected)
        );
    }
}

#[test]
fn business_cut_new_public_frames_have_independent_field_vectors_and_closed_decoders() {
    let identity: BusinessCutIdentity = claim();
    let identity_bytes: Vec<u8> = identity_vector(&identity);
    assert_eq!(
        encode_business_cut_identity(&identity).unwrap(),
        identity_bytes
    );
    assert_eq!(
        decode_business_cut_identity(&identity_bytes).unwrap(),
        identity
    );
    closed(
        &identity_bytes,
        0x64B0,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        decode_business_cut_identity,
    );
    assert_eq!(
        codec::encode_root(&root(BusinessCutCollection::State)).unwrap(),
        root_vector(BusinessCutCollection::State)
    );
    let bytes: Vec<u8> = package_vector();
    assert_eq!(encode_business_cut_package(&package()).unwrap(), bytes);
    closed(
        &bytes,
        0x64B2,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        decode_business_cut_package,
    );
    assert_eq!(
        encode_business_cut_descriptor(&descriptor()).unwrap(),
        descriptor_vector()
    );
    closed(
        &descriptor_vector(),
        0x64B3,
        &[1, 2, 3, 4, 5],
        decode_business_cut_descriptor,
    );
    assert_eq!(encode_business_cut_page(&page()).unwrap(), page_vector());
    closed(
        &page_vector(),
        0x64B4,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9],
        decode_business_cut_page,
    );
    assert_eq!(encode_business_cut_chunk(&chunk()).unwrap(), chunk_vector());
    closed(
        &chunk_vector(),
        0x64B5,
        &[1, 2, 3, 4, 5, 6],
        decode_business_cut_chunk,
    );
    closed(&state_metadata(true), 0x64B9, &[1, 2], codec::metadata_tag);
}

#[test]
fn business_cut_hash_frames_have_independent_seed_fold_and_body_vectors() {
    let resolver: HashSuiteResolver = resolver();
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x11; 32]).unwrap();
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64B6, 1);
    expected
        .field_bytes(1, encode_publication_context(&context()).unwrap())
        .unwrap();
    expected
        .field_bytes(2, encode_digest32(&digest()).unwrap())
        .unwrap();
    expected.field_bytes(3, vec![0x11; 32]).unwrap();
    expected.field_u16(4, 1).unwrap();
    expected.field_bytes(5, Vec::new()).unwrap();
    let seed: Digest32 = hash(&resolver, &context(), &expected.finish().unwrap()).unwrap();
    assert_eq!(
        transfer::seed(&resolver, &context(), digest(), domain, 1, None).unwrap(),
        seed
    );
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64B7, 1);
    expected
        .field_bytes(1, encode_digest32(&seed).unwrap())
        .unwrap();
    expected.field_bytes(2, descriptor_vector()).unwrap();
    assert_eq!(
        transfer::fold(&resolver, &context(), seed, &descriptor()).unwrap(),
        hash(&resolver, &context(), &expected.finish().unwrap()).unwrap()
    );
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64BC, 1);
    expected.field_u64(1, 3).unwrap();
    let seed: Digest32 = hash(&resolver, &context(), &expected.finish().unwrap()).unwrap();
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64BB, 1);
    expected
        .field_bytes(1, encode_digest32(&seed).unwrap())
        .unwrap();
    expected.field_u64(2, 0).unwrap();
    expected.field_bytes(3, b"abc".to_vec()).unwrap();
    assert_eq!(
        business_cut_component_digest(&resolver, &context(), b"abc").unwrap(),
        hash(&resolver, &context(), &expected.finish().unwrap()).unwrap()
    );
    let full: Vec<u8> = vec![9; runtime::MAX_STATE_VALUE_BYTES];
    assert!(
        business_cut_component_digest(&resolver, &context(), &full).is_ok(),
        "legal maximum body is not wrapped in an oversized superframe"
    );
}

#[test]
fn business_cut_transfer_refuses_unknown_metadata_limits_ranges_and_missing_empty_terminal() {
    let mut bad: BusinessCutComponentDescriptor = descriptor();
    bad.length = runtime::MAX_STATE_VALUE_BYTES as u64 + 1;
    assert!(encode_business_cut_descriptor(&bad).is_err());
    bad = descriptor();
    bad.metadata = state_metadata(false);
    assert!(encode_business_cut_descriptor(&bad).is_err());
    let mut unknown: CanonicalStruct = CanonicalStruct::new(0x64B9, 1);
    unknown.field_u16(1, 99).unwrap();
    bad = descriptor();
    bad.metadata = unknown.finish().unwrap();
    assert!(encode_business_cut_descriptor(&bad).is_err());
    let mut artifact_metadata: CanonicalStruct = CanonicalStruct::new(0x64B9, 1);
    artifact_metadata.field_u16(1, 5).unwrap();
    artifact_metadata.field_u16(2, 1).unwrap();
    artifact_metadata
        .field_bytes(3, encode_digest32(&digest()).unwrap())
        .unwrap();
    let mut artifact_key: Vec<u8> = 1u16.to_be_bytes().to_vec();
    artifact_key.extend(encode_digest32(&digest()).unwrap());
    let mut artifact: BusinessCutComponentDescriptor = BusinessCutComponentDescriptor {
        collection: BusinessCutCollection::Artifacts,
        key: artifact_key,
        metadata: artifact_metadata.finish().unwrap(),
        length: 3,
        digest: digest(),
    };
    assert!(encode_business_cut_descriptor(&artifact).is_ok());
    artifact.key[1] = 2;
    assert!(encode_business_cut_descriptor(&artifact).is_err());
    artifact.key[1] = 1;
    *artifact.key.last_mut().unwrap() ^= 1;
    assert!(encode_business_cut_descriptor(&artifact).is_err());
    let mut oversized: BusinessCutPage = page();
    oversized.descriptors = vec![descriptor(); 129];
    assert!(encode_business_cut_page(&oversized).is_err());
    let mut bad_chunk: BusinessCutChunk = chunk();
    bad_chunk.offset = u64::MAX;
    assert!(encode_business_cut_chunk(&bad_chunk).is_err());
    bad_chunk = chunk();
    bad_chunk.bytes = vec![1; MAX_BUSINESS_CUT_CHUNK_BYTES + 1];
    assert!(encode_business_cut_chunk(&bad_chunk).is_err());
    let resolver: HashSuiteResolver = resolver();
    let mut identity: BusinessCutIdentity = claim();
    let streams: [BusinessCutCollectionRoot; 7] =
        BUSINESS_CUT_STREAMS.map(|collection| BusinessCutCollectionRoot {
            collection,
            count: 0,
            root: transfer::seed(
                &resolver,
                &identity.context,
                identity.genesis_digest,
                identity.domain,
                collection as u16,
                None,
            )
            .unwrap(),
        });
    identity.business = [
        streams[0].clone(),
        streams[1].clone(),
        streams[2].clone(),
        streams[3].clone(),
    ];
    identity.artifacts = streams[5].clone();
    let package: BusinessCutPackageIdentity = BusinessCutPackageIdentity {
        cut_digest: business_cut_identity_digest(&resolver, &identity).unwrap(),
        streams,
        component_count: 0,
        accumulator: digest(),
    };
    for collection in BUSINESS_CUT_STREAMS {
        let mut verifier: BusinessCutPageVerifier =
            BusinessCutPageVerifier::new(&resolver, &identity, &package, collection).unwrap();
        assert!(!verifier.is_terminal());
        let seed: Digest32 = package.streams[usize::from(collection as u16) - 1].root;
        let terminal: BusinessCutPage = BusinessCutPage {
            cut_digest: package.cut_digest,
            package_digest: business_cut_package_digest(&resolver, &identity, &package).unwrap(),
            collection,
            after_key: None,
            previous_accumulator: seed,
            descriptors: Vec::new(),
            accumulator: seed,
            terminal: true,
        };
        let mut changed: BusinessCutPage = terminal.clone();
        changed.collection = if collection == BusinessCutCollection::Proofs {
            BusinessCutCollection::State
        } else {
            BusinessCutCollection::Proofs
        };
        assert!(verifier.push_page(&resolver, &changed).is_err());
        assert!(!verifier.is_terminal());
        verifier.push_page(&resolver, &terminal).unwrap();
        assert!(verifier.push_page(&resolver, &terminal).is_err());
        verifier.finish().unwrap();
        assert!(
            BusinessCutPageVerifier::new(&resolver, &identity, &package, collection)
                .unwrap()
                .finish()
                .is_err()
        );
    }
}
