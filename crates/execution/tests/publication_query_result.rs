#![forbid(unsafe_code)]

//! Independent outer-frame controls for untrusted query data. These fixtures
//! use only execution's payload APIs and confer no durable publication authority.

use abi::AccessManifest;
use abi::package_types::PackageOrigin;
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::{CallIntent, InstanceTarget};
use execution::paid_execution::{
    FeeSourceConsent, MAX_SIGNED_PAID_INTENT_BYTES, PaidApplication, PaidExecutionError,
    PaidIntent, ReservationAccessKind, SignedPaidIntent, encode_signed_paid_intent,
    paid_intent_signing_frame,
};
use execution::publication::{
    ArtifactParts, CodeArtifact, MAX_PUBLICATION_QUERY_RESULT_BYTES,
    PUBLICATION_QUERY_RESULT_FRAME_TYPE, PublicationContext, PublicationError,
    PublicationQueryResult, PublicationQueryResultError, PublicationRequest, PublicationSubmission,
    UnverifiedDependencyRef, artifact_commitment, decode_publication_query_result,
    encode_publication_query_result, encode_publication_submission,
    publication_submission_signing_frame,
};
use fees::Amount;
use hashing::HashSuiteResolver;
use objects::{ObjectId, ObjectRef};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
};
use std::error::Error;

fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("query-codec-contract").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(0),
    )
    .unwrap()
}

fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}

fn sender() -> [u8; 32] {
    VerificationKey::from(&SigningKey::from([71; 32])).into()
}

fn artifact() -> CodeArtifact {
    let context: PublicationContext = context();
    let origin: PackageOrigin =
        PackageOrigin::unverified(context.chain_id().clone(), sender(), [72; 32]).unwrap();
    CodeArtifact::new(ArtifactParts {
        context,
        origin,
        revision: 1,
        wasm_profile: 1,
        semantics: digest(0x66),
        wasm: wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"run\")))")
            .unwrap(),
        unverified_abi: b"opaque declaration".to_vec(),
        exports: vec!["run".to_owned()],
        unverified_dependencies: Vec::new(),
    })
    .unwrap()
}

fn legacy() -> PublicationSubmission {
    let context: PublicationContext = context();
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        context.chain_id().clone(),
        context.protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let artifact: CodeArtifact = artifact();
    let commitment: Digest32 = artifact_commitment(&resolver, &context, &artifact).unwrap();
    let frame: Vec<u8> =
        publication_submission_signing_frame(&resolver, &context, &artifact, 3, [73; 32]).unwrap();
    let signature: [u8; 64] = SigningKey::from([71; 32]).sign(&frame).into();
    PublicationSubmission::new(
        [73; 32],
        PublicationRequest::new(artifact, 3, commitment, signature),
    )
    .unwrap()
}

fn paid(application: PaidApplication) -> SignedPaidIntent {
    let intent: PaidIntent = PaidIntent {
        context: context(),
        request_id: [74; 32],
        sender: sender(),
        nonce: 4,
        fee_policy_digest: digest(0x99),
        consent: FeeSourceConsent {
            source: ObjectRef {
                id: ObjectId::new([0x30; 32]),
                version: 1,
                digest: digest(0x30),
            },
            access: ReservationAccessKind::Consume,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application,
        gas_limit: 100_000,
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = paid_intent_signing_frame(&intent.context, &intent).unwrap();
    let signature: [u8; 64] = SigningKey::from([71; 32]).sign(&frame).into();
    SignedPaidIntent { intent, signature }
}

fn call() -> CallIntent {
    CallIntent {
        context: context(),
        request_id: [74; 32],
        sender: sender(),
        nonce: 4,
        code: UnverifiedDependencyRef::new(artifact().origin().clone(), 1, context(), digest(0x66))
            .unwrap(),
        instance: InstanceTarget {
            creator: sender(),
            seed: [75; 32],
            revision: 1,
            record_digest: digest(0x77),
        },
        entrypoint: "run".to_owned(),
        type_arguments: Vec::new(),
        access: AccessManifest {
            entries: Vec::new(),
        },
        arguments: Vec::new(),
        gas_limit: 100_000,
    }
}

// The query codec is never used to build expected outer bytes or malformed
// inputs. Literal schema fields below are framed by canonical-encoding alone.
fn frame(type_id: u16, version: u16, fields: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(type_id, version);
    for (field_id, payload) in fields {
        frame.field_bytes(*field_id, payload.clone()).unwrap();
    }
    frame.finish().unwrap()
}

fn expect_publication_decoding(bytes: &[u8], expected: CanonicalDecodingError) {
    let error: PublicationQueryResultError = decode_publication_query_result(bytes).unwrap_err();
    match error {
        PublicationQueryResultError::Publication(PublicationError::Decoding(actual)) => {
            assert_eq!(actual, expected);
        }
        other => panic!("expected publication decoding {expected:?}, got {other:?}"),
    }
}

fn expect_paid_decoding(bytes: &[u8], expected: CanonicalDecodingError) {
    let error: PublicationQueryResultError = decode_publication_query_result(bytes).unwrap_err();
    match error {
        PublicationQueryResultError::Paid(PaidExecutionError::Decoding(actual)) => {
            assert_eq!(actual, expected);
        }
        other => panic!("expected paid decoding {expected:?}, got {other:?}"),
    }
}

#[test]
fn legacy_and_paid_preserve_independently_framed_complete_payloads() {
    assert_eq!(PUBLICATION_QUERY_RESULT_FRAME_TYPE, 0x6418);
    assert_eq!(
        MAX_PUBLICATION_QUERY_RESULT_BYTES,
        MAX_SIGNED_PAID_INTENT_BYTES + 256
    );
    let legacy: PublicationSubmission = legacy();
    let paid: SignedPaidIntent = paid(PaidApplication::Publish(artifact()));
    let cases: [(PublicationQueryResult, u16, u16, u16, Vec<u8>); 2] = [
        (
            PublicationQueryResult::Legacy(legacy.clone()),
            1,
            2,
            0x6308,
            encode_publication_submission(&legacy).unwrap(),
        ),
        (
            PublicationQueryResult::Paid(paid.clone()),
            2,
            3,
            0x6413,
            encode_signed_paid_intent(&paid).unwrap(),
        ),
    ];
    for (result, provenance, payload_field, nested_type, payload) in cases {
        let expected: Vec<u8> = frame(
            0x6418,
            1,
            &[
                (1, provenance.to_le_bytes().to_vec()),
                (payload_field, payload.clone()),
            ],
        );
        assert_eq!(encode_publication_query_result(&result).unwrap(), expected);
        assert_eq!(decode_publication_query_result(&expected).unwrap(), result);
        let outer: CanonicalFrame<'_> = decode_canonical_frame(&expected).unwrap();
        assert_eq!(outer.field_count(), 2);
        assert_eq!(
            outer.required_field(payload_field).unwrap(),
            payload.as_slice()
        );
        let nested: CanonicalFrame<'_> = decode_canonical_frame(&payload).unwrap();
        assert_eq!(nested.type_id(), nested_type);
        assert_eq!(nested.version(), 1);
    }
}

#[test]
fn a_non_publish_paid_application_is_structural_data_not_publication_authority() {
    let signed: SignedPaidIntent = paid(PaidApplication::Call(call()));
    let bytes: Vec<u8> = frame(
        0x6418,
        1,
        &[
            (1, 2u16.to_le_bytes().to_vec()),
            (3, encode_signed_paid_intent(&signed).unwrap()),
        ],
    );
    let decoded: PublicationQueryResult = decode_publication_query_result(&bytes).unwrap();
    assert_eq!(decoded, PublicationQueryResult::Paid(signed));
    assert!(matches!(
        &decoded,
        PublicationQueryResult::Paid(SignedPaidIntent {
            intent: PaidIntent {
                application: PaidApplication::Call(_),
                ..
            },
            ..
        })
    ));
    assert_eq!(encode_publication_query_result(&decoded).unwrap(), bytes);
    // The actual SDK refusal remains in clients/rust/tests/publication.rs.
}

#[test]
fn type_version_and_discriminant_fail_in_the_existing_order() {
    let payload: Vec<u8> = encode_publication_submission(&legacy()).unwrap();
    let fields: [(u16, Vec<u8>); 2] = [(1, 1u16.to_le_bytes().to_vec()), (2, payload)];
    // Both type and version are wrong: type must win.
    expect_publication_decoding(
        &frame(0x6417, 2, &fields),
        CanonicalDecodingError::UnexpectedTypeId {
            expected: 0x6418,
            actual: 0x6417,
        },
    );
    expect_publication_decoding(
        &frame(0x6418, 2, &fields),
        CanonicalDecodingError::UnexpectedVersion {
            expected: 1,
            actual: 2,
        },
    );
    expect_publication_decoding(
        &frame(0x6418, 1, &[(2, b"oops".to_vec())]),
        CanonicalDecodingError::MissingField(1),
    );
    expect_publication_decoding(
        &frame(0x6418, 1, &[(1, vec![1, 0, 0])]),
        CanonicalDecodingError::InvalidFieldLength {
            field_id: 1,
            expected: 2,
            actual: 3,
        },
    );
    let unknowns: [u16; 3] = [0, 3, u16::MAX];
    for provenance in unknowns {
        let bytes: Vec<u8> = frame(0x6418, 1, &[(1, provenance.to_le_bytes().to_vec())]);
        assert!(matches!(
            decode_publication_query_result(&bytes),
            Err(PublicationQueryResultError::CorruptRecord)
        ));
    }
}

#[test]
fn branch_fields_precede_missing_and_malformed_nested_payloads() {
    let branches: [(u16, u16, u16); 2] = [(1, 2, 3), (2, 3, 2)];
    for (provenance, payload_field, foreign_field) in branches {
        let tag: Vec<u8> = provenance.to_le_bytes().to_vec();
        // Both branch fields, and both payloads malformed: foreign field wins.
        let both: Vec<u8> = frame(
            0x6418,
            1,
            &[
                (1, tag.clone()),
                (2, b"oops".to_vec()),
                (3, b"oops".to_vec()),
            ],
        );
        expect_publication_decoding(
            &both,
            CanonicalDecodingError::UnexpectedField(foreign_field),
        );
        // The selected payload is absent as well as a foreign field present.
        let foreign: Vec<u8> = frame(0x6418, 1, &[(1, tag.clone()), (foreign_field, Vec::new())]);
        expect_publication_decoding(
            &foreign,
            CanonicalDecodingError::UnexpectedField(foreign_field),
        );
        let unknown: Vec<u8> = frame(
            0x6418,
            1,
            &[(1, tag), (payload_field, b"oops".to_vec()), (4, Vec::new())],
        );
        expect_publication_decoding(&unknown, CanonicalDecodingError::UnexpectedField(4));
    }
}

#[test]
fn required_outer_payload_and_nested_errors_keep_their_distinct_owners() {
    expect_publication_decoding(
        &frame(0x6418, 1, &[(1, 1u16.to_le_bytes().to_vec())]),
        CanonicalDecodingError::MissingField(2),
    );
    expect_publication_decoding(
        &frame(0x6418, 1, &[(1, 2u16.to_le_bytes().to_vec())]),
        CanonicalDecodingError::MissingField(3),
    );
    expect_publication_decoding(
        &frame(
            0x6418,
            1,
            &[(1, 1u16.to_le_bytes().to_vec()), (2, b"oops".to_vec())],
        ),
        CanonicalDecodingError::InvalidMagic,
    );
    expect_paid_decoding(
        &frame(
            0x6418,
            1,
            &[(1, 2u16.to_le_bytes().to_vec()), (3, b"oops".to_vec())],
        ),
        CanonicalDecodingError::InvalidMagic,
    );
    expect_publication_decoding(
        &frame(
            0x6418,
            1,
            &[(1, 1u16.to_le_bytes().to_vec()), (2, frame(0x6308, 1, &[]))],
        ),
        CanonicalDecodingError::MissingField(1),
    );
    expect_paid_decoding(
        &frame(
            0x6418,
            1,
            &[(1, 2u16.to_le_bytes().to_vec()), (3, frame(0x6413, 1, &[]))],
        ),
        CanonicalDecodingError::MissingField(1),
    );
    expect_publication_decoding(
        &frame(
            0x6418,
            1,
            &[
                (1, 1u16.to_le_bytes().to_vec()),
                (
                    2,
                    encode_signed_paid_intent(&paid(PaidApplication::Publish(artifact()))).unwrap(),
                ),
            ],
        ),
        CanonicalDecodingError::UnexpectedTypeId {
            expected: 0x6308,
            actual: 0x6413,
        },
    );
    expect_paid_decoding(
        &frame(
            0x6418,
            1,
            &[
                (1, 2u16.to_le_bytes().to_vec()),
                (3, encode_publication_submission(&legacy()).unwrap()),
            ],
        ),
        CanonicalDecodingError::UnexpectedTypeId {
            expected: 0x6413,
            actual: 0x6308,
        },
    );
}

#[test]
fn outer_truncation_and_trailing_bytes_precede_malformed_nested_decoding() {
    let bytes: Vec<u8> = frame(
        0x6418,
        1,
        &[(1, 1u16.to_le_bytes().to_vec()), (2, b"oops".to_vec())],
    );
    expect_publication_decoding(
        &bytes[..bytes.len() - 1],
        CanonicalDecodingError::Truncated {
            offset: 24,
            needed: 4,
            remaining: 3,
        },
    );
    let mut trailing: Vec<u8> = bytes;
    trailing.push(0);
    expect_publication_decoding(&trailing, CanonicalDecodingError::TrailingBytes(1));
}

#[test]
fn oversize_and_unknown_provenance_precede_framing_branch_and_nested_failures() {
    let oversized: Vec<u8> = vec![0xff; MAX_PUBLICATION_QUERY_RESULT_BYTES + 1];
    assert!(matches!(
        decode_publication_query_result(&oversized),
        Err(PublicationQueryResultError::Limit)
    ));
    let at_bound: Vec<u8> = vec![0xff; MAX_PUBLICATION_QUERY_RESULT_BYTES];
    expect_publication_decoding(&at_bound, CanonicalDecodingError::InvalidMagic);
    let unknown: Vec<u8> = frame(
        0x6418,
        1,
        &[
            (1, 9u16.to_le_bytes().to_vec()),
            (2, b"oops".to_vec()),
            (3, b"oops".to_vec()),
            (4, Vec::new()),
        ],
    );
    assert!(matches!(
        decode_publication_query_result(&unknown),
        Err(PublicationQueryResultError::CorruptRecord)
    ));
}

#[test]
fn encoding_retains_the_nested_paid_structural_error_category() {
    let mut signed: SignedPaidIntent = paid(PaidApplication::Publish(artifact()));
    signed.intent.gas_limit = 0;
    let error: PublicationQueryResultError =
        encode_publication_query_result(&PublicationQueryResult::Paid(signed)).unwrap_err();
    assert!(matches!(
        &error,
        PublicationQueryResultError::Paid(PaidExecutionError::Invalid("gas_limit must be > 0"))
    ));
    assert_eq!(
        error.to_string(),
        "invalid paid execution wire: gas_limit must be > 0"
    );
    assert!(error.source().is_none());
}

#[test]
fn conversions_display_and_all_four_error_sources_stay_flat() {
    let encoding: PublicationQueryResultError = CanonicalEncodingError::DuplicateField(7).into();
    assert!(matches!(
        &encoding,
        PublicationQueryResultError::Publication(PublicationError::Encoding(
            CanonicalEncodingError::DuplicateField(7)
        ))
    ));
    let decoding: PublicationQueryResultError = CanonicalDecodingError::MissingField(1).into();
    assert!(matches!(
        &decoding,
        PublicationQueryResultError::Publication(PublicationError::Decoding(
            CanonicalDecodingError::MissingField(1)
        ))
    ));
    let inner: PublicationError = PublicationError::Decoding(CanonicalDecodingError::InvalidMagic);
    assert!(inner.source().is_some());
    let publication: PublicationQueryResultError = inner.into();
    let paid: PublicationQueryResultError = PaidExecutionError::Invalid("control").into();
    assert!(matches!(
        &paid,
        PublicationQueryResultError::Paid(PaidExecutionError::Invalid("control"))
    ));
    let controls: Vec<(PublicationQueryResultError, &str)> = vec![
        (encoding, "duplicate canonical field id: 7"),
        (decoding, "missing canonical field id: 1"),
        (publication, "invalid canonical protocol magic"),
        (paid, "invalid paid execution wire: control"),
        (
            PublicationQueryResultError::Limit,
            "publication resource bound exceeded",
        ),
        (
            PublicationQueryResultError::CorruptRecord,
            "invalid canonical durable publication record",
        ),
    ];
    for (error, expected) in controls {
        assert_eq!(error.to_string(), expected);
        assert!(
            error.source().is_none(),
            "unexpected deeper source for {error}"
        );
    }
}
