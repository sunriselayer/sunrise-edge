//! Constants independently reconstructed by scripts/paid-execution-vectors.mjs.
//! This test constructs the exact same DR-0124 fixture through the Rust
//! encoders and asserts the identical length/SHA256 pairs, policy digest,
//! signature and complete signed-frame invocation digest as that
//! independent JS reimplementation. A change here without a matching
//! change there (or vice versa) is a wire regression, not an update to hide.
use abi::AccessManifest;
use abi::package_types::{PackageOrigin, ScopedTypeTag};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::{CallIntent, InstanceTarget};
use execution::paid_execution::*;
use execution::publication::{PublicationContext, UnverifiedDependencyRef};
use fees::{Amount, GasSchedule};
use hashing::HashSuiteResolver;
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn vector(bytes: &[u8], length: usize, expected: &str) {
    assert_eq!(bytes.len(), length);
    assert_eq!(hex(&Sha256::digest(bytes)), expected);
}
fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}

#[test]
fn independently_reconstructed_paid_execution_wires_and_digests() {
    let chain: ChainId = ChainId::new("paid-vector").unwrap();
    let context: PublicationContext =
        PublicationContext::new(chain.clone(), ProtocolVersion::new(3), Epoch::new(0)).unwrap();
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain.clone(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let key: SigningKey = SigningKey::from([7; 32]);
    let sender: [u8; 32] = VerificationKey::from(&key).into();

    let source_code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        PackageOrigin::unverified(chain.clone(), sender, [10; 32]).unwrap(),
        1,
        context.clone(),
        digest(0x66),
    )
    .unwrap();
    let instance = |seed: u8| InstanceTarget {
        creator: sender,
        seed: [seed; 32],
        revision: 1,
        record_digest: digest(seed),
    };

    let consent: FeeSourceConsent = FeeSourceConsent {
        source: objects::ObjectRef {
            id: objects::ObjectId::new([0x30; 32]),
            version: 1,
            digest: digest(0x30),
        },
        access: ReservationAccessKind::Write,
        max_fee: Amount::new(1_000_000),
        refund_recipient: sender,
    };
    let consent_bytes: Vec<u8> = encode_fee_source_consent(&consent).unwrap();
    vector(
        &consent_bytes,
        216,
        "74cbb9deb656ff15ca9b01e3a8ffef5c22bc5ae428b5d02d854ec5cc41f6cc36",
    );

    let call_application: CallIntent = CallIntent {
        context: context.clone(),
        request_id: [1; 32],
        sender,
        nonce: 4,
        code: source_code.clone(),
        instance: instance(2),
        entrypoint: "run".into(),
        type_arguments: vec![],
        access: AccessManifest::default(),
        arguments: vec![],
        gas_limit: 100_000,
    };
    let application: PaidApplication = PaidApplication::Call(call_application.clone());
    let application_bytes: Vec<u8> = encode_paid_application(&application).unwrap();
    vector(
        &application_bytes,
        694,
        "2a748a7be95ae2fc7c785a0333458dc4612988b1f866de09cec774cf32cd852d",
    );

    let policy_origin: PackageOrigin =
        PackageOrigin::unverified(chain.clone(), sender, [20; 32]).unwrap();
    let policy_code: UnverifiedDependencyRef =
        UnverifiedDependencyRef::new(policy_origin.clone(), 1, context.clone(), digest(0x88))
            .unwrap();
    let fee_policy: PaidFeePolicy = PaidFeePolicy {
        context: context.clone(),
        // A raw pinned digest, not the actual base-policy digest: this
        // fixture tests codec/wire stability only, not policy consistency.
        base_policy_digest: digest(0x99),
        instance: instance(9),
        code: policy_code,
        reserve_entrypoint: "reserve".into(),
        reserve_all_entrypoint: "reserve_all".into(),
        settle_entrypoint: "settle".into(),
        type_arguments: vec![],
        asset_type: ScopedTypeTag::new(policy_origin.clone(), 2, vec![]).unwrap(),
        reservation_type: ScopedTypeTag::new(policy_origin, 4, vec![]).unwrap(),
        schema: 1,
        fee_recipient: sender,
        gas_schedule: GasSchedule {
            base_fee: 10,
            execution_price: 1,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        },
        conversion_divisor: 1,
        reserve_allowance: 30000,
        settle_allowance: 20000,
        calls: 8,
        handles: 16,
        creations: 4,
        events: 16,
        memory_bytes: 8 * 1024 * 1024,
        output_bytes: 1024 * 1024,
        publish_artifact_byte_price: 1,
        publish_closure_node_price: 1,
    };
    let policy_bytes: Vec<u8> = encode_paid_fee_policy(&fee_policy).unwrap();
    vector(
        &policy_bytes,
        1213,
        "5ada415ae7950357bbfaf603e7b45bf17179a5a8310bbb1867b19cd1db10d13d",
    );
    let policy_digest: Digest32 = paid_fee_policy_digest(&resolver, &fee_policy).unwrap();
    assert_eq!(
        hex(&policy_digest.bytes()),
        "2acddde1e103821c54753426941cd28f2900823f957a3277858d752a12bb822a"
    );

    let intent: PaidIntent = PaidIntent {
        context: context.clone(),
        request_id: [1; 32],
        sender,
        nonce: 4,
        fee_policy_digest: policy_digest,
        consent,
        application,
        gas_limit: 100_000,
        authorizations: vec![],
    };
    let intent_bytes: Vec<u8> = encode_paid_intent(&intent).unwrap();
    vector(
        &intent_bytes,
        1155,
        "d4a21596fbb60b11d587e8ba29e8aa3f459b4dfe51b3e79096f06e9339c7773f",
    );

    let signing_bytes: Vec<u8> = paid_intent_signing_frame(&context, &intent).unwrap();
    vector(
        &signing_bytes,
        1245,
        "3fe63168640395db37e4e3f227316a0a9d9d8e0bada7bc7bf507697a6518be32",
    );
    let signature: [u8; 64] = key.sign(&signing_bytes).into();
    assert_eq!(
        hex(&signature),
        "03de053c27d8284359f9dfa4a7377bdeef869b154aa2250d4ef6636e26213df184fb575ae1bb5f1dcc8c9091b05b8e1f125693fbb5c9083a05fb5d1487112708"
    );

    let signed: SignedPaidIntent = SignedPaidIntent { intent, signature };
    let signed_bytes: Vec<u8> = encode_signed_paid_intent(&signed).unwrap();
    vector(
        &signed_bytes,
        1241,
        "4d74857078fb74d34bfdf87c3856a099a17f8f2871f4b6ce2d24983258ddcff0",
    );

    let invocation_digest: Digest32 = paid_invocation_digest(&resolver, &signed).unwrap();
    assert_eq!(
        hex(&invocation_digest.bytes()),
        "922b2e2fc3a335bfd065c6026cbefcb1946879fb1a5752425c3d798a68e74f73"
    );
}
