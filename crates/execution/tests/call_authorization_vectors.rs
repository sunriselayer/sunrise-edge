//! DR-0123 constants reconstructed independently by the JavaScript wire script.
use abi::call_values::{CallValue, ValueLayout, encode_call_value};
use abi::package_types::PackageOrigin;
use abi::{AccessEntry, AccessManifest};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::call_authorization::*;
use execution::local_execution::*;
use execution::publication::{PublicationContext, UnverifiedDependencyRef};
use hashing::HashSuiteResolver;
use objects::{AccessMode, ObjectId, ObjectRef};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn vector(bytes: &[u8], length: usize, sha256: &str) {
    assert_eq!(bytes.len(), length);
    assert_eq!(hex(&Sha256::digest(bytes)), sha256);
}

#[test]
fn general_call_wires_match_independent_reconstruction() {
    let chain: ChainId = ChainId::new("local-vector").unwrap();
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
    let code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        PackageOrigin::unverified(chain, sender, [10; 32]).unwrap(),
        1,
        context.clone(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32]),
    )
    .unwrap();
    let record: InstanceRecord = InstanceRecord {
        context: context.clone(),
        creator: sender,
        seed: [2; 32],
        code: code.clone(),
        revision: 1,
        initializer: "run".into(),
    };
    let caller: ExecutionTarget = ExecutionTarget {
        instance: instance_target(&resolver, &record).unwrap(),
        code: code.clone(),
    };
    let callee_record: InstanceRecord = InstanceRecord {
        seed: [9; 32],
        ..record.clone()
    };
    let callee: ExecutionTarget = ExecutionTarget {
        instance: instance_target(&resolver, &callee_record).unwrap(),
        code: code.clone(),
    };
    let object: AuthorizedObject = AuthorizedObject {
        object_id: ObjectId::new([0x44; 32]),
        mode: AccessMode::Read,
    };
    let authorization: CallAuthorization = CallAuthorization {
        caller: caller.clone(),
        callee: callee.clone(),
        entrypoint: "run".into(),
        type_arguments: vec![],
        objects: vec![object.clone()],
    };
    for (target, expected) in [
        (
            &caller,
            "9c4c450067f8f8bf1840fcd87120e8c5941b38e41823ba0fb408ed7868e591f4",
        ),
        (
            &callee,
            "167ad6be3ca6c37251b92eab6bc41f1dabb323bb780248d5533a46bffcd87bfb",
        ),
    ] {
        let bytes: Vec<u8> = encode_execution_target(target).unwrap();
        vector(&bytes, 446, expected);
        assert_eq!(decode_execution_target(&bytes).unwrap(), *target);
    }
    let bytes: Vec<u8> = encode_authorized_object(&object).unwrap();
    vector(
        &bytes,
        71,
        "c2611cc3b4bb1c5a0750d153bbfe046ba2c237742821e8ce4d301851f1185e41",
    );
    assert_eq!(decode_authorized_object(&bytes).unwrap(), object);
    let bytes: Vec<u8> = encode_call_authorization(&authorization).unwrap();
    vector(
        &bytes,
        1050,
        "deb2369bfc95285f6dc1ffe192c692f6020ccc6e342fd0d3a5698e84bac537fe",
    );
    assert_eq!(decode_call_authorization(&bytes).unwrap(), authorization);
    let table: Vec<u8> = encode_call_authorizations(std::slice::from_ref(&authorization)).unwrap();
    vector(
        &table,
        1076,
        "423d1d76bcaf26f048fd1b9baa54a33bd13bf3c293bedd1268df4d0998c36a39",
    );
    assert_eq!(
        decode_call_authorizations(&table).unwrap(),
        vec![authorization.clone()]
    );
    vector(
        &encode_general_execution_semantics().unwrap(),
        192,
        "7f82b8a972a9ff4e23d5e731fc1c5b9776c77ad7a922ba6f4f7cde1b297502d4",
    );
    let policy: LocalExecutionPolicy = LocalExecutionPolicy::general(context.clone());
    vector(
        &policy.encode().unwrap(),
        492,
        "dba4c439e2cdcbcabd78e211680c9973b458420e69b912c2244ed2c45fc2da5f",
    );
    assert_eq!(
        LocalExecutionPolicy::decode(&policy.encode().unwrap()).unwrap(),
        policy
    );
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&resolver).unwrap(),
        authorizations: vec![authorization],
        call: CallIntent {
            context: context.clone(),
            request_id: [3; 32],
            sender,
            nonce: 4,
            code,
            instance: caller.instance,
            entrypoint: "run".into(),
            type_arguments: vec![],
            access: AccessManifest {
                entries: vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: object.object_id,
                        version: 1,
                        digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x55; 32]),
                    },
                    mode: AccessMode::Read,
                }],
            },
            arguments: encode_call_value(&ValueLayout::Tuple(vec![]), &CallValue::Tuple(vec![]))
                .unwrap(),
            gas_limit: 100_000,
        },
    };
    let bytes: Vec<u8> = encode_local_execution_intent(&intent).unwrap();
    vector(
        &bytes,
        2068,
        "febb4c8f79868db1cd7d52fe2f7f3bb63b131b45f8057aef9fc21a7e210f0ea5",
    );
    assert_eq!(decode_local_execution_intent(&bytes).unwrap(), intent);
    let signing: Vec<u8> = local_execution_signing_frame(&context, &intent).unwrap();
    vector(
        &signing,
        2160,
        "3c9bb339ab69f8297c386e7804e3290186f7ebc84813582bc6903ba19a8816ad",
    );
    let signed: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
        intent,
        signature: key.sign(&signing).into(),
    };
    assert_eq!(
        hex(&signed.signature),
        "538d0165cd3bea6ec97329f1eeff9196872f31a7875167ef51621d2a4c1b66aaade8f10e1a9807d1c495992673076cd2ef0972a8a2ea955cc9fea99dedd1020e"
    );
    let bytes: Vec<u8> = encode_signed_local_execution(&signed).unwrap();
    vector(
        &bytes,
        2154,
        "2d0396172ebffb16c683e26e0c4c3c8dc643714cb53281dbddfebe07bfc2d86a",
    );
    authenticate_local_execution(&resolver, &policy, &bytes).unwrap();
    assert!(
        authenticate_local_execution(&resolver, &LocalExecutionPolicy::new(context), &bytes)
            .is_err()
    );
    assert_eq!(
        hex(&local_execution_event_digest(&resolver, &signed)
            .unwrap()
            .bytes()),
        "b25f2975709b03e4c57d096b48b0a7966379f21e8625ed166f74d318be80aeb9"
    );
}
