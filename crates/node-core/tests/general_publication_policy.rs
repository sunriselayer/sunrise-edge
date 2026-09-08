use execution::local_execution::LocalExecutionPolicy;
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::local_instance_state::{execution_policy_key, execution_policy_key_for_profile};
use node_core::publication::{
    LocalPublicationPolicy, local_general_publication_semantics,
    local_object_result_publication_semantics, publication_policy_key_for_profile,
};
use protocol_types::{ChainId, Epoch, HashSuite, HashSuiteSchedule, ProtocolVersion};
use sha2::{Digest, Sha256};

#[test]
fn general_policies_have_independent_explicit_keys_and_strict_versions() {
    let context = PublicationContext::new(
        ChainId::new("local-vector").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(0),
    )
    .unwrap();
    let resolver = HashSuiteResolver::new(
        context.chain_id().clone(),
        context.protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let semantics = local_general_publication_semantics(&resolver, &context).unwrap();
    let policy = LocalPublicationPolicy::general(context.clone(), semantics);
    assert_eq!(policy.profile(), 3);
    let encoded: Vec<u8> = policy.encode().unwrap();
    assert_eq!(encoded.len(), 172);
    let actual: String = Sha256::digest(&encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        actual,
        "58f4003c412cfaaae09bb6aabc04a10f9fbdba56d10c5220e8e724b4b57f6a5f"
    );
    assert_eq!(
        LocalPublicationPolicy::decode(&policy.encode().unwrap()).unwrap(),
        policy
    );
    assert_ne!(
        publication_policy_key_for_profile(&context, 2).unwrap(),
        publication_policy_key_for_profile(&context, 3).unwrap()
    );
    assert_ne!(
        execution_policy_key(&context).unwrap(),
        execution_policy_key_for_profile(&context, 3).unwrap()
    );
    assert_ne!(
        execution_policy_key_for_profile(&context, 3).unwrap(),
        execution_policy_key_for_profile(&context, 4).unwrap()
    );
    assert_ne!(
        publication_policy_key_for_profile(&context, 3).unwrap(),
        publication_policy_key_for_profile(&context, 4).unwrap()
    );
    assert!(execution_policy_key_for_profile(&context, 5).is_err());
    assert!(publication_policy_key_for_profile(&context, 5).is_err());
    let mut bytes = policy.encode().unwrap();
    bytes[6] = 2;
    assert!(LocalPublicationPolicy::decode(&bytes).is_err());
    let execution = LocalExecutionPolicy::general(context);
    assert_eq!(
        LocalExecutionPolicy::decode(&execution.encode().unwrap()).unwrap(),
        execution
    );
}

#[test]
fn object_result_policy_has_permanent_fixed_encoding_vector() {
    let context = PublicationContext::new(
        ChainId::new("local-vector").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(0),
    )
    .unwrap();
    let resolver = HashSuiteResolver::new(
        context.chain_id().clone(),
        context.protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let semantics = local_object_result_publication_semantics(&resolver, &context).unwrap();
    let policy = LocalPublicationPolicy::object_results(context.clone(), semantics);
    assert_eq!(policy.profile(), 4);
    let encoded: Vec<u8> = policy.encode().unwrap();
    assert_eq!(encoded.len(), 172);
    let actual: String = Sha256::digest(&encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        actual,
        "d0164f69c566329eb87d564246dbc09929d98dff1f39220deedd91e47882c85a"
    );
    assert_eq!(
        LocalPublicationPolicy::decode(&policy.encode().unwrap()).unwrap(),
        policy
    );
    assert_ne!(
        publication_policy_key_for_profile(&context, 3).unwrap(),
        publication_policy_key_for_profile(&context, 4).unwrap()
    );
    let mut bytes = policy.encode().unwrap();
    bytes[6] = 2;
    assert!(LocalPublicationPolicy::decode(&bytes).is_err());
}
