use super::*;
use abi::package_types::{PackageOrigin, ScopedTypeArg, ScopedTypeTag};
use bonds::BondResourceConfig;
use fees::Amount;
use protocol_types::{ChainId, Digest32, Epoch, HashAlgorithmId, ProtocolVersion};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect()
}

fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("dr0137-economics").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(9),
    )
    .unwrap()
}

fn resource_policy(domain: u16, value: u8) -> FastPathEconomicsResourcePolicy {
    let context: PublicationContext = context();
    let origin: PackageOrigin =
        PackageOrigin::unverified(context.chain_id().clone(), [0x11; 32], [0x12; 32]).unwrap();
    let resource_id: BondResourceId = BondResourceId::new(domain, [value; 32]).unwrap();
    FastPathEconomicsResourcePolicy {
        resource_id,
        context: context.clone(),
        instance: InstanceTarget {
            creator: [0x13; 32],
            seed: [0x14; 32],
            revision: 1,
            record_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x15; 32]),
        },
        code: UnverifiedDependencyRef::new(
            origin.clone(),
            1,
            context,
            Digest32::new(HashAlgorithmId::Sha2_256, [0x16; 32]),
        )
        .unwrap(),
        ty: ScopedTypeTag::new(
            origin,
            2,
            vec![ScopedTypeArg::Opaque {
                domain,
                value: [value; 32],
            }],
        )
        .unwrap(),
        schema: 1,
        split_entrypoint: "split".to_owned(),
        transfer_entrypoint: "transfer".to_owned(),
        bond: Some(BondResourceConfig {
            resource_id,
            min_bond: Amount::new(100),
            enabled: true,
            unbonding_epochs: 7,
            max_validator_exposure: None,
        }),
        fee_escrow: true,
    }
}

#[test]
fn economics_policy_round_trips_with_ordered_resources() {
    let policy: FastPathEconomicsPolicy = FastPathEconomicsPolicy {
        context: context(),
        resources: vec![resource_policy(7, 0x21), resource_policy(8, 0x22)],
    };
    let bytes: Vec<u8> = encode_fastpath_economics_policy(&policy).unwrap();
    assert_eq!(decode_fastpath_economics_policy(&bytes).unwrap(), policy);

    let mut trailing: Vec<u8> = bytes;
    trailing.push(0);
    assert!(decode_fastpath_economics_policy(&trailing).is_err());
}

#[test]
fn economics_policy_frames_0x642b_and_0x642c_are_stable() {
    let resource: FastPathEconomicsResourcePolicy = resource_policy(7, 0x21);
    let resource_bytes: Vec<u8> = encode_fastpath_economics_resource_policy(&resource).unwrap();
    let policy_bytes: Vec<u8> = encode_fastpath_economics_policy(&FastPathEconomicsPolicy {
        context: context(),
        resources: vec![resource],
    })
    .unwrap();
    assert_eq!(resource_bytes.len(), 958);
    assert_eq!(
        hex(&Sha256::digest(&resource_bytes)),
        "58298611f7b701ed6eb904aa53f17ccd791a04be7723345914013a107cc1b694"
    );
    assert_eq!(policy_bytes.len(), 1046);
    assert_eq!(
        hex(&Sha256::digest(&policy_bytes)),
        "8307f47937bfb98a84e2fe4d48953ae716647461cb3677caeb703f45db49dbc3"
    );
}

#[test]
fn economics_policy_rejects_duplicate_resource_wrong_type_and_purposeless_entry() {
    let first: FastPathEconomicsResourcePolicy = resource_policy(7, 0x31);
    let duplicate: FastPathEconomicsPolicy = FastPathEconomicsPolicy {
        context: context(),
        resources: vec![first.clone(), first.clone()],
    };
    assert!(encode_fastpath_economics_policy(&duplicate).is_err());

    let mut wrong_type: FastPathEconomicsResourcePolicy = first.clone();
    wrong_type.resource_id = BondResourceId::new(7, [0x32; 32]).unwrap();
    assert!(encode_fastpath_economics_resource_policy(&wrong_type).is_err());

    let mut purposeless: FastPathEconomicsResourcePolicy = first;
    purposeless.bond = None;
    purposeless.fee_escrow = false;
    assert!(encode_fastpath_economics_resource_policy(&purposeless).is_err());
}

#[test]
fn economics_policy_rejects_context_schema_entrypoint_and_bond_mismatches() {
    let base: FastPathEconomicsResourcePolicy = resource_policy(9, 0x41);

    let mut wrong_context: FastPathEconomicsResourcePolicy = base.clone();
    wrong_context.context = PublicationContext::new(
        ChainId::new("other-chain").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(9),
    )
    .unwrap();
    assert!(encode_fastpath_economics_resource_policy(&wrong_context).is_err());

    let mut zero_schema: FastPathEconomicsResourcePolicy = base.clone();
    zero_schema.schema = 0;
    assert!(encode_fastpath_economics_resource_policy(&zero_schema).is_err());

    let mut same_entrypoint: FastPathEconomicsResourcePolicy = base.clone();
    same_entrypoint.transfer_entrypoint = same_entrypoint.split_entrypoint.clone();
    assert!(encode_fastpath_economics_resource_policy(&same_entrypoint).is_err());

    let mut wrong_bond: FastPathEconomicsResourcePolicy = base;
    wrong_bond.bond.as_mut().unwrap().resource_id = BondResourceId::new(9, [0x42; 32]).unwrap();
    assert!(encode_fastpath_economics_resource_policy(&wrong_bond).is_err());
}
