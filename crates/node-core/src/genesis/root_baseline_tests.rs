//! Frozen before/after contract evidence for the immutable root migration.
//!
//! A pre-migration run of this module's predecessor exercised the
//! pre-migration owning constructors (`OrderedEconomicsPolicy::new`,
//! `VerifiedAdmissionProfile::from_pinned_genesis`) once, before they were
//! removed, and printed the exact digest/anchor/causal/freeze/economics
//! values below. This module now exercises only the post-migration
//! `VerifiedGenesisRoot`/`OrderedEconomicsPolicy::from_genesis_root` path and
//! asserts those exact frozen values -- hardcoded, not recomputed from the
//! new implementation -- so a regression in the migrated path is a test
//! failure rather than a silently accepted new baseline.

use super::*;
use crate::ordered_economics::OrderedEconomicsPolicy;

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect::<String>()
}

fn hex_to_bytes(hex: &str) -> [u8; 32] {
    let mut bytes: [u8; 32] = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}

struct Fixture {
    name: &'static str,
    manifest: GenesisManifest,
    digest: &'static str,
    anchor: &'static str,
    causal: bool,
    minimum_freeze_block_height: u64,
    economics: Option<&'static str>,
}

#[test]
fn genesis_root_post_migration_matches_frozen_pre_migration_baseline() {
    let resolver: HashSuiteResolver = tests::resolver();
    let fixtures: [Fixture; 4] = [
        Fixture {
            name: "v1",
            manifest: tests::build_bonded_fixture().0,
            digest: "78a0d42a2a112edd84c7134f08fce26d0f9b647aa91045ed9cba62c9ba0c1bd0",
            anchor: "700a2c7b46cc03e1f6fa41e7c3892749b8442917e19d359bda98a5b7c733c845",
            causal: false,
            minimum_freeze_block_height: 0,
            economics: None,
        },
        Fixture {
            name: "v2",
            manifest: tests::logical_bonded_manifest(),
            digest: "4d278fb694a52d2ebafb41a2935c7e826be6599e0b22bfb9be428b76b70bead2",
            anchor: "49ad9b56c61a0ea53c17e8c51e6577926500b9e82bcb2b83287d25a2c8fa3675",
            causal: false,
            minimum_freeze_block_height: 0,
            economics: None,
        },
        Fixture {
            name: "v3",
            manifest: tests::freeze_bonded_manifest(),
            digest: "c4890dc78f61186d9bc666a2508a4a3b75130510952ba6e399b9422ec2683b06",
            anchor: "5f2c149a928f6c14dc84dcbbc5be78393dc939c4ef71a5eb740db71b69ec1f24",
            causal: false,
            minimum_freeze_block_height: 1,
            economics: None,
        },
        Fixture {
            name: "v4",
            manifest: tests::causal_bonded_manifest(),
            digest: "bc485d54b7d7da449d6744b8db9b835f9f026560030786e04e7c51c7414d14be",
            anchor: "d39eefc9449359e1c70a69be636d2a584c130d9f9a3644e50604ea666999aef1",
            causal: true,
            minimum_freeze_block_height: 1,
            economics: Some("762f31a317f8aee675cfac8fce261bb4f2e12d8f9ea377a687c9cc5ac0e348e0"),
        },
    ];
    for fixture in fixtures {
        let bytes: Vec<u8> = encode_genesis_manifest(&fixture.manifest).unwrap();
        let expected_digest: [u8; 32] = hex_to_bytes(fixture.digest);
        let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
            &resolver,
            &bytes,
            expected_digest,
            fixture.manifest.context(),
        )
        .unwrap_or_else(|error| panic!("{} root verification failed: {error}", fixture.name));
        assert_eq!(
            hex(&root.digest().bytes()),
            fixture.digest,
            "{} digest",
            fixture.name
        );
        let policy: OrderedEconomicsPolicy =
            OrderedEconomicsPolicy::from_genesis_root(&root, tests::domain()).unwrap_or_else(
                |error| panic!("{} policy derivation failed: {error}", fixture.name),
            );
        assert_eq!(
            hex(&policy.anchor().bytes()),
            fixture.anchor,
            "{} anchor",
            fixture.name
        );
        assert_eq!(
            root.admission_profile().is_causal(),
            fixture.causal,
            "{} causal",
            fixture.name
        );
        assert_eq!(
            policy.minimum_freeze_block_height(),
            fixture.minimum_freeze_block_height,
            "{} freeze height",
            fixture.name
        );
        match (policy.registration_economics(), fixture.economics) {
            (None, None) => {}
            (Some(economics), Some(expected)) => {
                let economics_bytes: Vec<u8> = encode_fastpath_economics_policy(economics).unwrap();
                let economics_digest: Digest32 = resolver
                    .hash_for_purpose(
                        fixture.manifest.context().epoch(),
                        HashPurpose::ProtocolConfig,
                        &economics_bytes,
                    )
                    .unwrap();
                assert_eq!(
                    hex(&economics_digest.bytes()),
                    expected,
                    "{} economics",
                    fixture.name
                );
            }
            (actual, expected) => panic!(
                "{} economics presence differs: actual={actual:?} expected={expected:?}",
                fixture.name
            ),
        }
    }
}
