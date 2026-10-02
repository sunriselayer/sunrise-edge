//! Before/after contract evidence for the immutable root migration.
//!
//! The pre-migration owning constructors are exercised before they are
//! removed. The final migration replaces them with the root-derived path and
//! freezes the recorded values, not a second expected implementation.

use super::*;
use crate::admission_profile::VerifiedAdmissionProfile;
use crate::ordered_economics::OrderedEconomicsPolicy;

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect::<String>()
}

#[test]
fn genesis_root_pre_migration_contract_baseline() {
    let resolver: HashSuiteResolver = tests::resolver();
    let manifests: [(&str, GenesisManifest); 4] = [
        ("v1", tests::build_bonded_fixture().0),
        ("v2", tests::logical_bonded_manifest()),
        ("v3", tests::freeze_bonded_manifest()),
        ("v4", tests::causal_bonded_manifest()),
    ];
    for (name, manifest) in manifests {
        let digest: Digest32 = genesis_manifest_commitment(&resolver, &manifest).unwrap();
        let members: Vec<ValidatorInfo> = manifest
            .validator_set
            .validators
            .iter()
            .map(|member| ValidatorInfo {
                id: member.id,
                voting_power: member.voting_power,
                signature_scheme: member.signature_scheme,
                public_key: member.public_key.clone(),
            })
            .collect::<Vec<ValidatorInfo>>();
        let committee: ValidatorSet =
            ValidatorSet::new(manifest.context().epoch(), members).unwrap();
        let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::new(
            manifest.context().clone(),
            tests::domain(),
            digest,
            Some(&manifest),
            committee,
            resolver.clone(),
        )
        .unwrap();
        let profile: VerifiedAdmissionProfile =
            VerifiedAdmissionProfile::from_pinned_genesis(&resolver, &manifest, digest).unwrap();
        let economics: String = match policy.registration_economics() {
            Some(economics) => {
                let bytes: Vec<u8> = encode_fastpath_economics_policy(economics).unwrap();
                let digest: Digest32 = resolver
                    .hash_for_purpose(
                        manifest.context().epoch(),
                        HashPurpose::ProtocolConfig,
                        &bytes,
                    )
                    .unwrap();
                hex(&digest.bytes())
            }
            None => "none".to_string(),
        };
        println!(
            "ROOT_BASELINE {name} digest={} anchor={} causal={} freeze={} economics={economics}",
            hex(&digest.bytes()),
            hex(&policy.anchor().bytes()),
            profile.is_causal(),
            policy.minimum_freeze_block_height(),
        );
        assert_eq!(profile.genesis_digest(), digest);
        assert_eq!(profile.context(), manifest.context());
    }
}
