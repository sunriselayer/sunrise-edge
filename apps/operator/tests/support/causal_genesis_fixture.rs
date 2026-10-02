//! Disposable signed v4 fixture. Funding belongs to the signed genesis only;
//! no proof, receipt, publication or live business row is seeded by this module.

use abi::call_values::{CallValue, encode_call_value};
use ed25519_zebra::SigningKey;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::genesis::genesis_manifest_signing_frame;
use node_core::logical_generation::CommitmentProfile;
use node_core::{GenesisManifest, GenesisObjectEntry};
use objects::ObjectId;
use sunrise_edge_devnet::DEVNET_PAID_GENESIS_SEED;

use crate::support::genesis_fixture::{FastVoteGenesisFixture, build_economics_fixture};

pub struct CausalGenesisFixture {
    pub network: FastVoteGenesisFixture,
    /// Too small for the ordinary quoted fee: the genuine paid protocol must
    /// certify its zero-charge refusal rather than execute the application.
    pub zero_fee_coin: ObjectId,
}

pub fn build(unique: &str) -> CausalGenesisFixture {
    let mut network: FastVoteGenesisFixture = build_economics_fixture(unique);
    let mut manifest: GenesisManifest =
        node_core::decode_genesis_manifest(&network.manifest_bytes).unwrap();
    let zero_fee_coin: ObjectId = ObjectId::new([0x16; 32]);
    assert!(
        manifest
            .objects
            .iter()
            .all(|entry| entry.object.id != zero_fee_coin)
    );
    let mut coin: GenesisObjectEntry = manifest
        .objects
        .iter()
        .find(|entry| entry.object.id == network.fee_coin)
        .unwrap()
        .clone();
    coin.object.id = zero_fee_coin;
    coin.authority.object_id = zero_fee_coin;
    coin.object.data = encode_call_value(
        &public_standard_asset::coin_body_layout(),
        &CallValue::U64(1),
    )
    .unwrap();
    manifest.objects.push(coin);
    let treasury: &mut GenesisObjectEntry = &mut manifest.objects[1];
    let supply: u64 = public_standard_asset::treasury_supply(&treasury.object.data)
        .unwrap()
        .checked_add(1)
        .unwrap();
    treasury.object.data = encode_call_value(
        &public_standard_asset::treasury_cap_body_layout(),
        &CallValue::U64(supply),
    )
    .unwrap();
    manifest.commitment_profile = CommitmentProfile::CausalAdmission;
    manifest.minimum_freeze_block_height = 1;
    let key: SigningKey = SigningKey::from(DEVNET_PAID_GENESIS_SEED);
    manifest.signature = key
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();
    assert_eq!(manifest.encoding_version(), 4);
    network.manifest_digest = node_core::genesis_manifest_commitment(&network.resolver, &manifest)
        .unwrap()
        .bytes();
    network.manifest_bytes = node_core::encode_genesis_manifest(&manifest).unwrap();
    // Historical fixtures use C7. Fresh Owned IDs must have their top bit clear.
    network.request_id = [0x47; 32];
    network.paid_intent_bytes = network.sign_transfer(network.request_id, 0, network.sender);
    network
        .validators
        .sort_by_key(|validator| validator.validator_id);
    CausalGenesisFixture {
        network,
        zero_fee_coin,
    }
}

#[test]
fn genuine_causal_fixture_has_signed_v4_and_disjoint_owned_ids() {
    let fixture: CausalGenesisFixture = build("causal-audit-fixture");
    let manifest: GenesisManifest =
        node_core::decode_genesis_manifest(&fixture.network.manifest_bytes).unwrap();
    let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
        &fixture.network.resolver,
        &fixture.network.manifest_bytes,
        fixture.network.manifest_digest,
        &fixture.network.context,
    )
    .unwrap();
    assert!(root.admission_profile().is_causal());
    assert_eq!(manifest.encoding_version(), 4);
    assert_eq!(root.digest().bytes(), fixture.network.manifest_digest);
    assert_eq!(fixture.network.request_id[0] & 0x80, 0);
    assert!(
        fixture
            .network
            .validators
            .windows(2)
            .all(|pair| pair[0].validator_id < pair[1].validator_id)
    );
    assert_eq!(
        public_standard_asset::coin_amount(
            &manifest
                .objects
                .iter()
                .find(|entry| entry.object.id == fixture.zero_fee_coin)
                .unwrap()
                .object
                .data,
        )
        .unwrap(),
        1,
    );
}
