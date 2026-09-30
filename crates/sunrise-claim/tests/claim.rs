use k256::ecdsa::SigningKey;
use k256::ecdsa::signature::Signer;
use sunrise_claim::{
    Authorization, ClaimRequest, ClaimState, Leaf, MerkleTree, apply_claim, canonical_bytes,
    encode_sunrise, ledger_leaves, ledger_sha256, sign_doc_bytes, withdraw_usdrise,
};

const STRISE_STAKING: &str = "sunrise1ghd753shjuwexxywmgs4xz7x2q732vcnkm6h2pyv9s6ah3hylvrqz5nv4h";
const USDRISE_WRAPPER: &str = "sunrise14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s2v9j75";

fn sample_file(owner: &str, unlocked: &str, locked_at: u64) -> Vec<u8> {
    format!(
        r#"{{"snapshot_unix":1000,"claims":[{{"owner":"{owner}","asset":"rise","amount":"{unlocked}","claimable_at":1000,"payout":"edge"}},{{"owner":"{owner}","asset":"usdn","amount":"5","claimable_at":1000,"payout":"usdc"}},{{"owner":"{owner}","asset":"rise","amount":"7","claimable_at":{locked_at},"payout":"edge"}}]}}"#
    )
    .into_bytes()
}

#[test]
fn canonical_json_matches_the_go_encoder() {
    let bytes = canonical_bytes(&Authorization {
        ledger_sha256: "abc".into(),
        claimant: "sunrise1example".into(),
        asset: "usdn".into(),
        amount: 5,
        destination: "0x0000000000000000000000000000000000000001".into(),
        nonce: 7,
    })
    .unwrap();
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        r#"{"amount":"5","asset":"usdn","claimant":"sunrise1example","destination":"0x0000000000000000000000000000000000000001","ledger_sha256":"abc","nonce":7}"#
    );
}

#[test]
fn a_signed_unlocked_leaf_reduces_custody_and_replay_fails() {
    let signing = SigningKey::from_slice(&[0x22; 32]).unwrap();
    let pubkey = signing.verifying_key().to_encoded_point(true);
    let pubkey = pubkey.as_bytes();
    let address = cosmos_from_pubkey(pubkey);
    let owner = encode_sunrise(&address);
    let raw = sample_file(&owner, "9", 5000);
    let (snapshot, leaves) = ledger_leaves(&raw).unwrap();
    assert_eq!(leaves.len(), 3);
    let tree = MerkleTree::new(&leaves).unwrap();
    let index = leaves
        .iter()
        .position(|leaf| leaf.asset == "rise" && leaf.claimable_at == snapshot)
        .unwrap();
    let usdrise = leaves
        .iter()
        .find(|leaf| leaf.asset == "usdrise")
        .expect("unwrapped USDN is credited as USDrise");
    assert_eq!(usdrise.amount, 5);
    let proof = tree.proof(index).unwrap();
    let auth = Authorization {
        ledger_sha256: hex::encode(ledger_sha256(&raw)),
        claimant: owner,
        asset: "rise".into(),
        amount: 4,
        destination: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
        nonce: 3,
    };
    let sign_doc = sign_doc_bytes(&canonical_bytes(&auth).unwrap(), &auth.claimant);
    let signature: k256::ecdsa::Signature = signing.sign(sign_doc.as_bytes());
    let mut state = ClaimState {
        root: tree.root(),
        ledger_sha256: ledger_sha256(&raw),
        snapshot_unix: snapshot,
        custody: [("rise".into(), 16u64)].into(),
        edge_balance: Default::default(),
        consumed: Default::default(),
        nonces: Default::default(),
    };
    let request = ClaimRequest {
        authorization: auth.clone(),
        pubkey: pubkey.to_vec(),
        signature: signature.to_bytes().to_vec(),
        leaf: leaves[index].clone(),
        proof: proof.siblings,
    };
    let receipt = apply_claim(&mut state, &request).unwrap();
    let sunrise_claim::Settlement::Edge { amount, .. } = receipt else {
        panic!("rise claim must credit an Edge balance");
    };
    assert_eq!(amount, 4);
    assert_eq!(state.custody.get("rise").copied(), Some(12));
    let err = apply_claim(&mut state, &request).unwrap_err();
    assert!(err.to_string().contains("nonce"));
}

#[test]
fn a_leaf_after_the_snapshot_is_rejected() {
    let signing = SigningKey::from_slice(&[0x22; 32]).unwrap();
    let pubkey = signing.verifying_key().to_encoded_point(true);
    let pubkey = pubkey.as_bytes();
    let owner = encode_sunrise(&cosmos_from_pubkey(pubkey));
    let raw = sample_file(&owner, "9", 5000);
    let (snapshot, leaves) = ledger_leaves(&raw).unwrap();
    let tree = MerkleTree::new(&leaves).unwrap();
    let index = leaves
        .iter()
        .position(|leaf| leaf.claimable_at > snapshot)
        .unwrap();
    let auth = Authorization {
        ledger_sha256: hex::encode(ledger_sha256(&raw)),
        claimant: owner,
        asset: "rise".into(),
        amount: 1,
        destination: "11".repeat(32),
        nonce: 1,
    };
    let sign_doc = sign_doc_bytes(&canonical_bytes(&auth).unwrap(), &auth.claimant);
    let signature: k256::ecdsa::Signature = signing.sign(sign_doc.as_bytes());
    let mut state = ClaimState {
        root: tree.root(),
        ledger_sha256: ledger_sha256(&raw),
        snapshot_unix: snapshot,
        custody: [("rise".into(), 100u64)].into(),
        edge_balance: Default::default(),
        consumed: Default::default(),
        nonces: Default::default(),
    };
    let err = apply_claim(
        &mut state,
        &ClaimRequest {
            authorization: auth,
            pubkey: pubkey.to_vec(),
            signature: signature.to_bytes().to_vec(),
            leaf: leaves[index].clone(),
            proof: tree.proof(index).unwrap().siblings,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("unlocks"));
    assert_eq!(state.custody.get("rise").copied(), Some(100));
}

#[test]
fn the_staking_contract_rise_is_not_a_second_strise_claim() {
    let holder = encode_sunrise(&[0x11; 20]);
    let raw = format!(
        r#"{{"snapshot_unix":1000,"claims":[{{"owner":"{holder}","asset":"factory/{STRISE_STAKING}/strise","amount":"40","claimable_at":1000,"payout":"edge"}},{{"owner":"{holder}","asset":"rise","amount":"9","claimable_at":1000,"payout":"edge"}},{{"owner":"{STRISE_STAKING}","asset":"rise","amount":"30","claimable_at":1000,"payout":"edge"}},{{"owner":"{STRISE_STAKING}","asset":"rise","amount":"10","claimable_at":5000,"payout":"edge"}}]}}"#
    )
    .into_bytes();
    let (_, leaves) = ledger_leaves(&raw).unwrap();
    assert_eq!(
        leaves,
        vec![Leaf {
            claimant: [0x11; 20],
            asset: "rise".into(),
            claimable_at: 1000,
            amount: 49,
        }]
    );
}

#[test]
fn only_the_staking_contract_own_rise_is_skipped() {
    for (owner, asset) in [(USDRISE_WRAPPER, "rise"), (STRISE_STAKING, "usdn")] {
        let raw = format!(
            r#"{{"snapshot_unix":1000,"claims":[{{"owner":"{owner}","asset":"{asset}","amount":"3","claimable_at":1000,"payout":"edge"}}]}}"#
        )
        .into_bytes();
        let err = ledger_leaves(&raw).unwrap_err();
        assert!(err.to_string().contains(owner), "{owner} {asset}: {err}");
    }
}

#[test]
fn a_usdrise_withdrawal_to_a_malformed_evm_address_burns_nothing() {
    let signing = SigningKey::from_slice(&[0x22; 32]).unwrap();
    let pubkey = signing.verifying_key().to_encoded_point(true);
    let claimant = cosmos_from_pubkey(pubkey.as_bytes());
    let key = (claimant, "usdrise".to_string());
    let ledger = ledger_sha256(b"claims");
    let mut state = credited_usdrise(claimant, ledger, 5);
    for destination in [
        "0x".to_string(),
        "0x1234".to_string(),
        "11".repeat(20),
        format!("0x{}", "zz".repeat(20)),
        format!("0x{}1", "11".repeat(20)),
        format!("0x{}", "00".repeat(20)),
        // A signed USDrise claim to a 32-byte Edge address is not a withdrawal.
        format!("0x{}", "11".repeat(32)),
    ] {
        let request = withdrawal(&signing, ledger, &destination);
        let err = withdraw_usdrise(&mut state, &request).unwrap_err();
        assert!(
            err.to_string().contains("destination"),
            "{destination}: {err}"
        );
    }
    assert_eq!(state.edge_balance.get(&key), Some(&5));
    assert!(state.nonces.is_empty());

    let destination = format!("0x{}", "11".repeat(20));
    let request = withdrawal(&signing, ledger, &destination);
    let order = withdraw_usdrise(&mut state, &request).unwrap();
    assert_eq!(order.destination, destination);
    assert_eq!(order.amount, 3);
    assert_eq!(order.ledger_sha256, hex::encode(ledger));
    assert_eq!(state.edge_balance.get(&key), Some(&2));
}

#[test]
fn a_usdrise_withdrawal_signed_for_another_ledger_burns_nothing() {
    let signing = SigningKey::from_slice(&[0x22; 32]).unwrap();
    let pubkey = signing.verifying_key().to_encoded_point(true);
    let claimant = cosmos_from_pubkey(pubkey.as_bytes());
    let key = (claimant, "usdrise".to_string());
    let mut state = credited_usdrise(claimant, ledger_sha256(b"claims"), 5);
    let destination = format!("0x{}", "11".repeat(20));
    let request = withdrawal(&signing, ledger_sha256(b"rehearsal"), &destination);
    let err = withdraw_usdrise(&mut state, &request).unwrap_err();
    assert!(err.to_string().contains("ledger hash"), "{err}");
    assert_eq!(state.edge_balance.get(&key), Some(&5));
    assert!(state.nonces.is_empty());
}

fn credited_usdrise(claimant: [u8; 20], ledger: [u8; 32], balance: u64) -> ClaimState {
    ClaimState {
        root: [0; 32],
        ledger_sha256: ledger,
        snapshot_unix: 1000,
        custody: Default::default(),
        edge_balance: [((claimant, "usdrise".to_string()), balance)].into(),
        consumed: Default::default(),
        nonces: Default::default(),
    }
}

fn withdrawal(signing: &SigningKey, ledger: [u8; 32], destination: &str) -> ClaimRequest {
    let pubkey = signing.verifying_key().to_encoded_point(true);
    let claimant = cosmos_from_pubkey(pubkey.as_bytes());
    let auth = Authorization {
        ledger_sha256: hex::encode(ledger),
        claimant: encode_sunrise(&claimant),
        asset: "usdrise".into(),
        amount: 3,
        destination: destination.into(),
        nonce: 1,
    };
    let sign_doc = sign_doc_bytes(&canonical_bytes(&auth).unwrap(), &auth.claimant);
    let signature: k256::ecdsa::Signature = signing.sign(sign_doc.as_bytes());
    ClaimRequest {
        authorization: auth,
        pubkey: pubkey.as_bytes().to_vec(),
        signature: signature.to_bytes().to_vec(),
        leaf: Leaf {
            claimant,
            asset: "usdrise".into(),
            claimable_at: 0,
            amount: 0,
        },
        proof: Vec::new(),
    }
}

fn cosmos_from_pubkey(pubkey: &[u8]) -> [u8; 20] {
    let sha = <sha2::Sha256 as sha2::Digest>::digest(pubkey);
    let ripe = <ripemd::Ripemd160 as digest010::Digest>::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}
