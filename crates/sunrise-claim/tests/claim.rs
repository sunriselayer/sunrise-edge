use k256::ecdsa::SigningKey;
use k256::ecdsa::signature::Signer;
use sunrise_claim::{
    Authorization, ClaimRequest, ClaimState, MerkleTree, apply_claim, canonical_bytes,
    encode_sunrise, ledger_sha256, rise_leaves, sign_doc_bytes,
};

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
    let (snapshot, leaves) = rise_leaves(&raw).unwrap();
    assert_eq!(leaves.len(), 2);
    let tree = MerkleTree::new(&leaves).unwrap();
    let index = leaves
        .iter()
        .position(|leaf| leaf.claimable_at == snapshot)
        .unwrap();
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
        custody: leaves.iter().map(|leaf| leaf.amount).sum(),
        consumed: Default::default(),
        nonces: Default::default(),
    };
    let request = ClaimRequest {
        authorization: auth.clone(),
        pubkey: pubkey.to_vec(),
        signature: signature.to_bytes().to_vec(),
        leaf: leaves[index],
        proof: proof.siblings,
    };
    let receipt = apply_claim(&mut state, &request).unwrap();
    assert_eq!(receipt.amount, 4);
    assert_eq!(state.custody, receipt.custody_remaining);
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
    let (snapshot, leaves) = rise_leaves(&raw).unwrap();
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
        custody: 100,
        consumed: Default::default(),
        nonces: Default::default(),
    };
    let err = apply_claim(
        &mut state,
        &ClaimRequest {
            authorization: auth,
            pubkey: pubkey.to_vec(),
            signature: signature.to_bytes().to_vec(),
            leaf: leaves[index],
            proof: tree.proof(index).unwrap().siblings,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("unlocks"));
    assert_eq!(state.custody, 100);
}

fn cosmos_from_pubkey(pubkey: &[u8]) -> [u8; 20] {
    let sha = <sha2::Sha256 as sha2::Digest>::digest(pubkey);
    let ripe = <ripemd::Ripemd160 as digest010::Digest>::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}
