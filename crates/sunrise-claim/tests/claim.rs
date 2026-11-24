use bech32::{Bech32, Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use k256::ecdsa::SigningKey;
use k256::ecdsa::signature::Signer;
use sha2::{Digest, Sha256};
use sunrise_claim::{
    Authorization, ClaimRequest, ClaimState, Leaf, MerkleTree, PayoutOrder, apply_claim,
    canonical_bytes, encode_sunrise, ledger_leaves, ledger_sha256, payout_order_bytes,
    payout_order_id, sign_doc_bytes, withdraw_usdrise,
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
fn uvrise_is_added_to_rise_one_to_one() {
    let holder = encode_sunrise(&[0x11; 20]);
    let raw = format!(
        r#"{{"snapshot_unix":1000,"claims":[{{"owner":"{holder}","asset":"uvrise","amount":"40","claimable_at":1000,"payout":"edge"}},{{"owner":"{holder}","asset":"rise","amount":"9","claimable_at":1000,"payout":"edge"}},{{"owner":"{holder}","asset":"uvrise","amount":"2","claimable_at":5000,"payout":"edge"}}]}}"#
    )
    .into_bytes();
    let (_, leaves) = ledger_leaves(&raw).unwrap();
    assert_eq!(
        leaves,
        vec![
            Leaf {
                claimant: [0x11; 20],
                asset: "rise".into(),
                claimable_at: 1000,
                amount: 49,
            },
            Leaf {
                claimant: [0x11; 20],
                asset: "rise".into(),
                claimable_at: 5000,
                amount: 2,
            },
        ]
    );
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
    let before = state.clone();
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
    assert_all_claim_state_fields_eq(&before, &state);
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
    let before = state.clone();
    let destination = format!("0x{}", "11".repeat(20));
    let request = withdrawal(&signing, ledger_sha256(b"rehearsal"), &destination);
    let err = withdraw_usdrise(&mut state, &request).unwrap_err();
    assert!(err.to_string().contains("ledger hash"), "{err}");
    assert_all_claim_state_fields_eq(&before, &state);
    assert_eq!(state.edge_balance.get(&key), Some(&5));
    assert!(state.nonces.is_empty());
}

const ORDINARY_PAYOUT_JSON: &[u8] = br#"{"amount":"5","asset":"usdn","chain_id":"1","claimant":"sunrise1example","denom":"uusdc","destination":"0x0000000000000000000000000000000000000001","ledger_sha256":"abc","nonce":7}"#;

#[test]
fn ordinary_payout_order_bytes_and_id_stay_stable() {
    let order = ordinary_payout_order();
    let bytes = payout_order_bytes(&order);
    assert_eq!(bytes, ORDINARY_PAYOUT_JSON);
    assert_eq!(
        payout_order_id(&order),
        hex::encode(Sha256::digest(ORDINARY_PAYOUT_JSON))
    );
}

#[test]
fn payout_order_bytes_round_trip_quotes_backslashes_and_controls() {
    let order = PayoutOrder {
        asset: r#"rise"quote"#.into(),
        chain_id: "line\nbreak".into(),
        denom: r#"path\to\token"#.into(),
        destination: "tab\there\u{0001}".into(),
        amount: 5,
        claimant: r#"sunrise1"slash\\end"#.into(),
        nonce: 7,
        ledger_sha256: "abc\rdef".into(),
    };
    let bytes = payout_order_bytes(&order);
    let text = std::str::from_utf8(&bytes).expect("payout JSON is utf-8");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("payout JSON parses");
    assert_eq!(parsed["amount"], serde_json::Value::String("5".into()));
    assert_eq!(parsed["nonce"], serde_json::Value::Number(7.into()));
    assert_eq!(parsed["asset"].as_str(), Some(order.asset.as_str()));
    assert_eq!(parsed["chain_id"].as_str(), Some(order.chain_id.as_str()));
    assert_eq!(parsed["claimant"].as_str(), Some(order.claimant.as_str()));
    assert_eq!(parsed["denom"].as_str(), Some(order.denom.as_str()));
    assert_eq!(
        parsed["destination"].as_str(),
        Some(order.destination.as_str())
    );
    assert_eq!(
        parsed["ledger_sha256"].as_str(),
        Some(order.ledger_sha256.as_str())
    );
    assert!(text.contains(r#"rise\"quote"#), "{text}");
    assert!(text.contains(r#"path\\to\\token"#), "{text}");
    assert!(text.contains(r#"line\nbreak"#), "{text}");
    assert!(text.contains(r#"tab\there"#), "{text}");
    assert!(text.contains(r#"\u0001"#), "{text}");
}

#[test]
fn a_signed_usdrise_withdrawal_misrouted_to_claim_mutates_nothing() {
    let setup = unlocked_setup();
    let index = setup.usdrise_index();
    let leaf = setup.leaves[index].clone();
    assert_eq!(leaf.amount, 5);
    let destination = format!("0x{}", "11".repeat(20));
    let request = setup.sign(
        Authorization {
            ledger_sha256: hex::encode(setup.ledger()),
            claimant: setup.owner.clone(),
            asset: "usdrise".into(),
            amount: 2,
            destination,
            nonce: 1,
        },
        leaf,
        setup.tree.proof(index).unwrap().siblings,
    );
    let mut state = ClaimState {
        root: setup.tree.root(),
        ledger_sha256: setup.ledger(),
        snapshot_unix: setup.snapshot,
        custody: [("usdrise".into(), 8u64)].into(),
        edge_balance: [
            ((setup.claimant, "usdrise".into()), 2u64),
            ((setup.claimant, "rise".into()), 1u64),
        ]
        .into(),
        consumed: [((setup.claimant, "usdrise".into(), setup.snapshot), 2u64)].into(),
        nonces: [(setup.claimant, 99u64)].into(),
    };
    let before = state.clone();
    let err = apply_claim(&mut state, &request).unwrap_err();
    assert!(
        err.to_string().contains("destination") && err.to_string().contains("32 bytes"),
        "{err}"
    );
    assert_all_claim_state_fields_eq(&before, &state);
    let payout = withdraw_usdrise(&mut state, &request)
        .expect("the same authorization remains usable by its intended withdrawal");
    assert_eq!(payout.amount, 2);
    assert_eq!(
        state.edge_balance.get(&(setup.claimant, "usdrise".into())),
        Some(&0)
    );
    assert_eq!(state.consumed, before.consumed);
    assert_eq!(state.custody, before.custody);
}

#[test]
fn a_claim_with_a_malformed_edge_destination_mutates_nothing() {
    let setup = unlocked_setup();
    let mut state = setup.rise_state(16, 0, 0);
    let before = state.clone();
    let request = setup.signed_rise(4, "not-a-hex-address", 3);
    let err = apply_claim(&mut state, &request).unwrap_err();
    assert!(err.to_string().contains("destination"), "{err}");
    assert_all_claim_state_fields_eq(&before, &state);
}

#[test]
fn external_claims_require_a_valid_destination_before_consuming_entitlement() {
    let signing = SigningKey::from_slice(&[0x22; 32]).unwrap();
    let pubkey = signing.verifying_key().to_encoded_point(true);
    let claimant = cosmos_from_pubkey(pubkey.as_bytes());
    let owner = encode_sunrise(&claimant);
    for (asset, prefix) in [
        (
            "ibc/C4CFF46FD6DE35CA4CF4CE031E643C8FDC9BA4B99AE598E9B0ED98FE3A2319F9",
            "cosmos",
        ),
        (
            "ibc/47BD209179859CDE4A2806763D7189B6E6FE13A17880FE2B42DE1E6C1E329E23",
            "osmo",
        ),
        (
            "ibc/AAF322A78A0E34B76CDA05BA9AE96DC1521F9E103EC576AB9931116B2AB8C26B",
            "noble",
        ),
    ] {
        let raw = format!(
            r#"{{"snapshot_unix":1000,"claims":[{{"owner":"{owner}","asset":"{asset}","amount":"5","claimable_at":1000}}]}}"#
        );
        let (_, leaves) = ledger_leaves(raw.as_bytes()).unwrap();
        let tree = MerkleTree::new(&leaves).unwrap();
        let ledger = ledger_sha256(raw.as_bytes());
        let mut state = ClaimState {
            root: tree.root(),
            ledger_sha256: ledger,
            snapshot_unix: 1000,
            custody: Default::default(),
            edge_balance: Default::default(),
            consumed: Default::default(),
            nonces: Default::default(),
        };
        let sign = |destination: &str| {
            let auth = Authorization {
                ledger_sha256: hex::encode(ledger),
                claimant: owner.clone(),
                asset: asset.into(),
                amount: 3,
                destination: destination.into(),
                nonce: 7,
            };
            let sign_doc = sign_doc_bytes(&canonical_bytes(&auth).unwrap(), &auth.claimant);
            let signature: k256::ecdsa::Signature = signing.sign(sign_doc.as_bytes());
            ClaimRequest {
                authorization: auth,
                pubkey: pubkey.as_bytes().to_vec(),
                signature: signature.to_bytes().to_vec(),
                leaf: leaves[0].clone(),
                proof: tree.proof(0).unwrap().siblings,
            }
        };
        let hrp = Hrp::parse(prefix).unwrap();
        let valid = bech32::encode::<Bech32>(hrp, &[0x11; 20]).unwrap();
        let valid_contract = bech32::encode::<Bech32>(hrp, &[0x11; 32]).unwrap();
        let wrong_prefix =
            bech32::encode::<Bech32>(Hrp::parse("sunrise").unwrap(), &[0x11; 20]).unwrap();
        let wrong_checksum = bech32::encode::<Bech32m>(hrp, &[0x11; 20]).unwrap();
        let empty_payload = bech32::encode::<Bech32>(hrp, &[]).unwrap();
        let short_payload = bech32::encode::<Bech32>(hrp, &[0x11]).unwrap();
        let mut noncanonical_fes: Vec<Fe32> = [0x11u8; 32].into_iter().bytes_to_fes().collect();
        let last = noncanonical_fes.last_mut().unwrap();
        *last = Fe32::try_from(last.to_u8() ^ 1).unwrap();
        let noncanonical_padding: String = noncanonical_fes
            .into_iter()
            .with_checksum::<Bech32>(&hrp)
            .chars()
            .collect();
        for destination in [
            "",
            "not-an-address",
            wrong_prefix.as_str(),
            wrong_checksum.as_str(),
            empty_payload.as_str(),
            short_payload.as_str(),
            noncanonical_padding.as_str(),
            &"x".repeat(91),
        ] {
            let before = state.clone();
            let err = apply_claim(&mut state, &sign(destination)).unwrap_err();
            assert!(err.to_string().contains("destination"), "{asset}: {err}");
            assert_all_claim_state_fields_eq(&before, &state);
        }
        let order = apply_claim(&mut state, &sign(&valid)).unwrap();
        assert!(
            matches!(order, sunrise_claim::Settlement::External(ref payout) if payout.destination == valid)
        );
        assert_eq!(
            state.consumed.get(&(claimant, asset.into(), 1000)),
            Some(&3)
        );
        assert!(state.nonces.contains(&(claimant, 7)));

        for destination in [valid.to_uppercase(), valid_contract] {
            let mut fresh = ClaimState {
                root: tree.root(),
                ledger_sha256: ledger,
                snapshot_unix: 1000,
                custody: Default::default(),
                edge_balance: Default::default(),
                consumed: Default::default(),
                nonces: Default::default(),
            };
            let order = apply_claim(&mut fresh, &sign(&destination)).unwrap();
            assert!(
                matches!(order, sunrise_claim::Settlement::External(ref payout) if payout.destination == destination)
            );
        }
    }
}

#[test]
fn a_claim_with_insufficient_custody_mutates_nothing() {
    let setup = unlocked_setup();
    let mut state = setup.rise_state(1, 0, 0);
    let before = state.clone();
    let request = setup.signed_rise(4, &"11".repeat(32), 3);
    let err = apply_claim(&mut state, &request).unwrap_err();
    assert!(err.to_string().contains("custody"), "{err}");
    assert_all_claim_state_fields_eq(&before, &state);
}

#[test]
fn a_claim_that_would_overflow_credited_balance_mutates_nothing() {
    let setup = unlocked_setup();
    let mut state = setup.rise_state(16, 0, u64::MAX);
    let before = state.clone();
    let request = setup.signed_rise(4, &"11".repeat(32), 3);
    let err = apply_claim(&mut state, &request).unwrap_err();
    assert_eq!(err, sunrise_claim::ClaimError::Overflow);
    assert_all_claim_state_fields_eq(&before, &state);
}

#[test]
fn an_invalid_usdrise_withdrawal_from_absent_balance_mutates_nothing() {
    let signing = SigningKey::from_slice(&[0x22; 32]).unwrap();
    let ledger = ledger_sha256(b"claims");
    let mut state = ClaimState {
        root: [0; 32],
        ledger_sha256: ledger,
        snapshot_unix: 1000,
        custody: Default::default(),
        edge_balance: Default::default(),
        consumed: Default::default(),
        nonces: Default::default(),
    };
    let before = state.clone();
    let destination = format!("0x{}", "11".repeat(20));
    let request = withdrawal(&signing, ledger, &destination);
    let err = withdraw_usdrise(&mut state, &request).unwrap_err();
    assert!(
        err.to_string().contains("exceeds credited USDrise"),
        "{err}"
    );
    assert_all_claim_state_fields_eq(&before, &state);
    assert!(state.edge_balance.is_empty());
    assert!(state.nonces.is_empty());
}

fn ordinary_payout_order() -> PayoutOrder {
    PayoutOrder {
        asset: "usdn".into(),
        chain_id: "1".into(),
        denom: "uusdc".into(),
        destination: "0x0000000000000000000000000000000000000001".into(),
        amount: 5,
        claimant: "sunrise1example".into(),
        nonce: 7,
        ledger_sha256: "abc".into(),
    }
}

fn assert_all_claim_state_fields_eq(left: &ClaimState, right: &ClaimState) {
    assert_eq!(left.root, right.root);
    assert_eq!(left.ledger_sha256, right.ledger_sha256);
    assert_eq!(left.snapshot_unix, right.snapshot_unix);
    assert_eq!(left.custody, right.custody);
    assert_eq!(left.edge_balance, right.edge_balance);
    assert_eq!(left.consumed, right.consumed);
    assert_eq!(left.nonces, right.nonces);
}

struct UnlockedSetup {
    signing: SigningKey,
    pubkey: Vec<u8>,
    claimant: [u8; 20],
    owner: String,
    raw: Vec<u8>,
    snapshot: u64,
    leaves: Vec<Leaf>,
    tree: MerkleTree,
}

fn unlocked_setup() -> UnlockedSetup {
    let signing = SigningKey::from_slice(&[0x22; 32]).unwrap();
    let pubkey = signing.verifying_key().to_encoded_point(true);
    let pubkey = pubkey.as_bytes().to_vec();
    let claimant = cosmos_from_pubkey(&pubkey);
    let owner = encode_sunrise(&claimant);
    let raw = sample_file(&owner, "9", 5000);
    let (snapshot, leaves) = ledger_leaves(&raw).unwrap();
    let tree = MerkleTree::new(&leaves).unwrap();
    UnlockedSetup {
        signing,
        pubkey,
        claimant,
        owner,
        raw,
        snapshot,
        leaves,
        tree,
    }
}

impl UnlockedSetup {
    fn ledger(&self) -> [u8; 32] {
        ledger_sha256(&self.raw)
    }

    fn usdrise_index(&self) -> usize {
        self.leaves
            .iter()
            .position(|leaf| leaf.asset == "usdrise")
            .expect("unwrapped USDN is credited as USDrise")
    }

    fn rise_index(&self) -> usize {
        self.leaves
            .iter()
            .position(|leaf| leaf.asset == "rise" && leaf.claimable_at == self.snapshot)
            .unwrap()
    }

    fn sign(&self, auth: Authorization, leaf: Leaf, proof: Vec<[u8; 32]>) -> ClaimRequest {
        let sign_doc = sign_doc_bytes(&canonical_bytes(&auth).unwrap(), &auth.claimant);
        let signature: k256::ecdsa::Signature = self.signing.sign(sign_doc.as_bytes());
        ClaimRequest {
            authorization: auth,
            pubkey: self.pubkey.clone(),
            signature: signature.to_bytes().to_vec(),
            leaf,
            proof,
        }
    }

    fn signed_rise(&self, amount: u64, destination: &str, nonce: u64) -> ClaimRequest {
        let index = self.rise_index();
        self.sign(
            Authorization {
                ledger_sha256: hex::encode(self.ledger()),
                claimant: self.owner.clone(),
                asset: "rise".into(),
                amount,
                destination: destination.into(),
                nonce,
            },
            self.leaves[index].clone(),
            self.tree.proof(index).unwrap().siblings,
        )
    }

    fn rise_state(&self, custody: u64, consumed: u64, credited: u64) -> ClaimState {
        ClaimState {
            root: self.tree.root(),
            ledger_sha256: self.ledger(),
            snapshot_unix: self.snapshot,
            custody: [("rise".into(), custody)].into(),
            edge_balance: [((self.claimant, "rise".to_string()), credited)].into(),
            consumed: if consumed == 0 {
                Default::default()
            } else {
                [((self.claimant, "rise".to_string(), self.snapshot), consumed)].into()
            },
            nonces: Default::default(),
        }
    }
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
