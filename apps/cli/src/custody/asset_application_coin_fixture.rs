//! Exact ignored oracle for the separate DR-0261 follow-on application flow.
//! The original create/mint/burn and stopped E67 lifecycle finish unchanged
//! before this probe starts. This flow mints/splits/merges/burns to supply0,
//! then mints and transfers to the existing distinct disposable recipient.
//! Its final state deliberately has supply5M, cap version6 and next nonce9.

use super::asset_create_fixture::{
    connect, current_inline, new_definition_and_cap, new_minted_coin_id, read_bounded,
    require_receipt, required, required_hex32,
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use sunrise_edge_client::{
    AccessMode, Address, ChainId, Client,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, Epoch, ExpectedProtocolContext,
    HashSuiteId, HashSuiteResolver, HttpObjectQueryResult, LocalSigner, LoopbackHttpTransport,
    Object, ObjectEffect, ObjectId, ObjectRef, Owner, PaidApplication, PaidExecutionResult,
    PaidExecutionStatus, PaidResultKind, RequestId, SignatureSchemeId, SignedPaidIntent,
    decode_paid_execution_result, decode_signed_paid_intent, encode_paid_execution_result,
    local_execution::{InstanceRecord, decode_instance_record, instance_target},
};

const AMOUNT: u64 = 5_000_000;
const SPLIT: u64 = 2_000_000;
const TAGS: [&str; 6] = ["mint-one", "split", "merge", "burn", "mint-two", "transfer"];
const NONCES: [u64; 6] = [3, 4, 5, 6, 7, 8];
const IDS: [[u8; 32]; 6] = [
    [0xa0; 32], [0xa1; 32], [0xa2; 32], [0xa3; 32], [0xa4; 32], [0xa5; 32],
];

struct Accepted {
    signed: SignedPaidIntent,
    result: PaidExecutionResult,
    bytes: Vec<u8>,
}

fn read_accepted(
    directory: &Path,
    index: usize,
    resolver: &HashSuiteResolver,
    context: &sunrise_edge_client::PublicationContext,
) -> Accepted {
    let signed_bytes: Vec<u8> =
        read_bounded(&directory.join(format!("app-coins-{}-submission.bin", TAGS[index])));
    let signed: SignedPaidIntent = decode_signed_paid_intent(&signed_bytes).unwrap();
    execution::paid_execution::authenticate_paid_intent(resolver, context, &signed_bytes).unwrap();
    assert_eq!(
        execution::paid_execution::encode_signed_paid_intent(&signed).unwrap(),
        signed_bytes
    );
    let bytes: Vec<u8> =
        read_bounded(&directory.join(format!("app-coins-{}-result.bin", TAGS[index])));
    let result: PaidExecutionResult = decode_paid_execution_result(&bytes).unwrap();
    assert_eq!(encode_paid_execution_result(&result).unwrap(), bytes);
    assert_eq!(result.status, PaidExecutionStatus::Success);
    assert_eq!(result.kind, PaidResultKind::Call);
    assert_eq!(result.request_id, IDS[index]);
    assert_eq!(
        result.effects.tx_hash,
        execution::paid_execution::paid_invocation_digest(resolver, &signed).unwrap()
    );
    assert_eq!(signed.intent.request_id, IDS[index]);
    assert_eq!(signed.intent.nonce, NONCES[index]);
    Accepted {
        signed,
        result,
        bytes,
    }
}

fn object_preimage(directory: &Path, role: &str, nonce: u64) -> (Object, Vec<u8>) {
    let bytes: Vec<u8> = read_bounded(&directory.join(format!("app-coins-{role}-{nonce}.bin")));
    let object: Object = objects::decode_object(&bytes).unwrap();
    assert_eq!(objects::encode_object(&object).unwrap(), bytes);
    (object, bytes)
}

fn expect_reference(
    reference: &ObjectRef,
    object: &Object,
    bytes: &[u8],
    resolver: &HashSuiteResolver,
) {
    assert_eq!(reference.id, object.id);
    assert_eq!(reference.version, object.version);
    assert_eq!(
        reference.digest,
        resolver
            .hash_for_purpose(Epoch::new(0), protocol_types::HashPurpose::Object, bytes)
            .unwrap()
    );
}

fn effect_object(result: &PaidExecutionResult, id: ObjectId, previous: Option<u64>) -> &Object {
    let effects: Vec<&ObjectEffect> = result
        .effects
        .object_effects
        .iter()
        .filter(|effect| match effect {
            ObjectEffect::Created(object) => object.id == id,
            ObjectEffect::Mutated { new_object, .. } => new_object.id == id,
            ObjectEffect::Deleted { id: deleted, .. } => *deleted == id,
        })
        .collect();
    match (effects.as_slice(), previous) {
        ([ObjectEffect::Created(object)], None) => object,
        (
            [
                ObjectEffect::Mutated {
                    previous_version,
                    new_object,
                },
            ],
            Some(version),
        ) => {
            assert_eq!(*previous_version, version);
            new_object
        }
        _ => panic!("one exact expected application object effect"),
    }
}

fn expect_deleted(result: &PaidExecutionResult, id: ObjectId, version: u64) {
    let effects: Vec<&ObjectEffect> = result
        .effects
        .object_effects
        .iter()
        .filter(|effect| match effect {
            ObjectEffect::Created(object) => object.id == id,
            ObjectEffect::Mutated { new_object, .. } => new_object.id == id,
            ObjectEffect::Deleted { id: deleted, .. } => *deleted == id,
        })
        .collect();
    assert!(
        matches!(effects.as_slice(), [ObjectEffect::Deleted { id: actual, version: actual_version }]
        if *actual == id && *actual_version == version)
    );
}

fn expect_coin(
    object: &Object,
    id: ObjectId,
    version: u64,
    owner: Address,
    amount: u64,
    coin_type: sunrise_edge_client::Digest32,
) {
    assert_eq!(object.id, id);
    assert_eq!(object.version, version);
    assert_eq!(object.owner, Owner::Address(owner));
    assert_eq!(object.schema_version, public_standard_asset::SCHEMA_VERSION);
    assert_eq!(object.type_hash, coin_type);
    assert_eq!(
        public_standard_asset::coin_amount(&object.data).unwrap(),
        amount
    );
}

fn expect_tombstone(client: &Client<LoopbackHttpTransport>, id: ObjectId, version: u64) {
    match client.query_object(id).unwrap() {
        HttpObjectQueryResult::Tombstoned {
            last_object_version,
            ..
        } => assert_eq!(last_object_version.get(), version),
        other => panic!("consumed application Coin is not tombstoned: {other:?}"),
    }
}

fn live_coin(
    client: &Client<LoopbackHttpTransport>,
    id: ObjectId,
    version: u64,
    owner: Address,
    amount: u64,
    coin_type: sunrise_edge_client::Digest32,
) -> Vec<u8> {
    let (bytes, actual_version): (Vec<u8>, u64) =
        current_inline(client.query_object(id).unwrap(), "application Coin");
    assert_eq!(actual_version, version);
    let object: Object = objects::decode_object(&bytes).unwrap();
    expect_coin(&object, id, version, owner, amount, coin_type);
    bytes
}

#[test]
#[ignore = "requires the bounded Docker distinct-UID application Coin follow-on fixture"]
fn distinct_uid_application_coin_probe() {
    let mode: String = required("CUSTODY_CREATE_MODE");
    let count: usize = match mode.as_str() {
        "coin-initial" => 0,
        "coin-after-mint-one" => 1,
        "coin-after-split" => 2,
        "coin-after-merge" => 3,
        "coin-after-burn" => 4,
        "coin-after-mint-two" => 5,
        "coin-verify-transfer" => 6,
        other => panic!("unknown application Coin mode {other:?}"),
    };
    let directory: PathBuf = required("CUSTODY_CREATE_DIR").into();
    let publisher: Address = Address::new(required_hex32("CUSTODY_CREATE_PUBLIC_KEY"));
    let recipient: Address = LocalSigner::from_seed([0x74; 32]).address();
    assert_ne!(
        publisher, recipient,
        "existing distinct disposable recipient"
    );
    let client: Client<LoopbackHttpTransport> = connect(&required("CUSTODY_CREATE_ENDPOINT"));
    let protocol: sunrise_edge_devnet::DevnetProtocolContext =
        sunrise_edge_devnet::build_devnet_protocol_context(
            ChainId::new("custody-whole-coin-test").unwrap(),
            Epoch::new(0),
        )
        .unwrap();
    let context: sunrise_edge_client::PublicationContext =
        sunrise_edge_client::PublicationContext::new(
            protocol.chain_id().clone(),
            protocol.resolver().protocol_version(),
            protocol.epoch(),
        )
        .unwrap();
    let (manifest, metadata) = sunrise_edge_devnet::build_paid_genesis_manifest(
        protocol.resolver(),
        &context,
        &[sunrise_edge_devnet::DevOwner::new(*publisher.as_bytes())],
        sunrise_edge_devnet::DevOwner::new(
            *LocalSigner::from_seed([0x7a; 32]).address().as_bytes(),
        ),
    )
    .unwrap();
    let fee_id: ObjectId = metadata.owner_coins[0].fee_coin;
    let spend_id: ObjectId = metadata.owner_coins[0].spend_coin;
    let create_result: PaidExecutionResult =
        decode_paid_execution_result(&read_bounded(&directory.join("create-result.bin"))).unwrap();
    let (asset, cap, definition_type, cap_type) = new_definition_and_cap(
        &create_result,
        protocol.resolver(),
        protocol.epoch(),
        manifest.fee_policy.code.origin(),
    );
    let record: InstanceRecord =
        decode_instance_record(&read_bounded(&directory.join("create-instance.bin"))).unwrap();
    assert_eq!(record.context, context);
    assert_eq!(record.creator, *publisher.as_bytes());
    assert_eq!(record.code, manifest.fee_policy.code);
    assert_eq!(record.initializer, public_standard_asset::INITIALIZER);
    assert_eq!(record.revision, 1);
    let target: sunrise_edge_client::call::InstanceTarget =
        instance_target(protocol.resolver(), &record).unwrap();
    assert_ne!(target, manifest.fee_policy.instance);
    let expected: ExpectedProtocolContext = ExpectedProtocolContext::new(
        protocol.chain_id().clone(),
        protocol.resolver().protocol_version(),
        protocol.epoch(),
        HashSuiteId::new(1),
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
        SignatureSchemeId::Ed25519.as_u16(),
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
        protocol.domain(),
    )
    .unwrap();
    assert_eq!(
        client
            .query_instance(record.creator, record.seed, protocol.resolver(), &expected)
            .unwrap()
            .as_ref(),
        Some(&record)
    );
    let coin_tag: sunrise_edge_client::package_types::ScopedTypeTag =
        public_standard_asset::coin_type_tag(manifest.fee_policy.code.origin(), &asset).unwrap();
    let coin_type: sunrise_edge_client::Digest32 =
        sunrise_edge_client::package_types::derive_scoped_type_id(
            protocol.resolver(),
            protocol.epoch(),
            &coin_tag,
        )
        .unwrap();
    let histories: Vec<Accepted> = (0..count)
        .map(|index: usize| read_accepted(&directory, index, protocol.resolver(), &context))
        .collect();
    let first_coin: Option<ObjectId> = histories
        .first()
        .map(|entry| new_minted_coin_id(&entry.result));
    let split_coin: Option<ObjectId> = histories
        .get(1)
        .map(|entry| new_minted_coin_id(&entry.result));
    let second_coin: Option<ObjectId> = histories
        .get(4)
        .map(|entry| new_minted_coin_id(&entry.result));

    for (index, accepted) in histories.iter().enumerate() {
        let signed: &SignedPaidIntent = &accepted.signed;
        assert_eq!(signed.intent.context, context);
        assert_eq!(signed.intent.sender, *publisher.as_bytes());
        assert_eq!(
            signed.intent.consent.refund_recipient,
            *publisher.as_bytes()
        );
        assert_eq!(
            signed.intent.consent.access,
            sunrise_edge_client::ReservationAccessKind::Write
        );
        assert_eq!(
            signed.intent.consent.max_fee,
            sunrise_edge_client::Amount::new(1_000_000)
        );
        assert_eq!(signed.intent.gas_limit, 200_000);
        let PaidApplication::Call(call) = &signed.intent.application else {
            panic!("paid Call");
        };
        assert_eq!(call.context, context);
        assert_eq!(call.sender, *publisher.as_bytes());
        assert_eq!(call.nonce, NONCES[index]);
        assert_eq!(call.request_id, IDS[index]);
        assert_eq!(call.code, manifest.fee_policy.code);
        assert_eq!(call.instance, target);
        assert_eq!(
            call.type_arguments,
            vec![public_standard_asset::asset_type_argument(&asset)]
        );
        assert_eq!(call.gas_limit, 200_000);
        let (fee_object, fee_bytes) = object_preimage(&directory, "fee", NONCES[index]);
        assert_eq!(fee_object.id, fee_id);
        assert_eq!(fee_object.version, NONCES[index] + 1);
        assert_eq!(fee_object.owner, Owner::Address(publisher));
        assert_eq!(
            fee_object.schema_version,
            public_standard_asset::SCHEMA_VERSION
        );
        let genesis_fee: &Object = &manifest
            .objects
            .iter()
            .find(|entry| entry.object.id == fee_id)
            .unwrap()
            .object;
        assert_eq!(fee_object.type_hash, genesis_fee.type_hash);
        assert!(public_standard_asset::coin_amount(&fee_object.data).unwrap() > 1_000_000);
        expect_reference(
            &signed.intent.consent.source,
            &fee_object,
            &fee_bytes,
            protocol.resolver(),
        );
        let expected_inputs: Vec<(&str, ObjectId, u64, AccessMode)> = match index {
            0 => vec![("cap", cap, 3, AccessMode::Write)],
            1 => vec![("first", first_coin.unwrap(), 1, AccessMode::Write)],
            2 => vec![
                ("first", first_coin.unwrap(), 2, AccessMode::Write),
                ("split", split_coin.unwrap(), 1, AccessMode::Consume),
            ],
            3 => vec![
                ("cap", cap, 4, AccessMode::Write),
                ("first", first_coin.unwrap(), 3, AccessMode::Consume),
            ],
            4 => vec![("cap", cap, 5, AccessMode::Write)],
            5 => vec![("second", second_coin.unwrap(), 1, AccessMode::Write)],
            _ => unreachable!(),
        };
        assert_eq!(call.access.entries.len(), expected_inputs.len());
        for (entry, (role, id, version, access)) in call.access.entries.iter().zip(&expected_inputs)
        {
            let (object, bytes) = object_preimage(&directory, role, NONCES[index]);
            assert_eq!(object.id, *id);
            assert_eq!(object.version, *version);
            assert_eq!(entry.mode, *access);
            expect_reference(&entry.object_ref, &object, &bytes, protocol.resolver());
        }
        let (entrypoint, arguments): (&str, Vec<u8>) = match index {
            0 | 4 => (
                "mint",
                public_standard_asset::mint_arguments(AMOUNT, publisher.as_bytes()).unwrap(),
            ),
            1 => (
                "split",
                public_standard_asset::split_arguments(SPLIT, publisher.as_bytes()).unwrap(),
            ),
            2 => ("merge", public_standard_asset::no_arguments().unwrap()),
            3 => ("burn", public_standard_asset::no_arguments().unwrap()),
            5 => (
                "transfer",
                public_standard_asset::transfer_arguments(recipient.as_bytes()).unwrap(),
            ),
            _ => unreachable!(),
        };
        assert_eq!(call.entrypoint, entrypoint);
        assert_eq!(call.arguments, arguments);
        let result: &PaidExecutionResult = &accepted.result;
        let charged: &sunrise_edge_client::PaidChargedOutcome = result.charged.as_ref().unwrap();
        let allowed_fee_ids: BTreeSet<ObjectId> = [
            Some(fee_id),
            Some(charged.fee_output.id),
            Some(charged.reservation),
            charged.refund_output.as_ref().map(|value| value.id),
        ]
        .into_iter()
        .flatten()
        .collect();
        let mut application_ids: BTreeSet<ObjectId> = BTreeSet::new();
        let mut all_ids: BTreeSet<ObjectId> = BTreeSet::new();
        for effect in &result.effects.object_effects {
            let id: ObjectId = match effect {
                ObjectEffect::Created(object) => object.id,
                ObjectEffect::Mutated { new_object, .. } => new_object.id,
                ObjectEffect::Deleted { id, .. } => *id,
            };
            assert!(all_ids.insert(id), "one effect per object");
            if !allowed_fee_ids.contains(&id) {
                assert!(application_ids.insert(id));
            }
        }
        let expected_app_ids: BTreeSet<ObjectId> = match index {
            0 | 3 => [cap, first_coin.unwrap()].into_iter().collect(),
            1 | 2 => [first_coin.unwrap(), split_coin.unwrap()]
                .into_iter()
                .collect(),
            4 => [cap, second_coin.unwrap()].into_iter().collect(),
            5 => [second_coin.unwrap()].into_iter().collect(),
            _ => unreachable!(),
        };
        assert!(expected_app_ids.is_disjoint(&allowed_fee_ids));
        assert_eq!(application_ids, expected_app_ids);
        match index {
            0 | 4 => {
                let previous: u64 = if index == 0 { 3 } else { 5 };
                let cap_object: &Object = effect_object(result, cap, Some(previous));
                assert_eq!(cap_object.version, previous + 1);
                assert_eq!(cap_object.owner, Owner::Address(publisher));
                assert_eq!(
                    cap_object.schema_version,
                    public_standard_asset::SCHEMA_VERSION
                );
                assert_eq!(cap_object.type_hash, cap_type);
                assert_eq!(
                    public_standard_asset::treasury_supply(&cap_object.data).unwrap(),
                    AMOUNT
                );
                let id: ObjectId = if index == 0 {
                    first_coin.unwrap()
                } else {
                    second_coin.unwrap()
                };
                expect_coin(
                    effect_object(result, id, None),
                    id,
                    1,
                    publisher,
                    AMOUNT,
                    coin_type,
                );
            }
            1 => {
                expect_coin(
                    effect_object(result, first_coin.unwrap(), Some(1)),
                    first_coin.unwrap(),
                    2,
                    publisher,
                    AMOUNT - SPLIT,
                    coin_type,
                );
                expect_coin(
                    effect_object(result, split_coin.unwrap(), None),
                    split_coin.unwrap(),
                    1,
                    publisher,
                    SPLIT,
                    coin_type,
                );
            }
            2 => {
                expect_coin(
                    effect_object(result, first_coin.unwrap(), Some(2)),
                    first_coin.unwrap(),
                    3,
                    publisher,
                    AMOUNT,
                    coin_type,
                );
                expect_deleted(result, split_coin.unwrap(), 1);
            }
            3 => {
                let cap_object: &Object = effect_object(result, cap, Some(4));
                assert_eq!(cap_object.version, 5);
                assert_eq!(cap_object.owner, Owner::Address(publisher));
                assert_eq!(
                    cap_object.schema_version,
                    public_standard_asset::SCHEMA_VERSION
                );
                assert_eq!(cap_object.type_hash, cap_type);
                assert_eq!(
                    public_standard_asset::treasury_supply(&cap_object.data).unwrap(),
                    0
                );
                expect_deleted(result, first_coin.unwrap(), 3);
            }
            5 => expect_coin(
                effect_object(result, second_coin.unwrap(), Some(1)),
                second_coin.unwrap(),
                2,
                recipient,
                AMOUNT,
                coin_type,
            ),
            _ => unreachable!(),
        }
        require_receipt(&client, IDS[index], result.effects.tx_hash, &accepted.bytes);
    }

    let nonce: u64 = 3 + count as u64;
    assert_eq!(
        client.query_next_nonce(publisher).unwrap().next_nonce(),
        nonce
    );
    let cap_version: u64 = [3, 4, 4, 4, 5, 6, 6][count];
    let supply: u64 = [0, AMOUNT, AMOUNT, AMOUNT, 0, AMOUNT, AMOUNT][count];
    let (cap_bytes, actual_cap_version): (Vec<u8>, u64) =
        current_inline(client.query_object(cap).unwrap(), "application TreasuryCap");
    let cap_object: Object = objects::decode_object(&cap_bytes).unwrap();
    assert_eq!(actual_cap_version, cap_version);
    assert_eq!(cap_object.id, cap);
    assert_eq!(cap_object.version, cap_version);
    assert_eq!(cap_object.type_hash, cap_type);
    assert_eq!(
        cap_object.schema_version,
        public_standard_asset::SCHEMA_VERSION
    );
    assert_eq!(cap_object.owner, Owner::Address(publisher));
    assert_eq!(
        public_standard_asset::treasury_supply(&cap_object.data).unwrap(),
        supply
    );
    let (definition_bytes, version) = current_inline(
        client.query_object(asset).unwrap(),
        "application Definition",
    );
    let definition_object: Object = objects::decode_object(&definition_bytes).unwrap();
    assert_eq!(version, 1);
    assert_eq!(definition_object.id, asset);
    assert_eq!(definition_object.type_hash, definition_type);
    assert_eq!(definition_object.owner, Owner::Address(publisher));
    assert_eq!(
        definition_object.schema_version,
        public_standard_asset::SCHEMA_VERSION
    );
    assert_eq!(
        objects::encode_object(effect_object(&create_result, asset, None)).unwrap(),
        definition_bytes
    );
    let (spend_bytes, spend_version) = current_inline(
        client.query_object(spend_id).unwrap(),
        "untouched genesis application Coin",
    );
    assert_eq!(spend_version, 1);
    assert_eq!(
        spend_bytes,
        objects::encode_object(
            &manifest
                .objects
                .iter()
                .find(|entry| entry.object.id == spend_id)
                .unwrap()
                .object
        )
        .unwrap()
    );
    let old_mint: PaidExecutionResult =
        decode_paid_execution_result(&read_bounded(&directory.join("own-mint-result.bin")))
            .unwrap();
    let old_coin: ObjectId = new_minted_coin_id(&old_mint);
    expect_tombstone(&client, old_coin, 1);
    let mut export: Vec<(&str, Vec<u8>)> = vec![("cap", cap_bytes)];
    if (1..4).contains(&count) {
        let (version, amount): (u64, u64) = match count {
            1 => (1, AMOUNT),
            2 => (2, AMOUNT - SPLIT),
            3 => (3, AMOUNT),
            _ => unreachable!(),
        };
        export.push((
            "first",
            live_coin(
                &client,
                first_coin.unwrap(),
                version,
                publisher,
                amount,
                coin_type,
            ),
        ));
    } else if count >= 4 {
        expect_tombstone(&client, first_coin.unwrap(), 3);
    }
    if count == 2 {
        export.push((
            "split",
            live_coin(&client, split_coin.unwrap(), 1, publisher, SPLIT, coin_type),
        ));
    } else if count >= 3 {
        expect_tombstone(&client, split_coin.unwrap(), 1);
    }
    if count >= 5 {
        export.push((
            "second",
            live_coin(
                &client,
                second_coin.unwrap(),
                if count == 5 { 1 } else { 2 },
                if count == 5 { publisher } else { recipient },
                AMOUNT,
                coin_type,
            ),
        ));
    }
    let (fee_bytes, fee_version) =
        current_inline(client.query_object(fee_id).unwrap(), "genesis fee source");
    let fee_object: Object = objects::decode_object(&fee_bytes).unwrap();
    assert_eq!(fee_version, nonce + 1);
    assert_eq!(fee_object.id, fee_id);
    assert_eq!(fee_object.owner, Owner::Address(publisher));
    let genesis_fee: &Object = &manifest
        .objects
        .iter()
        .find(|entry| entry.object.id == fee_id)
        .unwrap()
        .object;
    assert_eq!(fee_object.type_hash, genesis_fee.type_hash);
    assert_eq!(
        fee_object.schema_version,
        public_standard_asset::SCHEMA_VERSION
    );
    assert!(public_standard_asset::coin_amount(&fee_object.data).unwrap() > 1_000_000);
    export.push(("fee", fee_bytes));

    let mut ids: BTreeSet<ObjectId> = [asset, cap, spend_id, fee_id, old_coin]
        .into_iter()
        .collect();
    for accepted in &histories {
        for effect in &accepted.result.effects.object_effects {
            ids.insert(match effect {
                ObjectEffect::Created(object) => object.id,
                ObjectEffect::Mutated { new_object, .. } => new_object.id,
                ObjectEffect::Deleted { id, .. } => *id,
            });
        }
    }
    let before: Vec<(ObjectId, Vec<u8>)> = ids
        .iter()
        .map(|id| (*id, client.query_object(*id).unwrap().encode().unwrap()))
        .collect();
    let receipts: Vec<Vec<u8>> = histories
        .iter()
        .enumerate()
        .map(|(index, accepted)| {
            require_receipt(
                &client,
                IDS[index],
                accepted.result.effects.tx_hash,
                &accepted.bytes,
            )
        })
        .collect();
    for accepted in &histories {
        let replay: PaidExecutionResult = client
            .submit_paid_execution(&accepted.signed, protocol.resolver())
            .unwrap();
        assert_eq!(replay.status, PaidExecutionStatus::Success);
        assert_eq!(
            encode_paid_execution_result(&replay).unwrap(),
            accepted.bytes
        );
        assert_eq!(
            client.query_next_nonce(publisher).unwrap().next_nonce(),
            nonce
        );
    }
    for (id, bytes) in before {
        assert_eq!(client.query_object(id).unwrap().encode().unwrap(), bytes);
    }
    for (index, receipt) in receipts.iter().enumerate() {
        assert_eq!(
            &client
                .query_receipt(RequestId::new(IDS[index]).unwrap())
                .unwrap()
                .encode()
                .unwrap(),
            receipt
        );
    }
    assert_eq!(
        client
            .query_instance(record.creator, record.seed, protocol.resolver(), &expected)
            .unwrap()
            .as_ref(),
        Some(&record)
    );
    for (role, bytes) in export {
        super::write_review_preimage(
            &directory.join(format!("app-coins-{role}-{nonce}.bin")),
            &bytes,
        )
        .unwrap();
    }
    let first_hex: String = first_coin.map(|id| id.to_string()).unwrap_or_default();
    let split_hex: String = split_coin.map(|id| id.to_string()).unwrap_or_default();
    let second_hex: String = second_coin.map(|id| id.to_string()).unwrap_or_default();
    println!(
        "{{\"mode\":\"{mode}\",\"verified\":true,\"stage_count\":{count},\"asset_hex\":\"{asset}\",\"treasury_cap_hex\":\"{cap}\",\"first_coin_hex\":\"{first_hex}\",\"split_coin_hex\":\"{split_hex}\",\"second_coin_hex\":\"{second_hex}\",\"recipient_hex\":\"{recipient}\",\"supply\":{supply},\"cap_version\":{cap_version},\"next_nonce\":{nonce},\"replay_count\":{count},\"replay_equal\":true}}"
    );
}
