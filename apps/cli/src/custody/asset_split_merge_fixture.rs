//! Exact ignored entry point for the contained, distinct-UID split/merge
//! fixture (DR-0249).
//!
//! This probe never builds its own genesis: it only ever runs *after* the
//! existing `custody::asset_fixture::distinct_uid_transfer_probe`'s
//! `"generate"`/`"serve"` modes have booted the same one-owner,
//! one-app-coin/one-fee-coin devnet genesis into this phase's own fresh
//! directories (never the original transfer phase's store). It only adds
//! the two modes that family does not need: `"after-split"` (independent
//! post-split verification plus fresh merge preimages) and `"verify-merge"`
//! (independent post-merge verification plus an idempotent replay of both
//! requests). `#[ignore]` keeps this out of the ordinary `cargo test` gate;
//! the Docker fixture runs it by exact name, like the transfer probe.
//!

use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use sunrise_edge_client::{
    Address, ChainId, Client, Epoch, HttpObjectQueryResult, LoopbackHttpTransport, ObjectEffect,
    ObjectId, Owner, PaidApplication, PaidExecutionResult, PaidExecutionStatus,
    decode_paid_execution_result, decode_signed_paid_intent, encode_paid_execution_result,
};

fn required(name: &str) -> String {
    std::env::var(name).expect("split/merge fixture missing explicit prerequisite")
}

fn required_hex32(name: &'static str) -> [u8; 32] {
    crate::hex::decode_hex_32(name, &required(name))
        .unwrap_or_else(|error| panic!("split/merge fixture: {name} is invalid: {error}"))
}

fn required_u64(name: &str) -> u64 {
    required(name)
        .parse()
        .unwrap_or_else(|error| panic!("split/merge fixture: {name} is invalid: {error}"))
}

fn connect(endpoint: &str) -> Client<LoopbackHttpTransport> {
    let address = endpoint
        .parse()
        .unwrap_or_else(|error| panic!("split/merge fixture: invalid endpoint: {error}"));
    let transport = LoopbackHttpTransport::new(
        address,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        std::num::NonZeroUsize::new(16384).unwrap(),
        std::num::NonZeroUsize::new(1_048_576).unwrap(),
    )
    .unwrap();
    Client::new(transport)
}

fn read_bounded(path: &Path) -> Vec<u8> {
    const CAP: u64 = 1_048_576;
    let mut bytes: Vec<u8> = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .take(CAP + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(
        bytes.len() <= CAP as usize,
        "fixture input exceeds its fixed bound"
    );
    bytes
}

fn current_inline(result: HttpObjectQueryResult, label: &'static str) -> (Vec<u8>, u64) {
    let HttpObjectQueryResult::CurrentInline {
        canonical_object_bytes,
        object_version,
        ..
    } = result
    else {
        panic!("{label} must be a current inline object");
    };
    (canonical_object_bytes, object_version.get())
}

/// Identifies the single Created object this successful paid Call's own
/// effects report, excluding every identity its own charged outcome already
/// explains (fee, refund, reservation). Never derived from, or trusted
/// against, any amount the result alone reports: callers must independently
/// re-query this identifier live afterward.
fn new_created_object_id(result: &PaidExecutionResult) -> ObjectId {
    let charged = result
        .charged
        .as_ref()
        .expect("a successful split must be charged");
    let fee_id: ObjectId = charged.fee_output.id;
    let refund_id: Option<ObjectId> = charged.refund_output.as_ref().map(|output| output.id);
    let reservation_id: ObjectId = charged.reservation;
    let created: Vec<ObjectId> = result
        .effects
        .object_effects
        .iter()
        .filter_map(|effect: &ObjectEffect| match effect {
            ObjectEffect::Created(object)
                if object.id != fee_id
                    && Some(object.id) != refund_id
                    && object.id != reservation_id =>
            {
                Some(object.id)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        created.len(),
        1,
        "split must create exactly one new application Coin beyond its fee/refund/reservation effects"
    );
    created[0]
}

fn require_receipt(
    client: &Client<LoopbackHttpTransport>,
    request_bytes: [u8; 32],
    digest: sunrise_edge_client::Digest32,
) -> Vec<u8> {
    let request: sunrise_edge_client::RequestId =
        sunrise_edge_client::RequestId::new(request_bytes).unwrap();
    let receipt: sunrise_edge_client::HttpReceiptQueryResult =
        client.query_receipt(request).unwrap();
    let sunrise_edge_client::HttpReceiptQueryResult::Present {
        request_id,
        event_digest,
        ..
    } = &receipt
    else {
        panic!("accepted paid request must expose its actual receipt");
    };
    assert_eq!(*request_id, request);
    assert_eq!(*event_digest, digest);
    receipt.encode().unwrap()
}

fn require_mutation(
    result: &PaidExecutionResult,
    id: ObjectId,
    previous: u64,
    bytes: &[u8],
    version: u64,
) {
    let effects: Vec<&ObjectEffect> = result.effects.object_effects.iter().filter(|effect| {
        matches!(effect, ObjectEffect::Mutated { new_object, .. } if new_object.id == id)
    }).collect();
    let [
        ObjectEffect::Mutated {
            previous_version,
            new_object,
        },
    ] = effects.as_slice()
    else {
        panic!("exact one application mutation");
    };
    assert_eq!(*previous_version, previous);
    assert_eq!(new_object.version, version);
    assert_eq!(objects::encode_object(new_object).unwrap(), bytes);
}

#[test]
#[ignore = "requires the bounded Docker distinct-UID split/merge fixture"]
fn distinct_uid_split_merge_probe() {
    let mode: String = required("CUSTODY_SPLIT_MERGE_MODE");
    let directory: PathBuf = required("CUSTODY_SPLIT_MERGE_DIR").into();
    let publisher: Address = Address::new(required_hex32("CUSTODY_SPLIT_MERGE_PUBLIC_KEY"));
    let endpoint: String = required("CUSTODY_SPLIT_MERGE_ENDPOINT");
    let protocol = sunrise_edge_devnet::build_devnet_protocol_context(
        ChainId::new("custody-whole-coin-test").unwrap(),
        Epoch::new(0),
    )
    .unwrap();
    let context: execution::publication::PublicationContext =
        execution::publication::PublicationContext::new(
            protocol.chain_id().clone(),
            protocol.resolver().protocol_version(),
            protocol.epoch(),
        )
        .unwrap();
    let fee_recipient: Address = sunrise_edge_client::LocalSigner::from_seed([0x7A; 32]).address();
    let (manifest, _metadata) = sunrise_edge_devnet::build_paid_genesis_manifest(
        protocol.resolver(),
        &context,
        &[sunrise_edge_devnet::DevOwner::new(*publisher.as_bytes())],
        sunrise_edge_devnet::DevOwner::new(*fee_recipient.as_bytes()),
    )
    .unwrap();
    let client: Client<LoopbackHttpTransport> = connect(&endpoint);

    match mode.as_str() {
        "after-split" => {
            let original_coin: ObjectId =
                ObjectId::new(required_hex32("CUSTODY_SPLIT_MERGE_ORIGINAL_COIN_HEX"));
            let fee_coin: ObjectId =
                ObjectId::new(required_hex32("CUSTODY_SPLIT_MERGE_FEE_COIN_HEX"));
            let split_amount: u64 = required_u64("CUSTODY_SPLIT_MERGE_SPLIT_AMOUNT");
            let held: u64 = sunrise_edge_devnet::DEVNET_PAID_SPEND_COIN_BALANCE;
            assert!(split_amount > 0 && split_amount < held);
            let remainder: u64 = held.checked_sub(split_amount).unwrap();

            let signed_bytes: Vec<u8> = read_bounded(&directory.join("split-submission.bin"));
            let decoded = decode_signed_paid_intent(&signed_bytes).unwrap();
            execution::paid_execution::authenticate_paid_intent(
                protocol.resolver(),
                &context,
                &signed_bytes,
            )
            .unwrap();
            assert_eq!(
                execution::paid_execution::encode_signed_paid_intent(&decoded).unwrap(),
                signed_bytes
            );
            assert_eq!(decoded.intent.context, context);
            assert_eq!(decoded.intent.request_id, [0x91; 32]);
            assert_eq!(
                decoded.intent.consent.refund_recipient,
                *publisher.as_bytes()
            );
            assert_eq!(decoded.intent.sender, *publisher.as_bytes());
            assert_eq!(decoded.intent.nonce, 0);
            let PaidApplication::Call(call) = &decoded.intent.application else {
                panic!("split must be a paid Call application");
            };
            assert_eq!(call.entrypoint, "split");
            assert_eq!(call.code, manifest.fee_policy.code);
            assert_eq!(call.instance, manifest.fee_policy.instance);
            assert_eq!(
                decoded.intent.consent.access,
                sunrise_edge_client::ReservationAccessKind::Write
            );
            assert_eq!(
                decoded.intent.consent.max_fee,
                sunrise_edge_client::Amount::new(1_000_000)
            );
            assert_eq!(decoded.intent.gas_limit, 200_000);
            assert_eq!(call.gas_limit, 200_000);
            assert_eq!(call.access.entries.len(), 1);
            assert_eq!(call.access.entries[0].object_ref.id, original_coin);
            assert_eq!(
                call.access.entries[0].mode,
                sunrise_edge_client::AccessMode::Write
            );
            assert_eq!(
                call.arguments,
                public_standard_asset::split_arguments(split_amount, publisher.as_bytes()).unwrap()
            );
            assert_eq!(decoded.intent.consent.source.id, fee_coin);

            let result_bytes: Vec<u8> = read_bounded(&directory.join("split-result.bin"));
            let result: PaidExecutionResult = decode_paid_execution_result(&result_bytes).unwrap();
            assert_eq!(result.status, PaidExecutionStatus::Success);
            assert_eq!(result.request_id, decoded.intent.request_id);
            assert_eq!(
                result.effects.tx_hash,
                execution::paid_execution::paid_invocation_digest(protocol.resolver(), &decoded)
                    .unwrap()
            );
            // Canonical round-trip: the stored result file is exactly what
            // this decoded value re-encodes to, never a loosely equivalent
            // reinterpretation of it.
            assert_eq!(encode_paid_execution_result(&result).unwrap(), result_bytes);

            let new_coin: ObjectId = new_created_object_id(&result);

            // Never trust the result file's embedded amount alone: both
            // coins are independently re-queried live, and every assertion
            // below is against that fresh query, not the decoded result.
            let (original_bytes, original_version) = current_inline(
                client.query_object(original_coin).unwrap(),
                "post-split original coin",
            );
            let original_object = objects::decode_object(&original_bytes).unwrap();
            assert_eq!(original_object.owner, Owner::Address(publisher));
            assert_eq!(
                public_standard_asset::coin_amount(&original_object.data).unwrap(),
                remainder
            );
            assert_eq!(original_version, 2);
            require_mutation(
                &result,
                original_coin,
                call.access.entries[0].object_ref.version,
                &original_bytes,
                original_version,
            );

            let (new_bytes, new_version) = current_inline(
                client.query_object(new_coin).unwrap(),
                "split's new application coin",
            );
            let new_object = objects::decode_object(&new_bytes).unwrap();
            assert_eq!(new_object.owner, Owner::Address(publisher));
            assert_eq!(
                public_standard_asset::coin_amount(&new_object.data).unwrap(),
                split_amount
            );
            assert_eq!(new_version, 1);
            let created: Vec<&sunrise_edge_client::Object> = result
                .effects
                .object_effects
                .iter()
                .filter_map(|effect| match effect {
                    ObjectEffect::Created(object) if object.id == new_coin => Some(object),
                    _ => None,
                })
                .collect();
            let [new_effect] = created.as_slice() else {
                panic!("one exact new application Coin");
            };
            assert_eq!(objects::encode_object(new_effect).unwrap(), new_bytes);

            let next_nonce: u64 = client.query_next_nonce(publisher).unwrap().next_nonce();
            assert_eq!(next_nonce, 1);

            let (fee_bytes, _fee_version) = current_inline(
                client.query_object(fee_coin).unwrap(),
                "fee coin after split's settlement",
            );

            // Bounded private preimages at their actual current version, for
            // the offline `custody prepare-merge` leg; never the stale
            // genesis fee.bin, which `settle` has already superseded.
            super::write_review_preimage(&directory.join("into.bin"), &original_bytes).unwrap();
            super::write_review_preimage(&directory.join("from.bin"), &new_bytes).unwrap();
            super::write_review_preimage(&directory.join("fee.bin"), &fee_bytes).unwrap();

            println!(
                "{{\"mode\":\"after-split\",\"verified\":true,\"original_coin_hex\":\"{original_coin}\",\"new_coin_hex\":\"{new_coin}\",\"split_amount\":{split_amount},\"remaining_amount\":{remainder},\"next_nonce\":{next_nonce}}}",
            );
        }
        "verify-merge" => {
            let original_coin: ObjectId =
                ObjectId::new(required_hex32("CUSTODY_SPLIT_MERGE_ORIGINAL_COIN_HEX"));
            let new_coin: ObjectId =
                ObjectId::new(required_hex32("CUSTODY_SPLIT_MERGE_NEW_COIN_HEX"));
            let recombined_amount: u64 = required_u64("CUSTODY_SPLIT_MERGE_RECOMBINED_AMOUNT");
            assert_eq!(
                recombined_amount,
                sunrise_edge_devnet::DEVNET_PAID_SPEND_COIN_BALANCE
            );
            let fee_coin: ObjectId =
                ObjectId::new(required_hex32("CUSTODY_SPLIT_MERGE_FEE_COIN_HEX"));

            let merge_signed: Vec<u8> = read_bounded(&directory.join("merge-submission.bin"));
            let merge_decoded = decode_signed_paid_intent(&merge_signed).unwrap();
            execution::paid_execution::authenticate_paid_intent(
                protocol.resolver(),
                &context,
                &merge_signed,
            )
            .unwrap();
            assert_eq!(
                execution::paid_execution::encode_signed_paid_intent(&merge_decoded).unwrap(),
                merge_signed
            );
            assert_eq!(merge_decoded.intent.context, context);
            assert_eq!(merge_decoded.intent.request_id, [0x92; 32]);
            assert_eq!(
                merge_decoded.intent.consent.refund_recipient,
                *publisher.as_bytes()
            );
            assert_eq!(merge_decoded.intent.sender, *publisher.as_bytes());
            assert_eq!(merge_decoded.intent.nonce, 1);
            let PaidApplication::Call(merge_call) = &merge_decoded.intent.application else {
                panic!("merge must be a paid Call application");
            };
            assert_eq!(merge_call.entrypoint, "merge");
            assert_eq!(merge_call.code, manifest.fee_policy.code);
            assert_eq!(merge_call.instance, manifest.fee_policy.instance);
            assert_eq!(
                merge_decoded.intent.consent.access,
                sunrise_edge_client::ReservationAccessKind::Write
            );
            assert_eq!(
                merge_decoded.intent.consent.max_fee,
                sunrise_edge_client::Amount::new(1_000_000)
            );
            assert_eq!(merge_decoded.intent.gas_limit, 200_000);
            assert_eq!(merge_call.gas_limit, 200_000);
            assert_eq!(merge_call.access.entries.len(), 2);
            assert_eq!(merge_call.access.entries[0].object_ref.id, original_coin);
            assert_eq!(merge_call.access.entries[1].object_ref.id, new_coin);
            assert_eq!(merge_decoded.intent.consent.source.id, fee_coin);
            assert_eq!(merge_decoded.intent.consent.source.version, 2);
            assert_eq!(
                merge_call.access.entries[0].mode,
                sunrise_edge_client::AccessMode::Write
            );
            assert_eq!(
                merge_call.access.entries[1].mode,
                sunrise_edge_client::AccessMode::Consume
            );
            assert_eq!(
                merge_call.arguments,
                public_standard_asset::no_arguments().unwrap()
            );

            let merge_result_bytes: Vec<u8> = read_bounded(&directory.join("merge-result.bin"));
            let merge_result: PaidExecutionResult =
                decode_paid_execution_result(&merge_result_bytes).unwrap();
            assert_eq!(merge_result.status, PaidExecutionStatus::Success);
            assert_eq!(merge_result.request_id, merge_decoded.intent.request_id);
            assert_eq!(
                merge_result.effects.tx_hash,
                execution::paid_execution::paid_invocation_digest(
                    protocol.resolver(),
                    &merge_decoded
                )
                .unwrap()
            );
            assert_eq!(
                encode_paid_execution_result(&merge_result).unwrap(),
                merge_result_bytes
            );
            let consumed: bool = merge_result.effects.object_effects.iter().any(
                |effect| matches!(effect, ObjectEffect::Deleted { id, version } if *id == new_coin && *version == 1),
            );
            assert!(
                consumed,
                "merge must consume the split's new application coin"
            );

            let (into_bytes, into_version) = current_inline(
                client.query_object(original_coin).unwrap(),
                "post-merge destination coin",
            );
            let into_object = objects::decode_object(&into_bytes).unwrap();
            assert_eq!(into_object.owner, Owner::Address(publisher));
            assert_eq!(
                public_standard_asset::coin_amount(&into_object.data).unwrap(),
                recombined_amount
            );
            assert_eq!(into_version, 3);
            require_mutation(
                &merge_result,
                original_coin,
                merge_call.access.entries[0].object_ref.version,
                &into_bytes,
                into_version,
            );

            assert!(
                matches!(
                    client.query_object(new_coin).unwrap(),
                    HttpObjectQueryResult::Tombstoned { .. }
                ),
                "the consumed split application coin must be tombstoned, not merely absent"
            );

            let next_nonce: u64 = client.query_next_nonce(publisher).unwrap().next_nonce();
            assert_eq!(next_nonce, 2);

            // Idempotent receipt replay of *both* requests: neither consumes
            // a fresh nonce or mutates state beyond what already happened.
            let split_signed: Vec<u8> = read_bounded(&directory.join("split-submission.bin"));
            let split_decoded = decode_signed_paid_intent(&split_signed).unwrap();
            let split_result_bytes: Vec<u8> = read_bounded(&directory.join("split-result.bin"));
            let split_result: PaidExecutionResult =
                decode_paid_execution_result(&split_result_bytes).unwrap();
            let mut observed_ids: std::collections::BTreeSet<ObjectId> =
                std::collections::BTreeSet::new();
            for effect in split_result
                .effects
                .object_effects
                .iter()
                .chain(merge_result.effects.object_effects.iter())
            {
                let id: ObjectId = match effect {
                    ObjectEffect::Created(object) => object.id,
                    ObjectEffect::Mutated { new_object, .. } => new_object.id,
                    ObjectEffect::Deleted { id, .. } => *id,
                };
                observed_ids.insert(id);
            }
            let before: Vec<(ObjectId, Vec<u8>)> = observed_ids
                .iter()
                .map(|id| (*id, client.query_object(*id).unwrap().encode().unwrap()))
                .collect();
            let split_receipt: Vec<u8> =
                require_receipt(&client, [0x91; 32], split_result.effects.tx_hash);
            let merge_receipt: Vec<u8> =
                require_receipt(&client, [0x92; 32], merge_result.effects.tx_hash);
            let split_replay: PaidExecutionResult = client
                .submit_paid_execution(&split_decoded, protocol.resolver())
                .unwrap();
            assert_eq!(split_replay.status, PaidExecutionStatus::Success);
            assert_eq!(
                encode_paid_execution_result(&split_replay).unwrap(),
                split_result_bytes
            );
            assert_eq!(client.query_next_nonce(publisher).unwrap().next_nonce(), 2);

            let merge_replay: PaidExecutionResult = client
                .submit_paid_execution(&merge_decoded, protocol.resolver())
                .unwrap();
            assert_eq!(merge_replay.status, PaidExecutionStatus::Success);
            assert_eq!(
                encode_paid_execution_result(&merge_replay).unwrap(),
                merge_result_bytes
            );
            assert_eq!(client.query_next_nonce(publisher).unwrap().next_nonce(), 2);
            for (id, bytes) in before {
                assert_eq!(client.query_object(id).unwrap().encode().unwrap(), bytes);
            }
            assert_eq!(
                client
                    .query_receipt(sunrise_edge_client::RequestId::new([0x91; 32]).unwrap())
                    .unwrap()
                    .encode()
                    .unwrap(),
                split_receipt
            );
            assert_eq!(
                client
                    .query_receipt(sunrise_edge_client::RequestId::new([0x92; 32]).unwrap())
                    .unwrap()
                    .encode()
                    .unwrap(),
                merge_receipt
            );

            println!(
                "{{\"mode\":\"verify-merge\",\"verified\":true,\"recombined_amount\":{recombined_amount},\"next_nonce\":{next_nonce},\"replay_equal\":true}}",
            );
        }
        other => panic!("unknown split/merge fixture mode {other:?}"),
    }
    assert!(Path::new(&directory).is_dir());
}
