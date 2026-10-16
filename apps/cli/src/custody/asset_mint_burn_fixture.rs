//! Exact ignored entry point for the contained, distinct-UID mint/burn
//! fixture (DR-0253).
//!
//! Like `asset_split_merge_fixture`, this probe never installs or serves its
//! own genesis: the Docker fixture still boots the one-owner, one-app-coin/
//! one-fee-coin devnet genesis via the existing
//! `custody::asset_fixture::distinct_uid_transfer_probe`'s `"generate"`/
//! `"serve"` modes, into this phase's own fresh directories. Those modes
//! never export a `TreasuryCap` preimage (the transfer/split/merge families
//! never need one), so this module adds `"generate-cap"`, a pure,
//! side-effect-free rebuild of the identical deterministic genesis manifest
//! that independently locates and exports the `TreasuryCap` object the
//! mint/burn family needs as its own owned input. It then adds the two
//! verification modes this family needs: `"after-mint"` (independent
//! post-mint verification of the increased supply and the newly created
//! recipient Coin, plus fresh burn preimages) and `"verify-burn"`
//! (independent post-burn verification of the decreased supply and the
//! tombstoned consumed Coin, plus an idempotent replay of both requests).
//! `#[ignore]` keeps this out of the ordinary `cargo test` gate; the Docker
//! fixture runs it by its exact name, like the transfer and split/merge
//! probes.

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
    std::env::var(name).expect("mint/burn fixture missing explicit prerequisite")
}

fn required_hex32(name: &'static str) -> [u8; 32] {
    crate::hex::decode_hex_32(name, &required(name))
        .unwrap_or_else(|error| panic!("mint/burn fixture: {name} is invalid: {error}"))
}

fn required_u64(name: &str) -> u64 {
    required(name)
        .parse()
        .unwrap_or_else(|error| panic!("mint/burn fixture: {name} is invalid: {error}"))
}

fn connect(endpoint: &str) -> Client<LoopbackHttpTransport> {
    let address = endpoint
        .parse()
        .unwrap_or_else(|error| panic!("mint/burn fixture: invalid endpoint: {error}"));
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
        .expect("a successful mint must be charged");
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
        "mint must create exactly one new application Coin beyond its fee/refund/reservation effects"
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
#[ignore = "requires the bounded Docker distinct-UID mint/burn fixture"]
fn distinct_uid_mint_burn_probe() {
    let mode: String = required("CUSTODY_MINT_BURN_MODE");
    let directory: PathBuf = required("CUSTODY_MINT_BURN_DIR").into();
    let publisher: Address = Address::new(required_hex32("CUSTODY_MINT_BURN_PUBLIC_KEY"));
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
    let (manifest, metadata) = sunrise_edge_devnet::build_paid_genesis_manifest(
        protocol.resolver(),
        &context,
        &[sunrise_edge_devnet::DevOwner::new(*publisher.as_bytes())],
        sunrise_edge_devnet::DevOwner::new(*fee_recipient.as_bytes()),
    )
    .unwrap();
    let cap_id: ObjectId = metadata.treasury_cap_id;
    let genesis_fee_coin: ObjectId = metadata.owner_coins[0].fee_coin;
    let genesis_cap_object = &manifest
        .objects
        .iter()
        .find(|entry| entry.object.id == cap_id)
        .unwrap()
        .object;
    let supply_before_mint: u64 =
        public_standard_asset::treasury_supply(&genesis_cap_object.data).unwrap();

    match mode.as_str() {
        "generate-cap" => {
            let digest =
                node_core::genesis::genesis_manifest_commitment(protocol.resolver(), &manifest)
                    .unwrap();
            let cap_bytes: Vec<u8> = objects::encode_object(genesis_cap_object).unwrap();
            super::write_review_preimage(&directory.join("cap.bin"), &cap_bytes).unwrap();
            println!(
                "{{\"mode\":\"generate-cap\",\"cap_hex\":\"{cap_id}\",\"digest\":\"{}\"}}",
                crate::hex::encode_hex(&digest.bytes()),
            );
        }
        "after-mint" => {
            let fee_coin: ObjectId = ObjectId::new(required_hex32("CUSTODY_MINT_BURN_FEE_COIN_HEX"));
            assert_eq!(
                fee_coin, genesis_fee_coin,
                "fee coin id must match the independently derived genesis fee coin"
            );
            let expected_cap: ObjectId = ObjectId::new(required_hex32("CUSTODY_MINT_BURN_CAP_HEX"));
            assert_eq!(
                expected_cap, cap_id,
                "cap id must match the independently derived genesis TreasuryCap"
            );
            let mint_amount: u64 = required_u64("CUSTODY_MINT_BURN_MINT_AMOUNT");
            assert!(mint_amount > 0);
            let supply_after: u64 = supply_before_mint.checked_add(mint_amount).unwrap();

            let endpoint: String = required("CUSTODY_MINT_BURN_ENDPOINT");
            let client: Client<LoopbackHttpTransport> = connect(&endpoint);

            let signed_bytes: Vec<u8> = read_bounded(&directory.join("mint-submission.bin"));
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
            assert_eq!(decoded.intent.request_id, [0x93; 32]);
            assert_eq!(
                decoded.intent.consent.refund_recipient,
                *publisher.as_bytes()
            );
            assert_eq!(decoded.intent.sender, *publisher.as_bytes());
            assert_eq!(decoded.intent.nonce, 0);
            let PaidApplication::Call(call) = &decoded.intent.application else {
                panic!("mint must be a paid Call application");
            };
            assert_eq!(call.entrypoint, "mint");
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
            assert_eq!(call.access.entries[0].object_ref.id, cap_id);
            assert_eq!(
                call.access.entries[0].mode,
                sunrise_edge_client::AccessMode::Write
            );
            assert_eq!(
                call.arguments,
                public_standard_asset::mint_arguments(mint_amount, publisher.as_bytes()).unwrap()
            );
            assert_eq!(decoded.intent.consent.source.id, fee_coin);

            let result_bytes: Vec<u8> = read_bounded(&directory.join("mint-result.bin"));
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

            // Never trust the result file's embedded amount alone: both the
            // cap and the newly created coin are independently re-queried
            // live, and every assertion below is against that fresh query,
            // not the decoded result.
            let (cap_bytes, cap_version) = current_inline(
                client.query_object(cap_id).unwrap(),
                "post-mint treasury cap",
            );
            let cap_object = objects::decode_object(&cap_bytes).unwrap();
            assert_eq!(cap_object.owner, Owner::Address(publisher));
            assert_eq!(
                public_standard_asset::treasury_supply(&cap_object.data).unwrap(),
                supply_after
            );
            assert_eq!(cap_version, 2);
            require_mutation(
                &result,
                cap_id,
                call.access.entries[0].object_ref.version,
                &cap_bytes,
                cap_version,
            );

            let (new_bytes, new_version) = current_inline(
                client.query_object(new_coin).unwrap(),
                "mint's new recipient coin",
            );
            let new_object = objects::decode_object(&new_bytes).unwrap();
            assert_eq!(new_object.owner, Owner::Address(publisher));
            assert_eq!(
                public_standard_asset::coin_amount(&new_object.data).unwrap(),
                mint_amount
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
                panic!("one exact new recipient Coin");
            };
            assert_eq!(objects::encode_object(new_effect).unwrap(), new_bytes);

            let next_nonce: u64 = client.query_next_nonce(publisher).unwrap().next_nonce();
            assert_eq!(next_nonce, 1);

            let (fee_bytes, _fee_version) = current_inline(
                client.query_object(fee_coin).unwrap(),
                "fee coin after mint's settlement",
            );

            // Bounded private preimages at their actual current version, for
            // the offline `custody prepare-burn` leg; never the stale
            // genesis fee.bin, which `settle` has already superseded.
            super::write_review_preimage(&directory.join("cap.bin"), &cap_bytes).unwrap();
            super::write_review_preimage(&directory.join("coin.bin"), &new_bytes).unwrap();
            super::write_review_preimage(&directory.join("fee.bin"), &fee_bytes).unwrap();

            println!(
                "{{\"mode\":\"after-mint\",\"verified\":true,\"cap_hex\":\"{cap_id}\",\"new_coin_hex\":\"{new_coin}\",\"mint_amount\":{mint_amount},\"supply_after\":{supply_after},\"next_nonce\":{next_nonce}}}",
            );
        }
        "verify-burn" => {
            let expected_cap: ObjectId = ObjectId::new(required_hex32("CUSTODY_MINT_BURN_CAP_HEX"));
            assert_eq!(expected_cap, cap_id);
            let fee_coin: ObjectId = ObjectId::new(required_hex32("CUSTODY_MINT_BURN_FEE_COIN_HEX"));
            assert_eq!(fee_coin, genesis_fee_coin);
            let burned_coin: ObjectId =
                ObjectId::new(required_hex32("CUSTODY_MINT_BURN_NEW_COIN_HEX"));

            let endpoint: String = required("CUSTODY_MINT_BURN_ENDPOINT");
            let client: Client<LoopbackHttpTransport> = connect(&endpoint);

            let burn_signed: Vec<u8> = read_bounded(&directory.join("burn-submission.bin"));
            let burn_decoded = decode_signed_paid_intent(&burn_signed).unwrap();
            execution::paid_execution::authenticate_paid_intent(
                protocol.resolver(),
                &context,
                &burn_signed,
            )
            .unwrap();
            assert_eq!(
                execution::paid_execution::encode_signed_paid_intent(&burn_decoded).unwrap(),
                burn_signed
            );
            assert_eq!(burn_decoded.intent.context, context);
            assert_eq!(burn_decoded.intent.request_id, [0x94; 32]);
            assert_eq!(
                burn_decoded.intent.consent.refund_recipient,
                *publisher.as_bytes()
            );
            assert_eq!(burn_decoded.intent.sender, *publisher.as_bytes());
            assert_eq!(burn_decoded.intent.nonce, 1);
            let PaidApplication::Call(burn_call) = &burn_decoded.intent.application else {
                panic!("burn must be a paid Call application");
            };
            assert_eq!(burn_call.entrypoint, "burn");
            assert_eq!(burn_call.code, manifest.fee_policy.code);
            assert_eq!(burn_call.instance, manifest.fee_policy.instance);
            assert_eq!(
                burn_decoded.intent.consent.access,
                sunrise_edge_client::ReservationAccessKind::Write
            );
            assert_eq!(
                burn_decoded.intent.consent.max_fee,
                sunrise_edge_client::Amount::new(1_000_000)
            );
            assert_eq!(burn_decoded.intent.gas_limit, 200_000);
            assert_eq!(burn_call.gas_limit, 200_000);
            assert_eq!(burn_call.access.entries.len(), 2);
            assert_eq!(burn_call.access.entries[0].object_ref.id, cap_id);
            assert_eq!(burn_call.access.entries[1].object_ref.id, burned_coin);
            assert_eq!(burn_decoded.intent.consent.source.id, fee_coin);
            assert_eq!(
                burn_call.access.entries[0].mode,
                sunrise_edge_client::AccessMode::Write
            );
            assert_eq!(
                burn_call.access.entries[1].mode,
                sunrise_edge_client::AccessMode::Consume
            );
            assert_eq!(
                burn_call.arguments,
                public_standard_asset::no_arguments().unwrap()
            );

            let burn_result_bytes: Vec<u8> = read_bounded(&directory.join("burn-result.bin"));
            let burn_result: PaidExecutionResult =
                decode_paid_execution_result(&burn_result_bytes).unwrap();
            assert_eq!(burn_result.status, PaidExecutionStatus::Success);
            assert_eq!(burn_result.request_id, burn_decoded.intent.request_id);
            assert_eq!(
                burn_result.effects.tx_hash,
                execution::paid_execution::paid_invocation_digest(
                    protocol.resolver(),
                    &burn_decoded
                )
                .unwrap()
            );
            assert_eq!(
                encode_paid_execution_result(&burn_result).unwrap(),
                burn_result_bytes
            );
            let consumed: bool = burn_result.effects.object_effects.iter().any(
                |effect| matches!(effect, ObjectEffect::Deleted { id, version } if *id == burned_coin && *version == 1),
            );
            assert!(consumed, "burn must consume the minted coin");

            let (cap_bytes, cap_version) = current_inline(
                client.query_object(cap_id).unwrap(),
                "post-burn treasury cap",
            );
            let cap_object = objects::decode_object(&cap_bytes).unwrap();
            assert_eq!(cap_object.owner, Owner::Address(publisher));
            assert_eq!(
                public_standard_asset::treasury_supply(&cap_object.data).unwrap(),
                supply_before_mint
            );
            assert_eq!(cap_version, 3);
            require_mutation(
                &burn_result,
                cap_id,
                burn_call.access.entries[0].object_ref.version,
                &cap_bytes,
                cap_version,
            );

            assert!(
                matches!(
                    client.query_object(burned_coin).unwrap(),
                    HttpObjectQueryResult::Tombstoned { .. }
                ),
                "the consumed minted coin must be tombstoned, not merely absent"
            );

            let next_nonce: u64 = client.query_next_nonce(publisher).unwrap().next_nonce();
            assert_eq!(next_nonce, 2);

            // Idempotent receipt replay of *both* requests: neither consumes
            // a fresh nonce or mutates state beyond what already happened.
            let mint_signed: Vec<u8> = read_bounded(&directory.join("mint-submission.bin"));
            let mint_decoded = decode_signed_paid_intent(&mint_signed).unwrap();
            let mint_result_bytes: Vec<u8> = read_bounded(&directory.join("mint-result.bin"));
            let mint_result: PaidExecutionResult =
                decode_paid_execution_result(&mint_result_bytes).unwrap();
            let mut observed_ids: std::collections::BTreeSet<ObjectId> =
                std::collections::BTreeSet::new();
            for effect in mint_result
                .effects
                .object_effects
                .iter()
                .chain(burn_result.effects.object_effects.iter())
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
            let mint_receipt: Vec<u8> =
                require_receipt(&client, [0x93; 32], mint_result.effects.tx_hash);
            let burn_receipt: Vec<u8> =
                require_receipt(&client, [0x94; 32], burn_result.effects.tx_hash);
            let mint_replay: PaidExecutionResult = client
                .submit_paid_execution(&mint_decoded, protocol.resolver())
                .unwrap();
            assert_eq!(mint_replay.status, PaidExecutionStatus::Success);
            assert_eq!(
                encode_paid_execution_result(&mint_replay).unwrap(),
                mint_result_bytes
            );
            assert_eq!(client.query_next_nonce(publisher).unwrap().next_nonce(), 2);

            let burn_replay: PaidExecutionResult = client
                .submit_paid_execution(&burn_decoded, protocol.resolver())
                .unwrap();
            assert_eq!(burn_replay.status, PaidExecutionStatus::Success);
            assert_eq!(
                encode_paid_execution_result(&burn_replay).unwrap(),
                burn_result_bytes
            );
            assert_eq!(client.query_next_nonce(publisher).unwrap().next_nonce(), 2);
            for (id, bytes) in before {
                assert_eq!(client.query_object(id).unwrap().encode().unwrap(), bytes);
            }
            assert_eq!(
                client
                    .query_receipt(sunrise_edge_client::RequestId::new([0x93; 32]).unwrap())
                    .unwrap()
                    .encode()
                    .unwrap(),
                mint_receipt
            );
            assert_eq!(
                client
                    .query_receipt(sunrise_edge_client::RequestId::new([0x94; 32]).unwrap())
                    .unwrap()
                    .encode()
                    .unwrap(),
                burn_receipt
            );

            println!(
                "{{\"mode\":\"verify-burn\",\"verified\":true,\"supply_after_burn\":{supply_before_mint},\"next_nonce\":{next_nonce},\"replay_equal\":true}}",
            );
        }
        other => panic!("unknown mint/burn fixture mode {other:?}"),
    }
    assert!(Path::new(&directory).is_dir());
}
