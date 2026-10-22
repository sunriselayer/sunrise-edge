//! Exact ignored entry point for the contained, distinct-UID create-asset
//! fixture (M2 create-asset interface).
//!
//! This probe never builds its own genesis: it only ever runs *after* the
//! existing `custody::asset_fixture::distinct_uid_transfer_probe`'s
//! `"generate"`/`"serve"` modes have booted the same one-owner,
//! one-app-coin/one-fee-coin devnet genesis into this phase's own fresh
//! directories (never the original transfer/split-merge/mint-burn phases'
//! stores). It independently verifies a real, already-captured
//! `create-asset` CLI submission/result/instance-ref triple against the live
//! backend: the signed `Instantiate` frame, the newly created Definition and
//! zero-supply TreasuryCap, the durably queryable `InstanceRecord`, the bound
//! non-empty `NodeDedupRecord`, and an idempotent replay of the exact
//! captured signed bytes.
//!
//! Custody mediates this family too (DR-0255/M2): `custody prepare-
//! create`/`approve-create`/`sign-create`/`serve-create` under the closed
//! wire kind 5 (see `custody::asset_create`, `asset_create_wire`,
//! `asset_create_commands`). The Docker orchestration
//! (`scripts/check-docker-custody-fixture-1013.mjs`'s `phase_create_asset`)
//! drives the real protected round trip — prepare/approve (real PTY, full
//! typed confirmation)/offline sign-create against a real `serve-create`
//! process under the distinct custody UID, then the actual `standard_asset
//! create-asset` CLI itself signing through the same custody socket — and
//! this module independently verifies the resulting submission/result/
//! instance-ref triple against the live backend.
//!
//! `#[ignore]` keeps this out of the ordinary `cargo test` gate; the Docker
//! fixture runs it by its exact name, like the transfer/split-merge/mint-burn
//! probes.

use std::{
    collections::BTreeSet,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use sunrise_edge_client::{
    Address, ChainId, Client, ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, Epoch,
    ExpectedProtocolContext, HashSuiteId, HttpObjectQueryResult, LoopbackHttpTransport, Object,
    ObjectEffect, ObjectId, Owner, PaidApplication, PaidExecutionResult, PaidExecutionStatus,
    RequestId, SignatureSchemeId, decode_paid_execution_result, decode_signed_paid_intent,
    encode_paid_execution_result,
    local_execution::{InstanceRecord, decode_instance_record, instance_target},
};

/// Never used elsewhere in this fixture family: the custody lifecycle,
/// transfer, split/merge and mint/burn phases already occupy request IDs
/// 0x5a, 0x11, 0x22, 0x33, 0x44, 0x75, 0x91, 0x92, 0x93 and 0x94 (0x99 is a
/// public key value, `WRONG_PUBLIC_KEY_HEX`, never a request ID).
const CREATE_REQUEST_ID: [u8; 32] = [0x95; 32];

fn required(name: &str) -> String {
    std::env::var(name).expect("create-asset fixture missing explicit prerequisite")
}

fn required_hex32(name: &'static str) -> [u8; 32] {
    crate::hex::decode_hex_32(name, &required(name))
        .unwrap_or_else(|error| panic!("create-asset fixture: {name} is invalid: {error}"))
}

fn connect(endpoint: &str) -> Client<LoopbackHttpTransport> {
    let address = endpoint
        .parse()
        .unwrap_or_else(|error| panic!("create-asset fixture: invalid endpoint: {error}"));
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

/// Identifies the exact two objects a successful create-asset `Instantiate`
/// creates beyond its own fee/refund/reservation effects: the Definition and
/// the zero-supply TreasuryCap, each identified by its own independently
/// derived scoped nominal type hash (never by trusting effect order, body
/// shape, or any embedded amount). Returns both object IDs plus the two
/// derived type hashes, so callers can repeat the same type check against a
/// later live query instead of only this one decoded result.
fn new_definition_and_cap(
    result: &PaidExecutionResult,
    resolver: &sunrise_edge_client::HashSuiteResolver,
    epoch: Epoch,
    origin: &sunrise_edge_client::PackageOrigin,
) -> (
    ObjectId,
    ObjectId,
    sunrise_edge_client::Digest32,
    sunrise_edge_client::Digest32,
) {
    let charged = result
        .charged
        .as_ref()
        .expect("a successful create-asset must be charged");
    let fee_id: ObjectId = charged.fee_output.id;
    let refund_id: Option<ObjectId> = charged.refund_output.as_ref().map(|output| output.id);
    let reservation_id: ObjectId = charged.reservation;
    let created: Vec<&Object> = result
        .effects
        .object_effects
        .iter()
        .filter_map(|effect: &ObjectEffect| match effect {
            ObjectEffect::Created(object)
                if object.id != fee_id
                    && Some(object.id) != refund_id
                    && object.id != reservation_id =>
            {
                Some(object)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        created.len(),
        2,
        "create-asset initializer must create exactly Definition and TreasuryCap beyond its fee/refund/reservation effects"
    );
    let definition_type: sunrise_edge_client::Digest32 =
        sunrise_edge_client::package_types::derive_scoped_type_id(
            resolver,
            epoch,
            &public_standard_asset::definition_type_tag(origin).unwrap(),
        )
        .unwrap();
    let definition: &Object = created
        .iter()
        .copied()
        .find(|object: &&Object| object.type_hash == definition_type)
        .expect("create-asset initializer omitted Definition");
    assert_eq!(
        definition.data,
        public_standard_asset::definition_body().unwrap(),
        "Definition must carry its fixed canonical body"
    );
    let cap_type: sunrise_edge_client::Digest32 =
        sunrise_edge_client::package_types::derive_scoped_type_id(
            resolver,
            epoch,
            &public_standard_asset::treasury_cap_type_tag(origin, &definition.id).unwrap(),
        )
        .unwrap();
    let cap: &Object = created
        .iter()
        .copied()
        .find(|object: &&Object| object.type_hash == cap_type)
        .expect("create-asset initializer omitted TreasuryCap");
    assert_eq!(
        public_standard_asset::treasury_supply(&cap.data).unwrap(),
        0,
        "a freshly created asset's TreasuryCap must start at zero supply"
    );
    assert_ne!(definition.id, cap.id);
    (definition.id, cap.id, definition_type, cap_type)
}

fn require_receipt(
    client: &Client<LoopbackHttpTransport>,
    request_bytes: [u8; 32],
    digest: sunrise_edge_client::Digest32,
    expected_result_bytes: &[u8],
) -> Vec<u8> {
    let request: RequestId = RequestId::new(request_bytes).unwrap();
    let receipt: sunrise_edge_client::HttpReceiptQueryResult = client.query_receipt(request).unwrap();
    let sunrise_edge_client::HttpReceiptQueryResult::Present {
        request_id,
        event_digest,
        dedup_record_bytes,
        ..
    } = &receipt
    else {
        panic!("accepted paid request must expose its actual receipt");
    };
    assert_eq!(*request_id, request);
    assert_eq!(*event_digest, digest);
    // Never trust the outer query fields alone: bind the nested canonical
    // dedup record to this exact request id and event digest, and require
    // its own exact canonical re-encoding, before trusting anything inside
    // it.
    let record: node_core::NodeDedupRecord =
        node_core::NodeDedupRecord::decode_bound(dedup_record_bytes, request, digest)
            .unwrap_or_else(|error| panic!("dedup record binding failed: {error}"));
    let [response] = record.responses() else {
        panic!("a successful paid execution must replay exactly one response");
    };
    assert_eq!(response.request_id(), request);
    assert_eq!(response.status(), node_core::NodeResponseStatus::Accepted);
    assert_eq!(response.payload(), Some(expected_result_bytes));
    receipt.encode().unwrap()
}

#[test]
#[ignore = "requires the bounded Docker distinct-UID create-asset fixture"]
fn distinct_uid_create_asset_probe() {
    let mode: String = required("CUSTODY_CREATE_MODE");
    let directory: PathBuf = required("CUSTODY_CREATE_DIR").into();
    let publisher: Address = Address::new(required_hex32("CUSTODY_CREATE_PUBLIC_KEY"));
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
    let coins = metadata.owner_coins[0];
    let genesis_spend_bytes: Vec<u8> = objects::encode_object(
        &manifest
            .objects
            .iter()
            .find(|entry| entry.object.id == coins.spend_coin)
            .unwrap()
            .object,
    )
    .unwrap();

    match mode.as_str() {
        "after-create" => {
            let endpoint: String = required("CUSTODY_CREATE_ENDPOINT");
            let client: Client<LoopbackHttpTransport> = connect(&endpoint);
            let instance_seed: [u8; 32] = required_hex32("CUSTODY_CREATE_INSTANCE_SEED_HEX");

            let signed_bytes: Vec<u8> = read_bounded(&directory.join("create-submission.bin"));
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
            assert_eq!(decoded.intent.request_id, CREATE_REQUEST_ID);
            assert_eq!(
                decoded.intent.consent.refund_recipient,
                *publisher.as_bytes()
            );
            assert_eq!(decoded.intent.sender, *publisher.as_bytes());
            assert_eq!(decoded.intent.nonce, 0);
            let PaidApplication::Instantiate(call) = &decoded.intent.application else {
                panic!("create-asset must be a paid Instantiate application");
            };
            assert_eq!(call.entrypoint, public_standard_asset::INITIALIZER);
            assert_eq!(call.code, manifest.fee_policy.code);
            assert!(
                call.access.entries.is_empty(),
                "create-asset's own Instantiate access must be empty"
            );
            assert!(
                call.type_arguments.is_empty(),
                "create-asset's own Instantiate type arguments must be empty"
            );
            assert_eq!(
                call.arguments,
                public_standard_asset::no_arguments().unwrap()
            );
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
            assert_eq!(decoded.intent.consent.source.id, coins.fee_coin);

            // The signed instance target is independently re-derived from the
            // untrusted seed input and the genesis-pinned code, never trusted
            // from the submission file alone.
            let record: InstanceRecord = InstanceRecord {
                context: context.clone(),
                creator: *publisher.as_bytes(),
                seed: instance_seed,
                code: manifest.fee_policy.code.clone(),
                revision: 1,
                initializer: public_standard_asset::INITIALIZER.to_owned(),
            };
            let target = instance_target(protocol.resolver(), &record).unwrap();
            assert_ne!(
                target, manifest.fee_policy.instance,
                "the created asset's instance must be distinct from the fee policy's own instance"
            );
            assert_eq!(call.instance, target);

            let result_bytes: Vec<u8> = read_bounded(&directory.join("create-result.bin"));
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

            let (definition_id, cap_id, definition_type, cap_type) = new_definition_and_cap(
                &result,
                protocol.resolver(),
                protocol.epoch(),
                manifest.fee_policy.code.origin(),
            );

            // Independent durable instance query: never trust the local
            // `--instance-ref-out` file alone.
            let record_bytes: Vec<u8> = read_bounded(&directory.join("create-instance.bin"));
            let decoded_record: InstanceRecord = decode_instance_record(&record_bytes).unwrap();
            assert_eq!(decoded_record, record);
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
            let remote: Option<InstanceRecord> = client
                .query_instance(record.creator, record.seed, protocol.resolver(), &expected)
                .unwrap();
            assert_eq!(remote.as_ref(), Some(&record));

            // Never trust the result file's embedded identities alone: both
            // the Definition and TreasuryCap are independently re-queried
            // live, and every assertion below is against that fresh query,
            // not the decoded result.
            let (definition_bytes, definition_version) = current_inline(
                client.query_object(definition_id).unwrap(),
                "newly created asset Definition",
            );
            let definition_object = objects::decode_object(&definition_bytes).unwrap();
            assert_eq!(definition_object.owner, Owner::Address(publisher));
            assert_eq!(definition_object.version, 1);
            assert_eq!(definition_version, 1);
            assert_eq!(
                definition_object.schema_version,
                public_standard_asset::SCHEMA_VERSION
            );
            assert_eq!(
                definition_object.type_hash, definition_type,
                "live Definition must carry the independently derived Definition nominal type"
            );

            let (cap_bytes, cap_version) = current_inline(
                client.query_object(cap_id).unwrap(),
                "newly created asset TreasuryCap",
            );
            let cap_object = objects::decode_object(&cap_bytes).unwrap();
            assert_eq!(cap_object.owner, Owner::Address(publisher));
            assert_eq!(cap_object.version, 1);
            assert_eq!(cap_version, 1);
            assert_eq!(
                cap_object.schema_version,
                public_standard_asset::SCHEMA_VERSION
            );
            assert_eq!(
                cap_object.type_hash, cap_type,
                "live TreasuryCap must carry the independently derived TreasuryCap nominal type"
            );
            assert_eq!(
                public_standard_asset::treasury_supply(&cap_object.data).unwrap(),
                0
            );
            assert_ne!(definition_id, cap_id);

            let created: Vec<&Object> = result
                .effects
                .object_effects
                .iter()
                .filter_map(|effect| match effect {
                    ObjectEffect::Created(object)
                        if object.id == definition_id || object.id == cap_id =>
                    {
                        Some(object)
                    }
                    _ => None,
                })
                .collect();
            let [first, second] = created.as_slice() else {
                panic!("exactly the Definition and TreasuryCap creation effects");
            };
            for object in [first, second] {
                let expected_bytes: &[u8] = if object.id == definition_id {
                    definition_bytes.as_slice()
                } else {
                    cap_bytes.as_slice()
                };
                assert_eq!(
                    objects::encode_object(object).unwrap().as_slice(),
                    expected_bytes
                );
            }

            // The genesis application (spend) coin is never part of
            // create-asset's empty access manifest: it must remain exactly
            // as genesis left it.
            let (spend_bytes, spend_version) = current_inline(
                client.query_object(coins.spend_coin).unwrap(),
                "genesis application coin after create-asset",
            );
            assert_eq!(spend_version, 1);
            assert_eq!(spend_bytes, genesis_spend_bytes);

            let next_nonce: u64 = client.query_next_nonce(publisher).unwrap().next_nonce();
            assert_eq!(next_nonce, 1);

            let receipt_bytes: Vec<u8> = require_receipt(
                &client,
                CREATE_REQUEST_ID,
                result.effects.tx_hash,
                &result_bytes,
            );

            // Idempotent replay of the exact captured signed request: no
            // re-preparation against an updated fee/nonce, and no change to
            // any touched object beyond what already happened.
            let mut observed_ids: BTreeSet<ObjectId> = BTreeSet::new();
            observed_ids.insert(coins.spend_coin);
            observed_ids.insert(coins.fee_coin);
            for effect in &result.effects.object_effects {
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
            let replay: PaidExecutionResult = client
                .submit_paid_execution(&decoded, protocol.resolver())
                .unwrap();
            assert_eq!(replay.status, PaidExecutionStatus::Success);
            assert_eq!(encode_paid_execution_result(&replay).unwrap(), result_bytes);
            assert_eq!(client.query_next_nonce(publisher).unwrap().next_nonce(), 1);
            for (id, bytes) in before {
                assert_eq!(client.query_object(id).unwrap().encode().unwrap(), bytes);
            }
            assert_eq!(
                client
                    .query_receipt(RequestId::new(CREATE_REQUEST_ID).unwrap())
                    .unwrap()
                    .encode()
                    .unwrap(),
                receipt_bytes
            );

            println!(
                "{{\"mode\":\"after-create\",\"verified\":true,\"definition_hex\":\"{definition_id}\",\"treasury_cap_hex\":\"{cap_id}\",\"next_nonce\":{next_nonce},\"replay_equal\":true}}",
            );
        }
        other => panic!("unknown create-asset fixture mode {other:?}"),
    }
    assert!(Path::new(&directory).is_dir());
}
