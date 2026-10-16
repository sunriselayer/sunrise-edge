//! Real genesis, query, paid WASM and approval lifecycle controls for the
//! split/merge custody family (DR-0249).

use super::{
    approvals::{self, ApprovalRecord},
    asset_split_merge::{AssetMergeRequest, AssetSplitMergeTrust, AssetSplitRequest},
    config::CustodyConfig,
    error::CustodyError,
    fsperm::test_support::{TempDir, write_mode_file},
    server,
    wire::CustodyResponseStatus,
};
use abi::call_values::{CallValue, encode_call_value};
use runtime::{
    DurableOperationContext, MemoryBlobStore, MemoryDurableStateStore, StorageCorrelationId,
    StorageDeadline, WriterFenceGeneration,
};
use sunrise_edge_client::{
    Address, ChainId, Epoch, LocalSigner, Object, Owner, PublicationContext, RequestId,
    VerifiedGenesisRoot,
};

struct Fixture {
    _directory: TempDir,
    config: CustodyConfig,
    manifest: node_core::genesis::GenesisManifest,
    resolver: sunrise_edge_client::HashSuiteResolver,
    signer: LocalSigner,
    split_request: AssetSplitRequest,
    merge_request: AssetMergeRequest,
}

impl Fixture {
    fn new() -> Self {
        let directory: TempDir = TempDir::new(0o700);
        let signer: LocalSigner = LocalSigner::from_seed([0x83; 32]);
        let recipient: LocalSigner = LocalSigner::from_seed([0x84; 32]);
        let protocol = sunrise_edge_devnet::build_devnet_protocol_context(
            ChainId::new("custody-split-merge-test").unwrap(),
            Epoch::new(0),
        )
        .unwrap();
        let context: PublicationContext = PublicationContext::new(
            protocol.chain_id().clone(),
            protocol.resolver().protocol_version(),
            protocol.epoch(),
        )
        .unwrap();
        // Two owner slots for the *same* signer: the devnet genesis builder
        // derives each coin id from (role, owner index, owner), so two
        // slots for one signer yield two genuinely distinct owned coins
        // (needed for `merge`'s distinct `into`/`from`), not a collision.
        let owners = [
            sunrise_edge_devnet::DevOwner::new(*signer.address().as_bytes()),
            sunrise_edge_devnet::DevOwner::new(*signer.address().as_bytes()),
        ];
        let (manifest, metadata) = sunrise_edge_devnet::build_paid_genesis_manifest(
            protocol.resolver(),
            &context,
            &owners,
            sunrise_edge_devnet::DevOwner::new(
                *LocalSigner::from_seed([0x8A; 32]).address().as_bytes(),
            ),
        )
        .unwrap();
        let text: String = format!(
            "chain_id={}\nprotocol_version=7\nepoch=0\nhash_suite_id=1\ndomain={}\npublisher_public_key={}\noperator_uid=12002\n",
            protocol.chain_id(),
            crate::hex::encode_hex(protocol.domain().as_bytes()),
            signer.address(),
        );
        let config_path = directory.child("config");
        write_mode_file(&config_path, 0o600, text.as_bytes());
        let config = CustodyConfig::load(&config_path).unwrap();
        let object_bytes = |id| -> Vec<u8> {
            objects::encode_object(
                &manifest
                    .objects
                    .iter()
                    .find(|entry| entry.object.id == id)
                    .unwrap()
                    .object,
            )
            .unwrap()
        };
        let split_request = AssetSplitRequest {
            coin_bytes: object_bytes(metadata.owner_coins[0].spend_coin),
            fee_bytes: object_bytes(metadata.owner_coins[0].fee_coin),
            amount: sunrise_edge_devnet::DEVNET_PAID_SPEND_COIN_BALANCE / 2,
            recipient: *recipient.address().as_bytes(),
            nonce: 0,
            request_id: RequestId::new([0x85; 32]).unwrap(),
            max_fee: 1_000_000,
            gas_limit: 200_000,
        };
        let merge_request = AssetMergeRequest {
            into_bytes: object_bytes(metadata.owner_coins[0].spend_coin),
            from_bytes: object_bytes(metadata.owner_coins[1].spend_coin),
            fee_bytes: object_bytes(metadata.owner_coins[0].fee_coin),
            nonce: 0,
            request_id: RequestId::new([0x86; 32]).unwrap(),
            max_fee: 1_000_000,
            gas_limit: 200_000,
        };
        Self {
            _directory: directory,
            config,
            manifest,
            resolver: protocol.resolver().clone(),
            signer,
            split_request,
            merge_request,
        }
    }

    fn trust(&self) -> AssetSplitMergeTrust {
        let bytes: Vec<u8> = node_core::genesis::encode_genesis_manifest(&self.manifest).unwrap();
        let digest =
            node_core::genesis::genesis_manifest_commitment(&self.resolver, &self.manifest)
                .unwrap();
        let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
            &self.resolver,
            &bytes,
            digest.bytes(),
            self.manifest.context(),
        )
        .unwrap();
        AssetSplitMergeTrust::new(self.config.clone(), root).unwrap()
    }
}

fn operation() -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x87; 16]).unwrap(),
    )
}

/// Reads `object_id` back from `store`, requiring a current inline object.
fn query_current_object(
    store: &MemoryDurableStateStore,
    resolver: &sunrise_edge_client::HashSuiteResolver,
    domain: sunrise_edge_client::AtomicityDomainId,
    object_id: sunrise_edge_client::ObjectId,
) -> Object {
    let node_core::ObjectQueryResult::CurrentInline {
        canonical_object_bytes,
        ..
    } = node_core::query_object(store, &operation(), domain, resolver.chain_id(), object_id)
        .unwrap()
    else {
        panic!("queried object inline");
    };
    objects::decode_object(&canonical_object_bytes).unwrap()
}

/// Installs genesis once, then executes the identical signed paid intent
/// bytes *twice* against that one preinstalled store. The second call must
/// be an idempotent replay of the durable receipt, never a second
/// application of the effect: the sender's next nonce
/// ([`node_core::query_sender_next_nonce`]) must advance exactly once, the
/// two `NodeOutput` response sets must be byte-identical, and `queried_id`'s
/// object must be identical before and after the replay. Returns the final
/// decoded result, the queried object, and the store itself (so a merge test
/// can also independently query its consumed `from` coin from the same
/// post-execution state). Querying from a second, freshly re-installed store
/// would only ever show pre-execution genesis state, not the actual effect.
fn execute_and_query(
    fixture: &Fixture,
    bytes: &[u8],
    queried_id: sunrise_edge_client::ObjectId,
) -> (
    execution::paid_execution::PaidExecutionResult,
    Object,
    MemoryDurableStateStore,
) {
    let expected = fixture.config.expected_context().unwrap();
    let domain = expected.domain();
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new_bound(domain, WriterFenceGeneration::new(1).unwrap());
    node_core::genesis::install_genesis(
        &store,
        &operation(),
        domain,
        &fixture.resolver,
        &fixture.manifest,
        1,
    )
    .unwrap();
    let base = execution::local_execution::LocalExecutionPolicy::generic_object_results(
        fixture.manifest.context().clone(),
    );
    let engine = execution::LocalWasmExecutionEngine::new();
    let blobs: MemoryBlobStore = MemoryBlobStore::default();
    let sender: [u8; 32] = *fixture.signer.address().as_bytes();

    let nonce_before = node_core::query_sender_next_nonce(
        &store,
        &operation(),
        domain,
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
        sender,
    )
    .unwrap();

    let first = node_core::paid_execution::handle_paid_execution(
        &store,
        &blobs,
        &operation(),
        domain,
        &fixture.resolver,
        &[],
        fixture.manifest.context(),
        &base,
        &fixture.manifest.fee_policy,
        &engine,
        bytes,
        2,
    )
    .unwrap();
    let after_first = query_current_object(&store, &fixture.resolver, domain, queried_id);

    // Exact replay of the identical signed bytes against the same store:
    // must return the identical cached receipt, never re-apply the effect.
    let second = node_core::paid_execution::handle_paid_execution(
        &store,
        &blobs,
        &operation(),
        domain,
        &fixture.resolver,
        &[],
        fixture.manifest.context(),
        &base,
        &fixture.manifest.fee_policy,
        &engine,
        bytes,
        2,
    )
    .unwrap();
    assert_eq!(first.responses(), second.responses());

    let nonce_after = node_core::query_sender_next_nonce(
        &store,
        &operation(),
        domain,
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
        sender,
    )
    .unwrap();
    assert_eq!(nonce_after, nonce_before + 1);

    let after_second = query_current_object(&store, &fixture.resolver, domain, queried_id);
    assert_eq!(after_first, after_second);

    let result = execution::paid_execution::decode_paid_execution_result(
        first.responses()[0].payload().unwrap(),
    )
    .unwrap();
    (result, after_second, store)
}

#[test]
fn authenticated_outer_genesis_does_not_waive_split_merge_trust_checks() {
    use crypto::SignatureSigner;
    let fixture: Fixture = Fixture::new();
    let authority = LocalSigner::from_seed(sunrise_edge_devnet::DEVNET_PAID_GENESIS_SEED);
    assert_eq!(
        authority.address().as_bytes(),
        &fixture.manifest.genesis_authority
    );
    let mut manifest = fixture.manifest.clone();
    manifest.fee_policy.instance.revision += 1;
    let frame = node_core::genesis::genesis_manifest_signing_frame(&manifest).unwrap();
    manifest.signature = authority.sign_framed(&frame).unwrap().try_into().unwrap();
    let bytes = node_core::genesis::encode_genesis_manifest(&manifest).unwrap();
    let digest =
        node_core::genesis::genesis_manifest_commitment(&fixture.resolver, &manifest).unwrap();
    let root = VerifiedGenesisRoot::verify_bytes(
        &fixture.resolver,
        &bytes,
        digest.bytes(),
        manifest.context(),
    )
    .unwrap();
    assert!(AssetSplitMergeTrust::new(fixture.config.clone(), root).is_err());
}

#[test]
fn split_amount_between_zero_and_held_renders_review_and_replays_with_self_recipient_allowed() {
    let fixture: Fixture = Fixture::new();
    let mut self_recipient_request = fixture.split_request.clone();
    self_recipient_request.recipient = *fixture.signer.address().as_bytes();
    let split = fixture
        .trust()
        .prepare_split(&self_recipient_request)
        .unwrap();
    assert_eq!(
        split.held,
        sunrise_edge_devnet::DEVNET_PAID_SPEND_COIN_BALANCE
    );
    assert!(split.review.contains("split_amount="));
    assert!(split.review.contains("recipient_is_self=true"));

    let signed = split
        .prepared
        .sign_and_finalize_with(&fixture.signer)
        .unwrap();
    let bytes: Vec<u8> = execution::paid_execution::encode_signed_paid_intent(&signed).unwrap();
    let coin_id: sunrise_edge_client::ObjectId =
        objects::decode_object(&self_recipient_request.coin_bytes)
            .unwrap()
            .id;
    let (first, after, store) = execute_and_query(&fixture, &bytes, coin_id);
    assert_eq!(
        first.status,
        execution::paid_execution::PaidExecutionStatus::Success
    );
    assert_eq!(after.owner, Owner::Address(fixture.signer.address()));
    assert_eq!(
        public_standard_asset::coin_amount(&after.data).unwrap(),
        split.held - self_recipient_request.amount
    );

    // The actual new coin `split` creates: excluded from the fee-charge
    // outcome's own fee/refund/reservation ids, so this can never be
    // mistaken for the unrelated fee-refund coin the same charge produces.
    let charged = first.charged.as_ref().unwrap();
    let created: Vec<&Object> = first
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            execution::ObjectEffect::Created(object) => Some(object),
            _ => None,
        })
        .filter(|object| {
            object.id != charged.fee_output.id
                && object.id != charged.reservation
                && charged
                    .refund_output
                    .as_ref()
                    .is_none_or(|refund| refund.id != object.id)
        })
        .collect();
    assert_eq!(created.len(), 1);
    let created_coin: &Object = created[0];
    assert_eq!(
        created_coin.owner,
        Owner::Address(Address::new(self_recipient_request.recipient))
    );
    assert_eq!(
        public_standard_asset::coin_amount(&created_coin.data).unwrap(),
        self_recipient_request.amount
    );
    let domain = fixture.config.expected_context().unwrap().domain();
    let queried_created_coin: Object =
        query_current_object(&store, &fixture.resolver, domain, created_coin.id);
    assert_eq!(&queried_created_coin, created_coin);
}

#[test]
fn merge_checked_total_renders_review_and_replays_consuming_the_source() {
    let fixture: Fixture = Fixture::new();
    let merge = fixture
        .trust()
        .prepare_merge(&fixture.merge_request)
        .unwrap();
    assert_eq!(merge.checked_total, merge.into_amount + merge.from_amount);
    assert!(merge.review.contains("checked_total="));

    let signed = merge
        .prepared
        .sign_and_finalize_with(&fixture.signer)
        .unwrap();
    let bytes: Vec<u8> = execution::paid_execution::encode_signed_paid_intent(&signed).unwrap();
    let into_id: sunrise_edge_client::ObjectId =
        objects::decode_object(&fixture.merge_request.into_bytes)
            .unwrap()
            .id;
    let (result, after, store) = execute_and_query(&fixture, &bytes, into_id);
    assert_eq!(
        result.status,
        execution::paid_execution::PaidExecutionStatus::Success
    );
    assert_eq!(
        public_standard_asset::coin_amount(&after.data).unwrap(),
        merge.checked_total
    );

    // The consumed source: `merge` must leave it tombstoned, never still
    // current, on this same post-execution store.
    let from_id: sunrise_edge_client::ObjectId =
        objects::decode_object(&fixture.merge_request.from_bytes)
            .unwrap()
            .id;
    let domain = fixture.config.expected_context().unwrap().domain();
    let from_status = node_core::query_object(
        &store,
        &operation(),
        domain,
        fixture.resolver.chain_id(),
        from_id,
    )
    .unwrap();
    assert!(matches!(
        from_status,
        node_core::ObjectQueryResult::Tombstoned { object_id, .. } if object_id == from_id
    ));
}

#[test]
fn split_rejects_zero_full_and_overflowing_amounts_and_bad_recipient() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut zero = fixture.split_request.clone();
    zero.amount = 0;
    assert!(trust.prepare_split(&zero).is_err());
    let mut full = fixture.split_request.clone();
    full.amount = sunrise_edge_devnet::DEVNET_PAID_SPEND_COIN_BALANCE;
    assert!(trust.prepare_split(&full).is_err());
    let mut over = fixture.split_request.clone();
    over.amount = u64::MAX;
    assert!(trust.prepare_split(&over).is_err());
    let mut bad_recipient = fixture.split_request.clone();
    bad_recipient.recipient = [0; 32];
    assert!(trust.prepare_split(&bad_recipient).is_err());
    let mut same_as_fee = fixture.split_request.clone();
    same_as_fee.coin_bytes = same_as_fee.fee_bytes.clone();
    assert!(trust.prepare_split(&same_as_fee).is_err());
}

#[test]
fn split_rejects_wrong_owner_type_schema_and_trailing_preimage_bytes() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let original: Object = objects::decode_object(&fixture.split_request.coin_bytes).unwrap();
    let mut requests: Vec<AssetSplitRequest> = Vec::new();
    let mut trailing = fixture.split_request.clone();
    trailing.coin_bytes.push(0);
    requests.push(trailing);
    for field in 0..3 {
        let mut object: Object = original.clone();
        match field {
            0 => object.owner = Owner::Address(Address::new(fixture.split_request.recipient)),
            1 => object.schema_version += 1,
            _ => object.type_hash = fixture.manifest.fee_policy.base_policy_digest,
        }
        let mut request = fixture.split_request.clone();
        request.coin_bytes = objects::encode_object(&object).unwrap();
        requests.push(request);
    }
    for request in &requests {
        assert!(trust.prepare_split(request).is_err());
    }
}

#[test]
fn split_rejects_a_zero_max_fee_and_a_zero_gas_limit() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut zero_max_fee = fixture.split_request.clone();
    zero_max_fee.max_fee = 0;
    assert!(trust.prepare_split(&zero_max_fee).is_err());
    let mut zero_gas_limit = fixture.split_request.clone();
    zero_gas_limit.gas_limit = 0;
    assert!(trust.prepare_split(&zero_gas_limit).is_err());
}

#[test]
fn merge_rejects_shared_identity_foreign_fee_and_unowned_inputs() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut same_into_from = fixture.merge_request.clone();
    same_into_from.from_bytes = same_into_from.into_bytes.clone();
    assert!(trust.prepare_merge(&same_into_from).is_err());
    let mut fee_equals_into = fixture.merge_request.clone();
    fee_equals_into.fee_bytes = fee_equals_into.into_bytes.clone();
    assert!(trust.prepare_merge(&fee_equals_into).is_err());
    let mut fee_equals_from = fixture.merge_request.clone();
    fee_equals_from.fee_bytes = fee_equals_from.from_bytes.clone();
    assert!(trust.prepare_merge(&fee_equals_from).is_err());
    let original: Object = objects::decode_object(&fixture.merge_request.from_bytes).unwrap();
    let mut wrong_owner: Object = original.clone();
    wrong_owner.owner = Owner::Address(Address::new([0x42; 32]));
    let mut wrong_owner_request = fixture.merge_request.clone();
    wrong_owner_request.from_bytes = objects::encode_object(&wrong_owner).unwrap();
    assert!(trust.prepare_merge(&wrong_owner_request).is_err());
    let mut trailing = fixture.merge_request.clone();
    trailing.from_bytes.push(0);
    assert!(trust.prepare_merge(&trailing).is_err());
}

#[test]
fn merge_rejects_a_zero_max_fee_and_a_zero_gas_limit() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut zero_max_fee = fixture.merge_request.clone();
    zero_max_fee.max_fee = 0;
    assert!(trust.prepare_merge(&zero_max_fee).is_err());
    let mut zero_gas_limit = fixture.merge_request.clone();
    zero_gas_limit.gas_limit = 0;
    assert!(trust.prepare_merge(&zero_gas_limit).is_err());
}

/// Crafts `original` with its canonical `Coin` body (a bare scalar `u64`,
/// never a tuple) replaced by `amount`, preserving owner/schema/type exactly.
fn with_coin_amount(original: &Object, amount: u64) -> Vec<u8> {
    let mut object: Object = original.clone();
    object.data = encode_call_value(
        &public_standard_asset::coin_body_layout(),
        &CallValue::U64(amount),
    )
    .unwrap();
    objects::encode_object(&object).unwrap()
}

#[test]
fn merge_rejects_a_zero_source_amount_from_a_canonical_coin_body() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let original: Object = objects::decode_object(&fixture.merge_request.from_bytes).unwrap();
    let mut zero_source = fixture.merge_request.clone();
    zero_source.from_bytes = with_coin_amount(&original, 0);
    assert!(trust.prepare_merge(&zero_source).is_err());
}

#[test]
fn merge_rejects_an_overflowing_checked_total_from_canonical_coin_bodies() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let original: Object = objects::decode_object(&fixture.merge_request.from_bytes).unwrap();
    // `into_amount` (the devnet fixture's genesis balance) is already
    // positive, so pairing it with a `u64::MAX` source always overflows the
    // checked sum.
    let mut overflowing = fixture.merge_request.clone();
    overflowing.from_bytes = with_coin_amount(&original, u64::MAX);
    assert!(trust.prepare_merge(&overflowing).is_err());
}

#[test]
fn exact_approval_refuses_tampered_frame_signer_binding_expiry_and_restored_revocation() {
    let fixture: Fixture = Fixture::new();
    let trust: AssetSplitMergeTrust = fixture.trust();
    let approvals_dir: TempDir = TempDir::new(0o700);
    let split_request = super::asset_split_merge::AssetSplitMergeRequest::Split(Box::new(
        fixture.split_request.clone(),
    ));
    let merge_request = super::asset_split_merge::AssetSplitMergeRequest::Merge(Box::new(
        fixture.merge_request.clone(),
    ));
    let sign = |request: &super::asset_split_merge::AssetSplitMergeRequest| {
        server::sign_split_merge_request(
            &fixture.config,
            &fixture.signer,
            &approvals_dir.0,
            &trust,
            request,
        )
    };

    let split_frame: Vec<u8> = trust
        .prepare_split(&fixture.split_request)
        .unwrap()
        .prepared
        .signable_frame()
        .to_vec();
    let merge_frame: Vec<u8> = trust
        .prepare_merge(&fixture.merge_request)
        .unwrap()
        .prepared
        .signable_frame()
        .to_vec();
    let record = ApprovalRecord {
        publisher: fixture.signer.address(),
        not_after_unix_seconds: u64::MAX,
        frame: split_frame.clone(),
    };
    let merge_record = ApprovalRecord {
        publisher: fixture.signer.address(),
        not_after_unix_seconds: u64::MAX,
        frame: merge_frame.clone(),
    };

    assert_eq!(sign(&split_request), Err(CustodyResponseStatus::NoApproval));

    // A tampered store: the *merge* operation's own frame recorded under the
    // *split* request id, with an otherwise correct publisher and a far
    // future expiry. A right publisher and expiry never substitute for the
    // exact approved frame.
    approvals::write_approval(
        &approvals_dir.0,
        &fixture.split_request.request_id,
        &ApprovalRecord {
            publisher: fixture.signer.address(),
            not_after_unix_seconds: u64::MAX,
            frame: merge_frame.clone(),
        },
    )
    .unwrap();
    assert_eq!(sign(&split_request), Err(CustodyResponseStatus::NoApproval));

    approvals::write_approval(&approvals_dir.0, &fixture.split_request.request_id, &record)
        .unwrap();
    let signature: [u8; 64] = sign(&split_request).unwrap();
    trust
        .prepare_split(&fixture.split_request)
        .unwrap()
        .prepared
        .finalize(signature.to_vec())
        .unwrap();

    let mut expired = record.clone();
    expired.not_after_unix_seconds = 0;
    approvals::write_approval(
        &approvals_dir.0,
        &fixture.split_request.request_id,
        &expired,
    )
    .unwrap();
    assert_eq!(sign(&split_request), Err(CustodyResponseStatus::NoApproval));
    approvals::write_approval(&approvals_dir.0, &fixture.split_request.request_id, &record)
        .unwrap();
    super::revoke::revoke(&approvals_dir.0, &fixture.split_request.request_id).unwrap();
    assert_eq!(sign(&split_request), Err(CustodyResponseStatus::NoApproval));
    // Revocation is not reversible by rewriting the exact same, still-valid
    // record: the write itself must refuse, and signing must still refuse.
    assert!(matches!(
        approvals::write_approval(&approvals_dir.0, &fixture.split_request.request_id, &record),
        Err(CustodyError::ApprovalRevoked)
    ));
    assert_eq!(sign(&split_request), Err(CustodyResponseStatus::NoApproval));

    assert_eq!(sign(&merge_request), Err(CustodyResponseStatus::NoApproval));

    // The mirrored tamper: the *split* operation's own frame recorded under
    // the *merge* request id must refuse merge signing too.
    approvals::write_approval(
        &approvals_dir.0,
        &fixture.merge_request.request_id,
        &ApprovalRecord {
            publisher: fixture.signer.address(),
            not_after_unix_seconds: u64::MAX,
            frame: split_frame,
        },
    )
    .unwrap();
    assert_eq!(sign(&merge_request), Err(CustodyResponseStatus::NoApproval));

    approvals::write_approval(
        &approvals_dir.0,
        &fixture.merge_request.request_id,
        &merge_record,
    )
    .unwrap();
    let merge_signature: [u8; 64] = sign(&merge_request).unwrap();
    trust
        .prepare_merge(&fixture.merge_request)
        .unwrap()
        .prepared
        .finalize(merge_signature.to_vec())
        .unwrap();

    let mut expired_merge = merge_record.clone();
    expired_merge.not_after_unix_seconds = 0;
    approvals::write_approval(
        &approvals_dir.0,
        &fixture.merge_request.request_id,
        &expired_merge,
    )
    .unwrap();
    assert_eq!(sign(&merge_request), Err(CustodyResponseStatus::NoApproval));
    approvals::write_approval(
        &approvals_dir.0,
        &fixture.merge_request.request_id,
        &merge_record,
    )
    .unwrap();
    super::revoke::revoke(&approvals_dir.0, &fixture.merge_request.request_id).unwrap();
    assert_eq!(sign(&merge_request), Err(CustodyResponseStatus::NoApproval));
    assert!(matches!(
        approvals::write_approval(
            &approvals_dir.0,
            &fixture.merge_request.request_id,
            &merge_record,
        ),
        Err(CustodyError::ApprovalRevoked)
    ));
    assert_eq!(sign(&merge_request), Err(CustodyResponseStatus::NoApproval));

    // A signer that is not the pinned custody publisher fails the explicit
    // signer-binding guard before any approval is even looked up — it is not
    // an approval check, so it must refuse the same way whether or not an
    // approval for this (now-revoked) request id exists.
    assert_eq!(
        server::sign_split_merge_request(
            &fixture.config,
            &LocalSigner::from_seed([0x88; 32]),
            &approvals_dir.0,
            &trust,
            &merge_request,
        ),
        Err(CustodyResponseStatus::Internal)
    );
}
