//! Real genesis, query, paid WASM and approval lifecycle controls for the
//! mint/burn custody family (DR-0253).

use super::{
    approvals::{self, ApprovalRecord},
    asset_mint_burn::{AssetBurnRequest, AssetMintBurnTrust, AssetMintRequest},
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
    mint_request: AssetMintRequest,
    burn_request: AssetBurnRequest,
}

impl Fixture {
    fn new() -> Self {
        let directory: TempDir = TempDir::new(0o700);
        let signer: LocalSigner = LocalSigner::from_seed([0x93; 32]);
        let recipient: LocalSigner = LocalSigner::from_seed([0x94; 32]);
        let protocol = sunrise_edge_devnet::build_devnet_protocol_context(
            ChainId::new("custody-mint-burn-test").unwrap(),
            Epoch::new(0),
        )
        .unwrap();
        let context: PublicationContext = PublicationContext::new(
            protocol.chain_id().clone(),
            protocol.resolver().protocol_version(),
            protocol.epoch(),
        )
        .unwrap();
        // One owner slot: the devnet genesis builder makes `dev_owners[0]`
        // both the sole owner and the fixed `mint_authority`, so this one
        // signer already owns the installed `TreasuryCap<A>` exactly like
        // the real one-owner Docker fixture (no second owner needed).
        let owners = [sunrise_edge_devnet::DevOwner::new(
            *signer.address().as_bytes(),
        )];
        let (manifest, metadata) = sunrise_edge_devnet::build_paid_genesis_manifest(
            protocol.resolver(),
            &context,
            &owners,
            sunrise_edge_devnet::DevOwner::new(
                *LocalSigner::from_seed([0x9A; 32]).address().as_bytes(),
            ),
        )
        .unwrap();
        assert_eq!(metadata.mint_authority, owners[0]);
        let text: String = format!(
            "chain_id={}\nprotocol_version=7\nepoch=0\nhash_suite_id=1\ndomain={}\npublisher_public_key={}\noperator_uid=12003\n",
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
        let mint_request = AssetMintRequest {
            cap_bytes: object_bytes(metadata.treasury_cap_id),
            fee_bytes: object_bytes(metadata.owner_coins[0].fee_coin),
            amount: 1_000,
            recipient: *recipient.address().as_bytes(),
            nonce: 0,
            request_id: RequestId::new([0x95; 32]).unwrap(),
            max_fee: 1_000_000,
            gas_limit: 200_000,
        };
        let burn_request = AssetBurnRequest {
            cap_bytes: object_bytes(metadata.treasury_cap_id),
            coin_bytes: object_bytes(metadata.owner_coins[0].spend_coin),
            fee_bytes: object_bytes(metadata.owner_coins[0].fee_coin),
            nonce: 0,
            request_id: RequestId::new([0x96; 32]).unwrap(),
            max_fee: 1_000_000,
            gas_limit: 200_000,
        };
        Self {
            _directory: directory,
            config,
            manifest,
            resolver: protocol.resolver().clone(),
            signer,
            mint_request,
            burn_request,
        }
    }

    fn trust(&self) -> AssetMintBurnTrust {
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
        AssetMintBurnTrust::new(self.config.clone(), root).unwrap()
    }
}

fn operation() -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x97; 16]).unwrap(),
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
/// bytes *twice* against that one preinstalled store, exactly mirroring
/// `asset_split_merge_tests::execute_and_query`'s idempotent-replay proof.
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
fn authenticated_outer_genesis_does_not_waive_mint_burn_trust_checks() {
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
    assert!(AssetMintBurnTrust::new(fixture.config.clone(), root).is_err());
}

#[test]
fn mint_amount_renders_review_and_replays_increasing_supply() {
    let fixture: Fixture = Fixture::new();
    let mint = fixture.trust().prepare_mint(&fixture.mint_request).unwrap();
    assert_eq!(
        mint.supply_after,
        mint.supply_before + fixture.mint_request.amount
    );
    assert!(mint.review.contains("supply_before="));
    assert!(mint.review.contains("supply_after="));
    assert!(mint.review.contains("mint_amount="));

    let signed = mint
        .prepared
        .sign_and_finalize_with(&fixture.signer)
        .unwrap();
    let bytes: Vec<u8> = execution::paid_execution::encode_signed_paid_intent(&signed).unwrap();
    let cap_id: sunrise_edge_client::ObjectId =
        objects::decode_object(&fixture.mint_request.cap_bytes)
            .unwrap()
            .id;
    let (result, after, _store) = execute_and_query(&fixture, &bytes, cap_id);
    assert_eq!(
        result.status,
        execution::paid_execution::PaidExecutionStatus::Success
    );
    assert_eq!(
        public_standard_asset::treasury_supply(&after.data).unwrap(),
        mint.supply_after
    );
}

#[test]
fn burn_amount_renders_review_and_replays_decreasing_supply_and_consumes_coin() {
    let fixture: Fixture = Fixture::new();
    let burn = fixture.trust().prepare_burn(&fixture.burn_request).unwrap();
    assert_eq!(burn.supply_after, burn.supply_before - burn.burn_amount);
    assert!(burn.review.contains("supply_before="));
    assert!(burn.review.contains("burn_amount="));
    assert!(burn.review.contains("supply_after="));

    let signed = burn
        .prepared
        .sign_and_finalize_with(&fixture.signer)
        .unwrap();
    let bytes: Vec<u8> = execution::paid_execution::encode_signed_paid_intent(&signed).unwrap();
    let cap_id: sunrise_edge_client::ObjectId =
        objects::decode_object(&fixture.burn_request.cap_bytes)
            .unwrap()
            .id;
    let (result, after, store) = execute_and_query(&fixture, &bytes, cap_id);
    assert_eq!(
        result.status,
        execution::paid_execution::PaidExecutionStatus::Success
    );
    assert_eq!(
        public_standard_asset::treasury_supply(&after.data).unwrap(),
        burn.supply_after
    );

    let coin_id: sunrise_edge_client::ObjectId =
        objects::decode_object(&fixture.burn_request.coin_bytes)
            .unwrap()
            .id;
    let domain = fixture.config.expected_context().unwrap().domain();
    let coin_status = node_core::query_object(
        &store,
        &operation(),
        domain,
        fixture.resolver.chain_id(),
        coin_id,
    )
    .unwrap();
    assert!(matches!(
        coin_status,
        node_core::ObjectQueryResult::Tombstoned { object_id, .. } if object_id == coin_id
    ));
}

#[test]
fn mint_rejects_zero_overflowing_amount_and_bad_recipient() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut zero = fixture.mint_request.clone();
    zero.amount = 0;
    assert!(trust.prepare_mint(&zero).is_err());
    let mut overflowing = fixture.mint_request.clone();
    overflowing.amount = u64::MAX;
    assert!(trust.prepare_mint(&overflowing).is_err());
    let mut bad_recipient = fixture.mint_request.clone();
    bad_recipient.recipient = [0; 32];
    assert!(trust.prepare_mint(&bad_recipient).is_err());
    let mut same_as_fee = fixture.mint_request.clone();
    same_as_fee.cap_bytes = same_as_fee.fee_bytes.clone();
    assert!(trust.prepare_mint(&same_as_fee).is_err());
}

#[test]
fn mint_rejects_wrong_owner_type_schema_and_trailing_preimage_bytes() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let original: Object = objects::decode_object(&fixture.mint_request.cap_bytes).unwrap();
    let mut requests: Vec<AssetMintRequest> = Vec::new();
    let mut trailing = fixture.mint_request.clone();
    trailing.cap_bytes.push(0);
    requests.push(trailing);
    for field in 0..3 {
        let mut object: Object = original.clone();
        match field {
            0 => object.owner = Owner::Address(Address::new(fixture.mint_request.recipient)),
            1 => object.schema_version += 1,
            _ => object.type_hash = fixture.manifest.fee_policy.base_policy_digest,
        }
        let mut request = fixture.mint_request.clone();
        request.cap_bytes = objects::encode_object(&object).unwrap();
        requests.push(request);
    }
    for request in &requests {
        assert!(trust.prepare_mint(request).is_err());
    }
}

#[test]
fn mint_rejects_a_zero_max_fee_and_a_zero_gas_limit() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut zero_max_fee = fixture.mint_request.clone();
    zero_max_fee.max_fee = 0;
    assert!(trust.prepare_mint(&zero_max_fee).is_err());
    let mut zero_gas_limit = fixture.mint_request.clone();
    zero_gas_limit.gas_limit = 0;
    assert!(trust.prepare_mint(&zero_gas_limit).is_err());
}

#[test]
fn burn_rejects_shared_identity_foreign_fee_and_unowned_inputs() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut same_cap_coin = fixture.burn_request.clone();
    same_cap_coin.coin_bytes = same_cap_coin.cap_bytes.clone();
    assert!(trust.prepare_burn(&same_cap_coin).is_err());
    let mut fee_equals_cap = fixture.burn_request.clone();
    fee_equals_cap.fee_bytes = fee_equals_cap.cap_bytes.clone();
    assert!(trust.prepare_burn(&fee_equals_cap).is_err());
    let mut fee_equals_coin = fixture.burn_request.clone();
    fee_equals_coin.fee_bytes = fee_equals_coin.coin_bytes.clone();
    assert!(trust.prepare_burn(&fee_equals_coin).is_err());
    let original: Object = objects::decode_object(&fixture.burn_request.coin_bytes).unwrap();
    let mut wrong_owner: Object = original.clone();
    wrong_owner.owner = Owner::Address(Address::new([0x42; 32]));
    let mut wrong_owner_request = fixture.burn_request.clone();
    wrong_owner_request.coin_bytes = objects::encode_object(&wrong_owner).unwrap();
    assert!(trust.prepare_burn(&wrong_owner_request).is_err());
    let mut trailing = fixture.burn_request.clone();
    trailing.coin_bytes.push(0);
    assert!(trust.prepare_burn(&trailing).is_err());
}

#[test]
fn burn_rejects_a_zero_max_fee_and_a_zero_gas_limit() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut zero_max_fee = fixture.burn_request.clone();
    zero_max_fee.max_fee = 0;
    assert!(trust.prepare_burn(&zero_max_fee).is_err());
    let mut zero_gas_limit = fixture.burn_request.clone();
    zero_gas_limit.gas_limit = 0;
    assert!(trust.prepare_burn(&zero_gas_limit).is_err());
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

/// Crafts `original` with its canonical `TreasuryCap` body replaced by
/// `supply`, preserving owner/schema/type exactly.
fn with_cap_supply(original: &Object, supply: u64) -> Vec<u8> {
    let mut object: Object = original.clone();
    object.data = encode_call_value(
        &public_standard_asset::treasury_cap_body_layout(),
        &CallValue::U64(supply),
    )
    .unwrap();
    objects::encode_object(&object).unwrap()
}

#[test]
fn burn_rejects_a_zero_coin_amount_from_a_canonical_coin_body() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let original: Object = objects::decode_object(&fixture.burn_request.coin_bytes).unwrap();
    let mut zero_coin = fixture.burn_request.clone();
    zero_coin.coin_bytes = with_coin_amount(&original, 0);
    assert!(trust.prepare_burn(&zero_coin).is_err());
}

/// The protected review's own independently rebuilt checked-subtraction
/// must reject an underflowing burn — a coin amount exceeding the cap's
/// current supply — before any approval or signing step, exactly mirroring
/// the published contract's own checked-underflow guard.
#[test]
fn burn_rejects_an_underflowing_checked_supply_from_canonical_bodies() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let original_cap: Object = objects::decode_object(&fixture.burn_request.cap_bytes).unwrap();
    let mut underflowing = fixture.burn_request.clone();
    underflowing.cap_bytes = with_cap_supply(&original_cap, 0);
    assert!(trust.prepare_burn(&underflowing).is_err());
}

/// The protected review's own independently rebuilt checked-addition must
/// reject an overflowing mint supply before any approval or signing step,
/// exactly mirroring the published contract's own checked-overflow guard.
#[test]
fn mint_rejects_an_overflowing_checked_supply_from_a_canonical_cap_body() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let original_cap: Object = objects::decode_object(&fixture.mint_request.cap_bytes).unwrap();
    let mut overflowing = fixture.mint_request.clone();
    overflowing.cap_bytes = with_cap_supply(&original_cap, u64::MAX);
    assert!(trust.prepare_mint(&overflowing).is_err());
}

#[test]
fn exact_approval_refuses_tampered_frame_signer_binding_expiry_and_restored_revocation() {
    let fixture: Fixture = Fixture::new();
    let trust: AssetMintBurnTrust = fixture.trust();
    let approvals_dir: TempDir = TempDir::new(0o700);
    let mint_request =
        super::asset_mint_burn::AssetMintBurnRequest::Mint(Box::new(fixture.mint_request.clone()));
    let burn_request =
        super::asset_mint_burn::AssetMintBurnRequest::Burn(Box::new(fixture.burn_request.clone()));
    let sign = |request: &super::asset_mint_burn::AssetMintBurnRequest| {
        server::sign_mint_burn_request(
            &fixture.config,
            &fixture.signer,
            &approvals_dir.0,
            &trust,
            request,
        )
    };

    let mint_frame: Vec<u8> = trust
        .prepare_mint(&fixture.mint_request)
        .unwrap()
        .prepared
        .signable_frame()
        .to_vec();
    let burn_frame: Vec<u8> = trust
        .prepare_burn(&fixture.burn_request)
        .unwrap()
        .prepared
        .signable_frame()
        .to_vec();
    let record = ApprovalRecord {
        publisher: fixture.signer.address(),
        not_after_unix_seconds: u64::MAX,
        frame: mint_frame.clone(),
    };
    let burn_record = ApprovalRecord {
        publisher: fixture.signer.address(),
        not_after_unix_seconds: u64::MAX,
        frame: burn_frame.clone(),
    };

    assert_eq!(sign(&mint_request), Err(CustodyResponseStatus::NoApproval));

    // A tampered store: the *burn* operation's own frame recorded under the
    // *mint* request id, with an otherwise correct publisher and a far
    // future expiry. A right publisher and expiry never substitute for the
    // exact approved frame — proves swapped-operation frames are refused.
    approvals::write_approval(
        &approvals_dir.0,
        &fixture.mint_request.request_id,
        &ApprovalRecord {
            publisher: fixture.signer.address(),
            not_after_unix_seconds: u64::MAX,
            frame: burn_frame.clone(),
        },
    )
    .unwrap();
    assert_eq!(sign(&mint_request), Err(CustodyResponseStatus::NoApproval));

    approvals::write_approval(&approvals_dir.0, &fixture.mint_request.request_id, &record).unwrap();
    let signature: [u8; 64] = sign(&mint_request).unwrap();
    trust
        .prepare_mint(&fixture.mint_request)
        .unwrap()
        .prepared
        .finalize(signature.to_vec())
        .unwrap();

    let mut expired = record.clone();
    expired.not_after_unix_seconds = 0;
    approvals::write_approval(&approvals_dir.0, &fixture.mint_request.request_id, &expired)
        .unwrap();
    assert_eq!(sign(&mint_request), Err(CustodyResponseStatus::NoApproval));
    approvals::write_approval(&approvals_dir.0, &fixture.mint_request.request_id, &record).unwrap();
    super::revoke::revoke(&approvals_dir.0, &fixture.mint_request.request_id).unwrap();
    assert_eq!(sign(&mint_request), Err(CustodyResponseStatus::NoApproval));
    // Revocation is not reversible by rewriting the exact same, still-valid
    // record: the write itself must refuse, and signing must still refuse.
    assert!(matches!(
        approvals::write_approval(&approvals_dir.0, &fixture.mint_request.request_id, &record),
        Err(CustodyError::ApprovalRevoked)
    ));
    assert_eq!(sign(&mint_request), Err(CustodyResponseStatus::NoApproval));

    assert_eq!(sign(&burn_request), Err(CustodyResponseStatus::NoApproval));

    // The mirrored swapped-operation tamper: the *mint* operation's own
    // frame recorded under the *burn* request id must refuse burn signing.
    approvals::write_approval(
        &approvals_dir.0,
        &fixture.burn_request.request_id,
        &ApprovalRecord {
            publisher: fixture.signer.address(),
            not_after_unix_seconds: u64::MAX,
            frame: mint_frame,
        },
    )
    .unwrap();
    assert_eq!(sign(&burn_request), Err(CustodyResponseStatus::NoApproval));

    approvals::write_approval(
        &approvals_dir.0,
        &fixture.burn_request.request_id,
        &burn_record,
    )
    .unwrap();
    let burn_signature: [u8; 64] = sign(&burn_request).unwrap();
    trust
        .prepare_burn(&fixture.burn_request)
        .unwrap()
        .prepared
        .finalize(burn_signature.to_vec())
        .unwrap();

    let mut expired_burn = burn_record.clone();
    expired_burn.not_after_unix_seconds = 0;
    approvals::write_approval(
        &approvals_dir.0,
        &fixture.burn_request.request_id,
        &expired_burn,
    )
    .unwrap();
    assert_eq!(sign(&burn_request), Err(CustodyResponseStatus::NoApproval));
    approvals::write_approval(
        &approvals_dir.0,
        &fixture.burn_request.request_id,
        &burn_record,
    )
    .unwrap();
    super::revoke::revoke(&approvals_dir.0, &fixture.burn_request.request_id).unwrap();
    assert_eq!(sign(&burn_request), Err(CustodyResponseStatus::NoApproval));
    assert!(matches!(
        approvals::write_approval(
            &approvals_dir.0,
            &fixture.burn_request.request_id,
            &burn_record,
        ),
        Err(CustodyError::ApprovalRevoked)
    ));
    assert_eq!(sign(&burn_request), Err(CustodyResponseStatus::NoApproval));

    // A signer that is not the pinned custody publisher fails the explicit
    // signer-binding guard before any approval is even looked up — it is not
    // an approval check, so it must refuse the same way whether or not an
    // approval for this (now-revoked) request id exists.
    assert_eq!(
        server::sign_mint_burn_request(
            &fixture.config,
            &LocalSigner::from_seed([0x98; 32]),
            &approvals_dir.0,
            &trust,
            &burn_request,
        ),
        Err(CustodyResponseStatus::Internal)
    );
}
