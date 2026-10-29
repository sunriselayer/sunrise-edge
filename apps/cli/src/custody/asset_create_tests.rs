//! Real genesis, independently derived instance target, paid WASM and
//! approval lifecycle controls for the create-asset custody family
//! (DR-0255).

use super::{
    approvals::{self, ApprovalRecord},
    asset_create::{AssetCreateRequest, AssetCreateTrust},
    config::CustodyConfig,
    error::CustodyError,
    fsperm::test_support::{TempDir, write_mode_file},
    server,
    wire::CustodyResponseStatus,
};
use objects::{Object, Owner};
use runtime::{
    DurableOperationContext, MemoryBlobStore, MemoryDurableStateStore, StorageCorrelationId,
    StorageDeadline, WriterFenceGeneration,
};
use sunrise_edge_client::{
    Address, ChainId, Digest32, Epoch, LocalSigner, ObjectEffect, ObjectId, PublicationContext,
    RequestId, VerifiedGenesisRoot,
};

struct Fixture {
    _directory: TempDir,
    config: CustodyConfig,
    manifest: node_core::genesis::GenesisManifest,
    resolver: sunrise_edge_client::HashSuiteResolver,
    signer: LocalSigner,
    create_request: AssetCreateRequest,
}

impl Fixture {
    fn new() -> Self {
        let directory: TempDir = TempDir::new(0o700);
        let signer: LocalSigner = LocalSigner::from_seed([0xC0; 32]);
        let protocol = sunrise_edge_devnet::build_devnet_protocol_context(
            ChainId::new("custody-create-asset-test").unwrap(),
            Epoch::new(0),
        )
        .unwrap();
        let context: PublicationContext = PublicationContext::new(
            protocol.chain_id().clone(),
            protocol.resolver().protocol_version(),
            protocol.epoch(),
        )
        .unwrap();
        // `dev_owners[0]` is the sole owner and `mint_authority`, distinct
        // from the fixed genesis signer (`DEVNET_PAID_GENESIS_SEED`) that
        // actually creates the genesis Standard Asset instance, and from
        // the separate fee recipient below.
        let owners = [sunrise_edge_devnet::DevOwner::new(
            *signer.address().as_bytes(),
        )];
        let (manifest, metadata) = sunrise_edge_devnet::build_paid_genesis_manifest(
            protocol.resolver(),
            &context,
            &owners,
            sunrise_edge_devnet::DevOwner::new(
                *LocalSigner::from_seed([0xC9; 32]).address().as_bytes(),
            ),
        )
        .unwrap();
        assert_eq!(metadata.mint_authority, owners[0]);
        assert_ne!(
            manifest.genesis_authority,
            *signer.address().as_bytes(),
            "the genesis signer must remain distinct from the custody publisher"
        );
        let text: String = format!(
            "chain_id={}\nprotocol_version=7\nepoch=0\nhash_suite_id=1\ndomain={}\npublisher_public_key={}\noperator_uid=12004\n",
            protocol.chain_id(),
            crate::hex::encode_hex(protocol.domain().as_bytes()),
            signer.address(),
        );
        let config_path = directory.child("config");
        write_mode_file(&config_path, 0o600, text.as_bytes());
        let config = CustodyConfig::load(&config_path).unwrap();
        let fee_bytes: Vec<u8> = objects::encode_object(
            &manifest
                .objects
                .iter()
                .find(|entry| entry.object.id == metadata.owner_coins[0].fee_coin)
                .unwrap()
                .object,
        )
        .unwrap();
        let create_request = AssetCreateRequest {
            seed: [0xC1; 32],
            fee_bytes,
            nonce: 0,
            request_id: RequestId::new([0xC2; 32]).unwrap(),
            max_fee: 1_000_000,
            gas_limit: 200_000,
        };
        Self {
            _directory: directory,
            config,
            manifest,
            resolver: protocol.resolver().clone(),
            signer,
            create_request,
        }
    }

    fn trust(&self) -> AssetCreateTrust {
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
        AssetCreateTrust::new(self.config.clone(), root).unwrap()
    }
}

fn operation() -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0xC3; 16]).unwrap(),
    )
}

#[test]
fn authenticated_outer_genesis_does_not_waive_create_trust_checks() {
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
    assert!(AssetCreateTrust::new(fixture.config.clone(), root).is_err());
}

#[test]
fn create_renders_review_and_derives_a_fresh_instance_distinct_from_genesis() {
    let fixture: Fixture = Fixture::new();
    let prepared = fixture
        .trust()
        .prepare_create(&fixture.create_request)
        .unwrap();
    assert_ne!(prepared.new_instance, fixture.manifest.fee_policy.instance);
    assert!(prepared.review.contains("new_instance_seed="));
    assert!(prepared.review.contains("new_instance_record_digest="));
    assert!(
        prepared
            .review
            .contains("created_definition=unknown-until-execution")
    );
    assert!(
        prepared
            .review
            .contains("created_treasury_cap=unknown-until-execution")
    );
    assert!(prepared.review.contains("initial_supply=0"));
    assert!(prepared.review.contains("entrypoint=init"));
}

/// Reusing the *exact same seed bytes* as the pinned genesis fee instance
/// must not falsely collide: the custody publisher (`dev_owners[0]`/mint
/// authority) is a different creator than the genesis signer
/// (`DEVNET_PAID_GENESIS_SEED`) that actually created that instance, so the
/// derived `InstanceTarget` legitimately differs. Only an *actual* equal
/// target (same creator, seed, code, revision) is refused — never equal
/// seed bytes alone.
#[test]
fn create_does_not_falsely_collide_merely_from_reusing_the_genesis_seed_bytes() {
    let fixture: Fixture = Fixture::new();
    let mut reused_seed = fixture.create_request.clone();
    reused_seed.seed = fixture.manifest.fee_policy.instance.seed;
    let prepared = fixture.trust().prepare_create(&reused_seed).unwrap();
    assert_ne!(prepared.new_instance, fixture.manifest.fee_policy.instance);
    assert_ne!(
        prepared.new_instance.creator,
        fixture.manifest.fee_policy.instance.creator
    );
}

#[test]
fn create_rejects_wrong_owner_type_schema_and_trailing_preimage_bytes() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let original: Object = objects::decode_object(&fixture.create_request.fee_bytes).unwrap();
    let mut requests: Vec<AssetCreateRequest> = Vec::new();
    let mut trailing = fixture.create_request.clone();
    trailing.fee_bytes.push(0);
    requests.push(trailing);
    for field in 0..3 {
        let mut object: Object = original.clone();
        match field {
            0 => object.owner = Owner::Address(Address::new([0x42; 32])),
            1 => object.schema_version += 1,
            _ => object.type_hash = fixture.manifest.fee_policy.base_policy_digest,
        }
        let mut request = fixture.create_request.clone();
        request.fee_bytes = objects::encode_object(&object).unwrap();
        requests.push(request);
    }
    for request in &requests {
        assert!(trust.prepare_create(request).is_err());
    }
}

#[test]
fn create_rejects_a_zero_max_fee_and_a_zero_gas_limit() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut zero_max_fee = fixture.create_request.clone();
    zero_max_fee.max_fee = 0;
    assert!(trust.prepare_create(&zero_max_fee).is_err());
    let mut zero_gas_limit = fixture.create_request.clone();
    zero_gas_limit.gas_limit = 0;
    assert!(trust.prepare_create(&zero_gas_limit).is_err());
}

/// `max_fee` must be strictly less than the fee balance: both the exact
/// boundary (`max_fee == fee_balance`) and a value above it must be
/// refused.
#[test]
fn create_rejects_a_max_fee_at_or_above_the_fee_balance() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let fee_balance: u64 = public_standard_asset::coin_amount(
        &objects::decode_object(&fixture.create_request.fee_bytes)
            .unwrap()
            .data,
    )
    .unwrap();
    let mut at_balance = fixture.create_request.clone();
    at_balance.max_fee = fee_balance;
    assert!(trust.prepare_create(&at_balance).is_err());
    let mut above_balance = fixture.create_request.clone();
    above_balance.max_fee = fee_balance + 1;
    assert!(trust.prepare_create(&above_balance).is_err());
}

/// End-to-end: the independently prepared and signed `create-asset` intent
/// actually executes against the real genesis/paid WASM path, creating
/// exactly one fresh `Definition` and one fresh `TreasuryCap` — both owned
/// by the custody publisher, with initial supply zero — and replaying the
/// identical signed bytes a second time produces the identical response
/// without mutating state further or consuming a second nonce.
#[test]
fn create_replays_end_to_end_creating_definition_and_treasury_cap_with_zero_supply() {
    let fixture: Fixture = Fixture::new();
    let prepared = fixture
        .trust()
        .prepare_create(&fixture.create_request)
        .unwrap();
    let signed = prepared
        .prepared
        .sign_and_finalize_with(&fixture.signer)
        .unwrap();
    let bytes: Vec<u8> = execution::paid_execution::encode_signed_paid_intent(&signed).unwrap();

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
        &bytes,
        2,
    )
    .unwrap();
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
        &bytes,
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

    let result = execution::paid_execution::decode_paid_execution_result(
        first.responses()[0].payload().unwrap(),
    )
    .unwrap();
    assert_eq!(
        result.status,
        execution::paid_execution::PaidExecutionStatus::Success
    );
    let charged = result.charged.as_ref().unwrap();
    let fee_id: ObjectId = charged.fee_output.id;
    let refund_id: Option<ObjectId> = charged.refund_output.as_ref().map(|output| output.id);
    let created: Vec<&Object> = result
        .effects
        .object_effects
        .iter()
        .filter_map(|effect: &ObjectEffect| match effect {
            ObjectEffect::Created(object)
                if object.id != fee_id && Some(object.id) != refund_id =>
            {
                Some(object)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        created.len(),
        2,
        "the initializer must create exactly a Definition and a TreasuryCap"
    );
    let origin = fixture.manifest.fee_policy.code.origin().clone();
    let definition_tag = public_standard_asset::definition_type_tag(&origin).unwrap();
    let definition_type: Digest32 = sunrise_edge_client::package_types::derive_scoped_type_id(
        &fixture.resolver,
        expected.epoch(),
        &definition_tag,
    )
    .unwrap();
    let definition: &Object = created
        .iter()
        .copied()
        .find(|object| object.type_hash == definition_type)
        .expect("initializer must create a Definition");
    let asset: ObjectId = definition.id;
    let cap_tag = public_standard_asset::treasury_cap_type_tag(&origin, &asset).unwrap();
    let cap_type: Digest32 = sunrise_edge_client::package_types::derive_scoped_type_id(
        &fixture.resolver,
        expected.epoch(),
        &cap_tag,
    )
    .unwrap();
    let cap: &Object = created
        .iter()
        .copied()
        .find(|object| object.type_hash == cap_type)
        .expect("initializer must create a TreasuryCap");
    assert_ne!(definition.id, cap.id);
    assert_eq!(definition.version, 1);
    assert_eq!(cap.version, 1);
    assert_eq!(definition.owner, Owner::Address(fixture.signer.address()));
    assert_eq!(cap.owner, Owner::Address(fixture.signer.address()));
    assert_eq!(
        public_standard_asset::treasury_supply(&cap.data).unwrap(),
        0
    );
    // The result's own reported target -- built by node-core directly from
    // the signed intent's sender/seed/code/entrypoint, never from this
    // test's or custody's own derivation -- must independently rederive to
    // the exact same `InstanceTarget` `prepare_create` committed to.
    let execution::paid_execution::PaidResultTarget::Instance(result_record) = &result.target
    else {
        panic!("create-asset must report an Instance result target");
    };
    assert_eq!(
        execution::local_execution::instance_target(&fixture.resolver, result_record).unwrap(),
        prepared.new_instance
    );
}

/// Independently recomputes the exact `InstanceRecord`/`InstanceTarget`
/// derivation `prepare_create` used, from only the request's own public
/// seed and the fixture's own pinned genesis code/sender -- never from
/// `prepared` itself -- and checks it against `prepared.new_instance`.
/// Also inspects the prepared `Instantiate` call and fee consent directly:
/// sender, code, entrypoint, empty type arguments/access/arguments, the
/// `Instantiate` variant, and a refund/fee-source binding to the publisher
/// and the exact fee reference.
#[test]
fn create_prepares_the_exact_independently_rebuilt_instantiate_call_and_consent() {
    let fixture: Fixture = Fixture::new();
    let prepared = fixture
        .trust()
        .prepare_create(&fixture.create_request)
        .unwrap();

    let expected = fixture.config.expected_context().unwrap();
    let record = sunrise_edge_client::local_execution::InstanceRecord {
        context: PublicationContext::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            expected.epoch(),
        )
        .unwrap(),
        creator: *fixture.signer.address().as_bytes(),
        seed: fixture.create_request.seed,
        code: fixture.manifest.fee_policy.code.clone(),
        revision: 1,
        initializer: public_standard_asset::INITIALIZER.to_owned(),
    };
    let recomputed_target =
        sunrise_edge_client::local_execution::instance_target(&fixture.resolver, &record).unwrap();
    assert_eq!(recomputed_target, prepared.new_instance);

    let intent = prepared.prepared.intent();
    let sunrise_edge_client::PaidApplication::Instantiate(call) = &intent.application else {
        panic!("create-asset must prepare a PaidApplication::Instantiate");
    };
    assert_eq!(call.sender, *fixture.signer.address().as_bytes());
    assert_eq!(call.code, fixture.manifest.fee_policy.code);
    assert_eq!(call.entrypoint, public_standard_asset::INITIALIZER);
    assert_eq!(call.instance, prepared.new_instance);
    assert!(call.type_arguments.is_empty());
    assert!(call.access.entries.is_empty());
    assert_eq!(
        call.arguments,
        public_standard_asset::no_arguments().unwrap()
    );

    let fee_object: Object = objects::decode_object(&fixture.create_request.fee_bytes).unwrap();
    assert_eq!(
        intent.consent.refund_recipient,
        *fixture.signer.address().as_bytes()
    );
    assert_eq!(intent.consent.source.id, fee_object.id);
    assert_eq!(intent.consent.max_fee.get(), fixture.create_request.max_fee);
}

/// An approval is bound to the *whole* exact signable frame, not merely the
/// approved request id: a request that reuses the same `request_id` but
/// changes the seed, nonce, or max fee independently rebuilds a different
/// frame and must be refused (`NoApproval`), never silently signed under
/// the stale approval for a different seed/nonce/fee.
#[test]
fn sign_create_request_refuses_a_request_id_reused_with_a_changed_seed_nonce_or_max_fee() {
    let fixture: Fixture = Fixture::new();
    let trust: AssetCreateTrust = fixture.trust();
    let approvals_dir: TempDir = TempDir::new(0o700);

    let approved_frame: Vec<u8> = trust
        .prepare_create(&fixture.create_request)
        .unwrap()
        .prepared
        .signable_frame()
        .to_vec();
    approvals::write_approval(
        &approvals_dir.0,
        &fixture.create_request.request_id,
        &ApprovalRecord {
            publisher: fixture.signer.address(),
            not_after_unix_seconds: u64::MAX,
            frame: approved_frame,
        },
    )
    .unwrap();

    // Sanity: the exact approved request still signs under its own record.
    server::sign_create_request(
        &fixture.config,
        &fixture.signer,
        &approvals_dir.0,
        &trust,
        &fixture.create_request,
    )
    .unwrap();

    let mut changed_seed = fixture.create_request.clone();
    changed_seed.seed = [0xEE; 32];
    assert_eq!(
        server::sign_create_request(
            &fixture.config,
            &fixture.signer,
            &approvals_dir.0,
            &trust,
            &changed_seed,
        ),
        Err(CustodyResponseStatus::NoApproval)
    );

    let mut changed_nonce = fixture.create_request.clone();
    changed_nonce.nonce += 1;
    assert_eq!(
        server::sign_create_request(
            &fixture.config,
            &fixture.signer,
            &approvals_dir.0,
            &trust,
            &changed_nonce,
        ),
        Err(CustodyResponseStatus::NoApproval)
    );

    let mut changed_max_fee = fixture.create_request.clone();
    changed_max_fee.max_fee -= 1;
    assert_eq!(
        server::sign_create_request(
            &fixture.config,
            &fixture.signer,
            &approvals_dir.0,
            &trust,
            &changed_max_fee,
        ),
        Err(CustodyResponseStatus::NoApproval)
    );
}

#[test]
fn exact_approval_refuses_tampered_frame_signer_binding_expiry_and_restored_revocation() {
    let fixture: Fixture = Fixture::new();
    let trust: AssetCreateTrust = fixture.trust();
    let approvals_dir: TempDir = TempDir::new(0o700);
    let sign = || {
        server::sign_create_request(
            &fixture.config,
            &fixture.signer,
            &approvals_dir.0,
            &trust,
            &fixture.create_request,
        )
    };

    let frame: Vec<u8> = trust
        .prepare_create(&fixture.create_request)
        .unwrap()
        .prepared
        .signable_frame()
        .to_vec();
    let record = ApprovalRecord {
        publisher: fixture.signer.address(),
        not_after_unix_seconds: u64::MAX,
        frame: frame.clone(),
    };

    assert_eq!(sign(), Err(CustodyResponseStatus::NoApproval));

    // A tampered store: a frame that does not match the exact signable
    // bytes this request independently rebuilds (flip the last byte).
    let mut tampered_frame = frame.clone();
    *tampered_frame.last_mut().unwrap() ^= 0xFF;
    approvals::write_approval(
        &approvals_dir.0,
        &fixture.create_request.request_id,
        &ApprovalRecord {
            publisher: fixture.signer.address(),
            not_after_unix_seconds: u64::MAX,
            frame: tampered_frame,
        },
    )
    .unwrap();
    assert_eq!(sign(), Err(CustodyResponseStatus::NoApproval));

    approvals::write_approval(
        &approvals_dir.0,
        &fixture.create_request.request_id,
        &record,
    )
    .unwrap();
    let signature: [u8; 64] = sign().unwrap();
    trust
        .prepare_create(&fixture.create_request)
        .unwrap()
        .prepared
        .finalize(signature.to_vec())
        .unwrap();

    let mut expired = record.clone();
    expired.not_after_unix_seconds = 0;
    approvals::write_approval(
        &approvals_dir.0,
        &fixture.create_request.request_id,
        &expired,
    )
    .unwrap();
    assert_eq!(sign(), Err(CustodyResponseStatus::NoApproval));
    approvals::write_approval(
        &approvals_dir.0,
        &fixture.create_request.request_id,
        &record,
    )
    .unwrap();
    super::revoke::revoke(&approvals_dir.0, &fixture.create_request.request_id).unwrap();
    assert_eq!(sign(), Err(CustodyResponseStatus::NoApproval));
    // Revocation is not reversible by rewriting the exact same, still-valid
    // record: the write itself must refuse, and signing must still refuse.
    assert!(matches!(
        approvals::write_approval(
            &approvals_dir.0,
            &fixture.create_request.request_id,
            &record,
        ),
        Err(CustodyError::ApprovalRevoked)
    ));
    assert_eq!(sign(), Err(CustodyResponseStatus::NoApproval));

    // A signer that is not the pinned custody publisher fails the explicit
    // signer-binding guard before any approval is even looked up.
    assert_eq!(
        server::sign_create_request(
            &fixture.config,
            &LocalSigner::from_seed([0xCF; 32]),
            &approvals_dir.0,
            &trust,
            &fixture.create_request,
        ),
        Err(CustodyResponseStatus::Internal)
    );
}
