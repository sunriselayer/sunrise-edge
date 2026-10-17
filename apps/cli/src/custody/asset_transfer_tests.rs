//! Real genesis, query, paid WASM and approval lifecycle controls.

use super::{
    approvals::{self, ApprovalRecord},
    asset_transfer::{AssetTransferRequest, AssetTransferTrust},
    config::CustodyConfig,
    fsperm::test_support::{TempDir, write_mode_file},
    server,
    wire::CustodyResponseStatus,
};
use runtime::{
    DurableOperationContext, MemoryBlobStore, MemoryDurableStateStore, StorageCorrelationId,
    StorageDeadline, WriterFenceGeneration,
};
use sunrise_edge_client::{
    Address, ChainId, Epoch, LocalSigner, Object, Owner, PreparedPaidExecution, PublicationContext,
    RequestId, VerifiedGenesisRoot,
};

struct Fixture {
    _directory: TempDir,
    config: CustodyConfig,
    manifest: node_core::genesis::GenesisManifest,
    resolver: sunrise_edge_client::HashSuiteResolver,
    signer: LocalSigner,
    request: AssetTransferRequest,
}

impl Fixture {
    fn new() -> Self {
        let directory: TempDir = TempDir::new(0o700);
        let signer: LocalSigner = LocalSigner::from_seed([0x73; 32]);
        let recipient: LocalSigner = LocalSigner::from_seed([0x74; 32]);
        let protocol = sunrise_edge_devnet::build_devnet_protocol_context(
            ChainId::new("custody-whole-coin-test").unwrap(),
            Epoch::new(0),
        )
        .unwrap();
        let context: PublicationContext = PublicationContext::new(
            protocol.chain_id().clone(),
            protocol.resolver().protocol_version(),
            protocol.epoch(),
        )
        .unwrap();
        let owners = [sunrise_edge_devnet::DevOwner::new(
            *signer.address().as_bytes(),
        )];
        let (manifest, metadata) = sunrise_edge_devnet::build_paid_genesis_manifest(
            protocol.resolver(),
            &context,
            &owners,
            sunrise_edge_devnet::DevOwner::new(
                *LocalSigner::from_seed([0x7A; 32]).address().as_bytes(),
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
        let request = AssetTransferRequest {
            coin_bytes: object_bytes(metadata.owner_coins[0].spend_coin),
            fee_bytes: object_bytes(metadata.owner_coins[0].fee_coin),
            recipient: *recipient.address().as_bytes(),
            nonce: 0,
            request_id: RequestId::new([0x75; 32]).unwrap(),
            max_fee: 1_000_000,
            gas_limit: 200_000,
        };
        Self {
            _directory: directory,
            config,
            manifest,
            resolver: protocol.resolver().clone(),
            signer,
            request,
        }
    }

    fn trust(&self) -> AssetTransferTrust {
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
        AssetTransferTrust::new(self.config.clone(), root, None).unwrap()
    }
}

fn operation() -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x76; 16]).unwrap(),
    )
}

#[test]
fn authenticated_outer_genesis_does_not_waive_fee_instance_or_nested_signature_checks() {
    use crypto::SignatureSigner;
    let fixture: Fixture = Fixture::new();
    let authority = LocalSigner::from_seed(sunrise_edge_devnet::DEVNET_PAID_GENESIS_SEED);
    assert_eq!(
        authority.address().as_bytes(),
        &fixture.manifest.genesis_authority
    );
    for alteration in 0..3 {
        let mut manifest = fixture.manifest.clone();
        match alteration {
            0 => manifest.fee_policy.reserve_entrypoint = "split".to_owned(),
            1 => manifest.fee_policy.instance.revision += 1,
            _ => manifest.initialization.signature[0] ^= 1,
        }
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
        assert!(AssetTransferTrust::new(fixture.config.clone(), root, None).is_err());
    }
}

#[test]
fn actual_query_digest_and_paid_wasm_match_review_and_replay() {
    let fixture: Fixture = Fixture::new();
    let transfer = fixture.trust().prepare(&fixture.request).unwrap();
    assert_eq!(
        transfer.amount,
        sunrise_edge_devnet::DEVNET_PAID_SPEND_COIN_BALANCE
    );
    assert_eq!(
        transfer.fee_balance,
        sunrise_edge_devnet::DEVNET_PAID_FEE_COIN_BALANCE
    );
    assert!(
        transfer
            .review
            .contains(&crate::hex::encode_hex(&fixture.request.recipient))
    );
    let intent = transfer.prepared.intent().clone();
    let independent: PreparedPaidExecution = PreparedPaidExecution::prepare(
        fixture.signer.address(),
        &fixture.resolver,
        &fixture.config.expected_context().unwrap(),
        &fixture.manifest.fee_policy,
        intent.consent.clone(),
        intent.application.clone(),
        fixture.request.request_id,
        0,
        fixture.request.gas_limit,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        transfer.prepared.signable_frame(),
        independent.signable_frame()
    );
    let signed = transfer
        .prepared
        .sign_and_finalize_with(&fixture.signer)
        .unwrap();
    let bytes: Vec<u8> = execution::paid_execution::encode_signed_paid_intent(&signed).unwrap();
    assert_eq!(
        bytes,
        execution::paid_execution::encode_signed_paid_intent(
            &independent.sign_and_finalize_with(&fixture.signer).unwrap()
        )
        .unwrap()
    );
    let domain = fixture.config.expected_context().unwrap().domain();
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
    let coin: Object = objects::decode_object(&fixture.request.coin_bytes).unwrap();
    let queried = node_core::query_object(
        &store,
        &operation(),
        domain,
        fixture.resolver.chain_id(),
        coin.id,
    )
    .unwrap();
    let node_core::ObjectQueryResult::CurrentInline {
        digest,
        canonical_object_bytes,
        ..
    } = queried
    else {
        panic!("installed coin inline");
    };
    let execution::paid_execution::PaidApplication::Call(call) = &signed.intent.application else {
        panic!("known call");
    };
    assert_eq!(digest, call.access.entries[0].object_ref.digest);
    assert_eq!(canonical_object_bytes, fixture.request.coin_bytes);
    let base = execution::local_execution::LocalExecutionPolicy::generic_object_results(
        fixture.manifest.context().clone(),
    );
    let engine = execution::LocalWasmExecutionEngine::new();
    let blobs: MemoryBlobStore = MemoryBlobStore::default();
    let execute = || {
        node_core::paid_execution::handle_paid_execution(
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
        .unwrap()
    };
    let first = execute();
    let replay = execute();
    assert_eq!(first.responses(), replay.responses());
    let result = execution::paid_execution::decode_paid_execution_result(
        first.responses()[0].payload().unwrap(),
    )
    .unwrap();
    assert_eq!(
        result.status,
        execution::paid_execution::PaidExecutionStatus::Success
    );
    let node_core::ObjectQueryResult::CurrentInline {
        canonical_object_bytes,
        ..
    } = node_core::query_object(
        &store,
        &operation(),
        domain,
        fixture.resolver.chain_id(),
        coin.id,
    )
    .unwrap()
    else {
        panic!("transferred coin inline");
    };
    let after: Object = objects::decode_object(&canonical_object_bytes).unwrap();
    assert_eq!(
        after.owner,
        Owner::Address(Address::new(fixture.request.recipient))
    );
    assert_ne!(
        fixture.request.recipient,
        fixture.manifest.fee_policy.fee_recipient
    );
    assert_eq!(
        public_standard_asset::coin_amount(&after.data).unwrap(),
        transfer.amount
    );
    assert_eq!(after.version, coin.version + 1);
}

#[test]
fn exact_approval_refuses_tamper_wrong_key_expiry_and_restored_revocation() {
    let fixture: Fixture = Fixture::new();
    let trust: AssetTransferTrust = fixture.trust();
    let approvals_dir: TempDir = TempDir::new(0o700);
    let sign = |request: &AssetTransferRequest| {
        server::sign_transfer_request(
            &fixture.config,
            &fixture.signer,
            &approvals_dir.0,
            &trust,
            request,
        )
    };
    assert_eq!(
        sign(&fixture.request),
        Err(CustodyResponseStatus::NoApproval)
    );
    let record = ApprovalRecord {
        publisher: fixture.signer.address(),
        not_after_unix_seconds: u64::MAX,
        frame: trust
            .prepare(&fixture.request)
            .unwrap()
            .prepared
            .signable_frame()
            .to_vec(),
    };
    approvals::write_approval(&approvals_dir.0, &fixture.request.request_id, &record).unwrap();
    let signature: [u8; 64] = sign(&fixture.request).unwrap();
    trust
        .prepare(&fixture.request)
        .unwrap()
        .prepared
        .finalize(signature.to_vec())
        .unwrap();
    let mut changed: AssetTransferRequest = fixture.request.clone();
    changed.recipient = *LocalSigner::from_seed([0x77; 32]).address().as_bytes();
    assert!(sign(&changed).is_err());
    changed = fixture.request.clone();
    changed.max_fee -= 1;
    assert!(sign(&changed).is_err());
    changed = fixture.request.clone();
    changed.nonce += 1;
    assert!(sign(&changed).is_err());
    assert!(
        server::sign_transfer_request(
            &fixture.config,
            &LocalSigner::from_seed([0x78; 32]),
            &approvals_dir.0,
            &trust,
            &fixture.request
        )
        .is_err()
    );
    let mut expired = record.clone();
    expired.not_after_unix_seconds = 0;
    approvals::write_approval(&approvals_dir.0, &fixture.request.request_id, &expired).unwrap();
    assert_eq!(
        sign(&fixture.request),
        Err(CustodyResponseStatus::NoApproval)
    );
    approvals::write_approval(&approvals_dir.0, &fixture.request.request_id, &record).unwrap();
    super::revoke::revoke(&approvals_dir.0, &fixture.request.request_id).unwrap();
    assert_eq!(
        sign(&fixture.request),
        Err(CustodyResponseStatus::NoApproval)
    );
    assert!(
        approvals::write_approval(&approvals_dir.0, &fixture.request.request_id, &record).is_err()
    );
    assert!(
        server::sign_transfer_request(
            &fixture.config,
            &fixture.signer,
            &approvals_dir.0,
            &fixture.trust(),
            &fixture.request
        )
        .is_err()
    );
}

#[test]
fn coin_preimage_owner_type_schema_and_fee_bounds_fail_closed() {
    let fixture: Fixture = Fixture::new();
    let trust: AssetTransferTrust = fixture.trust();
    let original: Object = objects::decode_object(&fixture.request.coin_bytes).unwrap();
    let mut requests: Vec<AssetTransferRequest> = Vec::new();
    let mut request = fixture.request.clone();
    request.coin_bytes.push(0);
    requests.push(request);
    for field in 0..3 {
        let mut object: Object = original.clone();
        match field {
            0 => object.owner = Owner::Address(Address::new(fixture.request.recipient)),
            1 => object.schema_version += 1,
            _ => object.type_hash = fixture.manifest.fee_policy.base_policy_digest,
        }
        let mut request = fixture.request.clone();
        request.coin_bytes = objects::encode_object(&object).unwrap();
        requests.push(request);
    }
    let mut request = fixture.request.clone();
    request.coin_bytes = request.fee_bytes.clone();
    requests.push(request);
    let mut request = fixture.request.clone();
    request.max_fee = 0;
    requests.push(request);
    let mut request = fixture.request.clone();
    request.max_fee = sunrise_edge_devnet::DEVNET_PAID_FEE_COIN_BALANCE;
    requests.push(request);
    let mut request = fixture.request.clone();
    request.recipient = *fixture.signer.address().as_bytes();
    requests.push(request);
    for request in &requests {
        assert!(trust.prepare(request).is_err());
    }
    let mut invalid_recipient = fixture.request.clone();
    invalid_recipient.recipient = [0; 32];
    assert!(trust.prepare(&invalid_recipient).is_err());
}
