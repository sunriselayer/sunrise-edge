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

    fn root(&self) -> VerifiedGenesisRoot {
        let bytes: Vec<u8> = node_core::genesis::encode_genesis_manifest(&self.manifest).unwrap();
        let digest =
            node_core::genesis::genesis_manifest_commitment(&self.resolver, &self.manifest)
                .unwrap();
        VerifiedGenesisRoot::verify_bytes(
            &self.resolver,
            &bytes,
            digest.bytes(),
            self.manifest.context(),
        )
        .unwrap()
    }

    fn trust(&self) -> AssetMintBurnTrust {
        AssetMintBurnTrust::new(self.config.clone(), self.root(), None).unwrap()
    }

    /// Builds a locally pinned, non-genesis application asset/instance: a
    /// fresh `InstanceRecord` under the exact same genesis-verified Standard
    /// Asset code, with this fixture's own publisher as creator, revision
    /// one and the known initializer — exactly the shape `create-asset`
    /// (DR-0255) would have produced, without actually executing it.
    fn application_instance_record(
        &self,
        seed: [u8; 32],
    ) -> execution::local_execution::InstanceRecord {
        execution::local_execution::InstanceRecord {
            context: self.manifest.context().clone(),
            creator: *self.signer.address().as_bytes(),
            seed,
            code: self.manifest.fee_policy.code.clone(),
            revision: 1,
            initializer: public_standard_asset::INITIALIZER.to_owned(),
        }
    }

    /// Builds a trust with one application pin bound, targeting a fresh
    /// instance derived from `seed` plus a synthetic owned `TreasuryCap`
    /// object (`cap_supply`, as the published initializer would create one)
    /// under that pinned asset's own derived nominal type.
    fn application_pinned_trust_and_cap(
        &self,
        seed: [u8; 32],
        asset: sunrise_edge_client::ObjectId,
        cap_id: sunrise_edge_client::ObjectId,
        cap_supply: u64,
    ) -> (AssetMintBurnTrust, Vec<u8>) {
        let record = self.application_instance_record(seed);
        let record_bytes: Vec<u8> =
            execution::local_execution::encode_instance_record(&record).unwrap();
        let trust = AssetMintBurnTrust::new(
            self.config.clone(),
            self.root(),
            Some((asset, record_bytes)),
        )
        .unwrap();
        let cap_tag = public_standard_asset::treasury_cap_type_tag(
            self.manifest.fee_policy.code.origin(),
            &asset,
        )
        .unwrap();
        let cap_object = sunrise_edge_client::Object {
            id: cap_id,
            version: 1,
            owner: Owner::Address(self.signer.address()),
            type_hash: sunrise_edge_client::package_types::derive_scoped_type_id(
                &self.resolver,
                self.config.expected_context().unwrap().epoch(),
                &cap_tag,
            )
            .unwrap(),
            schema_version: public_standard_asset::SCHEMA_VERSION,
            data: encode_call_value(
                &public_standard_asset::treasury_cap_body_layout(),
                &CallValue::U64(cap_supply),
            )
            .unwrap(),
        };
        (trust, objects::encode_object(&cap_object).unwrap())
    }

    /// Builds a synthetic owned `Coin` object under the pinned application
    /// `asset`'s own derived nominal type (never the genesis one), mirroring
    /// `application_pinned_trust_and_cap` but for `Coin` instead of
    /// `TreasuryCap`. Used both to prove a pinned application's own `Coin`
    /// is still refused as a fee source (fee always requires the genesis
    /// `Coin` type) and to prepare a positive pinned `burn`.
    fn application_coin_bytes(
        &self,
        asset: sunrise_edge_client::ObjectId,
        coin_id: sunrise_edge_client::ObjectId,
        amount: u64,
    ) -> Vec<u8> {
        let coin_tag =
            public_standard_asset::coin_type_tag(self.manifest.fee_policy.code.origin(), &asset)
                .unwrap();
        let coin_object = sunrise_edge_client::Object {
            id: coin_id,
            version: 1,
            owner: Owner::Address(self.signer.address()),
            type_hash: sunrise_edge_client::package_types::derive_scoped_type_id(
                &self.resolver,
                self.config.expected_context().unwrap().epoch(),
                &coin_tag,
            )
            .unwrap(),
            schema_version: public_standard_asset::SCHEMA_VERSION,
            data: encode_call_value(
                &public_standard_asset::coin_body_layout(),
                &CallValue::U64(amount),
            )
            .unwrap(),
        };
        objects::encode_object(&coin_object).unwrap()
    }

    /// Builds a second, constructor-only `CustodyConfig` whose `publisher`
    /// is the verified genesis Standard Asset instance's own creator (the
    /// separate genesis authority that actually instantiated it), instead of
    /// this fixture's own mint/burn publisher. This never touches the
    /// fixture's own signer, key file, or any real credential: it exists
    /// only so an application-pin record whose `creator` legitimately
    /// equals *this* trust's own publisher can derive the exact genesis
    /// `InstanceTarget`, reaching the alias-refusal guard honestly rather
    /// than by weakening it.
    fn genesis_authority_config(&self) -> CustodyConfig {
        let genesis_authority: Address = Address::new(self.manifest.fee_policy.instance.creator);
        let expected = self.config.expected_context().unwrap();
        let text: String = format!(
            "chain_id={}\nprotocol_version=7\nepoch=0\nhash_suite_id=1\ndomain={}\npublisher_public_key={}\noperator_uid=12099\n",
            expected.chain_id(),
            crate::hex::encode_hex(expected.domain().as_bytes()),
            genesis_authority,
        );
        let path = self._directory.child("genesis-authority-config");
        write_mode_file(&path, 0o600, text.as_bytes());
        CustodyConfig::load(&path).unwrap()
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
    assert!(AssetMintBurnTrust::new(fixture.config.clone(), root, None).is_err());
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
}

/// `mint`'s cap/fee distinctness guard (`cap_object.id == fee_object.id`
/// in `asset_mint_burn.rs`) can never actually fire from two preimages that
/// otherwise pass their own checks: the cap slot requires the genesis
/// `TreasuryCap` nominal type and the fee slot requires the genesis `Coin`
/// nominal type, so one object cannot satisfy both type checks at once —
/// it is defense-in-depth, not a reachable guard. Swapping `fee_bytes` into
/// `cap_bytes` is still refused, but by the earlier `TreasuryCap` type
/// check, not the distinctness guard. This asserts that exact error
/// message rather than treating `is_err()` alone as proof the distinctness
/// guard works.
#[test]
fn mint_cap_fee_type_collision_is_refused_by_the_type_guard_not_distinctness() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut same_as_fee = fixture.mint_request.clone();
    same_as_fee.cap_bytes = same_as_fee.fee_bytes.clone();
    let error: crate::CliError = trust
        .prepare_mint(&same_as_fee)
        .err()
        .expect("TreasuryCap slot must refuse a Coin preimage");
    assert!(
        error
            .to_string()
            .contains("mint cap is not the genesis Standard Asset TreasuryCap type")
    );
}

/// `max_fee` must be strictly less than the fee balance: both the exact
/// boundary (`max_fee == fee_balance`) and a value above it must be
/// refused, not only the already-covered `max_fee == 0` case.
#[test]
fn mint_rejects_a_max_fee_at_or_above_the_fee_balance() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let fee_balance: u64 = public_standard_asset::coin_amount(
        &objects::decode_object(&fixture.mint_request.fee_bytes)
            .unwrap()
            .data,
    )
    .unwrap();
    let mut at_balance = fixture.mint_request.clone();
    at_balance.max_fee = fee_balance;
    assert!(trust.prepare_mint(&at_balance).is_err());
    let mut above_balance = fixture.mint_request.clone();
    above_balance.max_fee = fee_balance + 1;
    assert!(trust.prepare_mint(&above_balance).is_err());
}

/// A non-canonical fee preimage (decodable but not the exact canonical
/// re-encoding) is refused in `mint`, mirroring the existing cap-preimage
/// coverage in `mint_rejects_wrong_owner_type_schema_and_trailing_preimage_bytes`.
#[test]
fn mint_rejects_a_noncanonical_fee_preimage() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut trailing = fixture.mint_request.clone();
    trailing.fee_bytes.push(0);
    assert!(trust.prepare_mint(&trailing).is_err());
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
fn burn_rejects_foreign_fee_and_unowned_inputs() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let original: Object = objects::decode_object(&fixture.burn_request.coin_bytes).unwrap();
    let mut wrong_owner: Object = original.clone();
    wrong_owner.owner = Owner::Address(Address::new([0x42; 32]));
    let mut wrong_owner_request = fixture.burn_request.clone();
    wrong_owner_request.coin_bytes = objects::encode_object(&wrong_owner).unwrap();
    assert!(trust.prepare_burn(&wrong_owner_request).is_err());
}

/// A non-canonical cap or coin preimage (decodable but not the exact
/// canonical re-encoding) is refused in `burn`, for both inputs
/// independently — not just the coin, which the removed combined test
/// previously checked alone.
#[test]
fn burn_rejects_a_noncanonical_cap_or_coin_preimage() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut trailing_cap = fixture.burn_request.clone();
    trailing_cap.cap_bytes.push(0);
    assert!(trust.prepare_burn(&trailing_cap).is_err());
    let mut trailing_coin = fixture.burn_request.clone();
    trailing_coin.coin_bytes.push(0);
    assert!(trust.prepare_burn(&trailing_coin).is_err());
}

/// `burn`'s cap/coin and fee/cap distinctness guards (`cap_object.id ==
/// coin_object.id` and `fee_object.id == cap_object.id` in
/// `asset_mint_burn.rs`) can never actually fire from preimages that
/// otherwise pass their own checks, for the same structural reason as
/// mint's cap/fee guard: the cap slot requires the genesis `TreasuryCap`
/// nominal type while the coin and fee slots both require the genesis
/// `Coin` nominal type, so no single object can satisfy a `TreasuryCap`
/// check and a `Coin` check at once. Both swaps below are still refused,
/// but by the earlier type check, not the distinctness guard — this
/// asserts the exact error message rather than treating `is_err()` alone
/// as proof either distinctness guard works.
#[test]
fn burn_cap_coin_and_fee_cap_type_collisions_are_refused_by_the_type_guard_not_distinctness() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut same_cap_coin = fixture.burn_request.clone();
    same_cap_coin.coin_bytes = same_cap_coin.cap_bytes.clone();
    let coin_error: crate::CliError = trust
        .prepare_burn(&same_cap_coin)
        .err()
        .expect("burn Coin slot must refuse a TreasuryCap preimage");
    assert!(
        coin_error
            .to_string()
            .contains("burn coin is not the genesis Standard Asset Coin type")
    );
    let mut fee_equals_cap = fixture.burn_request.clone();
    fee_equals_cap.fee_bytes = fee_equals_cap.cap_bytes.clone();
    let fee_error: crate::CliError = trust
        .prepare_burn(&fee_equals_cap)
        .err()
        .expect("fee Coin slot must refuse a TreasuryCap preimage");
    assert!(
        fee_error
            .to_string()
            .contains("fee source is not the genesis Standard Asset Coin type")
    );
}

/// `burn`'s fee/coin distinctness guard (`fee_object.id == coin_object.id`)
/// is the one guard in this family that two otherwise-valid preimages can
/// actually reach: the fee and coin slots both require the genesis `Coin`
/// nominal type, so passing the same coin preimage for both legitimately
/// passes every type/owner/schema check and is refused only by the
/// distinctness guard itself.
#[test]
fn burn_rejects_fee_coin_identity_via_the_distinctness_guard() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let mut fee_equals_coin = fixture.burn_request.clone();
    fee_equals_coin.fee_bytes = fee_equals_coin.coin_bytes.clone();
    let error: crate::CliError = trust
        .prepare_burn(&fee_equals_coin)
        .err()
        .expect("burn must refuse the same Coin as the fee source");
    assert!(
        error
            .to_string()
            .contains("fee source must be distinct from every burn application input")
    );
}

/// `max_fee` must be strictly less than the fee balance: both the exact
/// boundary (`max_fee == fee_balance`) and a value above it must be
/// refused, not only the already-covered `max_fee == 0` case.
#[test]
fn burn_rejects_a_max_fee_at_or_above_the_fee_balance() {
    let fixture: Fixture = Fixture::new();
    let trust = fixture.trust();
    let fee_balance: u64 = public_standard_asset::coin_amount(
        &objects::decode_object(&fixture.burn_request.fee_bytes)
            .unwrap()
            .data,
    )
    .unwrap();
    let mut at_balance = fixture.burn_request.clone();
    at_balance.max_fee = fee_balance;
    assert!(trust.prepare_burn(&at_balance).is_err());
    let mut above_balance = fixture.burn_request.clone();
    above_balance.max_fee = fee_balance + 1;
    assert!(trust.prepare_burn(&above_balance).is_err());
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

/// DR-0258: omitting `--asset`/`--instance-ref` entirely (the `None`
/// application argument every other test in this file already uses via
/// `Fixture::trust`) must keep `prepare_mint`'s review, supply arithmetic and
/// `CallIntent` target byte-identical to the original genesis-only family —
/// in particular, no `application_pinned` line is ever rendered.
#[test]
fn no_application_pin_renders_no_application_lines_and_keeps_the_genesis_target() {
    let fixture: Fixture = Fixture::new();
    let prepared = fixture.trust().prepare_mint(&fixture.mint_request).unwrap();
    assert!(!prepared.review.contains("application_pinned"));
    assert!(!prepared.review.contains("application_asset"));
    let sunrise_edge_client::PaidApplication::Call(call) = &prepared.prepared.intent().application
    else {
        panic!("mint must be a paid Call application");
    };
    assert_eq!(call.instance, fixture.manifest.fee_policy.instance);
}

/// A bound application pin independently derives a fresh, non-genesis
/// `InstanceTarget`/nominal type pair and targets *that* instead of the
/// pinned genesis instance, while the genesis identity fields in the review
/// stay present and unchanged alongside the new `application_*` ones (both
/// identities, never only one).
#[test]
fn application_pin_targets_the_pinned_asset_instance_and_cap_type_instead_of_genesis() {
    let fixture: Fixture = Fixture::new();
    let asset: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xA1; 32]);
    let cap_id: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xA2; 32]);
    let (trust, cap_bytes) =
        fixture.application_pinned_trust_and_cap([0xA3; 32], asset, cap_id, 500);
    let mut request: AssetMintRequest = fixture.mint_request.clone();
    request.cap_bytes = cap_bytes;
    request.request_id = RequestId::new([0xA4; 32]).unwrap();
    let prepared = trust.prepare_mint(&request).unwrap();
    assert_eq!(prepared.supply_before, 500);
    assert_eq!(prepared.supply_after, 500 + request.amount);
    assert!(prepared.review.contains("application_pinned=true\n"));
    assert!(
        prepared
            .review
            .contains(&format!("application_asset={asset}\n"))
    );
    // The genesis identity line is still present and unchanged.
    assert!(prepared.review.contains(&format!(
        "instance_creator={}\n",
        crate::hex::encode_hex(&fixture.manifest.fee_policy.instance.creator)
    )));
    let sunrise_edge_client::PaidApplication::Call(call) = &prepared.prepared.intent().application
    else {
        panic!("mint must be a paid Call application");
    };
    assert_ne!(call.instance, fixture.manifest.fee_policy.instance);
    assert_eq!(call.code, fixture.manifest.fee_policy.code);
    assert_eq!(
        call.type_arguments,
        vec![public_standard_asset::asset_type_argument(&asset)]
    );
}

/// The fee source always validates against the genesis `Coin` nominal type,
/// even when an application pin is bound: a pinned application's own
/// `Coin` — same object *shape*/schema as the genesis `Coin`, differing only
/// in its nominal asset type — must still be refused as a fee source,
/// proving fee/application validation stay separate at the nominal-type
/// level, not merely by object kind (a `TreasuryCap` would trivially fail
/// this check for an unrelated reason).
#[test]
fn application_pin_still_requires_the_genesis_fee_coin_not_an_application_typed_coin() {
    let fixture: Fixture = Fixture::new();
    let asset: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xB1; 32]);
    let cap_id: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xB2; 32]);
    let fee_like_id: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xB3; 32]);
    let (trust, cap_bytes) =
        fixture.application_pinned_trust_and_cap([0xB4; 32], asset, cap_id, 10);
    let application_coin_bytes: Vec<u8> = fixture.application_coin_bytes(asset, fee_like_id, 999);
    let mut request: AssetMintRequest = fixture.mint_request.clone();
    request.cap_bytes = cap_bytes;
    request.fee_bytes = application_coin_bytes;
    let error: crate::CliError = trust.prepare_mint(&request).err().expect(
        "an application-typed (pinned-asset) Coin must never satisfy the genesis fee Coin nominal type check",
    );
    assert!(
        error
            .to_string()
            .contains("fee source is not the genesis Standard Asset Coin type")
    );
}

/// A genesis-identity cap preimage is refused once an application pin is
/// bound: the pinned asset's own derived `TreasuryCap` nominal type differs
/// from the genesis one, so `type confusion` between the two is rejected.
#[test]
fn application_pin_rejects_a_genesis_cap_preimage_as_type_confusion() {
    let fixture: Fixture = Fixture::new();
    let asset: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xC1; 32]);
    let cap_id: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xC2; 32]);
    let (trust, _cap_bytes) =
        fixture.application_pinned_trust_and_cap([0xC3; 32], asset, cap_id, 10);
    // `fixture.mint_request.cap_bytes` is the genesis TreasuryCap preimage.
    let error: crate::CliError = trust.prepare_mint(&fixture.mint_request).err().expect(
        "a genesis TreasuryCap preimage must never satisfy a pinned application's own cap type",
    );
    assert!(
        error
            .to_string()
            .contains("mint cap is not the genesis Standard Asset TreasuryCap type")
    );
}

/// The application record must match the pinned exact context, exact
/// genesis code, known initializer, and the pinned custody publisher as
/// creator. A valid base record (every field held fixed except the one
/// under test) is accepted first, proving each variant below changes
/// exactly one field relative to a record that otherwise passes. Every
/// variant is then independently exercised — not only via `is_err()`, but
/// also by asserting the resulting value is the typed
/// `CliError::LocalExecution` carrying this check's own exact combined
/// message (`ApplicationAssetPin::new` reports context/code/revision/
/// initializer/creator mismatches as one shared message, not a distinct one
/// per field, so asserting that one message for every variant is the
/// strongest claim this test can truthfully make without changing that
/// production message).
#[test]
fn application_pin_rejects_wrong_context_code_initializer_or_creator_with_the_exact_message() {
    let fixture: Fixture = Fixture::new();
    let asset: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xD1; 32]);
    let base_record = fixture.application_instance_record([0xD2; 32]);
    let base_bytes = execution::local_execution::encode_instance_record(&base_record).unwrap();
    assert!(
        super::asset_mint_burn::AssetMintBurnTrust::new(
            fixture.config.clone(),
            fixture.root(),
            Some((asset, base_bytes)),
        )
        .is_ok()
    );

    let mut wrong_context = base_record.clone();
    wrong_context.context = PublicationContext::new(
        wrong_context.context.chain_id().clone(),
        wrong_context.context.protocol_version(),
        Epoch::new(wrong_context.context.epoch().get() + 1),
    )
    .unwrap();

    let mut wrong_code = base_record.clone();
    wrong_code.code = sunrise_edge_client::publication::UnverifiedDependencyRef::new(
        wrong_code.code.origin().clone(),
        1,
        wrong_code.context.clone(),
        sunrise_edge_client::Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0x55; 32]),
    )
    .unwrap();

    let mut wrong_initializer = base_record.clone();
    wrong_initializer.initializer = "not-init".to_owned();

    let mut wrong_creator = base_record.clone();
    wrong_creator.creator = fixture.manifest.genesis_authority;
    assert_ne!(wrong_creator.creator, base_record.creator);

    const EXPECTED_MESSAGE: &str = "application instance record does not match the pinned custody context, code, revision, initializer or creator";
    for record in [wrong_context, wrong_code, wrong_initializer, wrong_creator] {
        let bytes = execution::local_execution::encode_instance_record(&record).unwrap();
        let result = super::asset_mint_burn::AssetMintBurnTrust::new(
            fixture.config.clone(),
            fixture.root(),
            Some((asset, bytes)),
        );
        let error: crate::CliError = result
            .err()
            .expect("each single-field mismatch must be refused");
        assert!(
            matches!(&error, crate::CliError::LocalExecution(_)),
            "every mismatch must surface as the same typed CliError variant"
        );
        assert!(error.to_string().contains(EXPECTED_MESSAGE));
    }
}

/// A non-one revision is refused even earlier than this trust ever sees it:
/// `encode_instance_record` itself requires exactly revision one.
#[test]
fn application_pin_instance_record_with_a_non_one_revision_cannot_even_be_encoded() {
    let fixture: Fixture = Fixture::new();
    let mut wrong_revision = fixture.application_instance_record([0xD3; 32]);
    wrong_revision.revision = 2;
    assert!(execution::local_execution::encode_instance_record(&wrong_revision).is_err());
}

/// A pinned application asset must not alias the pinned genesis fee asset:
/// construction fails even when every other field is otherwise valid.
#[test]
fn application_pin_rejects_the_genesis_fee_asset_as_the_pinned_application_asset() {
    let fixture: Fixture = Fixture::new();
    let record = fixture.application_instance_record([0xE1; 32]);
    let bytes = execution::local_execution::encode_instance_record(&record).unwrap();
    let genesis_asset: sunrise_edge_client::ObjectId =
        match fixture.manifest.fee_policy.type_arguments.as_slice() {
            [sunrise_edge_client::package_types::ScopedTypeArg::Opaque { value, .. }] => {
                sunrise_edge_client::ObjectId::new(*value)
            }
            _ => panic!("genesis fee policy must carry exactly one opaque asset argument"),
        };
    assert!(
        super::asset_mint_burn::AssetMintBurnTrust::new(
            fixture.config.clone(),
            fixture.root(),
            Some((genesis_asset, bytes)),
        )
        .is_err()
    );
}

/// A record whose `creator` honestly equals *this* trust's own publisher
/// (so it passes the creator check without weakening it), but whose
/// `seed`/`creator`/context/code combination hashes to exactly the pinned
/// genesis fee instance, is refused by the alias guard specifically — not
/// by the creator check. Reached via a constructor-only `CustodyConfig`
/// whose publisher is set to the genesis instance's own verified creator
/// (`genesis_authority_config`); no real signer/key material changes.
#[test]
fn application_pin_rejects_a_record_that_actually_derives_the_genesis_fee_instance() {
    let fixture: Fixture = Fixture::new();
    let genesis_authority_config: CustodyConfig = fixture.genesis_authority_config();
    let alias_record = execution::local_execution::InstanceRecord {
        context: fixture.manifest.context().clone(),
        creator: fixture.manifest.fee_policy.instance.creator,
        seed: fixture.manifest.fee_policy.instance.seed,
        code: fixture.manifest.fee_policy.code.clone(),
        revision: 1,
        initializer: public_standard_asset::INITIALIZER.to_owned(),
    };
    let bytes = execution::local_execution::encode_instance_record(&alias_record).unwrap();
    let asset: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xF1; 32]);
    let error: crate::CliError = super::asset_mint_burn::AssetMintBurnTrust::new(
        genesis_authority_config,
        fixture.root(),
        Some((asset, bytes)),
    )
    .err()
    .expect("a record that actually derives the genesis fee instance must be refused");
    assert!(
        error
            .to_string()
            .contains("application instance must not alias the pinned genesis fee instance")
    );
}

/// Positive pinned `burn`: a pinned application's own `TreasuryCap` and
/// `Coin` (both derived from the same pinned asset) are accepted together,
/// exercising `validate_application_coin`'s success path, not only its
/// refusals.
#[test]
fn application_pin_prepares_a_valid_burn_through_validate_application_coin() {
    let fixture: Fixture = Fixture::new();
    let asset: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xB5; 32]);
    let cap_id: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xB6; 32]);
    let coin_id: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xB7; 32]);
    let (trust, cap_bytes) =
        fixture.application_pinned_trust_and_cap([0xB8; 32], asset, cap_id, 1_000);
    let coin_bytes: Vec<u8> = fixture.application_coin_bytes(asset, coin_id, 100);
    let mut request: AssetBurnRequest = fixture.burn_request.clone();
    request.cap_bytes = cap_bytes;
    request.coin_bytes = coin_bytes;
    request.request_id = RequestId::new([0xB9; 32]).unwrap();
    let prepared = trust.prepare_burn(&request).unwrap();
    assert_eq!(prepared.supply_before, 1_000);
    assert_eq!(prepared.burn_amount, 100);
    assert_eq!(prepared.supply_after, 900);
}

/// A genesis `Coin` preimage is refused as a pinned application's own burn
/// `Coin`: its nominal type is the genesis one, not the pinned asset's.
#[test]
fn application_pin_rejects_a_genesis_coin_as_the_application_burn_coin() {
    let fixture: Fixture = Fixture::new();
    let asset: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xBA; 32]);
    let cap_id: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xBB; 32]);
    let (trust, cap_bytes) =
        fixture.application_pinned_trust_and_cap([0xBC; 32], asset, cap_id, 1_000);
    let mut request: AssetBurnRequest = fixture.burn_request.clone();
    request.cap_bytes = cap_bytes;
    // `fixture.burn_request.coin_bytes` is the genesis Coin preimage.
    let error: crate::CliError = trust
        .prepare_burn(&request)
        .err()
        .expect("a genesis Coin preimage must never satisfy a pinned application's own coin type");
    assert!(
        error
            .to_string()
            .contains("burn coin is not the genesis Standard Asset Coin type")
    );
}

/// Decodable but non-canonical (trailing-byte) application `InstanceRecord`
/// bytes are refused before any field is ever inspected.
#[test]
fn application_pin_rejects_a_noncanonical_instance_record_with_trailing_bytes() {
    let fixture: Fixture = Fixture::new();
    let asset: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xBD; 32]);
    let record = fixture.application_instance_record([0xBE; 32]);
    let mut bytes = execution::local_execution::encode_instance_record(&record).unwrap();
    bytes.push(0);
    assert!(
        super::asset_mint_burn::AssetMintBurnTrust::new(
            fixture.config.clone(),
            fixture.root(),
            Some((asset, bytes)),
        )
        .is_err()
    );
}

/// A stale approval for a *different* application under the exact same
/// pinned asset is refused: the cap/coin nominal-type checks alone cannot
/// distinguish two instances sharing one asset (both pass identically), so
/// only the full approved frame — which also encodes the targeted instance —
/// can, and does, refuse the mismatch.
#[test]
fn stale_approval_for_a_different_instance_under_the_same_pinned_asset_is_refused() {
    let fixture: Fixture = Fixture::new();
    let asset: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xC5; 32]);
    let cap_id: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xC6; 32]);
    let (trust_s1, cap_bytes) =
        fixture.application_pinned_trust_and_cap([0xC7; 32], asset, cap_id, 10);
    let (trust_s2, _unused_cap_bytes) =
        fixture.application_pinned_trust_and_cap([0xC8; 32], asset, cap_id, 10);

    let mut request: AssetMintRequest = fixture.mint_request.clone();
    request.cap_bytes = cap_bytes;
    request.request_id = RequestId::new([0xC9; 32]).unwrap();

    // The premise: the exact same cap preimage (same pinned asset, two
    // different instances) passes *both* trusts' own cap-type check
    // identically, since that check depends only on the asset.
    let approved_frame: Vec<u8> = trust_s1
        .prepare_mint(&request)
        .unwrap()
        .prepared
        .signable_frame()
        .to_vec();
    assert!(trust_s2.prepare_mint(&request).is_ok());

    let approvals_dir: TempDir = TempDir::new(0o700);
    approvals::write_approval(
        &approvals_dir.0,
        &request.request_id,
        &ApprovalRecord {
            publisher: fixture.signer.address(),
            not_after_unix_seconds: u64::MAX,
            frame: approved_frame,
        },
    )
    .unwrap();

    let wire_request = super::asset_mint_burn::AssetMintBurnRequest::Mint(Box::new(request));
    assert_eq!(
        server::sign_mint_burn_request(
            &fixture.config,
            &fixture.signer,
            &approvals_dir.0,
            &trust_s2,
            &wire_request,
        ),
        Err(CustodyResponseStatus::NoApproval)
    );
}

/// A genesis (no-pin) approval cannot authorize a pinned-application
/// request: the genesis-prepared frame targets the genesis instance, so it
/// never matches a pinned trust's own, differently targeted, prepared frame.
#[test]
fn a_genesis_approval_cannot_authorize_a_pinned_application_request() {
    let fixture: Fixture = Fixture::new();
    let asset: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xCA; 32]);
    let cap_id: sunrise_edge_client::ObjectId = sunrise_edge_client::ObjectId::new([0xCB; 32]);
    let (trust, cap_bytes) =
        fixture.application_pinned_trust_and_cap([0xCC; 32], asset, cap_id, 10);

    let genesis_frame: Vec<u8> = fixture
        .trust()
        .prepare_mint(&fixture.mint_request)
        .unwrap()
        .prepared
        .signable_frame()
        .to_vec();

    let mut request: AssetMintRequest = fixture.mint_request.clone();
    request.cap_bytes = cap_bytes;
    request.request_id = RequestId::new([0xCD; 32]).unwrap();

    let approvals_dir: TempDir = TempDir::new(0o700);
    approvals::write_approval(
        &approvals_dir.0,
        &request.request_id,
        &ApprovalRecord {
            publisher: fixture.signer.address(),
            not_after_unix_seconds: u64::MAX,
            frame: genesis_frame,
        },
    )
    .unwrap();

    let wire_request = super::asset_mint_burn::AssetMintBurnRequest::Mint(Box::new(request));
    assert_eq!(
        server::sign_mint_burn_request(
            &fixture.config,
            &fixture.signer,
            &approvals_dir.0,
            &trust,
            &wire_request,
        ),
        Err(CustodyResponseStatus::NoApproval)
    );
}
