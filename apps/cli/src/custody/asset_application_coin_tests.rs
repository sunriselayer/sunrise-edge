//! Pure preparation and existing whole-frame approval controls for DR-0261.
//! Application records/coins here are synthetic preimages: these controls do
//! not claim an executed create/mint/transfer/split/merge or live currentness.

use super::{
    approvals::{self, ApprovalRecord},
    asset_split_merge::{
        AssetMergeRequest, AssetSplitMergeRequest, AssetSplitMergeTrust, AssetSplitRequest,
    },
    asset_transfer::{AssetTransferRequest, AssetTransferTrust},
    config::CustodyConfig,
    fsperm::test_support::{TempDir, write_mode_file},
    server,
    wire::CustodyResponseStatus,
};
use abi::call_values::{CallValue, encode_call_value};
use execution::local_execution::{InstanceRecord, encode_instance_record, instance_target};
use sunrise_edge_client::{
    AccessMode, ChainId, Epoch, HashSuiteResolver, LocalSigner, Object, ObjectId, Owner,
    PaidApplication, PreparedPaidExecution, PublicationContext, RequestId, VerifiedGenesisRoot,
};

struct Fixture {
    _directory: TempDir,
    config: CustodyConfig,
    manifest: node_core::genesis::GenesisManifest,
    resolver: HashSuiteResolver,
    signer: LocalSigner,
    genesis_coin: Vec<u8>,
    genesis_second_coin: Vec<u8>,
    genesis_fee: Vec<u8>,
    genesis_asset: ObjectId,
    recipient: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        let directory: TempDir = TempDir::new(0o700);
        let signer: LocalSigner = LocalSigner::from_seed([0xd1; 32]);
        let recipient: LocalSigner = LocalSigner::from_seed([0xd2; 32]);
        let protocol = sunrise_edge_devnet::build_devnet_protocol_context(
            ChainId::new("custody-application-coin-test").unwrap(),
            Epoch::new(0),
        )
        .unwrap();
        let context: PublicationContext = PublicationContext::new(
            protocol.chain_id().clone(),
            protocol.resolver().protocol_version(),
            protocol.epoch(),
        )
        .unwrap();
        let owners = [
            sunrise_edge_devnet::DevOwner::new(*signer.address().as_bytes()),
            sunrise_edge_devnet::DevOwner::new(*signer.address().as_bytes()),
        ];
        let (manifest, metadata) = sunrise_edge_devnet::build_paid_genesis_manifest(
            protocol.resolver(),
            &context,
            &owners,
            sunrise_edge_devnet::DevOwner::new(
                *LocalSigner::from_seed([0xd3; 32]).address().as_bytes(),
            ),
        )
        .unwrap();
        let config_path = directory.child("config");
        let config_text: String = format!(
            "chain_id={}\nprotocol_version=7\nepoch=0\nhash_suite_id=1\ndomain={}\npublisher_public_key={}\noperator_uid=12002\n",
            protocol.chain_id(),
            crate::hex::encode_hex(protocol.domain().as_bytes()),
            signer.address(),
        );
        write_mode_file(&config_path, 0o600, config_text.as_bytes());
        let config: CustodyConfig = CustodyConfig::load(&config_path).unwrap();
        let object_bytes = |id: ObjectId| -> Vec<u8> {
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
        let genesis_coin: Vec<u8> = object_bytes(metadata.owner_coins[0].spend_coin);
        let genesis_second_coin: Vec<u8> = object_bytes(metadata.owner_coins[1].spend_coin);
        let genesis_fee: Vec<u8> = object_bytes(metadata.owner_coins[0].fee_coin);
        Self {
            _directory: directory,
            config,
            manifest,
            resolver: protocol.resolver().clone(),
            signer,
            genesis_coin,
            genesis_second_coin,
            genesis_fee,
            genesis_asset: metadata.definition_id,
            recipient: *recipient.address().as_bytes(),
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

    fn record(&self, seed: u8) -> InstanceRecord {
        InstanceRecord {
            context: self.manifest.context().clone(),
            creator: *self.signer.address().as_bytes(),
            seed: [seed; 32],
            code: self.manifest.fee_policy.code.clone(),
            revision: 1,
            initializer: public_standard_asset::INITIALIZER.to_owned(),
        }
    }

    fn trusts(&self, seed: u8) -> (AssetTransferTrust, AssetSplitMergeTrust) {
        let bytes: Vec<u8> = encode_instance_record(&self.record(seed)).unwrap();
        let asset: ObjectId = ObjectId::new([0xe1; 32]);
        (
            AssetTransferTrust::new(
                self.config.clone(),
                self.root(),
                Some((asset, bytes.clone())),
            )
            .unwrap(),
            AssetSplitMergeTrust::new(self.config.clone(), self.root(), Some((asset, bytes)))
                .unwrap(),
        )
    }

    fn coin(&self, asset: ObjectId, id: u8, amount: u64) -> Vec<u8> {
        let tag =
            public_standard_asset::coin_type_tag(self.manifest.fee_policy.code.origin(), &asset)
                .unwrap();
        let object: Object = Object {
            id: ObjectId::new([id; 32]),
            version: 1,
            owner: Owner::Address(self.signer.address()),
            type_hash: sunrise_edge_client::package_types::derive_scoped_type_id(
                &self.resolver,
                self.config.expected_context().unwrap().epoch(),
                &tag,
            )
            .unwrap(),
            schema_version: public_standard_asset::SCHEMA_VERSION,
            data: encode_call_value(
                &public_standard_asset::coin_body_layout(),
                &CallValue::U64(amount),
            )
            .unwrap(),
        };
        objects::encode_object(&object).unwrap()
    }

    fn requests(
        &self,
        application: bool,
    ) -> (AssetTransferRequest, AssetSplitRequest, AssetMergeRequest) {
        let asset: ObjectId = ObjectId::new([0xe1; 32]);
        let (first, second): (Vec<u8>, Vec<u8>) = if application {
            (self.coin(asset, 0xe2, 100), self.coin(asset, 0xe3, 70))
        } else {
            (self.genesis_coin.clone(), self.genesis_second_coin.clone())
        };
        (
            AssetTransferRequest {
                coin_bytes: first.clone(),
                fee_bytes: self.genesis_fee.clone(),
                recipient: self.recipient,
                nonce: 0,
                request_id: RequestId::new([0xe4; 32]).unwrap(),
                max_fee: 1_000_000,
                gas_limit: 200_000,
            },
            AssetSplitRequest {
                coin_bytes: first.clone(),
                fee_bytes: self.genesis_fee.clone(),
                amount: 30,
                recipient: self.recipient,
                nonce: 0,
                request_id: RequestId::new([0xe5; 32]).unwrap(),
                max_fee: 1_000_000,
                gas_limit: 200_000,
            },
            AssetMergeRequest {
                into_bytes: first,
                from_bytes: second,
                fee_bytes: self.genesis_fee.clone(),
                nonce: 0,
                request_id: RequestId::new([0xe6; 32]).unwrap(),
                max_fee: 1_000_000,
                gas_limit: 200_000,
            },
        )
    }
}

fn assert_application_review(fixture: &Fixture, prepared: &PreparedPaidExecution, review: &str) {
    let PaidApplication::Call(call) = &prepared.intent().application else {
        panic!("paid Call");
    };
    assert_eq!(
        call.instance,
        instance_target(&fixture.resolver, &fixture.record(0xe7)).unwrap()
    );
    assert_eq!(call.code, fixture.manifest.fee_policy.code);
    assert_eq!(
        call.type_arguments,
        vec![public_standard_asset::asset_type_argument(&ObjectId::new(
            [0xe1; 32]
        ))]
    );
    assert!(review.contains("application_pinned=true\n"));
    assert!(review.contains(&format!(
        "application_asset={}\n",
        ObjectId::new([0xe1; 32])
    )));
    assert!(review.contains(&format!(
        "instance_record_digest={}\n",
        fixture.manifest.fee_policy.instance.record_digest
    )));
    assert!(review.contains(&format!(
        "application_instance_record_digest={}\n",
        call.instance.record_digest
    )));
    let fee: Object = objects::decode_object(&fixture.genesis_fee).unwrap();
    assert_eq!(prepared.intent().consent.source.id, fee.id);
}

#[test]
fn application_transfer_split_and_merge_target_the_local_pin_and_keep_genesis_fees() {
    let fixture: Fixture = Fixture::new();
    let (transfer_trust, coin_trust) = fixture.trusts(0xe7);
    let (transfer, split, merge) = fixture.requests(true);
    let prepared_transfer = transfer_trust.prepare(&transfer).unwrap();
    let prepared_split = coin_trust.prepare_split(&split).unwrap();
    let prepared_merge = coin_trust.prepare_merge(&merge).unwrap();
    for (prepared, review) in [
        (
            &prepared_transfer.prepared,
            prepared_transfer.review.as_str(),
        ),
        (&prepared_split.prepared, prepared_split.review.as_str()),
        (&prepared_merge.prepared, prepared_merge.review.as_str()),
    ] {
        assert_application_review(&fixture, prepared, review);
    }
    assert_eq!(prepared_transfer.amount, 100);
    assert_eq!(prepared_split.held, 100);
    assert!(prepared_split.review.contains("remainder=70\n"));
    assert_eq!(prepared_merge.checked_total, 170);
    let PaidApplication::Call(call) = &prepared_merge.prepared.intent().application else {
        panic!("merge Call");
    };
    assert_eq!(call.access.entries[0].mode, AccessMode::Write);
    assert_eq!(call.access.entries[1].mode, AccessMode::Consume);
}

#[test]
fn no_application_pin_keeps_genesis_targets_and_emits_no_application_review_lines() {
    let fixture: Fixture = Fixture::new();
    let transfer_trust =
        AssetTransferTrust::new(fixture.config.clone(), fixture.root(), None).unwrap();
    let coin_trust =
        AssetSplitMergeTrust::new(fixture.config.clone(), fixture.root(), None).unwrap();
    let (transfer, split, merge) = fixture.requests(false);
    let prepared_transfer = transfer_trust.prepare(&transfer).unwrap();
    let prepared_split = coin_trust.prepare_split(&split).unwrap();
    let prepared_merge = coin_trust.prepare_merge(&merge).unwrap();
    for (prepared, review) in [
        (
            &prepared_transfer.prepared,
            prepared_transfer.review.as_str(),
        ),
        (&prepared_split.prepared, prepared_split.review.as_str()),
        (&prepared_merge.prepared, prepared_merge.review.as_str()),
    ] {
        let PaidApplication::Call(call) = &prepared.intent().application else {
            panic!("paid Call");
        };
        assert_eq!(call.instance, fixture.manifest.fee_policy.instance);
        assert_eq!(
            call.type_arguments,
            fixture.manifest.fee_policy.type_arguments
        );
        assert!(!review.contains("application_"));
    }
}

#[test]
fn every_application_coin_position_refuses_genesis_or_another_asset_type() {
    let fixture: Fixture = Fixture::new();
    let (transfer_trust, coin_trust) = fixture.trusts(0xe7);
    for bytes in [
        fixture.genesis_coin.clone(),
        fixture.coin(ObjectId::new([0xf1; 32]), 0xf2, 100),
    ] {
        let (mut transfer, mut split, merge) = fixture.requests(true);
        transfer.coin_bytes = bytes.clone();
        split.coin_bytes = bytes.clone();
        assert!(
            transfer_trust
                .prepare(&transfer)
                .err()
                .unwrap()
                .to_string()
                .contains("pinned application Standard Asset Coin type")
        );
        assert!(
            coin_trust
                .prepare_split(&split)
                .err()
                .unwrap()
                .to_string()
                .contains("pinned application Standard Asset Coin type")
        );
        for source in [false, true] {
            let mut mixed: AssetMergeRequest = merge.clone();
            if source {
                mixed.from_bytes = bytes.clone();
            } else {
                mixed.into_bytes = bytes.clone();
            }
            assert!(
                coin_trust
                    .prepare_merge(&mixed)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("pinned application Standard Asset Coin type")
            );
        }
    }
}

#[test]
fn application_coins_never_become_fee_sources_for_any_operation() {
    let fixture: Fixture = Fixture::new();
    let (transfer_trust, coin_trust) = fixture.trusts(0xe7);
    let (mut transfer, mut split, mut merge) = fixture.requests(true);
    // Distinct IDs, correct owner/schema/body, only the nominal asset differs.
    let fee: Vec<u8> = fixture.coin(ObjectId::new([0xe1; 32]), 0xf3, 9_000_000);
    transfer.fee_bytes = fee.clone();
    split.fee_bytes = fee.clone();
    merge.fee_bytes = fee;
    for error in [
        transfer_trust.prepare(&transfer).err().unwrap(),
        coin_trust.prepare_split(&split).err().unwrap(),
        coin_trust.prepare_merge(&merge).err().unwrap(),
    ] {
        assert!(
            error
                .to_string()
                .contains("fee source is not the genesis Standard Asset Coin type")
        );
    }
}

#[test]
fn application_pin_validation_is_not_bypassed_by_transfer_or_split_merge_constructors() {
    let fixture: Fixture = Fixture::new();
    let asset: ObjectId = ObjectId::new([0xe1; 32]);
    for alteration in 0..4 {
        let mut record: InstanceRecord = fixture.record(0xe7);
        match alteration {
            0 => record.creator = fixture.recipient,
            1 => record.initializer = "different_initializer".to_owned(),
            2 => {
                record.context = PublicationContext::new(
                    record.context.chain_id().clone(),
                    record.context.protocol_version(),
                    Epoch::new(1),
                )
                .unwrap()
            }
            _ => {
                record.code = sunrise_edge_client::publication::UnverifiedDependencyRef::new(
                    record.code.origin().clone(),
                    record.code.revision(),
                    record.code.context().clone(),
                    fixture.manifest.fee_policy.base_policy_digest,
                )
                .unwrap()
            }
        }
        let bytes: Vec<u8> = encode_instance_record(&record).unwrap();
        for error in [
            AssetTransferTrust::new(
                fixture.config.clone(),
                fixture.root(),
                Some((asset, bytes.clone())),
            )
            .err()
            .unwrap(),
            AssetSplitMergeTrust::new(fixture.config.clone(), fixture.root(), Some((asset, bytes)))
                .err()
                .unwrap(),
        ] {
            assert!(error.to_string().contains("application instance record does not match the pinned custody context, code, revision, initializer or creator"));
        }
    }
    let mut trailing: Vec<u8> = encode_instance_record(&fixture.record(0xe7)).unwrap();
    trailing.push(0);
    assert!(
        AssetTransferTrust::new(
            fixture.config.clone(),
            fixture.root(),
            Some((asset, trailing.clone()))
        )
        .is_err()
    );
    assert!(
        AssetSplitMergeTrust::new(
            fixture.config.clone(),
            fixture.root(),
            Some((asset, trailing))
        )
        .is_err()
    );
    let genesis_asset: ObjectId = fixture.genesis_asset;
    let bytes: Vec<u8> = encode_instance_record(&fixture.record(0xe7)).unwrap();
    assert!(
        AssetTransferTrust::new(
            fixture.config.clone(),
            fixture.root(),
            Some((genesis_asset, bytes.clone()))
        )
        .is_err()
    );
    assert!(
        AssetSplitMergeTrust::new(
            fixture.config.clone(),
            fixture.root(),
            Some((genesis_asset, bytes))
        )
        .is_err()
    );
}

fn store_approval(
    directory: &TempDir,
    fixture: &Fixture,
    request_id: RequestId,
    prepared: &PreparedPaidExecution,
) {
    approvals::write_approval(
        &directory.0,
        &request_id,
        &ApprovalRecord {
            publisher: fixture.signer.address(),
            not_after_unix_seconds: u64::MAX,
            frame: prepared.signable_frame().to_vec(),
        },
    )
    .unwrap();
}

#[test]
fn approval_for_one_application_instance_refuses_another_even_with_the_same_coin_types() {
    let fixture: Fixture = Fixture::new();
    let (approved_transfer, approved_coins) = fixture.trusts(0xe7);
    let (other_transfer, other_coins) = fixture.trusts(0xe8);
    let (transfer, split, merge) = fixture.requests(true);
    let directory: TempDir = TempDir::new(0o700);
    let prepared_transfer = approved_transfer.prepare(&transfer).unwrap();
    let prepared_split = approved_coins.prepare_split(&split).unwrap();
    let prepared_merge = approved_coins.prepare_merge(&merge).unwrap();
    assert!(other_transfer.prepare(&transfer).is_ok());
    assert!(other_coins.prepare_split(&split).is_ok());
    assert!(other_coins.prepare_merge(&merge).is_ok());
    store_approval(
        &directory,
        &fixture,
        transfer.request_id,
        &prepared_transfer.prepared,
    );
    store_approval(
        &directory,
        &fixture,
        split.request_id,
        &prepared_split.prepared,
    );
    store_approval(
        &directory,
        &fixture,
        merge.request_id,
        &prepared_merge.prepared,
    );
    assert!(
        server::sign_transfer_request(
            &fixture.config,
            &fixture.signer,
            &directory.0,
            &approved_transfer,
            &transfer
        )
        .is_ok()
    );
    assert_eq!(
        server::sign_transfer_request(
            &fixture.config,
            &fixture.signer,
            &directory.0,
            &other_transfer,
            &transfer
        ),
        Err(CustodyResponseStatus::NoApproval)
    );
    for request in [
        AssetSplitMergeRequest::Split(Box::new(split)),
        AssetSplitMergeRequest::Merge(Box::new(merge)),
    ] {
        assert!(
            server::sign_split_merge_request(
                &fixture.config,
                &fixture.signer,
                &directory.0,
                &approved_coins,
                &request
            )
            .is_ok()
        );
        assert_eq!(
            server::sign_split_merge_request(
                &fixture.config,
                &fixture.signer,
                &directory.0,
                &other_coins,
                &request
            ),
            Err(CustodyResponseStatus::NoApproval)
        );
    }
}

#[test]
fn genesis_approvals_cannot_authorize_application_transfer_split_or_merge() {
    let fixture: Fixture = Fixture::new();
    let genesis_transfer =
        AssetTransferTrust::new(fixture.config.clone(), fixture.root(), None).unwrap();
    let genesis_coins =
        AssetSplitMergeTrust::new(fixture.config.clone(), fixture.root(), None).unwrap();
    let (application_transfer, application_coins) = fixture.trusts(0xe7);
    let (transfer, split, merge) = fixture.requests(false);
    let directory: TempDir = TempDir::new(0o700);
    store_approval(
        &directory,
        &fixture,
        transfer.request_id,
        &genesis_transfer.prepare(&transfer).unwrap().prepared,
    );
    store_approval(
        &directory,
        &fixture,
        split.request_id,
        &genesis_coins.prepare_split(&split).unwrap().prepared,
    );
    store_approval(
        &directory,
        &fixture,
        merge.request_id,
        &genesis_coins.prepare_merge(&merge).unwrap().prepared,
    );
    let (transfer, split, merge) = fixture.requests(true);
    // Positive preparation proves the refusals below reach full-frame comparison.
    assert!(application_transfer.prepare(&transfer).is_ok());
    assert!(application_coins.prepare_split(&split).is_ok());
    assert!(application_coins.prepare_merge(&merge).is_ok());
    assert_eq!(
        server::sign_transfer_request(
            &fixture.config,
            &fixture.signer,
            &directory.0,
            &application_transfer,
            &transfer
        ),
        Err(CustodyResponseStatus::NoApproval)
    );
    for request in [
        AssetSplitMergeRequest::Split(Box::new(split)),
        AssetSplitMergeRequest::Merge(Box::new(merge)),
    ] {
        assert_eq!(
            server::sign_split_merge_request(
                &fixture.config,
                &fixture.signer,
                &directory.0,
                &application_coins,
                &request
            ),
            Err(CustodyResponseStatus::NoApproval)
        );
    }
}
