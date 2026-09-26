//! Test-only, four-validator FastVote genesis manifest and one real
//! sender-signed paid intent, built entirely from public production types.
//!
//! Reuses `sunrise_edge_devnet::build_paid_genesis_manifest` (the devnet's
//! pure, non-`#[cfg(test)]` genesis builder) and its public
//! `DEVNET_PAID_GENESIS_SEED` development-only signing seed -- both
//! explicitly permitted for test use only; nothing here ever runs inside
//! `fastvote_pg` itself. The builder's own manifest is single-validator, so
//! this module replaces its one genesis-authority bond with one positive
//! bond per test validator, adjusts the treasury supply to match, and
//! re-signs the manifest under the exact same devnet genesis key.
#![allow(dead_code)]

use abi::call_values::{CallValue, encode_call_value};
use abi::{AccessEntry, AccessManifest};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::{CallIntent, InstanceTarget};
use execution::local_execution::ObjectAuthority;
use execution::paid_execution::{
    FeeSourceConsent, PaidApplication, PaidIntent, ReservationAccessKind, SignedPaidIntent,
    encode_signed_paid_intent, paid_fee_policy_digest, paid_intent_signing_frame,
};
use execution::publication::PublicationContext;
use execution::publication::UnverifiedDependencyRef;
use fees::Amount;
use hashing::HashSuiteResolver;
use node_core::fast_path::FastPathValidatorSetRecord;
use node_core::fast_path::records::FastPathValidatorEntry;
use node_core::genesis::genesis_manifest_signing_frame;
use node_core::{GenesisObjectEntry, encode_genesis_manifest, genesis_manifest_commitment};
use objects::{
    AccessMode, Object, ObjectId, ObjectRef, Owner, ProtocolCustodyPurpose, ProtocolCustodyScope,
    encode_object,
};
use protocol_types::{
    AtomicityDomainId, ChainId, Epoch, HashPurpose, HashSuite, HashSuiteSchedule, ProtocolVersion,
    SignatureSchemeId, ValidatorId,
};
use public_standard_asset::{
    asset_type_argument, coin_amount, coin_body_layout, transfer_arguments,
    treasury_cap_body_layout, treasury_supply,
};
use sunrise_edge_devnet::{
    DEVNET_PAID_GENESIS_SEED, DevOwner, build_paid_genesis_manifest, paid_genesis_authority,
};

/// One test-only FastVote validator: a real, freshly generated Ed25519
/// identity, never used outside this fixture.
pub struct FastVoteValidator {
    /// Raw 32-byte Ed25519 seed, exactly the shape `fastvote_pg` reads from
    /// its local signing-key file.
    pub seed: [u8; 32],
    pub signing_key: SigningKey,
    pub validator_id: ValidatorId,
}

/// A complete, self-consistent, exactly-signed four-validator genesis plus
/// one real sender-signed paid intent, ready to drive four independent
/// `fastvote_pg` operator namespaces end to end.
pub struct FastVoteGenesisFixture {
    pub resolver: HashSuiteResolver,
    pub context: PublicationContext,
    pub chain_id: ChainId,
    pub protocol_version: ProtocolVersion,
    pub epoch: Epoch,
    pub domain: AtomicityDomainId,
    pub validators: Vec<FastVoteValidator>,
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest: [u8; 32],
    pub paid_intent_bytes: Vec<u8>,
    pub sender: [u8; 32],
    pub request_id: [u8; 32],
    pub fee_coin: ObjectId,
    sender_key: SigningKey,
    fee_coin_ref: ObjectRef,
    fee_policy_digest: protocol_types::Digest32,
    definition_id: ObjectId,
    code: UnverifiedDependencyRef,
    instance: InstanceTarget,
}

impl FastVoteGenesisFixture {
    /// Signs a second, independent `transfer` paid intent reusing the exact
    /// same genesis fee coin and sender, under an explicitly chosen
    /// `request_id`/`nonce`/recipient. Used only to build fail-closed
    /// conflict/replay negatives against the fixture's own real genesis
    /// state; the positive path only ever uses [`Self::paid_intent_bytes`].
    #[must_use]
    pub fn sign_transfer(&self, request_id: [u8; 32], nonce: u64, recipient: [u8; 32]) -> Vec<u8> {
        let call: CallIntent = CallIntent {
            context: self.context.clone(),
            request_id,
            sender: self.sender,
            nonce,
            code: self.code.clone(),
            instance: self.instance.clone(),
            entrypoint: "transfer".to_owned(),
            type_arguments: vec![asset_type_argument(&self.definition_id)],
            access: AccessManifest {
                entries: vec![AccessEntry {
                    object_ref: self.fee_coin_ref.clone(),
                    mode: AccessMode::Write,
                }],
            },
            arguments: transfer_arguments(&recipient).unwrap(),
            gas_limit: 100_000,
        };
        let intent: PaidIntent = PaidIntent {
            context: self.context.clone(),
            request_id,
            sender: self.sender,
            nonce,
            fee_policy_digest: self.fee_policy_digest,
            consent: FeeSourceConsent {
                source: self.fee_coin_ref.clone(),
                access: ReservationAccessKind::Write,
                max_fee: Amount::new(1_000_000),
                refund_recipient: recipient,
            },
            application: PaidApplication::Call(call),
            gas_limit: 100_000,
            authorizations: Vec::new(),
        };
        let frame: Vec<u8> = paid_intent_signing_frame(&self.context, &intent).unwrap();
        let signature: [u8; 64] = self.sender_key.sign(&frame).into();
        encode_signed_paid_intent(&SignedPaidIntent { intent, signature }).unwrap()
    }

    /// Signs the exact supplied intent under its declared context for HTTP
    /// authentication/epoch regressions, without changing any live state.
    #[must_use]
    pub fn sign_intent(&self, intent: PaidIntent) -> Vec<u8> {
        let frame: Vec<u8> = paid_intent_signing_frame(&intent.context, &intent).unwrap();
        let signature: [u8; 64] = self.sender_key.sign(&frame).into();
        encode_signed_paid_intent(&SignedPaidIntent { intent, signature }).unwrap()
    }

    /// The public Standard Asset definition object id, needed to build the
    /// `asset_type_argument` a real CLI-built `transfer` call's
    /// `--type-args` must supply.
    #[must_use]
    pub const fn definition_id(&self) -> ObjectId {
        self.definition_id
    }

    /// The exact `UnverifiedDependencyRef` a real CLI-built call's
    /// `--code-ref`/`--instance-ref` resolution needs to match this
    /// fixture's installed code.
    #[must_use]
    pub fn code(&self) -> UnverifiedDependencyRef {
        self.code.clone()
    }

    /// The exact fee-coin `ObjectRef` (including its live digest) a real
    /// CLI-built call's `--access`/`--fee-source` must reference.
    #[must_use]
    pub fn fee_coin_ref(&self) -> ObjectRef {
        self.fee_coin_ref.clone()
    }

    /// Reconstructs the exact `InstanceRecord`
    /// `sunrise_edge_devnet::build_paid_genesis_manifest` installed for the
    /// public Standard Asset instance this fixture's fee coin belongs to --
    /// the same shape `contract paid-call --instance-ref` needs, so a real
    /// CLI invocation can independently build and sign a call against it
    /// instead of only ever replaying [`Self::paid_intent_bytes`].
    #[must_use]
    pub fn instance_record(&self) -> execution::local_execution::InstanceRecord {
        execution::local_execution::InstanceRecord {
            context: self.context.clone(),
            creator: paid_genesis_authority(),
            seed: self
                .resolver
                .hash_for_purpose(
                    self.epoch,
                    HashPurpose::ProtocolConfig,
                    b"sunrise.devnet.public-standard-asset.instance.v1",
                )
                .unwrap()
                .bytes(),
            code: self.code.clone(),
            revision: 1,
            initializer: public_standard_asset::INITIALIZER.to_owned(),
        }
    }
}

/// The fixed hash-suite string every `fastvote_pg` `--suite` flag must carry
/// to match [`build_fixture`]'s resolver: `HashSuite::genesis()` under a
/// genesis-epoch-only schedule.
pub const SUITE_FLAG: &str = "0:1:1:1:1:1:1:1";

fn genesis_signing_key() -> SigningKey {
    SigningKey::from(DEVNET_PAID_GENESIS_SEED)
}

/// Builds one fresh, self-consistent fixture. `unique` must be distinct per
/// test run sharing the live database (used only to derive the chain id and
/// atomicity domain, so repeated runs never collide with prior fast-path
/// state).
#[must_use]
pub fn build_fixture(unique: &str) -> FastVoteGenesisFixture {
    build_fixture_with_protocol(unique, ProtocolVersion::new(1), Epoch::new(0))
}

/// Network CLI queries require the activated transaction-auth profile (v3).
#[must_use]
pub fn build_network_fixture(unique: &str) -> FastVoteGenesisFixture {
    build_network_fixture_at_epoch(unique, Epoch::new(0))
}

/// Controlled fixture for fixed-pin and live-epoch HTTP regressions.
#[must_use]
pub fn build_network_fixture_at_epoch(unique: &str, epoch: Epoch) -> FastVoteGenesisFixture {
    build_fixture_with_protocol(unique, ProtocolVersion::new(3), epoch)
}

/// Explicit context fixture for authentication mismatch tests.
#[must_use]
pub fn build_fixture_with_protocol(
    unique: &str,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
) -> FastVoteGenesisFixture {
    let chain_id: ChainId = ChainId::new(format!("fastvote-pg-e2e-{unique}")).unwrap();
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain_id.clone(),
        protocol_version,
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let context: PublicationContext =
        PublicationContext::new(chain_id.clone(), protocol_version, epoch).unwrap();
    let mut domain_bytes: [u8; 32] = [0x51; 32];
    domain_bytes[..unique.len().min(24)]
        .copy_from_slice(&unique.as_bytes()[..unique.len().min(24)]);
    let domain: AtomicityDomainId = AtomicityDomainId::new(domain_bytes).unwrap();

    let sender_key: SigningKey = SigningKey::from([0x21; 32]);
    let sender: [u8; 32] = VerificationKey::from(&sender_key).into();
    let sender_owner: DevOwner = DevOwner::new(sender);

    let (mut manifest, metadata) =
        build_paid_genesis_manifest(&resolver, &context, &[sender_owner], sender_owner).unwrap();

    let mut validators: Vec<FastVoteValidator> = Vec::with_capacity(4);
    for seed_byte in [0xA1u8, 0xA2, 0xA3, 0xA4] {
        let seed: [u8; 32] = [seed_byte; 32];
        let signing_key: SigningKey = SigningKey::from(seed);
        let public_key: [u8; 32] = VerificationKey::from(&signing_key).into();
        validators.push(FastVoteValidator {
            seed,
            signing_key,
            validator_id: ValidatorId::new(public_key),
        });
    }

    // Replace the builder's single genesis-authority bond with one positive
    // bond per test validator (DR-0136: exactly one genesis bond per
    // genesis validator), keeping the same custody resource and the same
    // authority/type shape as every other Coin-typed genesis object.
    let original_bond: GenesisObjectEntry = manifest.objects.pop().expect("genesis bond present");
    let resource: [u8; 32] = match original_bond.object.owner {
        Owner::ProtocolCustody(scope) => scope.resource,
        _ => panic!("devnet genesis bond must be protocol-custody owned"),
    };
    let bond_amount: u64 = coin_amount(&original_bond.object.data).unwrap();
    let bond_authority_template: ObjectAuthority = manifest.objects[2].authority.clone();
    let bond_type_hash = manifest.objects[2].object.type_hash;

    for (index, validator) in validators.iter().enumerate() {
        let label: String = format!("fastvote-pg-e2e.bond.v1/{index}");
        let object_id: ObjectId = ObjectId::new(
            resolver
                .hash_for_purpose(epoch, HashPurpose::Object, label.as_bytes())
                .unwrap()
                .bytes(),
        );
        let mut authority: ObjectAuthority = bond_authority_template.clone();
        authority.object_id = object_id;
        let bond_object: Object = Object {
            id: object_id,
            version: 1,
            owner: Owner::ProtocolCustody(ProtocolCustodyScope {
                purpose: ProtocolCustodyPurpose::BondCollateral,
                chain_id: chain_id.clone(),
                subject: *validator.validator_id.as_bytes(),
                resource,
            }),
            type_hash: bond_type_hash,
            schema_version: public_standard_asset::SCHEMA_VERSION,
            data: encode_call_value(&coin_body_layout(), &CallValue::U64(bond_amount)).unwrap(),
        };
        manifest.objects.push(GenesisObjectEntry {
            authority,
            object: bond_object,
        });
    }

    manifest.validator_set = FastPathValidatorSetRecord {
        context: context.clone(),
        validators: validators
            .iter()
            .map(|validator| FastPathValidatorEntry {
                id: validator.validator_id,
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: validator.validator_id.as_bytes().to_vec(),
            })
            .collect(),
    };

    // Keep the TreasuryCap total supply consistent with the seeded Coin
    // total: one bond removed, four added, at the same per-bond amount.
    let treasury_entry: &mut GenesisObjectEntry = &mut manifest.objects[1];
    let old_supply: u64 = treasury_supply(&treasury_entry.object.data).unwrap();
    let new_supply: u64 = old_supply
        .checked_add(bond_amount.checked_mul(3).unwrap())
        .unwrap();
    treasury_entry.object.data =
        encode_call_value(&treasury_cap_body_layout(), &CallValue::U64(new_supply)).unwrap();

    manifest.signature = genesis_signing_key()
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();

    let manifest_bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    let manifest_digest: [u8; 32] = genesis_manifest_commitment(&resolver, &manifest)
        .unwrap()
        .bytes();

    // One real sender-signed paid intent: transfers the sender's own
    // genesis fee_coin (funding both the fee reservation and the transfer
    // itself, exactly like node-core's own canonical fixture transfer) to a
    // fixed recipient address.
    let fee_coin: ObjectId = metadata.owner_coins[0].fee_coin;
    let fee_coin_object: Object = manifest
        .objects
        .iter()
        .find(|entry| entry.object.id == fee_coin)
        .expect("fee coin genesis object present")
        .object
        .clone();
    let fee_coin_ref: ObjectRef = ObjectRef {
        id: fee_coin,
        version: 1,
        digest: resolver
            .hash_for_purpose(
                epoch,
                HashPurpose::Object,
                &encode_object(&fee_coin_object).unwrap(),
            )
            .unwrap(),
    };
    let recipient: [u8; 32] = VerificationKey::from(&SigningKey::from([0x31; 32])).into();
    let request_id: [u8; 32] = [0xC7; 32];
    let fee_policy_digest = paid_fee_policy_digest(&resolver, &manifest.fee_policy).unwrap();

    let mut fixture: FastVoteGenesisFixture = FastVoteGenesisFixture {
        resolver,
        context,
        chain_id,
        protocol_version,
        epoch,
        domain,
        validators,
        manifest_bytes,
        manifest_digest,
        paid_intent_bytes: Vec::new(),
        sender,
        request_id,
        fee_coin,
        sender_key,
        fee_coin_ref,
        fee_policy_digest,
        definition_id: metadata.definition_id,
        code: metadata.code,
        instance: metadata.instance,
    };
    fixture.paid_intent_bytes = fixture.sign_transfer(request_id, 0, recipient);
    fixture
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::{ConsensusSigner, FastPathCertifier, FastVote, encode_fast_certificate};
    use execution::LocalWasmExecutionEngine;
    use execution::local_execution::LocalExecutionPolicy;
    use node_core::fast_path::{self, FastPathEd25519Verifier};
    use node_core::{GenesisInstallOutcome, decode_genesis_manifest, install_genesis};
    use runtime::{
        DurableOperationContext, MemoryBlobStore, MemoryDurableStateStore, StorageCorrelationId,
        StorageDeadline, WriterFenceGeneration,
    };
    use validator_set::{ValidatorInfo, ValidatorSet};

    struct MemorySigner<'a> {
        id: ValidatorId,
        key: &'a SigningKey,
    }

    impl ConsensusSigner for MemorySigner<'_> {
        fn validator_id(&self) -> ValidatorId {
            self.id
        }
        fn signature_scheme(&self) -> SignatureSchemeId {
            SignatureSchemeId::Ed25519
        }
        fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
            let signature: [u8; 64] = self.key.sign(framed).into();
            Ok(signature.to_vec())
        }
    }

    /// Cheap, no-database regression proving the fixture itself is
    /// internally consistent: the manifest installs fresh, all four
    /// validators can independently prepare the same real paid intent into
    /// byte-identical votes, a 3-of-4 certificate forms, and applying it
    /// succeeds. Any future change to this fixture that breaks the live
    /// PostgreSQL E2E should already fail here first, in-memory.
    #[test]
    fn fixture_installs_and_certifies_in_memory() {
        let fixture: FastVoteGenesisFixture = build_fixture("memcheck");
        let manifest = decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
        let context: DurableOperationContext = DurableOperationContext::new(
            WriterFenceGeneration::new(1).unwrap(),
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([1; 16]).unwrap(),
        );

        let base_policy: LocalExecutionPolicy =
            LocalExecutionPolicy::generic_object_results(fixture.context.clone());
        let engine = LocalWasmExecutionEngine::new();

        // Mirrors the real deployment: each validator owns an entirely
        // independent durable namespace, so every validator gets its own
        // fresh store here too, each independently installing the same
        // signed genesis manifest before preparing.
        let mut stores: Vec<(MemoryDurableStateStore, MemoryBlobStore)> =
            Vec::with_capacity(fixture.validators.len());
        let mut votes: Vec<FastVote> = Vec::with_capacity(fixture.validators.len());
        for validator in &fixture.validators {
            let store: MemoryDurableStateStore = MemoryDurableStateStore::new_bound(
                fixture.domain,
                WriterFenceGeneration::new(1).unwrap(),
            );
            let outcome = install_genesis(
                &store,
                &context,
                fixture.domain,
                &fixture.resolver,
                &manifest,
                1,
            )
            .unwrap();
            assert!(matches!(
                outcome,
                GenesisInstallOutcome::FreshInstall { .. }
            ));

            let blobs: MemoryBlobStore = MemoryBlobStore::default();
            let signer: MemorySigner<'_> = MemorySigner {
                id: validator.validator_id,
                key: &validator.signing_key,
            };
            let vote: FastVote = fast_path::prepare(
                &store,
                &blobs,
                &context,
                fixture.domain,
                &fixture.resolver,
                &[],
                &fixture.context,
                &base_policy,
                &manifest.fee_policy,
                &engine,
                &signer,
                &fixture.paid_intent_bytes,
                1,
            )
            .unwrap();
            votes.push(vote);
            stores.push((store, blobs));
        }

        // A conflicting second intent under the exact same request id (same
        // fee coin, different nonce) must fail closed, without disturbing
        // the already-prepared vote for that request id.
        let (first_store, first_blobs) = &stores[0];
        let conflicting_signer: MemorySigner<'_> = MemorySigner {
            id: fixture.validators[0].validator_id,
            key: &fixture.validators[0].signing_key,
        };
        let conflicting_bytes: Vec<u8> = fixture.sign_transfer(
            fixture.request_id,
            1,
            VerificationKey::from(&SigningKey::from([0x41; 32])).into(),
        );
        let conflict_result = fast_path::prepare(
            first_store,
            first_blobs,
            &context,
            fixture.domain,
            &fixture.resolver,
            &[],
            &fixture.context,
            &base_policy,
            &manifest.fee_policy,
            &engine,
            &conflicting_signer,
            &conflicting_bytes,
            1,
        );
        assert!(
            conflict_result.is_err(),
            "a conflicting prepared replay under the same request id must fail closed"
        );
        // The original, already-prepared vote is unaffected by the rejected
        // conflicting attempt: exact replay of the real bytes still returns
        // the identical vote.
        let replayed_vote: FastVote = fast_path::prepare(
            first_store,
            first_blobs,
            &context,
            fixture.domain,
            &fixture.resolver,
            &[],
            &fixture.context,
            &base_policy,
            &manifest.fee_policy,
            &engine,
            &conflicting_signer,
            &fixture.paid_intent_bytes,
            1,
        )
        .unwrap();
        assert_eq!(replayed_vote, votes[0]);

        let validator_infos: Vec<ValidatorInfo> = manifest
            .validator_set
            .validators
            .iter()
            .map(|entry| ValidatorInfo {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key.clone(),
            })
            .collect();
        let validator_set: ValidatorSet =
            ValidatorSet::new(fixture.epoch, validator_infos).unwrap();
        let certifier: FastPathCertifier = FastPathCertifier::new(
            fixture.chain_id.clone(),
            fixture.protocol_version,
            fixture.epoch,
            validator_set,
        )
        .unwrap();
        let target: &FastVote = &votes[0];
        let certificate = certifier
            .try_form_certificate(
                target.tx_hash,
                target.execution_effects_hash,
                target.locked_objects_digest,
                &votes[..3],
                &FastPathEd25519Verifier,
            )
            .unwrap()
            .expect("3-of-4 equal-power votes must certify");

        let certificate_bytes: Vec<u8> = encode_fast_certificate(&certificate).unwrap();
        for (store, blobs) in &stores {
            let output = fast_path::apply(
                store,
                blobs,
                &context,
                fixture.domain,
                &fixture.resolver,
                &[],
                &fixture.context,
                &base_policy,
                &manifest.fee_policy,
                &engine,
                &fixture.paid_intent_bytes,
                &certificate_bytes,
            )
            .unwrap();
            assert!(!output.responses().is_empty());
        }
    }
}
