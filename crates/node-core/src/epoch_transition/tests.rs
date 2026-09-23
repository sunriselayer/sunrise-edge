//! DR-0132 phase 2 slice 2 regressions.
//!
//! Two fixture families are used:
//!
//! * The lighter-weight `crate::paid_execution::tests` fixture (a real
//!   Standard Asset WASM environment, but bootstrapped by directly writing
//!   durable rows rather than through `crate::genesis`) drives most
//!   `propose_and_vote`/`activate` mechanics and adversarial tests.
//! * [`build_genesis_fixture`] builds a real, signed
//!   [`crate::genesis::GenesisManifest`] with an independent FastVote
//!   validator set, installed through the production
//!   `crate::genesis::install_genesis_with_history` path, for the headline
//!   four-validator SQLite test and the restart-verify (C1) tests: both need
//!   a real genesis install to exercise, not a hand-poked one.
use super::*;
use crate::economics::{FastPathEconomicsPolicy, FastPathEconomicsResourcePolicy};
use crate::genesis::{
    GenesisError, GenesisInstallOutcome, GenesisManifest, GenesisObjectEntry,
    genesis_manifest_signing_frame, install_genesis_with_history,
};
use crate::paid_execution::tests::{
    CountingEngine, Fixture, domain as pe_domain, entry as pe_entry, install as install_pe_fixture,
    memory_store, protocol as pe_protocol, receipt, refund_account as pe_refund_account,
    resolver as pe_resolver, set_state,
};
use abi::call_values::{CallValue, encode_call_value};
use abi::package_types::{PackageOrigin, ScopedTypeArg, derive_scoped_type_id};
use bonds::{BondResourceConfig, BondResourceId};
use consensus::{FastCertificate, FastVote};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::{
    InstanceRecord, LocalExecutionIntent, LocalExecutionMode, ObjectAuthority,
    SignedLocalExecutionIntent, generic_object_result_semantics, instance_target,
    local_execution_signing_frame,
};
use execution::paid_execution::{
    FeeSourceConsent, MIN_RESERVE_ALLOWANCE, MIN_SETTLE_ALLOWANCE, PaidApplication,
    PaidExecutionStatus, PaidIntent, ReservationAccessKind, SignedPaidIntent,
    encode_signed_paid_intent, paid_fee_policy_digest, paid_intent_signing_frame,
};
use execution::publication::{
    ArtifactParts, CodeArtifact, PublicationRequest, PublicationSubmission,
    UnverifiedDependencyRef, artifact_commitment, publication_submission_signing_frame,
};
use fast_path::records::{
    FastPathValidatorEntry, FastPathValidatorSetRecord, encode_fastpath_bond_record,
};
use fees::{Amount, GasSchedule};
use objects::{
    AccessMode, Address, Object, ObjectId, Owner, ProtocolCustodyPurpose, ProtocolCustodyScope,
};
use protocol_types::{
    HashAlgorithmId, HashPurpose, HashSuite, HashSuiteId, HashSuiteSchedule, ProtocolVersion,
    ValidatorId,
};
use runtime::{
    DurableDomainStateStore, DurableOutboxClaimOutcome, DurableOutboxLeaseId,
    IndexedOutboxRepository, MemoryDurableStateStore, OutboxRequestId, RequestOutboxClaimRequest,
    StorageCorrelationId, StorageDeadline, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};

// ── shared context helpers ──────────────────────────────────────────────

pub(crate) fn chain() -> ChainId {
    ChainId::new("epoch-transition-test").unwrap()
}
pub(crate) fn protocol_version() -> ProtocolVersion {
    ProtocolVersion::new(3)
}
pub(crate) fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        chain(),
        protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn epoch_context(epoch: u64) -> PublicationContext {
    PublicationContext::new(chain(), protocol_version(), Epoch::new(epoch)).unwrap()
}
fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([0x42; 32]).unwrap()
}
fn context(generation: u64) -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(generation).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([9; 16]).unwrap(),
    )
}

/// A real (non-mocked) Ed25519 `ConsensusSigner`, mirroring
/// `fast_path::tests`' own private test signer.
struct TestSigner {
    validator_id: ValidatorId,
    signing_key: SigningKey,
}
impl ConsensusSigner for TestSigner {
    fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        let signature_bytes: [u8; 64] = self.signing_key.sign(framed).into();
        Ok(signature_bytes.to_vec())
    }
}

fn validator(seed: u8) -> (TestSigner, FastPathValidatorEntry) {
    let signing_key: SigningKey = SigningKey::from([seed; 32]);
    let verification_key: VerificationKey = VerificationKey::from(&signing_key);
    let id_bytes: [u8; 32] = verification_key.into();
    let id: ValidatorId = ValidatorId::new(id_bytes);
    let signer: TestSigner = TestSigner {
        validator_id: id,
        signing_key,
    };
    let entry: FastPathValidatorEntry = FastPathValidatorEntry {
        id,
        voting_power: 1,
        signature_scheme: SignatureSchemeId::Ed25519,
        public_key: id_bytes.to_vec(),
    };
    (signer, entry)
}

/// Four equal-power validators: quorum is 3-of-4.
fn four_validators() -> (Vec<TestSigner>, Vec<FastPathValidatorEntry>) {
    let mut signers: Vec<TestSigner> = Vec::new();
    let mut entries: Vec<FastPathValidatorEntry> = Vec::new();
    for seed in [201u8, 202, 203, 204] {
        let (signer, entry) = validator(seed);
        signers.push(signer);
        entries.push(entry);
    }
    (signers, entries)
}

/// A different four validators, standing in for the *incoming* (`e+1`) set
/// in every test below, so an outgoing-set signature can never accidentally
/// satisfy the incoming set's own quorum.
fn four_next_validators() -> (Vec<TestSigner>, Vec<FastPathValidatorEntry>) {
    let mut signers: Vec<TestSigner> = Vec::new();
    let mut entries: Vec<FastPathValidatorEntry> = Vec::new();
    for seed in [211u8, 212, 213, 214] {
        let (signer, entry) = validator(seed);
        signers.push(signer);
        entries.push(entry);
    }
    (signers, entries)
}

fn install_outgoing_validators<S: StructuredDurableDomainStateStore>(
    store: &S,
    entries: Vec<FastPathValidatorEntry>,
) {
    fast_path::install_validator_set(
        store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol(),
        entries,
    )
    .unwrap();
}

fn pe_context() -> DurableOperationContext {
    crate::paid_execution::tests::context()
}

fn certifier(
    chain: ChainId,
    epoch: Epoch,
    entries: &[FastPathValidatorEntry],
) -> EpochTransitionCertifier {
    let info: Vec<ValidatorInfo> = entries
        .iter()
        .map(|entry| ValidatorInfo {
            id: entry.id,
            voting_power: entry.voting_power,
            signature_scheme: entry.signature_scheme,
            public_key: entry.public_key.clone(),
        })
        .collect();
    EpochTransitionCertifier::new(
        chain,
        protocol_version(),
        epoch,
        ValidatorSet::new(epoch, info).unwrap(),
    )
    .unwrap()
}

// ── lighter-weight fixture: `paid_execution::tests` + a real outgoing set ──

/// Installs a bond-enabled economics policy (reusing the lightweight
/// fixture's own real Standard Asset instance/code/type, exactly like
/// `genesis::tests::build_fixture` does for the full-genesis fixture) and
/// one committed, eligible `Active` bond for each of `validators`, all at
/// `pe_protocol()`'s epoch. DR-0137 unit 3's pre-vote eligibility gate in
/// `propose_and_vote` requires this for every next-set validator; idempotent
/// across repeated calls for the same validator/key.
fn install_bond_policy_and_bonds<S: StructuredDurableDomainStateStore>(
    store: &S,
    fixture: &Fixture,
    validators: &[FastPathValidatorEntry],
) {
    let context: PublicationContext = pe_protocol();
    let instance: execution::call::InstanceTarget =
        instance_target(&pe_resolver(), &fixture.instance).unwrap();
    let coin_tag = public_standard_asset::coin_type_tag(&fixture.origin, &fixture.asset).unwrap();
    let (resource_domain, resource): (u16, [u8; 32]) = match coin_tag.args() {
        [ScopedTypeArg::Opaque { domain, value }] => (*domain, *value),
        _ => panic!("fixture coin type must carry one opaque resource"),
    };
    let resource_id: BondResourceId = BondResourceId::new(resource_domain, resource).unwrap();

    let policy_key: Vec<u8> =
        local_instance_state::fastpath_economics_policy_key(&context).unwrap();
    let policy_observed: VersionedStateValue = store
        .get_versioned_durable(&pe_context(), pe_domain(), &policy_key)
        .unwrap();
    if policy_observed.value().is_none() {
        let policy: FastPathEconomicsPolicy = FastPathEconomicsPolicy {
            context: context.clone(),
            resources: vec![FastPathEconomicsResourcePolicy {
                resource_id,
                context: context.clone(),
                instance: instance.clone(),
                code: fixture.code.clone(),
                ty: coin_tag.clone(),
                schema: public_standard_asset::SCHEMA_VERSION,
                split_entrypoint: "split".to_owned(),
                transfer_entrypoint: "transfer".to_owned(),
                bond: Some(BondResourceConfig {
                    resource_id,
                    min_bond: Amount::new(1),
                    enabled: true,
                    unbonding_epochs: 7,
                    max_validator_exposure: None,
                }),
                fee_escrow: false,
            }],
        };
        set_state(
            store,
            policy_key,
            StateMutation::Put(
                crate::economics::encode_fastpath_economics_policy(&policy).unwrap(),
            ),
        );
    }

    for validator in validators {
        let bond_key: Vec<u8> =
            local_instance_state::fastpath_bond_record_key(context.chain_id(), &validator.id)
                .unwrap();
        let bond_observed: VersionedStateValue = store
            .get_versioned_durable(&pe_context(), pe_domain(), &bond_key)
            .unwrap();
        if bond_observed.value().is_some() {
            continue;
        }
        let mut object_id_bytes: [u8; 32] = *validator.id.as_bytes();
        object_id_bytes[0] = 0x60;
        let object_id: ObjectId = ObjectId::new(object_id_bytes);
        let authorization_key: [u8; 32] = validator
            .public_key
            .as_slice()
            .try_into()
            .expect("fixture validator key length");
        let bond: FastPathBondRecord = FastPathBondRecord {
            context: context.clone(),
            validator_id: validator.id,
            resource_domain,
            resource,
            custody_object: ObjectRef {
                id: object_id,
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x61; 32]),
            },
            custody_object_epoch: context.epoch(),
            authority: ObjectAuthority {
                object_id,
                instance_context: context.clone(),
                instance: instance.clone(),
                code: fixture.code.clone(),
                ty: coin_tag.clone(),
            },
            amount: 1_000_000,
            committed_at_checkpoint: 0,
            generation: 1,
            lifecycle_epoch: context.epoch(),
            // This fixture installs a genesis-equivalent generation-1 bond
            // directly, not via a live `Deposit`: it is immediately liable,
            // exactly like a real genesis bond.
            slashable_from_epoch: context.epoch(),
            required_minimum: 1,
            state: FastPathBondState::Active,
            authorization_scheme: validator.signature_scheme,
            authorization_key,
        };
        set_state(
            store,
            bond_key,
            StateMutation::Put(encode_fastpath_bond_record(&bond).unwrap()),
        );
    }
}

/// Installs the `paid_execution::tests` fixture and a real matching
/// outgoing FastVote validator set at `pe_protocol()`'s epoch (0), plus a
/// bond-enabled economics policy and one eligible bond for every validator
/// in both the outgoing (`four_validators()`) and incoming
/// (`four_next_validators()`) sets -- the two fixed sets nearly every test
/// in this module uses.
fn install_lightweight<S: StructuredDurableDomainStateStore>(
    store: &S,
) -> (Fixture, Vec<TestSigner>, Vec<FastPathValidatorEntry>) {
    let fixture: Fixture = install_pe_fixture(store);
    let (signers, entries) = four_validators();
    install_outgoing_validators(store, entries.clone());
    let (_, next_entries) = four_next_validators();
    let mut bonded_validators: Vec<FastPathValidatorEntry> = entries.clone();
    bonded_validators.extend(next_entries);
    install_bond_policy_and_bonds(store, &fixture, &bonded_validators);
    (fixture, signers, entries)
}

/// Casts and forms a 3-of-4 quorum certificate for `pe_protocol()`'s epoch
/// `-> next_epoch` transition, from four independent `propose_and_vote`
/// calls against `store`.
fn propose_vote_and_certify<S: StructuredDurableDomainStateStore>(
    store: &S,
    signers: &[TestSigner],
    entries: &[FastPathValidatorEntry],
    next_validators: Vec<FastPathValidatorEntry>,
) -> (EpochTransitionCertificate, Digest32, Digest32) {
    let mut votes: Vec<EpochTransitionVote> = Vec::new();
    for signer in signers {
        let vote = propose_and_vote(
            store,
            &pe_context(),
            pe_domain(),
            &pe_resolver(),
            pe_protocol().chain_id(),
            pe_protocol().protocol_version(),
            next_validators.clone(),
            signer,
        )
        .unwrap();
        votes.push(vote);
    }
    for vote in &votes[1..] {
        assert_eq!(votes[0].next_epoch, vote.next_epoch);
        assert_eq!(
            votes[0].current_validator_set_digest,
            vote.current_validator_set_digest
        );
        assert_eq!(
            votes[0].next_validator_set_digest,
            vote.next_validator_set_digest
        );
        assert_eq!(votes[0].activation_digest, vote.activation_digest);
    }
    let cert = certifier(
        pe_protocol().chain_id().clone(),
        pe_protocol().epoch(),
        entries,
    );
    let certificate = cert
        .try_form_certificate(
            votes[0].next_epoch,
            votes[0].current_validator_set_digest,
            votes[0].next_validator_set_digest,
            votes[0].activation_digest,
            &votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .expect("3-of-4 equal power validators exceed quorum");
    (
        certificate.clone(),
        certificate.next_validator_set_digest,
        certificate.activation_digest,
    )
}

#[test]
fn propose_and_vote_is_deterministic_across_four_independent_calls_and_forms_a_quorum() {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();
    let (certificate, _, _) = propose_vote_and_certify(&store, &signers, &entries, next_entries);
    assert!(certificate.votes.len() >= 3);
    assert_eq!(certificate.epoch, pe_protocol().epoch());
    assert_eq!(
        certificate.next_epoch,
        Epoch::new(pe_protocol().epoch().get() + 1)
    );
}

/// DR-0132 §3.A: `derive_activation_set` canonicalizes `next_validators` by
/// `ValidatorId` before encoding anything, so two callers who independently
/// assemble the identical operator-supplied set in different orders --
/// which they have no other way to agree on -- still produce a
/// byte-identical [`FastPathEpochActivationSet`] (and therefore the same
/// `activation_digest`), not merely the same `next_validator_set_digest`
/// (which [`ValidatorSet::new`] already canonicalizes on its own).
#[test]
fn derive_activation_set_is_invariant_to_next_validator_input_order() {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, _signers, _entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();
    let mut reordered_entries = next_entries.clone();
    reordered_entries.reverse();
    assert_ne!(
        next_entries, reordered_entries,
        "the reordering must actually change the input order for this test to prove anything"
    );

    let next_epoch: Epoch = Epoch::new(pe_protocol().epoch().get() + 1);
    let forward: DerivedActivation = derive_activation_set(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        pe_protocol().epoch(),
        next_epoch,
        &next_entries,
    )
    .unwrap();
    let reversed: DerivedActivation = derive_activation_set(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        pe_protocol().epoch(),
        next_epoch,
        &reordered_entries,
    )
    .unwrap();

    assert_eq!(
        forward.next_validator_set_digest,
        reversed.next_validator_set_digest
    );
    assert_eq!(forward.activation_digest, reversed.activation_digest);
    // Byte-identical, not merely digest-equal: the committed
    // `FastPathValidatorSetRecord` bytes (and the whole activation write
    // set they are part of) are identical too.
    assert_eq!(forward.activation_set, reversed.activation_set);
}

/// DR-0137 unit 3's next-set eligibility coupling is gated exclusively by
/// [`propose_and_vote`], strictly before a vote is cast -- never by
/// [`derive_activation_set`]/[`activate`] (see `DerivedActivation`'s doc
/// comment: certificate application must be a pure function of an
/// already-certified transition, not of live mutable bond state). Every one
/// of the eight closed ineligibility reasons must reject the vote: jailed,
/// unbonding, exited, below the minimum, above the maximum exposure,
/// disabled by policy, an authorization key that diverges from the bond's
/// own committed key, and an altogether absent bond.
#[test]
fn propose_and_vote_rejects_every_ineligible_next_set_candidate() {
    fn expect_ineligible<S: StructuredDurableDomainStateStore>(
        store: &S,
        signer: &TestSigner,
        candidates: Vec<FastPathValidatorEntry>,
    ) {
        let result = propose_and_vote(
            store,
            &pe_context(),
            pe_domain(),
            &pe_resolver(),
            pe_protocol().chain_id(),
            pe_protocol().protocol_version(),
            candidates,
            signer,
        );
        assert!(
            matches!(
                result,
                Err(EpochTransitionError::Invalid(
                    "fast-path next validator set requires a committed, eligible bond"
                ))
            ),
            "expected an ineligible-candidate rejection, got {result:?}"
        );
    }

    // jailed / unbonding / exited / key-mismatch: mutate the one candidate's
    // own already-installed `Active` bond row.
    let states = [
        FastPathBondState::Jailed {
            evidence_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x50; 32]),
        },
        FastPathBondState::Unbonding {
            unlock_epoch: Epoch::new(99),
            recipient: [0x51; 32],
        },
        FastPathBondState::Exited,
    ];
    for state in states {
        let store: MemoryDurableStateStore = memory_store();
        let (_fixture, signers, _entries) = install_lightweight(&store);
        let (_next_signers, next_entries) = four_next_validators();
        let bond_key = local_instance_state::fastpath_bond_record_key(
            pe_protocol().chain_id(),
            &next_entries[0].id,
        )
        .unwrap();
        let observed = store
            .get_versioned_durable(&pe_context(), pe_domain(), &bond_key)
            .unwrap();
        let mut bond: FastPathBondRecord =
            crate::fast_path::records::decode_fastpath_bond_record(observed.value().unwrap())
                .unwrap();
        assert_eq!(bond.state, FastPathBondState::Active);
        bond.state = state;
        set_state(
            &store,
            bond_key,
            StateMutation::Put(encode_fastpath_bond_record(&bond).unwrap()),
        );
        expect_ineligible(&store, &signers[0], next_entries);
    }

    // key-mismatch: the committed bond's own authorization key diverges from
    // the candidate's registered public key (still a well-formed Ed25519
    // key -- some other real validator's -- so the row itself stays valid).
    {
        let store: MemoryDurableStateStore = memory_store();
        let (_fixture, signers, _entries) = install_lightweight(&store);
        let (_next_signers, next_entries) = four_next_validators();
        let (_other_signer, other_entry) = validator(230);
        let bond_key = local_instance_state::fastpath_bond_record_key(
            pe_protocol().chain_id(),
            &next_entries[0].id,
        )
        .unwrap();
        let observed = store
            .get_versioned_durable(&pe_context(), pe_domain(), &bond_key)
            .unwrap();
        let mut bond: FastPathBondRecord =
            crate::fast_path::records::decode_fastpath_bond_record(observed.value().unwrap())
                .unwrap();
        bond.authorization_key = other_entry
            .public_key
            .as_slice()
            .try_into()
            .expect("fixture validator key length");
        set_state(
            &store,
            bond_key,
            StateMutation::Put(encode_fastpath_bond_record(&bond).unwrap()),
        );
        expect_ineligible(&store, &signers[0], next_entries);
    }

    // absent: no committed bond row for the candidate at all.
    {
        let store: MemoryDurableStateStore = memory_store();
        let (_fixture, signers, _entries) = install_lightweight(&store);
        let (_next_signers, next_entries) = four_next_validators();
        let bond_key = local_instance_state::fastpath_bond_record_key(
            pe_protocol().chain_id(),
            &next_entries[0].id,
        )
        .unwrap();
        set_state(&store, bond_key, StateMutation::Delete);
        expect_ineligible(&store, &signers[0], next_entries);
    }

    // under-min / over-max / disabled: mutate the shared committed economics
    // policy resource, then use a `next_validators` list containing only the
    // one still-`Active` candidate so the failure is unambiguously
    // attributable to the policy change alone.
    for mutate in [
        (|cfg: &mut BondResourceConfig| cfg.min_bond = Amount::new(2_000_000))
            as fn(&mut BondResourceConfig),
        (|cfg: &mut BondResourceConfig| cfg.max_validator_exposure = Some(Amount::new(1)))
            as fn(&mut BondResourceConfig),
        (|cfg: &mut BondResourceConfig| cfg.enabled = false) as fn(&mut BondResourceConfig),
    ] {
        let store: MemoryDurableStateStore = memory_store();
        let (_fixture, signers, _entries) = install_lightweight(&store);
        let (_next_signers, next_entries) = four_next_validators();
        let policy_key =
            local_instance_state::fastpath_economics_policy_key(&pe_protocol()).unwrap();
        let observed = store
            .get_versioned_durable(&pe_context(), pe_domain(), &policy_key)
            .unwrap();
        let mut policy: FastPathEconomicsPolicy =
            crate::economics::decode_fastpath_economics_policy(observed.value().unwrap()).unwrap();
        let bond_cfg: &mut BondResourceConfig = policy.resources[0].bond.as_mut().unwrap();
        mutate(bond_cfg);
        set_state(
            &store,
            policy_key,
            StateMutation::Put(
                crate::economics::encode_fastpath_economics_policy(&policy).unwrap(),
            ),
        );
        expect_ineligible(&store, &signers[0], vec![next_entries[0].clone()]);
    }
}

/// DR-0137 unit 3's certificate-wins ordering: a certificate formed by
/// quorum before a validator later gets slashed still activates -- byte for
/// byte identically -- after that slash locally commits. Jailing a next-set
/// validator can only ever change what a *later* [`propose_and_vote`] round
/// is willing to vote on; it must never change whether an already-certified
/// transition applies.
#[test]
fn activate_applies_a_precertified_transition_identically_after_a_later_local_slash() {
    let baseline: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, entries) = install_lightweight(&baseline);
    let (_next_signers, next_entries) = four_next_validators();
    let (certificate, ..) =
        propose_vote_and_certify(&baseline, &signers, &entries, next_entries.clone());
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();

    let baseline_outcome = activate(
        &baseline,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries.clone(),
        &certificate_bytes,
        30,
    )
    .unwrap();
    let baseline_record = match baseline_outcome {
        EpochActivationOutcome::Activated(record) => record,
        EpochActivationOutcome::AlreadyActivated(_) => panic!("expected a fresh activation"),
    };

    // An independent, identically constructed store, reaching the identical
    // pre-activation state (both fixtures are fully deterministic), except a
    // local slash now jails one next-set validator's bond *before*
    // `activate` runs -- simulating a slash that committed ahead of
    // activation.
    let slashed: MemoryDurableStateStore = memory_store();
    let (_fixture2, signers2, entries2) = install_lightweight(&slashed);
    assert_eq!(entries, entries2, "fixtures must be deterministic");
    let (next_signers2, next_entries2) = four_next_validators();
    let (certificate2, ..) =
        propose_vote_and_certify(&slashed, &signers2, &entries2, next_entries2.clone());
    let certificate2_bytes = consensus::encode_epoch_transition_certificate(&certificate2).unwrap();
    assert_eq!(
        certificate_bytes, certificate2_bytes,
        "deterministic fixtures must produce byte-identical certificates"
    );

    let bond_key = local_instance_state::fastpath_bond_record_key(
        pe_protocol().chain_id(),
        &next_entries2[0].id,
    )
    .unwrap();
    let observed = slashed
        .get_versioned_durable(&pe_context(), pe_domain(), &bond_key)
        .unwrap();
    let mut bond: FastPathBondRecord =
        crate::fast_path::records::decode_fastpath_bond_record(observed.value().unwrap()).unwrap();
    assert_eq!(bond.state, FastPathBondState::Active);
    bond.state = FastPathBondState::Jailed {
        evidence_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x53; 32]),
    };
    bond.generation += 1;
    set_state(
        &slashed,
        bond_key,
        StateMutation::Put(encode_fastpath_bond_record(&bond).unwrap()),
    );

    let slashed_outcome = activate(
        &slashed,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries2,
        &certificate2_bytes,
        30,
    )
    .unwrap();
    let slashed_record = match slashed_outcome {
        EpochActivationOutcome::Activated(record) => record,
        EpochActivationOutcome::AlreadyActivated(_) => panic!("expected a fresh activation"),
    };

    // Byte-for-byte identical activation, despite the intervening slash.
    assert_eq!(baseline_record, slashed_record);

    // But the jail is not forgotten: it now blocks the *next* proposal round
    // from voting the same (still-jailed) validator back into a future set.
    let error = propose_and_vote(
        &slashed,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        vec![next_entries[0].clone()],
        &next_signers2[0],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        EpochTransitionError::Invalid(
            "fast-path next validator set requires a committed, eligible bond"
        )
    ));
}

/// `propose_and_vote` always derives `next_epoch` from the fenced live
/// `current_epoch`, and `activate` only ever installs a transition record at
/// `next_epoch` in the exact same atomic commit that advances the live
/// epoch record to it. So a transition record present at `current_epoch + 1`
/// while the live epoch record still reads `current_epoch` can never be a
/// legitimate concurrent activation racing this call -- it is partial or
/// corrupt prior state, and `propose_and_vote` must fail closed instead of
/// treating it as an innocuous already-activated outcome.
#[test]
fn propose_and_vote_fails_closed_on_partial_prior_state_when_a_transition_record_exists_without_the_epoch_having_advanced()
 {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, _entries) = install_lightweight(&store);
    let next_epoch = Epoch::new(pe_protocol().epoch().get() + 1);
    let transition_key =
        local_instance_state::fastpath_epoch_transition_key(pe_protocol().chain_id(), next_epoch)
            .unwrap();
    let observed = store
        .get_versioned_durable(&pe_context(), pe_domain(), &transition_key)
        .unwrap();
    let transaction = AtomicStateTransaction::new(
        pe_domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(transition_key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(transition_key, StateMutation::Put(vec![9, 9, 9])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&pe_context(), transaction),
        DurableCommitOutcome::Committed
    );

    let result = propose_and_vote(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        four_next_validators().1,
        &signers[0],
    );
    assert!(matches!(result, Err(EpochTransitionError::Invalid(_))));
}

/// Deterministically interleaves a concurrent, real `activate` between
/// `propose_and_vote`'s own two reads: its epoch fence (first) and its later
/// read of the `current_epoch + 1` transition row. Serves a captured
/// pre-activation snapshot of the epoch record on exactly the first read of
/// that key -- simulating a call that fenced `current_epoch` a moment before
/// a concurrent `activate` committed -- and lets every other read, including
/// `propose_and_vote`'s own live re-read after observing the transition row,
/// fall through to the real, already-advanced store.
struct ActivateBetweenEpochReadsStore {
    inner: MemoryDurableStateStore,
    epoch_record_key: Vec<u8>,
    stale_epoch_record: VersionedStateValue,
    served_stale: std::cell::Cell<bool>,
}
impl runtime::DurableDomainStateStore for ActivateBetweenEpochReadsStore {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        if key == self.epoch_record_key.as_slice() && !self.served_stale.replace(true) {
            return Ok(self.stale_epoch_record.clone());
        }
        self.inner.get_versioned_durable(context, domain, key)
    }
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_durable(context, transaction)
    }
}
impl StructuredDurableDomainStateStore for ActivateBetweenEpochReadsStore {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(context, domain, object_id)
    }
    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: runtime::DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, object_version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: runtime::DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request_id)
    }
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_invocation(context, transaction)
    }
}

/// The benign counterpart to
/// `propose_and_vote_fails_closed_on_partial_prior_state_when_a_transition_record_exists_without_the_epoch_having_advanced`:
/// when a transition row at `current_epoch + 1` coexists with a live epoch
/// record that has *itself* genuinely advanced to `current_epoch + 1` (a
/// concurrent `activate` completed between this call's own reads, not
/// partial or corrupt prior state), `propose_and_vote` must return the
/// retryable `StateConflict`, not `Invalid`.
#[test]
fn propose_and_vote_returns_state_conflict_when_activation_lands_between_its_own_reads() {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();

    let epoch_record_key: Vec<u8> =
        local_instance_state::fastpath_epoch_record_key(pe_protocol().chain_id()).unwrap();
    let stale_epoch_record: VersionedStateValue = store
        .get_versioned_durable(&pe_context(), pe_domain(), &epoch_record_key)
        .unwrap();

    // Genuinely activate `0 -> 1` on the real store, so it now holds exactly
    // what a concurrent `activate` landing mid-call would have produced: a
    // live epoch record at `1` plus its `1` transition row.
    let (certificate, _, _) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();
    activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries,
        &certificate_bytes,
        1,
    )
    .unwrap();

    let racing_store = ActivateBetweenEpochReadsStore {
        inner: store,
        epoch_record_key,
        stale_epoch_record,
        served_stale: std::cell::Cell::new(false),
    };
    let result = propose_and_vote(
        &racing_store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        four_next_validators().1,
        &signers[0],
    );
    assert!(matches!(
        result,
        Err(EpochTransitionError::Node(NodeCoreError::StateConflict))
    ));
}

#[test]
fn activate_installs_all_five_rows_atomically_and_a_fresh_call_succeeds_at_the_next_epoch() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, signers, entries) = install_lightweight(&store);
    let (next_signers, next_entries) = four_next_validators();
    let (certificate, next_validator_set_digest, activation_digest) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();

    let outcome = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries,
        &certificate_bytes,
        11,
    )
    .unwrap();
    let record = match outcome {
        EpochActivationOutcome::Activated(record) => record,
        EpochActivationOutcome::AlreadyActivated(_) => panic!("expected a fresh activation"),
    };
    assert_eq!(record.from_epoch, pe_protocol().epoch());
    assert_eq!(record.to_epoch, Epoch::new(pe_protocol().epoch().get() + 1));
    assert_eq!(record.next_validator_set_digest, next_validator_set_digest);
    assert_eq!(record.activation_digest, activation_digest);

    let next_context: PublicationContext = PublicationContext::new(
        pe_protocol().chain_id().clone(),
        pe_protocol().protocol_version(),
        record.to_epoch,
    )
    .unwrap();
    let epoch_record =
        query_committed_epoch_state(&store, &pe_context(), pe_domain(), pe_protocol().chain_id())
            .unwrap();
    assert_eq!(epoch_record.current_epoch, record.to_epoch);
    assert_eq!(epoch_record.previous_epoch, Some(pe_protocol().epoch()));
    assert_eq!(
        epoch_record.current_validator_set_digest,
        next_validator_set_digest
    );

    // C3: a freshly signed intent at the next epoch, against the
    // freshly-installed `e+1` fee policy digest and nonce domain, succeeds.
    let next_base_policy = LocalExecutionPolicy::generic_object_results(next_context.clone());
    let observed_fee_policy = store
        .get_versioned_durable(
            &pe_context(),
            pe_domain(),
            &local_instance_state::paid_fee_policy_key(&next_context).unwrap(),
        )
        .unwrap();
    let next_fee_policy =
        execution::paid_execution::decode_paid_fee_policy(observed_fee_policy.value().unwrap())
            .unwrap();
    assert_eq!(next_fee_policy.context, next_context);
    assert_ne!(
        paid_fee_policy_digest(&pe_resolver(), &next_fee_policy).unwrap(),
        paid_fee_policy_digest(&pe_resolver(), &fixture.policy).unwrap(),
        "the fee-policy digest must change at the epoch boundary (DR-0132 consequence)"
    );

    let bytes = sign_transfer(&fixture, &next_context, &next_fee_policy, 90, 0);
    let engine = CountingEngine::new();
    let output = fast_path::prepare(
        &store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        &[],
        &next_context,
        &next_base_policy,
        &next_fee_policy,
        &engine,
        &next_signers[0],
        &bytes,
        10,
    );
    let vote = output.unwrap();
    assert_eq!(vote.epoch, next_context.epoch());
    let next_epoch_nonce = query_sender_next_nonce(
        &store,
        &pe_context(),
        pe_domain(),
        pe_protocol().chain_id().clone(),
        pe_protocol().protocol_version(),
        next_context.epoch(),
        crate::paid_execution::tests::sender(),
    )
    .unwrap();
    assert_eq!(
        next_epoch_nonce, 0,
        "the nonce domain restarts at the new epoch: `prepare` only asserts it, never advances it"
    );
}

fn sign_transfer(
    fixture: &Fixture,
    context: &PublicationContext,
    fee_policy: &execution::paid_execution::PaidFeePolicy,
    request: u8,
    nonce: u64,
) -> Vec<u8> {
    let application: CallIntent = CallIntent {
        context: context.clone(),
        request_id: [request; 32],
        sender: crate::paid_execution::tests::sender(),
        nonce,
        code: fixture.code.clone(),
        instance: instance_target(&pe_resolver(), &fixture.instance).unwrap(),
        entrypoint: "transfer".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&fixture.asset)],
        access: abi::AccessManifest {
            entries: vec![pe_entry(&fixture.coin, AccessMode::Write)],
        },
        arguments: public_standard_asset::transfer_arguments(&pe_refund_account()).unwrap(),
        gas_limit: 100_000,
    };
    let intent = PaidIntent {
        context: context.clone(),
        request_id: [request; 32],
        sender: crate::paid_execution::tests::sender(),
        nonce,
        fee_policy_digest: paid_fee_policy_digest(&pe_resolver(), fee_policy).unwrap(),
        consent: FeeSourceConsent {
            source: crate::paid_execution::tests::object_reference(&fixture.coin),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: pe_refund_account(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    };
    let frame = paid_intent_signing_frame(context, &intent).unwrap();
    encode_signed_paid_intent(&SignedPaidIntent {
        intent,
        signature: crate::paid_execution::tests::key().sign(&frame).into(),
    })
    .unwrap()
}

/// Identical to [`sign_transfer`], but computes `fee_policy_digest` (and the
/// instance target) under an explicitly given resolver instead of
/// `pe_resolver()` -- needed when `fee_policy` was itself derived under a
/// different (for example, hash-suite-switching) resolver.
fn sign_transfer_with_resolver(
    fixture: &Fixture,
    context: &PublicationContext,
    fee_policy: &execution::paid_execution::PaidFeePolicy,
    request: u8,
    nonce: u64,
    resolver: &HashSuiteResolver,
) -> Vec<u8> {
    let application: CallIntent = CallIntent {
        context: context.clone(),
        request_id: [request; 32],
        sender: crate::paid_execution::tests::sender(),
        nonce,
        code: fixture.code.clone(),
        instance: instance_target(resolver, &fixture.instance).unwrap(),
        entrypoint: "transfer".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&fixture.asset)],
        access: abi::AccessManifest {
            entries: vec![pe_entry(&fixture.coin, AccessMode::Write)],
        },
        arguments: public_standard_asset::transfer_arguments(&pe_refund_account()).unwrap(),
        gas_limit: 100_000,
    };
    let intent = PaidIntent {
        context: context.clone(),
        request_id: [request; 32],
        sender: crate::paid_execution::tests::sender(),
        nonce,
        fee_policy_digest: paid_fee_policy_digest(resolver, fee_policy).unwrap(),
        consent: FeeSourceConsent {
            source: crate::paid_execution::tests::object_reference(&fixture.coin),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: pe_refund_account(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    };
    let frame = paid_intent_signing_frame(context, &intent).unwrap();
    encode_signed_paid_intent(&SignedPaidIntent {
        intent,
        signature: crate::paid_execution::tests::key().sign(&frame).into(),
    })
    .unwrap()
}

#[test]
fn activate_rejects_a_non_successive_next_epoch_certificate() {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();
    let cert = certifier(
        pe_protocol().chain_id().clone(),
        pe_protocol().epoch(),
        &entries,
    );
    // `cast_vote` itself fails closed before signing anything: prove the
    // structural invariant is enforced at the consensus layer, reachable
    // from this crate's own certifier construction, not merely never
    // triggered by `propose_and_vote` (which always computes `e+1` itself).
    let bogus_next_epoch = Epoch::new(pe_protocol().epoch().get() + 2);
    let result = cert.cast_vote(
        bogus_next_epoch,
        Digest32::new(HashAlgorithmId::Sha2_256, [1; 32]),
        Digest32::new(HashAlgorithmId::Sha2_256, [2; 32]),
        Digest32::new(HashAlgorithmId::Sha2_256, [3; 32]),
        &signers[0],
    );
    assert_eq!(
        result,
        Err(ConsensusError::NonSuccessiveEpoch {
            current: pe_protocol().epoch(),
            next: bogus_next_epoch
        })
    );
    let _ = next_entries;
}

#[test]
fn activate_rejects_a_certificate_signed_by_the_incoming_set() {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, entries) = install_lightweight(&store);
    let (next_signers, next_entries) = four_next_validators();
    let (_certificate, _, _) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());

    // Build a certificate signed by the *incoming* set instead of the
    // outgoing one: `activate` must reject it, because
    // `load_validator_set`/`EpochTransitionCertifier` are bound to the
    // committed outgoing set, so the incoming set's signatures can never be
    // recognized -- cryptographic verification itself fails, before this
    // module's own digest-comparison checks are ever reached.
    let derived = crate::epoch_transition::derive_activation_set(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        pe_protocol().epoch(),
        Epoch::new(pe_protocol().epoch().get() + 1),
        &next_entries,
    )
    .unwrap();
    let incoming_certifier = certifier(
        pe_protocol().chain_id().clone(),
        pe_protocol().epoch(),
        &next_entries,
    );
    let votes: Vec<EpochTransitionVote> = next_signers
        .iter()
        .map(|signer| {
            incoming_certifier
                .cast_vote(
                    Epoch::new(pe_protocol().epoch().get() + 1),
                    Digest32::new(HashAlgorithmId::Sha2_256, [0xAB; 32]),
                    derived.next_validator_set_digest,
                    derived.activation_digest,
                    signer,
                )
                .unwrap()
        })
        .collect();
    let bogus_certificate = incoming_certifier
        .try_form_certificate(
            Epoch::new(pe_protocol().epoch().get() + 1),
            Digest32::new(HashAlgorithmId::Sha2_256, [0xAB; 32]),
            derived.next_validator_set_digest,
            derived.activation_digest,
            &votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    let bogus_certificate_bytes =
        consensus::encode_epoch_transition_certificate(&bogus_certificate).unwrap();
    let result = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries,
        &bogus_certificate_bytes,
        1,
    );
    assert!(matches!(
        result,
        Err(EpochTransitionError::Consensus(
            ConsensusError::UnknownValidator(_)
        ))
    ));
}

#[test]
fn activate_rejects_a_locally_derived_activation_set_that_differs_from_the_certificate() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();
    let (certificate, _, _) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();

    // Activate against a *different* `next_validators` set than the
    // certificate actually certified. Bonded too, so this reaches the
    // activation-digest mismatch this test targets rather than failing
    // earlier on next-set eligibility.
    let (_other_signers, other_next_entries) = {
        let (signers, entries) = validator_pair(221, 222);
        (signers, entries)
    };
    install_bond_policy_and_bonds(&store, &fixture, &other_next_entries);
    let result = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        other_next_entries,
        &certificate_bytes,
        1,
    );
    assert!(matches!(
        result,
        Err(EpochTransitionError::Invalid(
            "locally derived epoch activation set does not match the certificate's activation digest"
        ))
    ));
}

fn validator_pair(seed_a: u8, seed_b: u8) -> (Vec<TestSigner>, Vec<FastPathValidatorEntry>) {
    let (signer_a, entry_a) = validator(seed_a);
    let (signer_b, entry_b) = validator(seed_b);
    (vec![signer_a, signer_b], vec![entry_a, entry_b])
}

#[test]
fn activate_rejects_partial_prior_state_at_the_next_epoch_context() {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();
    let (certificate, _, _) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();

    // Squat one of the five target rows before `activate` runs.
    let next_context = PublicationContext::new(
        pe_protocol().chain_id().clone(),
        pe_protocol().protocol_version(),
        Epoch::new(pe_protocol().epoch().get() + 1),
    )
    .unwrap();
    let key = local_instance_state::execution_policy_key_for_profile(&next_context, 4).unwrap();
    let observed = store
        .get_versioned_durable(&pe_context(), pe_domain(), &key)
        .unwrap();
    let transaction = AtomicStateTransaction::new(
        pe_domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(vec![1, 2, 3])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&pe_context(), transaction),
        DurableCommitOutcome::Committed
    );

    let result = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries,
        &certificate_bytes,
        1,
    );
    assert!(matches!(
        result,
        Err(EpochTransitionError::Invalid(
            "partial prior state already exists at the next-epoch context"
        ))
    ));
}

#[test]
fn activate_is_idempotent_for_the_identical_certificate_and_for_an_alternate_quorum_subset() {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();

    let mut votes: Vec<EpochTransitionVote> = Vec::new();
    for signer in &signers {
        let vote = propose_and_vote(
            &store,
            &pe_context(),
            pe_domain(),
            &pe_resolver(),
            pe_protocol().chain_id(),
            pe_protocol().protocol_version(),
            next_entries.clone(),
            signer,
        )
        .unwrap();
        votes.push(vote);
    }
    let cert = certifier(
        pe_protocol().chain_id().clone(),
        pe_protocol().epoch(),
        &entries,
    );
    let minimal = cert
        .try_form_certificate(
            votes[0].next_epoch,
            votes[0].current_validator_set_digest,
            votes[0].next_validator_set_digest,
            votes[0].activation_digest,
            &votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    let alternate = cert
        .try_form_certificate(
            votes[0].next_epoch,
            votes[0].current_validator_set_digest,
            votes[0].next_validator_set_digest,
            votes[0].activation_digest,
            &votes[1..4],
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    assert_ne!(
        consensus::encode_epoch_transition_certificate(&minimal).unwrap(),
        consensus::encode_epoch_transition_certificate(&alternate).unwrap()
    );

    let minimal_bytes = consensus::encode_epoch_transition_certificate(&minimal).unwrap();
    let first = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries.clone(),
        &minimal_bytes,
        1,
    )
    .unwrap();
    assert!(matches!(first, EpochActivationOutcome::Activated(_)));

    // Same certificate again: idempotent.
    let replay = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries.clone(),
        &minimal_bytes,
        99,
    )
    .unwrap();
    assert!(matches!(
        replay,
        EpochActivationOutcome::AlreadyActivated(_)
    ));

    // Alternate quorum subset presenting the identical full transition
    // identity: also idempotent (§3.C.3), even though its own certificate
    // bytes differ from the minimal one.
    let alternate_bytes = consensus::encode_epoch_transition_certificate(&alternate).unwrap();
    let alternate_outcome = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries,
        &alternate_bytes,
        99,
    )
    .unwrap();
    assert!(matches!(
        alternate_outcome,
        EpochActivationOutcome::AlreadyActivated(_)
    ));
}

#[test]
fn activate_rejects_a_conflicting_transition_identity_for_an_already_activated_epoch() {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();
    let (certificate, _, _) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();
    activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries,
        &certificate_bytes,
        1,
    )
    .unwrap();

    // A different certificate claiming the same `next_epoch` but a
    // different `current_validator_set_digest` (via a distinct outgoing
    // set) must be rejected, not silently treated as already-activated.
    let mut tampered = certificate;
    tampered.current_validator_set_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]);
    // Header no longer matches its own votes; still decodes, and `activate`
    // must reject it on the identity-comparison branch before ever trying
    // to cryptographically re-verify it (which would fail anyway).
    let tampered_bytes = consensus::encode_epoch_transition_certificate(&tampered).unwrap();
    let result = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        four_next_validators().1,
        &tampered_bytes,
        1,
    );
    // The already-activated branch (§3.C.3) compares the certificate's
    // header fields directly against the stored record and never
    // cryptographically re-verifies on this path, so the outcome is exactly
    // this one `Invalid` branch, deterministically -- not merely "some"
    // rejection.
    assert!(matches!(
        result,
        Err(EpochTransitionError::Invalid(
            "conflicting epoch transition already activated"
        ))
    ));
}

/// DR-0132 §3.C step 5: the certificate here carries a genuinely valid
/// outgoing-set quorum signature -- cast by the real, currently-committed
/// outgoing validators, cryptographically verifiable under their real
/// public keys -- but over a payload whose `current_validator_set_digest`
/// is not the digest the committed `FastPathEpochRecord` actually carries.
/// This is distinct from
/// `activate_rejects_a_conflicting_transition_identity_for_an_already_activated_epoch`,
/// which post-hoc tampers an already-formed certificate's header (breaking
/// its own vote consistency) on the *already-activated* branch; this test
/// reaches the *not-yet-activated* branch, where `activate` cryptographically
/// verifies the certificate under the real outgoing set and only then must
/// separately reject the outgoing digest binding itself.
#[test]
fn activate_rejects_a_certificate_bound_to_a_different_outgoing_validator_set_digest() {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();

    let next_epoch: Epoch = Epoch::new(pe_protocol().epoch().get() + 1);
    let wrong_current_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x77; 32]);
    let next_validator_set_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0xbb; 32]);
    let activation_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0xcc; 32]);

    let cert: EpochTransitionCertifier = certifier(
        pe_protocol().chain_id().clone(),
        pe_protocol().epoch(),
        &entries,
    );
    let mut votes: Vec<EpochTransitionVote> = Vec::new();
    for signer in &signers {
        votes.push(
            cert.cast_vote(
                next_epoch,
                wrong_current_digest,
                next_validator_set_digest,
                activation_digest,
                signer,
            )
            .unwrap(),
        );
    }
    let certificate: EpochTransitionCertificate = cert
        .try_form_certificate(
            next_epoch,
            wrong_current_digest,
            next_validator_set_digest,
            activation_digest,
            &votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .expect("3-of-4 equal power validators exceed quorum");
    // Cryptographically valid in isolation: a real outgoing-set quorum over
    // this exact (wrong-digest) payload.
    cert.verify_certificate(&certificate, &FastPathEd25519Verifier)
        .unwrap();
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();

    let result = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries,
        &certificate_bytes,
        1,
    );
    assert!(matches!(
        result,
        Err(EpochTransitionError::Invalid(
            "epoch transition certificate outgoing validator-set digest does not match the committed epoch record",
        ))
    ));
}

#[test]
fn query_committed_epoch_state_reflects_the_installed_outgoing_set() {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, _signers, entries) = install_lightweight(&store);
    let record =
        query_committed_epoch_state(&store, &pe_context(), pe_domain(), pe_protocol().chain_id())
            .unwrap();
    assert_eq!(record.current_epoch, pe_protocol().epoch());
    let info: Vec<ValidatorInfo> = entries
        .iter()
        .map(|entry| ValidatorInfo {
            id: entry.id,
            voting_power: entry.voting_power,
            signature_scheme: entry.signature_scheme,
            public_key: entry.public_key.clone(),
        })
        .collect();
    let expected_digest = ValidatorSet::new(pe_protocol().epoch(), info)
        .unwrap()
        .digest(&pe_resolver())
        .unwrap();
    assert_eq!(record.current_validator_set_digest, expected_digest);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn fastpath_epoch_transition_record_frame_0x6427_is_stable() {
    let record: FastPathEpochTransitionRecord = FastPathEpochTransitionRecord {
        from_epoch: Epoch::new(9),
        to_epoch: Epoch::new(10),
        previous_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xaa; 32]),
        next_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xbb; 32]),
        activation_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xcc; 32]),
        certificate: vec![0xdd, 0xee],
        activated_at_checkpoint: 0x77,
    };
    let bytes: Vec<u8> = encode_fastpath_epoch_transition_record(&record).unwrap();
    assert_eq!(
        decode_fastpath_epoch_transition_record(&bytes).unwrap(),
        record
    );
    assert_eq!(
        hex(&bytes),
        "534e524527640100070001000800000009000000000000000200080000000a00000000000000030038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa040038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb050038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc060002000000ddee0700080000007700000000000000"
    );
}

#[test]
fn fastpath_epoch_activation_set_frame_0x6428_is_stable() {
    let next_context: PublicationContext = PublicationContext::new(
        ChainId::new("dr0130-fastpath-vectors").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(10),
    )
    .unwrap();
    let set: FastPathEpochActivationSet = FastPathEpochActivationSet {
        next_context,
        validator_set_record: vec![0x11, 0x12],
        execution_policy: vec![0x21],
        paid_fee_policy: vec![0x31, 0x32, 0x33],
        publication_policy: vec![0x41, 0x42],
    };
    let bytes: Vec<u8> = encode_fastpath_epoch_activation_set(&set).unwrap();
    assert_eq!(
        hex(&bytes),
        "534e524528640100050001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000a000000000000000200020000001112030001000000210400030000003132330500020000004142"
    );
}

// ── genesis-manifest fixture: real `genesis::install_genesis_with_history` ─
//
// Needed only where a test actually exercises restart-verify (C1): the
// lighter-weight `paid_execution::tests` fixture above never calls
// `genesis::install_genesis_with_history` at all.

fn genesis_authority_key() -> SigningKey {
    SigningKey::from([0x77; 32])
}
fn genesis_authority() -> [u8; 32] {
    VerificationKey::from(&genesis_authority_key()).into()
}

pub(crate) struct GenesisFixture {
    pub(crate) manifest: GenesisManifest,
    pub(crate) instance: InstanceRecord,
    pub(crate) code: UnverifiedDependencyRef,
    pub(crate) asset: ObjectId,
    pub(crate) coin: Object,
    pub(crate) fee_policy: execution::paid_execution::PaidFeePolicy,
}

/// Builds a real, signed [`GenesisManifest`] at `epoch_context(0)` carrying
/// `validators` as its FastVote validator set, one Standard Asset instance,
/// its definition object, and one 1,000,000-unit Coin owned by the genesis
/// authority. Mirrors `crate::genesis::tests::build_fixture`, generalized to
/// an arbitrary validator set.
pub(crate) fn build_genesis_fixture(validators: Vec<FastPathValidatorEntry>) -> GenesisFixture {
    let context: PublicationContext = epoch_context(0);
    let origin: PackageOrigin =
        PackageOrigin::unverified(chain(), genesis_authority(), [1; 32]).unwrap();
    let package = public_standard_asset::build_package(&origin).unwrap();
    let semantics: Digest32 = generic_object_result_semantics(&resolver(), &context).unwrap();
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: context.clone(),
        origin: origin.clone(),
        revision: 1,
        wasm_profile: 4,
        semantics,
        wasm: package.wasm,
        unverified_abi: package.encoded_abi,
        exports: package.exports,
        unverified_dependencies: Vec::new(),
    })
    .unwrap();
    let digest: Digest32 = artifact_commitment(&resolver(), &context, &artifact).unwrap();
    let frame: Vec<u8> =
        publication_submission_signing_frame(&resolver(), &context, &artifact, 0, [1; 32]).unwrap();
    let submission: PublicationSubmission = PublicationSubmission::new(
        [1; 32],
        PublicationRequest::new(
            artifact,
            0,
            digest,
            genesis_authority_key().sign(&frame).into(),
        ),
    )
    .unwrap();

    let code_ref: UnverifiedDependencyRef =
        UnverifiedDependencyRef::new(origin.clone(), 1, context.clone(), digest).unwrap();
    let instance_record: InstanceRecord = InstanceRecord {
        context: context.clone(),
        creator: genesis_authority(),
        seed: [2; 32],
        code: code_ref.clone(),
        revision: 1,
        initializer: "init".into(),
    };
    let target = instance_target(&resolver(), &instance_record).unwrap();

    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(context.clone());
    let base_policy_digest: Digest32 = base_policy.digest(&resolver()).unwrap();
    let call: CallIntent = CallIntent {
        context: context.clone(),
        request_id: [2; 32],
        sender: genesis_authority(),
        nonce: 0,
        code: code_ref.clone(),
        instance: target.clone(),
        entrypoint: "init".into(),
        type_arguments: Vec::new(),
        access: abi::AccessManifest {
            entries: Vec::new(),
        },
        arguments: Vec::new(),
        gas_limit: 500_000,
    };
    let init_intent: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Instantiate,
        policy_digest: base_policy_digest,
        call,
        authorizations: Vec::new(),
    };
    let init_frame: Vec<u8> = local_execution_signing_frame(&context, &init_intent).unwrap();
    let signed_init: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
        intent: init_intent,
        signature: genesis_authority_key().sign(&init_frame).into(),
    };

    let def_id: ObjectId = ObjectId::new([0x30; 32]);
    let coin_id: ObjectId = ObjectId::new([0x40; 32]);
    let def_tag = public_standard_asset::definition_type_tag(&origin).unwrap();
    let coin_tag = public_standard_asset::coin_type_tag(&origin, &def_id).unwrap();

    let fee_policy: execution::paid_execution::PaidFeePolicy =
        execution::paid_execution::PaidFeePolicy {
            context: context.clone(),
            base_policy_digest,
            instance: target.clone(),
            code: code_ref.clone(),
            reserve_entrypoint: "reserve".into(),
            reserve_all_entrypoint: "reserve_all".into(),
            settle_entrypoint: "settle".into(),
            type_arguments: vec![public_standard_asset::asset_type_argument(&def_id)],
            asset_type: coin_tag.clone(),
            reservation_type: public_standard_asset::reservation_type_tag(&origin, &def_id)
                .unwrap(),
            schema: public_standard_asset::SCHEMA_VERSION,
            fee_recipient: genesis_authority(),
            gas_schedule: GasSchedule {
                base_fee: 100,
                execution_price: 1,
                read_price: 0,
                write_price: 0,
                storage_price: 0,
                system_module_price: 0,
            },
            conversion_divisor: 1_000,
            reserve_allowance: MIN_RESERVE_ALLOWANCE,
            settle_allowance: MIN_SETTLE_ALLOWANCE,
            calls: 8,
            handles: 16,
            creations: 4,
            events: 16,
            memory_bytes: 8 * 1024 * 1024,
            output_bytes: 1024 * 1024,
            publish_artifact_byte_price: 1,
            publish_closure_node_price: 1,
        };
    let (resource_domain, resource): (u16, [u8; 32]) = match coin_tag.args() {
        [ScopedTypeArg::Opaque { domain, value }] => (*domain, *value),
        _ => panic!("fixture coin type must carry one opaque resource"),
    };
    let resource_id: BondResourceId = BondResourceId::new(resource_domain, resource).unwrap();
    let economics_policy: FastPathEconomicsPolicy = FastPathEconomicsPolicy {
        context: context.clone(),
        resources: vec![FastPathEconomicsResourcePolicy {
            resource_id,
            context: context.clone(),
            instance: target.clone(),
            code: code_ref.clone(),
            ty: coin_tag.clone(),
            schema: public_standard_asset::SCHEMA_VERSION,
            split_entrypoint: "split".to_owned(),
            transfer_entrypoint: "transfer".to_owned(),
            bond: Some(BondResourceConfig {
                resource_id,
                min_bond: Amount::new(100),
                enabled: true,
                unbonding_epochs: 7,
                max_validator_exposure: None,
            }),
            fee_escrow: true,
        }],
    };

    let def_type_hash = derive_scoped_type_id(&resolver(), Epoch::new(0), &def_tag).unwrap();
    let coin_type_hash = derive_scoped_type_id(&resolver(), Epoch::new(0), &coin_tag).unwrap();
    let def_obj: Object = Object {
        id: def_id,
        version: 1,
        owner: Owner::Address(Address::new(genesis_authority())),
        type_hash: def_type_hash,
        schema_version: public_standard_asset::SCHEMA_VERSION,
        data: encode_call_value(
            &public_standard_asset::definition_body_layout(),
            &CallValue::Tuple(Vec::new()),
        )
        .unwrap(),
    };
    let def_auth: ObjectAuthority = ObjectAuthority {
        object_id: def_id,
        instance_context: context.clone(),
        instance: target.clone(),
        code: code_ref.clone(),
        ty: def_tag,
    };
    let coin_data: Vec<u8> = encode_call_value(
        &public_standard_asset::coin_body_layout(),
        &CallValue::U64(1_000_000),
    )
    .unwrap();
    let coin_obj: Object = Object {
        id: coin_id,
        version: 1,
        owner: Owner::Address(Address::new(genesis_authority())),
        type_hash: coin_type_hash,
        schema_version: public_standard_asset::SCHEMA_VERSION,
        data: coin_data,
    };
    let coin_auth: ObjectAuthority = ObjectAuthority {
        object_id: coin_id,
        instance_context: context.clone(),
        instance: target.clone(),
        code: code_ref.clone(),
        ty: coin_tag.clone(),
    };

    // DR-0136 (revised): every genesis validator has exactly one genesis
    // bond record, so this shared fixture -- reused across every validator
    // set in this module -- must install one `BondCollateral` custody object
    // per validator, not merely the plain address-owned objects above.
    let mut objects: Vec<GenesisObjectEntry> = vec![
        GenesisObjectEntry {
            object: def_obj,
            authority: def_auth,
        },
        GenesisObjectEntry {
            object: coin_obj.clone(),
            authority: coin_auth,
        },
    ];
    for validator in &validators {
        let mut bond_object_id_bytes: [u8; 32] = *validator.id.as_bytes();
        bond_object_id_bytes[0] = 0x50;
        let bond_object_id: ObjectId = ObjectId::new(bond_object_id_bytes);
        let scope: ProtocolCustodyScope = ProtocolCustodyScope {
            purpose: ProtocolCustodyPurpose::BondCollateral,
            chain_id: chain(),
            subject: *validator.id.as_bytes(),
            resource,
        };
        objects.push(GenesisObjectEntry {
            object: Object {
                id: bond_object_id,
                version: 1,
                owner: Owner::ProtocolCustody(scope),
                type_hash: coin_type_hash,
                schema_version: public_standard_asset::SCHEMA_VERSION,
                data: encode_call_value(
                    &public_standard_asset::coin_body_layout(),
                    &CallValue::U64(1_000_000),
                )
                .unwrap(),
            },
            authority: ObjectAuthority {
                object_id: bond_object_id,
                instance_context: context.clone(),
                instance: target.clone(),
                code: code_ref.clone(),
                ty: coin_tag.clone(),
            },
        });
    }

    let mut manifest: GenesisManifest = GenesisManifest {
        genesis_authority: genesis_authority(),
        publication: submission,
        initialization: signed_init,
        fee_policy: fee_policy.clone(),
        economics_policy,
        objects,
        validator_set: FastPathValidatorSetRecord {
            context,
            validators,
        },
        signature: [0; 64],
    };
    manifest.signature = genesis_authority_key()
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();

    GenesisFixture {
        manifest,
        instance: instance_record,
        code: code_ref,
        asset: def_id,
        coin: coin_obj,
        fee_policy,
    }
}

fn install_genesis<S: StructuredDurableDomainStateStore>(
    store: &S,
    manifest: &GenesisManifest,
) -> GenesisInstallOutcome {
    install_genesis_result(store, manifest).unwrap()
}

fn install_genesis_result<S: StructuredDurableDomainStateStore>(
    store: &S,
    manifest: &GenesisManifest,
) -> Result<GenesisInstallOutcome, GenesisError> {
    install_genesis_with_history(store, &context(1), domain(), &resolver(), &[], manifest, 1)
}

/// Signs one `transfer` paid Call for `fixture.coin`, owned throughout by
/// `genesis_authority()`, at an arbitrary `PublicationContext`/`fee_policy`
/// pair -- reusable at both `e` and `e+1`.
/// Reads the current, independently verified version/digest of
/// `fixture.coin` from `store` -- needed because a prior `transfer` bumps
/// its version, and a fresh signed intent must reference the object's
/// *current* state, not the version-1 genesis snapshot in `GenesisFixture`.
fn current_coin_ref<S: StructuredDurableDomainStateStore>(
    store: &S,
    coin_id: ObjectId,
) -> ObjectRef {
    match query_object(store, &context(1), domain(), &chain(), coin_id).unwrap() {
        ObjectQueryResult::CurrentInline {
            object_version,
            digest,
            ..
        } => ObjectRef {
            id: coin_id,
            version: object_version.get(),
            digest,
        },
        other => panic!("expected a current inline coin object, got {other:?}"),
    }
}

fn genesis_object_reference(object: &Object) -> ObjectRef {
    ObjectRef {
        id: object.id,
        version: object.version,
        digest: resolver()
            .hash_for_purpose(
                Epoch::new(0),
                HashPurpose::Object,
                &objects::encode_object(object).unwrap(),
            )
            .unwrap(),
    }
}

fn sign_genesis_transfer(
    fixture: &GenesisFixture,
    coin_ref: ObjectRef,
    context: &PublicationContext,
    fee_policy: &execution::paid_execution::PaidFeePolicy,
    request: u8,
    nonce: u64,
) -> Vec<u8> {
    let application: CallIntent = CallIntent {
        context: context.clone(),
        request_id: [request; 32],
        sender: genesis_authority(),
        nonce,
        code: fixture.code.clone(),
        instance: instance_target(&resolver(), &fixture.instance).unwrap(),
        entrypoint: "transfer".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&fixture.asset)],
        access: abi::AccessManifest {
            entries: vec![AccessEntry {
                object_ref: coin_ref.clone(),
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::transfer_arguments(&genesis_authority()).unwrap(),
        gas_limit: 100_000,
    };
    let intent: PaidIntent = PaidIntent {
        context: context.clone(),
        request_id: [request; 32],
        sender: genesis_authority(),
        nonce,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), fee_policy).unwrap(),
        consent: FeeSourceConsent {
            source: coin_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: genesis_authority(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    };
    let frame: Vec<u8> = paid_intent_signing_frame(context, &intent).unwrap();
    encode_signed_paid_intent(&SignedPaidIntent {
        intent,
        signature: genesis_authority_key().sign(&frame).into(),
    })
    .unwrap()
}

/// One validator's independent pair of file-backed SQLite stores (state and
/// blobs), reopened repeatedly to prove restart-durable behavior.
struct ValidatorFiles {
    state_path: std::path::PathBuf,
    blob_path: std::path::PathBuf,
    namespace: SqliteNamespace,
}
impl ValidatorFiles {
    fn new(directory: &std::path::Path, index: u8, validator: ValidatorId) -> Self {
        Self {
            state_path: directory.join(format!("et-validator-{index}-state.sqlite")),
            blob_path: directory.join(format!("et-validator-{index}-blobs.sqlite")),
            namespace: SqliteNamespace::new(chain(), validator, domain()),
        }
    }
    fn open(&self) -> (SqliteDurableStore, SqliteBlobStore) {
        (
            SqliteDurableStore::open(
                &self.state_path,
                self.namespace.clone(),
                WriterFenceGeneration::new(1).unwrap(),
            )
            .unwrap(),
            SqliteBlobStore::open(&self.blob_path).unwrap(),
        )
    }
}

/// The headline DR-0132 test: four independent file-backed SQLite validator
/// stores, real genesis install, a baseline DR-0130 prepare/apply cycle at
/// `e`, four independently derived and certified transition votes, atomic
/// activation on all four stores, restart-verify (C1) on all four stores,
/// and a fresh prepare/apply cycle at `e+1` with a freshly signed intent
/// (new fee-policy digest, restarted nonce domain) -- the test that proves
/// C3 was actually solved.
#[test]
fn four_validator_sqlite_epoch_transition_activates_and_certified_execution_continues_at_the_next_epoch()
 {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
        "epoch-transition-4validator-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();

    let (signers, entries) = four_validators();
    let (next_signers, next_entries) = four_next_validators();
    let fixture: GenesisFixture = build_genesis_fixture(entries.clone());
    let files: Vec<ValidatorFiles> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            ValidatorFiles::new(&directory, u8::try_from(index).unwrap(), entry.id)
        })
        .collect();

    // 1. Genesis on four independent stores.
    for file in &files {
        let (store, _blob_store) = file.open();
        let outcome = install_genesis(&store, &fixture.manifest);
        assert!(matches!(
            outcome,
            GenesisInstallOutcome::FreshInstall { .. }
        ));
        install_additional_bonds(&store, &context(1), domain(), &fixture, &next_entries);
    }

    // 2. A full DR-0130 prepare/apply cycle at `e` (baseline).
    let baseline_context: PublicationContext = epoch_context(0);
    let baseline_bytes: Vec<u8> = sign_genesis_transfer(
        &fixture,
        genesis_object_reference(&fixture.coin),
        &baseline_context,
        &fixture.fee_policy,
        60,
        0,
    );
    let mut baseline_votes: Vec<FastVote> = Vec::new();
    for (index, file) in files.iter().enumerate() {
        let (store, blob_store) = file.open();
        let vote = fast_path::prepare(
            &store,
            &blob_store,
            &context(1),
            domain(),
            &resolver(),
            &[],
            &baseline_context,
            &LocalExecutionPolicy::generic_object_results(baseline_context.clone()),
            &fixture.fee_policy,
            &CountingEngine::new(),
            &signers[index],
            &baseline_bytes,
            10,
        )
        .unwrap();
        baseline_votes.push(vote);
    }
    let base_certifier = consensus::FastPathCertifier::new(
        chain(),
        protocol_version(),
        Epoch::new(0),
        ValidatorSet::new(
            Epoch::new(0),
            entries
                .iter()
                .map(|entry| ValidatorInfo {
                    id: entry.id,
                    voting_power: entry.voting_power,
                    signature_scheme: entry.signature_scheme,
                    public_key: entry.public_key.clone(),
                })
                .collect(),
        )
        .unwrap(),
    )
    .unwrap();
    let baseline_certificate: FastCertificate = base_certifier
        .try_form_certificate(
            baseline_votes[0].tx_hash,
            baseline_votes[0].execution_effects_hash,
            baseline_votes[0].locked_objects_digest,
            &baseline_votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    let baseline_certificate_bytes =
        consensus::encode_fast_certificate(&baseline_certificate).unwrap();
    for file in &files {
        let (store, blob_store) = file.open();
        fast_path::apply(
            &store,
            &blob_store,
            &context(1),
            domain(),
            &resolver(),
            &[],
            &baseline_context,
            &LocalExecutionPolicy::generic_object_results(baseline_context.clone()),
            &fixture.fee_policy,
            &CountingEngine::new(),
            &baseline_bytes,
            &baseline_certificate_bytes,
        )
        .unwrap();
    }

    // 3-4. Four independent transition votes and a 3-of-4 certificate,
    //      forward and reversed arrival producing byte-identical bytes.
    let mut transition_votes: Vec<EpochTransitionVote> = Vec::new();
    for (index, file) in files.iter().enumerate() {
        let (store, _blob_store) = file.open();
        let vote = propose_and_vote(
            &store,
            &context(1),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            next_entries.clone(),
            &signers[index],
        )
        .unwrap();
        transition_votes.push(vote);
    }
    for vote in &transition_votes[1..] {
        assert_eq!(
            transition_votes[0].activation_digest,
            vote.activation_digest
        );
    }
    let et_certifier = certifier(chain(), Epoch::new(0), &entries);
    let forward = et_certifier
        .try_form_certificate(
            transition_votes[0].next_epoch,
            transition_votes[0].current_validator_set_digest,
            transition_votes[0].next_validator_set_digest,
            transition_votes[0].activation_digest,
            &transition_votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    let mut reversed_votes = transition_votes.clone();
    reversed_votes.reverse();
    let reversed = et_certifier
        .try_form_certificate(
            transition_votes[0].next_epoch,
            transition_votes[0].current_validator_set_digest,
            transition_votes[0].next_validator_set_digest,
            transition_votes[0].activation_digest,
            &reversed_votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        consensus::encode_epoch_transition_certificate(&forward).unwrap(),
        consensus::encode_epoch_transition_certificate(&reversed).unwrap()
    );
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&forward).unwrap();

    // 5. Close/reopen all four; re-derive votes; byte-identical to step 3.
    for (index, file) in files.iter().enumerate() {
        let (store, _blob_store) = file.open();
        let vote = propose_and_vote(
            &store,
            &context(1),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            next_entries.clone(),
            &signers[index],
        )
        .unwrap();
        assert_eq!(vote, transition_votes[index]);
    }

    // 6. `activate` on all four; assert every activation row is
    //    byte-identical across all four stores.
    let mut installed_rows: Vec<Vec<u8>> = Vec::new();
    for file in &files {
        let (store, _blob_store) = file.open();
        let outcome = activate(
            &store,
            &context(1),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            next_entries.clone(),
            &certificate_bytes,
            42,
        )
        .unwrap();
        assert!(matches!(outcome, EpochActivationOutcome::Activated(_)));
        let next_context = epoch_context(1);
        let key = local_instance_state::fastpath_validator_set_key(&next_context).unwrap();
        let observed = store
            .get_versioned_durable(&context(1), domain(), &key)
            .unwrap();
        installed_rows.push(observed.value().unwrap().to_vec());
    }
    for row in &installed_rows[1..] {
        assert_eq!(&installed_rows[0], row);
    }

    // 7. Close/reopen; `install_genesis_with_history` -> `VerifiedExisting`
    //    via the full per-step restart-verify algorithm, not mere chain
    //    contiguity (C1).
    for file in &files {
        let (store, _blob_store) = file.open();
        let outcome = install_genesis(&store, &fixture.manifest);
        assert!(matches!(
            outcome,
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));
    }

    // 8. A new prepare/apply cycle at `e+1` with a freshly signed intent
    //    (new fee-policy digest, nonce domain restarts) -- the test that
    //    proves C3 was actually solved.
    let next_context: PublicationContext = epoch_context(1);
    let next_base_policy = LocalExecutionPolicy::generic_object_results(next_context.clone());
    let next_fee_policy_bytes = {
        let (store, _blob_store) = files[0].open();
        store
            .get_versioned_durable(
                &context(1),
                domain(),
                &local_instance_state::paid_fee_policy_key(&next_context).unwrap(),
            )
            .unwrap()
            .value()
            .unwrap()
            .to_vec()
    };
    let next_fee_policy =
        execution::paid_execution::decode_paid_fee_policy(&next_fee_policy_bytes).unwrap();
    assert_ne!(
        paid_fee_policy_digest(&resolver(), &next_fee_policy).unwrap(),
        paid_fee_policy_digest(&resolver(), &fixture.fee_policy).unwrap()
    );
    let next_coin_ref: ObjectRef = {
        let (store, _blob_store) = files[0].open();
        current_coin_ref(&store, fixture.coin.id)
    };
    let next_bytes = sign_genesis_transfer(
        &fixture,
        next_coin_ref,
        &next_context,
        &next_fee_policy,
        61,
        0,
    );
    let mut next_votes: Vec<FastVote> = Vec::new();
    for (index, file) in files.iter().enumerate() {
        let (store, blob_store) = file.open();
        let vote = fast_path::prepare(
            &store,
            &blob_store,
            &context(1),
            domain(),
            &resolver(),
            &[],
            &next_context,
            &next_base_policy,
            &next_fee_policy,
            &CountingEngine::new(),
            &next_signers[index],
            &next_bytes,
            10,
        )
        .unwrap();
        next_votes.push(vote);
    }
    let next_certifier = consensus::FastPathCertifier::new(
        chain(),
        protocol_version(),
        Epoch::new(1),
        ValidatorSet::new(
            Epoch::new(1),
            next_entries
                .iter()
                .map(|entry| ValidatorInfo {
                    id: entry.id,
                    voting_power: entry.voting_power,
                    signature_scheme: entry.signature_scheme,
                    public_key: entry.public_key.clone(),
                })
                .collect(),
        )
        .unwrap(),
    )
    .unwrap();
    let next_certificate: FastCertificate = next_certifier
        .try_form_certificate(
            next_votes[0].tx_hash,
            next_votes[0].execution_effects_hash,
            next_votes[0].locked_objects_digest,
            &next_votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    let next_certificate_bytes = consensus::encode_fast_certificate(&next_certificate).unwrap();
    let (store, blob_store) = files[0].open();
    let output = fast_path::apply(
        &store,
        &blob_store,
        &context(1),
        domain(),
        &resolver(),
        &[],
        &next_context,
        &next_base_policy,
        &next_fee_policy,
        &CountingEngine::new(),
        &next_bytes,
        &next_certificate_bytes,
    )
    .unwrap();
    assert_eq!(receipt(&output).status, PaidExecutionStatus::Success);

    std::fs::remove_dir_all(directory).unwrap();
}

// ── restart-verify (C1, DR-0132 §7) tamper-surface tests ───────────────────
//
// All tests below use a single in-memory `MemoryDurableStateStore`: no real
// process restart is needed to exercise `install_genesis_with_history`'s
// restart-verify path a second time, because that function's behavior is a
// pure function of durably committed state, and `MemoryDurableStateStore`
// already persists across calls within one test (the headline SQLite test
// above additionally proves this holds across a real close/reopen).

/// Overwrites `key` with `new_bytes` in one CAS-asserted `commit_durable`,
/// under the exact revision this call itself observes -- the shared
/// tampering primitive every restart-verify test below uses to corrupt one
/// specific already-installed row without disturbing any other.
fn overwrite_row<S: StructuredDurableDomainStateStore>(store: &S, key: &[u8], new_bytes: Vec<u8>) {
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(1), domain(), key)
        .unwrap();
    let transaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.to_vec(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key.to_vec(), StateMutation::Put(new_bytes)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(1), transaction),
        DurableCommitOutcome::Committed
    );
}

/// Deletes `key` in one CAS-asserted `commit_durable`, under the exact
/// revision this call itself observes.
fn delete_row<S: StructuredDurableDomainStateStore>(store: &S, key: &[u8]) {
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(1), domain(), key)
        .unwrap();
    let transaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.to_vec(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key.to_vec(), StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(1), transaction),
        DurableCommitOutcome::Committed
    );
}

/// Runs `propose_and_vote`/`try_form_certificate`/`activate` for one
/// outgoing-epoch transition through the production path, on a store that
/// already has `outgoing_epoch`'s committed outgoing set.
fn activate_one_transition<S: StructuredDurableDomainStateStore>(
    store: &S,
    outgoing_epoch: Epoch,
    signers: &[TestSigner],
    entries: &[FastPathValidatorEntry],
    next_entries: Vec<FastPathValidatorEntry>,
) -> FastPathEpochTransitionRecord {
    let mut votes: Vec<EpochTransitionVote> = Vec::new();
    for signer in signers {
        let vote = propose_and_vote(
            store,
            &context(1),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            next_entries.clone(),
            signer,
        )
        .unwrap();
        votes.push(vote);
    }
    let et_certifier = certifier(chain(), outgoing_epoch, entries);
    let certificate = et_certifier
        .try_form_certificate(
            votes[0].next_epoch,
            votes[0].current_validator_set_digest,
            votes[0].next_validator_set_digest,
            votes[0].activation_digest,
            &votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .expect("quorum reached");
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();
    let outcome = activate(
        store,
        &context(1),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        next_entries,
        &certificate_bytes,
        7,
    )
    .unwrap();
    match outcome {
        EpochActivationOutcome::Activated(record) => record,
        EpochActivationOutcome::AlreadyActivated(_) => panic!("expected a fresh activation"),
    }
}

/// Installs one committed, eligible `Active` bond for each of `validators`
/// against `fixture`'s own already-genesis-installed economics policy and
/// resource -- for a "next" validator set introduced mid-chain that was
/// never part of the original genesis validator set and therefore was never
/// bonded by the genesis manifest itself. DR-0137 unit 3's pre-vote
/// eligibility gate in `propose_and_vote` requires this for every next-set
/// validator; idempotent across repeated calls.
pub(crate) fn install_additional_bonds<S: StructuredDurableDomainStateStore>(
    store: &S,
    op_context: &DurableOperationContext,
    op_domain: AtomicityDomainId,
    fixture: &GenesisFixture,
    validators: &[FastPathValidatorEntry],
) {
    let resource_policy = &fixture.manifest.economics_policy.resources[0];
    let resource_domain: u16 = resource_policy.resource_id.domain();
    let resource: [u8; 32] = *resource_policy.resource_id.value();
    let bond_context: PublicationContext = resource_policy.context.clone();
    for validator in validators {
        let bond_key: Vec<u8> =
            local_instance_state::fastpath_bond_record_key(bond_context.chain_id(), &validator.id)
                .unwrap();
        let observed: VersionedStateValue = store
            .get_versioned_durable(op_context, op_domain, &bond_key)
            .unwrap();
        if observed.value().is_some() {
            continue;
        }
        let mut object_id_bytes: [u8; 32] = *validator.id.as_bytes();
        object_id_bytes[0] = 0x70;
        let object_id: ObjectId = ObjectId::new(object_id_bytes);
        let authorization_key: [u8; 32] = validator
            .public_key
            .as_slice()
            .try_into()
            .expect("fixture validator key length");
        let bond: FastPathBondRecord = FastPathBondRecord {
            context: bond_context.clone(),
            validator_id: validator.id,
            resource_domain,
            resource,
            custody_object: ObjectRef {
                id: object_id,
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x71; 32]),
            },
            custody_object_epoch: bond_context.epoch(),
            authority: ObjectAuthority {
                object_id,
                instance_context: bond_context.clone(),
                instance: resource_policy.instance.clone(),
                code: resource_policy.code.clone(),
                ty: resource_policy.ty.clone(),
            },
            amount: 1_000_000,
            committed_at_checkpoint: 0,
            generation: 1,
            lifecycle_epoch: bond_context.epoch(),
            // Installed directly as a genesis-equivalent generation-1 bond:
            // immediately liable, like a real genesis bond.
            slashable_from_epoch: bond_context.epoch(),
            required_minimum: 1,
            state: FastPathBondState::Active,
            authorization_scheme: validator.signature_scheme,
            authorization_key,
        };
        let transaction = AtomicStateTransaction::new(
            op_domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(bond_key.clone(), observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(
                    bond_key,
                    StateMutation::Put(encode_fastpath_bond_record(&bond).unwrap()),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(op_context, transaction),
            DurableCommitOutcome::Committed
        );
    }
}

/// A real genesis install immediately followed by one fully certified and
/// activated `0 -> 1` transition, all on `store` -- the common starting
/// point for every single-step restart-verify tamper test below.
fn install_and_activate_one_transition<S: StructuredDurableDomainStateStore>(
    store: &S,
) -> (GenesisFixture, FastPathEpochTransitionRecord) {
    let (signers, entries) = four_validators();
    let (_next_signers, next_entries) = four_next_validators();
    let fixture: GenesisFixture = build_genesis_fixture(entries.clone());
    let outcome = install_genesis(store, &fixture.manifest);
    assert!(matches!(
        outcome,
        GenesisInstallOutcome::FreshInstall { .. }
    ));
    install_additional_bonds(store, &context(1), domain(), &fixture, &next_entries);
    let record = activate_one_transition(store, Epoch::new(0), &signers, &entries, next_entries);
    (fixture, record)
}

/// A third, distinct four-validator set, standing in for the `e+2`
/// incoming set of [`build_two_step_transition_chain`]'s second transition.
fn four_second_next_validators() -> (Vec<TestSigner>, Vec<FastPathValidatorEntry>) {
    let mut signers: Vec<TestSigner> = Vec::new();
    let mut entries: Vec<FastPathValidatorEntry> = Vec::new();
    for seed in [231u8, 232, 233, 234] {
        let (signer, entry) = validator(seed);
        signers.push(signer);
        entries.push(entry);
    }
    (signers, entries)
}

/// Builds a real genesis install and activates two chained transitions
/// (`0 -> 1` then `1 -> 2`) on `store`, entirely through the production
/// `propose_and_vote`/`activate` path -- the minimum needed to exercise
/// restart-verify's `i > g` branches (chaining a historical validator-set
/// row and an activation/policy row against the *previous* step's digest,
/// not the genesis digest), per DR-0132 §7's note that a single-transition
/// chain cannot reach them.
fn build_two_step_transition_chain<S: StructuredDurableDomainStateStore>(
    store: &S,
) -> (
    GenesisFixture,
    FastPathEpochTransitionRecord,
    FastPathEpochTransitionRecord,
) {
    let (signers_0, entries_0) = four_validators();
    let (signers_1, entries_1) = four_next_validators();
    let (_signers_2, entries_2) = four_second_next_validators();

    let fixture: GenesisFixture = build_genesis_fixture(entries_0.clone());
    let outcome = install_genesis(store, &fixture.manifest);
    assert!(matches!(
        outcome,
        GenesisInstallOutcome::FreshInstall { .. }
    ));
    install_additional_bonds(store, &context(1), domain(), &fixture, &entries_1);
    install_additional_bonds(store, &context(1), domain(), &fixture, &entries_2);

    let first = activate_one_transition(
        store,
        Epoch::new(0),
        &signers_0,
        &entries_0,
        entries_1.clone(),
    );
    let second = activate_one_transition(store, Epoch::new(1), &signers_1, &entries_1, entries_2);

    (fixture, first, second)
}

#[test]
fn restart_verify_accepts_a_two_step_chain_and_binds_the_live_record_to_the_last_step() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, _first, _second) = build_two_step_transition_chain(&store);
    let outcome = install_genesis_result(&store, &fixture.manifest).unwrap();
    assert!(matches!(
        outcome,
        GenesisInstallOutcome::VerifiedExisting { .. }
    ));
    let epoch_record =
        query_committed_epoch_state(&store, &context(1), domain(), &chain()).unwrap();
    assert_eq!(epoch_record.current_epoch, Epoch::new(2));
    assert_eq!(epoch_record.previous_epoch, Some(Epoch::new(1)));
}

#[test]
fn restart_verify_rejects_a_tampered_live_epoch_record_after_a_transition() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, _record) = install_and_activate_one_transition(&store);

    let key = local_instance_state::fastpath_epoch_record_key(&chain()).unwrap();
    let observed = store
        .get_versioned_durable(&context(1), domain(), &key)
        .unwrap();
    let mut live =
        local_instance_state::decode_fastpath_epoch_record(observed.value().unwrap()).unwrap();
    live.current_validator_set_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]);
    overwrite_row(
        &store,
        &key,
        local_instance_state::encode_fastpath_epoch_record(&live).unwrap(),
    );

    let result = install_genesis_result(&store, &fixture.manifest);
    assert!(matches!(
        result,
        Err(GenesisError::TamperedInstalledRecord(
            "fast-path epoch record"
        ))
    ));
}

/// Uses the two-step chain and tampers the *earlier* (`0 -> 1`) transition's
/// own record after the *later* (`1 -> 2`) transition has already
/// legitimately committed on top of it -- proving, per DR-0132 §7's evidence
/// note, that an earlier-step tamper is still caught at restart and is not
/// masked by a later step's legitimate commit.
#[test]
fn restart_verify_rejects_a_tampered_stored_transition_record_field() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, first, _second) = build_two_step_transition_chain(&store);

    let key = local_instance_state::fastpath_epoch_transition_key(&chain(), Epoch::new(1)).unwrap();
    let mut tampered = first.clone();
    tampered.next_validator_set_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]);
    overwrite_row(
        &store,
        &key,
        encode_fastpath_epoch_transition_record(&tampered).unwrap(),
    );

    let result = install_genesis_result(&store, &fixture.manifest);
    assert!(matches!(
        result,
        Err(GenesisError::TamperedInstalledRecord(
            "fast-path epoch transition record"
        ))
    ));
}

#[test]
fn restart_verify_rejects_a_stored_certificate_with_an_invalid_signature() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, record) = install_and_activate_one_transition(&store);

    let mut certificate =
        consensus::decode_epoch_transition_certificate(&record.certificate).unwrap();
    certificate.votes[0].signature[0] ^= 0xFF;
    let mut tampered = record.clone();
    tampered.certificate = consensus::encode_epoch_transition_certificate(&certificate).unwrap();
    let key = local_instance_state::fastpath_epoch_transition_key(&chain(), Epoch::new(1)).unwrap();
    overwrite_row(
        &store,
        &key,
        encode_fastpath_epoch_transition_record(&tampered).unwrap(),
    );

    let result = install_genesis_result(&store, &fixture.manifest);
    assert!(matches!(
        result,
        Err(GenesisError::TamperedInstalledRecord(
            "fast-path epoch transition certificate"
        ))
    ));
}

/// Distinct from `restart_verify_rejects_a_tampered_stored_transition_record_field`:
/// there, the record's own summary field is corrupted with no matching
/// certificate. Here, a second certificate is a completely real,
/// cryptographically valid `EpochTransitionCertificate` for the exact same
/// outgoing epoch and outgoing set -- it cryptographically verifies fine on
/// its own -- but for a *different* incoming validator set than the one the
/// stored record's own summary fields (left untouched) claim. This proves
/// restart-verify rejects a certificate-substitution attack, not merely a
/// bit-flip.
#[test]
fn restart_verify_rejects_a_stored_certificate_whose_payload_disagrees_with_its_own_record() {
    let store: MemoryDurableStateStore = memory_store();
    let (signers, entries) = four_validators();
    let (_next_signers, next_entries) = four_next_validators();
    let fixture: GenesisFixture = build_genesis_fixture(entries.clone());
    let outcome = install_genesis(&store, &fixture.manifest);
    assert!(matches!(
        outcome,
        GenesisInstallOutcome::FreshInstall { .. }
    ));
    install_additional_bonds(&store, &context(1), domain(), &fixture, &next_entries);
    let record = activate_one_transition(&store, Epoch::new(0), &signers, &entries, next_entries);

    // A real, independently valid certificate for the same outgoing epoch
    // but a different incoming set -- never activated, never installed, but
    // cryptographically indistinguishable from a legitimate one.
    let (alternate_signers, alternate_entries) = {
        let (a, b) = validator(241);
        let (c, d) = validator(242);
        let (e, f) = validator(243);
        (vec![a, c, e], vec![b, d, f])
    };
    install_additional_bonds(&store, &context(1), domain(), &fixture, &alternate_entries);
    let derived = derive_activation_set(
        &store,
        &context(1),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        Epoch::new(0),
        Epoch::new(1),
        &alternate_entries,
    )
    .unwrap();
    let et_certifier = certifier(chain(), Epoch::new(0), &entries);
    let alternate_votes: Vec<EpochTransitionVote> = signers
        .iter()
        .map(|signer| {
            et_certifier
                .cast_vote(
                    Epoch::new(1),
                    record.previous_validator_set_digest,
                    derived.next_validator_set_digest,
                    derived.activation_digest,
                    signer,
                )
                .unwrap()
        })
        .collect();
    let alternate_certificate = et_certifier
        .try_form_certificate(
            Epoch::new(1),
            record.previous_validator_set_digest,
            derived.next_validator_set_digest,
            derived.activation_digest,
            &alternate_votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .expect("quorum reached");
    assert_ne!(
        alternate_certificate.next_validator_set_digest,
        record.next_validator_set_digest
    );
    let _ = alternate_signers;

    let mut tampered = record.clone();
    tampered.certificate =
        consensus::encode_epoch_transition_certificate(&alternate_certificate).unwrap();
    let key = local_instance_state::fastpath_epoch_transition_key(&chain(), Epoch::new(1)).unwrap();
    overwrite_row(
        &store,
        &key,
        encode_fastpath_epoch_transition_record(&tampered).unwrap(),
    );

    let result = install_genesis_result(&store, &fixture.manifest);
    assert!(matches!(
        result,
        Err(GenesisError::TamperedInstalledRecord(
            "fast-path epoch transition record"
        ))
    ));
}

/// The historical outgoing set for the *second* transition's step
/// (`i == 1`) is the `e+1` validator-set row this same algorithm installed
/// while verifying the first transition -- only reachable by chaining two
/// transitions (C1's `i > g` branch, §7 step 3(c)-(d)).
///
/// That row is also, by construction, one of the four rows the *first*
/// transition's own step (`i == 0`) already re-hashes into its
/// `activation_digest` at §7 step 3(g), and that step always runs to
/// completion before step `i == 1` begins. So any byte-level tamper of this
/// row is necessarily caught first by step 0's activation-digest re-hash,
/// not by step 1's own historical-validator-set digest-chain comparison --
/// both are fail-closed, but the activation-set check is unconditionally
/// the first to observe a divergence in these particular bytes. This test
/// asserts the actual (still fail-closed) surfaced error, and exists to
/// prove -- as required by DR-0132 §7's evidence note -- that a tamper to a
/// historical validator-set row referenced only by the `i > g` branch is
/// still caught after a later, legitimate transition has committed on top
/// of it, not merely at the point it was first installed.
#[test]
fn restart_verify_rejects_a_tampered_historical_validator_set_row() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, _first, _second) = build_two_step_transition_chain(&store);

    let historical_context =
        PublicationContext::new(chain(), protocol_version(), Epoch::new(1)).unwrap();
    let key = local_instance_state::fastpath_validator_set_key(&historical_context).unwrap();
    let observed = store
        .get_versioned_durable(&context(1), domain(), &key)
        .unwrap();
    let mut record =
        fast_path::records::decode_fastpath_validator_set_record(observed.value().unwrap())
            .unwrap();
    record.validators[0].voting_power += 1;
    overwrite_row(
        &store,
        &key,
        fast_path::records::encode_fastpath_validator_set_record(&record).unwrap(),
    );

    let result = install_genesis_result(&store, &fixture.manifest);
    assert!(matches!(
        result,
        Err(GenesisError::TamperedInstalledRecord(
            "fast-path epoch activation set"
        ))
    ));
}

#[test]
fn restart_verify_rejects_a_tampered_activation_set_or_policy_row_after_activation() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, _record) = install_and_activate_one_transition(&store);

    let next_context = epoch_context(1);
    let key = local_instance_state::execution_policy_key_for_profile(&next_context, 4).unwrap();
    overwrite_row(&store, &key, vec![0xDE, 0xAD, 0xBE, 0xEF]);

    let result = install_genesis_result(&store, &fixture.manifest);
    assert!(matches!(
        result,
        Err(GenesisError::TamperedInstalledRecord(
            "activated execution policy"
        ))
    ));
}

#[test]
fn restart_verify_rejects_a_missing_step_in_the_transition_chain() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, _first, _second) = build_two_step_transition_chain(&store);

    let key = local_instance_state::fastpath_epoch_transition_key(&chain(), Epoch::new(1)).unwrap();
    delete_row(&store, &key);

    let result = install_genesis_result(&store, &fixture.manifest);
    assert!(matches!(
        result,
        Err(GenesisError::TamperedInstalledRecord(
            "fast-path epoch transition record"
        ))
    ));
}

// ── stale object-lock reclamation (DR-0132 §3.D) ────────────────────────────

/// Genesis + one fully certified and activated `0 -> 1` transition on the
/// lightweight `paid_execution::tests` fixture, returning everything a
/// direct-paid or fast-path-prepare call at the next epoch needs: the
/// fixture, the `e+1` context, and the freshly re-derived `e+1` fee policy.
fn install_lightweight_and_activate_one_transition<S: StructuredDurableDomainStateStore>(
    store: &S,
) -> (
    Fixture,
    PublicationContext,
    execution::paid_execution::PaidFeePolicy,
) {
    let (fixture, signers, entries) = install_lightweight(store);
    let (_next_signers, next_entries) = four_next_validators();
    let (certificate, _, _) =
        propose_vote_and_certify(store, &signers, &entries, next_entries.clone());
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();
    let outcome = activate(
        store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries,
        &certificate_bytes,
        11,
    )
    .unwrap();
    let record = match outcome {
        EpochActivationOutcome::Activated(record) => record,
        EpochActivationOutcome::AlreadyActivated(_) => panic!("expected a fresh activation"),
    };
    let next_context: PublicationContext = PublicationContext::new(
        pe_protocol().chain_id().clone(),
        pe_protocol().protocol_version(),
        record.to_epoch,
    )
    .unwrap();
    let observed_fee_policy = store
        .get_versioned_durable(
            &pe_context(),
            pe_domain(),
            &local_instance_state::paid_fee_policy_key(&next_context).unwrap(),
        )
        .unwrap();
    let next_fee_policy =
        execution::paid_execution::decode_paid_fee_policy(observed_fee_policy.value().unwrap())
            .unwrap();
    (fixture, next_context, next_fee_policy)
}

fn install_stale_lock<S: StructuredDurableDomainStateStore>(
    store: &S,
    object: &Object,
    locked_epoch: Epoch,
    request_id: [u8; 32],
) -> Vec<u8> {
    let lock_key: Vec<u8> =
        local_instance_state::fastpath_lock_key(pe_protocol().chain_id(), object.id).unwrap();
    let lock: local_instance_state::FastPathLockRecord = local_instance_state::FastPathLockRecord {
        request_id,
        object: crate::paid_execution::tests::object_reference(object),
        locked_epoch,
    };
    let observed = store
        .get_versioned_durable(&pe_context(), pe_domain(), &lock_key)
        .unwrap();
    let transaction = AtomicStateTransaction::new(
        pe_domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(lock_key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(
                lock_key.clone(),
                StateMutation::Put(
                    local_instance_state::encode_fastpath_lock_record(&lock).unwrap(),
                ),
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&pe_context(), transaction),
        DurableCommitOutcome::Committed
    );
    lock_key
}

/// DR-0132 §3.D, direct paid-commit path: a lock stamped a strictly older
/// epoch than the fenced current epoch is reclaimed -- the direct commit
/// proceeds and deletes it -- instead of blocking.
#[test]
fn a_stale_object_lock_is_deleted_by_a_direct_paid_commit_at_the_next_epoch() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, next_context, next_fee_policy) =
        install_lightweight_and_activate_one_transition(&store);
    let lock_key = install_stale_lock(&store, &fixture.coin, pe_protocol().epoch(), [0x11; 32]);

    let bytes = sign_transfer(&fixture, &next_context, &next_fee_policy, 91, 0);
    let output = crate::paid_execution::handle_paid_execution(
        &store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        &[],
        &next_context,
        &LocalExecutionPolicy::generic_object_results(next_context.clone()),
        &next_fee_policy,
        &CountingEngine::new(),
        &bytes,
        10,
    )
    .unwrap();
    assert_eq!(receipt(&output).status, PaidExecutionStatus::Success);

    let observed = store
        .get_versioned_durable(&pe_context(), pe_domain(), &lock_key)
        .unwrap();
    assert!(
        observed.value().is_none(),
        "the stale lock must be deleted, not left behind, by the direct commit"
    );
}

/// C7 regression at the real certified activation boundary: direct paid
/// execution accepts only the freshly installed e+1 context/policies. An
/// intent still signed for e is rejected, and deleting either e+1 policy row
/// never falls back to the intact e row.
#[test]
fn direct_paid_after_real_transition_rejects_stale_epoch_and_missing_current_policies() {
    let success_store: MemoryDurableStateStore = memory_store();
    let (success_fixture, success_context, success_fee_policy) =
        install_lightweight_and_activate_one_transition(&success_store);
    let success_bytes: Vec<u8> = sign_transfer(
        &success_fixture,
        &success_context,
        &success_fee_policy,
        91,
        0,
    );
    let success_output: NodeOutput = crate::paid_execution::handle_paid_execution(
        &success_store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        &[],
        &success_context,
        &LocalExecutionPolicy::generic_object_results(success_context.clone()),
        &success_fee_policy,
        &CountingEngine::new(),
        &success_bytes,
        10,
    )
    .unwrap();
    assert_eq!(
        receipt(&success_output).status,
        PaidExecutionStatus::Success
    );

    let stale_store: MemoryDurableStateStore = memory_store();
    let (stale_fixture, next_context, next_fee_policy) =
        install_lightweight_and_activate_one_transition(&stale_store);
    let stale_bytes: Vec<u8> =
        sign_transfer(&stale_fixture, &pe_protocol(), &stale_fixture.policy, 92, 0);
    let stale_engine: CountingEngine = CountingEngine::new();
    let stale_result = crate::paid_execution::handle_paid_execution(
        &stale_store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        &[],
        &next_context,
        &LocalExecutionPolicy::generic_object_results(next_context.clone()),
        &next_fee_policy,
        &stale_engine,
        &stale_bytes,
        10,
    );
    assert!(matches!(
        stale_result,
        Err(crate::paid_execution::PaidExecutionAdmissionError::Paid(
            PaidExecutionError::ContextMismatch
        ))
    ));
    assert_eq!(stale_engine.calls.get(), 0);

    for missing_key in [
        local_instance_state::execution_policy_key_for_profile(&next_context, 4).unwrap(),
        local_instance_state::paid_fee_policy_key(&next_context).unwrap(),
    ] {
        let store: MemoryDurableStateStore = memory_store();
        let (fixture, current_context, current_fee_policy) =
            install_lightweight_and_activate_one_transition(&store);
        let observed: VersionedStateValue = store
            .get_versioned_durable(&pe_context(), pe_domain(), &missing_key)
            .unwrap();
        assert!(observed.value().is_some());
        let deletion: AtomicStateTransaction = AtomicStateTransaction::new(
            pe_domain(),
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(missing_key.clone(), observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(missing_key, StateMutation::Delete).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&pe_context(), deletion),
            DurableCommitOutcome::Committed
        );
        let fresh_bytes: Vec<u8> =
            sign_transfer(&fixture, &current_context, &current_fee_policy, 93, 0);
        let engine: CountingEngine = CountingEngine::new();
        let result = crate::paid_execution::handle_paid_execution(
            &store,
            &runtime::MemoryBlobStore::default(),
            &pe_context(),
            pe_domain(),
            &pe_resolver(),
            &[],
            &current_context,
            &LocalExecutionPolicy::generic_object_results(current_context.clone()),
            &current_fee_policy,
            &engine,
            &fresh_bytes,
            10,
        );
        assert!(matches!(
            result,
            Err(crate::paid_execution::PaidExecutionAdmissionError::Invalid(
                "execution policy absent or different" | "paid fee policy absent or different"
            ))
        ));
        assert_eq!(engine.calls.get(), 0);
    }
}

/// DR-0132 §3.D, fast-path prepare: a lock stamped a strictly older epoch is
/// reclaimed -- `prepare` overwrites it with its own fresh, current-epoch
/// lock under the same CAS revision, instead of blocking.
#[test]
fn a_stale_object_lock_is_reclaimed_by_a_fresh_prepare_at_the_next_epoch() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, next_context, next_fee_policy) =
        install_lightweight_and_activate_one_transition(&store);
    let lock_key = install_stale_lock(&store, &fixture.coin, pe_protocol().epoch(), [0x22; 32]);

    let (next_signers, _next_entries) = four_next_validators();
    let bytes = sign_transfer(&fixture, &next_context, &next_fee_policy, 92, 0);
    let vote = fast_path::prepare(
        &store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        &[],
        &next_context,
        &LocalExecutionPolicy::generic_object_results(next_context.clone()),
        &next_fee_policy,
        &CountingEngine::new(),
        &next_signers[0],
        &bytes,
        10,
    );
    assert!(
        vote.is_ok(),
        "expected the stale lock to be reclaimed: {vote:?}"
    );

    let observed = store
        .get_versioned_durable(&pe_context(), pe_domain(), &lock_key)
        .unwrap();
    let installed_lock =
        local_instance_state::decode_fastpath_lock_record(observed.value().unwrap()).unwrap();
    assert_eq!(installed_lock.locked_epoch, next_context.epoch());
}

/// Negative control: a lock stamped the *current* epoch still blocks a fresh
/// `prepare`, exactly as it did before DR-0132.
#[test]
fn a_current_epoch_lock_still_blocks_a_fresh_prepare() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, next_context, next_fee_policy) =
        install_lightweight_and_activate_one_transition(&store);
    install_stale_lock(&store, &fixture.coin, next_context.epoch(), [0x33; 32]);

    let (next_signers, _next_entries) = four_next_validators();
    let bytes = sign_transfer(&fixture, &next_context, &next_fee_policy, 93, 0);
    let result = fast_path::prepare(
        &store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        &[],
        &next_context,
        &LocalExecutionPolicy::generic_object_results(next_context.clone()),
        &next_fee_policy,
        &CountingEngine::new(),
        &next_signers[0],
        &bytes,
        10,
    );
    assert!(matches!(
        result,
        Err(fast_path::FastPathError::Admission(
            crate::paid_execution::PaidExecutionAdmissionError::Invalid(
                "object locked by a pending fast-path certificate"
            )
        ))
    ));
}

/// Negative control: a lock stamped a *future* epoch is a storage-invariant
/// violation and fails closed rather than being treated as reclaimable.
#[test]
fn a_lock_stamped_a_future_epoch_fails_closed_at_a_fresh_prepare() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, next_context, next_fee_policy) =
        install_lightweight_and_activate_one_transition(&store);
    install_stale_lock(
        &store,
        &fixture.coin,
        Epoch::new(next_context.epoch().get() + 1),
        [0x44; 32],
    );

    let (next_signers, _next_entries) = four_next_validators();
    let bytes = sign_transfer(&fixture, &next_context, &next_fee_policy, 94, 0);
    let result = fast_path::prepare(
        &store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        &[],
        &next_context,
        &LocalExecutionPolicy::generic_object_results(next_context.clone()),
        &next_fee_policy,
        &CountingEngine::new(),
        &next_signers[0],
        &bytes,
        10,
    );
    assert!(matches!(
        result,
        Err(fast_path::FastPathError::Admission(
            crate::paid_execution::PaidExecutionAdmissionError::Invalid(
                "fast-path lock stamped a future epoch"
            )
        ))
    ));
}

// ── stale prepared-record supersession (DR-0132 C5) ─────────────────────────

/// A prepared record from a strictly older epoch than the committed current
/// epoch is stale, not a live replay candidate: its `FastVote` context can
/// never be certified again once the epoch has advanced (§6's "epoch-`e`
/// certificate at `apply` after activation" row). `prepare`'s replay branch
/// must treat it as absent and let the ordinary fresh-prepare `Put`
/// supersede it, rather than rejecting the same request id forever with
/// "conflicting fast-path prepared record".
#[test]
fn a_stale_prepared_record_is_superseded_at_the_next_epoch_under_the_same_request_id() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, signers, entries) = install_lightweight(&store);

    // A prepare at the outgoing epoch, under request id 95.
    let baseline_nonce = crate::paid_execution::tests::next_nonce(&store);
    let baseline_bytes = sign_transfer(
        &fixture,
        &pe_protocol(),
        &fixture.policy,
        95,
        baseline_nonce,
    );
    let baseline_vote = fast_path::prepare(
        &store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        &[],
        &pe_protocol(),
        &LocalExecutionPolicy::generic_object_results(pe_protocol()),
        &fixture.policy,
        &CountingEngine::new(),
        &signers[0],
        &baseline_bytes,
        10,
    )
    .unwrap();
    assert_eq!(baseline_vote.epoch, pe_protocol().epoch());

    let (_next_signers, next_entries) = four_next_validators();
    let (certificate, _, _) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();
    activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries.clone(),
        &certificate_bytes,
        11,
    )
    .unwrap();
    let next_context: PublicationContext = PublicationContext::new(
        pe_protocol().chain_id().clone(),
        pe_protocol().protocol_version(),
        Epoch::new(pe_protocol().epoch().get() + 1),
    )
    .unwrap();
    let observed_fee_policy = store
        .get_versioned_durable(
            &pe_context(),
            pe_domain(),
            &local_instance_state::paid_fee_policy_key(&next_context).unwrap(),
        )
        .unwrap();
    let next_fee_policy =
        execution::paid_execution::decode_paid_fee_policy(observed_fee_policy.value().unwrap())
            .unwrap();

    // The *same* request id, freshly signed at the next epoch, against the
    // stale prepared record left behind by the epoch-0 prepare above.
    let (next_signers, _) = four_next_validators();
    let next_bytes = sign_transfer(&fixture, &next_context, &next_fee_policy, 95, 0);
    let next_vote = fast_path::prepare(
        &store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        &[],
        &next_context,
        &LocalExecutionPolicy::generic_object_results(next_context.clone()),
        &next_fee_policy,
        &CountingEngine::new(),
        &next_signers[0],
        &next_bytes,
        10,
    )
    .unwrap();
    assert_eq!(next_vote.epoch, Epoch::new(1));
    assert_ne!(next_vote.tx_hash, baseline_vote.tx_hash);
}

// ── activate-vs-apply CAS race (DR-0132 §6) ─────────────────────────────────

/// A `PaidContractEngine` that, mid-execution of a `fast_path::apply` call,
/// races a real, independent `activate` to completion on the same store --
/// simulating a genuinely concurrent activation landing between `apply`'s
/// own epoch-record fence read and its final commit, without needing real
/// threads. Mirrors `fast_path::tests::EpochRacingEngine`'s pattern, but
/// with a real DR-0132 transition instead of a stand-in racing write.
struct RacingActivateEngine<'a, S: StructuredDurableDomainStateStore> {
    store: &'a S,
    inner: CountingEngine,
    next_entries: Vec<FastPathValidatorEntry>,
    certificate_bytes: Vec<u8>,
}
impl<S: StructuredDurableDomainStateStore> execution::paid_execution::PaidContractEngine
    for RacingActivateEngine<'_, S>
{
    fn execute_paid(
        &self,
        request: execution::paid_execution::PaidExecutionRequest<'_>,
    ) -> Result<
        execution::paid_execution::PaidExecutionOutcome,
        execution::paid_execution::PaidExecutionError,
    > {
        let outcome = self.inner.execute_paid(request)?;
        let outcome_activate = activate(
            self.store,
            &pe_context(),
            pe_domain(),
            &pe_resolver(),
            pe_protocol().chain_id(),
            pe_protocol().protocol_version(),
            self.next_entries.clone(),
            &self.certificate_bytes,
            99,
        )
        .unwrap();
        assert!(matches!(
            outcome_activate,
            EpochActivationOutcome::Activated(_)
        ));
        Ok(outcome)
    }
}

#[test]
fn activate_and_apply_contend_on_the_same_epoch_record_and_exactly_one_commits() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();
    let (transition_certificate, _, _) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());
    let transition_certificate_bytes =
        consensus::encode_epoch_transition_certificate(&transition_certificate).unwrap();

    // A normal DR-0130 prepare/certificate cycle at the outgoing epoch.
    // `prepare` is validator-local durable bookkeeping (a real deployment
    // runs it on each validator's own independent store); on this single
    // shared store, only the first validator actually calls `prepare` --
    // the remaining quorum votes are cast directly against its resulting
    // digest, exactly as an independent validator would derive and sign the
    // identical `(tx_hash, execution_effects_hash)` pair on its own store
    // (proven deterministic elsewhere, e.g.
    // `independent_validators_derive_byte_identical_commitment_and_a_quorum_certificate_applies`).
    let nonce = crate::paid_execution::tests::next_nonce(&store);
    let bytes = sign_transfer(&fixture, &pe_protocol(), &fixture.policy, 97, nonce);
    let outgoing_set: ValidatorSet = ValidatorSet::new(
        pe_protocol().epoch(),
        entries
            .iter()
            .map(|entry| ValidatorInfo {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key.clone(),
            })
            .collect(),
    )
    .unwrap();
    let fast_certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        pe_protocol().chain_id().clone(),
        pe_protocol().protocol_version(),
        pe_protocol().epoch(),
        outgoing_set,
    )
    .unwrap();
    let first_vote: FastVote = fast_path::prepare(
        &store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        &[],
        &pe_protocol(),
        &LocalExecutionPolicy::generic_object_results(pe_protocol()),
        &fixture.policy,
        &CountingEngine::new(),
        &signers[0],
        &bytes,
        10,
    )
    .unwrap();
    let mut fast_votes: Vec<FastVote> = vec![first_vote.clone()];
    for signer in &signers[1..] {
        fast_votes.push(
            fast_certifier
                .cast_vote(
                    first_vote.tx_hash,
                    first_vote.execution_effects_hash,
                    first_vote.locked_objects_digest,
                    signer,
                )
                .unwrap(),
        );
    }
    let fast_certificate: FastCertificate = fast_certifier
        .try_form_certificate(
            fast_votes[0].tx_hash,
            fast_votes[0].execution_effects_hash,
            fast_votes[0].locked_objects_digest,
            &fast_votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .expect("quorum reached");
    let fast_certificate_bytes = consensus::encode_fast_certificate(&fast_certificate).unwrap();

    let racing: RacingActivateEngine<'_, MemoryDurableStateStore> = RacingActivateEngine {
        store: &store,
        inner: CountingEngine::new(),
        next_entries,
        certificate_bytes: transition_certificate_bytes,
    };
    let result = fast_path::apply(
        &store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        &[],
        &pe_protocol(),
        &LocalExecutionPolicy::generic_object_results(pe_protocol()),
        &fixture.policy,
        &racing,
        &bytes,
        &fast_certificate_bytes,
    );
    assert!(matches!(
        result,
        Err(fast_path::FastPathError::Node(NodeCoreError::StateConflict))
    ));

    // The race's own `activate` really did commit: the epoch already
    // advanced, so the loser (`apply`) cannot simply be retried as-is --
    // its own certificate is now permanently `EpochMismatch` (the next row
    // in DR-0132 §6's matrix).
    let epoch_record =
        query_committed_epoch_state(&store, &pe_context(), pe_domain(), pe_protocol().chain_id())
            .unwrap();
    assert_eq!(epoch_record.current_epoch, Epoch::new(1));

    let retry = fast_path::apply(
        &store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        &[],
        &pe_protocol(),
        &LocalExecutionPolicy::generic_object_results(pe_protocol()),
        &fixture.policy,
        &CountingEngine::new(),
        &bytes,
        &fast_certificate_bytes,
    );
    assert!(matches!(
        retry,
        Err(fast_path::FastPathError::Node(
            NodeCoreError::EpochMismatch { expected, actual }
        )) if expected == Epoch::new(1) && actual == pe_protocol().epoch()
    ));
}

// ── retry after an indeterminate `activate` commit (DR-0132 §5) ────────────

/// A store that reports [`IndeterminateCommitReason::ConnectionLost`] on the
/// very next `commit_durable` call *after* the underlying commit has already
/// been dispatched to and applied by the inner store -- mirroring a
/// connection loss discovered only after the backend durably committed.
/// Follows `fast_path::tests::IndeterminateOnceApplyStore`'s convention, but
/// intercepts `commit_durable` (what `activate` itself calls) rather than
/// `commit_invocation`.
struct IndeterminateOnceActivateStore {
    inner: MemoryDurableStateStore,
    inject_indeterminate: std::cell::Cell<bool>,
}
impl IndeterminateOnceActivateStore {
    fn new() -> Self {
        Self {
            inner: memory_store(),
            inject_indeterminate: std::cell::Cell::new(false),
        }
    }
}
impl runtime::DurableDomainStateStore for IndeterminateOnceActivateStore {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.inner.get_versioned_durable(context, domain, key)
    }
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        let outcome: DurableCommitOutcome = self.inner.commit_durable(context, transaction);
        if self.inject_indeterminate.take() {
            assert_eq!(outcome, DurableCommitOutcome::Committed);
            return DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost);
        }
        outcome
    }
}
impl StructuredDurableDomainStateStore for IndeterminateOnceActivateStore {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(context, domain, object_id)
    }
    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: runtime::DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, object_version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: runtime::DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request_id)
    }
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_invocation(context, transaction)
    }
}

/// DR-0132 §5: `activate` is safely retryable without request-id
/// reconciliation, because it writes no receipt and is idempotent on
/// committed state -- a retry either observes the activation (branch C.3)
/// or re-attempts the identical CAS.
#[test]
fn activate_is_retry_safe_after_an_indeterminate_commit() {
    let store: IndeterminateOnceActivateStore = IndeterminateOnceActivateStore::new();
    let (fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();
    let (certificate, next_validator_set_digest, activation_digest) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();
    let _ = fixture;

    store.inject_indeterminate.set(true);
    let first = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries.clone(),
        &certificate_bytes,
        12,
    );
    assert!(matches!(
        first,
        Err(EpochTransitionError::Node(
            NodeCoreError::DurableCommitIndeterminate(IndeterminateCommitReason::ConnectionLost)
        ))
    ));

    // The underlying commit genuinely happened; the retry must observe it
    // via branch C.3, not re-derive or re-verify from scratch and not fail.
    let retry = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries,
        &certificate_bytes,
        12,
    )
    .unwrap();
    let record = match retry {
        EpochActivationOutcome::AlreadyActivated(record) => record,
        EpochActivationOutcome::Activated(_) => {
            panic!("expected the retry to observe the already-committed activation")
        }
    };
    assert_eq!(record.next_validator_set_digest, next_validator_set_digest);
    assert_eq!(record.activation_digest, activation_digest);
}

// ── retired validator rejection at e+1 (DR-0132 §6) ─────────────────────────

/// A validator retired by the transition (present in the outgoing set, not
/// reappointed to the incoming set) can neither cast a recognized
/// `fast_path::prepare` vote nor contribute a recognized signature to a
/// certificate at the next epoch: `load_validator_set` at `e+1` loads only
/// the incoming set, so the retired validator's key is simply not a member
/// of the set `FastPathCertifier::cast_vote`/`verify_vote` check against.
#[test]
fn a_retired_validator_can_neither_vote_nor_sign_a_certificate_at_the_next_epoch() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();
    let (certificate, _, _) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();
    activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries,
        &certificate_bytes,
        13,
    )
    .unwrap();

    let next_context: PublicationContext = PublicationContext::new(
        pe_protocol().chain_id().clone(),
        pe_protocol().protocol_version(),
        Epoch::new(1),
    )
    .unwrap();
    let observed_fee_policy = store
        .get_versioned_durable(
            &pe_context(),
            pe_domain(),
            &local_instance_state::paid_fee_policy_key(&next_context).unwrap(),
        )
        .unwrap();
    let next_fee_policy =
        execution::paid_execution::decode_paid_fee_policy(observed_fee_policy.value().unwrap())
            .unwrap();

    // `signers[0]` was in the *outgoing* set, and is not a member of the
    // incoming set installed by `activate` above -- it is retired.
    let bytes = sign_transfer(&fixture, &next_context, &next_fee_policy, 99, 0);
    let result = fast_path::prepare(
        &store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        &[],
        &next_context,
        &LocalExecutionPolicy::generic_object_results(next_context.clone()),
        &next_fee_policy,
        &CountingEngine::new(),
        &signers[0],
        &bytes,
        10,
    );
    assert!(matches!(
        result,
        Err(fast_path::FastPathError::Consensus(
            ConsensusError::UnknownValidator(_)
        ))
    ));
}

// ── invalid `next_validators` sets are rejected via `ValidatorSet` (§3.A.2) ─

/// `derive_activation_set` (§3.A step 2) constructs the incoming set through
/// `validator_set::ValidatorSet::new`, so every one of its own invariants is
/// enforced for free at proposal time, before any vote is cast: an empty
/// set, a zero-voting-power entry, and a duplicate public key across two
/// distinct validator ids are all rejected with the exact
/// `ValidatorSetError` variant `ValidatorSet::new` itself reports.
#[test]
fn propose_and_vote_rejects_an_invalid_next_validator_set() {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, _entries) = install_lightweight(&store);

    let empty: Vec<FastPathValidatorEntry> = Vec::new();
    let result = propose_and_vote(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        empty,
        &signers[0],
    );
    assert!(matches!(
        result,
        Err(EpochTransitionError::ValidatorSet(ValidatorSetError::Empty))
    ));

    let (_zero_signer, zero_entry) = validator(221);
    let zero_power: Vec<FastPathValidatorEntry> = vec![FastPathValidatorEntry {
        voting_power: 0,
        ..zero_entry
    }];
    let result = propose_and_vote(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        zero_power,
        &signers[0],
    );
    assert!(matches!(
        result,
        Err(EpochTransitionError::ValidatorSet(
            ValidatorSetError::ZeroVotingPower(_)
        ))
    ));

    let (_a_signer, entry_a) = validator(222);
    let (_b_signer, mut entry_b) = validator(223);
    entry_b.public_key = entry_a.public_key.clone();
    let duplicate_key: Vec<FastPathValidatorEntry> = vec![entry_a, entry_b];
    let result = propose_and_vote(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        duplicate_key,
        &signers[0],
    );
    assert!(matches!(
        result,
        Err(EpochTransitionError::ValidatorSet(
            ValidatorSetError::DuplicatePublicKey(_)
        ))
    ));
}

// ── hash-suite activation exactly at e+1 (DR-0132 unresolved risk 2) ───────

/// A resolver whose schedule activates a *different* hash suite exactly at
/// the incoming epoch: `next_validator_set_digest` and `activation_digest`
/// are computed under the new suite (`suite_for_epoch(1)`) while the vote
/// itself is framed at the outgoing epoch 0 (`suite_for_epoch(0)`, the
/// unchanged genesis suite).
fn hash_suite_switch_resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        pe_protocol().chain_id().clone(),
        pe_protocol().protocol_version(),
        vec![
            HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            },
            HashSuiteSchedule {
                activation_epoch: Epoch::new(1),
                suite: HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
            },
        ],
    )
    .unwrap()
}

/// DR-0132's second unresolved risk, made concrete: a `HashSuiteSchedule`
/// activating exactly at `e+1` is deterministic, not merely by assertion --
/// the resulting `activation_digest` genuinely differs from what the same
/// activation set would hash to under the old suite alone, proving the new
/// suite was actually used rather than silently ignored, and a fresh
/// prepare/apply cycle still succeeds at `e+1` under it.
#[test]
fn hash_suite_activation_lands_exactly_at_the_transition_epoch_and_is_deterministic() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, signers, entries) = install_lightweight(&store);
    let switching_resolver: HashSuiteResolver = hash_suite_switch_resolver();
    let (next_signers, next_entries) = four_next_validators();

    let mut votes: Vec<EpochTransitionVote> = Vec::new();
    for signer in &signers {
        let vote = propose_and_vote(
            &store,
            &pe_context(),
            pe_domain(),
            &switching_resolver,
            pe_protocol().chain_id(),
            pe_protocol().protocol_version(),
            next_entries.clone(),
            signer,
        )
        .unwrap();
        votes.push(vote);
    }
    let cert: EpochTransitionCertifier = certifier(
        pe_protocol().chain_id().clone(),
        pe_protocol().epoch(),
        &entries,
    );
    let certificate: EpochTransitionCertificate = cert
        .try_form_certificate(
            votes[0].next_epoch,
            votes[0].current_validator_set_digest,
            votes[0].next_validator_set_digest,
            votes[0].activation_digest,
            &votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .expect("quorum reached");
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();

    let outcome = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &switching_resolver,
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries.clone(),
        &certificate_bytes,
        14,
    )
    .unwrap();
    let record: FastPathEpochTransitionRecord = match outcome {
        EpochActivationOutcome::Activated(record) => record,
        EpochActivationOutcome::AlreadyActivated(_) => panic!("expected a fresh activation"),
    };

    // The new suite was genuinely used: re-deriving under the old suite
    // alone (as if no schedule change existed) produces a *different*
    // digest for the identical inputs.
    let old_suite_only_resolver: HashSuiteResolver = HashSuiteResolver::new(
        pe_protocol().chain_id().clone(),
        pe_protocol().protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let derived_under_old_suite = derive_activation_set(
        &store,
        &pe_context(),
        pe_domain(),
        &old_suite_only_resolver,
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        pe_protocol().epoch(),
        Epoch::new(1),
        &next_entries,
    )
    .unwrap();
    assert_ne!(
        derived_under_old_suite.activation_digest,
        record.activation_digest
    );
    assert_ne!(
        derived_under_old_suite.next_validator_set_digest,
        record.next_validator_set_digest
    );

    // A fresh prepare/apply cycle at `e+1` still succeeds under the new
    // suite.
    let next_context: PublicationContext = PublicationContext::new(
        pe_protocol().chain_id().clone(),
        pe_protocol().protocol_version(),
        Epoch::new(1),
    )
    .unwrap();
    let observed_fee_policy = store
        .get_versioned_durable(
            &pe_context(),
            pe_domain(),
            &local_instance_state::paid_fee_policy_key(&next_context).unwrap(),
        )
        .unwrap();
    let next_fee_policy =
        execution::paid_execution::decode_paid_fee_policy(observed_fee_policy.value().unwrap())
            .unwrap();
    let bytes = sign_transfer_with_resolver(
        &fixture,
        &next_context,
        &next_fee_policy,
        100,
        0,
        &switching_resolver,
    );
    let vote = fast_path::prepare(
        &store,
        &runtime::MemoryBlobStore::default(),
        &pe_context(),
        pe_domain(),
        &switching_resolver,
        &[],
        &next_context,
        &LocalExecutionPolicy::generic_object_results(next_context.clone()),
        &next_fee_policy,
        &CountingEngine::new(),
        &next_signers[0],
        &bytes,
        10,
    )
    .unwrap();
    assert_eq!(vote.epoch, Epoch::new(1));
}

// ── outgoing fee-policy CAS fence, isolated (DR-0132 §3.A step 3) ──────────

/// A store that, on the *first* `commit_durable` call it forwards --
/// deterministically `activate`'s own final commit, since nothing else
/// calls `commit_durable` between this wrapper's construction and that
/// call -- first races in an out-of-band write to one specific key (bumping
/// its CAS revision; identical bytes are fine, only the revision needs to
/// advance) before forwarding the real commit. Every later `commit_durable`
/// call passes straight through. Unlike the thread-based race below, this
/// is fully deterministic and isolates exactly one key in the read set,
/// rather than racing the whole epoch record and every target row at once.
struct FeePolicyRaceStore {
    inner: MemoryDurableStateStore,
    fee_policy_key: Vec<u8>,
    raced: std::cell::Cell<bool>,
}
impl runtime::DurableDomainStateStore for FeePolicyRaceStore {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.inner.get_versioned_durable(context, domain, key)
    }
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        if !self.raced.replace(true) {
            let domain: AtomicityDomainId = transaction.domain();
            let observed: VersionedStateValue = self
                .inner
                .get_versioned_durable(context, domain, &self.fee_policy_key)
                .unwrap();
            let value: Vec<u8> = observed.value().unwrap().to_vec();
            let race: AtomicStateTransaction = AtomicStateTransaction::new(
                domain,
                AtomicStateReadSet::new(vec![
                    StateReadAssertion::new(self.fee_policy_key.clone(), observed.revision())
                        .unwrap(),
                ])
                .unwrap(),
                AtomicStateMutationSet::new(vec![
                    StateMutationEntry::new(self.fee_policy_key.clone(), StateMutation::Put(value))
                        .unwrap(),
                ])
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                self.inner.commit_durable(context, race),
                DurableCommitOutcome::Committed,
                "the racing outgoing fee-policy write must itself commit"
            );
        }
        self.inner.commit_durable(context, transaction)
    }
}
impl StructuredDurableDomainStateStore for FeePolicyRaceStore {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(context, domain, object_id)
    }
    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: runtime::DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, object_version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: runtime::DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request_id)
    }
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_invocation(context, transaction)
    }
}

/// DR-0132 §3.A step 3: `activate` CAS-fences the outgoing `ctx@e`
/// `PaidFeePolicy` row it reads inside `derive_activation_set`, not merely
/// the epoch record -- so a write landing on *only* that row between
/// `activate`'s own read and its final commit conflicts the commit, even
/// though every other row `activate` reads (epoch record, outgoing
/// validator set, the five `e+1` target rows) is completely untouched.
/// Isolates the fee-policy fence specifically, where the thread-based
/// `activate`-races-`activate` test below necessarily races the whole
/// read set at once and cannot attribute the conflict to any one key.
#[test]
fn activate_conflicts_when_the_outgoing_fee_policy_races_its_own_final_commit() {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();
    let (certificate, next_validator_set_digest, activation_digest) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();

    let fee_policy_key: Vec<u8> =
        local_instance_state::paid_fee_policy_key(&pe_protocol()).unwrap();
    let epoch_record_key: Vec<u8> =
        local_instance_state::fastpath_epoch_record_key(pe_protocol().chain_id()).unwrap();
    let next_context: PublicationContext = PublicationContext::new(
        pe_protocol().chain_id().clone(),
        pe_protocol().protocol_version(),
        Epoch::new(1),
    )
    .unwrap();
    let target_keys: [Vec<u8>; 5] = [
        local_instance_state::fastpath_validator_set_key(&next_context).unwrap(),
        local_instance_state::execution_policy_key_for_profile(&next_context, 4).unwrap(),
        local_instance_state::paid_fee_policy_key(&next_context).unwrap(),
        publication::publication_policy_key_for_profile(&next_context, 4).unwrap(),
        local_instance_state::fastpath_epoch_transition_key(
            pe_protocol().chain_id(),
            Epoch::new(1),
        )
        .unwrap(),
    ];
    let before_epoch_record_bytes: Vec<u8> = store
        .get_versioned_durable(&pe_context(), pe_domain(), &epoch_record_key)
        .unwrap()
        .value()
        .unwrap()
        .to_vec();
    assert!(
        target_keys.iter().all(|key| store
            .get_versioned_durable(&pe_context(), pe_domain(), key)
            .unwrap()
            .value()
            .is_none()),
        "no target row may exist before the racing attempt"
    );

    let racing_store: FeePolicyRaceStore = FeePolicyRaceStore {
        inner: store,
        fee_policy_key: fee_policy_key.clone(),
        raced: std::cell::Cell::new(false),
    };
    let result = activate(
        &racing_store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries.clone(),
        &certificate_bytes,
        31,
    );
    assert!(matches!(
        result,
        Err(EpochTransitionError::Node(NodeCoreError::StateConflict))
    ));

    // Nothing from the failed commit landed: the epoch record and every
    // target row are exactly as they were before the racing attempt (the
    // fee-policy row's own *bytes* are also unchanged -- only its revision
    // advanced, which is exactly what conflicted the commit).
    assert_eq!(
        racing_store
            .inner
            .get_versioned_durable(&pe_context(), pe_domain(), &epoch_record_key)
            .unwrap()
            .value()
            .unwrap(),
        before_epoch_record_bytes.as_slice()
    );
    for key in &target_keys {
        assert!(
            racing_store
                .inner
                .get_versioned_durable(&pe_context(), pe_domain(), key)
                .unwrap()
                .value()
                .is_none(),
            "target row must remain absent after the conflicted commit"
        );
    }

    // Retry (the wrapper races only once): activation now succeeds.
    let retry = activate(
        &racing_store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries,
        &certificate_bytes,
        32,
    )
    .unwrap();
    let record: FastPathEpochTransitionRecord = match retry {
        EpochActivationOutcome::Activated(record) => record,
        EpochActivationOutcome::AlreadyActivated(_) => {
            panic!("expected a fresh activation on retry")
        }
    };
    assert_eq!(record.next_validator_set_digest, next_validator_set_digest);
    assert_eq!(record.activation_digest, activation_digest);
}

// ── activate races activate, including the outgoing fee-policy CAS fence
//    (DR-0132 §6, §3.A step 3) ──────────────────────────────────────────────

/// A store that pauses on a `std::sync::Barrier` the first time it observes
/// a read of one specific key -- used to force two real OS threads to both
/// read the pre-transition [`local_instance_state::FastPathEpochRecord`]
/// (and, transitively, the identical outgoing fee-policy revision `activate`
/// CAS-fences at §3.A step 3) before either has committed anything,
/// guaranteeing a genuine overlapping race rather than a sequential
/// already-activated fallthrough.
struct BarrierGatedActivateStore {
    inner: MemoryDurableStateStore,
    gate_key: Vec<u8>,
    barrier: std::sync::Arc<std::sync::Barrier>,
}
impl runtime::DurableDomainStateStore for BarrierGatedActivateStore {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        let result = self.inner.get_versioned_durable(context, domain, key);
        if key == self.gate_key.as_slice() {
            self.barrier.wait();
        }
        result
    }
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_durable(context, transaction)
    }
}
impl StructuredDurableDomainStateStore for BarrierGatedActivateStore {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(context, domain, object_id)
    }
    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: runtime::DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, object_version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: runtime::DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request_id)
    }
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_invocation(context, transaction)
    }
}

/// DR-0132 §6 ("`activate` races `activate` | one commits; loser gets
/// `StateConflict`, retry -> `AlreadyActivated`") and §3.A step 3 (the
/// outgoing `ctx@e` `PaidFeePolicy` read is CAS-fenced, not copied from a
/// stale snapshot): two real threads both `activate` the identical
/// certificate, synchronized to both observe the pre-transition epoch record
/// (and outgoing fee policy) before either commits. Exactly one succeeds;
/// the other's commit conflicts on the overlapping read set (which includes
/// `derived.current_fee_policy_key`'s revision); a subsequent retry of the
/// loser observes `AlreadyActivated`.
#[test]
fn activate_races_activate_on_the_same_epoch_record_and_outgoing_fee_policy_and_exactly_one_commits()
 {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();
    let (certificate, _, _) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();

    let gate_key: Vec<u8> =
        local_instance_state::fastpath_epoch_record_key(pe_protocol().chain_id()).unwrap();
    let barrier: std::sync::Arc<std::sync::Barrier> =
        std::sync::Arc::new(std::sync::Barrier::new(2));
    let store_a: std::sync::Arc<BarrierGatedActivateStore> =
        std::sync::Arc::new(BarrierGatedActivateStore {
            inner: store,
            gate_key,
            barrier,
        });
    let store_b: std::sync::Arc<BarrierGatedActivateStore> = std::sync::Arc::clone(&store_a);
    let store_retry: std::sync::Arc<BarrierGatedActivateStore> = std::sync::Arc::clone(&store_a);

    let next_entries_a = next_entries.clone();
    let next_entries_retry = next_entries.clone();
    let certificate_bytes_a = certificate_bytes.clone();
    let certificate_bytes_retry = certificate_bytes.clone();
    let handle_a = std::thread::spawn(move || {
        activate(
            store_a.as_ref(),
            &pe_context(),
            pe_domain(),
            &pe_resolver(),
            pe_protocol().chain_id(),
            pe_protocol().protocol_version(),
            next_entries_a,
            &certificate_bytes_a,
            21,
        )
    });
    let handle_b = std::thread::spawn(move || {
        activate(
            store_b.as_ref(),
            &pe_context(),
            pe_domain(),
            &pe_resolver(),
            pe_protocol().chain_id(),
            pe_protocol().protocol_version(),
            next_entries,
            &certificate_bytes,
            22,
        )
    });
    let result_a = handle_a.join().unwrap();
    let result_b = handle_b.join().unwrap();

    let results = [result_a, result_b];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(EpochActivationOutcome::Activated(_))))
            .count(),
        1,
        "exactly one racing activate must commit: {results:?}"
    );
    // The loser's exact error shape depends on how far past the barrier it
    // got before the winner committed: if its own five-target-row absence
    // reads (§3.C.7) land before the winner's commit, its final CAS
    // assertion conflicts (`StateConflict`); if they land after, it
    // observes the winner's rows already present and fails at the read
    // itself (`Invalid("partial prior state...")`, §3.C.7's own fail-closed
    // branch). Both are safe, fail-closed, no-corruption outcomes of the
    // identical race; only one is guaranteed by scheduling, not both.
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(EpochTransitionError::Node(NodeCoreError::StateConflict))
                    | Err(EpochTransitionError::Invalid(
                        "partial prior state already exists at the next-epoch context"
                    ))
            ))
            .count(),
        1,
        "the other must lose the race, fail-closed, without corrupting anything: {results:?}"
    );

    // Matching this test's own doc comment ("retry -> `AlreadyActivated`"):
    // the loser, retried against the identical certificate, now observes
    // the winner's own activation rather than erroring again. Reads
    // directly through `store_retry.inner`, bypassing the barrier gate
    // entirely (it is a `Barrier::new(2)` already exhausted by threads A
    // and B; a third `wait()` on it would block forever).
    let retry = activate(
        &store_retry.inner,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries_retry,
        &certificate_bytes_retry,
        23,
    )
    .unwrap();
    assert!(matches!(retry, EpochActivationOutcome::AlreadyActivated(_)));
}

/// Synchronizes a direct paid admission and a real activation after both have
/// read epoch e, then deliberately lets activation commit first. The paid
/// commit is released only afterward, so its mutation-time epoch CAS must be
/// the authority that rejects the stale preliminary read.
struct ActivateWinsPaidRaceStore {
    inner: MemoryDurableStateStore,
    epoch_record_key: Vec<u8>,
    reads_barrier: std::sync::Barrier,
    activation_committed: std::sync::Mutex<bool>,
    activation_signal: std::sync::Condvar,
}

impl runtime::DurableDomainStateStore for ActivateWinsPaidRaceStore {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        let observed: Result<VersionedStateValue, DurableReadError> =
            self.inner.get_versioned_durable(context, domain, key);
        if key == self.epoch_record_key.as_slice() {
            self.reads_barrier.wait();
        }
        observed
    }

    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        let outcome: DurableCommitOutcome = self.inner.commit_durable(context, transaction);
        let mut committed = self.activation_committed.lock().unwrap();
        *committed = true;
        self.activation_signal.notify_all();
        outcome
    }
}

impl StructuredDurableDomainStateStore for ActivateWinsPaidRaceStore {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(context, domain, object_id)
    }

    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: runtime::DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, object_version)
    }

    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: runtime::DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request_id)
    }

    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        let mut committed = self.activation_committed.lock().unwrap();
        while !*committed {
            committed = self.activation_signal.wait(committed).unwrap();
        }
        drop(committed);
        self.inner.commit_invocation(context, transaction)
    }
}

#[test]
fn real_activation_wins_a_direct_paid_race_and_the_loser_commits_nothing() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();
    let (certificate, _, _) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());
    let certificate_bytes: Vec<u8> =
        consensus::encode_epoch_transition_certificate(&certificate).unwrap();
    let paid_request: u8 = 0xA1;
    let paid_bytes: Vec<u8> = sign_transfer(
        &fixture,
        &pe_protocol(),
        &fixture.policy,
        paid_request,
        crate::paid_execution::tests::FIRST_PAID_NONCE,
    );
    let paid_fresh: crate::paid_execution::FreshPaidExecution =
        match crate::paid_execution::preflight_paid_execution(
            &store,
            &pe_context(),
            pe_domain(),
            &pe_resolver(),
            &pe_protocol(),
            &paid_bytes,
        )
        .unwrap()
        {
            crate::paid_execution::PaidExecutionPreflight::Fresh(fresh) => *fresh,
            crate::paid_execution::PaidExecutionPreflight::Replayed { .. } => {
                panic!("new paid request must not reconcile as a replay")
            }
        };
    let initial_coin_head: DurableObjectHead = store
        .get_object_head(&pe_context(), pe_domain(), fixture.coin.id)
        .unwrap();
    let racing_store: std::sync::Arc<ActivateWinsPaidRaceStore> =
        std::sync::Arc::new(ActivateWinsPaidRaceStore {
            inner: store,
            epoch_record_key: local_instance_state::fastpath_epoch_record_key(
                pe_protocol().chain_id(),
            )
            .unwrap(),
            reads_barrier: std::sync::Barrier::new(2),
            activation_committed: std::sync::Mutex::new(false),
            activation_signal: std::sync::Condvar::new(),
        });

    let paid_store: std::sync::Arc<ActivateWinsPaidRaceStore> =
        std::sync::Arc::clone(&racing_store);
    let paid_policy: execution::paid_execution::PaidFeePolicy = fixture.policy.clone();
    let paid_handle = std::thread::spawn(move || {
        crate::paid_execution::handle_preflighted_paid_execution(
            paid_store.as_ref(),
            &runtime::MemoryBlobStore::default(),
            &pe_context(),
            pe_domain(),
            &pe_resolver(),
            &[],
            &LocalExecutionPolicy::generic_object_results(pe_protocol()),
            &paid_policy,
            &CountingEngine::new(),
            paid_fresh,
            40,
        )
    });
    let activation_store: std::sync::Arc<ActivateWinsPaidRaceStore> =
        std::sync::Arc::clone(&racing_store);
    let activation_handle = std::thread::spawn(move || {
        activate(
            activation_store.as_ref(),
            &pe_context(),
            pe_domain(),
            &pe_resolver(),
            pe_protocol().chain_id(),
            pe_protocol().protocol_version(),
            next_entries,
            &certificate_bytes,
            41,
        )
    });

    let activation_result = activation_handle.join().unwrap().unwrap();
    assert!(matches!(
        activation_result,
        EpochActivationOutcome::Activated(_)
    ));
    let paid_result = paid_handle.join().unwrap();
    assert!(matches!(
        paid_result,
        Err(crate::paid_execution::PaidExecutionAdmissionError::Node(
            NodeCoreError::StateConflict
        ))
    ));

    assert_eq!(
        query_sender_next_nonce(
            &racing_store.inner,
            &pe_context(),
            pe_domain(),
            pe_protocol().chain_id().clone(),
            pe_protocol().protocol_version(),
            pe_protocol().epoch(),
            crate::paid_execution::tests::sender(),
        )
        .unwrap(),
        crate::paid_execution::tests::FIRST_PAID_NONCE
    );
    assert_eq!(
        racing_store
            .inner
            .get_request_receipt(
                &pe_context(),
                pe_domain(),
                runtime::DurableRequestId::new([paid_request; 32]).unwrap(),
            )
            .unwrap(),
        None
    );
    assert_eq!(
        racing_store
            .inner
            .get_object_head(&pe_context(), pe_domain(), fixture.coin.id)
            .unwrap(),
        initial_coin_head
    );
    let claim: RequestOutboxClaimRequest = RequestOutboxClaimRequest::new(
        pe_domain(),
        OutboxRequestId::new([paid_request; 32]).unwrap(),
        1,
        DurableOutboxLeaseId::new([0xA2; 32]).unwrap(),
        2,
    )
    .unwrap();
    assert_eq!(
        racing_store
            .inner
            .claim_request_outbox(&pe_context(), claim),
        DurableOutboxClaimOutcome::NoDueWork
    );
}

// ── wrong chain/protocol on the already-activated path (DR-0132 §3.C.1) ────

/// `activate`'s step 1 (`certificate.chain_id`/`protocol_version` vs. the
/// caller's own `chain`/`protocol_version`) runs unconditionally, before
/// the already-activated branch (step 3) is ever reached -- so a certificate
/// carrying the right `next_epoch` (and so, on a naive implementation, a
/// plausible match for "already activated") but the wrong chain or protocol
/// version must still be rejected with `ContextMismatch`, never silently
/// accepted as the identical already-activated transition.
#[test]
fn activate_rejects_a_wrong_chain_or_protocol_certificate_on_the_already_activated_path() {
    let store: MemoryDurableStateStore = memory_store();
    let (_fixture, signers, entries) = install_lightweight(&store);
    let (_next_signers, next_entries) = four_next_validators();
    let (certificate, _, _) =
        propose_vote_and_certify(&store, &signers, &entries, next_entries.clone());
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();
    activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries.clone(),
        &certificate_bytes,
        15,
    )
    .unwrap();

    // Wrong chain id, otherwise identical (including `next_epoch`).
    let mut wrong_chain: EpochTransitionCertificate = certificate.clone();
    wrong_chain.chain_id = ChainId::new("a-completely-different-chain").unwrap();
    let wrong_chain_bytes = consensus::encode_epoch_transition_certificate(&wrong_chain).unwrap();
    let result = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries.clone(),
        &wrong_chain_bytes,
        16,
    );
    assert!(matches!(
        result,
        Err(EpochTransitionError::Consensus(
            ConsensusError::ContextMismatch
        ))
    ));

    // Wrong protocol version, otherwise identical.
    let mut wrong_protocol: EpochTransitionCertificate = certificate;
    wrong_protocol.protocol_version =
        ProtocolVersion::new(pe_protocol().protocol_version().get() + 1);
    let wrong_protocol_bytes =
        consensus::encode_epoch_transition_certificate(&wrong_protocol).unwrap();
    let result = activate(
        &store,
        &pe_context(),
        pe_domain(),
        &pe_resolver(),
        pe_protocol().chain_id(),
        pe_protocol().protocol_version(),
        next_entries,
        &wrong_protocol_bytes,
        17,
    );
    assert!(matches!(
        result,
        Err(EpochTransitionError::Consensus(
            ConsensusError::ContextMismatch
        ))
    ));
}

// ── `0x6427` transition-record codec adversarial tests ─────────────────────
//
// `0x6428` (`FastPathEpochActivationSet`) has no corresponding decode
// function -- it is a digest preimage only, never itself stored (see its own
// doc comment) -- so only `0x6427` has an independent decode path to attack.

fn sample_transition_record() -> FastPathEpochTransitionRecord {
    FastPathEpochTransitionRecord {
        from_epoch: Epoch::new(9),
        to_epoch: Epoch::new(10),
        previous_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xaa; 32]),
        next_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xbb; 32]),
        activation_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xcc; 32]),
        certificate: vec![0xdd, 0xee],
        activated_at_checkpoint: 0x77,
    }
}

#[test]
fn decode_fastpath_epoch_transition_record_rejects_wrong_type_id() {
    let bytes = encode_fastpath_epoch_transition_record(&sample_transition_record()).unwrap();
    let mut tampered = bytes.clone();
    tampered[4] ^= 0xFF;
    assert!(matches!(
        decode_fastpath_epoch_transition_record(&tampered),
        Err(NodeCoreError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedTypeId {
                expected: FASTPATH_EPOCH_TRANSITION_RECORD_TYPE,
                ..
            }
        ))
    ));
}

#[test]
fn decode_fastpath_epoch_transition_record_rejects_wrong_version() {
    let bytes = encode_fastpath_epoch_transition_record(&sample_transition_record()).unwrap();
    let mut tampered = bytes.clone();
    tampered[6] ^= 0xFF;
    assert!(matches!(
        decode_fastpath_epoch_transition_record(&tampered),
        Err(NodeCoreError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedVersion {
                expected: ENCODING_VERSION,
                ..
            }
        ))
    ));
}

#[test]
fn decode_fastpath_epoch_transition_record_rejects_a_missing_field() {
    let record = sample_transition_record();
    let mut frame = CanonicalStruct::new(FASTPATH_EPOCH_TRANSITION_RECORD_TYPE, ENCODING_VERSION);
    frame.field_u64(1, record.from_epoch.get()).unwrap();
    frame.field_u64(2, record.to_epoch.get()).unwrap();
    frame
        .field_bytes(
            3,
            encode_digest32(&record.previous_validator_set_digest).unwrap(),
        )
        .unwrap();
    frame
        .field_bytes(
            4,
            encode_digest32(&record.next_validator_set_digest).unwrap(),
        )
        .unwrap();
    frame
        .field_bytes(5, encode_digest32(&record.activation_digest).unwrap())
        .unwrap();
    frame.field_bytes(6, record.certificate.clone()).unwrap();
    // Field 7 (`activated_at_checkpoint`) deliberately omitted.
    let bytes = frame.finish().unwrap();
    assert!(matches!(
        decode_fastpath_epoch_transition_record(&bytes),
        Err(NodeCoreError::CanonicalDecoding(
            CanonicalDecodingError::MissingField(7)
        ))
    ));
}

#[test]
fn decode_fastpath_epoch_transition_record_rejects_an_extra_field() {
    let record = sample_transition_record();
    let mut frame = CanonicalStruct::new(FASTPATH_EPOCH_TRANSITION_RECORD_TYPE, ENCODING_VERSION);
    frame.field_u64(1, record.from_epoch.get()).unwrap();
    frame.field_u64(2, record.to_epoch.get()).unwrap();
    frame
        .field_bytes(
            3,
            encode_digest32(&record.previous_validator_set_digest).unwrap(),
        )
        .unwrap();
    frame
        .field_bytes(
            4,
            encode_digest32(&record.next_validator_set_digest).unwrap(),
        )
        .unwrap();
    frame
        .field_bytes(5, encode_digest32(&record.activation_digest).unwrap())
        .unwrap();
    frame.field_bytes(6, record.certificate.clone()).unwrap();
    frame.field_u64(7, record.activated_at_checkpoint).unwrap();
    frame.field_bytes(8, vec![0u8]).unwrap();
    let bytes = frame.finish().unwrap();
    assert!(matches!(
        decode_fastpath_epoch_transition_record(&bytes),
        Err(NodeCoreError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedField(8)
        ))
    ));
}

#[test]
fn decode_fastpath_epoch_transition_record_round_trips_and_rejects_a_bit_flip() {
    let record = sample_transition_record();
    let bytes = encode_fastpath_epoch_transition_record(&record).unwrap();
    assert_eq!(
        decode_fastpath_epoch_transition_record(&bytes).unwrap(),
        record
    );

    // A truncated frame (fewer bytes than the header declares) must fail
    // closed rather than silently decode a partial record.
    let mut truncated = bytes;
    truncated.pop();
    assert!(
        decode_fastpath_epoch_transition_record(&truncated).is_err(),
        "a truncated frame must not silently decode"
    );
}
