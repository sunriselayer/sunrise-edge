//! Genuine source-free terminal-Seal verification and SQLite activation.
//! This re-epochs the same eligible committee; ABCE replacement and shipped
//! host/CLI acceptance are distinct coverage, not claimed by these tests.

use super::*;
use crate::business_reconstruction::cut::{SavedBusinessCut, derive_source_business_cut};
use crate::business_reconstruction::inactive_import::verify_saved_business_import;
use crate::conditional_readiness::{
    ConditionalReadinessError, ReadinessSigningKey, retain_conditional_readiness,
};
use crate::serving_authority::{
    LiveAuthority, SuccessorActivationOutcome, SuccessorArtifactError, SuccessorArtifactSource,
    activate_successor, resolve_live_authority, verify_successor_authority,
};
use runtime::{BlobStore, SuccessorServingSlot};
use runtime_sqlite::SqliteImportTarget;

struct Artifacts<'a> {
    saved: &'a SavedBusinessCut,
    history: &'a [OrderedHistoryHeightMaterial],
    certificate: &'a [u8],
}

impl SuccessorArtifactSource for Artifacts<'_> {
    fn saved_business_cut(&mut self) -> Result<SavedBusinessCut, SuccessorArtifactError> {
        Ok(self.saved.clone())
    }
    fn history_height(
        &mut self,
        _identity: &OrderedHistoryIdentity,
        height: u64,
    ) -> Result<OrderedHistoryHeightMaterial, SuccessorArtifactError> {
        self.history
            .iter()
            .find(|item: &&OrderedHistoryHeightMaterial| item.descriptor.height == height)
            .cloned()
            .ok_or(SuccessorArtifactError::Missing)
    }
    fn readiness_certificate(&mut self, length: u32) -> Result<Vec<u8>, SuccessorArtifactError> {
        if self.certificate.len() != length as usize {
            return Err(SuccessorArtifactError::Malformed);
        }
        Ok(self.certificate.to_vec())
    }
}

#[test]
fn genuine_terminal_seal_activates_separate_sqlite_targets_and_reconciles_advanced_state() {
    let fixture: seal_signing::SealSigningFixture = seal_signing::seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let (cut_history, history_before) = complete_history(network);
    let cut = derive_source_business_cut(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &network.stores[0],
        &network.blobs,
        &history_before,
    )
    .unwrap();
    assert_eq!(cut.identity(), &fixture.cut_identity);
    let saved: SavedBusinessCut = preseal_cut::transfer(&cut, &network.resolver);
    let plan = verify_saved_business_import(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &saved,
    )
    .unwrap();
    let env_before: OrderedEconomicsEnvironment<'_> = seal_signing::env_with_seal(network);
    seal_acceptance::accept_genuine_seal(&fixture, &env_before);
    let (sealed_history, history) = complete_history(network);
    assert!(sealed_history.through_height > cut_history.through_height);
    let certificate: Vec<u8> = network
        .blobs
        .get_blob(&fixture.certificate_digest)
        .unwrap()
        .unwrap();
    let mut artifacts: Artifacts<'_> = Artifacts {
        saved: &saved,
        history: &history,
        certificate: &certificate,
    };
    let authority = verify_successor_authority(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &sealed_history,
        &mut artifacts,
    )
    .expect("genuinely accepted terminal Seal authenticates the successor");
    let mut corrupt_certificate: Vec<u8> = certificate.clone();
    let last: usize = corrupt_certificate.len() - 1;
    corrupt_certificate[last] ^= 1;
    let mut corrupt_artifacts: Artifacts<'_> = Artifacts {
        saved: &saved,
        history: &history,
        certificate: &corrupt_certificate,
    };
    assert!(
        matches!(
            verify_successor_authority(
                reconstruction_plan(&fixture.source.fixture, &cut_history),
                &sealed_history,
                &mut corrupt_artifacts,
            ),
            Err(crate::serving_authority::SuccessorActivationError::Invalid(
                "readiness certificate digest differs from the Seal"
            ))
        ),
        "certificate transport cannot substitute same-length bytes"
    );
    let next_context: PublicationContext = authority.policy_inputs().context().clone();
    let expected_subject: Digest32 = authority.subject_digest();
    let expected_manifest: Digest32 = authority.manifest_digest();
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_successor(&network.root, authority.policy_inputs()).unwrap();
    let next_base: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(next_context);
    let env_next: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy: &policy,
        history: &network.history,
        leg_policy: &next_base,
        engine: &network.engine,
        blobs: &network.blobs,
        seal: None,
    };
    let files: conditional_readiness::Files = conditional_readiness::Files::new();
    for index in 0..REPLICAS {
        let state = files.path(&format!("successor-state-{index}.db"));
        let body = files.path(&format!("successor-body-{index}.db"));
        let operation: DurableOperationContext = fixture::context(41);
        let namespace: SqliteNamespace = SqliteNamespace::new(
            fixture::chain(),
            network.signers[index].id,
            network.domain(),
        );
        let target: SqliteImportTarget = SqliteImportTarget::create(
            &state,
            namespace.clone(),
            operation.writer_fence(),
            plan.binding(),
        )
        .unwrap();
        let blobs: SqliteBlobStore = SqliteBlobStore::open(&body).unwrap();
        conditional_readiness::complete(&plan, &target, &blobs, &operation);
        let signer: ReadinessSigningKey =
            ReadinessSigningKey::new(network.signers[index].id, network.signers[index].key);
        if index == 0 {
            let wrong_key: ReadinessSigningKey =
                ReadinessSigningKey::new(signer.validator_id(), SigningKey::from([0xED; 32]));
            assert!(
                activate_successor(
                    reconstruction_plan(&fixture.source.fixture, &cut_history),
                    &sealed_history,
                    &mut artifacts,
                    &target,
                    &blobs,
                    &operation,
                    &wrong_key,
                    1,
                )
                .is_err()
            );
            assert_eq!(wrong_key.signatures_created(), 0);
            assert_eq!(
                target
                    .get_successor_serving(&operation, network.domain())
                    .unwrap(),
                SuccessorServingSlot::Inactive
            );
        }
        let activated = activate_successor(
            reconstruction_plan(&fixture.source.fixture, &cut_history),
            &sealed_history,
            &mut artifacts,
            &target,
            &blobs,
            &operation,
            &signer,
            1,
        )
        .expect("real complete import activates atomically");
        assert!(
            matches!(activated, SuccessorActivationOutcome::Activated { subject, manifest }
            if subject == expected_subject && manifest == expected_manifest)
        );
        assert_eq!(signer.signatures_created(), 0, "activation signs nothing");
        assert!(matches!(
            target
                .get_successor_serving(&operation, network.domain())
                .unwrap(),
            SuccessorServingSlot::Serving(_)
        ));
        let members: Vec<FastPathValidatorEntry> = network
            .signers
            .iter()
            .map(|member: &TestSigner| FastPathValidatorEntry {
                id: member.id,
                voting_power: 1,
                signature_scheme: protocol_types::SignatureSchemeId::Ed25519,
                public_key: VerificationKey::from(&member.key).as_ref().to_vec(),
            })
            .collect();
        assert!(matches!(
            retain_conditional_readiness(
                reconstruction_plan(&fixture.source.fixture, &cut_history),
                &saved,
                &target,
                &blobs,
                &operation,
                &members,
                &signer,
            ),
            Err(ConditionalReadinessError::UnsupportedSuccessorControl)
        ));
        assert_eq!(
            signer.signatures_created(),
            0,
            "Serving refuses readiness before signing"
        );
        let live = resolve_live_authority(
            &target,
            &operation,
            network.domain(),
            reconstruction_plan(&fixture.source.fixture, &cut_history),
            &sealed_history,
            &mut artifacts,
            signer.public_key(),
        )
        .unwrap();
        let warrant = match live {
            LiveAuthority::Successor(warrant) => *warrant,
            LiveAuthority::OriginalGenesis => panic!("import target is not an original namespace"),
        };
        let foreign_handle: SqliteImportTarget =
            SqliteImportTarget::open_existing(&state, namespace.clone(), plan.binding()).unwrap();
        assert!(
            process_tick_successor(
                &warrant,
                &foreign_handle,
                &env_next,
                20_001,
                &network.signers[index]
            )
            .is_err(),
            "a copied observation is not its warrant issuer"
        );
        process_tick_successor(
            &warrant,
            &target,
            &env_next,
            20_001,
            &network.signers[index],
        )
        .unwrap();
        drop(warrant);
        let advanced: OrderedStatus = query_status(&target, &operation, &env_next).unwrap();
        assert!(advanced.current_view > 1);
        assert!(matches!(
            activate_successor(
                reconstruction_plan(&fixture.source.fixture, &cut_history),
                &sealed_history,
                &mut artifacts,
                &target,
                &blobs,
                &operation,
                &signer,
                1,
            )
            .unwrap(),
            SuccessorActivationOutcome::AlreadyActivated { .. }
        ));
        assert_eq!(
            query_status(&target, &operation, &env_next).unwrap(),
            advanced
        );
        drop(foreign_handle);
        drop(target);
        let reopened_operation: DurableOperationContext = fixture::context(42);
        let reopened: SqliteImportTarget =
            SqliteImportTarget::open_existing(&state, namespace, plan.binding()).unwrap();
        reopened
            .advance_writer_fence(operation.writer_fence(), reopened_operation.writer_fence())
            .unwrap();
        assert!(matches!(
            activate_successor(
                reconstruction_plan(&fixture.source.fixture, &cut_history),
                &sealed_history,
                &mut artifacts,
                &reopened,
                &blobs,
                &reopened_operation,
                &signer,
                1,
            )
            .unwrap(),
            SuccessorActivationOutcome::AlreadyActivated { .. }
        ));
        assert_eq!(
            query_status(&reopened, &reopened_operation, &env_next).unwrap(),
            advanced
        );
        assert_eq!(signer.signatures_created(), 0);
    }
}

/// Four genuinely activated file-backed SQLite successor targets over one
/// genuinely accepted terminal Seal of the same eligible committee.
struct SuccessorWorld {
    fixture: seal_signing::SealSigningFixture,
    cut_history: OrderedHistoryIdentity,
    sealed_history: OrderedHistoryIdentity,
    saved: SavedBusinessCut,
    history: Vec<OrderedHistoryHeightMaterial>,
    certificate: Vec<u8>,
    policy: OrderedEconomicsPolicy,
    next_base: LocalExecutionPolicy,
    operation: DurableOperationContext,
    targets: Vec<(SqliteImportTarget, SqliteBlobStore)>,
    _files: conditional_readiness::Files,
}

fn activated_world() -> SuccessorWorld {
    let fixture: seal_signing::SealSigningFixture = seal_signing::seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let (cut_history, history_before) = complete_history(network);
    let cut = derive_source_business_cut(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &network.stores[0],
        &network.blobs,
        &history_before,
    )
    .unwrap();
    let saved: SavedBusinessCut = preseal_cut::transfer(&cut, &network.resolver);
    let plan = verify_saved_business_import(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &saved,
    )
    .unwrap();
    let env_before: OrderedEconomicsEnvironment<'_> = seal_signing::env_with_seal(network);
    seal_acceptance::accept_genuine_seal(&fixture, &env_before);
    let (sealed_history, history) = complete_history(network);
    let certificate: Vec<u8> = network
        .blobs
        .get_blob(&fixture.certificate_digest)
        .unwrap()
        .unwrap();
    let mut artifacts: Artifacts<'_> = Artifacts {
        saved: &saved,
        history: &history,
        certificate: &certificate,
    };
    let authority = verify_successor_authority(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &sealed_history,
        &mut artifacts,
    )
    .unwrap();
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_successor(&network.root, authority.policy_inputs()).unwrap();
    let next_base: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(authority.policy_inputs().context().clone());
    let files: conditional_readiness::Files = conditional_readiness::Files::new();
    let operation: DurableOperationContext = fixture::context(51);
    let mut targets: Vec<(SqliteImportTarget, SqliteBlobStore)> = Vec::new();
    for index in 0..REPLICAS {
        let namespace: SqliteNamespace = SqliteNamespace::new(
            fixture::chain(),
            network.signers[index].id,
            network.domain(),
        );
        let target: SqliteImportTarget = SqliteImportTarget::create(
            files.path(&format!("serving-state-{index}.db")),
            namespace,
            operation.writer_fence(),
            plan.binding(),
        )
        .unwrap();
        let blobs: SqliteBlobStore =
            SqliteBlobStore::open(files.path(&format!("serving-body-{index}.db"))).unwrap();
        conditional_readiness::complete(&plan, &target, &blobs, &operation);
        let signer: ReadinessSigningKey =
            ReadinessSigningKey::new(network.signers[index].id, network.signers[index].key);
        assert!(matches!(
            activate_successor(
                reconstruction_plan(&fixture.source.fixture, &cut_history),
                &sealed_history,
                &mut artifacts,
                &target,
                &blobs,
                &operation,
                &signer,
                1,
            )
            .unwrap(),
            SuccessorActivationOutcome::Activated { .. }
        ));
        targets.push((target, blobs));
    }
    SuccessorWorld {
        fixture,
        cut_history,
        sealed_history,
        saved,
        history,
        certificate,
        policy,
        next_base,
        operation,
        targets,
        _files: files,
    }
}

impl SuccessorWorld {
    fn network(&self) -> &Network {
        &self.fixture.source.fixture.network
    }

    fn artifacts(&self) -> Artifacts<'_> {
        Artifacts {
            saved: &self.saved,
            history: &self.history,
            certificate: &self.certificate,
        }
    }

    fn env(&self) -> OrderedEconomicsEnvironment<'_> {
        let network: &Network = self.network();
        OrderedEconomicsEnvironment {
            policy: &self.policy,
            history: &network.history,
            leg_policy: &self.next_base,
            engine: &network.engine,
            blobs: &network.blobs,
            seal: None,
        }
    }

    fn public_key(&self, index: usize) -> [u8; 32] {
        let network: &Network = self.network();
        ReadinessSigningKey::new(network.signers[index].id, network.signers[index].key).public_key()
    }

    fn resolve(
        &self,
        index: usize,
    ) -> Result<LiveAuthority<'_>, crate::serving_authority::ServingAuthorityError> {
        let mut artifacts: Artifacts<'_> = self.artifacts();
        resolve_live_authority(
            &self.targets[index].0,
            &self.operation,
            self.network().domain(),
            reconstruction_plan(&self.fixture.source.fixture, &self.cut_history),
            &self.sealed_history,
            &mut artifacts,
            self.public_key(index),
        )
    }

    /// A freshly resolved live warrant: the full evidence rerun and every
    /// destination comparison happen on each call.
    fn warrant(&self, index: usize) -> crate::serving_authority::LiveWarrant<'_> {
        match self.resolve(index).unwrap() {
            LiveAuthority::Successor(warrant) => *warrant,
            LiveAuthority::OriginalGenesis => panic!("an activated target is a successor"),
        }
    }

    fn reactivate(
        &self,
        index: usize,
    ) -> Result<SuccessorActivationOutcome, crate::serving_authority::SuccessorActivationError>
    {
        let network: &Network = self.network();
        let signer: ReadinessSigningKey =
            ReadinessSigningKey::new(network.signers[index].id, network.signers[index].key);
        let mut artifacts: Artifacts<'_> = self.artifacts();
        activate_successor(
            reconstruction_plan(&self.fixture.source.fixture, &self.cut_history),
            &self.sealed_history,
            &mut artifacts,
            &self.targets[index].0,
            &self.targets[index].1,
            &self.operation,
            &signer,
            1,
        )
    }

    fn value(&self, index: usize, key: &[u8]) -> (StateRevision, Option<Vec<u8>>) {
        let observed: VersionedStateValue = self.targets[index]
            .0
            .get_versioned_durable(&self.operation, self.network().domain(), key)
            .unwrap();
        (observed.revision(), observed.value().map(<[u8]>::to_vec))
    }
}

/// A genuine e+1 ordered round over four activated targets: the real leader
/// proposes, every member votes and the real quorum certificate is applied,
/// all through the shared engine under fresh warrants and protected ports.
/// Epoch-scoped safety rows advance; imported chain-only rows never move;
/// an exact proposal replay re-exposes the retained vote without a write;
/// a non-member signer and a foreign store handle are refused.
#[test]
fn successor_ordered_round_votes_and_certifies_through_protected_ports() {
    let world: SuccessorWorld = activated_world();
    let network: &Network = world.network();
    let env: OrderedEconomicsEnvironment<'_> = world.env();
    let chain: protocol_types::ChainId = fixture::chain();
    let imported_state: Vec<u8> = engine::ordered_state_key_for_tests(&chain);
    let imported_before: Vec<(StateRevision, Option<Vec<u8>>)> = (0..REPLICAS)
        .map(|index: usize| world.value(index, &imported_state))
        .collect();
    let status: OrderedStatus = crate::ordered_economics::query_status_successor(
        &world.warrant(0),
        &world.targets[0].0,
        &env,
    )
    .unwrap();
    let view: u64 = status.current_view;
    let leader_id: protocol_types::ValidatorId =
        world.policy.engine().validator_set().leader(view).unwrap();
    let leader: usize = network
        .signers
        .iter()
        .position(|signer: &TestSigner| signer.id == leader_id)
        .unwrap();
    let wrong_signer: usize = (leader + 1) % REPLICAS;
    assert!(
        crate::ordered_economics::propose_successor(
            &world.warrant(leader),
            &world.targets[leader].0,
            &env,
            None,
            &network.signers[wrong_signer],
        )
        .is_err(),
        "only the fresh physical namespace member may sign"
    );
    let proposal: OrderedProposal = crate::ordered_economics::propose_successor(
        &world.warrant(leader),
        &world.targets[leader].0,
        &env,
        None,
        &network.signers[leader],
    )
    .unwrap();
    assert_eq!(proposal.proposal.epoch, world.policy.context().epoch());
    let mut votes: Vec<consensus::ConsensusVote> = Vec::new();
    for index in 0..REPLICAS {
        let output: OrderedEventOutput = crate::ordered_economics::process_proposal_successor(
            &world.warrant(index),
            &world.targets[index].0,
            &env,
            &proposal,
            &network.signers[index],
        )
        .unwrap();
        let vote: consensus::ConsensusVote = output
            .messages
            .iter()
            .find_map(|message: &consensus::ConsensusMessage| match message {
                consensus::ConsensusMessage::Vote(vote) => Some(vote.clone()),
                _ => None,
            })
            .expect("every member votes on a safe successor proposal");
        votes.push(vote);
    }
    let vote_key: Vec<u8> = crate::ordered_economics::identity::scoped_vote_record_key(
        world.policy.key_scope(),
        &chain,
        view,
    )
    .unwrap();
    let retained: (StateRevision, Option<Vec<u8>>) = world.value(0, &vote_key);
    assert!(retained.1.is_some());
    let replay: OrderedEventOutput = crate::ordered_economics::process_proposal_successor(
        &world.warrant(0),
        &world.targets[0].0,
        &env,
        &proposal,
        &network.signers[0],
    )
    .unwrap();
    assert!(
        replay
            .messages
            .iter()
            .any(|message: &consensus::ConsensusMessage| {
                matches!(message, consensus::ConsensusMessage::Vote(vote) if *vote == votes[0])
            })
    );
    assert_eq!(
        world.value(0, &vote_key),
        retained,
        "exact replay writes nothing"
    );
    let certificate: consensus::QuorumCertificate = world
        .policy
        .engine()
        .certificate_from_votes(
            &proposal.proposal,
            &votes,
            &crate::ordered_economics::policy::Ed25519ConsensusVerifier,
        )
        .unwrap()
        .expect("four successor votes reach quorum");
    for (index, before) in imported_before.iter().enumerate() {
        crate::ordered_economics::process_certificate_successor(
            &world.warrant(index),
            &world.targets[index].0,
            &env,
            &certificate,
        )
        .unwrap();
        let status: OrderedStatus = crate::ordered_economics::query_status_successor(
            &world.warrant(index),
            &world.targets[index].0,
            &env,
        )
        .unwrap();
        assert_eq!(status.high_qc, certificate);
        assert_eq!(world.value(index, &imported_state), *before);
    }
}

/// A real protected-port write that changes the carried-forward e+1 fee
/// policy or the exact successor epoch record is refused by every later live
/// resolution and by reconciliation; an untouched replica is unaffected.
#[test]
fn successor_resolution_and_reconciliation_refuse_tampered_policy_and_epoch_rows() {
    let world: SuccessorWorld = activated_world();
    let domain: AtomicityDomainId = world.network().domain();
    let next: PublicationContext = world.policy.context().clone();
    let fee_key: Vec<u8> = crate::local_instance_state::paid_fee_policy_key(&next).unwrap();
    let epoch_key: Vec<u8> =
        crate::local_instance_state::fastpath_epoch_record_key(&fixture::chain()).unwrap();
    for (index, key) in [(0usize, fee_key), (1usize, epoch_key)] {
        let warrant: crate::serving_authority::LiveWarrant<'_> = world.warrant(index);
        let (revision, value): (StateRevision, Option<Vec<u8>>) = world.value(index, &key);
        let mut tampered: Vec<u8> = value.expect("verified successor row is installed");
        tampered.push(0);
        let transaction: runtime::AtomicStateTransaction = runtime::AtomicStateTransaction::new(
            domain,
            runtime::AtomicStateReadSet::new(vec![
                runtime::StateReadAssertion::new(key.clone(), revision).unwrap(),
            ])
            .unwrap(),
            runtime::AtomicStateMutationSet::new(vec![
                runtime::StateMutationEntry::new(
                    key.clone(),
                    runtime::StateMutation::Put(tampered),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            crate::serving_authority::ServingGate::Successor(&warrant).commit_durable(
                &world.targets[index].0,
                &world.operation,
                transaction,
            ),
            runtime::DurableCommitOutcome::Committed
        ));
        drop(warrant);
        assert!(
            world.resolve(index).is_err(),
            "tampered row refuses live authority"
        );
        assert!(
            world.reactivate(index).is_err(),
            "tampered row refuses reconciliation"
        );
    }
    assert!(matches!(
        world.resolve(2).unwrap(),
        LiveAuthority::Successor(_)
    ));
    assert!(matches!(
        world.reactivate(2).unwrap(),
        SuccessorActivationOutcome::AlreadyActivated { .. }
    ));
}

/// A genuinely signed e+1 paid `transfer` Call on the epoch-e Standard
/// Asset instance, consuming an imported coin.
fn successor_paid_transfer(
    world: &SuccessorWorld,
    signer_index: usize,
    coin: &Object,
    coin_digest: Digest32,
    request_id: [u8; 32],
    fee_policy: &PaidFeePolicy,
) -> Vec<u8> {
    let source: &CausalFixture = &world.fixture.source.fixture;
    let network: &Network = &source.network;
    let signer: &TestSigner = &network.signers[signer_index];
    let sender: [u8; 32] = *signer.id.as_bytes();
    let next: PublicationContext = world.policy.context().clone();
    let coin_ref: ObjectRef = ObjectRef {
        id: coin.id,
        version: coin.version,
        digest: coin_digest,
    };
    let call: CallIntent = CallIntent {
        context: next.clone(),
        request_id,
        sender,
        nonce: 0,
        code: source.instance.code.clone(),
        instance: instance_target(&network.resolver, &source.instance).unwrap(),
        entrypoint: "transfer".into(),
        type_arguments: fee_policy.type_arguments.clone(),
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: coin_ref.clone(),
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::transfer_arguments(&sender).unwrap(),
        gas_limit: 100_000,
    };
    let intent: PaidIntent = PaidIntent {
        context: next.clone(),
        request_id,
        sender,
        nonce: 0,
        fee_policy_digest: paid_fee_policy_digest(&network.resolver, fee_policy).unwrap(),
        consent: FeeSourceConsent {
            source: coin_ref,
            access: ReservationAccessKind::Write,
            max_fee: fees::Amount::new(1_000_000),
            refund_recipient: sender,
        },
        application: PaidApplication::Call(call),
        gas_limit: 100_000,
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = paid_intent_signing_frame(&next, &intent).unwrap();
    encode_signed_paid_intent(&SignedPaidIntent {
        signature: signer.key.sign(&frame).into(),
        intent,
    })
    .unwrap()
}

fn composition<'a>(
    world: &'a SuccessorWorld,
    index: usize,
    fee_policy: &'a PaidFeePolicy,
) -> crate::serving_authority::SuccessorFastVoteComposition<'a, LocalWasmExecutionEngine> {
    let network: &Network = world.network();
    crate::serving_authority::SuccessorFastVoteComposition {
        blob_store: &world.targets[index].1,
        resolver: &network.resolver,
        history: &network.history,
        base_policy: &world.next_base,
        fee_policy,
        engine: &network.engine,
    }
}

/// Genuine e+1 FastVote business: every successor member independently
/// executes and votes on a paid Call against the imported epoch-e instance,
/// retains the availability publication, and applies the certified result
/// through the protected port. The vote attests a generation strictly above
/// the verified cut floor; exact replay returns the original receipt; a
/// non-namespace signer is refused before any vote; the imported original
/// Seal receipt and the new receipt are exposed under fresh warrants.
#[test]
fn successor_fastvote_paid_call_on_imported_instance_applies_above_cut_floor() {
    let world: SuccessorWorld = activated_world();
    let network: &Network = world.network();
    let domain: AtomicityDomainId = network.domain();
    let next: PublicationContext = world.policy.context().clone();
    let fee_bytes: Vec<u8> = world
        .value(
            0,
            &crate::local_instance_state::paid_fee_policy_key(&next).unwrap(),
        )
        .1
        .unwrap();
    let fee_policy: PaidFeePolicy =
        execution::paid_execution::decode_paid_fee_policy(&fee_bytes).unwrap();
    assert_eq!(fee_policy.context, next);
    let coin_id: ObjectId = world.fixture.source.fixture.claimant_coin.id;
    let (version, digest): (DurableObjectVersion, Digest32) = match world.targets[0]
        .0
        .get_object_head(&world.operation, domain, coin_id)
        .unwrap()
    {
        DurableObjectHead::Current {
            object_version,
            digest,
            ..
        } => (object_version, digest),
        DurableObjectHead::Absent | DurableObjectHead::Tombstoned { .. } => {
            panic!("the imported claimant coin is live")
        }
    };
    let record: DurableObjectVersionRecord = world.targets[0]
        .0
        .get_object_version(&world.operation, domain, coin_id, version)
        .unwrap()
        .unwrap();
    let coin: Object = match record.payload() {
        DurableObjectPayload::Inline(inline) => {
            objects::decode_object(inline.canonical_bytes()).unwrap()
        }
        DurableObjectPayload::BlobReference(_) => panic!("standard asset coins are inline"),
    };
    let owner: [u8; 32] = match &coin.owner {
        Owner::Address(address) => *address.as_bytes(),
        _ => panic!("the claimant coin is address-owned"),
    };
    let sender: usize = network
        .signers
        .iter()
        .position(|signer: &TestSigner| *signer.id.as_bytes() == owner)
        .unwrap();
    let request_id: [u8; 32] = [0x6f; 32];
    let signed: Vec<u8> =
        successor_paid_transfer(&world, sender, &coin, digest, request_id, &fee_policy);
    assert!(
        crate::serving_authority::prepare_successor(
            &world.warrant(0),
            &world.targets[0].0,
            &composition(&world, 0, &fee_policy),
            &network.signers[1],
            &signed,
            1,
        )
        .is_err(),
        "a non-namespace consensus signer never votes"
    );
    let votes: Vec<consensus::FastVote> = (0..REPLICAS)
        .map(|index: usize| {
            crate::serving_authority::prepare_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &composition(&world, index, &fee_policy),
                &network.signers[index],
                &signed,
                1,
            )
            .unwrap()
        })
        .collect();
    let prepared: crate::fast_path::records::FastPathPreparedRecord =
        crate::fast_path::records::decode_fastpath_prepared_record(
            &world
                .value(
                    0,
                    &crate::local_instance_state::fastpath_prepared_record_key(
                        &fixture::chain(),
                        &request_id,
                    )
                    .unwrap(),
                )
                .1
                .unwrap(),
        )
        .unwrap();
    let floor: protocol_types::ExecutionGeneration =
        world.warrant(0).policy_inputs().generation_floor();
    assert!(prepared.prepared_generation.unwrap() > floor);
    let set: ValidatorSet = world.policy.engine().validator_set().clone();
    let certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        fixture::chain(),
        next.protocol_version(),
        next.epoch(),
        set.clone(),
    )
    .unwrap();
    let certificate: consensus::FastCertificate = certifier
        .try_form_certificate(
            votes[0].tx_hash,
            votes[0].execution_effects_hash,
            votes[0].locked_objects_digest,
            &votes,
            &crate::fast_path::FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    let bundle: PublicationBundle = crate::fast_path::publication::assemble_publication_bundle(
        &world.targets[0].0,
        &world.operation,
        domain,
        &network.resolver,
        &network.history,
        &next,
        &signed,
        &certificate_bytes,
    )
    .unwrap();
    let bundle_bytes: Vec<u8> = consensus::bundle::encode_publication_bundle(&bundle).unwrap();
    let acknowledgements: Vec<consensus::AvailabilityVote> = (0..REPLICAS)
        .map(|index: usize| {
            crate::serving_authority::retain_publication_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &network.resolver,
                &network.history,
                &bundle_bytes,
                &network.signers[index],
            )
            .unwrap()
        })
        .collect();
    let availability: consensus::AvailabilityCertificate = consensus::AvailabilityCertifier::new(
        fixture::chain(),
        next.protocol_version(),
        next.epoch(),
        set,
    )
    .unwrap()
    .try_form_certificate(
        &acknowledgements[0].identity,
        &acknowledgements,
        &crate::fast_path::FastPathEd25519Verifier,
    )
    .unwrap()
    .unwrap();
    let availability_bytes: Vec<u8> =
        consensus::encode_availability_certificate(&availability).unwrap();
    let mut outputs: Vec<NodeOutput> = Vec::new();
    for index in 0..REPLICAS {
        let output: NodeOutput = crate::serving_authority::apply_successor(
            &world.warrant(index),
            &world.targets[index].0,
            &composition(&world, index, &fee_policy),
            &signed,
            &certificate_bytes,
            Some(&availability_bytes),
            None,
        )
        .unwrap();
        assert_eq!(
            output.responses()[0].status(),
            crate::NodeResponseStatus::Accepted
        );
        outputs.push(output);
    }
    let head_after: (StateRevision, Option<Vec<u8>>) = world.value(
        0,
        &crate::local_instance_state::fastpath_prepared_record_key(&fixture::chain(), &request_id)
            .unwrap(),
    );
    let replay: NodeOutput = crate::serving_authority::apply_successor(
        &world.warrant(0),
        &world.targets[0].0,
        &composition(&world, 0, &fee_policy),
        &signed,
        &certificate_bytes,
        Some(&availability_bytes),
        None,
    )
    .unwrap();
    assert_eq!(
        replay, outputs[0],
        "exact replay returns the original receipt"
    );
    assert_eq!(
        world.value(
            0,
            &crate::local_instance_state::fastpath_prepared_record_key(
                &fixture::chain(),
                &request_id
            )
            .unwrap()
        ),
        head_after
    );
    for receipt in [request_id, world.fixture.candidate.request_id] {
        assert!(matches!(
            crate::serving_authority::query_request_receipt_successor(
                &world.warrant(1),
                &world.targets[1].0,
                crate::RequestId::new(receipt).unwrap(),
            )
            .unwrap(),
            crate::ReceiptQueryResult::Present { .. }
        ));
    }
}

/// The source-free verifier refuses every non-terminal, truncated, tampered
/// or incomplete variant of the genuine Seal-terminated artifacts.
#[test]
fn source_free_verifier_refuses_non_terminal_tampered_and_incomplete_artifacts() {
    let world: SuccessorWorld = activated_world();
    let source: &CausalFixture = &world.fixture.source.fixture;
    let seal_height: u64 = world.sealed_history.through_height;
    let verify = |identity: &OrderedHistoryIdentity,
                  history: &[OrderedHistoryHeightMaterial],
                  certificate: &[u8]| {
        let mut artifacts: Artifacts<'_> = Artifacts {
            saved: &world.saved,
            history,
            certificate,
        };
        verify_successor_authority(
            reconstruction_plan(source, &world.cut_history),
            identity,
            &mut artifacts,
        )
    };
    // The genuine artifacts verify.
    assert!(verify(&world.sealed_history, &world.history, &world.certificate).is_ok());
    // History ending at the cut is not a Seal-terminated extension.
    assert!(matches!(
        verify(&world.cut_history, &world.history, &world.certificate),
        Err(crate::serving_authority::SuccessorActivationError::Invalid(
            "manifest history is not a strict extension of the cut history"
        ))
    ));
    // The block before the Seal is not a terminal Seal height.
    let below: &OrderedHistoryHeightMaterial = world
        .history
        .iter()
        .find(|material: &&OrderedHistoryHeightMaterial| {
            material.descriptor.height == seal_height - 1
        })
        .unwrap();
    let non_terminal: OrderedHistoryIdentity = OrderedHistoryIdentity {
        through_height: seal_height - 1,
        through_view: below.descriptor.view,
        through_digest: below.descriptor.block_digest,
        ..world.sealed_history.clone()
    };
    let reidentified: Vec<OrderedHistoryHeightMaterial> = world
        .history
        .iter()
        .filter(|material: &&OrderedHistoryHeightMaterial| material.descriptor.height < seal_height)
        .map(|material: &OrderedHistoryHeightMaterial| {
            let mut copy: OrderedHistoryHeightMaterial = material.clone();
            copy.descriptor.identity = non_terminal.clone();
            copy
        })
        .collect();
    assert!(
        verify(&non_terminal, &reidentified, &world.certificate).is_err(),
        "the block before the Seal cannot terminate a successor history"
    );
    // A changed Seal component byte no longer matches its descriptor.
    let mut tampered: Vec<OrderedHistoryHeightMaterial> = world.history.clone();
    let terminal: &mut OrderedHistoryHeightMaterial = tampered
        .iter_mut()
        .find(|material: &&mut OrderedHistoryHeightMaterial| {
            material.descriptor.height == seal_height
        })
        .unwrap();
    let candidate: &mut (OrderedHistoryComponentKind, Vec<u8>) = terminal
        .components
        .iter_mut()
        .find(|(kind, _)| *kind == OrderedHistoryComponentKind::Candidate)
        .unwrap();
    let last: usize = candidate.1.len() - 1;
    candidate.1[last] ^= 1;
    assert!(verify(&world.sealed_history, &tampered, &world.certificate).is_err());
    // A missing empty suffix height stops; it is never skipped.
    let gapped: Vec<OrderedHistoryHeightMaterial> = world
        .history
        .iter()
        .filter(|material: &&OrderedHistoryHeightMaterial| {
            material.descriptor.height != seal_height - 1
        })
        .cloned()
        .collect();
    assert!(matches!(
        verify(&world.sealed_history, &gapped, &world.certificate),
        Err(
            crate::serving_authority::SuccessorActivationError::Artifact(
                SuccessorArtifactError::Missing
            )
        )
    ));
    // A certificate of another length is refused at transport.
    let short: &[u8] = &world.certificate[..world.certificate.len() - 1];
    assert!(matches!(
        verify(&world.sealed_history, &world.history, short),
        Err(
            crate::serving_authority::SuccessorActivationError::Artifact(
                SuccessorArtifactError::Malformed
            )
        )
    ));
}

/// One genuine e+1 ordered round on every activated target under fresh
/// warrants: the real leader proposes, every member votes, the real quorum
/// certificate is applied everywhere. Returns each replica's certificate
/// output and the certificate.
fn successor_round(
    world: &SuccessorWorld,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: Option<&OrderedCandidate>,
) -> (Vec<OrderedEventOutput>, consensus::QuorumCertificate) {
    let network: &Network = world.network();
    let view: u64 = crate::ordered_economics::query_status_successor(
        &world.warrant(0),
        &world.targets[0].0,
        env,
    )
    .unwrap()
    .current_view;
    let leader_id: protocol_types::ValidatorId =
        world.policy.engine().validator_set().leader(view).unwrap();
    let leader: usize = network
        .signers
        .iter()
        .position(|signer: &TestSigner| signer.id == leader_id)
        .unwrap();
    let proposal: OrderedProposal = crate::ordered_economics::propose_successor(
        &world.warrant(leader),
        &world.targets[leader].0,
        env,
        candidate,
        &network.signers[leader],
    )
    .unwrap();
    let votes: Vec<consensus::ConsensusVote> = (0..REPLICAS)
        .map(|index: usize| {
            crate::ordered_economics::process_proposal_successor(
                &world.warrant(index),
                &world.targets[index].0,
                env,
                &proposal,
                &network.signers[index],
            )
            .unwrap()
            .messages
            .into_iter()
            .find_map(|message: consensus::ConsensusMessage| match message {
                consensus::ConsensusMessage::Vote(vote) => Some(vote),
                _ => None,
            })
            .expect("every successor member votes on a safe proposal")
        })
        .collect();
    let certificate: consensus::QuorumCertificate = world
        .policy
        .engine()
        .certificate_from_votes(
            &proposal.proposal,
            &votes,
            &crate::ordered_economics::policy::Ed25519ConsensusVerifier,
        )
        .unwrap()
        .expect("four successor votes reach quorum");
    let outputs: Vec<OrderedEventOutput> = (0..REPLICAS)
        .map(|index: usize| {
            crate::ordered_economics::process_certificate_successor(
                &world.warrant(index),
                &world.targets[index].0,
                env,
                &certificate,
            )
            .unwrap()
        })
        .collect();
    (outputs, certificate)
}

/// The imported epoch-e settlement row of `escrow`, read from a target.
fn imported_settlement(
    world: &SuccessorWorld,
    index: usize,
    escrow: [u8; 32],
) -> FastPathSettlementRecord {
    let key: Vec<u8> =
        crate::local_instance_state::fastpath_settlement_key(&fixture::chain(), &escrow).unwrap();
    decode_fastpath_settlement_record(&world.value(index, &key).1.unwrap()).unwrap()
}

/// The claimant's own genuinely signed e+1 split leg over an imported escrow.
fn successor_split_leg(
    world: &SuccessorWorld,
    escrow: [u8; 32],
    request: [u8; 32],
    claimant: usize,
) -> Vec<u8> {
    let source: &CausalFixture = &world.fixture.source.fixture;
    let network: &Network = &source.network;
    let signer: &TestSigner = &network.signers[claimant];
    let next: PublicationContext = world.policy.context().clone();
    let settlement: FastPathSettlementRecord = imported_settlement(world, 0, escrow);
    let amount: u64 = settlement
        .shares
        .iter()
        .find(|share| share.validator_id == signer.id)
        .unwrap()
        .amount;
    let leg: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: world.next_base.digest(&network.resolver).unwrap(),
        call: CallIntent {
            context: next.clone(),
            request_id: request,
            sender: *signer.id.as_bytes(),
            nonce: 0,
            code: source.instance.code.clone(),
            instance: instance_target(&network.resolver, &source.instance).unwrap(),
            entrypoint: "split".into(),
            type_arguments: source.manifest.fee_policy.type_arguments.clone(),
            access: abi::AccessManifest {
                entries: vec![abi::AccessEntry {
                    object_ref: settlement.fee_output.clone().unwrap(),
                    mode: AccessMode::Write,
                }],
            },
            arguments: public_standard_asset::split_arguments(amount, signer.id.as_bytes())
                .unwrap(),
            gas_limit: 500_000,
        },
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = local_execution_signing_frame(&next, &leg).unwrap();
    encode_signed_local_execution(&SignedLocalExecutionIntent {
        signature: signer.key.sign(&frame).into(),
        intent: leg,
    })
    .unwrap()
}

/// Successor preparation plus the claimant's own claim signature, as an
/// ordered e+1 candidate. The claim binds its own certificate epoch.
fn successor_claim(
    world: &SuccessorWorld,
    escrow: [u8; 32],
    request: [u8; 32],
    claimant: usize,
) -> (OrderedCandidate, crate::fee_claims::PreparedFeeClaim) {
    let network: &Network = world.network();
    let signer: &TestSigner = &network.signers[claimant];
    let leg: Vec<u8> = successor_split_leg(world, escrow, request, claimant);
    let prepared: crate::fee_claims::PreparedFeeClaim =
        crate::serving_authority::prepare_fee_claim_successor(
            &world.warrant(0),
            &world.targets[0].0,
            &world.targets[0].1,
            &network.resolver,
            &network.history,
            &world.next_base,
            &network.engine,
            crate::fee_claims::FeeClaimPreparationRequest {
                escrow_request_id: escrow,
                request_id: request,
                validator_id: signer.id,
                claimant_public_key: *signer.id.as_bytes(),
                recipient: Address::new(*signer.id.as_bytes()),
                signed_leg: Some(&leg),
            },
            13,
        )
        .unwrap();
    let next: PublicationContext = world.policy.context().clone();
    let digest: Digest32 =
        crate::fee_claims::fee_claim_intent_digest(&network.resolver, &prepared.intent).unwrap();
    let frame: Vec<u8> = crate::fee_claims::fee_claim_signing_frame(&next, digest).unwrap();
    let signed: crate::fee_claims::codec::SignedFeeClaimIntent =
        crate::fee_claims::codec::SignedFeeClaimIntent {
            signature: signer.key.sign(&frame).into(),
            intent: prepared.intent.clone(),
        };
    (
        OrderedCandidate {
            context: next,
            request_id: request,
            kind: OrderedOperationKind::FeeClaim,
            intent: crate::fee_claims::codec::encode_signed_fee_claim_intent(&signed).unwrap(),
            created_checkpoint: 13,
        },
        prepared,
    )
}

/// DR-0189 Section 10: the genuine epoch-e drained paid escrow imported into
/// every target is claimed through the existing e+1 ordered handler with the
/// claimant's own claim and leg signatures bound to the certificate epoch e,
/// anchored by the verified outgoing committee. The settlement and payout
/// advance identically on every replica at a generation above the cut floor;
/// the completed claim is never re-placed; wrong scopes refuse.
#[test]
fn successor_ordered_claim_settles_imported_epoch_e_escrow_above_cut_floor() {
    let world: SuccessorWorld = activated_world();
    let env: OrderedEconomicsEnvironment<'_> = world.env();
    let network: &Network = world.network();
    let outgoing: Epoch = network.root.genesis_context().epoch();
    let claimant: usize = 1;
    let claim: [u8; 32] = [0xec; 32];
    let settlement_key: Vec<u8> =
        crate::local_instance_state::fastpath_settlement_key(&fixture::chain(), &PAID_REQUEST)
            .unwrap();
    let imported: FastPathSettlementRecord = imported_settlement(&world, 0, PAID_REQUEST);
    assert_eq!(imported.context.epoch(), outgoing);
    assert!(
        imported.fee_output.is_some(),
        "the drained escrow is charged"
    );

    // Preparation refuses a non-successor leg policy and a missing escrow.
    let leg: Vec<u8> = successor_split_leg(&world, PAID_REQUEST, claim, claimant);
    let request = |escrow: [u8; 32]| crate::fee_claims::FeeClaimPreparationRequest {
        escrow_request_id: escrow,
        request_id: claim,
        validator_id: network.signers[claimant].id,
        claimant_public_key: *network.signers[claimant].id.as_bytes(),
        recipient: Address::new(*network.signers[claimant].id.as_bytes()),
        signed_leg: Some(&leg),
    };
    assert!(
        crate::serving_authority::prepare_fee_claim_successor(
            &world.warrant(0),
            &world.targets[0].0,
            &world.targets[0].1,
            &network.resolver,
            &network.history,
            &network.leg_policy,
            &network.engine,
            request(PAID_REQUEST),
            13,
        )
        .is_err()
    );
    assert!(
        crate::serving_authority::prepare_fee_claim_successor(
            &world.warrant(0),
            &world.targets[0].0,
            &world.targets[0].1,
            &network.resolver,
            &network.history,
            &world.next_base,
            &network.engine,
            request([0x5c; 32]),
            13,
        )
        .is_err()
    );

    let (candidate, prepared): (OrderedCandidate, crate::fee_claims::PreparedFeeClaim) =
        successor_claim(&world, PAID_REQUEST, claim, claimant);
    assert_eq!(prepared.intent.certificate_epoch, outgoing);
    world.policy.authenticate_candidate(&candidate).unwrap();
    // Pure scope refusals: any certificate epoch other than the pinned e+1 or
    // the verified predecessor e, and any foreign replay context.
    let mut signed: crate::fee_claims::codec::SignedFeeClaimIntent =
        crate::fee_claims::codec::decode_signed_fee_claim_intent(&candidate.intent).unwrap();
    signed.intent.certificate_epoch = Epoch::new(outgoing.get().checked_add(2).unwrap());
    let mut wrong_epoch: OrderedCandidate = candidate.clone();
    wrong_epoch.intent = crate::fee_claims::codec::encode_signed_fee_claim_intent(&signed).unwrap();
    assert!(matches!(
        world.policy.authenticate_candidate(&wrong_epoch),
        Err(OrderedEconomicsError::Unauthenticated(_))
    ));
    let original: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&network.root, network.domain()).unwrap();
    assert!(matches!(
        original.authenticate_candidate(&candidate),
        Err(OrderedEconomicsError::Unauthenticated(_))
    ));

    let mut placed: Option<&OrderedCandidate> = Some(&candidate);
    let mut outcome: Option<OrderedOutcome> = None;
    for _ in 0..6 {
        let (outputs, _): (Vec<OrderedEventOutput>, consensus::QuorumCertificate) =
            successor_round(&world, &env, placed.take());
        if let Some(found) = outputs[0]
            .committed
            .iter()
            .find(|item: &&OrderedOutcome| item.request_id == claim)
        {
            outcome = Some(found.clone());
            break;
        }
    }
    let outcome: OrderedOutcome = outcome.expect("the imported escrow claim commits at e+1");
    assert_eq!(
        outcome.output.responses()[0].status(),
        crate::NodeResponseStatus::Accepted
    );
    for index in 0..REPLICAS {
        assert_eq!(
            imported_settlement(&world, index, PAID_REQUEST),
            prepared.next_settlement
        );
    }
    let profile: crate::logical_generation::LogicalProfileRecord =
        crate::logical_generation::decode_logical_profile_record(
            &world
                .value(
                    0,
                    &crate::logical_generation::logical_profile_key(&fixture::chain()).unwrap(),
                )
                .1
                .unwrap(),
        )
        .unwrap();
    // Settlement rows have their own authenticated history and are excluded
    // from generic logical subjects. The actual object and sender-nonce
    // changes must still carry provenance above the verified cut floor.
    assert!(crate::logical_generation::is_excluded_subject(
        &settlement_key
    ));
    let key_space: crate::logical_generation::LogicalKeySpace<'_> =
        crate::logical_generation::LogicalKeySpace::new(&profile, &network.resolver);
    let settlement_provenance: Vec<u8> = key_space
        .provenance_key(&crate::logical_generation::LogicalSubject::StateKey(
            settlement_key.clone(),
        ))
        .unwrap();
    assert!(world.value(0, &settlement_provenance).1.is_none());
    let payout: &objects::ObjectRef = prepared.expected_payout.as_ref().unwrap();
    let escrow: &objects::ObjectRef = prepared.next_settlement.fee_output.as_ref().unwrap();
    for subject in [
        crate::logical_generation::LogicalSubject::Object(payout.id),
        crate::logical_generation::LogicalSubject::Object(escrow.id),
        crate::logical_generation::LogicalSubject::SenderNonce {
            sender: *network.signers[claimant].id.as_bytes(),
            epoch: world.policy.context().epoch(),
        },
    ] {
        let provenance_key: Vec<u8> = key_space.provenance_key(&subject).unwrap();
        let expected: Vec<u8> = world.value(0, &provenance_key).1.unwrap();
        let provenance: crate::logical_generation::LogicalProvenanceRecord =
            crate::logical_generation::decode_logical_provenance_record(&expected).unwrap();
        assert_eq!(provenance.subject, subject);
        assert!(provenance.generation > world.warrant(0).policy_inputs().generation_floor());
        for index in 1..REPLICAS {
            assert_eq!(
                world.value(index, &provenance_key).1.as_deref(),
                Some(expected.as_slice())
            );
        }
    }

    // The completed original is answered, never re-placed or re-applied.
    let after: (StateRevision, Option<Vec<u8>>) = world.value(0, &settlement_key);
    let leader_id: protocol_types::ValidatorId = world
        .policy
        .engine()
        .validator_set()
        .leader(
            crate::ordered_economics::query_status_successor(
                &world.warrant(0),
                &world.targets[0].0,
                &env,
            )
            .unwrap()
            .current_view,
        )
        .unwrap();
    let leader: usize = network
        .signers
        .iter()
        .position(|signer: &TestSigner| signer.id == leader_id)
        .unwrap();
    assert!(matches!(
        crate::ordered_economics::propose_successor(
            &world.warrant(leader),
            &world.targets[leader].0,
            &env,
            Some(&candidate),
            &network.signers[leader],
        ),
        Err(OrderedEconomicsError::AlreadyCompleted(_))
    ));
    assert_eq!(world.value(0, &settlement_key), after);
}
