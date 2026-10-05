//! Real recurring SQLite handoffs through the installed withdrawal delay.
//! Every epoch and every live warrant comes from the original root and the
//! complete archive of genuinely accepted preceding Seals. This is core
//! acceptance coverage, separate from shipped host/CLI process acceptance.

use super::*;
use crate::business_reconstruction::{
    BusinessReconstructionPlan, SourceBusinessSnapshot, SourceSnapshotRecord,
};
use crate::serving_authority::{
    LiveWarrant, OwnerProvenance, ServingAuthorityError, SuccessorChainArtifacts,
    SuccessorChainBudget, SuccessorLinkPins, VerifiedSuccessorAuthority, activate_successor_chain,
    resolve_live_authority_chain, verify_successor_chain_authority,
};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::PathBuf;

/// The original per-link bytes, exported from that link's actual source.
/// No manifest, cut, root, activation row or receipt is synthesized here.
struct LinkArchive {
    pins: SuccessorLinkPins,
    saved: SavedBusinessCut,
    history: Vec<OrderedHistoryHeightMaterial>,
    certificate: Vec<u8>,
}

/// A bounded vector transport, rather than a special two-link adapter.
struct ArchiveTransport<'a> {
    links: &'a [LinkArchive],
    accessed: BTreeSet<u32>,
}

impl<'a> ArchiveTransport<'a> {
    fn new(links: &'a [LinkArchive]) -> Self {
        Self {
            links,
            accessed: BTreeSet::new(),
        }
    }

    fn link(&mut self, index: u32) -> Result<&'a LinkArchive, SuccessorArtifactError> {
        self.accessed.insert(index);
        self.links
            .get(usize::try_from(index).map_err(|_| SuccessorArtifactError::Missing)?)
            .ok_or(SuccessorArtifactError::Missing)
    }
}

impl SuccessorChainArtifacts for ArchiveTransport<'_> {
    fn saved_business_cut(
        &mut self,
        index: u32,
        _plan: &BusinessReconstructionPlan<'_>,
    ) -> Result<SavedBusinessCut, SuccessorArtifactError> {
        Ok(self.link(index)?.saved.clone())
    }

    fn history_height(
        &mut self,
        index: u32,
        _policy: &OrderedEconomicsPolicy,
        identity: &OrderedHistoryIdentity,
        height: u64,
    ) -> Result<OrderedHistoryHeightMaterial, SuccessorArtifactError> {
        let link: &LinkArchive = self.link(index)?;
        if identity != &link.pins.manifest_identity {
            return Err(SuccessorArtifactError::Malformed);
        }
        link.history
            .iter()
            .find(|item: &&OrderedHistoryHeightMaterial| item.descriptor.height == height)
            .cloned()
            .ok_or(SuccessorArtifactError::Missing)
    }

    fn readiness_certificate(
        &mut self,
        index: u32,
        length: u32,
    ) -> Result<Vec<u8>, SuccessorArtifactError> {
        let link: &LinkArchive = self.link(index)?;
        if link.certificate.len() != usize::try_from(length).unwrap() {
            return Err(SuccessorArtifactError::Malformed);
        }
        Ok(link.certificate.clone())
    }
}

/// Exactly the original root's lineage. The local budget is explicitly eight
/// links throughout; nothing checkpoints or resets it on the next handoff.
struct CompleteArchive {
    original_root: Digest32,
    links: Vec<LinkArchive>,
    pins: Vec<SuccessorLinkPins>,
}

impl CompleteArchive {
    fn budget() -> SuccessorChainBudget {
        SuccessorChainBudget::new(NonZeroU32::new(8).unwrap())
    }

    fn from_origin(origin: &SuccessorWorld) -> Self {
        let pins: SuccessorLinkPins = SuccessorLinkPins {
            cut_identity: origin.cut_history.clone(),
            manifest_identity: origin.sealed_history.clone(),
        };
        Self {
            original_root: origin.network().root.digest(),
            pins: vec![pins.clone()],
            links: vec![LinkArchive {
                pins,
                saved: origin.saved.clone(),
                history: origin.history.clone(),
                certificate: origin.certificate.clone(),
            }],
        }
    }

    fn append(&mut self, link: LinkArchive) {
        self.pins.push(link.pins.clone());
        self.links.push(link);
        assert_eq!(self.links.len(), self.pins.len());
    }

    fn verify(&self, origin: &SuccessorWorld) -> VerifiedSuccessorAuthority {
        assert_eq!(origin.network().root.digest(), self.original_root);
        let mut artifacts: ArchiveTransport<'_> = ArchiveTransport::new(&self.links);
        let authority: VerifiedSuccessorAuthority = verify_successor_chain_authority(
            reconstruction_plan(origin.source(), &origin.cut_history),
            &self.pins,
            Self::budget(),
            &mut artifacts,
        )
        .expect("every pinned link must verify through the owning complete-chain verifier");
        assert_eq!(
            usize::try_from(authority.link_count()).unwrap(),
            self.links.len()
        );
        let expected: BTreeSet<u32> = (0..authority.link_count()).collect();
        assert_eq!(artifacts.accessed, expected, "no earlier link is omitted");
        authority
    }

    fn resolve<'a>(
        &self,
        origin: &SuccessorWorld,
        hosts: &'a EpochHosts,
        index: usize,
    ) -> Result<LiveAuthority<'a>, ServingAuthorityError> {
        assert_eq!(origin.network().root.digest(), self.original_root);
        let mut artifacts: ArchiveTransport<'_> = ArchiveTransport::new(&self.links);
        resolve_live_authority_chain(
            &hosts.targets[index].0,
            &hosts.operation,
            origin.network().domain(),
            reconstruction_plan(origin.source(), &origin.cut_history),
            &self.pins,
            Self::budget(),
            &mut artifacts,
            hosts.public_key(origin, index),
        )
    }

    fn warrant<'a>(
        &self,
        origin: &SuccessorWorld,
        hosts: &'a EpochHosts,
        index: usize,
    ) -> LiveWarrant<'a> {
        match self.resolve(origin, hosts, index).unwrap() {
            LiveAuthority::Successor(warrant) => *warrant,
            LiveAuthority::OriginalGenesis => panic!("an imported epoch is a successor"),
        }
    }

    fn activate(
        &self,
        origin: &SuccessorWorld,
        hosts: &EpochHosts,
        index: usize,
    ) -> SuccessorActivationOutcome {
        let member: &TestSigner = &origin.members[index];
        let signer: ReadinessSigningKey = ReadinessSigningKey::new(member.id, member.key);
        let mut artifacts: ArchiveTransport<'_> = ArchiveTransport::new(&self.links);
        let outcome: SuccessorActivationOutcome = activate_successor_chain(
            reconstruction_plan(origin.source(), &origin.cut_history),
            &self.pins,
            Self::budget(),
            &mut artifacts,
            &hosts.targets[index].0,
            &hosts.targets[index].1,
            &hosts.operation,
            &signer,
            1,
        )
        .unwrap();
        assert_eq!(
            signer.signatures_created(),
            0,
            "activation creates no signature"
        );
        outcome
    }
}

/// Current committee members have independent state/body files. Old epochs
/// keep their files alive after Seal, so retirement and history are observable.
struct EpochHosts {
    policy: OrderedEconomicsPolicy,
    base: LocalExecutionPolicy,
    operation: DurableOperationContext,
    targets: Vec<(SqliteImportTarget, SqliteBlobStore)>,
    paths: Vec<(PathBuf, PathBuf)>,
    _files: Option<conditional_readiness::Files>,
}

impl EpochHosts {
    fn initial(origin: &SuccessorWorld, archive: &CompleteArchive) -> Self {
        let authority: VerifiedSuccessorAuthority = archive.verify(origin);
        let policy: OrderedEconomicsPolicy =
            authority.ordered_policy(&origin.network().root).unwrap();
        let paths: Vec<(PathBuf, PathBuf)> = (0..origin.members.len())
            .map(|index: usize| {
                (
                    origin._files.path(&format!("serving-{index}-state.db")),
                    origin._files.path(&format!("serving-{index}-body.db")),
                )
            })
            .collect();
        let targets: Vec<(SqliteImportTarget, SqliteBlobStore)> = paths
            .iter()
            .zip(&origin.members)
            .map(|((state, body), member)| {
                (
                    SqliteImportTarget::open_existing(
                        state,
                        SqliteNamespace::new(
                            fixture::chain(),
                            member.id,
                            origin.network().domain(),
                        ),
                        authority.import_binding(),
                    )
                    .unwrap(),
                    SqliteBlobStore::open(body).unwrap(),
                )
            })
            .collect();
        // G's genuine e1 registration helper executed against this actual
        // shared owner. Transfer its referenced closure explicitly before
        // later epochs use their independent SQLite body repositories.
        let source: SourceBusinessSnapshot = crate::test_support::capture::captured_source(
            &origin.targets[0].0,
            &origin.network().blobs,
            &origin.operation,
            origin.network().domain(),
        );
        for (_, blobs) in &targets {
            for (digest, body) in &source.referenced_blobs {
                blobs.put_blob(*digest, body.clone()).unwrap();
            }
        }
        let base: LocalExecutionPolicy =
            LocalExecutionPolicy::generic_object_results(policy.context().clone());
        Self {
            policy,
            base,
            operation: origin.operation,
            targets,
            paths,
            _files: None,
        }
    }

    fn env<'a>(&'a self, origin: &'a SuccessorWorld) -> OrderedEconomicsEnvironment<'a> {
        let network: &Network = origin.network();
        OrderedEconomicsEnvironment {
            policy: &self.policy,
            leg_policy: &self.base,
            history: &network.history,
            engine: &network.engine,
            blobs: &self.targets[0].1,
            seal: None,
        }
    }

    fn env_for_host<'a>(
        &'a self,
        template: &'a OrderedEconomicsEnvironment<'a>,
        index: usize,
    ) -> OrderedEconomicsEnvironment<'a> {
        OrderedEconomicsEnvironment {
            policy: template.policy,
            history: template.history,
            leg_policy: template.leg_policy,
            engine: template.engine,
            blobs: &self.targets[index].1,
            seal: template
                .seal
                .as_ref()
                .map(|seal: &OrderedSealComposition<'_>| OrderedSealComposition {
                    genesis_root: seal.genesis_root,
                    paid_base_policy: seal.paid_base_policy,
                    paid_engine: seal.paid_engine,
                    blobs: &self.targets[index].1,
                }),
        }
    }

    fn public_key(&self, origin: &SuccessorWorld, index: usize) -> [u8; 32] {
        let member: &TestSigner = &origin.members[index];
        ReadinessSigningKey::new(member.id, member.key).public_key()
    }

    fn value(
        &self,
        origin: &SuccessorWorld,
        index: usize,
        key: &[u8],
    ) -> (StateRevision, Option<Vec<u8>>) {
        let observed: VersionedStateValue = self.targets[index]
            .0
            .get_versioned_durable(&self.operation, origin.network().domain(), key)
            .unwrap();
        (observed.revision(), observed.value().map(<[u8]>::to_vec))
    }

    fn capture(&self, origin: &SuccessorWorld, index: usize) -> SourceBusinessSnapshot {
        crate::test_support::capture::captured_source(
            &self.targets[index].0,
            &self.targets[index].1,
            &self.operation,
            origin.network().domain(),
        )
    }

    fn bond(
        &self,
        origin: &SuccessorWorld,
        index: usize,
        owner: ValidatorId,
    ) -> (FastPathBondRecord, Vec<u8>) {
        let key: Vec<u8> = fastpath_bond_record_key(&fixture::chain(), &owner).unwrap();
        let bytes: Vec<u8> = self.value(origin, index, &key).1.unwrap();
        (decode_fastpath_bond_record(&bytes).unwrap(), bytes)
    }

    fn object(&self, origin: &SuccessorWorld, index: usize, id: ObjectId) -> Object {
        let store: &SqliteImportTarget = &self.targets[index].0;
        let head: DurableObjectHead = store
            .get_object_head(&self.operation, origin.network().domain(), id)
            .unwrap();
        let record: DurableObjectVersionRecord = store
            .get_object_version(
                &self.operation,
                origin.network().domain(),
                id,
                head.object_version().unwrap(),
            )
            .unwrap()
            .unwrap();
        match record.payload() {
            DurableObjectPayload::Inline(inline) => inline.object().clone(),
            DurableObjectPayload::BlobReference(_) => panic!("the genuine fixture coin is inline"),
        }
    }

    fn status(&self, origin: &SuccessorWorld, archive: &CompleteArchive) -> OrderedStatus {
        crate::ordered_economics::query_status_successor(
            &archive.warrant(origin, self, 0),
            &self.targets[0].0,
            &self.env(origin),
        )
        .unwrap()
    }

    /// The leader proposes, every member signs on its own actual file and
    /// a genuine E-required quorum forms its canonical minimal QC, which
    /// every replica applies. Each genuine per-replica warrant is held only
    /// for this round; each owner still checks runtime freshness, including
    /// the final Seal completion.
    fn round(
        &self,
        origin: &SuccessorWorld,
        archive: &CompleteArchive,
        env: &OrderedEconomicsEnvironment<'_>,
        candidate: Option<&OrderedCandidate>,
    ) -> (Vec<OrderedEventOutput>, consensus::QuorumCertificate) {
        // Resolve the complete immutable archive once per real replica in
        // this round, before status/proposal/vote/certificate processing.
        // These borrows never cross a round, epoch, reopen or writer-context
        // change. The archive and replica handles stay fixed here; every
        // actual handler still executes its unchanged issuer/freshness,
        // fence/Unsealed/signing and protected CAS checks. A final Seal QC
        // may retire its own store; no later live handler uses that warrant.
        let warrants: Vec<LiveWarrant<'_>> = (0..self.targets.len())
            .map(|index: usize| archive.warrant(origin, self, index))
            .collect();
        let status: OrderedStatus =
            crate::ordered_economics::query_status_successor(&warrants[0], &self.targets[0].0, env)
                .unwrap();
        let leader_id: ValidatorId = self
            .policy
            .engine()
            .validator_set()
            .leader(status.current_view)
            .unwrap();
        let leader: usize = origin
            .members
            .iter()
            .position(|member: &TestSigner| member.id == leader_id)
            .unwrap();
        let leader_env: OrderedEconomicsEnvironment<'_> = self.env_for_host(env, leader);
        let proposal: OrderedProposal = propose_successor(
            &warrants[leader],
            &self.targets[leader].0,
            &leader_env,
            candidate,
            &origin.members[leader],
        )
        .unwrap();
        let votes: Vec<consensus::ConsensusVote> = (0..self.targets.len())
            .map(|index: usize| {
                let local_env: OrderedEconomicsEnvironment<'_> = self.env_for_host(env, index);
                process_proposal_successor(
                    &warrants[index],
                    &self.targets[index].0,
                    &local_env,
                    &proposal,
                    &origin.members[index],
                )
                .unwrap()
                .messages
                .into_iter()
                .find_map(|message: consensus::ConsensusMessage| match message {
                    consensus::ConsensusMessage::Vote(vote) => Some(vote),
                    _ => None,
                })
                .expect("every current member votes on the genuine safe proposal")
            })
            .collect();
        let quorum_indices: Vec<usize> =
            quorum_member_indices(origin, self.policy.engine().validator_set());
        let quorum_votes: Vec<consensus::ConsensusVote> = quorum_indices
            .iter()
            .map(|index: &usize| votes[*index].clone())
            .collect();
        let certificate: consensus::QuorumCertificate = self
            .policy
            .engine()
            .certificate_from_votes(
                &proposal.proposal,
                &quorum_votes,
                &crate::ordered_economics::policy::Ed25519ConsensusVerifier,
            )
            .unwrap()
            .expect("the actual current committee reaches quorum");
        assert!(
            certificate
                .votes
                .iter()
                .any(|vote: &consensus::ConsensusVote| {
                    vote.validator == origin.members[quorum_indices[0]].id
                }),
            "the authentic canonical QC must include registered E's indispensable vote"
        );
        let outputs: Vec<OrderedEventOutput> = (0..self.targets.len())
            .map(|index: usize| {
                let local_env: OrderedEconomicsEnvironment<'_> = self.env_for_host(env, index);
                process_certificate_successor(
                    &warrants[index],
                    &self.targets[index].0,
                    &local_env,
                    &certificate,
                )
                .unwrap()
            })
            .collect();
        (outputs, certificate)
    }

    fn commit(
        &self,
        origin: &SuccessorWorld,
        archive: &CompleteArchive,
        env: &OrderedEconomicsEnvironment<'_>,
        candidate: &OrderedCandidate,
    ) -> (OrderedOutcome, consensus::QuorumCertificate) {
        let mut placed: Option<&OrderedCandidate> = Some(candidate);
        for _ in 0..6 {
            let (outputs, certificate): (Vec<OrderedEventOutput>, consensus::QuorumCertificate) =
                self.round(origin, archive, env, placed.take());
            if let Some(outcome) = outputs[0]
                .committed
                .iter()
                .find(|outcome: &&OrderedOutcome| outcome.request_id == candidate.request_id)
            {
                for output in &outputs {
                    assert!(
                        output
                            .committed
                            .iter()
                            .any(|other: &OrderedOutcome| other == outcome)
                    );
                }
                return (outcome.clone(), certificate);
            }
        }
        panic!("the real ordered candidate must commit within two economic windows")
    }

    /// Public bounded history owners serve the same fixed, independently
    /// verified prefix before and after Seal; history creates no live warrant.
    fn history(
        &self,
        origin: &SuccessorWorld,
    ) -> (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) {
        let env: OrderedEconomicsEnvironment<'_> = self.env(origin);
        let store: &SqliteImportTarget = &self.targets[0].0;
        let identity: OrderedHistoryIdentity =
            query_ordered_history_summary(store, &self.operation, &env)
                .unwrap()
                .identity;
        let mut verifier: OrderedHistoryVerifier =
            OrderedHistoryVerifier::new(self.policy.clone(), identity.clone()).unwrap();
        let mut history: Vec<OrderedHistoryHeightMaterial> = Vec::new();
        for height in 1..=identity.through_height {
            let descriptor: OrderedHistoryHeightDescriptor =
                read_ordered_history_height_descriptor(
                    store,
                    &self.operation,
                    &env,
                    &identity,
                    height,
                )
                .unwrap();
            let digest: Digest32 =
                ordered_history_descriptor_digest(&self.policy, &descriptor).unwrap();
            let mut components: Vec<(OrderedHistoryComponentKind, Vec<u8>)> = Vec::new();
            for reference in &descriptor.components {
                let mut bytes: Vec<u8> = Vec::new();
                let mut offset: u64 = 0;
                while offset < reference.length {
                    let limit: u32 =
                        u32::try_from(1024.min(reference.length.checked_sub(offset).unwrap()))
                            .unwrap();
                    let chunk: Vec<u8> = read_ordered_history_component_chunk(
                        store,
                        &self.operation,
                        &env,
                        &identity,
                        height,
                        digest,
                        reference.kind,
                        offset,
                        limit,
                    )
                    .unwrap();
                    assert_eq!(chunk.len(), usize::try_from(limit).unwrap());
                    offset = offset.checked_add(u64::from(limit)).unwrap();
                    bytes.extend(chunk);
                }
                components.push((reference.kind, bytes));
            }
            let material: OrderedHistoryHeightMaterial = OrderedHistoryHeightMaterial {
                descriptor,
                components,
            };
            verifier.verify_next_height(&material).unwrap();
            history.push(material);
        }
        assert_eq!(verifier.finish().unwrap().identity(), &identity);
        (identity, history)
    }
}

struct NoSignature<'a> {
    member: &'a TestSigner,
    count: Cell<usize>,
}

impl consensus::ConsensusSigner for NoSignature<'_> {
    fn validator_id(&self) -> ValidatorId {
        self.member.id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
        self.count.set(self.count.get().checked_add(1).unwrap());
        consensus::ConsensusSigner::sign_framed(self.member, frame)
    }
}

fn epoch_request(kind: u8, epoch: Epoch) -> [u8; 32] {
    let mut request: [u8; 32] = [0x5f; 32];
    // Every use is an Ordered envelope, including its embedded leg. The
    // owning causal profile requires that lane's high bit to be set.
    request[0] = kind | 0x80;
    request[8..16].copy_from_slice(&epoch.get().to_be_bytes());
    request
}

/// Fresh current-context registrations stop at Admit's verified owner gate.
/// D's actual custody object is sufficient: the owner gate precedes leg
/// execution, so this creates no new address-owned collateral for retired D.
#[allow(clippy::too_many_arguments)]
fn assert_historical_owner_registration_refused(
    origin: &SuccessorWorld,
    archive: &CompleteArchive,
    hosts: &EpochHosts,
    authority: &VerifiedSuccessorAuthority,
    owner: &ExitingOwner,
    source_id: ObjectId,
    request_kind: u8,
) {
    use super::successor_registration_reuse::{
        RegistrationAttempt, assert_owner_reuse_refused, registration_attempt,
    };
    let network: &Network = origin.network();
    let source: Object = hosts.object(origin, 0, source_id);
    let head: DurableObjectHead = hosts.targets[0]
        .0
        .get_object_head(&hosts.operation, network.domain(), source_id)
        .unwrap();
    let reference: ObjectRef = ObjectRef {
        id: source_id,
        version: source.version,
        digest: head.digest().unwrap(),
    };
    let authority_key: Vec<u8> = crate::local_instance_state::object_authority_key(source_id);
    let object_authority: execution::local_execution::ObjectAuthority =
        execution::local_execution::decode_object_authority(
            &hosts.value(origin, 0, &authority_key).1.unwrap(),
        )
        .unwrap();
    let nonce: u64 = crate::query_sender_next_nonce(
        &hosts.targets[0].0,
        &hosts.operation,
        network.domain(),
        hosts.policy.context().chain_id().clone(),
        hosts.policy.context().protocol_version(),
        hosts.policy.context().epoch(),
        *owner.signer.id.as_bytes(),
    )
    .unwrap();
    let checkpoint: u64 = hosts
        .status(origin, archive)
        .high_qc
        .height
        .checked_add(1)
        .unwrap();
    let attempt: RegistrationAttempt = registration_attempt(
        &network.root,
        authority,
        &network.resolver,
        &hosts.base,
        &owner.signer,
        source,
        reference,
        object_authority,
        epoch_request(request_kind, hosts.policy.context().epoch()),
        nonce,
        checkpoint,
    );
    assert_owner_reuse_refused(
        &network.root,
        authority,
        &attempt,
        &hosts.targets,
        &hosts.operation,
        &hosts.env(origin),
        checkpoint,
    );
}

#[test]
fn recurring_epoch_requests_use_the_external_ordered_lane() {
    use crate::admission_profile::{ExternalRequestLane, require_external_request_lane};
    let root: crate::genesis::VerifiedGenesisRoot = crate::serving_authority::tests::causal_root();
    for epoch in 1u64..=8 {
        for kind in [0x70u8, 0x71, 0x72, 0x73, 0x74] {
            let request: [u8; 32] = epoch_request(kind, Epoch::new(epoch));
            require_external_request_lane(
                root.admission_profile(),
                ExternalRequestLane::Ordered,
                &request,
            )
            .unwrap();
            assert!(
                require_external_request_lane(
                    root.admission_profile(),
                    ExternalRequestLane::Owned,
                    &request
                )
                .is_err()
            );
            assert!(!crate::local_instance_state::is_reserved_paid_request_id(
                &request
            ));
        }
    }
}

/// Select genuine current members without assuming every supplied vote is
/// retained by the canonical minimal certificate. E is identified from the
/// original certified ABCD -> ABCE committee, not an invented signer or row.
/// Its signature is indispensable because all selected other power remains
/// below the owning set's quorum threshold. Counts derive from current power,
/// so a five-member set does not inherit a hardcoded three-member quorum.
fn quorum_member_indices(origin: &SuccessorWorld, current: &ValidatorSet) -> Vec<usize> {
    let genesis: &ValidatorSet = origin.network().root.genesis_committee();
    let registered: Vec<ValidatorId> = origin
        .policy
        .engine()
        .validator_set()
        .validators()
        .iter()
        .filter(|member: &&validator_set::ValidatorInfo| genesis.get(member.id).is_none())
        .map(|member: &validator_set::ValidatorInfo| member.id)
        .collect();
    assert_eq!(
        registered.len(),
        1,
        "the original first handoff introduces E"
    );
    let e: ValidatorId = registered[0];
    let e_index: usize = origin
        .members
        .iter()
        .position(|member: &TestSigner| member.id == e)
        .unwrap();
    let e_power: u64 = current
        .get(e)
        .expect("E remains a current member")
        .voting_power;
    let required: u64 = current.quorum_threshold();
    let mut power: u64 = e_power;
    let mut selected: Vec<usize> = vec![e_index];
    for member in current.validators() {
        if power >= required {
            break;
        }
        if member.id == e {
            continue;
        }
        let index: usize = origin
            .members
            .iter()
            .position(|signer: &TestSigner| signer.id == member.id)
            .unwrap();
        selected.push(index);
        power = power.checked_add(member.voting_power).unwrap();
    }
    assert!(
        power >= required,
        "actual current members supply quorum power"
    );
    assert!(
        power.checked_sub(e_power).unwrap() < required,
        "selected quorum cannot form a certificate without E's real vote"
    );
    selected
}

fn current_entries(policy: &OrderedEconomicsPolicy) -> Vec<FastPathValidatorEntry> {
    policy
        .engine()
        .validator_set()
        .validators()
        .iter()
        .map(
            |entry: &validator_set::ValidatorInfo| FastPathValidatorEntry {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key.clone(),
            },
        )
        .collect()
}

/// Genuine current Freeze, an E-required current frontier quorum, current
/// DrainSet and EMPTY alignment. Earlier retained streams are not re-signed.
fn complete_preseal(origin: &SuccessorWorld, archive: &CompleteArchive, hosts: &EpochHosts) {
    let network: &Network = origin.network();
    let env: OrderedEconomicsEnvironment<'_> = hosts.env(origin);
    let current: PublicationContext = hosts.policy.context().clone();
    let next: PublicationContext = PublicationContext::new(
        current.chain_id().clone(),
        current.protocol_version(),
        Epoch::new(current.epoch().get().checked_add(1).unwrap()),
    )
    .unwrap();
    let freeze_request: [u8; 32] = epoch_request(0x70, current.epoch());
    let freeze: OrderedCandidate = OrderedCandidate {
        context: current.clone(),
        request_id: freeze_request,
        kind: OrderedOperationKind::Freeze,
        intent: encode_freeze_intent(&FreezeIntent {
            context: current.clone(),
            request_id: freeze_request,
            advisory_next_set: FastPathValidatorSetRecord {
                context: next,
                validators: current_entries(&hosts.policy),
            },
        })
        .unwrap(),
        created_checkpoint: hosts
            .status(origin, archive)
            .high_qc
            .height
            .checked_add(1)
            .unwrap(),
    };
    let (outcome, _): (OrderedOutcome, consensus::QuorumCertificate) =
        hosts.commit(origin, archive, &env, &freeze);
    assert_eq!(
        outcome.output.responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    // Batch only this local frontier/drain phase: the complete archive,
    // replica handles, live epoch and writer context remain unchanged.
    // Each warrant comes from the same genuine complete-chain resolver;
    // every step/page/union owner still checks freshness, issuer/fence,
    // Unsealed/signing prerequisites and protected CAS independently.
    // No Seal, activation, reopen or archive append occurs in this phase.
    let warrants: Vec<LiveWarrant<'_>> = (0..hosts.targets.len())
        .map(|index: usize| archive.warrant(origin, hosts, index))
        .collect();
    let mut selected: Vec<(FrozenFrontierVote, FrozenFrontierPage)> = Vec::new();
    let frontier_bound: u64 = archive
        .verify(origin)
        .import_binding()
        .row_count
        .checked_add(1)
        .unwrap();
    for index in quorum_member_indices(origin, hosts.policy.engine().validator_set()) {
        let counted: NoSignature<'_> = NoSignature {
            member: &origin.members[index],
            count: Cell::new(0),
        };
        let mut finalized: Option<Box<FrozenFrontierVote>> = None;
        // Every physical inherited publication consumes a bounded owner
        // step even though none enters this current epoch's frontier. The
        // verified import's complete row count bounds those publications;
        // one additional step permits genuine terminal finalization.
        for _ in 0..frontier_bound {
            let step: FrozenFrontierStep = advance_frozen_frontier_successor(
                &warrants[index],
                &hosts.targets[index].0,
                &hosts.operation,
                network.domain(),
                &network.resolver,
                &network.history,
                &current,
                &counted,
            )
            .unwrap();
            match step {
                FrozenFrontierStep::Advanced { entry_count } => {
                    assert_eq!(entry_count, 0, "earlier publications are history only");
                    assert_eq!(counted.count.get(), 0, "partial progress never signs");
                }
                FrozenFrontierStep::Finalized(vote) => {
                    assert_eq!(vote.identity.entry_count, 0);
                    assert_eq!(counted.count.get(), 1, "only the complete frontier signs");
                    finalized = Some(vote);
                    break;
                }
            }
        }
        let finalized: Box<FrozenFrontierVote> = finalized
            .expect("the genuine historical-only scan completes within its verified bound");
        let before: SourceBusinessSnapshot = hosts.capture(origin, index);
        let replay: FrozenFrontierStep = advance_frozen_frontier_successor(
            &warrants[index],
            &hosts.targets[index].0,
            &hosts.operation,
            network.domain(),
            &network.resolver,
            &network.history,
            &current,
            &counted,
        )
        .unwrap();
        assert_eq!(replay, FrozenFrontierStep::Finalized(finalized.clone()));
        assert_eq!(
            counted.count.get(),
            1,
            "retained completion creates no signature"
        );
        assert_eq!(hosts.capture(origin, index), before);
        let pair: (FrozenFrontierVote, FrozenFrontierPage) = read_frozen_frontier_page_successor(
            &warrants[index],
            &hosts.targets[index].0,
            &hosts.operation,
            network.domain(),
            &network.resolver,
            &network.history,
            &current,
            origin.members[index].id,
            None,
            NonZeroUsize::MIN,
        )
        .unwrap();
        assert_eq!(&pair.0, finalized.as_ref());
        assert_eq!(pair.0.identity.epoch, current.epoch());
        assert_eq!(&pair.0.identity.chain_id, current.chain_id());
        assert!(pair.1.terminal && pair.1.entries.is_empty());
        selected.push(pair);
    }
    selected.sort_by_key(|(vote, _)| vote.validator);
    let votes: Vec<FrozenFrontierVote> = selected.iter().map(|(vote, _)| vote.clone()).collect();
    let mut union: Option<DrainUnionIdentity> = None;
    for (index, warrant) in warrants.iter().enumerate() {
        for (vote, page) in &selected {
            ingest_drain_signer_page_successor(
                warrant,
                &hosts.targets[index].0,
                &hosts.operation,
                network.domain(),
                &network.resolver,
                &current,
                vote.validator,
                vote.clone(),
                page.clone(),
            )
            .unwrap();
        }
        let step: DrainUnionStep = advance_drain_union_successor(
            warrant,
            &hosts.targets[index].0,
            &hosts.operation,
            network.domain(),
            &network.resolver,
            &network.history,
            &current,
            &votes,
        )
        .unwrap();
        let DrainUnionStep::Ready(identity) = step else {
            panic!("the actual empty union must complete")
        };
        assert_eq!(identity.member_count, 0);
        if let Some(expected) = &union {
            assert_eq!(identity.as_ref(), expected);
        } else {
            union = Some(*identity);
        }
    }
    // End this batch before the separately resolved ordered DrainSet rounds.
    // Nothing is cached for a later phase, Seal, epoch or writer context.
    drop(warrants);
    let drain_request: [u8; 32] = epoch_request(0x71, current.epoch());
    let drain: OrderedCandidate = OrderedCandidate {
        context: current.clone(),
        request_id: drain_request,
        kind: OrderedOperationKind::DrainSet,
        intent: encode_drain_set_intent(&DrainSetIntent {
            context: current,
            request_id: drain_request,
            selected_votes: votes,
            drain_union_identity: union.unwrap(),
        })
        .unwrap(),
        created_checkpoint: hosts
            .status(origin, archive)
            .high_qc
            .height
            .checked_add(1)
            .unwrap(),
    };
    let (outcome, _): (OrderedOutcome, consensus::QuorumCertificate) =
        hosts.commit(origin, archive, &env, &drain);
    assert_eq!(
        outcome.output.responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    for _ in 0..3 {
        hosts.round(origin, archive, &env, None);
    }
}

type ReceiptJournal = BTreeMap<[u8; 32], (Digest32, Vec<u8>)>;

/// Keep every external original and successor receipt. Only owner-classified
/// local admission receipts, already validated/excluded by the genuine cut
/// producer, are not cross-import carriers. Full physical captures keep them.
fn remember_all_receipts(
    origin: &SuccessorWorld,
    hosts: &EpochHosts,
    receipts: &mut ReceiptJournal,
) {
    let snapshot: SourceBusinessSnapshot = hosts.capture(origin, 0);
    for row in &snapshot.records {
        let runtime::portable::DurableRecordKey::Receipt(id) = row.descriptor.key() else {
            continue;
        };
        let receipt: DurableRequestReceipt = hosts.targets[0]
            .0
            .read_request_receipt(&hosts.operation, origin.network().domain(), *id)
            .unwrap()
            .unwrap();
        let request: [u8; 32] = *id.as_bytes();
        if crate::local_instance_state::is_reserved_paid_request_id(&request) {
            let internal: crate::NodeDedupRecord =
                crate::NodeDedupRecord::decode(receipt.canonical_bytes()).unwrap();
            assert!(
                internal.responses().is_empty(),
                "internal admission receipt has no business outcome"
            );
            continue;
        }
        let value: (Digest32, Vec<u8>) =
            (receipt.event_digest(), receipt.canonical_bytes().to_vec());
        if let Some(old) = receipts.insert(request, value.clone()) {
            assert_eq!(old, value, "an existing receipt is never rewritten");
        }
    }
}

fn assert_receipts(origin: &SuccessorWorld, hosts: &EpochHosts, receipts: &ReceiptJournal) {
    for (index, (store, _)) in hosts.targets.iter().enumerate() {
        for (request, (event, canonical)) in receipts {
            let receipt: DurableRequestReceipt = store
                .read_request_receipt(
                    &hosts.operation,
                    origin.network().domain(),
                    DurableRequestId::new(*request).unwrap(),
                )
                .unwrap()
                .expect("every earlier receipt must survive the genuine next import");
            assert_eq!(&receipt.event_digest(), event);
            assert_eq!(receipt.canonical_bytes(), canonical.as_slice());
            let query: crate::ReceiptQueryResult = crate::query_request_receipt(
                store,
                &hosts.operation,
                origin.network().domain(),
                crate::RequestId::new(*request).unwrap(),
            )
            .unwrap();
            let crate::ReceiptQueryResult::Present {
                record,
                event_digest,
                ..
            } = query
            else {
                panic!("the historical receipt reader must reverify member {index}'s receipt")
            };
            assert_eq!(&event_digest, event);
            assert_eq!(record.encode().unwrap(), *canonical);
        }
    }
}

/// Close the actual current namespace through the same Seal owner, archive
/// its terminal history, verify the complete lineage and activate fresh files.
fn handoff(
    origin: &SuccessorWorld,
    archive: &mut CompleteArchive,
    current: &EpochHosts,
    receipts: &mut ReceiptJournal,
) -> EpochHosts {
    complete_preseal(origin, archive, current);
    let network: &Network = origin.network();
    let prior: VerifiedSuccessorAuthority = archive.verify(origin);
    assert_eq!(prior.policy_inputs().context(), current.policy.context());
    let (cut_identity, ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        current.history(origin);
    let mut plan: BusinessReconstructionPlan<'_> =
        reconstruction_plan(origin.source(), &origin.cut_history);
    plan.operation_context = current.operation;
    plan.ordered_history_identity = &cut_identity;
    let cut: crate::business_reconstruction::cut::VerifiedBusinessCut =
        crate::business_reconstruction::cut::derive_successor_source_business_cut(
            plan,
            &archive.warrant(origin, current, 0),
            &current.targets[0].0,
            &current.targets[0].1,
            &ordered,
        )
        .unwrap();
    assert_eq!(&cut.identity().ordered_history, &cut_identity);
    let saved: SavedBusinessCut = preseal_cut::transfer(&cut, &network.resolver);
    let import: VerifiedImportPlan =
        crate::business_reconstruction::inactive_import::verify_saved_business_import_chain(
            reconstruction_plan(origin.source(), &origin.cut_history),
            &prior,
            &cut_identity,
            &saved,
        )
        .unwrap();
    let files: conditional_readiness::Files = conditional_readiness::Files::new();
    let operation: DurableOperationContext = fixture::context(
        current
            .operation
            .writer_fence()
            .get()
            .checked_add(10)
            .unwrap(),
    );
    let targets: Vec<(SqliteImportTarget, SqliteBlobStore)> = member_imports(
        &import,
        network.domain(),
        &origin.members,
        &files,
        &operation,
    );
    let entries: Vec<FastPathValidatorEntry> = current_entries(&current.policy);
    let votes: Vec<ReadinessVote> = targets
        .iter()
        .zip(&origin.members)
        .map(|((target, blobs), member)| {
            let signer: ReadinessSigningKey = ReadinessSigningKey::new(member.id, member.key);
            let vote: ReadinessVote =
                crate::conditional_readiness::retain_conditional_readiness_chain(
                    reconstruction_plan(origin.source(), &origin.cut_history),
                    &prior,
                    &cut_identity,
                    &saved,
                    target,
                    blobs,
                    &operation,
                    &entries,
                    &signer,
                )
                .unwrap();
            assert_eq!(signer.signatures_created(), 1);
            let before: SourceBusinessSnapshot = crate::test_support::capture::captured_source(
                target,
                blobs,
                &operation,
                network.domain(),
            );
            let replay: ReadinessVote =
                crate::conditional_readiness::retain_conditional_readiness_chain(
                    reconstruction_plan(origin.source(), &origin.cut_history),
                    &prior,
                    &cut_identity,
                    &saved,
                    target,
                    blobs,
                    &operation,
                    &entries,
                    &signer,
                )
                .unwrap();
            assert_eq!(replay, vote);
            assert_eq!(signer.signatures_created(), 1);
            assert_eq!(
                crate::test_support::capture::captured_source(
                    target,
                    blobs,
                    &operation,
                    network.domain()
                ),
                before
            );
            assert_eq!(vote.signer, member.id);
            vote
        })
        .collect();
    let subject: ReadinessSubject = votes[0].subject.clone();
    assert_eq!(subject.epoch, current.policy.context().epoch());
    let next_set: ValidatorSet = ValidatorSet::new(
        subject.next_epoch,
        prior.validator_set().validators().to_vec(),
    )
    .unwrap();
    let quorum_indices: Vec<usize> = quorum_member_indices(origin, &next_set);
    let quorum_votes: Vec<ReadinessVote> = quorum_indices
        .iter()
        .map(|index: &usize| votes[*index].clone())
        .collect();
    let (certificate_digest, certificate_length): (Digest32, u32) =
        seal_signing::stage_votes(network, &subject, &next_set, &quorum_votes);
    let certificate: Vec<u8> = network
        .blobs
        .get_blob(&certificate_digest)
        .unwrap()
        .unwrap();
    let readiness: consensus::readiness::ReadinessCertificate =
        consensus::readiness::decode_readiness_certificate(&certificate).unwrap();
    assert!(
        readiness
            .votes
            .iter()
            .any(|vote: &ReadinessVote| { vote.signer == origin.members[quorum_indices[0]].id }),
        "the genuine readiness certificate includes E's indispensable signature"
    );
    // Retain the same genuine published body in each independent source and
    // target body store. This stores artifact bytes only, never an effect,
    // state root, receipt, activation record or capability.
    for (_, blobs) in current.targets.iter().chain(&targets) {
        blobs
            .put_blob(certificate_digest, certificate.clone())
            .unwrap();
    }
    let target: Digest32 = seal_target_digest(
        &network.resolver,
        current.policy.context(),
        subject.identity(&network.resolver).unwrap(),
        SEAL_PREDECESSOR_TAG_SUCCESSOR,
        prior.subject_digest(),
    )
    .unwrap();
    let request_id: [u8; 32] = seal_request_id(
        &network.resolver,
        current.policy.context(),
        target,
        certificate_digest,
    )
    .unwrap();
    let seal: OrderedCandidate = OrderedCandidate {
        context: current.policy.context().clone(),
        request_id,
        kind: OrderedOperationKind::Seal,
        created_checkpoint: cut_identity.through_height,
        intent: encode_seal_intent(&SealIntent {
            readiness_subject: subject,
            cut_identity_bytes: crate::business_reconstruction::cut::encode_business_cut_identity(
                cut.identity(),
            )
            .unwrap(),
            predecessor_tag: SEAL_PREDECESSOR_TAG_SUCCESSOR,
            predecessor_digest: prior.subject_digest(),
            certificate_digest,
            certificate_length,
        })
        .unwrap(),
    };
    let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        seal: Some(OrderedSealComposition {
            genesis_root: &network.root,
            paid_base_policy: &current.base,
            paid_engine: &network.engine,
            blobs: &current.targets[0].1,
        }),
        ..current.env(origin)
    };
    {
        // Retain a genuinely live warrant before completion solely to prove
        // the actual owner rejects later live control after terminal retirement.
        let old_warrant: LiveWarrant<'_> = archive.warrant(origin, current, 0);
        let (outcome, terminal_qc): (OrderedOutcome, consensus::QuorumCertificate) =
            current.commit(origin, archive, &env, &seal);
        assert_eq!(
            outcome.output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        for index in 0..current.targets.len() {
            assert!(archive.resolve(origin, current, index).is_err());
            let barrier: runtime::OutgoingBarrier = current.targets[index]
                .0
                .get_outgoing_barrier(&current.operation, network.domain())
                .unwrap();
            let runtime::OutgoingBarrier::Sealed(sealed) = barrier else {
                panic!("real Seal installs the permanent barrier")
            };
            assert_eq!(sealed.outgoing_epoch, current.policy.context().epoch());
            assert_eq!(sealed.request, request_id);
        }
        let before: SourceBusinessSnapshot = current.capture(origin, 0);
        let replay: Result<OrderedEventOutput, OrderedEconomicsError> =
            process_certificate_successor(&old_warrant, &current.targets[0].0, &env, &terminal_qc);
        if let Ok(output) = replay {
            assert!(output.messages.is_empty());
            assert!(output.committed.is_empty());
        }
        let counted: NoSignature<'_> = NoSignature {
            member: &origin.members[0],
            count: Cell::new(0),
        };
        assert!(
            propose_successor(&old_warrant, &current.targets[0].0, &env, None, &counted).is_err()
        );
        assert!(
            process_tick_successor(&old_warrant, &current.targets[0].0, &env, 20_001, &counted)
                .is_err()
        );
        assert!(
            advance_frozen_frontier_successor(
                &old_warrant,
                &current.targets[0].0,
                &current.operation,
                network.domain(),
                &network.resolver,
                &network.history,
                current.policy.context(),
                &counted,
            )
            .is_err()
        );
        assert_eq!(
            counted.count.get(),
            0,
            "a retired namespace exposes no new control signature"
        );
        assert_eq!(
            current.capture(origin, 0),
            before,
            "terminal QC replay and old controls have no durable effect"
        );
    }
    remember_all_receipts(origin, current, receipts);
    assert!(receipts.contains_key(&seal.request_id));
    let (manifest_identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        current.history(origin);
    assert!(manifest_identity.through_height > cut_identity.through_height);
    archive.append(LinkArchive {
        pins: SuccessorLinkPins {
            cut_identity,
            manifest_identity,
        },
        saved,
        history,
        certificate,
    });
    let authority: VerifiedSuccessorAuthority = archive.verify(origin);
    assert_eq!(authority.import_binding(), import.binding());
    assert_eq!(
        authority.policy_inputs().context().epoch(),
        next_set.epoch()
    );
    let policy: OrderedEconomicsPolicy = authority.ordered_policy(&network.root).unwrap();
    assert_eq!(
        policy.context().epoch().get(),
        current
            .policy
            .context()
            .epoch()
            .get()
            .checked_add(1)
            .unwrap()
    );
    let paths: Vec<(PathBuf, PathBuf)> = (0..origin.members.len())
        .map(|index: usize| {
            (
                files.path(&format!("serving-{index}-state.db")),
                files.path(&format!("serving-{index}-body.db")),
            )
        })
        .collect();
    let next: EpochHosts = EpochHosts {
        base: LocalExecutionPolicy::generic_object_results(policy.context().clone()),
        policy,
        operation,
        targets,
        paths,
        _files: Some(files),
    };
    for index in 0..next.targets.len() {
        assert!(matches!(
            archive.activate(origin, &next, index),
            SuccessorActivationOutcome::Activated { .. }
        ));
        let before: SourceBusinessSnapshot = next.capture(origin, index);
        assert!(matches!(
            archive.activate(origin, &next, index),
            SuccessorActivationOutcome::AlreadyActivated { .. }
        ));
        assert_eq!(
            next.capture(origin, index),
            before,
            "activation reconciliation never reapplies a link"
        );
        assert!(matches!(
            archive.resolve(origin, &next, index).unwrap(),
            LiveAuthority::Successor(_)
        ));
    }
    assert_receipts(origin, &next, receipts);
    next
}

/// Reopen every current member's actual files and refence through the storage
/// owner. A pre-refence warrant and old writer context cannot sign or write.
fn reopen_current(origin: &SuccessorWorld, archive: &CompleteArchive, hosts: &mut EpochHosts) {
    let authority: VerifiedSuccessorAuthority = archive.verify(origin);
    let old: DurableOperationContext = hosts.operation;
    let new: DurableOperationContext =
        fixture::context(old.writer_fence().get().checked_add(1).unwrap());
    let mut reopened_targets: Vec<(SqliteImportTarget, SqliteBlobStore)> = Vec::new();
    for index in 0..hosts.targets.len() {
        let member: &TestSigner = &origin.members[index];
        let env: OrderedEconomicsEnvironment<'_> = hosts.env(origin);
        let before_status: OrderedStatus =
            query_status(&hosts.targets[index].0, &old, &env).unwrap();
        let old_warrant: LiveWarrant<'_> = archive.warrant(origin, hosts, index);
        let reopened: SqliteImportTarget = SqliteImportTarget::open_existing(
            &hosts.paths[index].0,
            SqliteNamespace::new(fixture::chain(), member.id, origin.network().domain()),
            authority.import_binding(),
        )
        .unwrap();
        let blobs: SqliteBlobStore = SqliteBlobStore::open(&hosts.paths[index].1).unwrap();
        reopened
            .advance_writer_fence(old.writer_fence(), new.writer_fence())
            .unwrap();
        let before: SourceBusinessSnapshot = crate::test_support::capture::captured_source(
            &reopened,
            &blobs,
            &new,
            origin.network().domain(),
        );
        assert!(
            archive.resolve(origin, hosts, index).is_err(),
            "the old writer context is fenced"
        );
        let counted: NoSignature<'_> = NoSignature {
            member,
            count: Cell::new(0),
        };
        assert!(
            propose_successor(&old_warrant, &hosts.targets[index].0, &env, None, &counted).is_err()
        );
        assert_eq!(
            counted.count.get(),
            0,
            "a stale actual owner creates no signature"
        );
        let signer: ReadinessSigningKey = ReadinessSigningKey::new(member.id, member.key);
        let mut artifacts: ArchiveTransport<'_> = ArchiveTransport::new(&archive.links);
        assert!(matches!(
            activate_successor_chain(
                reconstruction_plan(origin.source(), &origin.cut_history),
                &archive.pins,
                CompleteArchive::budget(),
                &mut artifacts,
                &reopened,
                &blobs,
                &new,
                &signer,
                1,
            )
            .unwrap(),
            SuccessorActivationOutcome::AlreadyActivated { .. }
        ));
        assert_eq!(signer.signatures_created(), 0);
        assert_eq!(query_status(&reopened, &new, &env).unwrap(), before_status);
        assert_eq!(
            crate::test_support::capture::captured_source(
                &reopened,
                &blobs,
                &new,
                origin.network().domain()
            ),
            before
        );
        reopened_targets.push((reopened, blobs));
    }
    hosts.targets = reopened_targets;
    hosts.operation = new;
    for index in 0..hosts.targets.len() {
        assert!(matches!(
            archive.resolve(origin, hosts, index).unwrap(),
            LiveAuthority::Successor(_)
        ));
    }
}

fn installed_delay(origin: &SuccessorWorld, hosts: &EpochHosts, bond: &FastPathBondRecord) -> u64 {
    let key: Vec<u8> =
        crate::local_instance_state::fastpath_economics_policy_key(&bond.context).unwrap();
    let bytes: Vec<u8> = hosts.value(origin, 0, &key).1.unwrap();
    let policy: crate::economics::FastPathEconomicsPolicy =
        crate::economics::decode_fastpath_economics_policy(&bytes).unwrap();
    let resource: BondResourceId =
        BondResourceId::new(bond.resource_domain, bond.resource).unwrap();
    policy
        .resources
        .iter()
        .find(
            |entry: &&crate::economics::FastPathEconomicsResourcePolicy| {
                entry.resource_id == resource
            },
        )
        .unwrap()
        .bond
        .as_ref()
        .unwrap()
        .unbonding_epochs
}

struct ExitingOwner {
    signer: TestSigner,
    unbonded: FastPathBondRecord,
    delay: u64,
    unlock: Epoch,
}

fn exiting_owner(origin: &SuccessorWorld, hosts: &EpochHosts, signer: TestSigner) -> ExitingOwner {
    let (unbonded, _): (FastPathBondRecord, Vec<u8>) = hosts.bond(origin, 0, signer.id);
    let delay: u64 = installed_delay(origin, hosts, &unbonded);
    assert_eq!(
        delay, 7,
        "the signed fixture's installed delay is unchanged"
    );
    let unlock: Epoch = match unbonded.state {
        FastPathBondState::Unbonding {
            unlock_epoch,
            recipient,
        } => {
            assert_eq!(recipient, *signer.id.as_bytes());
            unlock_epoch
        }
        _ => panic!("the actual committed Unbond row determines the unlock"),
    };
    assert_eq!(
        unlock.get(),
        unbonded.lifecycle_epoch.get().checked_add(delay).unwrap()
    );
    ExitingOwner {
        signer,
        unbonded,
        delay,
        unlock,
    }
}

/// D really exits at e1 as well. Its committee retirement supplies no exit
/// authority: the ordinary handler authenticates its own genesis bond key.
fn unbond_retired_d(
    origin: &SuccessorWorld,
    archive: &CompleteArchive,
    hosts: &EpochHosts,
) -> ExitingOwner {
    let d: &TestSigner = origin
        .network()
        .signers
        .iter()
        .find(|signer: &&TestSigner| hosts.policy.registered_validator(signer.id).is_none())
        .expect("the ABCD -> ABCE handoff retires exactly D");
    let (bond, bytes): (FastPathBondRecord, Vec<u8>) = hosts.bond(origin, 0, d.id);
    assert_eq!(bond.state, FastPathBondState::Active);
    let delay: u64 = installed_delay(origin, hosts, &bond);
    let checkpoint: u64 = hosts
        .status(origin, archive)
        .high_qc
        .height
        .checked_add(1)
        .unwrap();
    let mut next: FastPathBondRecord = bond;
    next.generation = next.generation.checked_add(1).unwrap();
    next.committed_at_checkpoint = checkpoint;
    next.lifecycle_epoch = hosts.policy.context().epoch();
    next.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(next.lifecycle_epoch.get().checked_add(delay).unwrap()),
        recipient: *d.id.as_bytes(),
    };
    let candidate: OrderedCandidate = successor_replacement::bond_candidate_for_scope(
        &origin.network().resolver,
        hosts.policy.context(),
        d,
        epoch_request(0x72, hosts.policy.context().epoch()),
        &bytes,
        &next,
        BondLifecycleOperation::Unbond {
            recipient: Address::new(*d.id.as_bytes()),
        },
        checkpoint,
    );
    hosts.policy.authenticate_candidate(&candidate).unwrap();
    let (outcome, _): (OrderedOutcome, consensus::QuorumCertificate) =
        hosts.commit(origin, archive, &hosts.env(origin), &candidate);
    assert_eq!(
        outcome.output.responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    for index in 0..hosts.targets.len() {
        assert_eq!(hosts.bond(origin, index, d.id).0, next);
    }
    exiting_owner(
        origin,
        hosts,
        TestSigner {
            id: d.id,
            key: d.key,
        },
    )
}

/// A caller's predicted row is only its authenticated claim. The ordinary
/// release VM and lifecycle owner independently produce/check the real effect.
fn withdraw_candidate(
    origin: &SuccessorWorld,
    archive: &CompleteArchive,
    hosts: &EpochHosts,
    owner: &ExitingOwner,
) -> (OrderedCandidate, FastPathBondRecord, Object) {
    let network: &Network = origin.network();
    let (bond, bytes): (FastPathBondRecord, Vec<u8>) = hosts.bond(origin, 0, owner.signer.id);
    assert_eq!(
        bond, owner.unbonded,
        "no hop resets the actual Unbond or its delay"
    );
    let checkpoint: u64 = hosts
        .status(origin, archive)
        .high_qc
        .height
        .checked_add(1)
        .unwrap();
    let request: [u8; 32] = {
        let mut request: [u8; 32] = epoch_request(0x73, hosts.policy.context().epoch());
        request[1..8].copy_from_slice(&owner.signer.id.as_bytes()[..7]);
        request
    };
    let before: Object = hosts.object(origin, 0, bond.custody_object.id);
    assert_eq!(before.version, bond.custody_object.version);
    assert!(matches!(before.owner, Owner::ProtocolCustody(_)));
    let mut released: Object = before;
    released.version = released.version.checked_add(1).unwrap();
    released.owner = Owner::Address(Address::new(*owner.signer.id.as_bytes()));
    let mut exited: FastPathBondRecord = bond;
    exited.generation = exited.generation.checked_add(1).unwrap();
    exited.committed_at_checkpoint = checkpoint;
    exited.lifecycle_epoch = hosts.policy.context().epoch();
    exited.custody_object_epoch = exited.lifecycle_epoch;
    exited.custody_object = ObjectRef {
        id: released.id,
        version: released.version,
        digest: network
            .resolver
            .hash_for_purpose(
                exited.lifecycle_epoch,
                HashPurpose::Object,
                &objects::encode_object(&released).unwrap(),
            )
            .unwrap(),
    };
    exited.state = FastPathBondState::Exited;
    let original_leg: Vec<u8> = successor_replacement::release_leg_for_scope(
        origin,
        hosts.policy.context(),
        &hosts.base,
        &owner.signer,
        request,
        &owner.unbonded.custody_object,
        *owner.signer.id.as_bytes(),
    );
    // G's genuine e1 registration already consumed nonce 0. Every attempt
    // signs the actually committed next nonce at its own live epoch, so an
    // early ordered refusal tests eligibility, not an unrelated stale leg.
    let current_nonce: u64 = crate::query_sender_next_nonce(
        &hosts.targets[0].0,
        &hosts.operation,
        network.domain(),
        hosts.policy.context().chain_id().clone(),
        hosts.policy.context().protocol_version(),
        hosts.policy.context().epoch(),
        *owner.signer.id.as_bytes(),
    )
    .unwrap();
    let leg: Vec<u8> = if current_nonce == 0 {
        original_leg
    } else {
        let mut signed: SignedLocalExecutionIntent =
            execution::local_execution::decode_signed_local_execution(&original_leg).unwrap();
        signed.intent.call.nonce = current_nonce;
        let frame: Vec<u8> =
            local_execution_signing_frame(hosts.policy.context(), &signed.intent).unwrap();
        signed.signature = owner.signer.key.sign(&frame).into();
        encode_signed_local_execution(&signed).unwrap()
    };
    let candidate: OrderedCandidate = successor_replacement::bond_candidate_for_scope(
        &network.resolver,
        hosts.policy.context(),
        &owner.signer,
        request,
        &bytes,
        &exited,
        BondLifecycleOperation::Withdraw { leg },
        checkpoint,
    );
    (candidate, exited, released)
}

/// Exact value-bearing objects and all fast-path business/authority rows.
/// Only this attempt's nonce lock is omitted: actual admission acquires and
/// releases it, while the original ordinary sender nonce stays unchanged.
fn early_withdraw_business_records(
    snapshot: &SourceBusinessSnapshot,
    nonce_lock: &[u8],
) -> Vec<SourceSnapshotRecord> {
    snapshot
        .records
        .iter()
        .filter(|row: &&SourceSnapshotRecord| match row.descriptor.key() {
            runtime::portable::DurableRecordKey::ObjectHead(_)
            | runtime::portable::DurableRecordKey::ObjectVersion(_, _) => true,
            runtime::portable::DurableRecordKey::State(key) => {
                key.starts_with(crate::local_instance_state::FASTPATH_STATE_PREFIX)
                    && key.as_slice() != nonce_lock
            }
            runtime::portable::DurableRecordKey::Receipt(_) => false,
        })
        .cloned()
        .collect()
}

/// Every actual epoch below U independently preflights IneligibleState,
/// then genuinely orders the same authenticated body and retains that exact
/// refusal. Consensus/audit/receipt rows change; custody, value and nonce do
/// not. Exact completed replay exposes no new signature or durable effect.
fn assert_early_withdraw(
    origin: &SuccessorWorld,
    archive: &CompleteArchive,
    hosts: &EpochHosts,
    owner: &ExitingOwner,
) {
    assert!(hosts.policy.context().epoch().get() < owner.unlock.get());
    assert!(hosts.policy.registered_validator(owner.signer.id).is_none());
    assert_eq!(installed_delay(origin, hosts, &owner.unbonded), owner.delay);
    let (candidate, _, _): (OrderedCandidate, FastPathBondRecord, Object) =
        withdraw_candidate(origin, archive, hosts, owner);
    hosts.policy.authenticate_candidate(&candidate).unwrap();
    let env: OrderedEconomicsEnvironment<'_> = hosts.env(origin);
    let status: OrderedStatus = hosts.status(origin, archive);
    let before: Vec<SourceBusinessSnapshot> = (0..hosts.targets.len())
        .map(|index: usize| hosts.capture(origin, index))
        .collect();
    let context: &PublicationContext = hosts.policy.context();
    let sender: [u8; 32] = *owner.signer.id.as_bytes();
    let nonce_key: Vec<u8> =
        runtime::PersistenceLayout::new(context.chain_id().clone(), context.protocol_version())
            .sender_nonce_key(sender, context.epoch());
    let nonce_lock_key: Vec<u8> = crate::local_instance_state::fastpath_nonce_lock_key(
        context.chain_id(),
        &sender,
        context.epoch(),
    )
    .unwrap();
    let reservation_key: Vec<u8> = crate::ordered_economics::reservation::ordered_reservation_key(
        context.chain_id(),
        &candidate.request_id,
    )
    .unwrap();
    let nonce_before: Vec<(StateRevision, Option<Vec<u8>>)> = (0..hosts.targets.len())
        .map(|index: usize| hosts.value(origin, index, &nonce_key))
        .collect();
    let locks_before: Vec<(StateRevision, Option<Vec<u8>>)> = (0..hosts.targets.len())
        .map(|index: usize| hosts.value(origin, index, &nonce_lock_key))
        .collect();
    for index in 0..hosts.targets.len() {
        let local_env: OrderedEconomicsEnvironment<'_> = hosts.env_for_host(&env, index);
        assert!(matches!(
            crate::ordered_economics::preflight::preflight(
                &hosts.targets[index].0,
                &hosts.operation,
                &local_env,
                &candidate,
                status.high_qc.height.checked_add(1).unwrap(),
            ),
            Err(OrderedEconomicsError::Refused(
                OrderedRefusal::IneligibleState
            ))
        ));
        assert_eq!(
            &hosts.capture(origin, index),
            &before[index],
            "owning writer-free preflight has no physical effect"
        );
        assert!(locks_before[index].1.is_none());
        assert_eq!(
            hosts.value(origin, index, &reservation_key),
            (StateRevision::INITIAL, None),
            "each early attempt has a genuinely fresh request identity"
        );
        assert!(matches!(
            crate::query_request_receipt(
                &hosts.targets[index].0,
                &hosts.operation,
                origin.network().domain(),
                crate::RequestId::new(candidate.request_id).unwrap(),
            )
            .unwrap(),
            crate::ReceiptQueryResult::Absent { .. }
        ));
    }
    let (outcome, _): (OrderedOutcome, consensus::QuorumCertificate) =
        hosts.commit(origin, archive, &env, &candidate);
    assert_eq!(refusal_of(&outcome), OrderedRefusal::IneligibleState);
    assert_eq!(outcome.request_id, candidate.request_id);
    assert_eq!(
        outcome.candidate_digest,
        hosts.policy.candidate_digest(&candidate).unwrap()
    );
    let expected_receipt: crate::NodeDedupRecord = crate::NodeDedupRecord::new(
        crate::RequestId::new(candidate.request_id).unwrap(),
        outcome.candidate_digest,
        outcome.output.responses().to_vec(),
    )
    .unwrap();
    let canonical_receipt: Vec<u8> = expected_receipt.encode().unwrap();
    for index in 0..hosts.targets.len() {
        let after: SourceBusinessSnapshot = hosts.capture(origin, index);
        assert!(after.token.mutation_sequence() > before[index].token.mutation_sequence());
        assert_eq!(
            early_withdraw_business_records(&after, &nonce_lock_key),
            early_withdraw_business_records(&before[index], &nonce_lock_key),
            "refusal changes no object, bond, settlement, collateral value or authority row"
        );
        assert_eq!(hosts.bond(origin, index, owner.signer.id).0, owner.unbonded);
        assert_eq!(hosts.value(origin, index, &nonce_key), nonce_before[index]);
        let nonce_lock: (StateRevision, Option<Vec<u8>>) =
            hosts.value(origin, index, &nonce_lock_key);
        assert!(
            nonce_lock.1.is_none(),
            "the admitted nonce lock is released"
        );
        assert!(nonce_lock.0.get() > locks_before[index].0.get());
        let reservation: (StateRevision, Option<Vec<u8>>) =
            hosts.value(origin, index, &reservation_key);
        assert!(
            reservation.1.is_none(),
            "the actual reservation is released"
        );
        assert_ne!(reservation.0, StateRevision::INITIAL);
        assert_eq!(
            query_ordered_outcome(
                &hosts.targets[index].0,
                &hosts.operation,
                &env,
                &candidate.request_id
            )
            .unwrap()
            .as_ref(),
            Some(&outcome)
        );
        let raw: DurableRequestReceipt = hosts.targets[index]
            .0
            .read_request_receipt(
                &hosts.operation,
                origin.network().domain(),
                DurableRequestId::new(candidate.request_id).unwrap(),
            )
            .unwrap()
            .expect("a real committed refusal retains its original receipt");
        assert_eq!(raw.event_digest(), outcome.candidate_digest);
        assert_eq!(raw.canonical_bytes(), canonical_receipt.as_slice());
        let query: crate::ReceiptQueryResult = crate::query_request_receipt(
            &hosts.targets[index].0,
            &hosts.operation,
            origin.network().domain(),
            crate::RequestId::new(candidate.request_id).unwrap(),
        )
        .unwrap();
        let crate::ReceiptQueryResult::Present {
            record,
            event_digest,
            ..
        } = query
        else {
            panic!("every host independently reverifies the real refused receipt")
        };
        assert_eq!(event_digest, outcome.candidate_digest);
        assert_eq!(record, expected_receipt);
    }
    assert_completed_without_reapplication(origin, archive, hosts, &candidate, &outcome);
}

fn assert_completed_without_reapplication(
    origin: &SuccessorWorld,
    archive: &CompleteArchive,
    hosts: &EpochHosts,
    candidate: &OrderedCandidate,
    outcome: &OrderedOutcome,
) {
    let env: OrderedEconomicsEnvironment<'_> = hosts.env(origin);
    let status: OrderedStatus = hosts.status(origin, archive);
    let leader_id: ValidatorId = hosts
        .policy
        .engine()
        .validator_set()
        .leader(status.current_view)
        .unwrap();
    let leader: usize = origin
        .members
        .iter()
        .position(|member: &TestSigner| member.id == leader_id)
        .unwrap();
    let before: Vec<SourceBusinessSnapshot> = (0..hosts.targets.len())
        .map(|index: usize| hosts.capture(origin, index))
        .collect();
    let counted: NoSignature<'_> = NoSignature {
        member: &origin.members[leader],
        count: Cell::new(0),
    };
    let replay: Result<OrderedProposal, OrderedEconomicsError> = propose_successor(
        &archive.warrant(origin, hosts, leader),
        &hosts.targets[leader].0,
        &env,
        Some(candidate),
        &counted,
    );
    let Err(OrderedEconomicsError::AlreadyCompleted(retained)) = replay else {
        panic!("the real owner returns the original completed outcome without re-placing it")
    };
    assert_eq!(retained.as_ref(), outcome);
    assert_eq!(counted.count.get(), 0);
    for (index, expected) in before.iter().enumerate() {
        assert_eq!(
            query_ordered_outcome(
                &hosts.targets[index].0,
                &hosts.operation,
                &env,
                &candidate.request_id
            )
            .unwrap()
            .as_ref(),
            Some(outcome)
        );
        assert_eq!(
            &hosts.capture(origin, index),
            expected,
            "completed admission does not execute or mutate a second time"
        );
    }
}

/// D claims its actual e0 share at e2, through the original claim/VM owners.
/// Later imports must retain the changed historical settlement and receipt.
fn claim_original_d_share(
    origin: &SuccessorWorld,
    archive: &CompleteArchive,
    hosts: &EpochHosts,
    d: &ExitingOwner,
) -> (Vec<u8>, Vec<u8>) {
    let network: &Network = origin.network();
    let escrow: [u8; 32] = match &origin.source {
        WorldSource::Replacement(source) => source.funded_escrow(),
        WorldSource::SameCommittee(_) => panic!("the genuine registered-E source owns this escrow"),
    };
    let key: Vec<u8> =
        crate::local_instance_state::fastpath_settlement_key(&fixture::chain(), &escrow).unwrap();
    let settlement: FastPathSettlementRecord =
        decode_fastpath_settlement_record(&hosts.value(origin, 0, &key).1.unwrap()).unwrap();
    assert_eq!(
        settlement.context.epoch(),
        network.root.genesis_context().epoch()
    );
    let amount: u64 = settlement
        .shares
        .iter()
        .find(|share: &&crate::fast_path::records::FastPathFeeShare| {
            share.validator_id == d.signer.id
        })
        .unwrap()
        .amount;
    assert!(amount > 0);
    let request: [u8; 32] = epoch_request(0x74, hosts.policy.context().epoch());
    let current: PublicationContext = hosts.policy.context().clone();
    let leg: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: hosts.base.digest(&network.resolver).unwrap(),
        call: CallIntent {
            context: current.clone(),
            request_id: request,
            sender: *d.signer.id.as_bytes(),
            nonce: 0,
            code: origin.source().instance.code.clone(),
            instance: instance_target(&network.resolver, &origin.source().instance).unwrap(),
            entrypoint: "split".into(),
            type_arguments: origin.source().manifest.fee_policy.type_arguments.clone(),
            access: abi::AccessManifest {
                entries: vec![abi::AccessEntry {
                    object_ref: settlement.fee_output.clone().unwrap(),
                    mode: AccessMode::Write,
                }],
            },
            arguments: public_standard_asset::split_arguments(amount, d.signer.id.as_bytes())
                .unwrap(),
            gas_limit: 500_000,
        },
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = local_execution_signing_frame(&current, &leg).unwrap();
    let signed_leg: Vec<u8> = encode_signed_local_execution(&SignedLocalExecutionIntent {
        signature: d.signer.key.sign(&frame).into(),
        intent: leg,
    })
    .unwrap();
    let checkpoint: u64 = hosts
        .status(origin, archive)
        .high_qc
        .height
        .checked_add(1)
        .unwrap();
    let before: SourceBusinessSnapshot = hosts.capture(origin, 0);
    let prepared: crate::fee_claims::PreparedFeeClaim =
        crate::serving_authority::prepare_fee_claim_successor(
            &archive.warrant(origin, hosts, 0),
            &hosts.targets[0].0,
            &hosts.targets[0].1,
            &network.resolver,
            &network.history,
            &hosts.base,
            &network.engine,
            crate::fee_claims::FeeClaimPreparationRequest {
                escrow_request_id: escrow,
                request_id: request,
                validator_id: d.signer.id,
                claimant_public_key: *d.signer.id.as_bytes(),
                recipient: Address::new(*d.signer.id.as_bytes()),
                signed_leg: Some(&signed_leg),
            },
            checkpoint,
        )
        .unwrap();
    assert_eq!(
        hosts.capture(origin, 0),
        before,
        "claim preparation is writer-free"
    );
    assert_eq!(
        prepared.intent.certificate_epoch,
        network.root.genesis_context().epoch()
    );
    let digest: Digest32 =
        crate::fee_claims::fee_claim_intent_digest(&network.resolver, &prepared.intent).unwrap();
    let claim_frame: Vec<u8> =
        crate::fee_claims::fee_claim_signing_frame(&current, digest).unwrap();
    let signed: crate::fee_claims::codec::SignedFeeClaimIntent =
        crate::fee_claims::codec::SignedFeeClaimIntent {
            intent: prepared.intent.clone(),
            signature: d.signer.key.sign(&claim_frame).into(),
        };
    let candidate: OrderedCandidate = OrderedCandidate {
        context: current,
        request_id: request,
        kind: OrderedOperationKind::FeeClaim,
        intent: crate::fee_claims::codec::encode_signed_fee_claim_intent(&signed).unwrap(),
        created_checkpoint: checkpoint,
    };
    hosts.policy.authenticate_candidate(&candidate).unwrap();
    let (outcome, _): (OrderedOutcome, consensus::QuorumCertificate) =
        hosts.commit(origin, archive, &hosts.env(origin), &candidate);
    assert_eq!(
        outcome.output.responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    let expected: Vec<u8> =
        crate::fast_path::records::encode_fastpath_settlement_record(&prepared.next_settlement)
            .unwrap();
    for index in 0..hosts.targets.len() {
        assert_eq!(hosts.value(origin, index, &key).1.as_ref(), Some(&expected));
    }
    assert_completed_without_reapplication(origin, archive, hosts, &candidate, &outcome);
    (key, expected)
}

#[test]
fn genuine_recurring_sqlite_handoffs_reach_configured_seven_epoch_withdrawal_unlock() {
    let origin: SuccessorWorld = successor_chain::recurring_world();
    let g_anchor: Vec<u8> = successor_chain::register_and_unbond_g(&origin);
    let mut archive: CompleteArchive = CompleteArchive::from_origin(&origin);
    let mut current: EpochHosts = EpochHosts::initial(&origin, &archive);
    let g: ExitingOwner = exiting_owner(&origin, &current, successor_chain::never_member_g());
    let d: ExitingOwner = unbond_retired_d(&origin, &archive, &current);
    let terminal: Epoch = g.unlock.max(d.unlock);
    assert_eq!(
        terminal.get(),
        origin
            .network()
            .root
            .genesis_context()
            .epoch()
            .get()
            .checked_add(8)
            .unwrap()
    );
    let first_successor: Epoch = current.policy.context().epoch();
    assert_eq!(g.unbonded.lifecycle_epoch, first_successor);
    assert_eq!(d.unbonded.lifecycle_epoch, first_successor);
    let g_key: Vec<u8> = crate::bond_lifecycle::registration::bond_registration_anchor_key(
        &fixture::chain(),
        &g.signer.id,
    )
    .unwrap();
    let mut receipts: ReceiptJournal = BTreeMap::new();
    remember_all_receipts(&origin, &current, &mut receipts);
    let mut historical_claim: Option<(Vec<u8>, Vec<u8>)> = None;
    let mut sealed_hosts: Vec<(EpochHosts, Vec<SourceBusinessSnapshot>)> = Vec::new();
    while current.policy.context().epoch().get() < terminal.get() {
        let authority: VerifiedSuccessorAuthority = archive.verify(&origin);
        let epoch: Epoch = current.policy.context().epoch();
        assert_eq!(
            authority.policy_inputs().context(),
            current.policy.context()
        );
        assert_eq!(archive.original_root, origin.network().root.digest());
        assert_eq!(
            authority.committees().len(),
            archive.links.len().checked_add(1).unwrap()
        );
        for earlier in origin.network().root.genesis_context().epoch().get()..=epoch.get() {
            let committee: &ValidatorSet =
                authority.committees().get(Epoch::new(earlier)).unwrap().0;
            assert!(
                committee.get(g.signer.id).is_none(),
                "G is never selected into any verified committee"
            );
            assert_eq!(
                current.policy.certificate_set(Epoch::new(earlier)),
                Some(committee)
            );
        }
        if epoch.get() > first_successor.get() {
            let owner = authority
                .owners()
                .owner(g.signer.id)
                .expect("G is carried from its own genuine registration");
            assert!(
                matches!(owner.provenance(), OwnerProvenance::Registration { anchor_epoch, .. } if *anchor_epoch == first_successor)
            );
        }
        for index in 0..current.targets.len() {
            assert_eq!(
                current.value(&origin, index, &g_key).1.as_ref(),
                Some(&g_anchor)
            );
        }
        if epoch == first_successor {
            assert_historical_owner_registration_refused(
                &origin,
                &archive,
                &current,
                &authority,
                &d,
                d.unbonded.custody_object.id,
                0x75,
            );
        } else if epoch.get() == first_successor.get().checked_add(1).unwrap() {
            assert_historical_owner_registration_refused(
                &origin,
                &archive,
                &current,
                &authority,
                &d,
                d.unbonded.custody_object.id,
                0x75,
            );
            assert_historical_owner_registration_refused(
                &origin,
                &archive,
                &current,
                &authority,
                &g,
                ObjectId::new([0x24; 32]),
                0x76,
            );
        }
        for owner in [&d, &g] {
            assert_early_withdraw(&origin, &archive, &current, owner);
        }
        if epoch.get() == first_successor.get().checked_add(1).unwrap() {
            historical_claim = Some(claim_original_d_share(&origin, &archive, &current, &d));
            remember_all_receipts(&origin, &current, &mut receipts);
        }
        reopen_current(&origin, &archive, &mut current);
        assert_receipts(&origin, &current, &receipts);
        if let Some((key, bytes)) = &historical_claim {
            for index in 0..current.targets.len() {
                assert_eq!(current.value(&origin, index, key).1.as_ref(), Some(bytes));
            }
        }
        let next: EpochHosts = handoff(&origin, &mut archive, &current, &mut receipts);
        let retired: Vec<SourceBusinessSnapshot> = (0..current.targets.len())
            .map(|index: usize| current.capture(&origin, index))
            .collect();
        sealed_hosts.push((current, retired));
        current = next;
    }
    assert_eq!(
        current.policy.context().epoch(),
        terminal,
        "the reached epoch is derived from seven actual handoffs"
    );
    assert_eq!(archive.links.len(), 8);
    let authority: VerifiedSuccessorAuthority = archive.verify(&origin);
    assert_eq!(authority.link_count(), 8);
    assert!(authority.validator_set().get(g.signer.id).is_none());
    reopen_current(&origin, &archive, &mut current);
    for owner in [&d, &g] {
        assert_eq!(current.policy.context().epoch(), owner.unlock);
        assert_eq!(
            installed_delay(&origin, &current, &owner.unbonded),
            owner.delay
        );
        let (candidate, exited, released): (OrderedCandidate, FastPathBondRecord, Object) =
            withdraw_candidate(&origin, &archive, &current, owner);
        current.policy.authenticate_candidate(&candidate).unwrap();
        let (outcome, _): (OrderedOutcome, consensus::QuorumCertificate) =
            current.commit(&origin, &archive, &current.env(&origin), &candidate);
        assert_eq!(
            outcome.output.responses()[0].status(),
            NodeResponseStatus::Accepted,
            "Withdraw accepts at the committed unlock epoch"
        );
        for index in 0..current.targets.len() {
            assert_eq!(current.bond(&origin, index, owner.signer.id).0, exited);
            assert_eq!(current.object(&origin, index, released.id), released);
            assert_eq!(
                exited.amount, owner.unbonded.amount,
                "the original whole collateral amount is conserved"
            );
            assert_eq!(
                exited.context, owner.unbonded.context,
                "the original economics resource scope is retained"
            );
        }
        assert_completed_without_reapplication(&origin, &archive, &current, &candidate, &outcome);
        remember_all_receipts(&origin, &current, &mut receipts);
    }
    assert_receipts(&origin, &current, &receipts);
    let (claim_key, claim_bytes): (Vec<u8>, Vec<u8>) =
        historical_claim.expect("the actual e2 claim happened before its Freeze");
    for index in 0..current.targets.len() {
        assert_eq!(
            current.value(&origin, index, &claim_key).1.as_ref(),
            Some(&claim_bytes)
        );
        assert_eq!(
            current.value(&origin, index, &g_key).1.as_ref(),
            Some(&g_anchor)
        );
    }
    // All retired physical namespaces remain unchanged throughout later work.
    for (hosts, snapshots) in &sealed_hosts {
        for (index, expected) in snapshots.iter().enumerate() {
            assert!(archive.resolve(&origin, hosts, index).is_err());
            assert_eq!(&hosts.capture(&origin, index), expected);
        }
    }
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(origin.network());
    assert_eq!(identity, archive.links[0].pins.manifest_identity);
    assert_eq!(
        history, archive.links[0].history,
        "the actual original ordered history is unchanged"
    );
    assert_eq!(origin.network().root.digest(), archive.original_root);
}
