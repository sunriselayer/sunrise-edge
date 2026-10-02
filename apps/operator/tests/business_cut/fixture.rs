//! Real four-replica SQLite history and a no-AV paid drain completion.
//! No completion row, union-ready flag or business effect is seeded.

use super::capture_source_business_snapshot;
use super::{causal_genesis_fixture, genesis_fixture::FastVoteGenesisFixture};
use consensus::bundle::PublicationBundle;
use consensus::{
    ConsensusMessage, ConsensusSigner, ConsensusVerifier, ConsensusVote, FastCertificate,
    FastPathCertifier, FastVote, FrozenFrontierPage, FrozenFrontierVote, QuorumCertificate,
};
use crypto::{Ed25519Verifier, SignatureVerifier};
use execution::{
    LocalWasmExecutionEngine, local_execution::LocalExecutionPolicy,
    publication::PublicationContext,
};
use node_core::business_reconstruction::{BusinessReconstructionPlan, SourceBusinessSnapshot};
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::*;
use protocol_types::{Digest32, Epoch, SignatureSchemeId, ValidatorId};
use runtime::{
    Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const FREEZE: [u8; 32] = [0xCB; 32];
const DRAIN: [u8; 32] = [0xCC; 32];
const NOW: u64 = 1_700_000_000_000;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

pub struct Directory(pub PathBuf);
impl Directory {
    pub fn new(label: &str) -> Self {
        let sequence: u64 = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf = std::env::temp_dir().join(format!(
            "cut-operator-{label}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.0);
    }
}

struct Signer<'a>(&'a super::genesis_fixture::FastVoteValidator);
impl ConsensusSigner for Signer<'_> {
    fn validator_id(&self) -> ValidatorId {
        self.0.validator_id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
        let signature: [u8; 64] = self.0.signing_key.sign(frame).into();
        Ok(signature.to_vec())
    }
}
struct Verifier;
impl ConsensusVerifier for Verifier {
    fn verify_framed(
        &self,
        _validator: ValidatorId,
        scheme: SignatureSchemeId,
        public_key: &[u8],
        frame: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        if scheme != SignatureSchemeId::Ed25519 {
            return Ok(false);
        }
        Ed25519Verifier::from_verifying_key_bytes(public_key)
            .map_err(|error| error.to_string())?
            .verify_framed(frame, signature)
            .map_err(|error| error.to_string())
    }
}

pub struct Fixture {
    pub network: FastVoteGenesisFixture,
    pub root: VerifiedGenesisRoot,
    pub policy: OrderedEconomicsPolicy,
    pub local_policy: LocalExecutionPolicy,
    pub engine: LocalWasmExecutionEngine,
    pub stores: Vec<SqliteDurableStore>,
    pub blobs: SqliteBlobStore,
    pub operation: DurableOperationContext,
    pub directory: Directory,
}

impl Fixture {
    pub fn new() -> Self {
        let directory: Directory = Directory::new("genuine-source");
        let unique: String = format!("cut-{}", NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed));
        let network: FastVoteGenesisFixture = causal_genesis_fixture::build(&unique).network;
        let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
            &network.resolver,
            &network.manifest_bytes,
            network.manifest_digest,
            &network.context,
        )
        .unwrap();
        let policy: OrderedEconomicsPolicy =
            OrderedEconomicsPolicy::from_genesis_root(&root, network.domain).unwrap();
        let first: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        let stores: Vec<SqliteDurableStore> = network
            .validators
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                SqliteDurableStore::open(
                    directory.0.join(format!("state-{index}.sqlite")),
                    SqliteNamespace::new(
                        network.chain_id.clone(),
                        validator.validator_id,
                        network.domain,
                    ),
                    first,
                )
                .unwrap()
            })
            .collect();
        let blobs: SqliteBlobStore =
            SqliteBlobStore::open(directory.0.join("blobs.sqlite")).unwrap();
        let deadline: u64 = SystemClock
            .now_unix_millis()
            .unwrap()
            .checked_add(3_600_000)
            .unwrap();
        let operation: DurableOperationContext = DurableOperationContext::new(
            first,
            StorageDeadline::new(deadline).unwrap(),
            StorageCorrelationId::new([0xBC; 16]).unwrap(),
        );
        let local_policy: LocalExecutionPolicy =
            LocalExecutionPolicy::generic_object_results(network.context.clone());
        let fixture: Self = Self {
            network,
            root,
            policy,
            local_policy,
            engine: LocalWasmExecutionEngine::new(),
            stores,
            blobs,
            operation,
            directory,
        };
        for store in &fixture.stores {
            node_core::genesis::install_genesis(
                store,
                &fixture.operation,
                fixture.network.domain,
                &fixture.network.resolver,
                fixture.root.manifest(),
                10,
            )
            .unwrap();
            install_ordered_genesis(store, &fixture.operation, &fixture.environment(), NOW)
                .unwrap();
        }
        fixture
    }

    fn environment(&self) -> OrderedEconomicsEnvironment<'_> {
        OrderedEconomicsEnvironment {
            policy: &self.policy,
            resolver: self.policy.resolver(),
            history: &[],
            leg_policy: &self.local_policy,
            engine: &self.engine,
            blobs: &self.blobs,
        }
    }

    fn round(&self, view: u64, candidate: Option<&OrderedCandidate>) {
        let leader: ValidatorId = self.policy.engine().validator_set().leader(view).unwrap();
        let leader_index: usize = self
            .network
            .validators
            .iter()
            .position(|validator| validator.validator_id == leader)
            .unwrap();
        let proposal: OrderedProposal = propose(
            &self.stores[leader_index],
            &self.operation,
            &self.environment(),
            candidate,
            &Signer(&self.network.validators[leader_index]),
        )
        .unwrap();
        assert_eq!(proposal.proposal.view, view);
        let votes: Vec<ConsensusVote> = self
            .stores
            .iter()
            .zip(&self.network.validators)
            .map(|(store, validator)| {
                let output: OrderedEventOutput = process_proposal(
                    store,
                    &self.operation,
                    &self.environment(),
                    &proposal,
                    &Signer(validator),
                )
                .unwrap();
                output
                    .messages
                    .into_iter()
                    .find_map(|message| match message {
                        ConsensusMessage::Vote(vote) => Some(vote),
                        _ => None,
                    })
                    .unwrap()
            })
            .collect();
        let certificate: QuorumCertificate = self
            .policy
            .engine()
            .certificate_from_votes(&proposal.proposal, &votes, &Verifier)
            .unwrap()
            .unwrap();
        for store in &self.stores {
            process_certificate(store, &self.operation, &self.environment(), &certificate).unwrap();
        }
    }

    pub fn freeze_and_complete(&self) {
        let signed: &[u8] = &self.network.paid_intent_bytes;
        let votes: Vec<FastVote> = self
            .stores
            .iter()
            .zip(&self.network.validators)
            .map(|(store, validator)| {
                node_core::fast_path::prepare(
                    store,
                    &self.blobs,
                    &self.operation,
                    self.network.domain,
                    &self.network.resolver,
                    &[],
                    &self.network.context,
                    &self.local_policy,
                    &self.root.manifest().fee_policy,
                    &self.engine,
                    &Signer(validator),
                    signed,
                    11,
                )
                .unwrap()
            })
            .collect();
        let certifier: FastPathCertifier = FastPathCertifier::new(
            self.network.chain_id.clone(),
            self.network.protocol_version,
            self.network.epoch,
            self.policy.engine().validator_set().clone(),
        )
        .unwrap();
        let certificate: FastCertificate = certifier
            .try_form_certificate(
                votes[0].tx_hash,
                votes[0].execution_effects_hash,
                votes[0].locked_objects_digest,
                &votes[..3],
                &node_core::fast_path::FastPathEd25519Verifier,
            )
            .unwrap()
            .unwrap();
        let bundle: PublicationBundle =
            node_core::fast_path::publication::assemble_publication_bundle(
                &self.stores[0],
                &self.operation,
                self.network.domain,
                &self.network.resolver,
                &[],
                &self.network.context,
                signed,
                &consensus::encode_fast_certificate(&certificate).unwrap(),
            )
            .unwrap();
        let bundle_bytes: Vec<u8> = consensus::bundle::encode_publication_bundle(&bundle).unwrap();
        for (store, validator) in self.stores.iter().zip(&self.network.validators) {
            let _individual_ack = node_core::fast_path::publication::retain_publication(
                store,
                &self.operation,
                self.network.domain,
                &self.network.resolver,
                &[],
                &self.network.context,
                &bundle_bytes,
                &Signer(validator),
            )
            .unwrap();
        }
        // No AvailabilityCertifier or aggregate AV is constructed.
        let mut advisory = self.root.manifest().validator_set.clone();
        advisory.validators.sort_by_key(|member| member.id);
        advisory.context = PublicationContext::new(
            self.network.chain_id.clone(),
            self.network.protocol_version,
            Epoch::new(1),
        )
        .unwrap();
        let freeze: OrderedCandidate = OrderedCandidate {
            context: self.network.context.clone(),
            request_id: FREEZE,
            kind: OrderedOperationKind::Freeze,
            intent: encode_freeze_intent(&FreezeIntent {
                context: self.network.context.clone(),
                request_id: FREEZE,
                advisory_next_set: advisory,
            })
            .unwrap(),
            created_checkpoint: 12,
        };
        for view in 1..=3 {
            self.round(view, (view == 1).then_some(&freeze));
        }
        let mut selected: Vec<(FrozenFrontierVote, FrozenFrontierPage)> = Vec::new();
        for (store, validator) in self.stores.iter().zip(&self.network.validators).take(3) {
            let mut finalized: bool = false;
            for _ in 0..=1 {
                if matches!(
                    advance_frozen_frontier(
                        store,
                        &self.operation,
                        self.network.domain,
                        &self.network.resolver,
                        &[],
                        &self.network.context,
                        &Signer(validator)
                    )
                    .unwrap(),
                    FrozenFrontierStep::Finalized(_)
                ) {
                    finalized = true;
                    break;
                }
            }
            assert!(finalized);
            let pair: (FrozenFrontierVote, FrozenFrontierPage) = read_frozen_frontier_page(
                store,
                &self.operation,
                self.network.domain,
                &self.network.resolver,
                &[],
                &self.network.context,
                validator.validator_id,
                None,
                NonZeroUsize::new(2).unwrap(),
            )
            .unwrap();
            assert!(pair.1.terminal);
            assert_eq!(pair.1.entries.len(), 1);
            selected.push(pair);
        }
        selected.sort_by_key(|(vote, _)| vote.validator);
        let selected_votes: Vec<FrozenFrontierVote> =
            selected.iter().map(|(vote, _)| vote.clone()).collect();
        let mut union: Option<consensus::DrainUnionIdentity> = None;
        for store in &self.stores {
            for (vote, page) in &selected {
                ingest_drain_signer_page(
                    store,
                    &self.operation,
                    self.network.domain,
                    &self.network.resolver,
                    &self.network.context,
                    vote.validator,
                    vote.clone(),
                    page.clone(),
                )
                .unwrap();
                let entry = &page.entries[0];
                assert_eq!(
                    import_staged_drain_publication(
                        store,
                        &self.operation,
                        self.network.domain,
                        &self.network.resolver,
                        &[],
                        &self.network.context,
                        vote.validator,
                        &bundle_bytes
                    )
                    .unwrap(),
                    *entry
                );
                assert_eq!(
                    confirm_drain_signer_entry(
                        store,
                        &self.operation,
                        self.network.domain,
                        &self.network.resolver,
                        &[],
                        &self.network.context,
                        vote.validator,
                        entry.request_id
                    )
                    .unwrap(),
                    *entry
                );
            }
            let mut ready: Option<consensus::DrainUnionIdentity> = None;
            for _ in 0..=1 {
                if let DrainUnionStep::Ready(identity) = advance_drain_union(
                    store,
                    &self.operation,
                    self.network.domain,
                    &self.network.resolver,
                    &[],
                    &self.network.context,
                    &selected_votes,
                )
                .unwrap()
                {
                    ready = Some(*identity);
                    break;
                }
            }
            let ready = ready.unwrap();
            assert_eq!(ready.member_count, 1);
            if let Some(previous) = &union {
                assert_eq!(previous, &ready);
            } else {
                union = Some(ready);
            }
        }
        let drain: OrderedCandidate = OrderedCandidate {
            context: self.network.context.clone(),
            request_id: DRAIN,
            kind: OrderedOperationKind::DrainSet,
            intent: encode_drain_set_intent(&DrainSetIntent {
                context: self.network.context.clone(),
                request_id: DRAIN,
                selected_votes,
                drain_union_identity: union.unwrap(),
            })
            .unwrap(),
            created_checkpoint: 13,
        };
        for view in 4..=6 {
            self.round(view, (view == 4).then_some(&drain));
        }
        for store in &self.stores {
            node_core::fast_path::drain_apply::apply_drain_member(
                store,
                &self.blobs,
                &self.operation,
                self.network.domain,
                &self.network.resolver,
                &[],
                &self.network.context,
                &self.local_policy,
                &self.root.manifest().fee_policy,
                &self.engine,
                self.network.request_id,
                11,
            )
            .unwrap();
        }
        // The fixed target and both children are independently certified empty.
        self.round(7, None);
        self.round(8, None);
    }

    pub fn history(&self) -> (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) {
        let identity: OrderedHistoryIdentity =
            query_ordered_history_summary(&self.stores[0], &self.operation, &self.environment())
                .unwrap()
                .identity;
        let mut materials: Vec<OrderedHistoryHeightMaterial> = Vec::new();
        for height in 1..=identity.through_height {
            let descriptor = read_ordered_history_height_descriptor(
                &self.stores[0],
                &self.operation,
                &self.environment(),
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
                    let chunk: Vec<u8> = read_ordered_history_component_chunk(
                        &self.stores[0],
                        &self.operation,
                        &self.environment(),
                        &identity,
                        height,
                        digest,
                        reference.kind,
                        offset,
                        1_048_576,
                    )
                    .unwrap();
                    offset += chunk.len() as u64;
                    bytes.extend_from_slice(&chunk);
                }
                components.push((reference.kind, bytes));
            }
            materials.push(OrderedHistoryHeightMaterial {
                descriptor,
                components,
            });
        }
        (identity, materials)
    }

    pub fn plan<'a>(
        &'a self,
        identity: &'a OrderedHistoryIdentity,
        operation: DurableOperationContext,
    ) -> BusinessReconstructionPlan<'a> {
        BusinessReconstructionPlan {
            genesis_root: &self.root,
            operation_context: operation,
            domain: self.network.domain,
            resolver_history: &[],
            ordered_policy: &self.policy,
            ordered_history_identity: identity,
            ordered_leg_policy: &self.local_policy,
            ordered_engine: &self.engine,
            paid_base_policy: &self.local_policy,
            paid_engine: &self.engine,
        }
    }

    pub fn snapshot(&self) -> SourceBusinessSnapshot {
        capture_source_business_snapshot(
            &self.stores[0],
            &self.blobs,
            &self.operation,
            self.network.domain,
            NonZeroUsize::new(128).unwrap(),
        )
        .unwrap()
    }

    pub fn write_history(
        &self,
        root: &Path,
        identity: &OrderedHistoryIdentity,
        materials: &[OrderedHistoryHeightMaterial],
    ) {
        std::fs::create_dir(root).unwrap();
        let identity_bytes: Vec<u8> = encode_ordered_history_identity(identity).unwrap();
        std::fs::write(root.join("identity.bin"), &identity_bytes).unwrap();
        std::fs::write(root.join("chunk-size.bin"), 1_048_576u32.to_be_bytes()).unwrap();
        for material in materials {
            let height_root: PathBuf =
                root.join(format!("height-{:020}", material.descriptor.height));
            std::fs::create_dir(&height_root).unwrap();
            std::fs::write(
                height_root.join("descriptor.bin"),
                encode_ordered_history_height_descriptor(&material.descriptor).unwrap(),
            )
            .unwrap();
            for (kind, bytes) in &material.components {
                let component_root: PathBuf =
                    height_root.join(format!("component-{:02}", *kind as u16));
                std::fs::create_dir(&component_root).unwrap();
                for (index, chunk) in bytes.chunks(1_048_576).enumerate() {
                    let offset: usize = index.checked_mul(1_048_576).unwrap();
                    std::fs::write(
                        component_root.join(format!("chunk-{offset:020}.bin")),
                        chunk,
                    )
                    .unwrap();
                }
            }
        }
        std::fs::write(root.join("complete"), identity_bytes).unwrap();
    }
}

pub fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(root)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            if entry.file_name() == ".cut-staging-v1" {
                return None;
            }
            Some((
                entry.file_name().into_string().unwrap(),
                std::fs::read(entry.path()).unwrap(),
            ))
        })
        .collect()
}
pub fn copy_files(source: &Path, target: &Path) {
    for (name, bytes) in files(source) {
        std::fs::write(target.join(name), bytes).unwrap();
    }
}
