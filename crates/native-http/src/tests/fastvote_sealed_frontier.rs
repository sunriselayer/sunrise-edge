//! DR-0187 M1: genuine positive-then-Sealed cached-response proof for the
//! two native-http read-only FastVote routes that expose cached signing
//! output (frontier page, drain signer progress).
//!
//! Every cached value is produced by the real public node-core producers
//! (`advance_frozen_frontier`, `ingest_drain_signer_page`) over a genuinely
//! committed `Freeze`, reached through the real public ordered-economics
//! engine (`install_genesis`, `install_ordered_genesis`, `propose`,
//! `process_proposal`, `process_certificate`) with a one-validator quorum --
//! never a raw storage row. Only the Sealed barrier itself is installed
//! through the narrow `OutgoingSealRepository::commit_seal_completion`
//! capability, on the exact same already-live store/router. This is a
//! storage-level barrier-path control, not proof of protocol Seal acceptance.
use super::fastvote_router::fastvote_fee_policy;
use super::*;
use crate::fastvote::certified_fastvote_router;
use abi::call_values::{CallValue, encode_call_value};
use abi::package_types::{PackageOrigin, ScopedTypeArg, ScopedTypeTag, derive_scoped_type_id};
use bonds::{BondResourceConfig, BondResourceId};
use consensus::{
    ConsensusMessage, ConsensusSigner, ConsensusVote, FrozenFrontierPage, FrozenFrontierVote,
    QuorumCertificate, decode_frozen_frontier_page, decode_frozen_frontier_vote,
};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::{
    InstanceRecord, LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy,
    ObjectAuthority, SignedLocalExecutionIntent, generic_object_result_semantics, instance_target,
    local_execution_signing_frame,
};
use execution::paid_execution::{MIN_RESERVE_ALLOWANCE, MIN_SETTLE_ALLOWANCE, PaidFeePolicy};
use execution::publication::{
    ArtifactParts, CodeArtifact, PublicationContext, PublicationRequest, PublicationSubmission,
    UnverifiedDependencyRef, artifact_commitment, publication_submission_signing_frame,
};
use fees::{Amount, GasSchedule};
use node_core::economics::{FastPathEconomicsPolicy, FastPathEconomicsResourcePolicy};
use node_core::fast_path::{FastPathValidatorEntry, FastPathValidatorSetRecord};
use node_core::genesis::{
    GenesisInstallOutcome, GenesisManifest, GenesisObjectEntry, VerifiedGenesisRoot,
    encode_genesis_manifest, genesis_manifest_commitment, genesis_manifest_signing_frame,
    install_genesis,
};
use node_core::logical_generation::CommitmentProfile;
use node_core::ordered_economics::{
    AdmissionClosureRecord, DrainSignerProgress, FreezeIntent, FrozenFrontierStep,
    OrderedCandidate, OrderedEconomicsEnvironment, OrderedEconomicsPolicy, OrderedEventOutput,
    OrderedOperationKind, OrderedOutcome, OrderedProposal, advance_frozen_frontier,
    decode_admission_closure_record, encode_freeze_intent, install_ordered_genesis,
    process_certificate, process_proposal, propose, query_ordered_outcome,
    read_drain_signer_progress, read_frozen_frontier_page,
};
use objects::{ProtocolCustodyPurpose, ProtocolCustodyScope};
use runtime::portable::{DurablePortableSnapshotRepository, PortableSnapshotToken};
use runtime::{OutgoingBarrier, OutgoingSealRepository, SealBarrier, TransitionHistoryState};

/// The genesis's one and only validator, also the frontier/drain signer and
/// the fastvote composition's own signer: one real Ed25519 key throughout,
/// so every cached value is attributable to exactly one identity.
struct GenesisSigner {
    key: SigningKey,
    calls: Arc<AtomicUsize>,
}

impl GenesisSigner {
    fn new(calls: Arc<AtomicUsize>) -> Self {
        Self {
            key: SigningKey::from([0x31; 32]),
            calls,
        }
    }
}

impl ConsensusSigner for GenesisSigner {
    fn validator_id(&self) -> ValidatorId {
        ValidatorId::new(VerificationKey::from(&self.key).into())
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let bytes: [u8; 64] = self.key.sign(framed).into();
        Ok(bytes.to_vec())
    }
}

fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([0x8B; 32]).unwrap()
}

fn full_snapshot(
    store: &MemoryDurableStateStore,
    domain: AtomicityDomainId,
    operation: &DurableOperationContext,
) -> Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> {
    use runtime::portable::{
        DurableCollection, DurablePortableRepository, DurableRecordChunkOutcome,
        DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordKey, DurableRecordScan,
    };
    let mut rows: Vec<(DurableRecordDescriptor, Vec<u8>)> = Vec::new();
    for collection in [
        DurableCollection::State,
        DurableCollection::Receipts,
        DurableCollection::ObjectHeads,
        DurableCollection::ObjectVersions,
    ] {
        let mut after: Option<DurableRecordKey> = None;
        loop {
            let scan: DurableRecordScan =
                DurableRecordScan::new(collection, after.clone(), NonZeroUsize::new(128).unwrap())
                    .unwrap();
            let page = store.scan_portable_keys(operation, domain, &scan).unwrap();
            for key in page.keys() {
                let descriptor: DurableRecordDescriptor = store
                    .read_portable_descriptor(operation, domain, key)
                    .unwrap()
                    .unwrap();
                let mut bytes: Vec<u8> = Vec::new();
                if descriptor.payload_length().is_some() {
                    loop {
                        let request: DurableRecordChunkRequest = DurableRecordChunkRequest::new(
                            descriptor.clone(),
                            bytes.len(),
                            NonZeroUsize::new(1024 * 1024).unwrap(),
                        )
                        .unwrap();
                        let outcome: DurableRecordChunkOutcome = store
                            .read_portable_chunk(operation, domain, &request)
                            .unwrap();
                        let chunk = match outcome {
                            DurableRecordChunkOutcome::Chunk(chunk) => chunk,
                            DurableRecordChunkOutcome::Changed => panic!("unexpected"),
                        };
                        bytes.extend_from_slice(chunk.bytes());
                        if chunk.is_last() {
                            break;
                        }
                    }
                }
                rows.push((descriptor, bytes));
            }
            after = page.continuation().cloned();
            if after.is_none() {
                break;
            }
        }
    }
    rows
}

fn signed_genesis_manifest(key: &SigningKey) -> GenesisManifest {
    let sender: [u8; 32] = VerificationKey::from(key).into();
    let publication_context: PublicationContext = PublicationContext::new(
        config().chain_id().clone(),
        config().protocol_version(),
        config().epoch(),
    )
    .unwrap();
    let origin: PackageOrigin =
        PackageOrigin::unverified(publication_context.chain_id().clone(), sender, [0xB1; 32])
            .unwrap();
    let package: public_standard_asset::StandardAssetPackage =
        public_standard_asset::build_package(&origin).unwrap();
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: publication_context.clone(),
        origin: origin.clone(),
        revision: 1,
        wasm_profile: public_standard_asset::REQUIRED_WASM_PROFILE,
        semantics: generic_object_result_semantics(&resolver(), &publication_context).unwrap(),
        wasm: package.wasm,
        unverified_abi: package.encoded_abi,
        exports: package.exports,
        unverified_dependencies: Vec::new(),
    })
    .unwrap();
    let artifact_digest: Digest32 =
        artifact_commitment(&resolver(), &publication_context, &artifact).unwrap();
    let publication_frame: Vec<u8> = publication_submission_signing_frame(
        &resolver(),
        &publication_context,
        &artifact,
        0,
        [0xB2; 32],
    )
    .unwrap();
    let publication: PublicationSubmission = PublicationSubmission::new(
        [0xB2; 32],
        PublicationRequest::new(
            artifact,
            0,
            artifact_digest,
            key.sign(&publication_frame).into(),
        ),
    )
    .unwrap();
    let code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        origin.clone(),
        1,
        publication_context.clone(),
        artifact_digest,
    )
    .unwrap();
    let initializer = InstanceRecord {
        context: publication_context.clone(),
        creator: sender,
        seed: [0xB3; 32],
        code: code.clone(),
        revision: 1,
        initializer: "init".to_owned(),
    };
    let call_context: PublicationContext = publication_context.clone();
    let call_instance = instance_target(&resolver(), &initializer).unwrap();
    let request_id: [u8; 32] = [0xB4; 32];
    let nonce: u64 = 0;
    let entrypoint: String = "init".to_owned();
    let access: AccessManifest = AccessManifest {
        entries: Vec::new(),
    };
    let call_intent: CallIntent = CallIntent {
        context: call_context,
        request_id,
        sender,
        nonce,
        code: code.clone(),
        instance: call_instance,
        entrypoint,
        type_arguments: Vec::new(),
        access,
        arguments: Vec::new(),
        gas_limit: 500_000,
    };
    let policy_digest: Digest32 =
        LocalExecutionPolicy::generic_object_results(publication_context.clone())
            .digest(&resolver())
            .unwrap();
    let mode: LocalExecutionMode = LocalExecutionMode::Instantiate;
    let init_intent: LocalExecutionIntent = LocalExecutionIntent {
        mode,
        policy_digest,
        call: call_intent,
        authorizations: Vec::new(),
    };
    let init_frame: Vec<u8> =
        local_execution_signing_frame(&publication_context, &init_intent).unwrap();
    let init_signature: [u8; 64] = key.sign(&init_frame).into();
    let initialization: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
        intent: init_intent,
        signature: init_signature,
    };
    let definition_id: ObjectId = ObjectId::new([0xB5; 32]);
    let bond_id: ObjectId = ObjectId::new([0xB6; 32]);
    let definition_type: ScopedTypeTag =
        public_standard_asset::definition_type_tag(&origin).unwrap();
    let coin_type: ScopedTypeTag =
        public_standard_asset::coin_type_tag(&origin, &definition_id).unwrap();
    let (resource_domain, resource): (u16, [u8; 32]) = match coin_type.args() {
        [ScopedTypeArg::Opaque { domain, value }] => (*domain, *value),
        _ => panic!("fixture fee type must declare one opaque resource"),
    };
    let resource_id: BondResourceId = BondResourceId::new(resource_domain, resource).unwrap();
    let gas_schedule: GasSchedule = GasSchedule {
        base_fee: 100,
        execution_price: 1,
        read_price: 0,
        write_price: 0,
        storage_price: 0,
        system_module_price: 0,
    };
    let asset_type: ScopedTypeTag = coin_type.clone();
    let reservation_type: ScopedTypeTag =
        public_standard_asset::reservation_type_tag(&origin, &definition_id).unwrap();
    let fee_instance = instance_target(&resolver(), &initializer).unwrap();
    let fee_type_arguments = vec![public_standard_asset::asset_type_argument(&definition_id)];
    let fee_schema: u32 = public_standard_asset::SCHEMA_VERSION;
    let reserve_entrypoint: String = "reserve".to_owned();
    let reserve_all_entrypoint: String = "reserve_all".to_owned();
    let settle_entrypoint: String = "settle".to_owned();
    let fee_policy: PaidFeePolicy = PaidFeePolicy {
        context: publication_context.clone(),
        base_policy_digest: policy_digest,
        instance: fee_instance.clone(),
        code: code.clone(),
        reserve_entrypoint,
        reserve_all_entrypoint,
        settle_entrypoint,
        type_arguments: fee_type_arguments,
        asset_type,
        reservation_type,
        schema: fee_schema,
        fee_recipient: sender,
        gas_schedule,
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
    let bond_config: BondResourceConfig = BondResourceConfig {
        resource_id,
        min_bond: Amount::new(100),
        enabled: true,
        unbonding_epochs: 7,
        max_validator_exposure: None,
    };
    let split_entrypoint: String = "split".to_owned();
    let transfer_entrypoint: String = "transfer".to_owned();
    let resource_policy: FastPathEconomicsResourcePolicy = FastPathEconomicsResourcePolicy {
        resource_id,
        context: publication_context.clone(),
        instance: fee_instance.clone(),
        code: code.clone(),
        ty: coin_type.clone(),
        schema: fee_schema,
        split_entrypoint,
        transfer_entrypoint,
        bond: Some(bond_config),
        fee_escrow: true,
    };
    let economics_policy: FastPathEconomicsPolicy = FastPathEconomicsPolicy {
        context: publication_context.clone(),
        resources: vec![resource_policy],
    };
    let definition_type_hash: Digest32 =
        derive_scoped_type_id(&resolver(), publication_context.epoch(), &definition_type).unwrap();
    let coin_type_hash: Digest32 =
        derive_scoped_type_id(&resolver(), publication_context.epoch(), &coin_type).unwrap();
    let definition_data: Vec<u8> = public_standard_asset::definition_body().unwrap();
    let coin_amount: Vec<u8> = encode_call_value(
        &public_standard_asset::coin_body_layout(),
        &CallValue::U64(100),
    )
    .unwrap();
    let definition_object: Object = Object {
        id: definition_id,
        version: 1,
        owner: Owner::Address(Address::new(sender)),
        type_hash: definition_type_hash,
        schema_version: fee_schema,
        data: definition_data,
    };
    let definition_authority: ObjectAuthority = ObjectAuthority {
        object_id: definition_id,
        instance_context: publication_context.clone(),
        instance: fee_instance.clone(),
        code: code.clone(),
        ty: definition_type,
    };
    let custody_scope: ProtocolCustodyScope = ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::BondCollateral,
        chain_id: publication_context.chain_id().clone(),
        subject: sender,
        resource,
    };
    let bond_object: Object = Object {
        id: bond_id,
        version: 1,
        owner: Owner::ProtocolCustody(custody_scope),
        type_hash: coin_type_hash,
        schema_version: fee_schema,
        data: coin_amount,
    };
    let bond_authority: ObjectAuthority = ObjectAuthority {
        object_id: bond_id,
        instance_context: publication_context.clone(),
        instance: fee_instance.clone(),
        code: code.clone(),
        ty: coin_type.clone(),
    };
    let objects: Vec<GenesisObjectEntry> = vec![
        GenesisObjectEntry {
            object: definition_object,
            authority: definition_authority,
        },
        GenesisObjectEntry {
            object: bond_object,
            authority: bond_authority,
        },
    ];
    let validator_id: ValidatorId = ValidatorId::new(sender);
    let validator_entry: FastPathValidatorEntry = FastPathValidatorEntry {
        id: validator_id,
        voting_power: 1,
        signature_scheme: SignatureSchemeId::Ed25519,
        public_key: sender.to_vec(),
    };
    let validator_set: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
        context: publication_context.clone(),
        validators: vec![validator_entry],
    };
    let mut manifest: GenesisManifest = GenesisManifest {
        genesis_authority: sender,
        publication,
        initialization,
        fee_policy,
        economics_policy,
        objects,
        validator_set,
        commitment_profile: CommitmentProfile::LogicalGenerationV2,
        minimum_freeze_block_height: 1,
        signature: [0; 64],
    };
    let manifest_frame: Vec<u8> = genesis_manifest_signing_frame(&manifest).unwrap();
    manifest.signature = key.sign(&manifest_frame).into();
    manifest
}

/// A `Freeze` candidate whose advisory next set is exactly the genesis's own
/// single validator (already genesis-bonded and eligible), at the next
/// epoch. `created_checkpoint` is historical-profile physical metadata only.
fn freeze_candidate(
    context: &PublicationContext,
    request_id: [u8; 32],
    validator: FastPathValidatorEntry,
) -> OrderedCandidate {
    let next_context: PublicationContext = PublicationContext::new(
        context.chain_id().clone(),
        context.protocol_version(),
        Epoch::new(context.epoch().get() + 1),
    )
    .unwrap();
    let intent: FreezeIntent = FreezeIntent {
        context: context.clone(),
        request_id,
        advisory_next_set: FastPathValidatorSetRecord {
            context: next_context,
            validators: vec![validator],
        },
    };
    OrderedCandidate {
        context: context.clone(),
        request_id,
        kind: OrderedOperationKind::Freeze,
        intent: encode_freeze_intent(&intent).unwrap(),
        created_checkpoint: 11,
    }
}

/// Drives one real propose/vote/certify/apply round through the public
/// ordered-economics engine, with the single genesis validator as both
/// leader and sole voter. `candidate: None` is a genuine empty round --
/// DR-0153's chained three-round commit rule requires two of these after a
/// business candidate (here, `Freeze`) before that candidate commits.
fn drive_round(
    store: &MemoryDurableStateStore,
    operation: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    signer: &GenesisSigner,
    candidate: Option<&OrderedCandidate>,
) -> (OrderedProposal, OrderedEventOutput) {
    let proposal: OrderedProposal = propose(store, operation, env, candidate, signer).unwrap();
    let output: OrderedEventOutput =
        process_proposal(store, operation, env, &proposal, signer).unwrap();
    assert!(output.committed.is_empty());
    let votes: Vec<ConsensusVote> = output
        .messages
        .into_iter()
        .filter_map(|message| match message {
            ConsensusMessage::Vote(vote) => Some(vote),
            _ => None,
        })
        .collect();
    let certificate: QuorumCertificate = env
        .policy
        .engine()
        .certificate_from_votes(
            &proposal.proposal,
            &votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .expect("one validator at full voting power reaches quorum");
    let applied: OrderedEventOutput =
        process_certificate(store, operation, env, &certificate).unwrap();
    (proposal, applied)
}

#[tokio::test]
async fn cached_frontier_and_drain_progress_are_genuine_before_sealing_and_blocked_after() {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
    let key: SigningKey = SigningKey::from([0x31; 32]);
    let manifest: GenesisManifest = signed_genesis_manifest(&key);
    let context: PublicationContext = manifest.context().clone();
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new_bound(domain(), fence);
    let operation: DurableOperationContext = live_operation_context(fence, 0xB7);
    let outcome: GenesisInstallOutcome =
        install_genesis(&store, &operation, domain(), &resolver(), &manifest, 0).unwrap();
    assert!(matches!(
        outcome,
        GenesisInstallOutcome::FreshInstall { .. }
    ));
    let manifest_bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    let manifest_digest: Digest32 = genesis_manifest_commitment(&resolver(), &manifest).unwrap();
    let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
        &resolver(),
        &manifest_bytes,
        manifest_digest.bytes(),
        &context,
    )
    .unwrap();
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&root, domain()).unwrap();
    let leg_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(context.clone());
    let engine: execution::LocalWasmExecutionEngine = execution::LocalWasmExecutionEngine::new();
    let blobs: MemoryBlobStore = MemoryBlobStore::default();
    let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        seal: None,
        policy: &policy,
        history: &[],
        leg_policy: &leg_policy,
        engine: &engine,
        blobs: &blobs,
    };
    install_ordered_genesis(&store, &operation, &env, 10_000).unwrap();
    let calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let signer: GenesisSigner = GenesisSigner::new(calls.clone());
    let freeze_request_id: [u8; 32] = [0xB8; 32];
    let freeze: OrderedCandidate = freeze_candidate(
        &context,
        freeze_request_id,
        FastPathValidatorEntry {
            id: signer.validator_id(),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: signer.validator_id().as_bytes().to_vec(),
        },
    );
    let (proposal, round1): (OrderedProposal, OrderedEventOutput) =
        drive_round(&store, &operation, &env, &signer, Some(&freeze));
    assert_eq!(proposal.proposal.view, 1);
    assert_eq!(proposal.proposal.height, 1);
    assert!(round1.committed.is_empty());
    assert!(
        query_ordered_outcome(&store, &operation, &env, &freeze_request_id)
            .unwrap()
            .is_none()
    );
    let freeze_block_digest: Digest32 =
        policy.engine().proposal_digest(&proposal.proposal).unwrap();
    let (child, round2): (OrderedProposal, OrderedEventOutput) =
        drive_round(&store, &operation, &env, &signer, None);
    assert_eq!(child.proposal.view, 2);
    assert_eq!(child.proposal.height, 2);
    assert!(child.proposal.transactions.is_empty());
    assert_eq!(child.proposal.justify.proposal_digest, freeze_block_digest);
    assert!(round2.committed.is_empty());
    assert!(
        query_ordered_outcome(&store, &operation, &env, &freeze_request_id)
            .unwrap()
            .is_none()
    );
    let (grandchild, round3): (OrderedProposal, OrderedEventOutput) =
        drive_round(&store, &operation, &env, &signer, None);
    assert_eq!(grandchild.proposal.view, 3);
    assert_eq!(grandchild.proposal.height, 3);
    assert!(grandchild.proposal.transactions.is_empty());
    assert_eq!(
        grandchild.proposal.justify.proposal_digest,
        policy.engine().proposal_digest(&child.proposal).unwrap()
    );
    assert_eq!(round3.committed.len(), 1);
    let freeze_outcome: &OrderedOutcome = &round3.committed[0];
    assert_eq!(freeze_outcome.request_id, freeze_request_id);
    assert_eq!(
        freeze_outcome.candidate_digest,
        policy.candidate_digest(&freeze).unwrap()
    );
    assert_eq!(freeze_outcome.block_height, proposal.proposal.height);
    assert_eq!(freeze_outcome.block_digest, freeze_block_digest);
    assert_eq!(freeze_outcome.output.responses().len(), 1);
    assert_eq!(
        freeze_outcome.output.responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    assert_eq!(
        query_ordered_outcome(&store, &operation, &env, &freeze_request_id).unwrap(),
        Some(freeze_outcome.clone())
    );
    let freeze_receipt: DurableRequestReceipt = store
        .get_request_receipt(
            &operation,
            domain(),
            DurableRequestId::new(freeze_request_id).unwrap(),
        )
        .unwrap()
        .expect("the genuine Freeze completion retains its original receipt");
    let freeze_dedup: NodeDedupRecord =
        NodeDedupRecord::decode(freeze_receipt.canonical_bytes()).unwrap();
    assert_eq!(freeze_dedup.request_id().as_bytes(), &freeze_request_id);
    assert_eq!(freeze_dedup.event_digest(), freeze_receipt.event_digest());
    assert_eq!(freeze_dedup.responses(), freeze_outcome.output.responses());
    let closures: Vec<AdmissionClosureRecord> = full_snapshot(&store, domain(), &operation)
        .iter()
        .filter_map(|(_, bytes)| decode_admission_closure_record(bytes).ok())
        .collect();
    assert_eq!(
        closures,
        vec![AdmissionClosureRecord {
            closed_epoch: context.epoch(),
            request_id: freeze_request_id,
            closed_at_block_height: proposal.proposal.height,
        }]
    );
    calls.store(0, Ordering::SeqCst);
    let finalized_vote: FrozenFrontierVote = loop {
        match advance_frozen_frontier(
            &store,
            &operation,
            domain(),
            &resolver(),
            &[],
            &context,
            &signer,
        )
        .unwrap()
        {
            FrozenFrontierStep::Finalized(vote) => break *vote,
            FrozenFrontierStep::Advanced { .. } => continue,
        }
    };
    assert_eq!(
        finalized_vote.identity.closure_request_id,
        freeze_request_id
    );
    assert_eq!(
        finalized_vote.identity.closure_height,
        freeze_outcome.block_height
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the fresh frontier is signed once"
    );
    let limit: NonZeroUsize = NonZeroUsize::new(1).unwrap();
    let (page_vote, page): (FrozenFrontierVote, FrozenFrontierPage) = read_frozen_frontier_page(
        &store,
        &operation,
        domain(),
        &resolver(),
        &[],
        &context,
        signer.validator_id(),
        None,
        limit,
    )
    .unwrap();
    assert_eq!(page_vote, finalized_vote);
    let signer_id: ValidatorId = signer.validator_id();
    let fastvote_execution: PaidExecutionComposition =
        PaidExecutionComposition::new(leg_policy.clone(), fastvote_fee_policy());
    let fastvote: FastVoteComposition =
        FastVoteComposition::new(fastvote_execution, Arc::new(signer), 1);
    let store: Arc<MemoryDurableStateStore> = Arc::new(store);
    let components: StructuredDurableNativeComponents<
        MemoryDurableStateStore,
        MemoryBlobStore,
        MemoryTransport,
        ManualClock,
        SequenceIndexedIdentities,
    > = StructuredDurableNativeComponents::new(
        store.clone(),
        Arc::new(MemoryBlobStore::default()),
        Arc::new(MemoryTransport::default()),
        Arc::new(ManualClock::new(10_000)),
        Arc::new(SequenceIndexedIdentities::default()),
    );
    let router: Router = certified_fastvote_router(
        components,
        fastvote,
        active_protocol_config(domain()),
        structured_request_authority(),
        config(),
        resolver(),
        Vec::new(),
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();
    let frontier_request: Vec<u8> = node_wire::FrozenFrontierPageRequest {
        epoch: config().epoch(),
        after_request_id: None,
        limit: 1,
    }
    .encode()
    .unwrap();
    let drain_request: Vec<u8> = node_wire::DrainSignerProgressRequest {
        epoch: config().epoch(),
        signer: signer_id,
    }
    .encode()
    .unwrap();
    calls.store(0, Ordering::SeqCst);
    let frontier_response: Response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(node_wire::FASTVOTE_FROZEN_FRONTIER_PAGE_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(frontier_request.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(frontier_response.status(), StatusCode::OK);
    let frontier_bytes: Vec<u8> = to_bytes(frontier_response.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    let frontier_wire: node_wire::FrozenFrontierPageResponse =
        node_wire::FrozenFrontierPageResponse::decode(&frontier_bytes).unwrap();
    assert_eq!(
        decode_frozen_frontier_vote(&frontier_wire.vote).unwrap(),
        finalized_vote
    );
    assert_eq!(
        decode_frozen_frontier_page(&frontier_wire.page).unwrap(),
        page
    );
    // Route-table probes alone cannot prove genuine 204 progress. The first
    // ingestion of this verified vote/page goes through the actual HTTP/core
    // handler, not a direct store call or a fabricated response.
    let signer_page_request: Vec<u8> = node_wire::DrainSignerPageRequest {
        epoch: config().epoch(),
        vote: frontier_wire.vote.clone(),
        page: frontier_wire.page.clone(),
    }
    .encode()
    .unwrap();
    let signer_page_response: Response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(node_wire::FASTVOTE_DRAIN_SIGNER_PAGE_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(signer_page_request.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(signer_page_response.status(), StatusCode::NO_CONTENT);
    assert!(
        !signer_page_response
            .headers()
            .contains_key(header::CONTENT_TYPE)
    );
    assert!(
        to_bytes(signer_page_response.into_body(), 1)
            .await
            .unwrap()
            .is_empty()
    );
    let direct_progress: DrainSignerProgress = read_drain_signer_progress(
        store.as_ref(),
        &operation,
        domain(),
        &resolver(),
        &context,
        signer_id,
    )
    .unwrap();
    assert!(direct_progress.complete);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // A completed signer frontier intentionally refuses another submission.
    // Preserve that real definite refusal instead of assuming idempotency.
    let repeated_page_response: Response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(node_wire::FASTVOTE_DRAIN_SIGNER_PAGE_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(signer_page_request))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(repeated_page_response.status(), StatusCode::CONFLICT);
    assert_eq!(
        repeated_page_response.headers()[header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        to_bytes(repeated_page_response.into_body(), 1024)
            .await
            .unwrap()
            .as_ref(),
        b"drain-not-ready"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let drain_response: Response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(node_wire::FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(drain_request.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(drain_response.status(), StatusCode::OK);
    let drain_bytes: Vec<u8> = to_bytes(drain_response.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    let drain_wire: node_wire::DrainSignerProgressResponse =
        node_wire::DrainSignerProgressResponse::decode(&drain_bytes).unwrap();
    assert_eq!(
        decode_frozen_frontier_vote(&drain_wire.vote).unwrap(),
        finalized_vote
    );
    assert_eq!(drain_wire.complete, direct_progress.complete);
    assert_eq!(drain_wire.signer, signer_id);
    assert_eq!(drain_wire.cursor, direct_progress.confirmed_last_request_id);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "reading an already-retained cached vote must never sign"
    );
    let token: PortableSnapshotToken = store.begin_portable_snapshot(&operation, domain()).unwrap();
    let mut seal_request: [u8; 32] = [0xB9; 32];
    seal_request[0] |= 0x80;
    let sealed: SealBarrier = SealBarrier {
        outgoing_epoch: context.epoch(),
        request: seal_request,
        height: 1,
        block_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xBA; 32]),
        target_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xBB; 32]),
        transition_history: TransitionHistoryState::Virgin,
    };
    let seal_request_id: DurableRequestId = DurableRequestId::new(sealed.request).unwrap();
    let seal_event_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0xBC; 32]);
    let seal_receipt: DurableRequestReceipt =
        DurableRequestReceipt::new(seal_request_id, seal_event_digest, vec![1]).unwrap();
    let seal_invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
        domain(),
        None,
        DurableObjectChanges::empty(),
        seal_receipt,
        None,
    )
    .unwrap();
    assert_eq!(
        store.commit_seal_completion(&operation, &token, seal_invocation, sealed),
        DurableCommitOutcome::Committed
    );
    let before_reads: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(store.as_ref(), domain(), &operation);
    let token_before_reads: PortableSnapshotToken =
        store.begin_portable_snapshot(&operation, domain()).unwrap();
    let barrier_before_reads: OutgoingBarrier =
        store.get_outgoing_barrier(&operation, domain()).unwrap();
    assert!(barrier_before_reads.is_sealed());
    let sealed_frontier_response: Response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(node_wire::FASTVOTE_FROZEN_FRONTIER_PAGE_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(frontier_request))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        sealed_frontier_response.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let sealed_frontier_body: Bytes = to_bytes(sealed_frontier_response.into_body(), 1024)
        .await
        .unwrap();
    assert!(
        std::str::from_utf8(&sealed_frontier_body)
            .unwrap()
            .contains("invalid-node-output")
    );
    let sealed_drain_response: Response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(node_wire::FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(drain_request))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        sealed_drain_response.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let sealed_drain_body: Bytes = to_bytes(sealed_drain_response.into_body(), 1024)
        .await
        .unwrap();
    assert!(
        std::str::from_utf8(&sealed_drain_body)
            .unwrap()
            .contains("invalid-node-output")
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a sealed cached-read route must never sign"
    );
    let after_reads: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(store.as_ref(), domain(), &operation);
    assert_eq!(
        before_reads, after_reads,
        "both sealed cached-read routes together must write nothing at all"
    );
    assert_eq!(
        store.begin_portable_snapshot(&operation, domain()).unwrap(),
        token_before_reads,
        "the cached-read routes must not advance protected metadata or the mutation sequence"
    );
    assert_eq!(
        store.get_outgoing_barrier(&operation, domain()).unwrap(),
        barrier_before_reads
    );
    let (post_seal_vote, post_seal_page): (FrozenFrontierVote, FrozenFrontierPage) =
        read_frozen_frontier_page(
            store.as_ref(),
            &operation,
            domain(),
            &resolver(),
            &[],
            &context,
            signer_id,
            None,
            limit,
        )
        .unwrap();
    assert_eq!(post_seal_vote, finalized_vote);
    assert_eq!(post_seal_page, page);
    let post_seal_progress: DrainSignerProgress = read_drain_signer_progress(
        store.as_ref(),
        &operation,
        domain(),
        &resolver(),
        &context,
        signer_id,
    )
    .unwrap();
    assert_eq!(post_seal_progress, direct_progress);
}
