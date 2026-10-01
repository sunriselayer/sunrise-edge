//! DR-0169 routing/admission tests. A production-validated signed-v3 genesis
//! pins a real bonded committee and matching generic fee ABI. These adapter
//! tests drive only empty ordered windows; full economic/control histories
//! remain in the real PG operator fixture.
use super::*;
use crate::ordered_economics::{OrderedEconomicsState, certified_ordered_economics_router};
use abi::call_values::{CallValue, encode_call_value};
use abi::package_types::{PackageOrigin, ScopedTypeArg, ScopedTypeTag, derive_scoped_type_id};
use bonds::{BondResourceConfig, BondResourceId};
use consensus::{ConsensusMessage, ConsensusSigner, ConsensusVote, QuorumCertificate};
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
use node_core::fast_path::{
    FastPathEd25519Verifier, FastPathValidatorEntry, FastPathValidatorSetRecord,
};
use node_core::genesis::{
    GenesisInstallOutcome, GenesisManifest, GenesisObjectEntry, genesis_manifest_commitment,
    genesis_manifest_signing_frame, install_genesis,
};
use node_core::logical_generation::CommitmentProfile;
use node_core::ordered_economics::*;
use node_wire::ordered_history::*;
use objects::{ProtocolCustodyPurpose, ProtocolCustodyScope};
use std::collections::BTreeSet;
use validator_set::{ValidatorInfo, ValidatorSet};

struct CountedSigner {
    key: SigningKey,
    calls: Arc<AtomicUsize>,
}

impl CountedSigner {
    fn new(calls: Arc<AtomicUsize>) -> Self {
        Self {
            key: SigningKey::from([7; 32]),
            calls,
        }
    }
}

impl ConsensusSigner for CountedSigner {
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

struct TrackedStore {
    inner: MemoryDurableStateStore,
    reads: AtomicUsize,
    writes: AtomicUsize,
    contexts: Mutex<Vec<DurableOperationContext>>,
    keys: Mutex<BTreeSet<Vec<u8>>>,
}

impl TrackedStore {
    fn new(domain: AtomicityDomainId) -> Self {
        Self {
            inner: MemoryDurableStateStore::new_bound(
                domain,
                WriterFenceGeneration::new(3).unwrap(),
            ),
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            contexts: Mutex::new(Vec::new()),
            keys: Mutex::new(BTreeSet::new()),
        }
    }
    fn snapshot(
        &self,
        domain: AtomicityDomainId,
        fence: WriterFenceGeneration,
    ) -> Vec<(Vec<u8>, StateRevision, Option<Vec<u8>>)> {
        let context: DurableOperationContext = live_operation_context(fence, 0xe1);
        self.keys
            .lock()
            .unwrap()
            .iter()
            .map(|key| {
                let row: VersionedStateValue = self
                    .inner
                    .get_versioned_durable(&context, domain, key)
                    .unwrap();
                (key.clone(), row.revision(), row.value().map(<[u8]>::to_vec))
            })
            .collect()
    }
    fn reset_reads(&self) {
        self.reads.store(0, Ordering::SeqCst);
        self.contexts.lock().unwrap().clear();
    }
}

impl DurableDomainStateStore for TrackedStore {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.contexts.lock().unwrap().push(*context);
        self.keys.lock().unwrap().insert(key.to_vec());
        self.inner.get_versioned_durable(context, domain, key)
    }
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.writes.fetch_add(1, Ordering::SeqCst);
        for mutation in transaction.mutations() {
            self.keys.lock().unwrap().insert(mutation.key().to_vec());
        }
        self.inner.commit_durable(context, transaction)
    }
}

impl StructuredDurableDomainStateStore for TrackedStore {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.contexts.lock().unwrap().push(*context);
        self.inner.get_object_head(context, domain, object_id)
    }
    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.contexts.lock().unwrap().push(*context);
        self.inner
            .get_object_version(context, domain, object_id, object_version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.contexts.lock().unwrap().push(*context);
        self.inner.get_request_receipt(context, domain, request_id)
    }
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if let Some(state) = transaction.state() {
            for mutation in state.mutations() {
                self.keys.lock().unwrap().insert(mutation.key().to_vec());
            }
        }
        self.inner.commit_invocation(context, transaction)
    }
}

struct Fixture {
    store: Arc<TrackedStore>,
    policy: OrderedEconomicsPolicy,
    identities: Arc<CountingIndexedIdentities>,
    clock: Arc<CountingClock>,
    sign_calls: Arc<AtomicUsize>,
    executor: NativeBlockingExecutor,
}

impl Fixture {
    fn new() -> Self {
        let context: PublicationContext = PublicationContext::new(
            config().chain_id().clone(),
            config().protocol_version(),
            config().epoch(),
        )
        .unwrap();
        let domain: AtomicityDomainId = AtomicityDomainId::new([0x8d; 32]).unwrap();
        let sign_calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let signer: CountedSigner = CountedSigner::new(sign_calls.clone());
        let entry: FastPathValidatorEntry = FastPathValidatorEntry {
            id: signer.validator_id(),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: signer.validator_id().as_bytes().to_vec(),
        };
        let sender: [u8; 32] = *signer.validator_id().as_bytes();
        let origin: PackageOrigin =
            PackageOrigin::unverified(context.chain_id().clone(), sender, [0xec; 32]).unwrap();
        let package: public_standard_asset::StandardAssetPackage =
            public_standard_asset::build_package(&origin).unwrap();
        let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
            context: context.clone(),
            origin: origin.clone(),
            revision: 1,
            wasm_profile: public_standard_asset::REQUIRED_WASM_PROFILE,
            semantics: generic_object_result_semantics(&resolver(), &context).unwrap(),
            wasm: package.wasm,
            unverified_abi: package.encoded_abi,
            exports: package.exports,
            unverified_dependencies: Vec::new(),
        })
        .unwrap();
        let artifact_digest: Digest32 =
            artifact_commitment(&resolver(), &context, &artifact).unwrap();
        let publication_frame: Vec<u8> =
            publication_submission_signing_frame(&resolver(), &context, &artifact, 0, [0xec; 32])
                .unwrap();
        let publication: PublicationSubmission = PublicationSubmission::new(
            [0xec; 32],
            PublicationRequest::new(
                artifact,
                0,
                artifact_digest,
                signer.key.sign(&publication_frame).into(),
            ),
        )
        .unwrap();
        let code: UnverifiedDependencyRef =
            UnverifiedDependencyRef::new(origin.clone(), 1, context.clone(), artifact_digest)
                .unwrap();
        // All roles pin this signed creator, exact profile-4 code, and the
        // production-derived instance target. Shape-only fee fixtures cannot
        // authenticate a signed genesis or its actual fee ABI.
        let initializer: InstanceRecord = InstanceRecord {
            context: context.clone(),
            creator: sender,
            seed: [0xed; 32],
            code: code.clone(),
            revision: 1,
            initializer: "init".to_owned(),
        };
        let intent: LocalExecutionIntent = LocalExecutionIntent {
            mode: LocalExecutionMode::Instantiate,
            policy_digest: LocalExecutionPolicy::generic_object_results(context.clone())
                .digest(&resolver())
                .unwrap(),
            call: CallIntent {
                context: context.clone(),
                request_id: [0xee; 32],
                sender,
                nonce: 0,
                code: code.clone(),
                instance: instance_target(&resolver(), &initializer).unwrap(),
                entrypoint: "init".to_owned(),
                type_arguments: Vec::new(),
                access: AccessManifest {
                    entries: Vec::new(),
                },
                arguments: Vec::new(),
                gas_limit: 500_000,
            },
            authorizations: Vec::new(),
        };
        let frame: Vec<u8> = local_execution_signing_frame(&context, &intent).unwrap();
        let initialization: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
            intent,
            signature: signer.key.sign(&frame).into(),
        };
        let definition_id: ObjectId = ObjectId::new([0xe8; 32]);
        let bond_id: ObjectId = ObjectId::new([0xe9; 32]);
        let definition_type: ScopedTypeTag =
            public_standard_asset::definition_type_tag(&origin).unwrap();
        let coin_type: ScopedTypeTag =
            public_standard_asset::coin_type_tag(&origin, &definition_id).unwrap();
        let (resource_domain, resource): (u16, [u8; 32]) = match coin_type.args() {
            [ScopedTypeArg::Opaque { domain, value }] => (*domain, *value),
            _ => panic!("fixture fee type must declare one opaque resource"),
        };
        let resource_id: BondResourceId = BondResourceId::new(resource_domain, resource).unwrap();
        let fee_policy: PaidFeePolicy = PaidFeePolicy {
            context: context.clone(),
            base_policy_digest: initialization.intent.policy_digest,
            instance: initialization.intent.call.instance.clone(),
            code: code.clone(),
            reserve_entrypoint: "reserve".to_owned(),
            reserve_all_entrypoint: "reserve_all".to_owned(),
            settle_entrypoint: "settle".to_owned(),
            type_arguments: vec![public_standard_asset::asset_type_argument(&definition_id)],
            asset_type: coin_type.clone(),
            reservation_type: public_standard_asset::reservation_type_tag(&origin, &definition_id)
                .unwrap(),
            schema: public_standard_asset::SCHEMA_VERSION,
            fee_recipient: sender,
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
        let economics_policy: FastPathEconomicsPolicy = FastPathEconomicsPolicy {
            context: context.clone(),
            resources: vec![FastPathEconomicsResourcePolicy {
                resource_id,
                context: context.clone(),
                instance: initialization.intent.call.instance.clone(),
                code: code.clone(),
                ty: coin_type.clone(),
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
        let objects: Vec<GenesisObjectEntry> = vec![
            GenesisObjectEntry {
                object: Object {
                    id: definition_id,
                    version: 1,
                    owner: Owner::Address(Address::new(sender)),
                    type_hash: derive_scoped_type_id(
                        &resolver(),
                        context.epoch(),
                        &definition_type,
                    )
                    .unwrap(),
                    schema_version: public_standard_asset::SCHEMA_VERSION,
                    data: public_standard_asset::definition_body().unwrap(),
                },
                authority: ObjectAuthority {
                    object_id: definition_id,
                    instance_context: context.clone(),
                    instance: initialization.intent.call.instance.clone(),
                    code: code.clone(),
                    ty: definition_type,
                },
            },
            GenesisObjectEntry {
                object: Object {
                    id: bond_id,
                    version: 1,
                    owner: Owner::ProtocolCustody(ProtocolCustodyScope {
                        purpose: ProtocolCustodyPurpose::BondCollateral,
                        chain_id: context.chain_id().clone(),
                        subject: sender,
                        resource,
                    }),
                    type_hash: derive_scoped_type_id(&resolver(), context.epoch(), &coin_type)
                        .unwrap(),
                    schema_version: public_standard_asset::SCHEMA_VERSION,
                    data: encode_call_value(
                        &public_standard_asset::coin_body_layout(),
                        &CallValue::U64(100),
                    )
                    .unwrap(),
                },
                authority: ObjectAuthority {
                    object_id: bond_id,
                    instance_context: context.clone(),
                    instance: initialization.intent.call.instance.clone(),
                    code,
                    ty: coin_type,
                },
            },
        ];
        let mut manifest: GenesisManifest = GenesisManifest {
            genesis_authority: sender,
            publication,
            initialization,
            fee_policy,
            economics_policy,
            objects,
            validator_set: FastPathValidatorSetRecord {
                context: context.clone(),
                validators: vec![entry.clone()],
            },
            commitment_profile: CommitmentProfile::LogicalGenerationV2,
            minimum_freeze_block_height: 1,
            signature: [0; 64],
        };
        manifest.signature = signer
            .key
            .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
            .into();
        let set: ValidatorSet = ValidatorSet::new(
            context.epoch(),
            vec![ValidatorInfo {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key,
            }],
        )
        .unwrap();
        let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::new(
            context,
            domain,
            genesis_manifest_commitment(&resolver(), &manifest).unwrap(),
            Some(&manifest),
            set,
            resolver(),
        )
        .unwrap();
        let store: Arc<TrackedStore> = Arc::new(TrackedStore::new(domain));
        let operation: DurableOperationContext =
            live_operation_context(WriterFenceGeneration::new(3).unwrap(), 0xe3);
        assert!(matches!(
            install_genesis(
                store.as_ref(),
                &operation,
                domain,
                &resolver(),
                &manifest,
                0
            )
            .unwrap(),
            GenesisInstallOutcome::FreshInstall { .. }
        ));
        assert!(matches!(
            install_genesis(
                store.as_ref(),
                &operation,
                domain,
                &resolver(),
                &manifest,
                0
            )
            .unwrap(),
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));
        store.reset_reads();
        store.writes.store(0, Ordering::SeqCst);
        sign_calls.store(0, Ordering::SeqCst);
        Self {
            store,
            policy,
            identities: Arc::new(CountingIndexedIdentities::default()),
            clock: Arc::new(CountingClock::new(10_000)),
            sign_calls,
            executor: NativeBlockingExecutor::new(NativeBlockingPolicy::new(
                NonZeroUsize::new(1).unwrap(),
            )),
        }
    }
    fn state(
        &self,
        fence: WriterFenceGeneration,
        cancellation: Option<Arc<dyn InvocationCancellation>>,
    ) -> OrderedEconomicsState<TrackedStore, CountingClock, CountingIndexedIdentities, CountedSigner>
    {
        OrderedEconomicsState {
            store: self.store.clone(),
            clock: self.clock.clone(),
            identities: self.identities.clone(),
            domain: self.policy.domain(),
            writer_fence: fence,
            operation_timeout: Duration::from_secs(30),
            policy: self.policy.clone(),
            resolver: resolver(),
            history: Vec::new(),
            leg_policy: LocalExecutionPolicy::generic_object_results(self.policy.context().clone()),
            engine: Arc::new(execution::LocalWasmExecutionEngine::new()),
            blobs: Arc::new(MemoryBlobStore::default()),
            signer: CountedSigner::new(self.sign_calls.clone()),
            blocking_executor: self.executor.clone(),
            cancellation,
        }
    }
    fn app(&self) -> Router {
        certified_ordered_economics_router(self.state(WriterFenceGeneration::new(3).unwrap(), None))
    }
    fn advertised_identity(&self) -> OrderedHistoryIdentity {
        OrderedHistoryIdentity {
            context: self.policy.context().clone(),
            domain: self.policy.domain(),
            genesis_digest: self.policy.genesis_digest(),
            anchor: self.policy.anchor(),
            through_height: 1,
            through_view: 1,
            through_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xea; 32]),
        }
    }
    fn complete_empty_history(&self) {
        let state = self.state(WriterFenceGeneration::new(3).unwrap(), None);
        let context: DurableOperationContext = live_operation_context(state.writer_fence, 0xe2);
        let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
            policy: &state.policy,
            resolver: &state.resolver,
            history: &state.history,
            leg_policy: &state.leg_policy,
            engine: state.engine.as_ref(),
            blobs: state.blobs.as_ref(),
        };
        install_ordered_genesis(self.store.as_ref(), &context, &env, 10_000).unwrap();
        for view in 1..=5 {
            let proposal: OrderedProposal =
                propose(self.store.as_ref(), &context, &env, None, &state.signer).unwrap();
            assert_eq!(proposal.proposal.view, view);
            let output: OrderedEventOutput = process_proposal(
                self.store.as_ref(),
                &context,
                &env,
                &proposal,
                &state.signer,
            )
            .unwrap();
            let votes: Vec<ConsensusVote> = output
                .messages
                .into_iter()
                .filter_map(|message| match message {
                    ConsensusMessage::Vote(vote) => Some(vote),
                    _ => None,
                })
                .collect();
            let certificate: QuorumCertificate = state
                .policy
                .engine()
                .certificate_from_votes(&proposal.proposal, &votes, &FastPathEd25519Verifier)
                .unwrap()
                .unwrap();
            process_certificate(self.store.as_ref(), &context, &env, &certificate).unwrap();
        }
        self.store.reset_reads();
        self.sign_calls.store(0, Ordering::SeqCst);
    }
    fn assert_no_access(&self) {
        assert_eq!(self.store.reads.load(Ordering::SeqCst), 0);
        assert_eq!(self.store.writes.load(Ordering::SeqCst), 0);
        assert_eq!(self.identities.calls.load(Ordering::SeqCst), 0);
        assert_eq!(self.clock.calls.load(Ordering::SeqCst), 0);
        assert_eq!(self.sign_calls.load(Ordering::SeqCst), 0);
    }
}

async fn dispatch(
    app: &Router,
    method: &str,
    path: &str,
    body: Vec<u8>,
    encoding: Option<&str>,
    media_type: &str,
) -> Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, media_type);
    if let Some(encoding) = encoding {
        builder = builder.header(header::CONTENT_ENCODING, encoding);
    }
    app.clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

async fn response_bytes(response: Response) -> Vec<u8> {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        NODE_RESULT_MEDIA_TYPE
    );
    to_bytes(response.into_body(), 1024 * 1024 + 64)
        .await
        .unwrap()
        .to_vec()
}

fn raw_component(request: &OrderedHistoryComponentRequest, kind: u16, limit: u32) -> Vec<u8> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(ORDERED_HISTORY_COMPONENT_REQUEST_TYPE_ID, 1);
    frame
        .field_bytes(
            1,
            encode_ordered_history_identity(&request.identity).unwrap(),
        )
        .unwrap();
    frame.field_u64(2, request.height).unwrap();
    frame
        .field_bytes(
            3,
            canonical_encoding::encode_digest32(&request.descriptor_digest).unwrap(),
        )
        .unwrap();
    frame.field_u16(4, kind).unwrap();
    frame.field_u64(5, request.offset).unwrap();
    frame.field_u32(6, limit).unwrap();
    frame.finish().unwrap()
}

#[tokio::test]
async fn invalid_history_requests_fail_before_identity_clock_store_and_signing() {
    let fixture: Fixture = Fixture::new();
    let app: Router = fixture.app();
    let request: OrderedHistoryHeightRequest = OrderedHistoryHeightRequest {
        identity: fixture.advertised_identity(),
        height: 1,
    };
    let body: Vec<u8> = request.encode().unwrap();
    for (path, bytes, encoding, media, expected) in [
        (
            ORDERED_HISTORY_HEIGHT_PATH,
            body.clone(),
            None,
            "text/plain",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            ORDERED_HISTORY_HEIGHT_PATH,
            body.clone(),
            Some("gzip"),
            NODE_EVENT_MEDIA_TYPE,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            ORDERED_HISTORY_HEIGHT_PATH,
            vec![0; MAX_ORDERED_HISTORY_HEIGHT_REQUEST_BYTES + 1],
            None,
            NODE_EVENT_MEDIA_TYPE,
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            ORDERED_HISTORY_HEIGHT_PATH,
            vec![1, 2, 3],
            None,
            NODE_EVENT_MEDIA_TYPE,
            StatusCode::BAD_REQUEST,
        ),
        (
            "/v1/ordered-economics/history/unknown",
            body.clone(),
            None,
            NODE_EVENT_MEDIA_TYPE,
            StatusCode::NOT_FOUND,
        ),
    ] {
        assert_eq!(
            dispatch(&app, "POST", path, bytes, encoding, media)
                .await
                .status(),
            expected
        );
    }
    let component: OrderedHistoryComponentRequest = OrderedHistoryComponentRequest {
        identity: request.identity.clone(),
        height: 1,
        descriptor_digest: request.identity.through_digest,
        kind: OrderedHistoryComponentKind::CommitProof,
        offset: 0,
        limit: 64,
    };
    for bytes in [
        raw_component(&component, 99, 64),
        raw_component(&component, 1, 0),
        raw_component(&component, 1, 1024 * 1024 + 1),
    ] {
        assert_eq!(
            dispatch(
                &app,
                "POST",
                ORDERED_HISTORY_COMPONENT_PATH,
                bytes,
                None,
                NODE_EVENT_MEDIA_TYPE
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let mut extra: CanonicalStruct =
        CanonicalStruct::new(ORDERED_HISTORY_HEIGHT_REQUEST_TYPE_ID, 1);
    extra
        .field_bytes(
            1,
            encode_ordered_history_identity(&request.identity).unwrap(),
        )
        .unwrap();
    extra.field_u64(2, 1).unwrap();
    extra.field_u16(3, 1).unwrap();
    assert_eq!(
        dispatch(
            &app,
            "POST",
            ORDERED_HISTORY_HEIGHT_PATH,
            extra.finish().unwrap(),
            None,
            NODE_EVENT_MEDIA_TYPE
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    for (body, encoding, expected) in [
        (vec![1], None, StatusCode::BAD_REQUEST),
        (Vec::new(), Some("gzip"), StatusCode::UNSUPPORTED_MEDIA_TYPE),
    ] {
        assert_eq!(
            dispatch(
                &app,
                "GET",
                ORDERED_HISTORY_SUMMARY_PATH,
                body,
                encoding,
                NODE_EVENT_MEDIA_TYPE
            )
            .await
            .status(),
            expected
        );
    }
    fixture.assert_no_access();
}

#[tokio::test]
async fn foreign_identity_and_misconfigured_host_fail_before_io() {
    let fixture: Fixture = Fixture::new();
    let app: Router = fixture.app();
    for variant in 0..6 {
        let mut identity: OrderedHistoryIdentity = fixture.advertised_identity();
        let expected: StatusCode = if variant == 0 {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        };
        match variant {
            0 => {
                identity.context = PublicationContext::new(
                    identity.context.chain_id().clone(),
                    identity.context.protocol_version(),
                    Epoch::new(8),
                )
                .unwrap()
            }
            1 => identity.domain = AtomicityDomainId::new([0xff; 32]).unwrap(),
            2 => identity.genesis_digest = identity.through_digest,
            3 => identity.anchor = identity.through_digest,
            4 => {
                identity.context = PublicationContext::new(
                    ChainId::new("foreign").unwrap(),
                    identity.context.protocol_version(),
                    identity.context.epoch(),
                )
                .unwrap()
            }
            _ => {
                identity.context = PublicationContext::new(
                    identity.context.chain_id().clone(),
                    ProtocolVersion::new(99),
                    identity.context.epoch(),
                )
                .unwrap()
            }
        }
        let request: OrderedHistoryHeightRequest = OrderedHistoryHeightRequest {
            identity,
            height: 1,
        };
        assert_eq!(
            dispatch(
                &app,
                "POST",
                ORDERED_HISTORY_HEIGHT_PATH,
                request.encode().unwrap(),
                None,
                NODE_EVENT_MEDIA_TYPE
            )
            .await
            .status(),
            expected
        );
    }
    let mut state = fixture.state(WriterFenceGeneration::new(3).unwrap(), None);
    state.domain = AtomicityDomainId::new([0xfb; 32]).unwrap();
    let app: Router = certified_ordered_economics_router(state);
    assert_eq!(
        dispatch(
            &app,
            "GET",
            ORDERED_HISTORY_SUMMARY_PATH,
            Vec::new(),
            None,
            NODE_EVENT_MEDIA_TYPE
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    fixture.assert_no_access();
}

#[tokio::test]
async fn genuine_history_source_is_bounded_read_only_and_uses_fresh_contexts() {
    let fixture: Fixture = Fixture::new();
    fixture.complete_empty_history();
    let before = fixture.store.snapshot(
        fixture.policy.domain(),
        WriterFenceGeneration::new(3).unwrap(),
    );
    let writes: usize = fixture.store.writes.load(Ordering::SeqCst);
    let app: Router = fixture.app();
    let bytes: Vec<u8> = response_bytes(
        dispatch(
            &app,
            "GET",
            ORDERED_HISTORY_SUMMARY_PATH,
            Vec::new(),
            None,
            NODE_EVENT_MEDIA_TYPE,
        )
        .await,
    )
    .await;
    let summary: OrderedHistorySummary = decode_ordered_history_summary(&bytes).unwrap();
    assert_eq!(summary.identity.through_height, 3);
    let request: OrderedHistoryHeightRequest = OrderedHistoryHeightRequest {
        identity: summary.identity.clone(),
        height: 1,
    };
    let bytes: Vec<u8> = response_bytes(
        dispatch(
            &app,
            "POST",
            ORDERED_HISTORY_HEIGHT_PATH,
            request.encode().unwrap(),
            None,
            NODE_EVENT_MEDIA_TYPE,
        )
        .await,
    )
    .await;
    let descriptor: OrderedHistoryHeightDescriptor =
        decode_ordered_history_height_descriptor(&bytes).unwrap();
    assert_eq!(descriptor.components.len(), 1);
    let mut chunk_request: OrderedHistoryComponentRequest = OrderedHistoryComponentRequest {
        identity: summary.identity.clone(),
        height: 1,
        descriptor_digest: ordered_history_descriptor_digest(&fixture.policy, &descriptor).unwrap(),
        kind: OrderedHistoryComponentKind::CommitProof,
        offset: 0,
        limit: 512,
    };
    let mut assembled: Vec<u8> = Vec::new();
    while chunk_request.offset < descriptor.components[0].length {
        let bytes: Vec<u8> = response_bytes(
            dispatch(
                &app,
                "POST",
                ORDERED_HISTORY_COMPONENT_PATH,
                chunk_request.encode().unwrap(),
                None,
                NODE_EVENT_MEDIA_TYPE,
            )
            .await,
        )
        .await;
        let chunk: OrderedHistoryChunkResponse =
            OrderedHistoryChunkResponse::decode(&bytes).unwrap();
        assert_eq!(chunk.offset, chunk_request.offset);
        assert_eq!(chunk.total_length, descriptor.components[0].length);
        assert!(chunk.chunk_bytes.len() <= 512);
        assembled.extend(chunk.chunk_bytes);
        chunk_request.offset = u64::try_from(assembled.len()).unwrap();
    }
    assert_eq!(
        ordered_history_component_digest(&fixture.policy, &assembled).unwrap(),
        descriptor.components[0].digest
    );
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(fixture.policy.clone(), summary.identity).unwrap();
    verifier
        .verify_next_height(&OrderedHistoryHeightMaterial {
            descriptor,
            components: vec![(OrderedHistoryComponentKind::CommitProof, assembled)],
        })
        .unwrap();
    assert_eq!(verifier.height(), 1);
    assert!(verifier.finish().is_err());
    assert_eq!(fixture.store.writes.load(Ordering::SeqCst), writes);
    assert_eq!(fixture.sign_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.store.snapshot(
            fixture.policy.domain(),
            WriterFenceGeneration::new(3).unwrap()
        ),
        before
    );
    let contexts = fixture.store.contexts.lock().unwrap();
    let correlations: BTreeSet<StorageCorrelationId> = contexts
        .iter()
        .map(|context| context.correlation_id())
        .collect();
    assert_eq!(
        correlations.len(),
        fixture.identities.calls.load(Ordering::SeqCst)
    );
    assert!(correlations.len() > 2);
    for context in contexts.iter() {
        assert_eq!(
            context.writer_fence(),
            WriterFenceGeneration::new(3).unwrap()
        );
        assert_eq!(context.deadline(), StorageDeadline::new(40_000).unwrap());
    }
}

#[tokio::test]
async fn stale_writer_same_boot_and_reconstructed_router_fail_with_live_positive_control() {
    let fixture: Fixture = Fixture::new();
    fixture.complete_empty_history();
    let app: Router = fixture.app();
    fixture
        .store
        .inner
        .set_active_writer_fence(WriterFenceGeneration::new(4).unwrap());
    for app in [app, fixture.app()] {
        assert_eq!(
            dispatch(
                &app,
                "GET",
                ORDERED_HISTORY_SUMMARY_PATH,
                Vec::new(),
                None,
                NODE_EVENT_MEDIA_TYPE
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    let writes: usize = fixture.store.writes.load(Ordering::SeqCst);
    let app: Router = certified_ordered_economics_router(
        fixture.state(WriterFenceGeneration::new(4).unwrap(), None),
    );
    let bytes: Vec<u8> = response_bytes(
        dispatch(
            &app,
            "GET",
            ORDERED_HISTORY_SUMMARY_PATH,
            Vec::new(),
            None,
            NODE_EVENT_MEDIA_TYPE,
        )
        .await,
    )
    .await;
    assert_eq!(
        decode_ordered_history_summary(&bytes)
            .unwrap()
            .identity
            .through_height,
        3
    );
    assert_eq!(fixture.store.writes.load(Ordering::SeqCst), writes);
    assert_eq!(fixture.sign_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn history_cancellation_and_shared_admission_never_reach_store() {
    let fixture: Fixture = Fixture::new();
    let cancellation: Arc<dyn InvocationCancellation> = Arc::new(StepCancellation {
        cancel_at_call: 2,
        calls: AtomicUsize::new(0),
    });
    let app: Router = certified_ordered_economics_router(
        fixture.state(WriterFenceGeneration::new(3).unwrap(), Some(cancellation)),
    );
    assert_eq!(
        dispatch(
            &app,
            "GET",
            ORDERED_HISTORY_SUMMARY_PATH,
            Vec::new(),
            None,
            NODE_EVENT_MEDIA_TYPE
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(fixture.store.reads.load(Ordering::SeqCst), 0);
    let identity_calls: usize = fixture.identities.calls.load(Ordering::SeqCst);
    let clock_calls: usize = fixture.clock.calls.load(Ordering::SeqCst);
    let permit = fixture.executor.try_acquire().unwrap();
    let app: Router = fixture.app();
    let response: Response = dispatch(
        &app,
        "GET",
        ORDERED_HISTORY_SUMMARY_PATH,
        Vec::new(),
        None,
        NODE_EVENT_MEDIA_TYPE,
    )
    .await;
    // Exhausted shared admission preserves the adapter's existing 429
    // contract. A cancellation or a fenced storage stop is separately 503.
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "blocking-capacity-exhausted"
    );
    drop(permit);
    assert_eq!(fixture.store.reads.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.writes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.sign_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.identities.calls.load(Ordering::SeqCst),
        identity_calls
    );
    assert_eq!(fixture.clock.calls.load(Ordering::SeqCst), clock_calls);
    fixture.complete_empty_history();
    response_bytes(
        dispatch(
            &fixture.app(),
            "GET",
            ORDERED_HISTORY_SUMMARY_PATH,
            Vec::new(),
            None,
            NODE_EVENT_MEDIA_TYPE,
        )
        .await,
    )
    .await;
}

#[tokio::test]
async fn changed_descriptor_absent_component_bad_offset_and_corrupt_archive_refuse() {
    let fixture: Fixture = Fixture::new();
    fixture.complete_empty_history();
    let app: Router = fixture.app();
    let bytes: Vec<u8> = response_bytes(
        dispatch(
            &app,
            "GET",
            ORDERED_HISTORY_SUMMARY_PATH,
            Vec::new(),
            None,
            NODE_EVENT_MEDIA_TYPE,
        )
        .await,
    )
    .await;
    let summary: OrderedHistorySummary = decode_ordered_history_summary(&bytes).unwrap();
    let height_request: OrderedHistoryHeightRequest = OrderedHistoryHeightRequest {
        identity: summary.identity,
        height: 1,
    };
    let bytes: Vec<u8> = response_bytes(
        dispatch(
            &app,
            "POST",
            ORDERED_HISTORY_HEIGHT_PATH,
            height_request.encode().unwrap(),
            None,
            NODE_EVENT_MEDIA_TYPE,
        )
        .await,
    )
    .await;
    let descriptor: OrderedHistoryHeightDescriptor =
        decode_ordered_history_height_descriptor(&bytes).unwrap();
    let base: OrderedHistoryComponentRequest = OrderedHistoryComponentRequest {
        identity: height_request.identity.clone(),
        height: 1,
        descriptor_digest: ordered_history_descriptor_digest(&fixture.policy, &descriptor).unwrap(),
        kind: OrderedHistoryComponentKind::CommitProof,
        offset: 0,
        limit: 64,
    };
    for (request, status) in [
        (
            OrderedHistoryComponentRequest {
                descriptor_digest: fixture.policy.anchor(),
                ..base.clone()
            },
            StatusCode::CONFLICT,
        ),
        (
            OrderedHistoryComponentRequest {
                kind: OrderedHistoryComponentKind::Candidate,
                ..base.clone()
            },
            StatusCode::BAD_REQUEST,
        ),
        (
            OrderedHistoryComponentRequest {
                offset: descriptor.components[0].length,
                ..base
            },
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            dispatch(
                &app,
                "POST",
                ORDERED_HISTORY_COMPONENT_PATH,
                request.encode().unwrap(),
                None,
                NODE_EVENT_MEDIA_TYPE
            )
            .await
            .status(),
            status
        );
    }
    let before = fixture.store.snapshot(
        fixture.policy.domain(),
        WriterFenceGeneration::new(3).unwrap(),
    );
    let proof_key: Vec<u8> = before
        .iter()
        .find(|(key, _, _)| {
            key.windows(b"committed-proof/".len())
                .any(|part| part == b"committed-proof/")
                && key.ends_with(&1u64.to_be_bytes())
        })
        .unwrap()
        .0
        .clone();
    let context: DurableOperationContext =
        live_operation_context(WriterFenceGeneration::new(3).unwrap(), 0xe3);
    let row: VersionedStateValue = fixture
        .store
        .inner
        .get_versioned_durable(&context, fixture.policy.domain(), &proof_key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        fixture.policy.domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(proof_key.clone(), row.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(proof_key, StateMutation::Put(vec![1, 2, 3])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        fixture.store.inner.commit_durable(&context, transaction),
        DurableCommitOutcome::Committed
    );
    let writes: usize = fixture.store.writes.load(Ordering::SeqCst);
    let response: Response = dispatch(
        &app,
        "POST",
        ORDERED_HISTORY_HEIGHT_PATH,
        height_request.encode().unwrap(),
        None,
        NODE_EVENT_MEDIA_TYPE,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(fixture.store.writes.load(Ordering::SeqCst), writes);
    assert_eq!(fixture.sign_calls.load(Ordering::SeqCst), 0);
}
