#![forbid(unsafe_code)]

//! Deterministic, runtime-neutral ingress and persistence boundary for one node event.
//!
//! The core consumes exactly one bounded canonical event, loads one explicit state
//! value, delegates a pure transition, and conditionally persists the returned
//! state with compare-and-swap. It deliberately does not sign, send, schedule,
//! spawn, retry, or keep process-local protocol state.

use abi::AccessEntry;
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
};
use core::fmt;
use crypto::{Ed25519OwnerAddressError, Ed25519OwnerAddressPolicy, validate_ed25519_owner_address};
use execution::{
    ExecutionEffects, ExecutionEngine, ExecutionError, ExecutionStatus, Transaction,
    WasmExecutionEngine, derive_created_object_id, encode_execution_effects, hash_transaction,
};
use hashing::{HashSuiteResolver, HashingError};
use objects::{AccessMode, Address, Object, ObjectId, ObjectRef, Owner, decode_object};
use protocol_config::{DomainPlacementManifest, ProtocolConfig, ProtocolConfigError};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashPurpose, ProtocolVersion, TypeError,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, AtomicStateWriteResult,
    AtomicStateWriteSet, AtomicityDomainId, BlobStore, DomainTransactionalStateStore,
    DurableCommitOutcome, DurableCommitRejection, DurableInlineObject, DurableInvocationError,
    DurableInvocationTransaction, DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead,
    DurableObjectMutation, DurableObjectMutationEntry, DurableObjectOwnerProjection,
    DurableObjectPayload, DurableObjectVersion, DurableObjectVersionRecord,
    DurableOperationContext, DurableOutboxBatch, DurableOutboxMessage, DurableReadError,
    DurableRequestId, DurableRequestReceipt, DurableStateTransaction, IndeterminateCommitReason,
    MAX_ATOMIC_STATE_READS, MAX_ATOMIC_STATE_WRITES, MAX_STATE_KEY_BYTES, PersistenceLayout,
    Runtime, RuntimeError, StateMutation, StateMutationEntry, StateReadAssertion, StateRevision,
    StateStore, StateWrite, StructuredDurableDomainStateStore, TransactionalStateStore,
    VersionedStateValue,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use system_modules::{ModuleId, SystemModule, SystemModuleError};

mod authenticated_object_effects;
mod durable_reconciliation;
pub mod fee_effects;
pub mod local_execution;
pub mod local_instance_state;
mod object_snapshots;
pub mod paid_execution;
mod preinstalled_wasm;
pub mod publication;
mod query;
pub mod transaction_auth;

use authenticated_object_effects::{
    LoadedAuthenticatedObjects, PendingObjectCreation, translate_authenticated_object_effects,
    translate_authenticated_object_effects_with_creation,
    translate_authenticated_object_effects_with_owner_transition,
    translate_fee_only_object_effects, validate_output_owner_addresses,
};
use preinstalled_wasm::{
    check_preinstalled_module_gas_limit, normalize_trapped_preinstalled_execution,
    resolve_preinstalled_module,
};

pub use execution::{ObjectEffect, ResolvedObject};
pub use fee_effects::{
    CommittedFeePolicy, FeeChargeBodies, FeeChargeRequest, FeeCompositionError, FeeEffectComposer,
    GasScheduleShapeFault, PreinstalledFeeComposition, validate_gas_schedule_shape,
};
pub use object_snapshots::{BoundObjectSnapshots, BoundSnapshotError, load_bound_object_snapshots};
pub use preinstalled_wasm::{
    MAX_PREINSTALLED_MODULE_GAS_LIMIT, MAX_PREINSTALLED_MODULE_WASM_BYTES,
    MAX_PREINSTALLED_MODULES, MAX_PREINSTALLED_OBJECT_ACCESS_POLICIES,
    MAX_PREINSTALLED_OBJECT_CREATION_ARGS_FIELDS, MAX_PREINSTALLED_OBJECT_CREATION_POLICIES,
    MAX_PREINSTALLED_OWNER_TRANSITION_POLICIES, MAX_PREINSTALLED_SEMANTICS_BYTES,
    MAX_PREINSTALLED_TYPED_ENTRYPOINT_CONSTRUCTORS, MAX_PREINSTALLED_TYPED_ENTRYPOINT_POLICIES,
    PreinstalledModuleCatalog, PreinstalledModuleCatalogEntry, PreinstalledModuleSemanticsEnvelope,
    PreinstalledObjectAccessPolicy, PreinstalledObjectCreationPolicy,
    PreinstalledOwnerTransitionPolicy, PreinstalledTypedEntrypointPolicy,
    encode_preinstalled_object_access_policy, encode_preinstalled_object_creation_policy,
    encode_preinstalled_owner_transition_policy, encode_preinstalled_semantics_envelope,
    encode_preinstalled_typed_entrypoint_policy, reconcile_preinstalled_registry_and_catalog,
};
pub use query::{
    ObjectQueryResult, ReceiptQueryResult, query_object, query_request_receipt,
    query_sender_next_nonce,
};
pub use transaction_auth::{
    AuthenticatedTransaction, MAX_TRANSACTION_SIGNABLE_BYTES, SUBMIT_TRANSACTION_SIGNABLE_TYPE_ID,
    SUBMIT_TRANSACTION_V1_MESSAGE_TYPE, TRANSACTION_V1_MESSAGE_TYPE, TransactionAuthError,
    TrustedTransactionContext, authenticate_submit_transaction_bytes,
    authenticate_transaction_bytes, encode_submit_transaction_signable,
};

const NODE_EVENT_TYPE_ID: u16 = 0xE001;
const NODE_RESPONSE_TYPE_ID: u16 = 0xE002;
const NODE_DEDUP_RECORD_TYPE_ID: u16 = 0xE003;
const NODE_OUTBOX_BATCH_TYPE_ID: u16 = 0xE004;
const NODE_OUTBOX_DELIVERY_TYPE_ID: u16 = 0xE005;
const ENCODING_VERSION: u16 = 1;

/// Maximum UTF-8 byte length of a chain identifier accepted at node ingress.
pub const MAX_CHAIN_ID_BYTES: usize = 128;
/// Maximum canonical payload length carried by one node event or response.
pub const MAX_NODE_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum canonical state value replaced by one node-core invocation.
pub const MAX_NODE_STATE_BYTES: usize = 32 * 1024 * 1024;
/// Maximum responses or outbound messages produced by one invocation.
pub const MAX_NODE_OUTPUT_ITEMS: usize = 1_024;
/// Maximum aggregate payload bytes returned by one invocation.
pub const MAX_NODE_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
/// Maximum lease duration for one outbound delivery attempt.
pub const MAX_OUTBOX_LEASE_MILLIS: u64 = 5 * 60 * 1_000;
/// Pre-activation cap on authenticated object reads in one invocation.
///
/// Each entry costs two durable round-trips (head then version). Raising this
/// bound requires measured evidence and a decision record; see the PR83
/// design note on the `MAX_TRANSACTION_MANIFEST_ENTRIES`/
/// `MAX_DURABLE_OBJECT_READS` envelope.
const MAX_AUTHENTICATED_OBJECT_READS: usize = 32;
/// Per-object body bound applied before any hashing or decode work, to both
/// an inline body and a body fetched from a `BlobStore`.
///
/// Pre-activation admission budget, not a measured capacity limit: hashing is
/// attacker-influenced work over up to `MAX_STATE_VALUE_BYTES` (32 MiB) per
/// entry times the `MAX_AUTHENTICATED_OBJECT_READS` fan-out. Raising this
/// bound requires capacity evidence and a decision record.
pub const MAX_AUTHENTICATED_OBJECT_BODY_BYTES: usize = 1024 * 1024;
/// Aggregate body budget for one authenticated invocation, shared by every
/// inline and blob-fetched body loaded in it.
///
/// Pre-activation admission budget: bounds worst-case per-request hashing
/// work to 8 MiB, below the 16 MiB HTTP body limit already accepted by
/// `native-http`. Raising this bound requires capacity evidence and a
/// decision record.
pub const MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Fixed deterministic threshold, in exact canonical-encoded bytes, at or
/// under which a newly committed immutable object version stays inline; a
/// version whose canonical bytes exceed this threshold is instead published
/// to the supplied `BlobStore` and referenced.
///
/// This is a fixed node persistence-layout policy, not transaction input or a
/// protocol-config knob. Applying it to exact canonical bytes keeps the
/// choice deterministic without changing the object's canonical bytes,
/// digest, or logical head. It is deliberately far above ordinary small
/// object bodies (the devnet's `StandardAssetCoinV1` body is a few dozen
/// bytes) so
/// clients that require the bounded query API's inline body keep working
/// unchanged; only an object body actually large enough to justify separate
/// content-addressed storage crosses it. Raising or lowering this bound
/// requires a decision record.
pub const MAX_INLINE_OBJECT_BODY_BYTES: usize = 64 * 1024;

/// Errors returned by node-core validation, transition, and persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeCoreError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// Domain-separated event hashing failed.
    Hashing(HashingError),
    /// A decoded chain identifier was invalid.
    InvalidChainId(TypeError),
    /// A decoded hash algorithm identifier was invalid.
    InvalidHashAlgorithm(TypeError),
    /// A persisted digest had the wrong byte length.
    InvalidDigestLength(usize),
    /// A chain identifier exceeded the ingress resource bound.
    ChainIdTooLong(usize),
    /// A request identifier must not be all zeroes.
    ZeroRequestId,
    /// An outbox lease identifier must not be all zeroes.
    ZeroOutboxLeaseId,
    /// An outbox lease duration was zero or exceeded its bound.
    InvalidOutboxLeaseDuration(u64),
    /// A request identifier had the wrong encoded length.
    InvalidRequestIdLength(usize),
    /// An outbox lease identifier had the wrong encoded length.
    InvalidOutboxLeaseIdLength(usize),
    /// An event kind identifier is unknown.
    UnknownEventKind(u16),
    /// A response status identifier is unknown.
    UnknownResponseStatus(u16),
    /// The event belongs to a different chain.
    ChainMismatch {
        /// Configured chain.
        expected: ChainId,
        /// Event chain.
        actual: ChainId,
    },
    /// The event targets a different protocol version.
    ProtocolVersionMismatch {
        /// Configured protocol version.
        expected: ProtocolVersion,
        /// Event protocol version.
        actual: ProtocolVersion,
    },
    /// The event targets a different epoch.
    EpochMismatch {
        /// Configured epoch.
        expected: Epoch,
        /// Event epoch.
        actual: Epoch,
    },
    /// A persistence key was empty.
    EmptyStateKey,
    /// A transactional invocation declared no state access.
    EmptyStateAccessPlan,
    /// A transactional invocation declared too many state accesses.
    TooManyStateAccesses {
        /// Actual access count.
        count: usize,
        /// Maximum accepted access count.
        maximum: usize,
    },
    /// A transactional invocation declared the same state key twice.
    DuplicateStateAccessKey,
    /// A transactional transition returned no state updates.
    EmptyStateUpdates,
    /// A transactional transition returned too many state updates.
    TooManyStateUpdates {
        /// Actual update count.
        count: usize,
        /// Maximum accepted update count.
        maximum: usize,
    },
    /// A transactional transition returned the same state key twice.
    DuplicateStateUpdateKey,
    /// A transactional transition updated a key absent from its access plan.
    UndeclaredStateUpdate(Vec<u8>),
    /// A transactional transition attempted to update a read-only key.
    ReadOnlyStateUpdate(Vec<u8>),
    /// An application access plan attempted to claim a node-core metadata key.
    ReservedStateAccess(Vec<u8>),
    /// An event or response payload exceeded its resource bound.
    PayloadTooLarge(usize),
    /// A state value exceeded its resource bound.
    StateTooLarge(usize),
    /// Too many output items were returned by one transition.
    TooManyOutputItems {
        /// Output collection name.
        collection: &'static str,
        /// Actual item count.
        count: usize,
    },
    /// Aggregate output payload bytes exceeded their resource bound.
    OutputTooLarge(usize),
    /// The transition produced a response for another request.
    ResponseRequestMismatch {
        /// Event request identifier.
        expected: RequestId,
        /// Response request identifier.
        actual: RequestId,
    },
    /// The persisted state changed between read and conditional write.
    StateConflict,
    /// A request identifier was reused for different canonical event bytes.
    RequestIdReuse,
    /// Persisted deduplication/outbox state violated an invariant.
    PersistenceInvariant(&'static str),
    /// No persisted outbox exists for the requested invocation.
    OutboxNotFound,
    /// Another delivery attempt owns an unexpired lease.
    OutboxLeaseActive {
        /// Unix-millisecond lease deadline.
        expires_at_unix_millis: u64,
    },
    /// An acknowledgement did not match the active lease.
    OutboxLeaseMismatch,
    /// An acknowledgement did not match the next pending message index.
    OutboxIndexMismatch,
    /// Lease deadline or delivery-attempt arithmetic overflowed.
    OutboxArithmeticOverflow,
    /// A nested canonical-record item length could not be represented.
    NestedItemLengthOverflow(usize),
    /// Bytes remained after a declared nested canonical-record list.
    TrailingNestedListBytes(usize),
    /// A runtime storage operation failed.
    Runtime(RuntimeError),
    /// A durable storage read failed before a transition could commit.
    DurableRead(DurableReadError),
    /// A structured durable invocation failed validation before storage I/O.
    DurableInvocation(DurableInvocationError),
    /// Durable storage proved that the invocation did not commit.
    DurableCommitRejected(DurableCommitRejection),
    /// Durable storage could not prove whether the invocation committed.
    DurableCommitIndeterminate(IndeterminateCommitReason),
    /// Committed domain-placement configuration rejected routing.
    ProtocolConfig(ProtocolConfigError),
    /// Transaction authentication failed before any state-machine or storage work.
    TransactionAuth(TransactionAuthError),
    /// A generic handler received a transaction submission without an authenticated wrapper.
    UnauthenticatedTransactionSubmission,
    /// An authenticated transaction entrypoint received another node-event family.
    ExpectedSubmitTransaction,
    /// Ingress and committed protocol-version authorities disagreed.
    ProtocolConfigVersionMismatch {
        /// Version fixed by the node invocation configuration.
        node_config: ProtocolVersion,
        /// Version committed in protocol configuration.
        protocol_config: ProtocolVersion,
    },
    /// The application-specific state machine rejected the event.
    TransitionRejected(&'static str),
    /// A submitted transaction's declared nonce did not match the persisted
    /// next expected nonce for its sender and epoch.
    SenderNonceMismatch {
        /// Sender address bytes.
        sender: [u8; 32],
        /// Persisted next expected nonce.
        expected: u64,
        /// Nonce declared by the submitted transaction.
        actual: u64,
    },
    /// Incrementing a sender's persisted next nonce would overflow.
    SenderNonceOverflow {
        /// Sender address bytes.
        sender: [u8; 32],
    },
    /// A signed object reference named an object absent (or tombstoned) in
    /// the resolved domain.
    ObjectNotFound {
        /// Object identifier that could not be found.
        object_id: ObjectId,
    },
    /// The current object version did not match the signed reference.
    ObjectVersionMismatch {
        /// Object identifier.
        object_id: ObjectId,
        /// Version declared by the signed reference.
        expected: u64,
        /// Version observed on the current head.
        actual: u64,
    },
    /// The current object digest did not match the signed reference.
    ObjectDigestMismatch {
        /// Object identifier.
        object_id: ObjectId,
        /// Digest declared by the signed reference.
        expected: Digest32,
        /// Digest observed on the current head.
        actual: Digest32,
    },
    /// The object's typed owner did not authorize the transaction sender.
    ObjectOwnerMismatch {
        /// Object identifier.
        object_id: ObjectId,
    },
    /// An Address-owned object was loaded under a profile that requires a
    /// canonical, non-identity, prime-order Ed25519 value owner, and its
    /// owner bytes failed that policy.
    InadmissibleObjectOwnerAddress {
        /// Object carrying the rejected owner.
        object_id: ObjectId,
        /// Exact admissibility failure.
        source: Ed25519OwnerAddressError,
    },
    /// Authenticated execution returned an Address-owned object whose owner
    /// violates the profile that admitted the transaction.
    InadmissibleObjectOutputOwnerAddress {
        /// Object carrying the rejected output owner.
        object_id: ObjectId,
        /// Exact admissibility failure.
        source: Ed25519OwnerAddressError,
    },
    /// A manifest entry requested an access mode this slice cannot honor.
    ObjectAccessModeUnsupported {
        /// Object identifier.
        object_id: ObjectId,
        /// Requested access mode.
        mode: AccessMode,
    },
    /// A manifest entry named a shared or system-owned object.
    ObjectOwnerKindUnsupported {
        /// Object identifier.
        object_id: ObjectId,
    },
    /// A blob-backed payload's content digest was absent from the supplied
    /// `BlobStore`.
    ObjectBlobMissing {
        /// Object identifier.
        object_id: ObjectId,
        /// Content digest that could not be found.
        blob_digest: Digest32,
    },
    /// A blob-backed payload's fetched bytes did not hash to its own
    /// `blob_digest`, independent of the separate `ObjectBodyDigestMismatch`
    /// check against the immutable version record's `digest`.
    ObjectBlobDigestMismatch {
        /// Object identifier.
        object_id: ObjectId,
        /// Content digest the fetched bytes disagreed with.
        blob_digest: Digest32,
    },
    /// A `BlobStore::put_blob` call failed while publishing a new immutable
    /// object version's canonical bytes, staged for a request that has not
    /// yet reached `commit_invocation`. This runs strictly before
    /// `commit_invocation`, so this error means zero
    /// state/receipt/nonce/outbox/object changes were made for this
    /// request, distinct from a commit-time rejection. If more than one
    /// publication was staged, an earlier one that already succeeded is an
    /// unreachable orphan, not evidence that this request partially
    /// committed.
    ObjectBlobPublishFailed {
        /// Object identifier whose new version failed to publish.
        object_id: ObjectId,
        /// Content digest the publish attempt was keyed under.
        blob_digest: Digest32,
        /// The underlying `BlobStore` failure, including a digest/content
        /// collision, preserved rather than discarded.
        source: RuntimeError,
    },
    /// An authenticated transaction declared more object accesses than the
    /// pre-activation resource bound.
    ObjectManifestTooLarge {
        /// Declared access count.
        count: usize,
        /// Maximum accepted access count.
        maximum: usize,
    },
    /// An authenticated transaction's manifest declared the same object twice.
    DuplicateObjectAccess {
        /// Duplicated object identifier.
        object_id: ObjectId,
    },
    /// A manifest entry declared an object version that cannot be non-zero.
    InvalidObjectVersion {
        /// Object identifier.
        object_id: ObjectId,
        /// Declared version.
        version: u64,
    },
    /// Durable storage proved that an object-head assertion no longer
    /// matched and the commit did not apply.
    ObjectConflict {
        /// First conflicting object in canonical identifier order.
        object_id: ObjectId,
    },
    /// A current object head pointed at an immutable version record that
    /// storage does not have.
    ObjectRecordMissing {
        /// Object identifier.
        object_id: ObjectId,
    },
    /// A persisted immutable object-version record disagreed with its own
    /// head, or an inline object disagreed with its own version record.
    ObjectRecordMismatch {
        /// Object identifier.
        object_id: ObjectId,
    },
    /// The object's stored digest algorithm is not implemented, so this node
    /// cannot verify the body it was handed.
    ObjectDigestUnverifiable {
        /// Object identifier.
        object_id: ObjectId,
        /// Unimplemented digest algorithm recorded on the stored digest.
        algorithm: HashAlgorithmId,
    },
    /// The stored canonical body does not hash to the digest recorded for it.
    ObjectBodyDigestMismatch {
        /// Object identifier.
        object_id: ObjectId,
    },
    /// The version record's creating chain does not match the trusted event chain.
    ObjectProvenanceMismatch {
        /// Object identifier.
        object_id: ObjectId,
    },
    /// One object body — inline or fetched from a blob store — exceeded the
    /// pre-activation per-object bound, or the running aggregate total of
    /// every body (inline and blob-fetched) loaded so far in this invocation
    /// exceeded the pre-activation aggregate bound.
    ObjectBodyTooLarge {
        /// Object identifier.
        object_id: ObjectId,
        /// Actual body length, or running aggregate total, in bytes.
        actual: usize,
        /// Maximum accepted per-object or aggregate length in bytes.
        maximum: usize,
    },
    /// Deterministic execution returned two effects for the same object.
    DuplicateObjectEffect {
        /// Duplicated object identifier.
        object_id: ObjectId,
    },
    /// Deterministic execution returned more effects than one invocation permits.
    TooManyObjectEffects {
        /// Number of effects supplied by execution.
        actual: usize,
        /// Maximum accepted effects per invocation.
        maximum: usize,
    },
    /// Deterministic execution returned an effect for an undeclared object.
    UndeclaredObjectEffect {
        /// Undeclared object identifier.
        object_id: ObjectId,
    },
    /// A declared object access and its deterministic execution effect disagreed.
    ObjectEffectMismatch {
        /// Object whose declared access and effect disagreed.
        object_id: ObjectId,
        /// Stable, non-secret rejection reason.
        reason: &'static str,
    },
    /// Incrementing an object's immutable version would overflow.
    ObjectVersionOverflow {
        /// Object whose version cannot advance.
        object_id: ObjectId,
    },
    /// Object effects that create a new identity are outside this MVP slice.
    ObjectCreationUnsupported {
        /// Created object identifier.
        object_id: ObjectId,
    },
    /// A mutation effect was supplied without trusted creation context.
    ObjectMutationContextMissing {
        /// Object requiring a new immutable version.
        object_id: ObjectId,
    },
    /// A new immutable object version attempted to move its creation checkpoint backwards.
    ObjectCreatedCheckpointRegression {
        /// Object whose checkpoint would regress.
        object_id: ObjectId,
        /// Checkpoint stored on the previous immutable version.
        previous_created_checkpoint: u64,
        /// Checkpoint proposed for the new immutable version.
        attempted_created_checkpoint: u64,
    },
    /// A governance-installed system-module registry or manifest operation failed.
    SystemModules(SystemModuleError),
    /// Deterministic WASM execution or transaction hashing failed.
    Execution(ExecutionError),
    /// One preinstalled catalog entry's WASM bytes exceeded the bound.
    PreinstalledModuleWasmTooLarge {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
        /// Actual WASM byte length.
        actual: usize,
        /// Maximum accepted WASM byte length.
        maximum: usize,
    },
    /// A preinstalled catalog entry's manifest named a different module id.
    PreinstalledModuleManifestIdMismatch {
        /// Module identifier the entry is keyed under.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// A preinstalled catalog declared more module versions than the bound.
    PreinstalledModuleCatalogTooLarge {
        /// Declared entry count.
        count: usize,
        /// Maximum accepted entry count.
        maximum: usize,
    },
    /// A preinstalled catalog declared the same `(module_id, version)` twice.
    DuplicatePreinstalledModule {
        /// Duplicated module identifier.
        module_id: ModuleId,
        /// Duplicated module version.
        version: u64,
    },
    /// `Transaction.module_ref` named a `(module_id, version)` absent from the
    /// committed system-module registry.
    PreinstalledModuleUnknown {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// The registered module version exists but is not `Active`.
    PreinstalledModuleInactive {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// The registered module version is `Active` but not yet activated at the
    /// transaction's epoch.
    PreinstalledModuleNotYetActive {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
        /// Earliest activation epoch.
        activation_epoch: Epoch,
        /// Transaction epoch.
        current_epoch: Epoch,
    },
    /// The registered module version has no matching caller-supplied catalog entry.
    PreinstalledModuleNotCataloged {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// `Transaction.module_ref.digest` disagreed with the registry's committed
    /// `canonical_code_hash`.
    PreinstalledModuleReferenceDigestMismatch {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// The catalog entry's WASM bytes did not rehash to the registry's
    /// committed `canonical_code_hash`.
    PreinstalledModuleCodeHashMismatch {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// The catalog entry's manifest did not rehash to the registry's
    /// committed `manifest_hash`.
    PreinstalledModuleManifestHashMismatch {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// The catalog entry's `semantics_hash` disagreed with the registry's
    /// committed `semantics_hash`.
    PreinstalledModuleSemanticsHashMismatch {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// The transaction's `args` exceeded the resolved manifest's
    /// `max_input_size`.
    PreinstalledModuleArgsTooLarge {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
        /// Actual argument byte length.
        actual: u64,
        /// Maximum accepted argument byte length.
        maximum: u64,
    },
    /// The transaction's `gas_limit` exceeded the pre-activation preinstalled
    /// WASM ceiling.
    PreinstalledModuleGasLimitExceedsCeiling {
        /// Requested gas limit.
        requested: u64,
        /// Maximum accepted gas limit.
        maximum: u64,
    },
    /// A preinstalled-WASM call declared zero authenticated object accesses.
    /// This MVP path requires at least one.
    PreinstalledModuleZeroObjectAccess,
    /// A committed semantics envelope's opaque application bytes exceeded the bound.
    PreinstalledSemanticsBytesTooLarge {
        /// Actual opaque byte length.
        actual: usize,
        /// Maximum accepted opaque byte length.
        maximum: usize,
    },
    /// A committed semantics envelope declared more object-access policies
    /// than the bound.
    PreinstalledObjectAccessPolicyCollectionTooLarge {
        /// Declared policy count.
        count: usize,
        /// Maximum accepted policy count.
        maximum: usize,
    },
    /// A committed semantics envelope declared the same access index twice.
    DuplicatePreinstalledObjectAccessPolicyIndex {
        /// Duplicated access index.
        access_index: u32,
    },
    /// An object-access policy named the reserved source access index (`0`).
    PreinstalledObjectAccessPolicySourceIndexReserved,
    /// An object-access policy's access index exceeded the per-invocation
    /// authenticated object bound.
    PreinstalledObjectAccessPolicyIndexOutOfBounds {
        /// Declared access index.
        access_index: u32,
        /// Maximum accepted access index.
        maximum: u32,
    },
    /// An object-access policy declared an empty or oversized entrypoint name.
    PreinstalledObjectAccessPolicyEntrypointInvalid {
        /// Actual entrypoint byte length.
        actual: usize,
        /// Maximum accepted entrypoint byte length.
        maximum: usize,
    },
    /// An object-access policy declared an access mode other than
    /// [`AccessMode::Write`], the only mode this exception ever authorizes.
    PreinstalledObjectAccessPolicyModeUnsupported {
        /// Declared access mode.
        mode: AccessMode,
    },
    /// The committed schedule requires a non-zero fee at the worst-case
    /// `gas_limit`, but the transaction declared no `fee_payment`.
    FeePaymentRequired,
    /// The transaction declared a `fee_payment` on a fee-aware preinstalled-
    /// WASM invocation, but the committed schedule's worst-case fee at
    /// `gas_limit` is zero. Historical fee-free behavior applies only to a
    /// transaction that declares no `fee_payment` and no treasury access, so
    /// this is rejected rather than silently settling a zero-amount charge.
    FeePaymentNotRequired,
    /// A `fee_payment` was declared on a node-core entrypoint that has no
    /// fee-charging composition wired.
    FeePaymentUnsupportedOnPath,
    /// The declared `fee_payment` failed deterministic settlement against
    /// the committed schedule and fee-asset registry.
    FeePaymentRejected(fees::FeeError),
    /// `fee_payment.fee_object` did not exactly match one declared `Write`
    /// access.
    FeeObjectNotDeclaredWrite,
    /// The fee object's verified owner is not the authenticated sender.
    FeeObjectNotOwnedBySender,
    /// `fee_payment.fee_object` named the trusted composition's treasury
    /// object.
    FeeObjectIsTreasury,
    /// The trusted composition's treasury object was not declared exactly
    /// once, as the final `Write` access, exactly when a fee is due.
    FeeTreasuryAccessMisdeclared,
    /// This preinstalled-WASM invocation requires fee composition, but none
    /// was supplied by trusted node composition.
    FeeCompositionUnavailable,
    /// The trusted fee-effect composer rejected the settlement.
    FeeCompositionFailed(FeeCompositionError),
    /// The fee-effect composer returned the payer body, the treasury body,
    /// or both unchanged for a non-zero settled amount. A non-zero charge
    /// must always change both bodies.
    FeeCompositionNoOp,
    /// A fee was admitted as due at the worst-case `gas_limit` but settled to
    /// exactly zero at the actual `gas_used`, leaving a declared treasury
    /// `Write` access with no economically justified mutation.
    FeeAmountZero,
    /// The committed `GasSchedule` has a shape the preinstalled-WASM
    /// fee-aware path cannot safely charge; see
    /// [`fee_effects::GasScheduleShapeFault`]. A trusted committed
    /// configuration fault, never a caller-supplied one.
    UnsupportedGasScheduleShape(GasScheduleShapeFault),
    /// A typed-ABI policy construction, registry build, or
    /// `abi::verify_entrypoint_inputs` call failed (DR-0106).
    TypedAbi(abi::AbiError),
    /// A committed semantics envelope declared more typed-entrypoint
    /// constructors than the bound.
    PreinstalledTypedEntrypointConstructorsTooLarge {
        /// Declared constructor count.
        count: usize,
        /// Maximum accepted constructor count.
        maximum: usize,
    },
    /// A committed semantics envelope declared more typed-entrypoint
    /// policies than the bound.
    PreinstalledTypedEntrypointPolicyCollectionTooLarge {
        /// Declared policy count.
        count: usize,
        /// Maximum accepted policy count.
        maximum: usize,
    },
    /// A committed semantics envelope declared the same entrypoint twice
    /// across its typed-entrypoint policies.
    DuplicatePreinstalledTypedEntrypointPolicy {
        /// Duplicated entrypoint.
        entrypoint: String,
    },
    /// A committed semantics envelope declared more owner-transition
    /// policies than the bound.
    PreinstalledOwnerTransitionPolicyCollectionTooLarge {
        /// Declared policy count.
        count: usize,
        /// Maximum accepted policy count.
        maximum: usize,
    },
    /// A committed semantics envelope declared the same entrypoint twice
    /// across its owner-transition policies.
    DuplicatePreinstalledOwnerTransitionPolicy {
        /// Duplicated entrypoint.
        entrypoint: String,
    },
    /// An owner-transition policy declared an empty or oversized entrypoint
    /// name.
    PreinstalledOwnerTransitionPolicyEntrypointInvalid {
        /// Actual entrypoint byte length.
        actual: usize,
        /// Maximum accepted entrypoint byte length.
        maximum: usize,
    },
    /// An owner-transition policy's access index exceeded the
    /// per-invocation authenticated object bound.
    PreinstalledOwnerTransitionPolicyIndexOutOfBounds {
        /// Declared access index.
        access_index: u32,
        /// Maximum accepted access index.
        maximum: u32,
    },
    /// An owner-transition policy declared a zero recipient-args canonical
    /// type id.
    PreinstalledOwnerTransitionPolicyRecipientArgsTypeIdZero,
    /// An owner-transition policy declared a zero recipient-args canonical
    /// field id.
    PreinstalledOwnerTransitionPolicyRecipientArgsFieldIdZero,
    /// An owner-transition policy's entrypoint has no matching
    /// typed-entrypoint policy in the same envelope.
    PreinstalledOwnerTransitionPolicyMissingTypedEntrypoint {
        /// The owner-transition policy's entrypoint.
        entrypoint: String,
    },
    /// An owner-transition policy's `transferred_access_index` is at or
    /// beyond its typed-entrypoint policy's declared parameter count.
    PreinstalledOwnerTransitionPolicyIndexOutOfSignature {
        /// The owner-transition policy's entrypoint.
        entrypoint: String,
        /// The declared access index.
        access_index: u32,
        /// The typed-entrypoint policy's declared parameter count.
        param_count: usize,
    },
    /// An owner-transition policy's `transferred_access_index` names a typed
    /// parameter whose declared access mode is not `Write`.
    PreinstalledOwnerTransitionPolicyIndexNotWrite {
        /// The owner-transition policy's entrypoint.
        entrypoint: String,
        /// The declared access index.
        access_index: u32,
    },
    /// An owner-transition policy's `(entrypoint, transferred_access_index)`
    /// collides with an object-access policy's `(entrypoint, access_index)`:
    /// the two relaxations are deliberately kept mutually exclusive.
    PreinstalledOwnerTransitionPolicyConflictsWithObjectAccessPolicy {
        /// The shared entrypoint.
        entrypoint: String,
        /// The colliding access index.
        access_index: u32,
    },
    /// A committed owner-transition policy applies to this entrypoint, but
    /// the transaction's own `protocol_version` is below
    /// `MIN_OWNER_TRANSITION_PROTOCOL_VERSION`. Returned by
    /// `PreinstalledWasmMachine::transition` strictly before the WASM engine
    /// ever runs; the policy is never silently treated as absent.
    OwnerTransitionProtocolVersionTooLow {
        /// The transaction's declared protocol version.
        actual: ProtocolVersion,
        /// The minimum protocol version required to activate owner
        /// transition.
        minimum: ProtocolVersion,
    },
    /// The engine-visible object at the committed owner-transition index is
    /// not owned by the authenticated sender.
    OwnerTransitionSenderMismatch {
        /// The object at the committed index.
        object_id: ObjectId,
    },
    /// The engine-visible object at the committed owner-transition index was
    /// not resolved with `Write` access.
    OwnerTransitionModeMismatch {
        /// The object at the committed index.
        object_id: ObjectId,
    },
    /// The preinstalled module itself produced an effect naming the object
    /// at the committed owner-transition index; only node-core may
    /// synthesize this object's effect.
    OwnerTransitionObjectEffectForbidden {
        /// The object at the committed index.
        object_id: ObjectId,
    },
    /// The declared `fee_payment.fee_object`, or the trusted composition
    /// treasury, aliases the object at the committed owner-transition index.
    OwnerTransitionFeeObjectAlias {
        /// The aliased object.
        object_id: ObjectId,
    },
    /// A committed semantics envelope declared more object-creation policies
    /// than [`preinstalled_wasm::MAX_PREINSTALLED_OBJECT_CREATION_POLICIES`].
    PreinstalledObjectCreationPolicyCollectionTooLarge {
        /// Declared policy count.
        count: usize,
        /// Maximum accepted policy count.
        maximum: usize,
    },
    /// A committed semantics envelope declared the same entrypoint twice
    /// across its object-creation policies.
    DuplicatePreinstalledObjectCreationPolicy {
        /// Duplicated entrypoint.
        entrypoint: String,
    },
    /// An object-creation policy declared an empty or oversized entrypoint
    /// name.
    PreinstalledObjectCreationPolicyEntrypointInvalid {
        /// Actual entrypoint byte length.
        actual: usize,
        /// Maximum accepted entrypoint byte length.
        maximum: usize,
    },
    /// An object-creation policy declared a zero recipient-args canonical
    /// type id.
    PreinstalledObjectCreationPolicyRecipientArgsTypeIdZero,
    /// An object-creation policy declared a zero recipient-args canonical
    /// field id.
    PreinstalledObjectCreationPolicyRecipientArgsFieldIdZero,
    /// An object-creation policy's exact admitted argument-field set was
    /// empty or exceeded its deterministic bound.
    PreinstalledObjectCreationPolicyArgsFieldCountInvalid {
        /// Number of declared fields.
        count: usize,
        /// Maximum supported fields.
        maximum: usize,
    },
    /// An object-creation policy declared zero as an admitted argument field
    /// identifier.
    PreinstalledObjectCreationPolicyArgsFieldIdZero,
    /// An object-creation policy declared the same admitted argument field
    /// identifier more than once.
    PreinstalledObjectCreationPolicyArgsFieldIdDuplicate,
    /// The policy's recipient field was absent from its exact admitted
    /// argument-field set.
    PreinstalledObjectCreationPolicyRecipientFieldNotAllowed,
    /// An object-creation policy's entrypoint has no matching typed-entrypoint
    /// policy in the same envelope.
    PreinstalledObjectCreationPolicyMissingTypedEntrypoint {
        /// The object-creation policy's entrypoint.
        entrypoint: String,
    },
    /// An object-creation policy's `type_source_access_index` is at or beyond
    /// its typed-entrypoint policy's declared parameter count.
    PreinstalledObjectCreationPolicyIndexOutOfSignature {
        /// The object-creation policy's entrypoint.
        entrypoint: String,
        /// The declared type-source access index.
        access_index: u32,
        /// The typed-entrypoint policy's declared parameter count.
        param_count: usize,
    },
    /// A committed object-creation policy applies to this entrypoint, but the
    /// transaction's own `protocol_version` is below
    /// `MIN_OBJECT_CREATION_PROTOCOL_VERSION`. The policy is never silently
    /// treated as absent.
    ObjectCreationProtocolVersionTooLow {
        /// The transaction's declared protocol version.
        actual: ProtocolVersion,
        /// The minimum protocol version required to activate object
        /// creation.
        minimum: ProtocolVersion,
    },
    /// A committed object-creation policy's `type_source_access_index` did
    /// not resolve to an engine-visible input.
    ObjectCreationTypeSourceIndexUnresolved {
        /// The object-creation policy's entrypoint.
        entrypoint: String,
    },
    /// A call authorized by a committed object-creation policy returned no
    /// `Created` effect at all.
    CreationEffectMissing {
        /// The expected, independently derived created object id.
        object_id: ObjectId,
    },
    /// A call authorized by a committed object-creation policy returned more
    /// than one `Created` effect.
    CreationEffectCountExceeded {
        /// The count of `Created` effects actually returned.
        count: usize,
    },
    /// The module's returned `Created` effect names an id other than the
    /// independently derived, engine-owned deterministic id.
    CreatedObjectIdMismatch {
        /// The independently derived expected id.
        expected: ObjectId,
        /// The id the module's effect actually named.
        actual: ObjectId,
    },
    /// The module's returned `Created` effect's owner disagrees with the
    /// recipient projected from the committed object-creation policy.
    CreatedObjectOwnerMismatch {
        /// The created object id.
        object_id: ObjectId,
    },
    /// The module's returned `Created` effect's `type_hash` disagrees with
    /// the committed policy's type-source access index.
    CreatedObjectTypeMismatch {
        /// The created object id.
        object_id: ObjectId,
    },
    /// The module's returned `Created` effect's `schema_version` disagrees
    /// with the committed policy's type-source access index.
    CreatedObjectSchemaVersionMismatch {
        /// The created object id.
        object_id: ObjectId,
    },
    /// The module's returned `Created` effect did not declare the required
    /// initial object version.
    CreatedObjectVersionInvalid {
        /// The created object id.
        object_id: ObjectId,
    },
    /// The exact, independently derived deterministic created-object id
    /// already has a current or tombstoned durable head: current/tombstone
    /// collisions are always rejected, never silently recreated.
    CreatedObjectIdCollision {
        /// The colliding object id.
        object_id: ObjectId,
    },
}

impl fmt::Display for NodeCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => write!(f, "canonical encoding failed: {error}"),
            Self::CanonicalDecoding(error) => write!(f, "canonical decoding failed: {error}"),
            Self::Hashing(error) => write!(f, "node event hashing failed: {error}"),
            Self::InvalidChainId(error) => write!(f, "invalid chain id: {error}"),
            Self::InvalidHashAlgorithm(error) => {
                write!(f, "invalid hash algorithm: {error}")
            }
            Self::InvalidDigestLength(length) => {
                write!(f, "digest is {length} bytes, expected 32")
            }
            Self::ChainIdTooLong(length) => write!(
                f,
                "chain id is {length} bytes, maximum is {MAX_CHAIN_ID_BYTES}"
            ),
            Self::ZeroRequestId => f.write_str("request id must not be all zeroes"),
            Self::ZeroOutboxLeaseId => f.write_str("outbox lease id must not be all zeroes"),
            Self::InvalidOutboxLeaseDuration(duration) => write!(
                f,
                "outbox lease duration is {duration}ms, maximum is {MAX_OUTBOX_LEASE_MILLIS}ms"
            ),
            Self::InvalidRequestIdLength(length) => {
                write!(f, "request id is {length} bytes, expected 32")
            }
            Self::InvalidOutboxLeaseIdLength(length) => {
                write!(f, "outbox lease id is {length} bytes, expected 32")
            }
            Self::UnknownEventKind(kind) => write!(f, "unknown node event kind: {kind:#06x}"),
            Self::UnknownResponseStatus(status) => {
                write!(f, "unknown node response status: {status:#06x}")
            }
            Self::ChainMismatch { expected, actual } => {
                write!(f, "event chain mismatch: expected {expected}, got {actual}")
            }
            Self::ProtocolVersionMismatch { expected, actual } => write!(
                f,
                "event protocol version mismatch: expected {}, got {}",
                expected.get(),
                actual.get()
            ),
            Self::EpochMismatch { expected, actual } => write!(
                f,
                "event epoch mismatch: expected {}, got {}",
                expected.get(),
                actual.get()
            ),
            Self::EmptyStateKey => f.write_str("node-core state key must not be empty"),
            Self::EmptyStateAccessPlan => {
                f.write_str("transactional node state access plan must not be empty")
            }
            Self::TooManyStateAccesses { count, maximum } => write!(
                f,
                "transactional node state access plan has {count} keys, maximum is {maximum}"
            ),
            Self::DuplicateStateAccessKey => {
                f.write_str("transactional node state access plan contains a duplicate key")
            }
            Self::EmptyStateUpdates => {
                f.write_str("transactional node transition must update at least one state key")
            }
            Self::TooManyStateUpdates { count, maximum } => write!(
                f,
                "transactional node transition has {count} updates, maximum is {maximum}"
            ),
            Self::DuplicateStateUpdateKey => {
                f.write_str("transactional node transition contains a duplicate update key")
            }
            Self::UndeclaredStateUpdate(key) => write!(
                f,
                "transactional node transition updated an undeclared {}-byte state key",
                key.len()
            ),
            Self::ReadOnlyStateUpdate(key) => write!(
                f,
                "transactional node transition updated a read-only {}-byte state key",
                key.len()
            ),
            Self::ReservedStateAccess(key) => write!(
                f,
                "transactional node access plan claimed a reserved {}-byte state key",
                key.len()
            ),
            Self::PayloadTooLarge(length) => write!(
                f,
                "node payload is {length} bytes, maximum is {MAX_NODE_PAYLOAD_BYTES}"
            ),
            Self::StateTooLarge(length) => write!(
                f,
                "node state is {length} bytes, maximum is {MAX_NODE_STATE_BYTES}"
            ),
            Self::TooManyOutputItems { collection, count } => write!(
                f,
                "node output has {count} {collection}, maximum is {MAX_NODE_OUTPUT_ITEMS}"
            ),
            Self::OutputTooLarge(length) => write!(
                f,
                "node output is {length} bytes, maximum is {MAX_NODE_OUTPUT_BYTES}"
            ),
            Self::ResponseRequestMismatch { expected, actual } => write!(
                f,
                "response request id mismatch: expected {expected}, got {actual}"
            ),
            Self::StateConflict => f.write_str("node state changed before the conditional write"),
            Self::RequestIdReuse => {
                f.write_str("request id was already committed for a different event")
            }
            Self::PersistenceInvariant(reason) => {
                write!(f, "persisted node invocation invariant failed: {reason}")
            }
            Self::OutboxNotFound => f.write_str("outbox batch was not found"),
            Self::OutboxLeaseActive {
                expires_at_unix_millis,
            } => write!(
                f,
                "outbox message is leased until unix millisecond {expires_at_unix_millis}"
            ),
            Self::OutboxLeaseMismatch => f.write_str("outbox acknowledgement lease does not match"),
            Self::OutboxIndexMismatch => f.write_str("outbox acknowledgement index does not match"),
            Self::OutboxArithmeticOverflow => f.write_str("outbox delivery arithmetic overflow"),
            Self::NestedItemLengthOverflow(length) => {
                write!(
                    f,
                    "nested canonical item length cannot be represented: {length}"
                )
            }
            Self::TrailingNestedListBytes(length) => {
                write!(f, "nested canonical list has {length} trailing bytes")
            }
            Self::Runtime(error) => write!(f, "runtime operation failed: {error}"),
            Self::DurableRead(error) => write!(f, "durable read failed: {error:?}"),
            Self::DurableInvocation(error) => {
                write!(f, "durable invocation validation failed: {error}")
            }
            Self::DurableCommitRejected(error) => {
                write!(f, "durable commit was rejected: {error:?}")
            }
            Self::DurableCommitIndeterminate(reason) => {
                write!(f, "durable commit outcome is indeterminate: {reason:?}")
            }
            Self::ProtocolConfig(error) => {
                write!(f, "protocol configuration rejected routing: {error}")
            }
            Self::TransactionAuth(error) => {
                write!(f, "transaction authentication failed: {error}")
            }
            Self::UnauthenticatedTransactionSubmission => {
                f.write_str("SubmitTransaction requires an authenticated transaction entrypoint")
            }
            Self::ExpectedSubmitTransaction => {
                f.write_str("authenticated transaction entrypoint requires SubmitTransaction")
            }
            Self::ProtocolConfigVersionMismatch {
                node_config,
                protocol_config,
            } => write!(
                f,
                "node config protocol version {} does not match committed protocol version {}",
                node_config.get(),
                protocol_config.get()
            ),
            Self::TransitionRejected(reason) => write!(f, "node transition rejected: {reason}"),
            Self::SenderNonceMismatch {
                sender,
                expected,
                actual,
            } => write!(
                f,
                "sender {} nonce mismatch: expected {expected}, got {actual}",
                hex32(*sender)
            ),
            Self::SenderNonceOverflow { sender } => {
                write!(f, "sender {} next nonce overflowed", hex32(*sender))
            }
            Self::ObjectNotFound { object_id } => {
                write!(f, "object {object_id} was not found")
            }
            Self::ObjectVersionMismatch {
                object_id,
                expected,
                actual,
            } => write!(
                f,
                "object {object_id} version mismatch: expected {expected}, got {actual}"
            ),
            Self::ObjectDigestMismatch {
                object_id,
                expected,
                actual,
            } => write!(
                f,
                "object {object_id} digest mismatch: expected {expected}, got {actual}"
            ),
            Self::ObjectOwnerMismatch { object_id } => {
                write!(f, "object {object_id} owner did not authorize the sender")
            }
            Self::InadmissibleObjectOwnerAddress { object_id, source } => {
                write!(f, "object {object_id} owner is not admissible: {source}")
            }
            Self::InadmissibleObjectOutputOwnerAddress { object_id, source } => write!(
                f,
                "object {object_id} output owner is not admissible: {source}"
            ),
            Self::ObjectAccessModeUnsupported { object_id, mode } => write!(
                f,
                "object {object_id} requested unsupported access mode {mode:?}"
            ),
            Self::ObjectOwnerKindUnsupported { object_id } => write!(
                f,
                "object {object_id} owner kind is not supported by this slice"
            ),
            Self::ObjectBlobMissing {
                object_id,
                blob_digest,
            } => write!(
                f,
                "object {object_id} blob payload {blob_digest} is absent from blob storage"
            ),
            Self::ObjectBlobDigestMismatch {
                object_id,
                blob_digest,
            } => write!(
                f,
                "object {object_id} fetched blob bytes do not hash to {blob_digest}"
            ),
            Self::ObjectBlobPublishFailed {
                object_id,
                blob_digest,
                source,
            } => write!(
                f,
                "object {object_id} blob publication {blob_digest} failed: {source}"
            ),
            Self::ObjectManifestTooLarge { count, maximum } => write!(
                f,
                "authenticated object manifest has {count} entries, maximum is {maximum}"
            ),
            Self::DuplicateObjectAccess { object_id } => write!(
                f,
                "authenticated object manifest declared object {object_id} twice"
            ),
            Self::InvalidObjectVersion { object_id, version } => {
                write!(f, "object {object_id} declared invalid version {version}")
            }
            Self::ObjectConflict { object_id } => write!(
                f,
                "object {object_id} head changed before the conditional write"
            ),
            Self::ObjectRecordMissing { object_id } => write!(
                f,
                "object {object_id} head referenced a missing version record"
            ),
            Self::ObjectRecordMismatch { object_id } => write!(
                f,
                "object {object_id} version record disagreed with its head"
            ),
            Self::ObjectDigestUnverifiable {
                object_id,
                algorithm,
            } => write!(
                f,
                "object {object_id} digest algorithm {algorithm} is not implemented by this node"
            ),
            Self::ObjectBodyDigestMismatch { object_id } => write!(
                f,
                "object {object_id} stored body does not hash to its recorded digest"
            ),
            Self::ObjectProvenanceMismatch { object_id } => write!(
                f,
                "object {object_id} version provenance chain does not match the event chain"
            ),
            Self::ObjectBodyTooLarge {
                object_id,
                actual,
                maximum,
            } => write!(
                f,
                "object {object_id} body or aggregate body total is {actual} bytes, maximum is {maximum}"
            ),
            Self::DuplicateObjectEffect { object_id } => {
                write!(
                    f,
                    "execution returned duplicate effects for object {object_id}"
                )
            }
            Self::TooManyObjectEffects { actual, maximum } => write!(
                f,
                "execution returned {actual} object effects, maximum is {maximum}"
            ),
            Self::UndeclaredObjectEffect { object_id } => {
                write!(
                    f,
                    "execution returned an effect for undeclared object {object_id}"
                )
            }
            Self::ObjectEffectMismatch { object_id, reason } => {
                write!(f, "object {object_id} effect mismatch: {reason}")
            }
            Self::ObjectVersionOverflow { object_id } => {
                write!(f, "object {object_id} version overflowed")
            }
            Self::ObjectCreationUnsupported { object_id } => {
                write!(f, "creating object {object_id} is outside this MVP slice")
            }
            Self::ObjectMutationContextMissing { object_id } => write!(
                f,
                "object {object_id} mutation is missing trusted creation context"
            ),
            Self::ObjectCreatedCheckpointRegression {
                object_id,
                previous_created_checkpoint,
                attempted_created_checkpoint,
            } => write!(
                f,
                "object {object_id} creation checkpoint regressed from {previous_created_checkpoint} to {attempted_created_checkpoint}"
            ),
            Self::SystemModules(error) => write!(f, "system module error: {error}"),
            Self::Execution(error) => write!(f, "execution error: {error}"),
            Self::PreinstalledModuleWasmTooLarge {
                module_id,
                version,
                actual,
                maximum,
            } => write!(
                f,
                "preinstalled module {module_id} version {version} wasm bytes are {actual}, maximum is {maximum}"
            ),
            Self::PreinstalledModuleManifestIdMismatch { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} manifest names a different module id"
            ),
            Self::PreinstalledModuleCatalogTooLarge { count, maximum } => write!(
                f,
                "preinstalled module catalog has {count} entries, maximum is {maximum}"
            ),
            Self::DuplicatePreinstalledModule { module_id, version } => write!(
                f,
                "preinstalled module catalog declares {module_id} version {version} twice"
            ),
            Self::PreinstalledModuleUnknown { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} is not registered"
            ),
            Self::PreinstalledModuleInactive { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} is not active"
            ),
            Self::PreinstalledModuleNotYetActive {
                module_id,
                version,
                activation_epoch,
                current_epoch,
            } => write!(
                f,
                "preinstalled module {module_id} version {version} activates at epoch {}, current epoch is {}",
                activation_epoch.get(),
                current_epoch.get()
            ),
            Self::PreinstalledModuleNotCataloged { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} is registered but not cataloged"
            ),
            Self::PreinstalledModuleReferenceDigestMismatch { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} declared digest disagrees with the registry"
            ),
            Self::PreinstalledModuleCodeHashMismatch { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} wasm bytes do not hash to the registered code hash"
            ),
            Self::PreinstalledModuleManifestHashMismatch { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} manifest does not hash to the registered manifest hash"
            ),
            Self::PreinstalledModuleSemanticsHashMismatch { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} semantics hash disagrees with the registry"
            ),
            Self::PreinstalledModuleArgsTooLarge {
                module_id,
                version,
                actual,
                maximum,
            } => write!(
                f,
                "preinstalled module {module_id} version {version} args are {actual} bytes, maximum is {maximum}"
            ),
            Self::PreinstalledModuleGasLimitExceedsCeiling { requested, maximum } => write!(
                f,
                "preinstalled module gas_limit {requested} exceeds the pre-activation ceiling of {maximum}"
            ),
            Self::PreinstalledModuleZeroObjectAccess => write!(
                f,
                "preinstalled module call declared zero authenticated object accesses, at least one is required"
            ),
            Self::PreinstalledSemanticsBytesTooLarge { actual, maximum } => write!(
                f,
                "preinstalled semantics envelope opaque bytes are {actual}, maximum is {maximum}"
            ),
            Self::PreinstalledObjectAccessPolicyCollectionTooLarge { count, maximum } => write!(
                f,
                "preinstalled semantics envelope declares {count} object-access policies, maximum is {maximum}"
            ),
            Self::DuplicatePreinstalledObjectAccessPolicyIndex { access_index } => write!(
                f,
                "preinstalled semantics envelope declares access index {access_index} twice"
            ),
            Self::PreinstalledObjectAccessPolicySourceIndexReserved => write!(
                f,
                "preinstalled object-access policy cannot govern the reserved source access index 0"
            ),
            Self::PreinstalledObjectAccessPolicyIndexOutOfBounds {
                access_index,
                maximum,
            } => write!(
                f,
                "preinstalled object-access policy index {access_index} exceeds the maximum of {maximum}"
            ),
            Self::PreinstalledObjectAccessPolicyEntrypointInvalid { actual, maximum } => write!(
                f,
                "preinstalled object-access policy entrypoint is {actual} bytes, maximum is {maximum} and it must be non-empty"
            ),
            Self::PreinstalledObjectAccessPolicyModeUnsupported { mode } => write!(
                f,
                "preinstalled object-access policy declared unsupported access mode {mode:?}, only Write is authorized"
            ),
            Self::FeePaymentRequired => f.write_str(
                "committed fee schedule requires a non-zero worst-case fee, but no fee_payment was declared",
            ),
            Self::FeePaymentNotRequired => f.write_str(
                "fee_payment was declared but the committed worst-case fee at gas_limit is zero",
            ),
            Self::FeePaymentUnsupportedOnPath => {
                f.write_str("fee_payment is not supported on this node-core entrypoint")
            }
            Self::FeePaymentRejected(error) => write!(f, "fee payment settlement failed: {error}"),
            Self::FeeObjectNotDeclaredWrite => f.write_str(
                "fee_payment.fee_object did not exactly match a declared Write access",
            ),
            Self::FeeObjectNotOwnedBySender => {
                f.write_str("fee object's verified owner is not the authenticated sender")
            }
            Self::FeeObjectIsTreasury => {
                f.write_str("fee_payment.fee_object must not be the trusted composition treasury")
            }
            Self::FeeTreasuryAccessMisdeclared => f.write_str(
                "trusted composition treasury object must be declared exactly once, as the final Write access, exactly when a fee is due",
            ),
            Self::FeeCompositionUnavailable => f.write_str(
                "a fee is due but no trusted fee-effect composition was supplied",
            ),
            Self::FeeCompositionFailed(error) => write!(f, "fee composition failed: {error}"),
            Self::FeeCompositionNoOp => f.write_str(
                "fee composition returned the payer body, the treasury body, or both unchanged for a non-zero settled amount",
            ),
            Self::FeeAmountZero => f.write_str(
                "fee settled to zero at actual gas_used with a declared treasury access",
            ),
            Self::UnsupportedGasScheduleShape(fault) => {
                write!(f, "committed gas schedule shape is unsupported: {fault}")
            }
            Self::TypedAbi(error) => write!(f, "typed-ABI verification failed: {error}"),
            Self::PreinstalledTypedEntrypointConstructorsTooLarge { count, maximum } => write!(
                f,
                "typed-entrypoint policy declares {count} constructors, exceeds maximum {maximum}"
            ),
            Self::PreinstalledTypedEntrypointPolicyCollectionTooLarge { count, maximum } => {
                write!(
                    f,
                    "semantics envelope declares {count} typed-entrypoint policies, exceeds maximum {maximum}"
                )
            }
            Self::DuplicatePreinstalledTypedEntrypointPolicy { entrypoint } => write!(
                f,
                "semantics envelope declares typed-entrypoint policy for {entrypoint:?} more than once"
            ),
            Self::PreinstalledOwnerTransitionPolicyCollectionTooLarge { count, maximum } => {
                write!(
                    f,
                    "semantics envelope declares {count} owner-transition policies, exceeds maximum {maximum}"
                )
            }
            Self::DuplicatePreinstalledOwnerTransitionPolicy { entrypoint } => write!(
                f,
                "semantics envelope declares owner-transition policy for {entrypoint:?} more than once"
            ),
            Self::PreinstalledOwnerTransitionPolicyEntrypointInvalid { actual, maximum } => write!(
                f,
                "owner-transition policy entrypoint is {actual} bytes, maximum is {maximum} and it must be non-empty"
            ),
            Self::PreinstalledOwnerTransitionPolicyIndexOutOfBounds {
                access_index,
                maximum,
            } => write!(
                f,
                "owner-transition policy access index {access_index} exceeds maximum {maximum}"
            ),
            Self::PreinstalledOwnerTransitionPolicyRecipientArgsTypeIdZero => f.write_str(
                "owner-transition policy declared a zero recipient-args canonical type id",
            ),
            Self::PreinstalledOwnerTransitionPolicyRecipientArgsFieldIdZero => f.write_str(
                "owner-transition policy declared a zero recipient-args canonical field id",
            ),
            Self::PreinstalledOwnerTransitionPolicyMissingTypedEntrypoint { entrypoint } => write!(
                f,
                "owner-transition policy for {entrypoint:?} has no matching typed-entrypoint policy"
            ),
            Self::PreinstalledOwnerTransitionPolicyIndexOutOfSignature {
                entrypoint,
                access_index,
                param_count,
            } => write!(
                f,
                "owner-transition policy for {entrypoint:?} names access index {access_index}, but its typed signature declares only {param_count} parameters"
            ),
            Self::PreinstalledOwnerTransitionPolicyIndexNotWrite {
                entrypoint,
                access_index,
            } => write!(
                f,
                "owner-transition policy for {entrypoint:?} names access index {access_index}, whose typed parameter is not Write"
            ),
            Self::PreinstalledOwnerTransitionPolicyConflictsWithObjectAccessPolicy {
                entrypoint,
                access_index,
            } => write!(
                f,
                "owner-transition policy for {entrypoint:?} at access index {access_index} conflicts with an object-access policy at the same index"
            ),
            Self::OwnerTransitionProtocolVersionTooLow { actual, minimum } => write!(
                f,
                "owner transition requires protocol_version >= {minimum:?}, transaction declared {actual:?}"
            ),
            Self::OwnerTransitionSenderMismatch { object_id } => write!(
                f,
                "owner-transition object {object_id} is not owned by the authenticated sender"
            ),
            Self::OwnerTransitionModeMismatch { object_id } => write!(
                f,
                "owner-transition object {object_id} was not resolved with Write access"
            ),
            Self::OwnerTransitionObjectEffectForbidden { object_id } => write!(
                f,
                "preinstalled module produced a forbidden effect for owner-transition object {object_id}"
            ),
            Self::OwnerTransitionFeeObjectAlias { object_id } => write!(
                f,
                "fee object or treasury aliases owner-transition object {object_id}"
            ),
            Self::PreinstalledObjectCreationPolicyCollectionTooLarge { count, maximum } => write!(
                f,
                "committed semantics envelope has {count} object-creation policies, maximum is {maximum}"
            ),
            Self::DuplicatePreinstalledObjectCreationPolicy { entrypoint } => write!(
                f,
                "duplicate object-creation policy for entrypoint {entrypoint:?}"
            ),
            Self::PreinstalledObjectCreationPolicyEntrypointInvalid { actual, maximum } => write!(
                f,
                "object-creation policy entrypoint is {actual} bytes, maximum is {maximum} and it must be non-empty"
            ),
            Self::PreinstalledObjectCreationPolicyRecipientArgsTypeIdZero => {
                f.write_str("object-creation policy declared a zero recipient-args type id")
            }
            Self::PreinstalledObjectCreationPolicyRecipientArgsFieldIdZero => {
                f.write_str("object-creation policy declared a zero recipient-args field id")
            }
            Self::PreinstalledObjectCreationPolicyArgsFieldCountInvalid { count, maximum } => write!(
                f,
                "object-creation policy declares {count} exact argument fields, maximum is {maximum} and at least one is required"
            ),
            Self::PreinstalledObjectCreationPolicyArgsFieldIdZero => {
                f.write_str("object-creation policy admitted zero as an argument field id")
            }
            Self::PreinstalledObjectCreationPolicyArgsFieldIdDuplicate => {
                f.write_str("object-creation policy admitted a duplicate argument field id")
            }
            Self::PreinstalledObjectCreationPolicyRecipientFieldNotAllowed => {
                f.write_str("object-creation policy recipient field is not in its exact argument-field set")
            }
            Self::PreinstalledObjectCreationPolicyMissingTypedEntrypoint { entrypoint } => write!(
                f,
                "object-creation policy for {entrypoint:?} has no matching typed-entrypoint policy"
            ),
            Self::PreinstalledObjectCreationPolicyIndexOutOfSignature {
                entrypoint,
                access_index,
                param_count,
            } => write!(
                f,
                "object-creation policy for {entrypoint:?} names type-source index {access_index}, but its typed signature declares only {param_count} parameters"
            ),
            Self::ObjectCreationProtocolVersionTooLow { actual, minimum } => write!(
                f,
                "object creation requires protocol_version >= {minimum:?}, transaction declared {actual:?}"
            ),
            Self::ObjectCreationTypeSourceIndexUnresolved { entrypoint } => write!(
                f,
                "object-creation policy for {entrypoint:?} type-source index did not resolve to an engine-visible input"
            ),
            Self::CreationEffectMissing { object_id } => write!(
                f,
                "object-creation policy authorized creating {object_id}, but no Created effect was returned"
            ),
            Self::CreationEffectCountExceeded { count } => write!(
                f,
                "expected at most one Created effect, got {count}"
            ),
            Self::CreatedObjectIdMismatch { expected, actual } => write!(
                f,
                "created object id {actual} disagrees with the independently derived expected id {expected}"
            ),
            Self::CreatedObjectOwnerMismatch { object_id } => write!(
                f,
                "created object {object_id}'s owner disagrees with the projected recipient"
            ),
            Self::CreatedObjectTypeMismatch { object_id } => write!(
                f,
                "created object {object_id}'s type_hash disagrees with the committed type-source input"
            ),
            Self::CreatedObjectSchemaVersionMismatch { object_id } => write!(
                f,
                "created object {object_id}'s schema_version disagrees with the committed type-source input"
            ),
            Self::CreatedObjectVersionInvalid { object_id } => write!(
                f,
                "created object {object_id} did not declare the required initial version"
            ),
            Self::CreatedObjectIdCollision { object_id } => write!(
                f,
                "derived created-object id {object_id} already has a current or tombstoned durable head"
            ),
        }
    }
}

impl Error for NodeCoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::Hashing(error) => Some(error),
            Self::InvalidChainId(error) => Some(error),
            Self::InvalidHashAlgorithm(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::ProtocolConfig(error) => Some(error),
            Self::TransactionAuth(error) => Some(error),
            Self::SystemModules(error) => Some(error),
            Self::Execution(error) => Some(error),
            Self::FeePaymentRejected(error) => Some(error),
            Self::FeeCompositionFailed(error) => Some(error),
            Self::UnsupportedGasScheduleShape(error) => Some(error),
            Self::TypedAbi(error) => Some(error),
            Self::ObjectBlobPublishFailed { source, .. } => Some(source),
            Self::InadmissibleObjectOwnerAddress { source, .. } => Some(source),
            Self::InadmissibleObjectOutputOwnerAddress { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<SystemModuleError> for NodeCoreError {
    fn from(value: SystemModuleError) -> Self {
        Self::SystemModules(value)
    }
}

impl From<ExecutionError> for NodeCoreError {
    fn from(value: ExecutionError) -> Self {
        Self::Execution(value)
    }
}

impl From<CanonicalEncodingError> for NodeCoreError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for NodeCoreError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

impl From<HashingError> for NodeCoreError {
    fn from(value: HashingError) -> Self {
        Self::Hashing(value)
    }
}

impl From<RuntimeError> for NodeCoreError {
    fn from(value: RuntimeError) -> Self {
        Self::Runtime(value)
    }
}

impl From<DurableReadError> for NodeCoreError {
    fn from(value: DurableReadError) -> Self {
        Self::DurableRead(value)
    }
}

impl From<DurableInvocationError> for NodeCoreError {
    fn from(value: DurableInvocationError) -> Self {
        Self::DurableInvocation(value)
    }
}

impl From<ProtocolConfigError> for NodeCoreError {
    fn from(value: ProtocolConfigError) -> Self {
        Self::ProtocolConfig(value)
    }
}

impl From<TransactionAuthError> for NodeCoreError {
    fn from(value: TransactionAuthError) -> Self {
        Self::TransactionAuth(value)
    }
}

impl From<abi::AbiError> for NodeCoreError {
    fn from(value: abi::AbiError) -> Self {
        Self::TypedAbi(value)
    }
}

/// Stable, caller-supplied idempotency identifier for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId([u8; 32]);

impl RequestId {
    /// Creates a non-zero request identifier.
    pub fn new(bytes: [u8; 32]) -> Result<Self, NodeCoreError> {
        if bytes == [0; 32] {
            return Err(NodeCoreError::ZeroRequestId);
        }
        Ok(Self(bytes))
    }

    /// Returns the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Closed node event families routed to application-specific schema decoders.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeEventKind {
    /// Client transaction submission.
    SubmitTransaction = 0x0001,
    /// Validator vote delivery.
    ReceiveVote = 0x0002,
    /// Certificate delivery.
    ReceiveCertificate = 0x0003,
    /// Shared-object consensus message delivery.
    ReceiveConsensusMessage = 0x0004,
    /// Governance certificate application.
    ApplyGovernanceCertificate = 0x0005,
    /// Protocol-upgrade certificate application.
    ApplyProtocolUpgrade = 0x0006,
    /// Validator-set change certificate application.
    ApplyValidatorSetChange = 0x0007,
    /// Untrusted liveness tick delivery.
    Tick = 0x0008,
}

impl NodeEventKind {
    /// Returns the stable wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for NodeEventKind {
    type Error = NodeCoreError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::SubmitTransaction),
            0x0002 => Ok(Self::ReceiveVote),
            0x0003 => Ok(Self::ReceiveCertificate),
            0x0004 => Ok(Self::ReceiveConsensusMessage),
            0x0005 => Ok(Self::ApplyGovernanceCertificate),
            0x0006 => Ok(Self::ApplyProtocolUpgrade),
            0x0007 => Ok(Self::ApplyValidatorSetChange),
            0x0008 => Ok(Self::Tick),
            other => Err(NodeCoreError::UnknownEventKind(other)),
        }
    }
}

/// One replay-bounded, canonical input to the node state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeEvent {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    request_id: RequestId,
    kind: NodeEventKind,
    payload: Vec<u8>,
}

impl NodeEvent {
    /// Creates a validated event around one canonical application payload.
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        request_id: RequestId,
        kind: NodeEventKind,
        payload: Vec<u8>,
    ) -> Result<Self, NodeCoreError> {
        validate_chain_id(&chain_id)?;
        validate_payload(&payload)?;
        Ok(Self {
            chain_id,
            protocol_version,
            epoch,
            request_id,
            kind,
            payload,
        })
    }

    /// Returns the replay-protected chain identifier.
    #[must_use]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the replay-protected protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the replay-protected epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the event family.
    #[must_use]
    pub const fn kind(&self) -> NodeEventKind {
        self.kind
    }

    /// Returns the canonical application payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes the event into its stable canonical wire form.
    pub fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let mut frame = CanonicalStruct::new(NODE_EVENT_TYPE_ID, ENCODING_VERSION);
        frame.field_str(1, self.chain_id.as_str())?;
        frame.field_u32(2, self.protocol_version.get())?;
        frame.field_u64(3, self.epoch.get())?;
        frame.field_bytes(4, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(5, self.kind.as_u16())?;
        frame.field_bytes(6, self.payload.clone())?;
        Ok(frame.finish()?)
    }

    /// Hashes the complete canonical event in its dedicated idempotency domain.
    pub fn digest(&self, resolver: &HashSuiteResolver) -> Result<Digest32, NodeCoreError> {
        if resolver.chain_id() != &self.chain_id {
            return Err(NodeCoreError::ChainMismatch {
                expected: resolver.chain_id().clone(),
                actual: self.chain_id.clone(),
            });
        }
        if resolver.protocol_version() != self.protocol_version {
            return Err(NodeCoreError::ProtocolVersionMismatch {
                expected: resolver.protocol_version(),
                actual: self.protocol_version,
            });
        }
        Ok(resolver.hash_for_purpose(self.epoch, HashPurpose::NodeEvent, &self.encode()?)?)
    }

    /// Decodes and validates exactly one canonical event frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_EVENT_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;

        let chain_id = ChainId::new(frame.required_str(1)?.to_owned())
            .map_err(NodeCoreError::InvalidChainId)?;
        let request_bytes = frame.required_field(4)?;
        let request_array: [u8; 32] = request_bytes
            .try_into()
            .map_err(|_| NodeCoreError::InvalidRequestIdLength(request_bytes.len()))?;
        Self::new(
            chain_id,
            ProtocolVersion::new(frame.required_u32(2)?),
            Epoch::new(frame.required_u64(3)?),
            RequestId::new(request_array)?,
            NodeEventKind::try_from(frame.required_u16(5)?)?,
            frame.required_field(6)?.to_vec(),
        )
    }

    fn validate_context(&self, config: &NodeConfig) -> Result<(), NodeCoreError> {
        if self.chain_id != config.chain_id {
            return Err(NodeCoreError::ChainMismatch {
                expected: config.chain_id.clone(),
                actual: self.chain_id.clone(),
            });
        }
        if self.protocol_version != config.protocol_version {
            return Err(NodeCoreError::ProtocolVersionMismatch {
                expected: config.protocol_version,
                actual: self.protocol_version,
            });
        }
        if self.epoch != config.epoch {
            return Err(NodeCoreError::EpochMismatch {
                expected: config.epoch,
                actual: self.epoch,
            });
        }
        Ok(())
    }
}

/// Immutable invocation context supplied by the runtime adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeConfig {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    state_key: Vec<u8>,
}

impl NodeConfig {
    /// Creates a node-core invocation configuration.
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        state_key: Vec<u8>,
    ) -> Result<Self, NodeCoreError> {
        validate_chain_id(&chain_id)?;
        if state_key.is_empty() {
            return Err(NodeCoreError::EmptyStateKey);
        }
        Ok(Self {
            chain_id,
            protocol_version,
            epoch,
            state_key,
        })
    }

    /// Returns the configured chain identifier.
    #[must_use]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the configured protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the configured epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the explicit persistence key used by this state machine.
    #[must_use]
    pub fn state_key(&self) -> &[u8] {
        &self.state_key
    }
}

/// A `SubmitTransaction` event whose canonical inner transaction has been
/// authenticated against the same trusted ingress and committed protocol
/// configuration.
///
/// The fields are private and there is no public constructor. Callers must use
/// [`authenticate_submit_transaction_event`], and durable processing consumes
/// this wrapper through
/// [`handle_authenticated_resolved_durable_submit_transaction`]. The committed
/// placement and exact matching system-module record are captured at
/// authentication time so
/// a caller cannot authenticate under one `ProtocolConfig` and later route
/// storage or execute code through different committed configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedSubmitTransaction {
    event: NodeEvent,
    transaction: AuthenticatedTransaction,
    placement: DomainPlacementManifest,
    committed_system_module: Option<SystemModule>,
    committed_fee_policy: CommittedFeePolicy,
}

impl AuthenticatedSubmitTransaction {
    /// Returns the authenticated outer node event.
    #[must_use]
    pub const fn event(&self) -> &NodeEvent {
        &self.event
    }

    /// Returns the strictly decoded and signature-verified transaction.
    #[must_use]
    pub const fn transaction(&self) -> &AuthenticatedTransaction {
        &self.transaction
    }
}

/// Authenticates one `SubmitTransaction` event before any machine or storage
/// operation can begin.
///
/// The outer event is first matched against `NodeConfig`. Its protocol version
/// must also equal the committed `ProtocolConfig` version. The inner canonical
/// transaction is then authenticated with the outer trusted chain and epoch,
/// while protocol-version and profile authority come only from
/// `ProtocolConfig`. The returned wrapper captures that configuration's domain
/// placement and exact matching system-module record (or its committed absence)
/// for the later durable commit and module resolution.
pub fn authenticate_submit_transaction_event(
    event: NodeEvent,
    config: &NodeConfig,
    protocol_config: &ProtocolConfig,
) -> Result<AuthenticatedSubmitTransaction, NodeCoreError> {
    event.validate_context(config)?;
    if event.kind() != NodeEventKind::SubmitTransaction {
        return Err(NodeCoreError::ExpectedSubmitTransaction);
    }
    if config.protocol_version() != protocol_config.protocol_version {
        return Err(NodeCoreError::ProtocolConfigVersionMismatch {
            node_config: config.protocol_version(),
            protocol_config: protocol_config.protocol_version,
        });
    }

    let trusted_context =
        TrustedTransactionContext::new(config.chain_id().clone(), config.epoch(), protocol_config);
    let transaction = authenticate_submit_transaction_bytes(
        event.request_id(),
        event.payload(),
        &trusted_context,
    )?;
    let module_ref: &ObjectRef = &transaction.transaction().module_ref;
    let module_id: ModuleId = ModuleId::new(*module_ref.id.as_bytes());
    let committed_system_module: Option<SystemModule> = protocol_config
        .system_modules
        .get(module_id, module_ref.version)
        .cloned();
    let placement = protocol_config
        .domain_placement
        .clone()
        .ok_or(ProtocolConfigError::MissingDomainPlacement)?;
    let committed_fee_policy = CommittedFeePolicy {
        gas_schedule: protocol_config.gas_schedule.clone(),
        fee_assets: protocol_config.fee_assets.clone(),
    };

    Ok(AuthenticatedSubmitTransaction {
        event,
        transaction,
        placement,
        committed_system_module,
        committed_fee_policy,
    })
}

/// Sender-nonce enforcement input for one durable submit-transaction
/// invocation.
///
/// The fields are private and there is no public constructor. Transaction
/// ingress derives this from its authenticated transaction; publication ingress
/// derives it from its authenticated submission. Untrusted callers cannot
/// reserve a sender or nonce without authenticating that exact signed input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SenderNonceReservation {
    sender: [u8; 32],
    epoch: Epoch,
    nonce: u64,
}

impl SenderNonceReservation {
    /// Derives the reservation directly from the authenticated inner
    /// transaction's sender, epoch, and declared nonce.
    fn from_authenticated_transaction(transaction: &AuthenticatedTransaction) -> Self {
        let inner = transaction.transaction();
        Self {
            sender: *inner.sender.as_bytes(),
            epoch: inner.epoch,
            nonce: inner.nonce,
        }
    }
}

/// One read-only object access declared by a signed transaction manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedObjectAccess {
    object_ref: ObjectRef,
    mode: AccessMode,
}

/// Authenticated, pre-I/O-validated object dispatch input for one durable
/// submit-transaction invocation.
///
/// The fields are private and there is no public constructor. The only way to
/// obtain a value is [`Self::from_authenticated_transaction`], so a caller can
/// never authorize an object access against an authority or manifest it did
/// not cryptographically authenticate. `accesses` retains the signed manifest
/// declaration order, is deduplicated by [`ObjectId`], and has every entry's
/// version and access mode validated, so later per-entry storage I/O never
/// needs to re-check them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedObjectDispatch {
    authority: Address,
    owner_address_policy: Ed25519OwnerAddressPolicy,
    accesses: Vec<AuthenticatedObjectAccess>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthenticatedObjectPolicy {
    ReadOnly,
    OwnedMutations { created_checkpoint: u64 },
}

impl AuthenticatedObjectDispatch {
    /// Derives and validates the dispatch descriptor from the authenticated
    /// inner transaction's sender and declared object-access manifest.
    ///
    /// Every check here is pure and requires zero storage I/O: bounding the
    /// declared access count, rejecting a duplicate object identifier without
    /// changing signed declaration order, requiring a non-zero object version,
    /// and enforcing the selected internal access policy. The established
    /// public entrypoint uses read-only policy; only the additive owned-effects
    /// entrypoint enables Write/Consume.
    fn from_authenticated_transaction(
        transaction: &AuthenticatedTransaction,
        policy: AuthenticatedObjectPolicy,
    ) -> Result<Self, NodeCoreError> {
        let inner = transaction.transaction();
        let authority: Address = inner.sender;
        let accesses = validate_object_entries(inner.access_manifest.entries.as_slice(), policy)?;
        Ok(Self {
            authority,
            owner_address_policy: transaction.owner_address_policy(),
            accesses,
        })
    }
}

/// Pure, zero-I/O validation of one declared object-access manifest.
///
/// Bounds the declared access count, rejects a duplicate object identifier
/// without changing signed declaration order, requires a non-zero object
/// version, and enforces the selected internal access policy.
///
/// Split out of [`AuthenticatedObjectDispatch::from_authenticated_transaction`]
/// so it can be exercised directly with hand-built entries: the authenticated
/// decode path already rejects a duplicate `ObjectId` in
/// [`abi::decode_access_manifest`] before a manifest ever reaches here, so the
/// duplicate defense in this function is otherwise unreachable through the
/// full authenticated submission path.
fn validate_object_entries(
    entries: &[AccessEntry],
    policy: AuthenticatedObjectPolicy,
) -> Result<Vec<AuthenticatedObjectAccess>, NodeCoreError> {
    if entries.len() > MAX_AUTHENTICATED_OBJECT_READS {
        return Err(NodeCoreError::ObjectManifestTooLarge {
            count: entries.len(),
            maximum: MAX_AUTHENTICATED_OBJECT_READS,
        });
    }

    let accesses: Vec<AuthenticatedObjectAccess> = entries
        .iter()
        .map(|entry: &AccessEntry| AuthenticatedObjectAccess {
            object_ref: entry.object_ref.clone(),
            mode: entry.mode,
        })
        .collect();
    let mut seen_ids: BTreeSet<ObjectId> = BTreeSet::new();
    for access in &accesses {
        if !seen_ids.insert(access.object_ref.id) {
            return Err(NodeCoreError::DuplicateObjectAccess {
                object_id: access.object_ref.id,
            });
        }
    }

    for access in &accesses {
        if DurableObjectVersion::new(access.object_ref.version).is_none() {
            return Err(NodeCoreError::InvalidObjectVersion {
                object_id: access.object_ref.id,
                version: access.object_ref.version,
            });
        }
        if matches!(policy, AuthenticatedObjectPolicy::ReadOnly) && access.mode != AccessMode::Read
        {
            return Err(NodeCoreError::ObjectAccessModeUnsupported {
                object_id: access.object_ref.id,
                mode: access.mode,
            });
        }
    }

    Ok(accesses)
}

const SENDER_NONCE_RECORD_TYPE_ID: u16 = 0xE006;

/// Canonical persisted next-nonce record bound to one exact sender and epoch.
///
/// Binding `sender` and `epoch` inside the record, not only in the derived
/// storage key, lets a reader cross-check the persisted bytes against the
/// key that addressed them and fail closed on a corrupt or misbound record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SenderNonceRecord {
    sender: [u8; 32],
    epoch: Epoch,
    next_nonce: u64,
}

impl SenderNonceRecord {
    fn new(sender: [u8; 32], epoch: Epoch, next_nonce: u64) -> Self {
        Self {
            sender,
            epoch,
            next_nonce,
        }
    }

    /// Encodes the record canonically.
    fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let mut frame = CanonicalStruct::new(SENDER_NONCE_RECORD_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.sender.to_vec())?;
        frame.field_u64(2, self.epoch.get())?;
        frame.field_u64(3, self.next_nonce)?;
        Ok(frame.finish()?)
    }

    /// Decodes and strictly validates one persisted next-nonce record.
    fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(SENDER_NONCE_RECORD_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;

        let sender_bytes = frame.required_field(1)?;
        let sender: [u8; 32] =
            sender_bytes
                .try_into()
                .map_err(|_| CanonicalDecodingError::InvalidFieldLength {
                    field_id: 1,
                    expected: 32,
                    actual: sender_bytes.len(),
                })?;
        Ok(Self::new(
            sender,
            Epoch::new(frame.required_u64(2)?),
            frame.required_u64(3)?,
        ))
    }
}

/// Stable status returned to the request adapter.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeResponseStatus {
    /// The event was accepted and persisted.
    Accepted = 0x0001,
    /// The authenticated event was deterministically rejected by application logic.
    Rejected = 0x0002,
}

impl NodeResponseStatus {
    /// Returns the stable wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for NodeResponseStatus {
    type Error = NodeCoreError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::Accepted),
            0x0002 => Ok(Self::Rejected),
            other => Err(NodeCoreError::UnknownResponseStatus(other)),
        }
    }
}

/// Adapter-neutral response produced by a successful state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeResponse {
    request_id: RequestId,
    status: NodeResponseStatus,
    payload: Option<Vec<u8>>,
}

impl NodeResponse {
    /// Creates a bounded response. A present payload must be a canonical frame.
    pub fn new(
        request_id: RequestId,
        status: NodeResponseStatus,
        payload: Option<Vec<u8>>,
    ) -> Result<Self, NodeCoreError> {
        if let Some(bytes) = &payload {
            validate_payload(bytes)?;
        }
        Ok(Self {
            request_id,
            status,
            payload,
        })
    }

    /// Returns the matching request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the response status.
    #[must_use]
    pub const fn status(&self) -> NodeResponseStatus {
        self.status
    }

    /// Returns the optional canonical response payload.
    #[must_use]
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    /// Encodes this response into its adapter-neutral canonical wire form.
    pub fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let mut frame = CanonicalStruct::new(NODE_RESPONSE_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(2, self.status.as_u16())?;
        if let Some(payload) = &self.payload {
            frame.field_bytes(3, payload.clone())?;
        }
        Ok(frame.finish()?)
    }

    /// Decodes one adapter-neutral canonical response.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_RESPONSE_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;

        let request_bytes = frame.required_field(1)?;
        let request_array: [u8; 32] = request_bytes
            .try_into()
            .map_err(|_| NodeCoreError::InvalidRequestIdLength(request_bytes.len()))?;
        Self::new(
            RequestId::new(request_array)?,
            NodeResponseStatus::try_from(frame.required_u16(2)?)?,
            frame.field(3).map(<[u8]>::to_vec),
        )
    }
}

/// Adapter-neutral outbound delivery request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundMessage {
    event: NodeEvent,
}

impl OutboundMessage {
    /// Creates an outbound message around a fully framed node event.
    #[must_use]
    pub const fn new(event: NodeEvent) -> Self {
        Self { event }
    }

    /// Returns the event to deliver through an untrusted transport.
    #[must_use]
    pub const fn event(&self) -> &NodeEvent {
        &self.event
    }
}

/// Canonical completed-request record used for persisted idempotency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeDedupRecord {
    request_id: RequestId,
    event_digest: Digest32,
    responses: Vec<NodeResponse>,
}

impl NodeDedupRecord {
    /// Creates a completed request record with replayable adapter responses.
    pub fn new(
        request_id: RequestId,
        event_digest: Digest32,
        responses: Vec<NodeResponse>,
    ) -> Result<Self, NodeCoreError> {
        NodeOutput::new(responses.clone(), Vec::new())?;
        for response in &responses {
            if response.request_id() != request_id {
                return Err(NodeCoreError::ResponseRequestMismatch {
                    expected: request_id,
                    actual: response.request_id(),
                });
            }
        }
        Ok(Self {
            request_id,
            event_digest,
            responses,
        })
    }

    /// Returns the stable request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the digest of the complete canonical input event.
    #[must_use]
    pub const fn event_digest(&self) -> Digest32 {
        self.event_digest
    }

    /// Returns the responses replayed for a matching duplicate request.
    #[must_use]
    pub fn responses(&self) -> &[NodeResponse] {
        &self.responses
    }

    /// Encodes the completed request record canonically.
    pub fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let response_list = encode_nested_items(
            self.responses
                .iter()
                .map(NodeResponse::encode)
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let response_count =
            u32::try_from(self.responses.len()).map_err(|_| NodeCoreError::TooManyOutputItems {
                collection: "dedup responses",
                count: self.responses.len(),
            })?;
        let mut frame = CanonicalStruct::new(NODE_DEDUP_RECORD_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(2, self.event_digest.algorithm().as_u16())?;
        frame.field_bytes(3, self.event_digest.bytes())?;
        frame.field_u32(4, response_count)?;
        frame.field_bytes(5, response_list)?;
        Ok(frame.finish()?)
    }

    /// Decodes and validates one completed request record.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_DEDUP_RECORD_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5])?;

        let request_id = decode_request_id(frame.required_field(1)?)?;
        let event_digest = decode_digest(frame.required_u16(2)?, frame.required_field(3)?)?;
        let count = bounded_nested_count(frame.required_u32(4)?, "dedup responses")?;
        let responses = decode_nested_items(frame.required_field(5)?, count, NodeResponse::decode)?;
        Self::new(request_id, event_digest, responses)
    }
}

/// Canonical at-least-once outbound batch persisted with one request commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeOutboxBatch {
    request_id: RequestId,
    event_digest: Digest32,
    messages: Vec<OutboundMessage>,
}

impl NodeOutboxBatch {
    /// Creates the complete ordered outbound batch for one committed request.
    pub fn new(
        request_id: RequestId,
        event_digest: Digest32,
        messages: Vec<OutboundMessage>,
    ) -> Result<Self, NodeCoreError> {
        NodeOutput::new(Vec::new(), messages.clone())?;
        Ok(Self {
            request_id,
            event_digest,
            messages,
        })
    }

    /// Returns the request that created this batch.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the digest of the input event that created this batch.
    #[must_use]
    pub const fn event_digest(&self) -> Digest32 {
        self.event_digest
    }

    /// Returns outbound messages in deterministic transition order.
    #[must_use]
    pub fn messages(&self) -> &[OutboundMessage] {
        &self.messages
    }

    /// Encodes the outbound batch canonically.
    pub fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let message_list = encode_nested_items(
            self.messages
                .iter()
                .map(|message| message.event().encode())
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let message_count =
            u32::try_from(self.messages.len()).map_err(|_| NodeCoreError::TooManyOutputItems {
                collection: "outbox messages",
                count: self.messages.len(),
            })?;
        let mut frame = CanonicalStruct::new(NODE_OUTBOX_BATCH_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(2, self.event_digest.algorithm().as_u16())?;
        frame.field_bytes(3, self.event_digest.bytes())?;
        frame.field_u32(4, message_count)?;
        frame.field_bytes(5, message_list)?;
        Ok(frame.finish()?)
    }

    /// Decodes and validates one persisted outbound batch.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_OUTBOX_BATCH_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5])?;

        let request_id = decode_request_id(frame.required_field(1)?)?;
        let event_digest = decode_digest(frame.required_u16(2)?, frame.required_field(3)?)?;
        let count = bounded_nested_count(frame.required_u32(4)?, "outbox messages")?;
        let events = decode_nested_items(frame.required_field(5)?, count, NodeEvent::decode)?;
        let messages = events.into_iter().map(OutboundMessage::new).collect();
        Self::new(request_id, event_digest, messages)
    }
}

/// Non-zero caller-generated identity for one bounded outbox lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OutboxLeaseId([u8; 32]);

impl OutboxLeaseId {
    /// Creates a non-zero lease identifier.
    pub fn new(bytes: [u8; 32]) -> Result<Self, NodeCoreError> {
        if bytes == [0; 32] {
            return Err(NodeCoreError::ZeroOutboxLeaseId);
        }
        Ok(Self(bytes))
    }

    /// Returns the lease identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Mutable delivery cursor committed beside an immutable outbox batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeOutboxDelivery {
    request_id: RequestId,
    event_digest: Digest32,
    next_index: u32,
    attempts: u32,
    lease: Option<(OutboxLeaseId, u64)>,
}

impl NodeOutboxDelivery {
    fn pending(request_id: RequestId, event_digest: Digest32) -> Self {
        Self {
            request_id,
            event_digest,
            next_index: 0,
            attempts: 0,
            lease: None,
        }
    }

    /// Returns the request that owns this delivery cursor.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the event digest shared with the immutable outbox batch.
    #[must_use]
    pub const fn event_digest(&self) -> Digest32 {
        self.event_digest
    }

    /// Returns the next message index that requires delivery.
    #[must_use]
    pub const fn next_index(&self) -> u32 {
        self.next_index
    }

    /// Returns the number of leases granted for this batch.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Returns the active lease and deadline, if present.
    #[must_use]
    pub const fn lease(&self) -> Option<(OutboxLeaseId, u64)> {
        self.lease
    }

    /// Encodes the delivery cursor canonically.
    pub fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let mut frame = CanonicalStruct::new(NODE_OUTBOX_DELIVERY_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(2, self.event_digest.algorithm().as_u16())?;
        frame.field_bytes(3, self.event_digest.bytes())?;
        frame.field_u32(4, self.next_index)?;
        frame.field_u32(5, self.attempts)?;
        if let Some((lease_id, expires_at)) = self.lease {
            frame.field_bytes(6, lease_id.as_bytes().to_vec())?;
            frame.field_u64(7, expires_at)?;
        }
        Ok(frame.finish()?)
    }

    /// Decodes and validates one delivery cursor.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_OUTBOX_DELIVERY_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7])?;
        let request_id = decode_request_id(frame.required_field(1)?)?;
        let event_digest = decode_digest(frame.required_u16(2)?, frame.required_field(3)?)?;
        let lease = match (frame.field(6), frame.field(7)) {
            (None, None) => None,
            (Some(id), Some(expires)) => {
                let id: [u8; 32] = id
                    .try_into()
                    .map_err(|_| NodeCoreError::InvalidOutboxLeaseIdLength(id.len()))?;
                let expires: [u8; 8] =
                    expires
                        .try_into()
                        .map_err(|_| CanonicalDecodingError::InvalidFieldLength {
                            field_id: 7,
                            expected: 8,
                            actual: expires.len(),
                        })?;
                Some((OutboxLeaseId::new(id)?, u64::from_le_bytes(expires)))
            }
            _ => {
                return Err(NodeCoreError::PersistenceInvariant(
                    "outbox lease id and deadline must appear together",
                ));
            }
        };
        Ok(Self {
            request_id,
            event_digest,
            next_index: frame.required_u32(4)?,
            attempts: frame.required_u32(5)?,
            lease,
        })
    }
}

/// One leased outbound message. Delivery is at-least-once until acknowledged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxClaim {
    request_id: RequestId,
    index: u32,
    lease_id: OutboxLeaseId,
    expires_at_unix_millis: u64,
    message: OutboundMessage,
}

impl OutboxClaim {
    /// Returns the originating request.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the ordered message index.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Returns the lease identity required for acknowledgement.
    #[must_use]
    pub const fn lease_id(&self) -> OutboxLeaseId {
        self.lease_id
    }

    /// Returns the lease deadline.
    #[must_use]
    pub const fn expires_at_unix_millis(&self) -> u64 {
        self.expires_at_unix_millis
    }

    /// Returns the message to send through an untrusted relay.
    #[must_use]
    pub const fn message(&self) -> &OutboundMessage {
        &self.message
    }
}

/// Bounded side effects returned only after state persistence succeeds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeOutput {
    responses: Vec<NodeResponse>,
    outbound_messages: Vec<OutboundMessage>,
}

impl NodeOutput {
    /// Creates and validates one invocation's output.
    pub fn new(
        responses: Vec<NodeResponse>,
        outbound_messages: Vec<OutboundMessage>,
    ) -> Result<Self, NodeCoreError> {
        if responses.len() > MAX_NODE_OUTPUT_ITEMS {
            return Err(NodeCoreError::TooManyOutputItems {
                collection: "responses",
                count: responses.len(),
            });
        }
        if outbound_messages.len() > MAX_NODE_OUTPUT_ITEMS {
            return Err(NodeCoreError::TooManyOutputItems {
                collection: "outbound messages",
                count: outbound_messages.len(),
            });
        }

        let response_bytes = responses.iter().filter_map(|item| item.payload.as_ref());
        let outbound_bytes = outbound_messages.iter().map(|item| item.event.payload());
        let total = response_bytes
            .map(Vec::len)
            .chain(outbound_bytes.map(<[u8]>::len))
            .try_fold(0_usize, usize::checked_add)
            .ok_or(NodeCoreError::OutputTooLarge(usize::MAX))?;
        if total > MAX_NODE_OUTPUT_BYTES {
            return Err(NodeCoreError::OutputTooLarge(total));
        }

        Ok(Self {
            responses,
            outbound_messages,
        })
    }

    /// Returns adapter responses in deterministic application order.
    #[must_use]
    pub fn responses(&self) -> &[NodeResponse] {
        &self.responses
    }

    /// Returns outbound events in deterministic application order.
    #[must_use]
    pub fn outbound_messages(&self) -> &[OutboundMessage] {
        &self.outbound_messages
    }
}

/// Persisted node output paired with the committed logical atomicity domain.
///
/// Adapters carry this domain into outbox claim/ack instead of accepting a
/// domain selected by the request or independently rerunning placement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedNodeOutput {
    domain: AtomicityDomainId,
    output: NodeOutput,
}

impl ResolvedNodeOutput {
    fn new(domain: AtomicityDomainId, output: NodeOutput) -> Self {
        Self { domain, output }
    }

    /// Returns the manifest-resolved logical atomicity domain.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns output released after the domain transaction committed.
    #[must_use]
    pub const fn output(&self) -> &NodeOutput {
        &self.output
    }

    /// Consumes the wrapper and returns the persisted output.
    #[must_use]
    pub fn into_output(self) -> NodeOutput {
        self.output
    }
}

/// Storage access granted to one deterministic transactional transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeStateAccessMode {
    /// The transition may inspect but not mutate the key.
    ReadOnly,
    /// The transition may inspect and conditionally mutate the key.
    ReadWrite,
}

/// One key in a transactional node invocation's declared state access plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStateAccess {
    key: Vec<u8>,
    mode: NodeStateAccessMode,
}

impl NodeStateAccess {
    /// Creates a bounded state-access declaration.
    pub fn new(key: Vec<u8>, mode: NodeStateAccessMode) -> Result<Self, NodeCoreError> {
        validate_transactional_state_key(&key)?;
        Ok(Self { key, mode })
    }

    /// Returns the storage key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the allowed access mode.
    #[must_use]
    pub const fn mode(&self) -> NodeStateAccessMode {
        self.mode
    }
}

/// Bounded, unique, canonically key-ordered state access plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStateAccessPlan {
    accesses: Vec<NodeStateAccess>,
}

impl NodeStateAccessPlan {
    /// Validates and sorts an event-specific state access plan.
    pub fn new(mut accesses: Vec<NodeStateAccess>) -> Result<Self, NodeCoreError> {
        if accesses.is_empty() {
            return Err(NodeCoreError::EmptyStateAccessPlan);
        }
        if accesses.len() > MAX_ATOMIC_STATE_WRITES {
            return Err(NodeCoreError::TooManyStateAccesses {
                count: accesses.len(),
                maximum: MAX_ATOMIC_STATE_WRITES,
            });
        }
        accesses.sort_by(|left, right| left.key.cmp(&right.key));
        if accesses.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(NodeCoreError::DuplicateStateAccessKey);
        }
        Ok(Self { accesses })
    }

    /// Returns state accesses in deterministic raw-key order.
    #[must_use]
    pub fn accesses(&self) -> &[NodeStateAccess] {
        &self.accesses
    }

    fn access(&self, key: &[u8]) -> Option<&NodeStateAccess> {
        self.accesses
            .binary_search_by(|access| access.key.as_slice().cmp(key))
            .ok()
            .map(|index| &self.accesses[index])
    }
}

/// Immutable versioned snapshot supplied to a pure transactional transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStateSnapshot {
    values: BTreeMap<Vec<u8>, VersionedStateValue>,
    resolved_objects: Vec<ResolvedObject>,
}

impl NodeStateSnapshot {
    /// Returns the observation for a key declared by the access plan.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&VersionedStateValue> {
        self.values.get(key)
    }

    /// Iterates over observations in deterministic raw-key order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &VersionedStateValue)> {
        self.values
            .iter()
            .map(|(key, value)| (key.as_slice(), value))
    }

    /// Returns authenticated, integrity-checked object inputs in signed
    /// manifest declaration order. Generic event handlers always provide an
    /// empty slice.
    #[must_use]
    pub fn resolved_objects(&self) -> &[ResolvedObject] {
        &self.resolved_objects
    }
}

/// One state mutation produced by a pure transactional transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStateUpdate {
    key: Vec<u8>,
    mutation: StateMutation,
}

impl NodeStateUpdate {
    /// Creates a bounded canonical state replacement.
    pub fn put(key: Vec<u8>, value: Vec<u8>) -> Result<Self, NodeCoreError> {
        validate_transactional_state_key(&key)?;
        validate_state(&value)?;
        Ok(Self {
            key,
            mutation: StateMutation::Put(value),
        })
    }

    /// Creates a state deletion that will retain a storage revision tombstone.
    pub fn delete(key: Vec<u8>) -> Result<Self, NodeCoreError> {
        validate_transactional_state_key(&key)?;
        Ok(Self {
            key,
            mutation: StateMutation::Delete,
        })
    }

    /// Returns the storage key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the requested mutation.
    #[must_use]
    pub const fn mutation(&self) -> &StateMutation {
        &self.mutation
    }
}

/// How a [`TransactionalNodeTransition`]'s `object_effects` relate to the
/// signed manifest's declared `Write`/`Consume` accesses.
///
/// [`Self::Exact`] is the default and only publicly constructible mode: an
/// exact one-to-one match between every declared access and a returned
/// effect. The other two modes are narrow, `pub(crate)`-only escape hatches
/// used exclusively by the preinstalled-WASM composition, never by a caller
/// that is simply missing an effect it should have produced.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ObjectEffectMatching {
    /// Every declared `Write`/`Consume` access must have exactly one
    /// matching effect.
    Exact,
    /// A trapped call with no fee due: every declared access must have no
    /// effect at all, regardless of its mode.
    RejectedNoMutation,
    /// A trapped call that still charges a fee: only `payer` and `treasury`
    /// may have an effect; every other declared access must have none.
    RejectedFeeOnly {
        /// The sender-owned object the fee was debited from.
        payer: ObjectId,
        /// The trusted composition treasury the fee was credited to.
        treasury: ObjectId,
    },
    /// Identical to [`Self::Exact`], except the declared `Write` effect for
    /// `object_id` may change [`objects::Object::owner`] to exactly
    /// `recipient` (DR-0106). Every other declared access still requires an
    /// exact one-to-one match with an owner-preserving effect. Constructed
    /// only by `PreinstalledWasmMachine` after independently verifying a
    /// committed [`PreinstalledOwnerTransitionPolicy`] and synthesizing the
    /// owner-only effect itself — the module's own returned effects are
    /// never trusted to declare `object_id`'s new owner, and the translation
    /// boundary independently re-checks `recipient` and the unchanged body
    /// (see `authenticated_object_effects::translate_authenticated_object_effects_with_owner_transition`).
    ExactWithOwnerTransition {
        /// The one object id whose declared `Write` effect may change owner.
        object_id: ObjectId,
        /// The exact new owner address `object_id`'s effect must declare.
        recipient: Address,
    },
    /// Identical to [`Self::Exact`], except exactly one `Created` effect
    /// matching this independently derived expectation is also admitted
    /// (DR-0108). Constructed only by `PreinstalledWasmMachine` after
    /// independently verifying a committed
    /// [`crate::PreinstalledObjectCreationPolicy`]; the module's own returned
    /// `Created` effect's id/owner/type/schema are never trusted, only its
    /// body.
    ExactWithCreation {
        /// The exact, independently derived expected created object id.
        object_id: ObjectId,
        /// The exact expected owner (the projected recipient).
        owner: Address,
        /// The exact expected `type_hash`, sourced from an already-verified
        /// engine-visible input, never a literal governance commitment.
        type_hash: Digest32,
        /// The exact expected `schema_version`, sourced the same way.
        schema_version: u32,
        /// Signed engine-visible input index that selected `constructor`.
        type_source_access_index: usize,
        /// Exact constructor from the matching typed policy's type-source
        /// parameter, used to re-project and verify the created body.
        constructor: abi::ConstructorDeclaration,
    },
}

/// Candidate multi-key transition and outputs held until atomic commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionalNodeTransition {
    updates: Vec<NodeStateUpdate>,
    object_effects: Vec<ObjectEffect>,
    output: NodeOutput,
    object_effect_matching: ObjectEffectMatching,
}

impl TransactionalNodeTransition {
    /// Creates a bounded, unique, canonically key-ordered state transition.
    pub fn new(
        mut updates: Vec<NodeStateUpdate>,
        output: NodeOutput,
    ) -> Result<Self, NodeCoreError> {
        if updates.is_empty() {
            return Err(NodeCoreError::EmptyStateUpdates);
        }
        if updates.len() > MAX_ATOMIC_STATE_WRITES {
            return Err(NodeCoreError::TooManyStateUpdates {
                count: updates.len(),
                maximum: MAX_ATOMIC_STATE_WRITES,
            });
        }
        updates.sort_by(|left, right| left.key.cmp(&right.key));
        if updates.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(NodeCoreError::DuplicateStateUpdateKey);
        }
        Ok(Self {
            updates,
            object_effects: Vec::new(),
            output,
            object_effect_matching: ObjectEffectMatching::Exact,
        })
    }

    /// Creates a bounded transition that also requests deterministic owned-
    /// object mutations on the authenticated transaction path.
    ///
    /// The handler independently validates every effect against the signed
    /// access manifest and verified object versions before atomic commit.
    pub fn with_object_effects(
        mut updates: Vec<NodeStateUpdate>,
        object_effects: Vec<ObjectEffect>,
        output: NodeOutput,
    ) -> Result<Self, NodeCoreError> {
        if updates.is_empty() && object_effects.is_empty() {
            return Err(NodeCoreError::EmptyStateUpdates);
        }
        if updates.len() > MAX_ATOMIC_STATE_WRITES {
            return Err(NodeCoreError::TooManyStateUpdates {
                count: updates.len(),
                maximum: MAX_ATOMIC_STATE_WRITES,
            });
        }
        if object_effects.len() > MAX_AUTHENTICATED_OBJECT_READS {
            return Err(NodeCoreError::TooManyObjectEffects {
                actual: object_effects.len(),
                maximum: MAX_AUTHENTICATED_OBJECT_READS,
            });
        }
        updates.sort_by(|left: &NodeStateUpdate, right: &NodeStateUpdate| left.key.cmp(&right.key));
        if updates
            .windows(2)
            .any(|pair: &[NodeStateUpdate]| pair[0].key == pair[1].key)
        {
            return Err(NodeCoreError::DuplicateStateUpdateKey);
        }
        Ok(Self {
            updates,
            object_effects,
            output,
            object_effect_matching: ObjectEffectMatching::Exact,
        })
    }

    /// Creates a transition that publishes only a receipt after asserting reads.
    ///
    /// This is accepted by the structured durable handler, whose receipt write
    /// makes the overall invocation non-empty. Compatibility transaction
    /// handlers may reject it because their storage envelopes require a state
    /// mutation.
    #[must_use]
    pub const fn read_only(output: NodeOutput) -> Self {
        Self {
            updates: Vec::new(),
            object_effects: Vec::new(),
            output,
            object_effect_matching: ObjectEffectMatching::Exact,
        }
    }

    /// Creates a transition for a deterministically rejected (e.g. trapped)
    /// execution that must still commit a receipt, sender nonce, and every
    /// already-loaded object's head-read assertion, but produces no object
    /// mutation regardless of any `Write`/`Consume` access the transaction
    /// declared.
    ///
    /// Every other constructor requires an exact one-to-one match between a
    /// declared `Write`/`Consume` access and a returned effect
    /// ([`NodeCoreError::ObjectEffectMismatch`] otherwise). That rule assumes
    /// a machine that always produces effects when it succeeds; it cannot
    /// hold for genuine execution failure, where
    /// [`execution::ExecutionStatus::Failure`] discards every candidate
    /// effect by construction (see `execution::wasm_engine`). This
    /// constructor is the explicit, narrow escape hatch for exactly that
    /// case: it is only used by the preinstalled-WASM composition on a
    /// trapped call, never by a caller that is simply missing an effect it
    /// should have produced.
    #[must_use]
    pub(crate) const fn rejected_with_no_object_mutation(output: NodeOutput) -> Self {
        Self {
            updates: Vec::new(),
            object_effects: Vec::new(),
            output,
            object_effect_matching: ObjectEffectMatching::RejectedNoMutation,
        }
    }

    /// Creates a transition for a deterministically rejected (trapped) call
    /// that still charges a fee.
    ///
    /// A distinct, narrower escape hatch than
    /// [`Self::rejected_with_no_object_mutation`]: exactly `payer` and
    /// `treasury` may be mutated, and every other declared `Write`/`Consume`
    /// access must have no effect, matching the trapped application's own
    /// effects being discarded. Constructed only by `PreinstalledWasmMachine`
    /// after independently computing the fee from the committed, normalized
    /// `gas_used` and composing it over the loaded (pre-execution) bodies —
    /// never by a caller simply missing an effect it should have produced.
    /// The normal exact-matching path ([`ObjectEffectMatching::Exact`]) is
    /// completely unaffected by this mode's existence.
    #[must_use]
    pub(crate) fn rejected_with_fee_only_mutation(
        output: NodeOutput,
        object_effects: Vec<ObjectEffect>,
        payer: ObjectId,
        treasury: ObjectId,
    ) -> Self {
        Self {
            updates: Vec::new(),
            object_effects,
            output,
            object_effect_matching: ObjectEffectMatching::RejectedFeeOnly { payer, treasury },
        }
    }

    /// Creates a transition identical to [`Self::with_object_effects`],
    /// except the declared `Write` effect for `owner_transition_object_id`
    /// may change owner to exactly `recipient` (DR-0106).
    ///
    /// Constructed only by `PreinstalledWasmMachine` after independently
    /// verifying a committed [`PreinstalledOwnerTransitionPolicy`] and
    /// synthesizing the owner-only effect itself — never by a caller simply
    /// wanting to bypass the default owner-preserving rule.
    pub(crate) fn with_object_effects_and_owner_transition(
        mut updates: Vec<NodeStateUpdate>,
        object_effects: Vec<ObjectEffect>,
        output: NodeOutput,
        owner_transition_object_id: ObjectId,
        recipient: Address,
    ) -> Result<Self, NodeCoreError> {
        if updates.is_empty() && object_effects.is_empty() {
            return Err(NodeCoreError::EmptyStateUpdates);
        }
        if updates.len() > MAX_ATOMIC_STATE_WRITES {
            return Err(NodeCoreError::TooManyStateUpdates {
                count: updates.len(),
                maximum: MAX_ATOMIC_STATE_WRITES,
            });
        }
        if object_effects.len() > MAX_AUTHENTICATED_OBJECT_READS {
            return Err(NodeCoreError::TooManyObjectEffects {
                actual: object_effects.len(),
                maximum: MAX_AUTHENTICATED_OBJECT_READS,
            });
        }
        updates.sort_by(|left: &NodeStateUpdate, right: &NodeStateUpdate| left.key.cmp(&right.key));
        if updates
            .windows(2)
            .any(|pair: &[NodeStateUpdate]| pair[0].key == pair[1].key)
        {
            return Err(NodeCoreError::DuplicateStateUpdateKey);
        }
        Ok(Self {
            updates,
            object_effects,
            output,
            object_effect_matching: ObjectEffectMatching::ExactWithOwnerTransition {
                object_id: owner_transition_object_id,
                recipient,
            },
        })
    }

    /// Creates a transition identical to [`Self::with_object_effects`],
    /// except exactly one `Created` effect matching the given independently
    /// derived expectation is also admitted (DR-0108).
    ///
    /// Constructed only by `PreinstalledWasmMachine` after independently
    /// verifying a committed [`crate::PreinstalledObjectCreationPolicy`];
    /// never by a caller simply wanting to bypass the default rejection of
    /// every `Created` effect.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_object_effects_and_creation(
        mut updates: Vec<NodeStateUpdate>,
        object_effects: Vec<ObjectEffect>,
        output: NodeOutput,
        created_object_id: ObjectId,
        created_owner: Address,
        created_type_hash: Digest32,
        created_schema_version: u32,
        created_type_source_access_index: usize,
        created_constructor: abi::ConstructorDeclaration,
    ) -> Result<Self, NodeCoreError> {
        if updates.is_empty() && object_effects.is_empty() {
            return Err(NodeCoreError::EmptyStateUpdates);
        }
        if updates.len() > MAX_ATOMIC_STATE_WRITES {
            return Err(NodeCoreError::TooManyStateUpdates {
                count: updates.len(),
                maximum: MAX_ATOMIC_STATE_WRITES,
            });
        }
        if object_effects.len() > MAX_AUTHENTICATED_OBJECT_READS.saturating_add(1) {
            return Err(NodeCoreError::TooManyObjectEffects {
                actual: object_effects.len(),
                maximum: MAX_AUTHENTICATED_OBJECT_READS.saturating_add(1),
            });
        }
        updates.sort_by(|left: &NodeStateUpdate, right: &NodeStateUpdate| left.key.cmp(&right.key));
        if updates
            .windows(2)
            .any(|pair: &[NodeStateUpdate]| pair[0].key == pair[1].key)
        {
            return Err(NodeCoreError::DuplicateStateUpdateKey);
        }
        Ok(Self {
            updates,
            object_effects,
            output,
            object_effect_matching: ObjectEffectMatching::ExactWithCreation {
                object_id: created_object_id,
                owner: created_owner,
                type_hash: created_type_hash,
                schema_version: created_schema_version,
                type_source_access_index: created_type_source_access_index,
                constructor: created_constructor,
            },
        })
    }

    /// Returns state updates in deterministic raw-key order.
    #[must_use]
    pub fn updates(&self) -> &[NodeStateUpdate] {
        &self.updates
    }

    /// Returns output held until every state update commits.
    #[must_use]
    pub const fn output(&self) -> &NodeOutput {
        &self.output
    }

    /// Returns deterministic object effects held until the same atomic commit
    /// as state, nonce, receipt, and outbox.
    #[must_use]
    pub fn object_effects(&self) -> &[ObjectEffect] {
        &self.object_effects
    }

    /// Returns how this transition's `object_effects` relate to the signed
    /// manifest's declared accesses.
    #[must_use]
    const fn effect_matching(&self) -> &ObjectEffectMatching {
        &self.object_effect_matching
    }
}

fn reject_object_effects_without_authenticated_dispatch(
    effects: &[ObjectEffect],
) -> Result<(), NodeCoreError> {
    let mutations: Vec<DurableObjectMutationEntry> =
        translate_authenticated_object_effects(&[], effects, None, 0)?;
    debug_assert!(mutations.is_empty());
    Ok(())
}

/// Application transition over a declared, versioned multi-key snapshot.
pub trait TransactionalNodeStateMachine {
    /// Derives the bounded state keys and modes required by one validated event.
    fn access_plan(&self, event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError>;

    /// Computes one pure transition without performing I/O or retaining state.
    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError>;
}

/// One validated candidate state replacement and its deferred outputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeTransition {
    next_state: Vec<u8>,
    output: NodeOutput,
}

impl NodeTransition {
    /// Creates a transition around one bounded canonical state value.
    pub fn new(next_state: Vec<u8>, output: NodeOutput) -> Result<Self, NodeCoreError> {
        validate_state(&next_state)?;
        Ok(Self { next_state, output })
    }

    /// Returns the candidate persisted state.
    #[must_use]
    pub fn next_state(&self) -> &[u8] {
        &self.next_state
    }

    /// Returns output held until compare-and-swap succeeds.
    #[must_use]
    pub const fn output(&self) -> &NodeOutput {
        &self.output
    }
}

/// Application-specific deterministic transition over explicit persisted bytes.
pub trait NodeStateMachine {
    /// Computes one transition without performing I/O or retaining protocol state.
    fn transition(
        &self,
        current_state: Option<&[u8]>,
        event: &NodeEvent,
    ) -> Result<NodeTransition, NodeCoreError>;
}

fn asserted_transition_writes(
    plan: &NodeStateAccessPlan,
    snapshot: &NodeStateSnapshot,
    updates: Vec<NodeStateUpdate>,
) -> Result<Vec<StateWrite>, NodeCoreError> {
    let mut mutations = BTreeMap::new();
    for update in updates {
        let Some(access) = plan.access(update.key()) else {
            return Err(NodeCoreError::UndeclaredStateUpdate(update.key));
        };
        if access.mode() != NodeStateAccessMode::ReadWrite {
            return Err(NodeCoreError::ReadOnlyStateUpdate(update.key));
        }
        mutations.insert(update.key, update.mutation);
    }

    let mut writes = Vec::with_capacity(plan.accesses().len());
    for access in plan.accesses() {
        let observed = snapshot
            .get(access.key())
            .ok_or(NodeCoreError::PersistenceInvariant(
                "declared access missing from snapshot",
            ))?;
        let mutation = mutations
            .remove(access.key())
            .unwrap_or(StateMutation::Assert);
        writes.push(StateWrite::new(
            access.key().to_vec(),
            observed.revision(),
            mutation,
        )?);
    }
    Ok(writes)
}

fn domain_transition_parts(
    plan: &NodeStateAccessPlan,
    snapshot: &NodeStateSnapshot,
    updates: Vec<NodeStateUpdate>,
) -> Result<(Vec<StateReadAssertion>, Vec<StateMutationEntry>), NodeCoreError> {
    let mut mutations = Vec::with_capacity(updates.len());
    for update in updates {
        let Some(access) = plan.access(update.key()) else {
            return Err(NodeCoreError::UndeclaredStateUpdate(update.key));
        };
        if access.mode() != NodeStateAccessMode::ReadWrite {
            return Err(NodeCoreError::ReadOnlyStateUpdate(update.key));
        }
        mutations.push(StateMutationEntry::new(update.key, update.mutation)?);
    }

    let reads = plan
        .accesses()
        .iter()
        .map(|access| {
            let observed =
                snapshot
                    .get(access.key())
                    .ok_or(NodeCoreError::PersistenceInvariant(
                        "declared access missing from snapshot",
                    ))?;
            Ok(StateReadAssertion::new(
                access.key().to_vec(),
                observed.revision(),
            )?)
        })
        .collect::<Result<Vec<_>, NodeCoreError>>()?;
    Ok((reads, mutations))
}

fn validate_generic_event(event: &NodeEvent, config: &NodeConfig) -> Result<(), NodeCoreError> {
    event.validate_context(config)?;
    if event.kind() == NodeEventKind::SubmitTransaction {
        return Err(NodeCoreError::UnauthenticatedTransactionSubmission);
    }
    Ok(())
}

fn validate_sender_nonce_namespace(
    plan: &NodeStateAccessPlan,
    layout: &PersistenceLayout,
) -> Result<(), NodeCoreError> {
    let nonce_prefix = layout.sender_nonce_prefix();
    for access in plan.accesses() {
        if access.key().starts_with(nonce_prefix.as_slice())
            || access
                .key()
                .starts_with(publication::PUBLICATION_STATE_PREFIX)
            || local_instance_state::is_reserved(access.key())
        {
            return Err(NodeCoreError::ReservedStateAccess(access.key().to_vec()));
        }
    }
    Ok(())
}

/// Handles one event inside one explicit atomicity domain.
///
/// This is the domain-aware successor to [`handle_transactional_event`]. Every
/// declared observation enters the dedicated read set, while only returned
/// updates enter the mutation set. Conflicts publish neither state nor output.
pub fn handle_domain_transactional_event<R, M>(
    runtime: &R,
    domain: AtomicityDomainId,
    config: &NodeConfig,
    event: NodeEvent,
    machine: &M,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let plan = machine.access_plan(&event)?;
    handle_domain_transactional_event_with_plan(runtime, domain, config, event, machine, plan)
}

/// Resolves one event's domain from committed protocol configuration.
///
/// The access plan is derived exactly once before storage reads. The resolved
/// domain is returned beside committed output for subsequent outbox delivery.
pub fn handle_resolved_transactional_event<R, M>(
    runtime: &R,
    placement: &DomainPlacementManifest,
    config: &NodeConfig,
    event: NodeEvent,
    machine: &M,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let plan = machine.access_plan(&event)?;
    let domain = placement.resolve_domain(event.epoch(), plan.accesses().len())?;
    let output =
        handle_domain_transactional_event_with_plan(runtime, domain, config, event, machine, plan)?;
    Ok(ResolvedNodeOutput::new(domain, output))
}

fn handle_domain_transactional_event_with_plan<R, M>(
    runtime: &R,
    domain: AtomicityDomainId,
    config: &NodeConfig,
    event: NodeEvent,
    machine: &M,
    plan: NodeStateAccessPlan,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    let layout = PersistenceLayout::new(config.chain_id.clone(), config.protocol_version);
    validate_sender_nonce_namespace(&plan, &layout)?;
    let mut values = BTreeMap::new();
    for access in plan.accesses() {
        let observed = runtime
            .state_store()
            .get_versioned_in_domain(domain, access.key())?;
        if let Some(value) = observed.value() {
            validate_state(value)?;
        }
        values.insert(access.key.clone(), observed);
    }
    let snapshot = NodeStateSnapshot {
        values,
        resolved_objects: Vec::new(),
    };

    let transition = machine.transition(&snapshot, &event)?;
    reject_object_effects_without_authenticated_dispatch(transition.object_effects())?;
    validate_output_context(transition.output(), &event, config)?;
    let (reads, mutations) = domain_transition_parts(&plan, &snapshot, transition.updates)?;
    let transaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(reads)?,
        AtomicStateMutationSet::new(mutations)?,
    )?;
    match runtime.state_store().commit_transaction(transaction)? {
        AtomicStateWriteResult::Committed => Ok(transition.output),
        AtomicStateWriteResult::Conflict { .. } => Err(NodeCoreError::StateConflict),
    }
}

/// Handles one event through a declared multi-key atomic state transition.
///
/// The event context and access plan are validated before storage reads. Every
/// observed revision, including read-only and absent state, is asserted in the
/// final transaction, and output remains private until all writes commit.
/// Conflicts are surfaced without retry.
pub fn handle_transactional_event<R, M>(
    runtime: &R,
    config: &NodeConfig,
    event: NodeEvent,
    machine: &M,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: TransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let plan = machine.access_plan(&event)?;
    let layout = PersistenceLayout::new(config.chain_id.clone(), config.protocol_version);
    validate_sender_nonce_namespace(&plan, &layout)?;
    let mut values = BTreeMap::new();
    for access in plan.accesses() {
        let observed = runtime.state_store().get_versioned(access.key())?;
        if let Some(value) = observed.value() {
            validate_state(value)?;
        }
        values.insert(access.key.clone(), observed);
    }
    let snapshot = NodeStateSnapshot {
        values,
        resolved_objects: Vec::new(),
    };

    let transition = machine.transition(&snapshot, &event)?;
    reject_object_effects_without_authenticated_dispatch(transition.object_effects())?;
    validate_output_context(transition.output(), &event, config)?;

    let writes = asserted_transition_writes(&plan, &snapshot, transition.updates)?;

    let write_set = AtomicStateWriteSet::new(writes)?;
    match runtime.state_store().commit_atomic(write_set)? {
        AtomicStateWriteResult::Committed => Ok(transition.output),
        AtomicStateWriteResult::Conflict { .. } => Err(NodeCoreError::StateConflict),
    }
}

/// Handles one event with atomic state, deduplication, and outbox persistence.
///
/// A matching committed duplicate returns its persisted responses without
/// re-running the state machine or re-enqueuing outbound messages. Reusing a
/// request identifier for different canonical event bytes fails closed.
pub fn handle_idempotent_event<R, M>(
    runtime: &R,
    config: &NodeConfig,
    resolver: &HashSuiteResolver,
    event: NodeEvent,
    machine: &M,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: TransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let event_digest = event.digest(resolver)?;
    let layout = PersistenceLayout::new(config.chain_id.clone(), config.protocol_version);
    let request_bytes = *event.request_id.as_bytes();
    let dedup_key = layout.request_dedup_key(request_bytes);
    let outbox_key = layout.outbox_batch_key(request_bytes);
    let delivery_key = layout.outbox_delivery_key(request_bytes);

    let plan = machine.access_plan(&event)?;
    validate_sender_nonce_namespace(&plan, &layout)?;
    let maximum_application_accesses =
        core::cmp::min(MAX_ATOMIC_STATE_READS, MAX_ATOMIC_STATE_WRITES).saturating_sub(3);
    if plan.accesses.len() > maximum_application_accesses {
        return Err(NodeCoreError::TooManyStateAccesses {
            count: plan.accesses.len(),
            maximum: maximum_application_accesses,
        });
    }
    for reserved in [&dedup_key, &outbox_key, &delivery_key] {
        if plan.access(reserved).is_some() {
            return Err(NodeCoreError::ReservedStateAccess(reserved.clone()));
        }
    }

    let dedup = runtime.state_store().get_versioned(&dedup_key)?;
    let outbox = runtime.state_store().get_versioned(&outbox_key)?;
    let delivery = runtime.state_store().get_versioned(&delivery_key)?;

    if let Some(bytes) = dedup.value() {
        let record = NodeDedupRecord::decode(bytes)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid dedup record"))?;
        if record.request_id() != event.request_id() || record.event_digest() != event_digest {
            return Err(NodeCoreError::RequestIdReuse);
        }
        let batch_bytes = outbox.value().ok_or(NodeCoreError::PersistenceInvariant(
            "dedup exists without outbox",
        ))?;
        let batch = NodeOutboxBatch::decode(batch_bytes)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox batch"))?;
        if batch.request_id() != event.request_id() || batch.event_digest() != event_digest {
            return Err(NodeCoreError::PersistenceInvariant(
                "dedup and outbox identities differ",
            ));
        }
        for message in batch.messages() {
            message.event().validate_context(config)?;
        }
        let delivery_bytes = delivery.value().ok_or(NodeCoreError::PersistenceInvariant(
            "dedup exists without outbox delivery state",
        ))?;
        let delivery_record = NodeOutboxDelivery::decode(delivery_bytes)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox delivery state"))?;
        if delivery_record.request_id != event.request_id()
            || delivery_record.event_digest != event_digest
        {
            return Err(NodeCoreError::PersistenceInvariant(
                "dedup and outbox delivery identities differ",
            ));
        }
        return NodeOutput::new(record.responses().to_vec(), Vec::new());
    }
    if outbox.value().is_some() || delivery.value().is_some() {
        return Err(NodeCoreError::PersistenceInvariant(
            "outbox state exists without dedup",
        ));
    }

    let mut values = BTreeMap::new();
    for access in plan.accesses() {
        let observed = runtime.state_store().get_versioned(access.key())?;
        if let Some(value) = observed.value() {
            validate_state(value)?;
        }
        values.insert(access.key.clone(), observed);
    }
    let snapshot = NodeStateSnapshot {
        values,
        resolved_objects: Vec::new(),
    };
    let transition = machine.transition(&snapshot, &event)?;
    reject_object_effects_without_authenticated_dispatch(transition.object_effects())?;
    validate_output_context(transition.output(), &event, config)?;
    let dedup_record = NodeDedupRecord::new(
        event.request_id(),
        event_digest,
        transition.output.responses.clone(),
    )?;
    let outbox_batch = NodeOutboxBatch::new(
        event.request_id(),
        event_digest,
        transition.output.outbound_messages.clone(),
    )?;
    let outbox_delivery = NodeOutboxDelivery::pending(event.request_id(), event_digest);

    let mut writes = asserted_transition_writes(&plan, &snapshot, transition.updates)?;
    writes.push(StateWrite::new(
        dedup_key,
        dedup.revision(),
        StateMutation::Put(dedup_record.encode()?),
    )?);
    writes.push(StateWrite::new(
        outbox_key,
        outbox.revision(),
        StateMutation::Put(outbox_batch.encode()?),
    )?);
    writes.push(StateWrite::new(
        delivery_key,
        delivery.revision(),
        StateMutation::Put(outbox_delivery.encode()?),
    )?);

    let write_set = AtomicStateWriteSet::new(writes)?;
    match runtime.state_store().commit_atomic(write_set)? {
        AtomicStateWriteResult::Committed => Ok(transition.output),
        AtomicStateWriteResult::Conflict { .. } => Err(NodeCoreError::StateConflict),
    }
}

/// Handles one idempotent event inside one explicit atomicity domain.
///
/// Application state, the request receipt, the immutable outbox batch, and its
/// initial delivery cursor share one complete read set and one atomic commit.
/// A matching replay returns persisted responses without re-running the state
/// machine. This additive path does not change legacy unscoped storage.
pub fn handle_domain_idempotent_event<R, M>(
    runtime: &R,
    domain: AtomicityDomainId,
    config: &NodeConfig,
    resolver: &HashSuiteResolver,
    event: NodeEvent,
    machine: &M,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let plan = machine.access_plan(&event)?;
    handle_domain_idempotent_event_with_plan(
        runtime, domain, config, resolver, event, machine, plan,
    )
}

/// Resolves and commits one idempotent event from protocol configuration.
///
/// The returned domain is the only valid domain for delivering the committed
/// outbox. Placement is evaluated once from the non-empty bounded access plan
/// before any storage read.
pub fn handle_resolved_idempotent_event<R, M>(
    runtime: &R,
    placement: &DomainPlacementManifest,
    config: &NodeConfig,
    resolver: &HashSuiteResolver,
    event: NodeEvent,
    machine: &M,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let plan = machine.access_plan(&event)?;
    let domain = placement.resolve_domain(event.epoch(), plan.accesses().len())?;
    let output = handle_domain_idempotent_event_with_plan(
        runtime, domain, config, resolver, event, machine, plan,
    )?;
    Ok(ResolvedNodeOutput::new(domain, output))
}

/// Resolves and commits one idempotent event through the normalized durable boundary.
///
/// The access plan and logical domain are resolved before storage I/O. A typed
/// completed-request receipt is checked before application state is loaded, so
/// an exact replay returns only its persisted responses without rerunning the
/// transition. New application state, the receipt, and any ordered outbox are
/// then submitted as one structured invocation. Output is never released for a
/// rejected or indeterminate commit.
///
/// This entrypoint never declares an authenticated object dispatch, so it
/// never loads or fetches an object body and takes no `BlobStore` component:
/// only the authenticated entrypoints, which always declare a dispatch, do.
pub fn handle_resolved_durable_idempotent_event<S, M>(
    store: &S,
    context: &DurableOperationContext,
    placement: &DomainPlacementManifest,
    config: &NodeConfig,
    resolver: &HashSuiteResolver,
    event: NodeEvent,
    machine: &M,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let plan = machine.access_plan(&event)?;
    let domain = placement.resolve_domain(event.epoch(), plan.accesses().len())?;
    let output = handle_durable_idempotent_event_with_plan(
        None, store, context, domain, resolver, event, machine, plan, None, None, None, None,
    )?;
    Ok(ResolvedNodeOutput::new(domain, output))
}

/// Commits one previously authenticated `SubmitTransaction` through the
/// normalized durable boundary.
///
/// Unlike [`handle_resolved_durable_idempotent_event`], this entrypoint accepts
/// only the unforgeable [`AuthenticatedSubmitTransaction`] wrapper. The access
/// plan is derived only after authentication, and its logical domain comes from
/// the same committed placement captured when the wrapper was constructed.
/// Exact duplicates are still authenticated before receipt reconciliation. A
/// fresh request must match the persisted per-sender, per-epoch next nonce; its
/// checked increment commits atomically with the application state, receipt,
/// and outbox. The transaction's signed object-access manifest is loaded and
/// authorized against the same authenticated sender: every declared entry
/// must resolve, through its exact current head and immutable version, to a
/// typed object whose owner is that sender's address or is immutable, and the
/// resulting head-read assertions commit atomically alongside everything
/// else. A blob-backed entry is fetched from `blob_store` and independently
/// verified exactly like [`load_and_authorize_objects`] does for every other
/// authenticated entrypoint. This established entrypoint remains read-only;
/// `Write`/`Consume` and shared/system owners fail closed rather than
/// silently downgrade. Use the explicit owned-effects entrypoint for the
/// bounded MVP mutation surface.
pub fn handle_authenticated_resolved_durable_submit_transaction<S, B, M>(
    blob_store: &B,
    store: &S,
    context: &DurableOperationContext,
    resolver: &HashSuiteResolver,
    submission: AuthenticatedSubmitTransaction,
    machine: &M,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
    B: BlobStore,
    M: TransactionalNodeStateMachine,
{
    handle_authenticated_submit_transaction_with_policy(
        blob_store,
        store,
        context,
        resolver,
        submission,
        machine,
        AuthenticatedObjectPolicy::ReadOnly,
    )
}

/// Commits authenticated owned inline-object Write/Consume effects through the
/// same durable invocation as sender nonce, application state, receipt, and
/// outbox.
///
/// `created_checkpoint` is trusted node composition, never request input. The
/// caller must derive it from its already-validated chain progress. Node-core
/// rejects a value lower than the previous immutable object's checkpoint.
/// Create, shared/system ownership, and immutable mutations remain unsupported
/// and fail closed. A declared `Write`/`Consume` access may read a
/// blob-backed previous version (fetched and verified through `blob_store`
/// exactly like the read-only entrypoint). A new version stays inline through
/// [`MAX_INLINE_OBJECT_BODY_BYTES`] and is published to `blob_store` before
/// the structured commit only when its canonical body exceeds that fixed
/// threshold.
pub fn handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects<S, B, M>(
    blob_store: &B,
    store: &S,
    context: &DurableOperationContext,
    resolver: &HashSuiteResolver,
    submission: AuthenticatedSubmitTransaction,
    created_checkpoint: u64,
    machine: &M,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
    B: BlobStore,
    M: TransactionalNodeStateMachine,
{
    handle_authenticated_submit_transaction_with_policy(
        blob_store,
        store,
        context,
        resolver,
        submission,
        machine,
        AuthenticatedObjectPolicy::OwnedMutations { created_checkpoint },
    )
}

/// The minimum `Transaction.protocol_version` at which node-core will ever
/// activate a committed [`PreinstalledOwnerTransitionPolicy`] (DR-0106).
///
/// A matching policy below this version is rejected outright with
/// [`NodeCoreError::OwnerTransitionProtocolVersionTooLow`], checked once in
/// [`PreinstalledWasmMachine::transition`] strictly before the WASM engine
/// ever runs (alongside the typed-entrypoint-policy check) — never treated as
/// though the policy were merely absent, and never deferred to a later
/// engine-effect mismatch. See
/// `docs/architecture/decisions/0106-typed-entrypoint-owner-transition.md`.
pub const MIN_OWNER_TRANSITION_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(4);

/// The minimum `Transaction.protocol_version` at which node-core will ever
/// activate a committed [`PreinstalledObjectCreationPolicy`] (DR-0108).
///
/// A matching policy below this version is rejected outright with
/// [`NodeCoreError::ObjectCreationProtocolVersionTooLow`], checked once in
/// [`PreinstalledWasmMachine::transition`] strictly before the WASM engine
/// ever runs, mirroring [`MIN_OWNER_TRANSITION_PROTOCOL_VERSION`]'s gate.
pub const MIN_OBJECT_CREATION_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(5);

/// One owner-only mutation node-core independently synthesized for a
/// committed [`PreinstalledOwnerTransitionPolicy`] (DR-0106).
struct OwnerTransitionSynthesis {
    object_id: ObjectId,
    recipient: Address,
    effect: ObjectEffect,
}

/// Independently derived expectation for the one `Created` effect authorized
/// by a committed [`PreinstalledObjectCreationPolicy`] (DR-0108).
struct ObjectCreationExpectation {
    object_id: ObjectId,
    owner: Address,
    type_hash: Digest32,
    schema_version: u32,
    type_source_access_index: usize,
    constructor: abi::ConstructorDeclaration,
}

/// The internal `TransactionalNodeStateMachine` behind
/// [`handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution`].
///
/// This machine declares no opaque application state key: it is object-only.
/// [`Self::access_plan`] returns the crate-private empty
/// [`NodeStateAccessPlan`] representation directly (bypassing the public
/// [`NodeStateAccessPlan::new`], which still rejects an empty plan for every
/// other caller) instead of asserting a dummy/fake state key purely to
/// satisfy that constructor.
struct PreinstalledWasmMachine<'a> {
    transaction: &'a Transaction,
    resolver: &'a HashSuiteResolver,
    registered_module: Option<&'a SystemModule>,
    catalog: &'a PreinstalledModuleCatalog,
    engine: &'a WasmExecutionEngine,
    /// Committed `GasSchedule`/`FeeAssetRegistry`, captured at authentication
    /// time from the same committed `ProtocolConfig` as `registered_module`.
    fee_policy: &'a CommittedFeePolicy,
    /// Trusted node composition's fee-charging capability, if this
    /// deployment wires one. `None` preserves byte-identical historical
    /// behavior: no admission check, no engine-input exclusion, no charge.
    fee_composition: Option<PreinstalledFeeComposition<'a>>,
    resolved_module: std::cell::OnceCell<&'a PreinstalledModuleCatalogEntry>,
    /// The verified, loaded treasury object, populated by the durable
    /// handler (never by this machine) immediately after object load and
    /// strictly before `transition` runs, so `transition` can compose and
    /// merge a fee charge over a body the execution engine itself never
    /// receives (see `load_and_authorize_objects`'s engine-visibility
    /// exclusion).
    treasury_object: std::cell::OnceCell<Object>,
}

impl<'a> PreinstalledWasmMachine<'a> {
    /// Resolves and verifies the exact committed catalog entry at most once
    /// for this request. The durable handler invokes this only after receipt
    /// and nonce reconciliation and before object I/O; `transition` reuses the
    /// same verified reference without repeating resolution.
    fn resolve_once(
        &self,
        epoch: Epoch,
    ) -> Result<&'a PreinstalledModuleCatalogEntry, NodeCoreError> {
        if let Some(module) = self.resolved_module.get() {
            return Ok(*module);
        }
        let module: &'a PreinstalledModuleCatalogEntry = resolve_preinstalled_module(
            &self.transaction.module_ref,
            self.registered_module,
            self.catalog,
            epoch,
            self.resolver,
        )?;
        self.resolved_module.set(module).map_err(|_| {
            NodeCoreError::PersistenceInvariant("preinstalled module resolved twice")
        })?;
        Ok(module)
    }

    /// Deterministic worst-case fee at `gas_limit` under the committed
    /// schedule. Monotonic in `execution_units`, so a settlement that
    /// succeeds here always bounds the actual post-execution charge.
    fn worst_case_fee_units(&self) -> Result<fees::Amount, NodeCoreError> {
        fees::calculate_fee(
            &fees::FeeUsage {
                execution_units: self.transaction.gas_limit,
                ..Default::default()
            },
            &self.fee_policy.gas_schedule,
        )
        .map_err(NodeCoreError::FeePaymentRejected)
    }

    /// Pre-execution, fail-closed, zero-I/O-beyond-already-loaded admission.
    ///
    /// Returns `None` when this deployment wires no fee composition and the
    /// committed schedule's worst-case fee at `gas_limit` is zero and the
    /// transaction declares no `fee_payment`, or when a fee composition is
    /// wired but the worst-case fee is zero and the transaction declares no
    /// treasury access and no `fee_payment` — both byte-identical to
    /// historical fee-free behavior. A declared `fee_payment` against a zero
    /// worst-case fee is rejected ([`NodeCoreError::FeePaymentNotRequired`])
    /// rather than silently ignored, and — when this deployment wires no fee
    /// composition at all — a declared `fee_payment` is rejected
    /// ([`NodeCoreError::FeePaymentUnsupportedOnPath`]) while a non-zero
    /// committed worst-case fee with no declared `fee_payment` is rejected
    /// ([`NodeCoreError::FeeCompositionUnavailable`]): this call is only
    /// reached once `transition` actually runs a non-replayed invocation, so
    /// neither check ever affects exact-replay short-circuiting. Otherwise
    /// returns the exact declared `fee_payment`, the verified sender-owned
    /// fee object id, and the trusted treasury id, after enforcing every
    /// invariant in `docs/architecture/core-protocol.md`'s fee lifecycle section: the treasury
    /// is the final declared `Write` access, present exactly when a fee is
    /// due; the fee object is a distinct declared `Write` access owned by
    /// the sender; and the worst-case settlement (at `gas_limit`) succeeds
    /// against the signed `max_fee`, so a later post-execution settlement at
    /// the lower actual `gas_used` can never fail from insufficient
    /// authorization.
    fn admit_fee(
        &self,
        state: &NodeStateSnapshot,
    ) -> Result<Option<(&'a fees::FeePayment, ObjectId, ObjectId)>, NodeCoreError> {
        let Some(composition) = &self.fee_composition else {
            // No fee-charging composition is wired for this deployment. A
            // declared `fee_payment` can never be settled without one, and a
            // committed non-zero worst-case fee can never be collected
            // without one either — both must fail closed rather than
            // silently admitting the transaction as fee-free. Historical
            // fee-free behavior is preserved only for the zero-schedule,
            // no-`fee_payment` case.
            if self.transaction.fee_payment.is_some() {
                return Err(NodeCoreError::FeePaymentUnsupportedOnPath);
            }
            if self.worst_case_fee_units()?.get() > 0 {
                return Err(NodeCoreError::FeeCompositionUnavailable);
            }
            return Ok(None);
        };
        let treasury_id = composition.treasury_object_id;
        let entries = &self.transaction.access_manifest.entries;
        let treasury_declared_anywhere = entries
            .iter()
            .any(|entry| entry.object_ref.id == treasury_id);
        let fee_required = self.worst_case_fee_units()?.get() > 0;

        if !fee_required {
            if treasury_declared_anywhere {
                return Err(NodeCoreError::FeeTreasuryAccessMisdeclared);
            }
            // Historical fee-free behavior (`Ok(None)`, no admission check,
            // no engine-input exclusion, no charge) is preserved only when
            // the transaction also declares no `fee_payment`: a declared
            // `fee_payment` against a zero worst-case fee can never be
            // legitimately settled, so it must fail closed here rather than
            // being silently ignored.
            if self.transaction.fee_payment.is_some() {
                return Err(NodeCoreError::FeePaymentNotRequired);
            }
            return Ok(None);
        }

        let fee_payment = self
            .transaction
            .fee_payment
            .as_ref()
            .ok_or(NodeCoreError::FeePaymentRequired)?;
        let treasury_is_final_write = entries.last().is_some_and(|entry| {
            entry.object_ref.id == treasury_id && entry.mode == AccessMode::Write
        });
        if !treasury_is_final_write {
            return Err(NodeCoreError::FeeTreasuryAccessMisdeclared);
        }
        if fee_payment.fee_object.id == treasury_id {
            return Err(NodeCoreError::FeeObjectIsTreasury);
        }
        let fee_object_id = entries
            .iter()
            .find(|entry| {
                entry.object_ref == fee_payment.fee_object && entry.mode == AccessMode::Write
            })
            .map(|entry| entry.object_ref.id)
            .ok_or(NodeCoreError::FeeObjectNotDeclaredWrite)?;
        let fee_object = state
            .resolved_objects()
            .iter()
            .find(|resolved| resolved.object.id == fee_object_id)
            .map(|resolved| resolved.object.owner.clone())
            .ok_or(NodeCoreError::FeeObjectNotDeclaredWrite)?;
        if fee_object != Owner::Address(self.transaction.sender) {
            return Err(NodeCoreError::FeeObjectNotOwnedBySender);
        }
        let worst_case = self.worst_case_fee_units()?;
        fees::settle_fee_payment(&self.fee_policy.fee_assets, fee_payment, worst_case)
            .map_err(NodeCoreError::FeePaymentRejected)?;

        Ok(Some((fee_payment, fee_object_id, treasury_id)))
    }

    /// Deterministic post-execution fee at the exact committed `gas_used`.
    fn settle_actual_fee(
        &self,
        fee_payment: &fees::FeePayment,
        gas_used: u64,
    ) -> Result<fees::Amount, NodeCoreError> {
        let fee_units = fees::calculate_fee(
            &fees::FeeUsage {
                execution_units: gas_used,
                ..Default::default()
            },
            &self.fee_policy.gas_schedule,
        )
        .map_err(NodeCoreError::FeePaymentRejected)?;
        fees::settle_fee_payment(&self.fee_policy.fee_assets, fee_payment, fee_units)
            .map_err(NodeCoreError::FeePaymentRejected)
    }

    /// Composes and merges one settled fee charge into `application_effects`.
    ///
    /// Node-core, not the composer, builds every returned
    /// [`ObjectEffect::Mutated`]: identity, version (+1 from the verified
    /// loaded object), owner, type, and schema come from node-core's own
    /// verified state, never from the composer's opaque bytes. When
    /// `application_effects` already contains a `Mutated` effect for
    /// `fee_object_id` (the success path, `fee_object` may equal an
    /// application-mutated object), its `.data` is overwritten in place —
    /// one effect, one version bump — instead of inserting a second effect
    /// for the same id. The treasury never appears in
    /// `application_effects` (the module never sees it), so it always gets a
    /// fresh effect. At most one `application_effects` entry may name
    /// `fee_object_id`, and it must be `Mutated`
    /// ([`NodeCoreError::DuplicateObjectEffect`] /
    /// [`NodeCoreError::ObjectCreationUnsupported`] /
    /// [`NodeCoreError::ObjectEffectMismatch`] otherwise), and the composer's
    /// returned bodies must both differ from their effective inputs
    /// ([`NodeCoreError::FeeCompositionNoOp`] otherwise): a non-zero charge
    /// always changes both the payer and the treasury.
    fn charge_fee(
        &self,
        state: &NodeStateSnapshot,
        fee_payment: &fees::FeePayment,
        fee_object_id: ObjectId,
        treasury_id: ObjectId,
        amount: fees::Amount,
        application_effects: Vec<ObjectEffect>,
    ) -> Result<Vec<ObjectEffect>, NodeCoreError> {
        let composition = self
            .fee_composition
            .as_ref()
            .ok_or(NodeCoreError::FeeCompositionUnavailable)?;
        let payer_loaded: Object = state
            .resolved_objects()
            .iter()
            .find(|resolved| resolved.object.id == fee_object_id)
            .map(|resolved| resolved.object.clone())
            .ok_or(NodeCoreError::FeeObjectNotDeclaredWrite)?;
        let treasury_loaded: &Object = self
            .treasury_object
            .get()
            .ok_or(NodeCoreError::FeeCompositionUnavailable)?;

        // At most one application effect may name the fee object, and if
        // present it must be exactly `Mutated`: a duplicate effect, or a
        // `Created`/`Deleted` effect for the same id, is exactly what
        // `translate_authenticated_object_effects`'s exact one-to-one
        // matching would reject for a declared `Write` access, so charging
        // must reject it too rather than silently masking it by filtering
        // every same-id effect out during merge.
        let payer_effect_count = application_effects
            .iter()
            .filter(|effect| fee_effect_object_id(effect) == fee_object_id)
            .count();
        if payer_effect_count > 1 {
            return Err(NodeCoreError::DuplicateObjectEffect {
                object_id: fee_object_id,
            });
        }
        let existing_payer_effect: Option<ObjectEffect> = match application_effects
            .iter()
            .find(|effect| fee_effect_object_id(effect) == fee_object_id)
        {
            None => None,
            Some(effect @ ObjectEffect::Mutated { .. }) => Some(effect.clone()),
            Some(ObjectEffect::Created(object)) => {
                return Err(NodeCoreError::ObjectCreationUnsupported {
                    object_id: object.id,
                });
            }
            Some(ObjectEffect::Deleted { .. }) => {
                return Err(NodeCoreError::ObjectEffectMismatch {
                    object_id: fee_object_id,
                    reason: "fee object write access requires exactly one mutated effect",
                });
            }
        };
        let payer_effective_body: Vec<u8> = match &existing_payer_effect {
            Some(ObjectEffect::Mutated { new_object, .. }) => new_object.data.clone(),
            _ => payer_loaded.data.clone(),
        };

        let request = FeeChargeRequest {
            asset_id: fee_payment.asset_id,
            amount,
            payer_body: &payer_effective_body,
            treasury_body: &treasury_loaded.data,
        };
        let bodies = composition
            .composer
            .compose_fee_charge(&request)
            .map_err(NodeCoreError::FeeCompositionFailed)?;
        // A non-zero charge must change both the payer and treasury bodies:
        // either one coming back unchanged means the composer did not
        // actually settle the charge it was asked for.
        if bodies.payer_body == payer_effective_body || bodies.treasury_body == treasury_loaded.data
        {
            return Err(NodeCoreError::FeeCompositionNoOp);
        }

        let payer_effect = match existing_payer_effect {
            Some(ObjectEffect::Mutated {
                previous_version,
                mut new_object,
            }) => {
                new_object.data = bodies.payer_body;
                ObjectEffect::Mutated {
                    previous_version,
                    new_object,
                }
            }
            _ => {
                let next_version = payer_loaded.version.checked_add(1).ok_or(
                    NodeCoreError::ObjectVersionOverflow {
                        object_id: fee_object_id,
                    },
                )?;
                let mut new_object = payer_loaded.clone();
                new_object.version = next_version;
                new_object.data = bodies.payer_body;
                ObjectEffect::Mutated {
                    previous_version: payer_loaded.version,
                    new_object,
                }
            }
        };
        let treasury_next_version =
            treasury_loaded
                .version
                .checked_add(1)
                .ok_or(NodeCoreError::ObjectVersionOverflow {
                    object_id: treasury_id,
                })?;
        let mut treasury_new_object = treasury_loaded.clone();
        treasury_new_object.version = treasury_next_version;
        treasury_new_object.data = bodies.treasury_body;
        let treasury_effect = ObjectEffect::Mutated {
            previous_version: treasury_loaded.version,
            new_object: treasury_new_object,
        };

        let mut merged: Vec<ObjectEffect> = application_effects
            .into_iter()
            .filter(|effect| fee_effect_object_id(effect) != fee_object_id)
            .collect();
        merged.push(payer_effect);
        merged.push(treasury_effect);
        Ok(merged)
    }

    /// Independently synthesizes the exact owner-only mutation a committed
    /// [`PreinstalledOwnerTransitionPolicy`] authorizes for a successful
    /// call, or returns `None` if no such policy is committed for this
    /// entrypoint (DR-0106).
    ///
    /// [`PreinstalledWasmMachine::transition`] already rejects a matching
    /// policy below [`MIN_OWNER_TRANSITION_PROTOCOL_VERSION`] with
    /// [`NodeCoreError::OwnerTransitionProtocolVersionTooLow`] strictly
    /// before the WASM engine ever runs, so this function is never reached
    /// with such a transaction; it rechecks the same gate defensively below
    /// and fails the same way rather than assuming the caller enforced it.
    /// Every check below fails closed with a hard `Err`, since a matching
    /// committed policy makes this a fully authorized, narrowly-scoped
    /// capability rather than a best-effort one:
    ///
    /// * the committed `transferred_access_index` must resolve to an
    ///   engine-visible input actually accessed with `Write`
    ///   ([`NodeCoreError::OwnerTransitionModeMismatch`]) and owned by the
    ///   authenticated sender
    ///   ([`NodeCoreError::OwnerTransitionSenderMismatch`]);
    /// * the module's own returned effects must not name that object at all
    ///   ([`NodeCoreError::OwnerTransitionObjectEffectForbidden`]) — the
    ///   module is a no-op for this object by construction, and node-core
    ///   never trusts it to declare the new owner;
    /// * neither a declared `fee_payment.fee_object` nor the trusted
    ///   composition treasury may alias the transferred object
    ///   ([`NodeCoreError::OwnerTransitionFeeObjectAlias`]);
    /// * the recipient is projected from the exact canonical transaction
    ///   `args` via the policy's committed type/version/field (see
    ///   [`PreinstalledOwnerTransitionPolicy::project_recipient`]).
    ///
    /// The synthesized [`ObjectEffect::Mutated`] keeps `id`, `data`,
    /// `type_hash`, and `schema_version` exactly unchanged and advances
    /// `version` by exactly one; only `owner` changes, to
    /// `Owner::Address(recipient)`. This function never re-derives whether
    /// `recipient` is an admissible address under the authenticating
    /// profile — that revalidation is `validate_output_owner_addresses`'s
    /// existing, unmodified job, applied uniformly to every synthesized and
    /// module-produced effect after `transition` returns.
    fn synthesize_owner_transition(
        &self,
        module: &PreinstalledModuleCatalogEntry,
        state: &NodeStateSnapshot,
        effects: &ExecutionEffects,
    ) -> Result<Option<OwnerTransitionSynthesis>, NodeCoreError> {
        let Some(policy) = module
            .semantics_envelope()
            .matching_owner_transition_policy(&self.transaction.entrypoint)
        else {
            return Ok(None);
        };
        if self.transaction.protocol_version < MIN_OWNER_TRANSITION_PROTOCOL_VERSION {
            return Err(NodeCoreError::OwnerTransitionProtocolVersionTooLow {
                actual: self.transaction.protocol_version,
                minimum: MIN_OWNER_TRANSITION_PROTOCOL_VERSION,
            });
        }

        let index = usize::try_from(policy.transferred_access_index()).map_err(|_| {
            NodeCoreError::PersistenceInvariant(
                "owner-transition policy index validated at construction time did not fit usize",
            )
        })?;
        let resolved =
            state
                .resolved_objects()
                .get(index)
                .ok_or(NodeCoreError::PersistenceInvariant(
                    "owner-transition policy index exceeded the resolved engine-visible inputs",
                ))?;
        let object_id = resolved.object.id;
        if resolved.mode != AccessMode::Write {
            return Err(NodeCoreError::OwnerTransitionModeMismatch { object_id });
        }
        if resolved.object.owner != Owner::Address(self.transaction.sender) {
            return Err(NodeCoreError::OwnerTransitionSenderMismatch { object_id });
        }
        if effects
            .object_effects
            .iter()
            .any(|effect| fee_effect_object_id(effect) == object_id)
        {
            return Err(NodeCoreError::OwnerTransitionObjectEffectForbidden { object_id });
        }
        if let Some(fee_payment) = &self.transaction.fee_payment
            && fee_payment.fee_object.id == object_id
        {
            return Err(NodeCoreError::OwnerTransitionFeeObjectAlias { object_id });
        }
        if let Some(composition) = &self.fee_composition
            && composition.treasury_object_id == object_id
        {
            return Err(NodeCoreError::OwnerTransitionFeeObjectAlias { object_id });
        }

        let recipient = policy.project_recipient(&self.transaction.args)?;
        let next_version = resolved
            .object
            .version
            .checked_add(1)
            .ok_or(NodeCoreError::ObjectVersionOverflow { object_id })?;
        let mut new_object = resolved.object.clone();
        new_object.version = next_version;
        new_object.owner = Owner::Address(recipient);

        Ok(Some(OwnerTransitionSynthesis {
            object_id,
            recipient,
            effect: ObjectEffect::Mutated {
                previous_version: resolved.object.version,
                new_object,
            },
        }))
    }

    /// Independently derives the exact expectation a committed
    /// [`PreinstalledObjectCreationPolicy`] authorizes for this call's one
    /// admissible `Created` effect, or returns `None` if no such policy is
    /// committed for this entrypoint (DR-0108).
    ///
    /// Every returned field is computed by node-core itself from trusted,
    /// pre-execution inputs, never from the module's own returned effects:
    /// `object_id` is [`derive_created_object_id`]'s pure recomputation for
    /// creation ordinal zero; `owner` is projected from the transaction's
    /// signed `args` via the committed policy; `type_hash`/`schema_version`
    /// come from the already access-checked, already typed-ABI-verified
    /// engine-visible input the policy names as the type source
    /// ([`NodeCoreError::ObjectCreationTypeSourceIndexUnresolved`] if that
    /// index does not resolve, which the policy's own construction-time
    /// bound check against the matching typed signature makes unreachable in
    /// practice). The actual `Created` effect the module returned is neither
    /// inspected nor trusted here; independent reverification of its
    /// id/owner/type/schema/version/body against this expectation is
    /// `translate_authenticated_object_effects_with_creation`'s job.
    fn verify_creation(
        &self,
        module: &PreinstalledModuleCatalogEntry,
        state: &NodeStateSnapshot,
        tx_hash: Digest32,
    ) -> Result<Option<ObjectCreationExpectation>, NodeCoreError> {
        let Some(policy) = module
            .semantics_envelope()
            .matching_object_creation_policy(&self.transaction.entrypoint)
        else {
            return Ok(None);
        };
        if self.transaction.protocol_version < MIN_OBJECT_CREATION_PROTOCOL_VERSION {
            return Err(NodeCoreError::ObjectCreationProtocolVersionTooLow {
                actual: self.transaction.protocol_version,
                minimum: MIN_OBJECT_CREATION_PROTOCOL_VERSION,
            });
        }

        let index = usize::try_from(policy.type_source_access_index()).map_err(|_| {
            NodeCoreError::PersistenceInvariant(
                "object-creation policy index validated at construction time did not fit usize",
            )
        })?;
        let source = state.resolved_objects().get(index).ok_or_else(|| {
            NodeCoreError::ObjectCreationTypeSourceIndexUnresolved {
                entrypoint: self.transaction.entrypoint.clone(),
            }
        })?;
        let typed_policy = module
            .semantics_envelope()
            .matching_typed_entrypoint_policy(&self.transaction.entrypoint)
            .ok_or(NodeCoreError::PersistenceInvariant(
                "validated creation policy lost its matching typed entrypoint policy",
            ))?;
        let constructor_id = typed_policy
            .signature()
            .params()
            .get(index)
            .ok_or(NodeCoreError::PersistenceInvariant(
                "validated creation policy type-source index exceeded typed signature",
            ))?
            .constructor;
        let registry = typed_policy.registry()?;
        let constructor =
            registry
                .get(constructor_id)
                .cloned()
                .ok_or(NodeCoreError::PersistenceInvariant(
                    "validated typed entrypoint policy did not reconstruct its source constructor",
                ))?;

        let object_id = derive_created_object_id(self.transaction.protocol_version, tx_hash, 0);
        let owner = policy.project_recipient(&self.transaction.args)?;
        Ok(Some(ObjectCreationExpectation {
            object_id,
            owner,
            type_hash: source.object.type_hash,
            schema_version: source.object.schema_version,
            type_source_access_index: index,
            constructor,
        }))
    }
}

fn fee_effect_object_id(effect: &ObjectEffect) -> ObjectId {
    match effect {
        ObjectEffect::Created(object) => object.id,
        ObjectEffect::Mutated { new_object, .. } => new_object.id,
        ObjectEffect::Deleted { id, .. } => *id,
    }
}

impl TransactionalNodeStateMachine for PreinstalledWasmMachine<'_> {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        Ok(NodeStateAccessPlan {
            accesses: Vec::new(),
        })
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        let epoch = event.epoch();
        let module: &PreinstalledModuleCatalogEntry = self.resolve_once(epoch)?;
        let max_input_size = module.manifest().max_input_size;
        let args_len = self.transaction.args.len() as u64;
        if args_len > max_input_size {
            return Err(NodeCoreError::PreinstalledModuleArgsTooLarge {
                module_id: module.module_id(),
                version: module.version(),
                actual: args_len,
                maximum: max_input_size,
            });
        }
        check_preinstalled_module_gas_limit(self.transaction.gas_limit)?;

        // The committed schedule's shape is validated before fee admission
        // or the engine ever runs: it is a trusted configuration fact, never
        // request-dependent, so it must fail closed identically for every
        // invocation rather than only when this particular transaction
        // happens to owe a fee.
        validate_gas_schedule_shape(&self.fee_policy.gas_schedule)
            .map_err(NodeCoreError::UnsupportedGasScheduleShape)?;

        // Fee admission runs before the engine ever executes: an
        // insufficient `max_fee` at the worst-case `gas_limit` is rejected
        // here, so a request that cannot possibly pay never spends engine
        // work.
        let fee_admission = self.admit_fee(state)?;

        let tx_hash = hash_transaction(self.transaction, self.resolver)?;

        // DR-0106: if a typed-entrypoint policy is committed for this exact
        // entrypoint, every engine-visible input (in exact signed order)
        // must satisfy it before the WASM engine ever runs. `abi` never
        // resolves objects itself; `state.resolved_objects()` is already the
        // access-checked, engine-visible set `load_and_authorize_objects`
        // produced. `epoch` is the authenticated event epoch, never
        // request-supplied. The local devnet's Standard Asset v1 `transfer`
        // entrypoint commits such a policy (DR-0107), so this is reachable
        // end-to-end for that entrypoint; every other entrypoint without a
        // matching policy stays exactly as unreachable as before.
        if let Some(typed_policy) = module
            .semantics_envelope()
            .matching_typed_entrypoint_policy(&self.transaction.entrypoint)
        {
            let registry = typed_policy.registry()?;
            let typed_inputs: Vec<abi::ResolvedInput<'_>> = state
                .resolved_objects()
                .iter()
                .map(|resolved| abi::ResolvedInput {
                    mode: resolved.mode,
                    object: &resolved.object,
                })
                .collect();
            abi::verify_entrypoint_inputs(
                typed_policy.signature(),
                &registry,
                self.resolver,
                epoch,
                &typed_inputs,
            )?;
        }

        // DR-0106: a committed owner-transition policy that matches this
        // exact entrypoint but requires a `protocol_version` this transaction
        // does not meet is rejected outright, strictly before the WASM
        // engine ever runs — never treated as though the policy were merely
        // absent (see [`MIN_OWNER_TRANSITION_PROTOCOL_VERSION`]'s docs).
        if module
            .semantics_envelope()
            .matching_owner_transition_policy(&self.transaction.entrypoint)
            .is_some()
            && self.transaction.protocol_version < MIN_OWNER_TRANSITION_PROTOCOL_VERSION
        {
            return Err(NodeCoreError::OwnerTransitionProtocolVersionTooLow {
                actual: self.transaction.protocol_version,
                minimum: MIN_OWNER_TRANSITION_PROTOCOL_VERSION,
            });
        }

        // DR-0108: the same protocol-version gate, for a committed
        // object-creation policy.
        if module
            .semantics_envelope()
            .matching_object_creation_policy(&self.transaction.entrypoint)
            .is_some()
            && self.transaction.protocol_version < MIN_OBJECT_CREATION_PROTOCOL_VERSION
        {
            return Err(NodeCoreError::ObjectCreationProtocolVersionTooLow {
                actual: self.transaction.protocol_version,
                minimum: MIN_OBJECT_CREATION_PROTOCOL_VERSION,
            });
        }

        let creation = self.verify_creation(module, state, tx_hash)?;

        let effects = self.engine.execute(
            self.transaction.protocol_version,
            tx_hash,
            module.wasm_bytes(),
            &self.transaction.entrypoint,
            state.resolved_objects(),
            &self.transaction.args,
            self.transaction.gas_limit,
        )?;

        // A trap's raw reason/gas accounting is untrusted, engine-dependent
        // text; normalize before it is ever canonically encoded or
        // persisted. See `preinstalled_wasm::normalize_trapped_preinstalled_execution`.
        let effects = match effects.status {
            ExecutionStatus::Success => effects,
            ExecutionStatus::Failure { .. } => normalize_trapped_preinstalled_execution(
                effects.tx_hash,
                self.transaction.gas_limit,
            ),
        };

        let gas_used = effects.gas_used;

        match effects.status {
            // `WasmExecutionEngine` discards every candidate object effect on
            // a trap (see `execution::wasm_engine`), so a declared
            // `Write`/`Consume` access can never be matched here. A trap
            // never synthesizes an owner transition either: this arm never
            // calls `synthesize_owner_transition`, so the receipt's encoded
            // effects and the committed mutations agree (both empty, modulo
            // the fee-only payer/treasury mutations charged below, which are
            // deliberately never part of the canonically encoded
            // `ExecutionEffects`).
            ExecutionStatus::Failure { .. } => {
                let response_payload: Vec<u8> = encode_execution_effects(&effects)?;
                let response = NodeResponse::new(
                    event.request_id(),
                    NodeResponseStatus::Rejected,
                    Some(response_payload),
                )?;
                let output = NodeOutput::new(vec![response], Vec::new())?;
                match fee_admission {
                    None => {
                        Ok(TransactionalNodeTransition::rejected_with_no_object_mutation(output))
                    }
                    Some((fee_payment, fee_object_id, treasury_id)) => {
                        let amount = self.settle_actual_fee(fee_payment, gas_used)?;
                        if amount.get() == 0 {
                            Ok(
                                TransactionalNodeTransition::rejected_with_no_object_mutation(
                                    output,
                                ),
                            )
                        } else {
                            // Trap discards every application effect, so both
                            // bodies charged here are exactly the loaded
                            // (pre-execution) bodies.
                            let charged = self.charge_fee(
                                state,
                                fee_payment,
                                fee_object_id,
                                treasury_id,
                                amount,
                                Vec::new(),
                            )?;
                            Ok(
                                TransactionalNodeTransition::rejected_with_fee_only_mutation(
                                    output,
                                    charged,
                                    fee_object_id,
                                    treasury_id,
                                ),
                            )
                        }
                    }
                }
            }
            ExecutionStatus::Success => {
                let owner_transition = self.synthesize_owner_transition(module, state, &effects)?;
                if owner_transition.is_some() && creation.is_some() {
                    return Err(NodeCoreError::PersistenceInvariant(
                        "one preinstalled entrypoint cannot compose owner transition and object creation",
                    ));
                }
                // The synthesized owner-transition effect (if any) is folded
                // into the exact same `ExecutionEffects` this canonically
                // encodes for the receipt, so the receipt a caller observes
                // and the mutation node-core actually commits never
                // disagree. Fee payer/treasury mutations are charged
                // separately below and are never added to this struct, so
                // they stay excluded from the canonical application effects,
                // matching existing fee semantics.
                let mut canonical_effects = effects;
                if let Some(synthesis) = &owner_transition {
                    canonical_effects
                        .object_effects
                        .push(synthesis.effect.clone());
                }
                let response_payload: Vec<u8> = encode_execution_effects(&canonical_effects)?;
                let response = NodeResponse::new(
                    event.request_id(),
                    NodeResponseStatus::Accepted,
                    Some(response_payload),
                )?;
                let output = NodeOutput::new(vec![response], Vec::new())?;
                let object_effects = canonical_effects.object_effects;
                match fee_admission {
                    None if !object_effects.is_empty() => match owner_transition {
                        Some(synthesis) => {
                            TransactionalNodeTransition::with_object_effects_and_owner_transition(
                                Vec::new(),
                                object_effects,
                                output,
                                synthesis.object_id,
                                synthesis.recipient,
                            )
                        }
                        None => match creation {
                            Some(expectation) => {
                                TransactionalNodeTransition::with_object_effects_and_creation(
                                    Vec::new(),
                                    object_effects,
                                    output,
                                    expectation.object_id,
                                    expectation.owner,
                                    expectation.type_hash,
                                    expectation.schema_version,
                                    expectation.type_source_access_index,
                                    expectation.constructor,
                                )
                            }
                            None => TransactionalNodeTransition::with_object_effects(
                                Vec::new(),
                                object_effects,
                                output,
                            ),
                        },
                    },
                    None if creation.is_some() => Err(NodeCoreError::CreationEffectMissing {
                        object_id: creation
                            .as_ref()
                            .map(|expectation: &ObjectCreationExpectation| expectation.object_id)
                            .ok_or(NodeCoreError::PersistenceInvariant(
                                "creation expectation disappeared before success handling",
                            ))?,
                    }),
                    None => Ok(TransactionalNodeTransition::read_only(output)),
                    Some((fee_payment, fee_object_id, treasury_id)) => {
                        let amount = self.settle_actual_fee(fee_payment, gas_used)?;
                        if amount.get() == 0 {
                            return Err(NodeCoreError::FeeAmountZero);
                        }
                        let merged = self.charge_fee(
                            state,
                            fee_payment,
                            fee_object_id,
                            treasury_id,
                            amount,
                            object_effects,
                        )?;
                        match owner_transition {
                            Some(synthesis) => {
                                TransactionalNodeTransition::with_object_effects_and_owner_transition(
                                    Vec::new(),
                                    merged,
                                    output,
                                    synthesis.object_id,
                                    synthesis.recipient,
                                )
                            }
                            None => match creation {
                                Some(expectation) => {
                                    TransactionalNodeTransition::with_object_effects_and_creation(
                                        Vec::new(),
                                        merged,
                                        output,
                                        expectation.object_id,
                                        expectation.owner,
                                        expectation.type_hash,
                                        expectation.schema_version,
                                        expectation.type_source_access_index,
                                        expectation.constructor,
                                    )
                                }
                                None => TransactionalNodeTransition::with_object_effects(
                                    Vec::new(),
                                    merged,
                                    output,
                                ),
                            },
                        }
                    }
                }
            }
        }
    }
}

/// The resolved, already-verified authorization context
/// [`load_and_authorize_objects`] consults for the narrow preinstalled-module
/// cross-owner exception. Produced by resolving the request-local
/// [`PreinstalledWasmMachine`] exactly once, after receipt/nonce reconciliation
/// and before any object load.
struct ResolvedPreinstalledAuthorization<'a> {
    entrypoint: &'a str,
    envelope: &'a PreinstalledModuleSemanticsEnvelope,
}

/// Commits one preinstalled deterministic WASM contract call through the same
/// durable invocation as sender nonce, application state, receipt, and
/// outbox, passing its object effects to the same fail-closed owned-effects
/// translation already used by
/// [`handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects`].
///
/// `Transaction.module_ref` is resolved against the system-module registry
/// captured from committed `ProtocolConfig` during authentication and the
/// trusted `catalog` through the internal preinstalled-module resolver (see
/// function's docs for the exact MVP `module_id`/`version`/`digest` mapping
/// and every commitment check). `created_checkpoint` is trusted node
/// composition, never request input, exactly like the owned-effects
/// entrypoint. This composition is object-only: it declares no opaque
/// application state key, and domain placement uses the authenticated
/// object-access count rather than an opaque state-key count. A call that
/// declares zero authenticated object accesses is rejected with
/// [`NodeCoreError::PreinstalledModuleZeroObjectAccess`] before domain
/// resolution; this MVP path requires at least one.
///
/// `Transaction.gas_limit` is rejected before the WASM engine ever runs if it
/// exceeds the conservative pre-activation [`MAX_PREINSTALLED_MODULE_GAS_LIMIT`]
/// ceiling (see [`NodeCoreError::PreinstalledModuleGasLimitExceedsCeiling`]);
/// that ceiling remains an independent safety bound, not a price. S3's
/// committed base/execution schedule now settles the exact post-execution
/// `gas_used` As-Is; production gas calibration and broader economics remain
/// deferred.
///
/// A deterministically trapped/rejected execution still commits: it produces
/// a `Rejected` [`NodeResponse`] whose canonically encoded body is a
/// normalized, engine-independent closed failure (fixed reason, full
/// `gas_limit` charge, empty effects/events — see
/// `preinstalled_wasm::normalize_trapped_preinstalled_execution`), and,
/// because [`ExecutionStatus::Failure`] discards every object effect before
/// this function ever sees them, no application object effect. Under a
/// configured non-zero fee policy, the normalized full-gas charge still
/// commits the restricted fee-only payer/treasury mutations atomically with
/// the rejected receipt; without a due fee there is no object mutation. Exact
/// request replay is
/// reconciled from the persisted receipt before any module resolution,
/// object load, or execution, identical to every other structured durable
/// entrypoint. The module's committed semantics envelope is independently
/// re-resolved and reverified (never a caller-supplied digest) exactly once,
/// immediately after that
/// receipt/nonce reconciliation and strictly before any object is loaded;
/// its narrow cross-owner authorization exception (a non-sender
/// `Owner::Address` destination at exactly the declared access index the
/// envelope names, for this exact entrypoint, `Write` only, exact
/// type/schema match) is the only way `load_and_authorize_objects` ever
/// relaxes the default same-sender rule, and it never permits a literal
/// owner reassignment (independently enforced by
/// `authenticated_object_effects::translate_update`).
///
/// An additive `native_http::preinstalled_wasm_structured_durable_router`
/// wires this entrypoint over HTTP (see `docs/architecture/decisions/0076-0080-developer-mvp-foundation.md` DR-0080);
/// `native_http::structured_durable_router` remains on the read-only
/// entrypoint. A declared access may read a blob-backed previous version
/// (fetched and verified through `blob_store`). A new version stays inline
/// through [`MAX_INLINE_OBJECT_BODY_BYTES`] and is published before the
/// structured commit only when its canonical body exceeds that fixed
/// threshold. Create,
/// Shared/System ownership, validator/certificate fee distribution,
/// production gas calibration, and production economics remain unimplemented
/// and fail closed or are simply not reachable from this MVP slice.
#[allow(clippy::too_many_arguments)]
pub fn handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution<
    S,
    B,
>(
    blob_store: &B,
    store: &S,
    context: &DurableOperationContext,
    resolver: &HashSuiteResolver,
    catalog: &PreinstalledModuleCatalog,
    engine: &WasmExecutionEngine,
    submission: AuthenticatedSubmitTransaction,
    created_checkpoint: u64,
    fee_composition: Option<PreinstalledFeeComposition<'_>>,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
    B: BlobStore,
{
    let dispatch = AuthenticatedObjectDispatch::from_authenticated_transaction(
        &submission.transaction,
        AuthenticatedObjectPolicy::OwnedMutations { created_checkpoint },
    )?;
    // This MVP preinstalled-WASM path requires at least one authenticated
    // object; reject before domain resolution rather than resolving a
    // domain for a call the machine could never usefully service.
    if dispatch.accesses.is_empty() {
        return Err(NodeCoreError::PreinstalledModuleZeroObjectAccess);
    }
    // Object-only composition: domain placement uses the authenticated
    // object-access count instead of an opaque application state-key count,
    // because this machine declares no state keys (see
    // `PreinstalledWasmMachine::access_plan`).
    let domain = submission
        .placement
        .resolve_domain(submission.event().epoch(), dispatch.accesses.len())?;
    let reservation =
        SenderNonceReservation::from_authenticated_transaction(&submission.transaction);
    let AuthenticatedSubmitTransaction {
        event,
        transaction,
        placement: _,
        committed_system_module,
        committed_fee_policy,
    } = submission;
    let machine = PreinstalledWasmMachine {
        transaction: transaction.transaction(),
        resolver,
        registered_module: committed_system_module.as_ref(),
        catalog,
        engine,
        fee_policy: &committed_fee_policy,
        fee_composition,
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    let plan = machine.access_plan(&event)?;
    let output = handle_durable_idempotent_event_with_plan(
        Some(blob_store),
        store,
        context,
        domain,
        resolver,
        event,
        &machine,
        plan,
        Some(reservation),
        Some(dispatch),
        Some(created_checkpoint),
        Some(&machine),
    )?;
    Ok(ResolvedNodeOutput::new(domain, output))
}

#[allow(clippy::too_many_arguments)]
fn handle_authenticated_submit_transaction_with_policy<S, B, M>(
    blob_store: &B,
    store: &S,
    context: &DurableOperationContext,
    resolver: &HashSuiteResolver,
    submission: AuthenticatedSubmitTransaction,
    machine: &M,
    object_policy: AuthenticatedObjectPolicy,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
    B: BlobStore,
    M: TransactionalNodeStateMachine,
{
    // This shared read-only/generic-owned-effects entrypoint has no fee
    // composition to charge from: reject a declared `fee_payment` before any
    // receipt, nonce, or object I/O rather than silently ignoring it. Only
    // the preinstalled-WASM entrypoint is fee-aware.
    if submission.transaction.transaction().fee_payment.is_some() {
        return Err(NodeCoreError::FeePaymentUnsupportedOnPath);
    }
    let created_checkpoint: Option<u64> = match object_policy {
        AuthenticatedObjectPolicy::ReadOnly => None,
        AuthenticatedObjectPolicy::OwnedMutations { created_checkpoint } => {
            Some(created_checkpoint)
        }
    };
    let plan = machine.access_plan(submission.event())?;
    let domain = submission
        .placement
        .resolve_domain(submission.event().epoch(), plan.accesses().len())?;
    let reservation =
        SenderNonceReservation::from_authenticated_transaction(&submission.transaction);
    let dispatch = AuthenticatedObjectDispatch::from_authenticated_transaction(
        &submission.transaction,
        object_policy,
    )?;
    let AuthenticatedSubmitTransaction {
        event,
        transaction: _authenticated_transaction,
        placement: _,
        committed_system_module: _,
        committed_fee_policy: _,
    } = submission;
    let output = handle_durable_idempotent_event_with_plan(
        Some(blob_store),
        store,
        context,
        domain,
        resolver,
        event,
        machine,
        plan,
        Some(reservation),
        Some(dispatch),
        created_checkpoint,
        None,
    )?;
    Ok(ResolvedNodeOutput::new(domain, output))
}

/// One pending sender-nonce read assertion and canonical next-nonce write,
/// merged into the same [`DurableStateTransaction`] as the application state.
struct PendingSenderNonceWrite {
    key: Vec<u8>,
    read_revision: StateRevision,
    record: SenderNonceRecord,
}

#[allow(clippy::too_many_arguments)]
fn handle_durable_idempotent_event_with_plan<S, M>(
    blob_store: Option<&dyn BlobStore>,
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    event: NodeEvent,
    machine: &M,
    plan: NodeStateAccessPlan,
    reservation: Option<SenderNonceReservation>,
    dispatch: Option<AuthenticatedObjectDispatch>,
    created_checkpoint: Option<u64>,
    preinstalled_machine: Option<&PreinstalledWasmMachine<'_>>,
) -> Result<NodeOutput, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
    M: TransactionalNodeStateMachine,
{
    // Constructed from the validated event's own chain/version. Every
    // application plan key is rejected under this prefix for every event
    // family, including exact receipt replays: application state machines
    // must never claim the sender-nonce namespace.
    let layout = PersistenceLayout::new(event.chain_id().clone(), event.protocol_version());
    validate_sender_nonce_namespace(&plan, &layout)?;
    let nonce_prefix = layout.sender_nonce_prefix();

    if reservation.is_some() {
        let maximum_application_accesses =
            core::cmp::min(MAX_ATOMIC_STATE_READS, MAX_ATOMIC_STATE_WRITES).saturating_sub(1);
        if plan.accesses().len() > maximum_application_accesses {
            return Err(NodeCoreError::TooManyStateAccesses {
                count: plan.accesses().len(),
                maximum: maximum_application_accesses,
            });
        }
    }

    let event_digest = event.digest(resolver)?;
    let request_id = DurableRequestId::new(*event.request_id().as_bytes()).map_err(|_| {
        NodeCoreError::PersistenceInvariant("validated request id failed durable projection")
    })?;

    if let Some(output) = durable_reconciliation::reconcile_receipt(
        store,
        context,
        domain,
        event.request_id(),
        event_digest,
    )? {
        return Ok(output);
    }

    // A new request reads only the sender-nonce record, before any
    // application state, so a stale or replayed nonce fails before any app
    // state read, transition, or commit attempt.
    let pending_nonce = match reservation {
        Some(reservation) => Some(durable_reconciliation::reserve_sender_nonce(
            store,
            context,
            domain,
            &layout,
            reservation,
        )?),
        None => None,
    };

    // Resolve the exact committed module and its semantics envelope once,
    // after receipt and nonce reconciliation but before the first object I/O.
    // Generic owned-effects callers never provide a preinstalled machine and
    // therefore remain sender-only.
    let preinstalled_authorization: Option<ResolvedPreinstalledAuthorization<'_>> =
        match preinstalled_machine {
            Some(machine) => {
                let module: &PreinstalledModuleCatalogEntry =
                    machine.resolve_once(event.epoch())?;
                Some(ResolvedPreinstalledAuthorization {
                    entrypoint: &machine.transaction.entrypoint,
                    envelope: module.semantics_envelope(),
                })
            }
            None => None,
        };

    // Trusted fee-charging composition, if the preinstalled machine has one.
    // Its treasury object id is composition, never request input; passing it
    // to the loader lets it authorize the treasury independent of ownership
    // and hide it from execution-engine inputs (see
    // `load_and_authorize_objects` and `fee_effects::PreinstalledFeeComposition`).
    let treasury_object_id: Option<ObjectId> = preinstalled_machine
        .and_then(|machine| machine.fee_composition.as_ref())
        .map(|composition| composition.treasury_object_id);

    // A creation-capable entrypoint has one deterministic output identifier
    // before execution starts. Assert its true absence now and carry that
    // assertion into the same durable invocation as the later `Create`.
    // This runs after replay/nonce/module reconciliation but before loading
    // any signed object input, so a collision never executes the module.
    let pending_creation_head_read: Option<DurableObjectHeadRead> = match preinstalled_machine {
        Some(machine)
            if preinstalled_authorization
                .as_ref()
                .and_then(|authorization: &ResolvedPreinstalledAuthorization<'_>| {
                    authorization
                        .envelope
                        .matching_object_creation_policy(authorization.entrypoint)
                })
                .is_some() =>
        {
            if machine.transaction.protocol_version < MIN_OBJECT_CREATION_PROTOCOL_VERSION {
                return Err(NodeCoreError::ObjectCreationProtocolVersionTooLow {
                    actual: machine.transaction.protocol_version,
                    minimum: MIN_OBJECT_CREATION_PROTOCOL_VERSION,
                });
            }
            let transaction_hash: Digest32 = hash_transaction(machine.transaction, resolver)?;
            let created_object_id: ObjectId =
                derive_created_object_id(machine.transaction.protocol_version, transaction_hash, 0);
            let created_head: DurableObjectHead =
                store.get_object_head(context, domain, created_object_id)?;
            if created_head != DurableObjectHead::Absent {
                return Err(NodeCoreError::ObjectConflict {
                    object_id: created_object_id,
                });
            }
            Some(DurableObjectHeadRead::new(created_object_id, created_head))
        }
        _ => None,
    };

    // Legacy execution must never erase public defining-code authority merely
    // because the owner signed. Include absence CAS for every input/output ID.
    let mut legacy_object_ids: BTreeSet<ObjectId> = BTreeSet::new();
    if let Some(dispatch) = &dispatch {
        legacy_object_ids.extend(dispatch.accesses.iter().map(|access| access.object_ref.id));
    }
    if let Some(head) = &pending_creation_head_read {
        legacy_object_ids.insert(head.object_id());
    }
    let mut authority_reads: Vec<StateReadAssertion> = Vec::with_capacity(legacy_object_ids.len());
    for object_id in legacy_object_ids {
        authority_reads.push(local_instance_state::legacy_absence(
            store, context, domain, object_id,
        )?);
    }

    // Object reads happen only after the receipt and nonce checks above, so a
    // stale or replayed request never spends the fan-out cost of the
    // per-entry head/version storage round-trips. Only this authenticated
    // path supplies verified typed object inputs to the pure transition;
    // generic handlers always supply an empty object slice.
    let mut loaded_objects: LoadedAuthenticatedObjects = match &dispatch {
        Some(dispatch) => {
            // Every caller that ever constructs `Some(dispatch)` also
            // supplies a blob store (see `handle_authenticated_submit_transaction_with_policy`
            // and the preinstalled-WASM entrypoint); the fully generic,
            // never-dispatching idempotent path always passes `dispatch:
            // None` and therefore never reaches this branch. Absence here is
            // an internal composition bug, not reachable external input.
            let blob_store = blob_store.ok_or(NodeCoreError::PersistenceInvariant(
                "authenticated object dispatch requires a blob store",
            ))?;
            load_and_authorize_objects(
                store,
                blob_store,
                context,
                domain,
                event.chain_id(),
                dispatch,
                preinstalled_authorization.as_ref(),
                treasury_object_id,
            )?
        }
        None => LoadedAuthenticatedObjects::default(),
    };
    if let Some(head_read) = pending_creation_head_read {
        loaded_objects.push_additional_head_read(head_read);
    }
    // Give the preinstalled machine its verified, loaded treasury object (if
    // one was declared and authorized above) through a request-local cell it
    // alone can populate, so `transition` can compose and merge a fee charge
    // over a body the execution engine itself never receives.
    let treasury_object: Option<&Object> = preinstalled_machine
        .zip(treasury_object_id)
        .and_then(|(_, treasury_object_id)| loaded_objects.object(treasury_object_id));
    if let (Some(machine), Some(object)) = (preinstalled_machine, treasury_object) {
        machine.treasury_object.set(object.clone()).map_err(|_| {
            NodeCoreError::PersistenceInvariant("preinstalled treasury object resolved twice")
        })?;
    }
    let mut values = BTreeMap::new();
    for access in plan.accesses() {
        let observed = store.get_versioned_durable(context, domain, access.key())?;
        if let Some(value) = observed.value() {
            validate_state(value)?;
        }
        values.insert(access.key.clone(), observed);
    }
    let snapshot = NodeStateSnapshot {
        values,
        resolved_objects: loaded_objects.resolved_objects(),
    };
    let transition = machine.transition(&snapshot, &event)?;
    validate_output_event_context(transition.output(), &event)?;
    if let Some(dispatch) = &dispatch {
        validate_output_owner_addresses(
            transition.object_effects(),
            dispatch.owner_address_policy,
        )?;
    }
    let mutation_context: Option<authenticated_object_effects::TrustedObjectMutationContext<'_>> =
        created_checkpoint.map(|created_checkpoint: u64| {
            authenticated_object_effects::TrustedObjectMutationContext {
                resolver,
                chain_id: event.chain_id(),
                protocol_version: event.protocol_version(),
                epoch: event.epoch(),
                created_checkpoint,
            }
        });
    let object_mutations: Vec<DurableObjectMutationEntry> = match transition.effect_matching() {
        ObjectEffectMatching::Exact => translate_authenticated_object_effects(
            loaded_objects.verified(),
            transition.object_effects(),
            mutation_context.as_ref(),
            loaded_objects.total_body_bytes(),
        )?,
        ObjectEffectMatching::ExactWithOwnerTransition {
            object_id,
            recipient,
        } => translate_authenticated_object_effects_with_owner_transition(
            loaded_objects.verified(),
            transition.object_effects(),
            mutation_context.as_ref(),
            loaded_objects.total_body_bytes(),
            *object_id,
            *recipient,
        )?,
        ObjectEffectMatching::ExactWithCreation {
            object_id,
            owner,
            type_hash,
            schema_version,
            type_source_access_index,
            constructor,
        } => translate_authenticated_object_effects_with_creation(
            loaded_objects.verified(),
            transition.object_effects(),
            mutation_context.as_ref(),
            loaded_objects.total_body_bytes(),
            &PendingObjectCreation {
                expected_id: *object_id,
                expected_owner: *owner,
                expected_type_hash: *type_hash,
                expected_schema_version: *schema_version,
                type_source_access_index: *type_source_access_index,
                constructor: constructor.clone(),
            },
        )?,
        ObjectEffectMatching::RejectedNoMutation => {
            debug_assert!(transition.object_effects().is_empty());
            Vec::new()
        }
        ObjectEffectMatching::RejectedFeeOnly { payer, treasury } => {
            let context = mutation_context
                .as_ref()
                .ok_or(NodeCoreError::ObjectMutationContextMissing { object_id: *payer })?;
            translate_fee_only_object_effects(
                loaded_objects.verified(),
                transition.object_effects(),
                *payer,
                *treasury,
                context,
                loaded_objects.total_body_bytes(),
            )?
        }
    };
    // Every effect these mutations represent has already passed
    // `translate_authenticated_object_effects`/
    // `translate_fee_only_object_effects` validation, but staging is pure
    // and does no I/O: the complete envelope below (state/receipt/outbox/
    // object aggregate bounds) is validated afterward, not here. Exact
    // replay already returned above, before this point is ever reached, so
    // a replay never stages or publishes anything.
    let (object_mutations, pending_blob_publications) =
        stage_object_mutations_for_blob_store(object_mutations);

    let dedup_record = NodeDedupRecord::new(
        event.request_id(),
        event_digest,
        transition.output.responses.clone(),
    )?;
    let receipt = DurableRequestReceipt::new(request_id, event_digest, dedup_record.encode()?)?;
    let outbox = if transition.output.outbound_messages.is_empty() {
        None
    } else {
        let messages = transition
            .output
            .outbound_messages
            .iter()
            .map(|message| {
                let payload_digest = message.event().digest(resolver)?;
                Ok(DurableOutboxMessage::new(
                    payload_digest,
                    message.event().encode()?,
                )?)
            })
            .collect::<Result<Vec<_>, NodeCoreError>>()?;
        Some(DurableOutboxBatch::new(request_id, event_digest, messages)?)
    };
    let (mut reads, mut mutations) = domain_transition_parts(&plan, &snapshot, transition.updates)?;
    reads.extend(authority_reads);
    if let Some(mutation) = mutations.iter().find(|mutation| {
        mutation.key().starts_with(nonce_prefix.as_slice())
            || mutation
                .key()
                .starts_with(publication::PUBLICATION_STATE_PREFIX)
            || local_instance_state::is_reserved(mutation.key())
    }) {
        return Err(NodeCoreError::ReservedStateAccess(mutation.key().to_vec()));
    }
    if let Some(pending) = pending_nonce {
        reads.push(StateReadAssertion::new(
            pending.key.clone(),
            pending.read_revision,
        )?);
        mutations.push(StateMutationEntry::new(
            pending.key,
            StateMutation::Put(pending.record.encode()?),
        )?);
    }
    let state = DurableStateTransaction::new(domain, AtomicStateReadSet::new(reads)?, mutations)?;
    let objects = DurableObjectChanges::new(loaded_objects.into_reads(), object_mutations)?;
    let invocation =
        DurableInvocationTransaction::new(domain, Some(state), objects, receipt, outbox)?;

    // Only now that the complete envelope above has been built and
    // validated are the publications staged earlier actually performed,
    // strictly before `commit_invocation`.
    publish_pending_blobs(blob_store, pending_blob_publications)?;

    durable_reconciliation::committed_output(
        store.commit_invocation(context, invocation),
        transition.output,
    )
}

/// One deferred `BlobStore::put_blob` call staged by
/// `stage_object_mutations_for_blob_store`, to be performed only after the
/// caller has built and validated the complete structured envelope
/// (state/receipt/outbox/object) those staged mutations belong to.
struct PendingBlobPublication {
    object_id: ObjectId,
    blob_digest: Digest32,
    canonical_bytes: Vec<u8>,
}

/// Pure, I/O-free staging pass over mutations
/// `translate_authenticated_object_effects`/
/// `translate_fee_only_object_effects` already validated: a `Create`/
/// `Update` mutation whose inline canonical bytes exceed
/// `MAX_INLINE_OBJECT_BODY_BYTES` has its payload replaced with a
/// `BlobReference` keyed under the version's already-computed object digest
/// and provenance, and the exact bytes to publish are collected as a
/// `PendingBlobPublication` rather than published immediately. A body at or
/// under the threshold — every ordinary small object body, including every
/// devnet asset account — is returned unchanged with nothing staged and no
/// bytes cloned. A mutation that is already blob-backed (never produced by
/// `translate_update` today, but not assumed impossible) also passes
/// through unstaged.
///
/// This function does no I/O and is not the point at which the complete
/// envelope is validated: the caller still builds and validates
/// `DurableObjectChanges`/`DurableInvocationTransaction` from this
/// function's returned mutations afterward, and must not perform any staged
/// publication until that construction has succeeded.
///
/// Iterates in the mutations' existing deterministic order (the verified
/// manifest's declaration order) and applies the identical fixed threshold
/// to the identical canonical bytes, so every validator that reaches this
/// point stages the same publications in the same order.
fn stage_object_mutations_for_blob_store(
    mutations: Vec<DurableObjectMutationEntry>,
) -> (Vec<DurableObjectMutationEntry>, Vec<PendingBlobPublication>) {
    let mut pending: Vec<PendingBlobPublication> = Vec::new();
    let mutations = mutations
        .into_iter()
        .map(|entry| {
            let object_id = entry.object_id();
            let mutation = match entry.mutation().clone() {
                DurableObjectMutation::Create {
                    version,
                    owner_projection,
                    routing_projection,
                } => DurableObjectMutation::Create {
                    version: stage_inline_version_for_blob_store(version, &mut pending),
                    owner_projection,
                    routing_projection,
                },
                DurableObjectMutation::Update {
                    version,
                    owner_projection,
                    routing_projection,
                } => DurableObjectMutation::Update {
                    version: stage_inline_version_for_blob_store(version, &mut pending),
                    owner_projection,
                    routing_projection,
                },
                DurableObjectMutation::Delete => DurableObjectMutation::Delete,
            };
            DurableObjectMutationEntry::new(object_id, mutation)
        })
        .collect();
    (mutations, pending)
}

/// Stages one inline version for publication only when its canonical bytes
/// exceed `MAX_INLINE_OBJECT_BODY_BYTES`, reusing the version's own
/// already-computed `digest` unchanged as the staged payload's
/// `blob_digest`: both are independently reverified against the identical
/// fetched bytes on read (`load_and_authorize_objects`), so reusing the same
/// value is exactly what a later verified read expects, not a shortcut. A
/// body at or under the threshold is returned unchanged.
fn stage_inline_version_for_blob_store(
    version: DurableObjectVersionRecord,
    pending: &mut Vec<PendingBlobPublication>,
) -> DurableObjectVersionRecord {
    let DurableObjectPayload::Inline(inline) = version.payload() else {
        return version;
    };
    if inline.canonical_bytes().len() <= MAX_INLINE_OBJECT_BODY_BYTES {
        return version;
    }
    let object_id = version.object_id();
    let digest = version.digest();
    pending.push(PendingBlobPublication {
        object_id,
        blob_digest: digest,
        canonical_bytes: inline.canonical_bytes().to_vec(),
    });
    DurableObjectVersionRecord::from_blob_reference(
        object_id,
        version.object_version(),
        digest,
        version.schema_version(),
        version.provenance().clone(),
        version.created_checkpoint(),
        digest,
    )
}

/// Performs every publication staged by
/// `stage_object_mutations_for_blob_store`, in order, and only after the
/// caller has already built and validated the complete
/// `DurableInvocationTransaction` those staged mutations belong to.
///
/// A failure here (a typed `BlobStore` error, including a digest/content
/// collision) means `commit_invocation` is never called for this request:
/// zero state/receipt/nonce/outbox/object changes. If more than one
/// publication was staged, an earlier one that already succeeded before a
/// later one fails is already durably stored — an unreachable
/// content-addressed orphan, exactly like one a later `commit_invocation`
/// rejection can leave behind, never a partial commit.
fn publish_pending_blobs(
    blob_store: Option<&dyn BlobStore>,
    pending: Vec<PendingBlobPublication>,
) -> Result<(), NodeCoreError> {
    if pending.is_empty() {
        return Ok(());
    }
    // Every caller that ever constructs a mutation with an inline payload
    // also supplies a blob store (see
    // `handle_authenticated_submit_transaction_with_policy` and the
    // preinstalled-WASM entrypoint); the fully generic, never-dispatching
    // idempotent path never produces object mutations at all, so it never
    // stages a publication. Absence here is an internal composition bug,
    // not reachable external input.
    let blob_store = blob_store.ok_or(NodeCoreError::PersistenceInvariant(
        "a staged blob publication requires a blob store",
    ))?;
    for publication in pending {
        blob_store
            .put_blob(publication.blob_digest, publication.canonical_bytes)
            .map_err(|error| NodeCoreError::ObjectBlobPublishFailed {
                object_id: publication.object_id,
                blob_digest: publication.blob_digest,
                source: error,
            })?;
    }
    Ok(())
}

/// One object version's canonical body and typed object, either already
/// inline in the immutable version record or fetched and independently
/// verified from content-addressed blob storage.
enum LoadedObjectBody<'a> {
    /// Existing canonical bytes stored directly in the version row.
    Inline(&'a DurableInlineObject),
    /// Canonical bytes fetched from `blob_store` and already independently
    /// verified against the payload's `blob_digest` before this value is
    /// constructed.
    Blob { bytes: Vec<u8>, object: Object },
}

impl LoadedObjectBody<'_> {
    fn canonical_bytes(&self) -> &[u8] {
        match self {
            Self::Inline(inline) => inline.canonical_bytes(),
            Self::Blob { bytes, .. } => bytes,
        }
    }

    fn object(&self) -> &Object {
        match self {
            Self::Inline(inline) => inline.object(),
            Self::Blob { object, .. } => object,
        }
    }
}

/// Bounds one object body at the per-object limit and folds it into the
/// running aggregate total, bounding that at the aggregate limit. Shared by
/// the inline and blob-fetched paths so both budgets are enforced exactly
/// once per object, at the point each body's bytes first become available —
/// for a blob body, that is before its own digest is verified or it is
/// decoded.
fn accumulate_authenticated_body_bytes(
    total_body_bytes: usize,
    object_id: ObjectId,
    body_length: usize,
) -> Result<usize, NodeCoreError> {
    if body_length > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
        return Err(NodeCoreError::ObjectBodyTooLarge {
            object_id,
            actual: body_length,
            maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        });
    }
    let total_body_bytes =
        total_body_bytes
            .checked_add(body_length)
            .ok_or(NodeCoreError::ObjectBodyTooLarge {
                object_id,
                actual: usize::MAX,
                maximum: MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES,
            })?;
    if total_body_bytes > MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES {
        return Err(NodeCoreError::ObjectBodyTooLarge {
            object_id,
            actual: total_body_bytes,
            maximum: MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES,
        });
    }
    Ok(total_body_bytes)
}

/// Loads and authorizes every entry in `dispatch.accesses` against
/// `dispatch.authority`, returning one exact [`runtime::DurableObjectHeadRead`] per
/// entry in the same signed manifest declaration order. The runtime durable
/// envelope canonicalizes storage assertions independently before commit.
///
/// Every check fails closed:
///
/// * an absent or tombstoned head, a version/digest disagreement with the
///   signed reference, or an unauthorized owner all reject before any
///   assertion is recorded;
/// * a current head that points at a missing or disagreeing immutable
///   version record, or a decoded object that disagrees with its own version
///   record, is treated as storage corruption distinct from authorization
///   failure;
/// * the record's own stored provenance must name the trusted event `chain_id`
///   — a mismatch means a misbound namespace, a cross-chain body transplant,
///   or adapter corruption, never a legitimate historical object. This is
///   checked from the record header alone, before a blob-backed payload is
///   ever fetched from `blob_store`;
/// * a blob-backed payload is fetched from `blob_store` only after the
///   provenance check above; a `None` result is a typed missing-blob error
///   and a [`RuntimeError`] from the store is a typed runtime/storage error.
///   Fetched bytes are bounded at the same per-object limit as an inline body
///   before either digest is verified or the body is decoded. The payload's
///   own `blob_digest` is independently verified against the exact fetched
///   bytes with [`hashing::verify_digest`] and the record's stored
///   chain/protocol-version provenance before [`objects::decode_object`]
///   ever runs;
/// * this node independently recomputes the object digest from the record's
///   own stored provenance and canonical body using [`hashing::verify_digest`],
///   which selects the algorithm recorded self-describingly in the digest
///   itself. It never uses the reader's epoch-selected hash suite, which
///   would misjudge a legitimate object created under a different suite or
///   protocol version; every body (inline or blob-fetched) is bounded before
///   hashing, and an unsupported digest algorithm fails closed rather than
///   silently skipping verification.
#[allow(clippy::too_many_arguments)]
fn load_and_authorize_objects<S>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain_id: &ChainId,
    dispatch: &AuthenticatedObjectDispatch,
    preinstalled_authorization: Option<&ResolvedPreinstalledAuthorization<'_>>,
    treasury_object_id: Option<ObjectId>,
) -> Result<LoadedAuthenticatedObjects, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
{
    let mut loaded: LoadedAuthenticatedObjects =
        LoadedAuthenticatedObjects::with_capacity(dispatch.accesses.len());
    let mut total_body_bytes: usize = 0;
    for (access_index, access) in dispatch.accesses.iter().enumerate() {
        let object_id: ObjectId = access.object_ref.id;
        let snapshot: object_snapshots::ObjectSnapshot = object_snapshots::load_object_snapshot(
            store,
            blob_store,
            context,
            domain,
            chain_id,
            &access.object_ref,
            &mut total_body_bytes,
        )?;
        let object: &Object = &snapshot.object;

        // The trusted composition's fee treasury is authorized independent
        // of who owns it, but only for the exact final declared `Write`
        // access naming its exact id: the sender's signed manifest can never
        // redirect the fee, because `treasury_object_id` is composition,
        // never request input. See `fee_effects::PreinstalledFeeComposition`
        // and `PreinstalledWasmMachine::admit_fee`.
        let is_final_access: bool = access_index + 1 == dispatch.accesses.len();
        let is_treasury_access: bool = is_final_access
            && access.mode == AccessMode::Write
            && treasury_object_id == Some(object_id);

        match &object.owner {
            Owner::Address(owner_address) => {
                validate_ed25519_owner_address(
                    owner_address.as_bytes(),
                    dispatch.owner_address_policy,
                )
                .map_err(|source: Ed25519OwnerAddressError| {
                    NodeCoreError::InadmissibleObjectOwnerAddress { object_id, source }
                })?;
                if is_treasury_access {
                    // Trusted-composition exception: any Address owner.
                } else if *owner_address != dispatch.authority {
                    let access_index: u32 = u32::try_from(access_index).map_err(|_| {
                        NodeCoreError::PersistenceInvariant(
                            "bounded authenticated object index did not fit u32",
                        )
                    })?;
                    let policy: Option<&PreinstalledObjectAccessPolicy> =
                        preinstalled_authorization.and_then(|authorization| {
                            authorization.envelope.matching_object_access_policy(
                                authorization.entrypoint,
                                access_index,
                            )
                        });
                    let authorized: bool = policy.is_some_and(|policy| {
                        access.mode == AccessMode::Write
                            && access.mode == policy.mode()
                            && object.type_hash == policy.expected_type_hash()
                            && object.schema_version == policy.expected_schema_version()
                    });
                    if !authorized {
                        return Err(NodeCoreError::ObjectOwnerMismatch { object_id });
                    }
                }
            }
            Owner::Immutable if access.mode == AccessMode::Read => {}
            Owner::Immutable => {
                return Err(NodeCoreError::ObjectOwnerKindUnsupported { object_id });
            }
            Owner::Shared | Owner::System => {
                return Err(NodeCoreError::ObjectOwnerKindUnsupported { object_id });
            }
        }

        loaded.push_with_engine_visibility(
            object_id,
            access.mode,
            snapshot.head,
            snapshot.object,
            snapshot.created_checkpoint,
            !is_treasury_access,
        );
    }
    loaded.set_total_body_bytes(total_body_bytes);
    Ok(loaded)
}

fn handle_domain_idempotent_event_with_plan<R, M>(
    runtime: &R,
    domain: AtomicityDomainId,
    config: &NodeConfig,
    resolver: &HashSuiteResolver,
    event: NodeEvent,
    machine: &M,
    plan: NodeStateAccessPlan,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    let event_digest = event.digest(resolver)?;
    let layout = PersistenceLayout::new(config.chain_id.clone(), config.protocol_version);
    let request_bytes = *event.request_id.as_bytes();
    let dedup_key = layout.request_dedup_key(request_bytes);
    let outbox_key = layout.outbox_batch_key(request_bytes);
    let delivery_key = layout.outbox_delivery_key(request_bytes);

    validate_sender_nonce_namespace(&plan, &layout)?;
    let maximum_application_accesses =
        core::cmp::min(MAX_ATOMIC_STATE_READS, MAX_ATOMIC_STATE_WRITES).saturating_sub(3);
    if plan.accesses.len() > maximum_application_accesses {
        return Err(NodeCoreError::TooManyStateAccesses {
            count: plan.accesses.len(),
            maximum: maximum_application_accesses,
        });
    }
    for reserved in [&dedup_key, &outbox_key, &delivery_key] {
        if plan.access(reserved).is_some() {
            return Err(NodeCoreError::ReservedStateAccess(reserved.clone()));
        }
    }

    let store = runtime.state_store();
    let dedup = store.get_versioned_in_domain(domain, &dedup_key)?;
    let outbox = store.get_versioned_in_domain(domain, &outbox_key)?;
    let delivery = store.get_versioned_in_domain(domain, &delivery_key)?;

    if let Some(bytes) = dedup.value() {
        let record = NodeDedupRecord::decode(bytes)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid dedup record"))?;
        if record.request_id() != event.request_id() || record.event_digest() != event_digest {
            return Err(NodeCoreError::RequestIdReuse);
        }
        let batch_bytes = outbox.value().ok_or(NodeCoreError::PersistenceInvariant(
            "dedup exists without outbox",
        ))?;
        let batch = NodeOutboxBatch::decode(batch_bytes)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox batch"))?;
        if batch.request_id() != event.request_id() || batch.event_digest() != event_digest {
            return Err(NodeCoreError::PersistenceInvariant(
                "dedup and outbox identities differ",
            ));
        }
        for message in batch.messages() {
            message.event().validate_context(config)?;
        }
        let delivery_bytes = delivery.value().ok_or(NodeCoreError::PersistenceInvariant(
            "dedup exists without outbox delivery state",
        ))?;
        let delivery_record = NodeOutboxDelivery::decode(delivery_bytes)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox delivery state"))?;
        if delivery_record.request_id != event.request_id()
            || delivery_record.event_digest != event_digest
        {
            return Err(NodeCoreError::PersistenceInvariant(
                "dedup and outbox delivery identities differ",
            ));
        }
        return NodeOutput::new(record.responses().to_vec(), Vec::new());
    }
    if outbox.value().is_some() || delivery.value().is_some() {
        return Err(NodeCoreError::PersistenceInvariant(
            "outbox state exists without dedup",
        ));
    }

    let mut values = BTreeMap::new();
    for access in plan.accesses() {
        let observed = store.get_versioned_in_domain(domain, access.key())?;
        if let Some(value) = observed.value() {
            validate_state(value)?;
        }
        values.insert(access.key.clone(), observed);
    }
    let snapshot = NodeStateSnapshot {
        values,
        resolved_objects: Vec::new(),
    };
    let transition = machine.transition(&snapshot, &event)?;
    reject_object_effects_without_authenticated_dispatch(transition.object_effects())?;
    validate_output_context(transition.output(), &event, config)?;
    let dedup_record = NodeDedupRecord::new(
        event.request_id(),
        event_digest,
        transition.output.responses.clone(),
    )?;
    let outbox_batch = NodeOutboxBatch::new(
        event.request_id(),
        event_digest,
        transition.output.outbound_messages.clone(),
    )?;
    let outbox_delivery = NodeOutboxDelivery::pending(event.request_id(), event_digest);

    let (mut reads, mut mutations) = domain_transition_parts(&plan, &snapshot, transition.updates)?;
    reads.extend([
        StateReadAssertion::new(dedup_key.clone(), dedup.revision())?,
        StateReadAssertion::new(outbox_key.clone(), outbox.revision())?,
        StateReadAssertion::new(delivery_key.clone(), delivery.revision())?,
    ]);
    mutations.extend([
        StateMutationEntry::new(dedup_key, StateMutation::Put(dedup_record.encode()?))?,
        StateMutationEntry::new(outbox_key, StateMutation::Put(outbox_batch.encode()?))?,
        StateMutationEntry::new(delivery_key, StateMutation::Put(outbox_delivery.encode()?))?,
    ]);
    let transaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(reads)?,
        AtomicStateMutationSet::new(mutations)?,
    )?;
    match store.commit_transaction(transaction)? {
        AtomicStateWriteResult::Committed => Ok(transition.output),
        AtomicStateWriteResult::Conflict { .. } => Err(NodeCoreError::StateConflict),
    }
}

fn commit_legacy_transaction_parts<S>(
    store: &S,
    reads: Vec<StateReadAssertion>,
    mutations: Vec<StateMutationEntry>,
) -> Result<AtomicStateWriteResult, NodeCoreError>
where
    S: TransactionalStateStore,
{
    let mut mutations = mutations
        .iter()
        .map(|mutation| (mutation.key().to_vec(), mutation.mutation().clone()))
        .collect::<BTreeMap<_, _>>();
    let writes = reads
        .iter()
        .map(|read| {
            StateWrite::new(
                read.key().to_vec(),
                read.expected_revision(),
                mutations
                    .remove(read.key())
                    .unwrap_or(StateMutation::Assert),
            )
        })
        .collect::<Result<Vec<_>, RuntimeError>>()?;
    if !mutations.is_empty() {
        return Err(RuntimeError::StateMutationWithoutRead.into());
    }
    Ok(store.commit_atomic(AtomicStateWriteSet::new(writes)?)?)
}

fn claim_next_outbox_message_inner<G, C>(
    layout: &PersistenceLayout,
    request_id: RequestId,
    lease_id: OutboxLeaseId,
    now_unix_millis: u64,
    lease_duration_millis: u64,
    mut get_versioned: G,
    commit: C,
) -> Result<Option<OutboxClaim>, NodeCoreError>
where
    G: FnMut(&[u8]) -> Result<VersionedStateValue, RuntimeError>,
    C: FnOnce(
        Vec<StateReadAssertion>,
        Vec<StateMutationEntry>,
    ) -> Result<AtomicStateWriteResult, NodeCoreError>,
{
    if lease_duration_millis == 0 || lease_duration_millis > MAX_OUTBOX_LEASE_MILLIS {
        return Err(NodeCoreError::InvalidOutboxLeaseDuration(
            lease_duration_millis,
        ));
    }
    let request_bytes = *request_id.as_bytes();
    let batch_key = layout.outbox_batch_key(request_bytes);
    let delivery_key = layout.outbox_delivery_key(request_bytes);
    let batch_value = get_versioned(&batch_key)?;
    let delivery_value = get_versioned(&delivery_key)?;
    let batch = NodeOutboxBatch::decode(batch_value.value().ok_or(NodeCoreError::OutboxNotFound)?)
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox batch"))?;
    let mut delivery = NodeOutboxDelivery::decode(
        delivery_value
            .value()
            .ok_or(NodeCoreError::OutboxNotFound)?,
    )
    .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox delivery state"))?;
    validate_outbox_identity(request_id, &batch, &delivery)?;

    let index = usize::try_from(delivery.next_index)
        .map_err(|_| NodeCoreError::OutboxArithmeticOverflow)?;
    if index > batch.messages.len() {
        return Err(NodeCoreError::PersistenceInvariant(
            "outbox cursor exceeds batch length",
        ));
    }
    if index == batch.messages.len() {
        return Ok(None);
    }
    if let Some((_, expires_at)) = delivery.lease
        && expires_at > now_unix_millis
    {
        return Err(NodeCoreError::OutboxLeaseActive {
            expires_at_unix_millis: expires_at,
        });
    }

    let expires_at_unix_millis = now_unix_millis
        .checked_add(lease_duration_millis)
        .ok_or(NodeCoreError::OutboxArithmeticOverflow)?;
    delivery.attempts = delivery
        .attempts
        .checked_add(1)
        .ok_or(NodeCoreError::OutboxArithmeticOverflow)?;
    delivery.lease = Some((lease_id, expires_at_unix_millis));
    let reads = vec![
        StateReadAssertion::new(batch_key, batch_value.revision())?,
        StateReadAssertion::new(delivery_key.clone(), delivery_value.revision())?,
    ];
    let mutations = vec![StateMutationEntry::new(
        delivery_key,
        StateMutation::Put(delivery.encode()?),
    )?];
    if !matches!(commit(reads, mutations)?, AtomicStateWriteResult::Committed) {
        return Err(NodeCoreError::StateConflict);
    }

    Ok(Some(OutboxClaim {
        request_id,
        index: delivery.next_index,
        lease_id,
        expires_at_unix_millis,
        message: batch.messages[index].clone(),
    }))
}

/// Atomically leases the next pending message from one persisted outbox batch.
///
/// Expired leases may be replaced, intentionally providing at-least-once
/// delivery. The immutable batch revision is asserted in the same transaction.
pub fn claim_next_outbox_message<S>(
    store: &S,
    layout: &PersistenceLayout,
    request_id: RequestId,
    lease_id: OutboxLeaseId,
    now_unix_millis: u64,
    lease_duration_millis: u64,
) -> Result<Option<OutboxClaim>, NodeCoreError>
where
    S: TransactionalStateStore,
{
    claim_next_outbox_message_inner(
        layout,
        request_id,
        lease_id,
        now_unix_millis,
        lease_duration_millis,
        |key| store.get_versioned(key),
        |reads, mutations| commit_legacy_transaction_parts(store, reads, mutations),
    )
}

/// Atomically leases one pending outbox message inside an explicit domain.
pub fn claim_next_outbox_message_in_domain<S>(
    store: &S,
    domain: AtomicityDomainId,
    layout: &PersistenceLayout,
    request_id: RequestId,
    lease_id: OutboxLeaseId,
    now_unix_millis: u64,
    lease_duration_millis: u64,
) -> Result<Option<OutboxClaim>, NodeCoreError>
where
    S: DomainTransactionalStateStore,
{
    claim_next_outbox_message_inner(
        layout,
        request_id,
        lease_id,
        now_unix_millis,
        lease_duration_millis,
        |key| store.get_versioned_in_domain(domain, key),
        |reads, mutations| {
            let transaction = AtomicStateTransaction::new(
                domain,
                AtomicStateReadSet::new(reads)?,
                AtomicStateMutationSet::new(mutations)?,
            )?;
            Ok(store.commit_transaction(transaction)?)
        },
    )
}

fn acknowledge_outbox_message_inner<G, C>(
    layout: &PersistenceLayout,
    request_id: RequestId,
    index: u32,
    lease_id: OutboxLeaseId,
    mut get_versioned: G,
    commit: C,
) -> Result<(), NodeCoreError>
where
    G: FnMut(&[u8]) -> Result<VersionedStateValue, RuntimeError>,
    C: FnOnce(
        Vec<StateReadAssertion>,
        Vec<StateMutationEntry>,
    ) -> Result<AtomicStateWriteResult, NodeCoreError>,
{
    let request_bytes = *request_id.as_bytes();
    let batch_key = layout.outbox_batch_key(request_bytes);
    let delivery_key = layout.outbox_delivery_key(request_bytes);
    let batch_value = get_versioned(&batch_key)?;
    let delivery_value = get_versioned(&delivery_key)?;
    let batch = NodeOutboxBatch::decode(batch_value.value().ok_or(NodeCoreError::OutboxNotFound)?)
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox batch"))?;
    let mut delivery = NodeOutboxDelivery::decode(
        delivery_value
            .value()
            .ok_or(NodeCoreError::OutboxNotFound)?,
    )
    .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox delivery state"))?;
    validate_outbox_identity(request_id, &batch, &delivery)?;

    if delivery.next_index != index {
        return Err(NodeCoreError::OutboxIndexMismatch);
    }
    if delivery.lease.map(|(active, _)| active) != Some(lease_id) {
        return Err(NodeCoreError::OutboxLeaseMismatch);
    }
    let next_index = index
        .checked_add(1)
        .ok_or(NodeCoreError::OutboxArithmeticOverflow)?;
    let next_index_usize =
        usize::try_from(next_index).map_err(|_| NodeCoreError::OutboxArithmeticOverflow)?;
    if next_index_usize > batch.messages.len() {
        return Err(NodeCoreError::PersistenceInvariant(
            "outbox acknowledgement exceeds batch length",
        ));
    }
    delivery.next_index = next_index;
    delivery.lease = None;

    let reads = vec![
        StateReadAssertion::new(batch_key, batch_value.revision())?,
        StateReadAssertion::new(delivery_key.clone(), delivery_value.revision())?,
    ];
    let mutations = vec![StateMutationEntry::new(
        delivery_key,
        StateMutation::Put(delivery.encode()?),
    )?];
    match commit(reads, mutations)? {
        AtomicStateWriteResult::Committed => Ok(()),
        AtomicStateWriteResult::Conflict { .. } => Err(NodeCoreError::StateConflict),
    }
}

/// Acknowledges one leased message and advances the durable delivery cursor.
///
/// A send followed by a crash before this commit is deliberately redelivered.
pub fn acknowledge_outbox_message<S>(
    store: &S,
    layout: &PersistenceLayout,
    request_id: RequestId,
    index: u32,
    lease_id: OutboxLeaseId,
) -> Result<(), NodeCoreError>
where
    S: TransactionalStateStore,
{
    acknowledge_outbox_message_inner(
        layout,
        request_id,
        index,
        lease_id,
        |key| store.get_versioned(key),
        |reads, mutations| commit_legacy_transaction_parts(store, reads, mutations),
    )
}

/// Acknowledges one leased message inside an explicit atomicity domain.
pub fn acknowledge_outbox_message_in_domain<S>(
    store: &S,
    domain: AtomicityDomainId,
    layout: &PersistenceLayout,
    request_id: RequestId,
    index: u32,
    lease_id: OutboxLeaseId,
) -> Result<(), NodeCoreError>
where
    S: DomainTransactionalStateStore,
{
    acknowledge_outbox_message_inner(
        layout,
        request_id,
        index,
        lease_id,
        |key| store.get_versioned_in_domain(domain, key),
        |reads, mutations| {
            let transaction = AtomicStateTransaction::new(
                domain,
                AtomicStateReadSet::new(reads)?,
                AtomicStateMutationSet::new(mutations)?,
            )?;
            Ok(store.commit_transaction(transaction)?)
        },
    )
}

fn validate_outbox_identity(
    request_id: RequestId,
    batch: &NodeOutboxBatch,
    delivery: &NodeOutboxDelivery,
) -> Result<(), NodeCoreError> {
    if batch.request_id != request_id
        || delivery.request_id != request_id
        || batch.event_digest != delivery.event_digest
    {
        return Err(NodeCoreError::PersistenceInvariant(
            "outbox batch and delivery identities differ",
        ));
    }
    Ok(())
}

/// Handles exactly one event and atomically persists its deterministic transition.
///
/// Outputs are returned only after compare-and-swap succeeds. The caller may then
/// sign or deliver them. A conflict is surfaced to the adapter; node-core never
/// retries because retry policy and invocation budgets belong to the adapter.
pub fn handle_event<R, M>(
    runtime: &R,
    config: &NodeConfig,
    event: NodeEvent,
    machine: &M,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    M: NodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let current = runtime.state_store().get(config.state_key())?;
    if let Some(bytes) = &current {
        validate_state(bytes)?;
    }

    let transition = machine.transition(current.as_deref(), &event)?;
    validate_output_context(&transition.output, &event, config)?;

    let result = runtime.state_store().compare_and_swap(
        config.state_key.clone(),
        current,
        transition.next_state,
    )?;
    if !result.swapped {
        return Err(NodeCoreError::StateConflict);
    }
    Ok(transition.output)
}

fn validate_output_context(
    output: &NodeOutput,
    event: &NodeEvent,
    config: &NodeConfig,
) -> Result<(), NodeCoreError> {
    validate_output_event_context(output, event)?;
    for message in output.outbound_messages() {
        message.event().validate_context(config)?;
    }
    Ok(())
}

fn validate_output_event_context(
    output: &NodeOutput,
    event: &NodeEvent,
) -> Result<(), NodeCoreError> {
    for response in output.responses() {
        if response.request_id() != event.request_id() {
            return Err(NodeCoreError::ResponseRequestMismatch {
                expected: event.request_id(),
                actual: response.request_id(),
            });
        }
    }
    for message in output.outbound_messages() {
        let outbound = message.event();
        if outbound.chain_id() != event.chain_id() {
            return Err(NodeCoreError::ChainMismatch {
                expected: event.chain_id().clone(),
                actual: outbound.chain_id().clone(),
            });
        }
        if outbound.protocol_version() != event.protocol_version() {
            return Err(NodeCoreError::ProtocolVersionMismatch {
                expected: event.protocol_version(),
                actual: outbound.protocol_version(),
            });
        }
        if outbound.epoch() != event.epoch() {
            return Err(NodeCoreError::EpochMismatch {
                expected: event.epoch(),
                actual: outbound.epoch(),
            });
        }
    }
    Ok(())
}

fn validate_chain_id(chain_id: &ChainId) -> Result<(), NodeCoreError> {
    let length = chain_id.as_str().len();
    if length > MAX_CHAIN_ID_BYTES {
        return Err(NodeCoreError::ChainIdTooLong(length));
    }
    Ok(())
}

fn validate_payload(payload: &[u8]) -> Result<(), NodeCoreError> {
    if payload.len() > MAX_NODE_PAYLOAD_BYTES {
        return Err(NodeCoreError::PayloadTooLarge(payload.len()));
    }
    decode_canonical_frame(payload)?;
    Ok(())
}

fn validate_state(state: &[u8]) -> Result<(), NodeCoreError> {
    if state.len() > MAX_NODE_STATE_BYTES {
        return Err(NodeCoreError::StateTooLarge(state.len()));
    }
    decode_canonical_frame(state)?;
    Ok(())
}

fn validate_transactional_state_key(key: &[u8]) -> Result<(), NodeCoreError> {
    if key.is_empty() {
        return Err(NodeCoreError::EmptyStateKey);
    }
    if key.len() > MAX_STATE_KEY_BYTES {
        return Err(NodeCoreError::Runtime(RuntimeError::StateKeyTooLong {
            length: key.len(),
            maximum: MAX_STATE_KEY_BYTES,
        }));
    }
    Ok(())
}

fn hex32(bytes: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn decode_request_id(bytes: &[u8]) -> Result<RequestId, NodeCoreError> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| NodeCoreError::InvalidRequestIdLength(bytes.len()))?;
    RequestId::new(array)
}

fn decode_digest(algorithm: u16, bytes: &[u8]) -> Result<Digest32, NodeCoreError> {
    let algorithm =
        HashAlgorithmId::try_from(algorithm).map_err(NodeCoreError::InvalidHashAlgorithm)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| NodeCoreError::InvalidDigestLength(bytes.len()))?;
    Ok(Digest32::new(algorithm, bytes))
}

fn bounded_nested_count(count: u32, collection: &'static str) -> Result<usize, NodeCoreError> {
    let count = usize::try_from(count).map_err(|_| NodeCoreError::TooManyOutputItems {
        collection,
        count: usize::MAX,
    })?;
    if count > MAX_NODE_OUTPUT_ITEMS {
        return Err(NodeCoreError::TooManyOutputItems { collection, count });
    }
    Ok(count)
}

fn encode_nested_items(items: Vec<Vec<u8>>) -> Result<Vec<u8>, NodeCoreError> {
    let capacity = items.iter().try_fold(0_usize, |total, item| {
        total.checked_add(4)?.checked_add(item.len())
    });
    let capacity = capacity.ok_or(NodeCoreError::StateTooLarge(usize::MAX))?;
    if capacity > MAX_NODE_STATE_BYTES {
        return Err(NodeCoreError::StateTooLarge(capacity));
    }

    let mut encoded = Vec::with_capacity(capacity);
    for item in items {
        let length = u32::try_from(item.len())
            .map_err(|_| NodeCoreError::NestedItemLengthOverflow(item.len()))?;
        encoded.extend_from_slice(&length.to_le_bytes());
        encoded.extend_from_slice(&item);
    }
    Ok(encoded)
}

fn decode_nested_items<T, F>(
    bytes: &[u8],
    count: usize,
    mut decode: F,
) -> Result<Vec<T>, NodeCoreError>
where
    F: FnMut(&[u8]) -> Result<T, NodeCoreError>,
{
    let mut offset = 0_usize;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let length_bytes = take_nested_bytes(bytes, &mut offset, 4)?;
        let length = usize::try_from(u32::from_le_bytes([
            length_bytes[0],
            length_bytes[1],
            length_bytes[2],
            length_bytes[3],
        ]))
        .map_err(|_| NodeCoreError::NestedItemLengthOverflow(usize::MAX))?;
        items.push(decode(take_nested_bytes(bytes, &mut offset, length)?)?);
    }
    if offset != bytes.len() {
        return Err(NodeCoreError::TrailingNestedListBytes(bytes.len() - offset));
    }
    Ok(items)
}

fn take_nested_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], NodeCoreError> {
    let end = offset
        .checked_add(length)
        .ok_or(NodeCoreError::NestedItemLengthOverflow(usize::MAX))?;
    let value = bytes
        .get(*offset..end)
        .ok_or(CanonicalDecodingError::Truncated {
            offset: *offset,
            needed: length,
            remaining: bytes.len().saturating_sub(*offset),
        })?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests;
