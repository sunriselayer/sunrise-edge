#![forbid(unsafe_code)]
// Mirrors the existing `crates/node-core::fast_path`/
// `crates/node-core/tests/local_inventory.rs` precedent: these adapter
// errors wrap `node-core`/`node-wire` error types directly rather than
// boxing them, so callers keep a plain match over the real cause.
#![allow(clippy::result_large_err)]
//! Embedded Rust contract host for a SQLite-backed Cloudflare Durable
//! Object (DR-0152).
//!
//! This crate embeds the real `node-core`/`execution` Wasmi interpreter
//! (the same [`execution::LocalWasmExecutionEngine`] the native adapters
//! use) behind a `wasm-bindgen` boundary. It never compiles guest
//! contract code with the browser/Workers WASM engine, and never depends
//! on `native-http`, PostgreSQL, or any other native/system crate.
//!
//! [`sql_backend::DoSqlBackend`]/[`blob_store::DoBlobStoreAdapter`] over
//! [`host::SqlHost`]/[`host::DoBlobStore`] plug directly into
//! `runtime_sql_durable::SqlDurableEngine`, the same
//! `StructuredDurableDomainStateStore` statements/rules a native SQLite
//! host uses. [`ValidatorHost`] wires that engine to the unmodified
//! `node_core::fast_path`/`node_core::genesis`/`node_core` query
//! functions and to `node-wire`'s existing HTTP query-result encoders;
//! nothing here invents a new persistence engine or wire format.

pub mod blob_store;
pub mod config;
pub mod dispatch;
pub mod host;
pub mod sql_backend;

use std::cell::Cell;

use blob_store::DoBlobStoreAdapter;
use config::{AdapterConfigError, TrustedAdapterConfig, decode_trusted_adapter_config};
use consensus::ConsensusSigner;
use consensus::encode_fast_vote;
use dispatch::QueryDispatchError;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::LocalWasmExecutionEngine;
use execution::local_execution::LocalExecutionPolicy;
use execution::paid_execution::{decode_paid_fee_policy, decode_signed_paid_intent};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use host::{DoBlobStore, SqlHost};
use node_core::fast_path::records::decode_fastpath_validator_set_record;
use node_core::fast_path::{self, FastPathError};
use node_core::genesis::{
    GenesisError, GenesisInstallOutcome, decode_genesis_install_marker, decode_genesis_manifest,
    encode_genesis_install_marker, genesis_manifest_commitment, genesis_marker_key,
    install_genesis,
};
use node_core::local_instance_state::{fastpath_validator_set_key, paid_fee_policy_key};
use node_core::paid_execution::{PaidExecutionAdmissionError, authenticate_paid_execution};
use node_core::publication::PublicationAdmissionError;
use node_core::{NodeCoreError, RequestId, query_committed_epoch_state};
use node_wire::{FastVoteApplyRequest, HttpContextQueryResult, HttpNodeResult};
use objects::ObjectId;
use protocol_config::{
    DomainPlacementManifest, ProtocolConfig, TransactionAuthProfile,
    resolve_transaction_auth_profile,
};
use protocol_types::{Epoch, HashSuite, HashSuiteSchedule, SignatureSchemeId, ValidatorId};
use runtime::{
    DurableDomainStateStore, DurableOperationContext, StorageCorrelationId, StorageDeadline,
};
use runtime_sql_durable::backend::{SqlBackend, TransactionBudget, TransactionDecision};
use runtime_sql_durable::{SqlDurableEngine, SqlDurableNamespace, schema};
use sql_backend::{DoSqlBackend, read_now_millis};
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

/// Trusted local Ed25519 fast-path signer derived from
/// [`TrustedAdapterConfig::validator_signing_secret`], never a caller-
/// supplied key.
struct DoConsensusSigner {
    validator_id: ValidatorId,
    signing_key: SigningKey,
}

impl ConsensusSigner for DoConsensusSigner {
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

/// Errors an exported [`ValidatorHost`] method can return to JS.
#[derive(Debug)]
pub enum AdapterError {
    /// The supplied configuration bytes were rejected.
    Config(AdapterConfigError),
    /// The Ed25519 verification key derived from the configured signing
    /// secret does not equal the configured validator id.
    SignerDerivationMismatch,
    /// [`hashing::HashSuiteResolver::new`] rejected the pinned genesis
    /// suite schedule.
    Hashing(hashing::HashingError),
    /// Bootstrapping or verifying the SQL namespace/schema failed.
    NamespaceBootstrap(String),
    /// The genesis manifest failed to decode or install.
    Genesis(GenesisError),
    /// The manifest own `genesis_authority` did not match the pinned
    /// configuration.
    GenesisAuthorityMismatch,
    /// The manifest own commitment digest did not match the pinned
    /// configuration.
    GenesisDigestMismatch,
    /// A read-only query failed.
    Query(QueryDispatchError),
    /// A fast-path prepare/apply failed.
    /// A fast-path prepare/apply failed. The status/code are precomputed
    /// by [`categorize_fast_path_error`] at the point of failure,
    /// mirroring `crates/native-http/src/fastvote.rs`'s own
    /// `fastpath_error_response`/`node_error_response` categorization
    /// (malformed/signature admission -> 400, a genuine
    /// `RequestIdReuse`/`SenderNonceMismatch`/`StateConflict`/context
    /// conflict -> 409, storage corruption/fencing/indeterminacy ->
    /// 503), instead of one blanket status for every cause.
    FastPath(u16, &'static str),
    /// A request body failed to decode for its dispatched path.
    InvalidRequestBody,
    /// `dispatch` received a path this build does not route.
    UnknownPath,
    /// Building the durable operation context (clock read, deadline, or
    /// correlation id) failed.
    OperationContext(String),
    /// The committed genesis is not (yet) confirmed installed and
    /// verified against this instance own pinned config; mutation is
    /// refused until [`ValidatorHost::install_genesis`] succeeds.
    GenesisNotInstalled,
    /// The durably installed paid fee policy differs from
    /// [`TrustedAdapterConfig::paid_fee_policy`].
    FeePolicyMismatch,
    /// No committed paid fee policy exists although genesis reports
    /// installed; persisted-state corruption from this instance own
    /// perspective.
    FeePolicyNotInstalled,
    /// The durably committed current epoch differs from
    /// [`TrustedAdapterConfig::epoch`]. This closed profile has no epoch
    /// mutator, so it refuses to answer rather than silently reading (or
    /// signing) against either value.
    EpochMismatch,
    /// This instance own validator id is not an active member of the
    /// committed fast-path validator set, or its registered public key
    /// differs from the configured signing key.
    ValidatorNotRegistered,
    /// No publication exists for the requested `(publisher, seed)`.
    PublicationNotFound,
    /// No instance exists for the requested `(creator, seed)`.
    InstanceNotFound,
    /// A path selector segment was not exactly 64 lowercase hex digits.
    InvalidSelector,
    /// A query path (empty-body GET-equivalent) received a non-empty body.
    NonEmptyQueryBody,
}

impl AdapterError {
    /// Maps this error to the small, stable HTTP-style status the parent
    /// Worker/DO ingress uses to decide its own response, never the
    /// underlying debug detail.
    const fn http_status(&self) -> u16 {
        match self {
            Self::FastPath(status, _) => *status,
            Self::Config(_)
            | Self::SignerDerivationMismatch
            | Self::Hashing(_)
            | Self::InvalidRequestBody
            | Self::InvalidSelector
            | Self::NonEmptyQueryBody
            | Self::UnknownPath => 400,
            Self::PublicationNotFound | Self::InstanceNotFound => 404,
            Self::GenesisAuthorityMismatch
            | Self::GenesisDigestMismatch
            | Self::GenesisNotInstalled
            | Self::EpochMismatch
            | Self::FeePolicyMismatch
            | Self::ValidatorNotRegistered => 409,
            Self::NamespaceBootstrap(_)
            | Self::OperationContext(_)
            | Self::Genesis(_)
            | Self::Query(_)
            | Self::FeePolicyNotInstalled => 503,
        }
    }

    /// A short, stable, non-secret identifier for this error. Never
    /// formats an inner error, config value, or any other adapter-
    /// internal detail.
    const fn code(&self) -> &'static str {
        match self {
            Self::FastPath(_, code) => code,
            Self::Config(_) => "invalid-config",
            Self::SignerDerivationMismatch => "invalid-config-signer",
            Self::Hashing(_) => "invalid-config-hash-suite",
            Self::InvalidRequestBody => "invalid-request-body",
            Self::InvalidSelector => "invalid-selector",
            Self::NonEmptyQueryBody => "invalid-query-body",
            Self::UnknownPath => "unknown-path",
            Self::PublicationNotFound => "publication-not-found",
            Self::InstanceNotFound => "instance-not-found",
            Self::GenesisAuthorityMismatch => "genesis-authority-mismatch",
            Self::GenesisDigestMismatch => "genesis-digest-mismatch",
            Self::GenesisNotInstalled => "genesis-not-installed",
            Self::EpochMismatch => "fastvote-epoch-repin-required",
            Self::FeePolicyMismatch => "fee-policy-mismatch",
            Self::ValidatorNotRegistered => "validator-not-registered",
            Self::NamespaceBootstrap(_) => "namespace-unavailable",
            Self::OperationContext(_) => "operation-context-unavailable",
            Self::Genesis(_) => "genesis-failed",
            Self::Query(_) => "query-failed",
            Self::FeePolicyNotInstalled => "fee-policy-not-installed",
        }
    }
}

impl From<AdapterError> for JsValue {
    /// Builds `{ status, httpStatus, code }` only -- never the `Debug`
    /// dump of the inner error, which could echo back config-derived
    /// strings (chain id, path selectors) the parent may not want
    /// forwarded verbatim, and never any signing/config secret (none of
    /// which any `AdapterError` variant carries in the first place).
    fn from(error: AdapterError) -> Self {
        let status = f64::from(error.http_status());
        let object = js_sys::Object::new();
        let _ = js_sys::Reflect::set(
            &object,
            &JsValue::from_str("status"),
            &JsValue::from_f64(status),
        );
        let _ = js_sys::Reflect::set(
            &object,
            &JsValue::from_str("httpStatus"),
            &JsValue::from_f64(status),
        );
        let _ = js_sys::Reflect::set(
            &object,
            &JsValue::from_str("code"),
            &JsValue::from_str(error.code()),
        );
        object.into()
    }
}

/// Exact `GET`-equivalent selector paths, matching
/// `node_wire::{QUERY_CONTEXT_PATH, QUERY_OBJECT_PATH, QUERY_RECEIPT_PATH,
/// QUERY_NEXT_NONCE_PATH}` and
/// `crates/native-http/src/{publication.rs,local_execution.rs,paid_execution.rs}`
/// own route templates, with each `{selector}` segment already
/// substituted by the caller as 64 lowercase hex characters. Every path
/// below requires an empty request body.
pub const PATH_CONTEXT: &str = "/v1/context";
/// Prefix before one 64-lowercase-hex object id.
pub const PATH_OBJECTS_PREFIX: &str = "/v1/objects/";
/// Prefix before one 64-lowercase-hex request id.
pub const PATH_RECEIPTS_PREFIX: &str = "/v1/receipts/";
/// Prefix before one 64-lowercase-hex sender address; suffixed by
/// [`PATH_NEXT_NONCE_SUFFIX`].
pub const PATH_SENDERS_PREFIX: &str = "/v1/senders/";
/// Suffix after the sender address segment.
pub const PATH_NEXT_NONCE_SUFFIX: &str = "/next-nonce";
/// Exact match; matches `native-http`'s `PAID_FEE_POLICY_PATH`.
pub const PATH_PAID_FEE_POLICY: &str = "/v1/contracts/paid-fee-policy";
/// Prefix before `{publisher}/{origin_seed}`, each 64 lowercase hex
/// characters, matching `native-http::publication::QUERY_PATH`.
pub const PATH_PUBLICATIONS_PREFIX: &str = "/v1/contracts/publications/";
/// Prefix before `{creator}/{seed}`, each 64 lowercase hex characters,
/// matching `native-http::local_execution::INSTANCE_PATH`.
pub const PATH_INSTANCES_PREFIX: &str = "/v1/contracts/instances/";
/// The request body is one canonical `SignedPaidIntent`.
pub const PATH_FASTVOTE_PREPARE: &str = "/v1/fastvote/prepare";
/// The request body is one canonical `FastVoteApplyRequest`.
pub const PATH_FASTVOTE_APPLY: &str = "/v1/fastvote/certificates";

/// Decodes exactly 64 lowercase hex characters, matching
/// `crates/native-http::decode_hex64_selector` exactly (fixed length,
/// lowercase-only, no `0x` prefix).
fn decode_hex64_selector(input: &str) -> Option<[u8; 32]> {
    let bytes = input.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        out[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Some(out)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Splits `path` into two `/`-separated 64-hex-character segments, or
/// `None` if the shape or either segment own encoding is wrong.
fn decode_two_hex64_segments(path: &str) -> Option<([u8; 32], [u8; 32])> {
    let (first, second) = path.split_once('/')?;
    if second.contains('/') {
        return None;
    }
    Some((
        decode_hex64_selector(first)?,
        decode_hex64_selector(second)?,
    ))
}

/// Categorizes a `node_core::fast_path::FastPathError` into the small
/// stable status/code pair this crate exposes, mirroring
/// `crates/native-http/src/fastvote.rs::fastpath_error_response` and
/// `crates/native-http/src/lib.rs::node_error_response`. This is a
/// deliberately coarser subset of that mapping (every unlisted
/// `NodeCoreError` variant falls back to 503), not full parity with
/// every native-http status/code pair.
fn categorize_fast_path_error(error: &FastPathError) -> (u16, &'static str) {
    match error {
        FastPathError::Admission(admission) => categorize_admission_error(admission),
        FastPathError::Consensus(_) => (400, "fastvote-consensus-rejected"),
        FastPathError::Invalid(_) => (400, "fastvote-rejected"),
        FastPathError::Node(node_error) => categorize_node_core_error(node_error),
    }
}

fn categorize_admission_error(error: &PaidExecutionAdmissionError) -> (u16, &'static str) {
    match error {
        PaidExecutionAdmissionError::Node(node_error) => categorize_node_core_error(node_error),
        PaidExecutionAdmissionError::Publication(PublicationAdmissionError::OriginExists) => {
            (409, "publication-origin-exists")
        }
        PaidExecutionAdmissionError::Publication(PublicationAdmissionError::Node(node_error)) => {
            categorize_node_core_error(node_error)
        }
        PaidExecutionAdmissionError::Publication(_)
        | PaidExecutionAdmissionError::Execution(_)
        | PaidExecutionAdmissionError::Paid(_)
        | PaidExecutionAdmissionError::Invalid(_) => (400, "paid-execution-rejected"),
    }
}

/// Mirrors `crates/native-http/src/lib.rs::node_error_response`'s three
/// named buckets exactly (malformed/signature admission is handled by
/// the caller before this is ever reached; a genuine
/// `RequestIdReuse`/`SenderNonceMismatch`/`StateConflict`/chain-protocol-
/// epoch context conflict is 409; storage corruption, writer fencing,
/// and commit indeterminacy are 503); every other variant falls back to
/// 503 rather than guessing a caller-fault status for a cause this
/// crate has not specifically categorized.
fn categorize_node_core_error(error: &NodeCoreError) -> (u16, &'static str) {
    match error {
        NodeCoreError::ChainMismatch { .. }
        | NodeCoreError::ProtocolVersionMismatch { .. }
        | NodeCoreError::EpochMismatch { .. }
        | NodeCoreError::StateConflict
        | NodeCoreError::RequestIdReuse
        | NodeCoreError::SenderNonceMismatch { .. } => (409, "state-or-context-conflict"),
        NodeCoreError::Runtime(_)
        | NodeCoreError::DurableRead(_)
        | NodeCoreError::DurableInvocation(_)
        | NodeCoreError::DurableCommitRejected(_)
        | NodeCoreError::DurableCommitIndeterminate(_) => (503, "durable-storage-unavailable"),
        _ => (503, "fastpath-node-error"),
    }
}

/// The `wasm-bindgen`-exported embedded validator instance.
///
/// One `ValidatorHost` maps to exactly one Durable Object instance and one
/// trusted `(chain, validator, domain)` namespace, fixed for its lifetime
/// by [`TrustedAdapterConfig`] and re-verified against the persisted
/// `durable_metadata` row on every construction. Nothing here accepts a
/// caller-selected namespace, domain, or writer identity.
#[wasm_bindgen]
pub struct ValidatorHost {
    config: TrustedAdapterConfig,
    engine: SqlDurableEngine<DoSqlBackend>,
    blobs: DoBlobStoreAdapter,
    resolver: HashSuiteResolver,
    signer: DoConsensusSigner,
    request_counter: Cell<u64>,
    /// Cached result of the last [`ValidatorHost::verify_committed_genesis`]
    /// call: `true` only once this instance has itself durably confirmed
    /// the committed genesis marker/fee-policy/validator-set all match
    /// its own pinned config. Checked once at construction and once more
    /// after a successful `installGenesis`, never re-read per mutation
    /// dispatch, so no per-request freshness read is added ahead of
    /// `fast_path::prepare`/`apply_with_recovery`'s own committed-replay
    /// order.
    genesis_confirmed: Cell<bool>,
}

impl ValidatorHost {
    /// Builds one fenced, deadline-bounded operation context from a fresh
    /// host clock reading and a per-instance monotonically advancing
    /// correlation counter (never a global).
    fn build_operation_context(&self) -> Result<DurableOperationContext, AdapterError> {
        let now = read_now_millis(self.engine.backend().sql())
            .map_err(|error| AdapterError::OperationContext(format!("{error}")))?;
        let counter = self.request_counter.get();
        self.request_counter.set(counter.wrapping_add(1).max(1));
        let deadline_millis = now
            .checked_add(self.config.operation_timeout_millis())
            .ok_or_else(|| AdapterError::OperationContext("deadline overflow".to_owned()))?;
        let deadline = StorageDeadline::new(deadline_millis)
            .ok_or_else(|| AdapterError::OperationContext("zero deadline".to_owned()))?;
        let mut correlation_bytes = [0_u8; 16];
        correlation_bytes[..8].copy_from_slice(&now.to_be_bytes());
        correlation_bytes[8..].copy_from_slice(&counter.to_be_bytes());
        let correlation_id = StorageCorrelationId::new(correlation_bytes)
            .ok_or_else(|| AdapterError::OperationContext("zero correlation id".to_owned()))?;
        Ok(DurableOperationContext::new(
            self.config.writer_fence(),
            deadline,
            correlation_id,
        ))
    }

    fn expected_context(&self) -> Result<PublicationContext, AdapterError> {
        PublicationContext::new(
            self.config.chain_id().clone(),
            self.config.protocol_version(),
            self.config.epoch(),
        )
        .map_err(|_| {
            AdapterError::OperationContext("invalid pinned publication context".to_owned())
        })
    }

    /// Reads the durably committed current epoch and requires it equal
    /// [`TrustedAdapterConfig::epoch`]. This closed DO profile has no
    /// epoch mutator: a query needs *some* current epoch to answer
    /// against, and reading the committed one while requiring it agree
    /// with the pinned config is the fail-closed alternative to either
    /// blindly trusting the pinned epoch as "current" or signing/
    /// answering at a stale one.
    fn require_current_committed_epoch(
        &self,
        context: &DurableOperationContext,
    ) -> Result<Epoch, AdapterError> {
        let record = query_committed_epoch_state(
            &self.engine,
            context,
            self.config.domain(),
            self.config.chain_id(),
        )
        .map_err(|error| AdapterError::OperationContext(format!("{error}")))?;
        if record.current_epoch != self.config.epoch() {
            return Err(AdapterError::EpochMismatch);
        }
        Ok(record.current_epoch)
    }

    /// Independently re-verifies the committed genesis marker, paid fee
    /// policy, and fast-path validator set against this instance own
    /// pinned config -- the same three checks
    /// `apps/operator/src/bin/fastvote_host_pg.rs`'s own startup
    /// `require_committed_genesis_fee_policy`/`require_registered_signer`/
    /// `require_live_fastvote_pin` perform, reimplemented here directly
    /// (not by depending on `apps/operator`, which pulls PostgreSQL/axum/
    /// tokio) against [`SqlDurableEngine`]. Returns `Ok(false)` only when
    /// genesis has genuinely never been installed (no marker row at
    /// all); every other disagreement is a definite, fail-closed error.
    fn verify_committed_genesis(&self) -> Result<bool, AdapterError> {
        let expected = self.expected_context()?;
        let context = self.build_operation_context()?;
        let domain = self.config.domain();

        let marker_key = genesis_marker_key(&expected).map_err(AdapterError::Genesis)?;
        let marker_observed = self
            .engine
            .get_versioned_durable(&context, domain, &marker_key)
            .map_err(|error| AdapterError::OperationContext(format!("{error:?}")))?;
        let Some(marker_bytes) = marker_observed.value() else {
            if marker_observed.revision() != runtime::StateRevision::INITIAL {
                return Err(AdapterError::GenesisNotInstalled);
            }
            return Ok(false);
        };
        let marker = decode_genesis_install_marker(marker_bytes).map_err(AdapterError::Genesis)?;
        if marker.context != expected
            || marker.manifest_digest != *self.config.genesis_manifest_digest()
            || marker.genesis_authority != *self.config.genesis_authority_public_key()
        {
            return Err(AdapterError::GenesisDigestMismatch);
        }

        let policy_key = paid_fee_policy_key(&expected)
            .map_err(|error| AdapterError::OperationContext(format!("{error}")))?;
        let policy_observed = self
            .engine
            .get_versioned_durable(&context, domain, &policy_key)
            .map_err(|error| AdapterError::OperationContext(format!("{error:?}")))?;
        let policy_bytes = policy_observed
            .value()
            .ok_or(AdapterError::FeePolicyNotInstalled)?;
        let policy = decode_paid_fee_policy(policy_bytes)
            .map_err(|_| AdapterError::FeePolicyNotInstalled)?;
        if policy != *self.config.paid_fee_policy() {
            return Err(AdapterError::FeePolicyMismatch);
        }

        let validator_set_key = fastpath_validator_set_key(&expected)
            .map_err(|error| AdapterError::OperationContext(format!("{error}")))?;
        let validator_set_observed = self
            .engine
            .get_versioned_durable(&context, domain, &validator_set_key)
            .map_err(|error| AdapterError::OperationContext(format!("{error:?}")))?;
        let validator_set_bytes = validator_set_observed
            .value()
            .ok_or(AdapterError::ValidatorNotRegistered)?;
        let record = decode_fastpath_validator_set_record(validator_set_bytes)
            .map_err(|_| AdapterError::ValidatorNotRegistered)?;
        if record.context != expected {
            return Err(AdapterError::ValidatorNotRegistered);
        }
        let entry = record
            .validators
            .iter()
            .find(|entry| entry.id == self.signer.validator_id)
            .ok_or(AdapterError::ValidatorNotRegistered)?;
        let derived_public_key: [u8; 32] = VerificationKey::from(&self.signer.signing_key).into();
        if entry.signature_scheme != SignatureSchemeId::Ed25519
            || entry.public_key != derived_public_key.to_vec()
        {
            return Err(AdapterError::ValidatorNotRegistered);
        }

        Ok(true)
    }
}

#[wasm_bindgen]
impl ValidatorHost {
    /// Validates `config_bytes`, derives and cross-checks the local
    /// signer identity, then bootstraps or verifies the persisted SQL
    /// namespace/schema (`durable_metadata`) inside one host transaction
    /// *before* touching any state or blob row, exactly matching
    /// `SqlDurableEngine::new`'s own documented precondition.
    #[wasm_bindgen(constructor)]
    pub fn new(
        config_bytes: &[u8],
        sql: SqlHost,
        blobs: DoBlobStore,
    ) -> Result<ValidatorHost, JsValue> {
        let config = decode_trusted_adapter_config(config_bytes).map_err(AdapterError::Config)?;

        let signing_key = SigningKey::from(*config.validator_signing_secret());
        let derived_public_key: [u8; 32] = VerificationKey::from(&signing_key).into();
        if derived_public_key != *config.validator_id().as_bytes() {
            return Err(AdapterError::SignerDerivationMismatch.into());
        }

        let resolver = HashSuiteResolver::new(
            config.chain_id().clone(),
            config.protocol_version(),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .map_err(AdapterError::Hashing)?;

        let namespace = SqlDurableNamespace::new(
            config.chain_id().clone(),
            config.validator_id(),
            config.domain(),
        );
        let writer_fence = config.writer_fence();
        let backend = DoSqlBackend::new(sql);
        let bootstrap_outcome =
            backend.transaction(TransactionBudget::OperatorDefault, |session, _now| {
                match schema::bootstrap_namespace(session, &namespace, writer_fence) {
                    Ok(metadata) if metadata.writer_fence() == writer_fence => {
                        Ok(TransactionDecision::Commit(Ok(())))
                    }
                    Ok(metadata) => Ok(TransactionDecision::Rollback(Err(
                        AdapterError::NamespaceBootstrap(format!(
                            "persisted writer fence {} does not match configured fence {}",
                            metadata.writer_fence().get(),
                            writer_fence.get()
                        )),
                    ))),
                    Err(schema::SchemaError::Session(session_error)) => Err(session_error),
                    Err(other) => Ok(TransactionDecision::Rollback(Err(
                        AdapterError::NamespaceBootstrap(other.to_string()),
                    ))),
                }
            });
        match bootstrap_outcome {
            Ok(Ok(())) => {}
            Ok(Err(adapter_error)) => return Err(adapter_error.into()),
            Err(backend_error) => {
                return Err(AdapterError::NamespaceBootstrap(format!("{backend_error:?}")).into());
            }
        }

        let engine = SqlDurableEngine::new(backend, namespace);
        let blobs = DoBlobStoreAdapter::new(blobs);
        let signer = DoConsensusSigner {
            validator_id: config.validator_id(),
            signing_key,
        };

        let host = Self {
            config,
            engine,
            blobs,
            resolver,
            signer,
            request_counter: Cell::new(1),
            genesis_confirmed: Cell::new(false),
        };
        // A brand-new database has no genesis installed yet, which
        // `verify_committed_genesis` reports as `Ok(false)`, not an
        // error; only a genuine disagreement between what is already
        // committed and this instance own pinned config refuses
        // construction outright.
        let confirmed = host.verify_committed_genesis()?;
        host.genesis_confirmed.set(confirmed);
        Ok(host)
    }
}

#[wasm_bindgen]
impl ValidatorHost {
    /// Installs the pinned genesis manifest.
    ///
    /// Fails closed unless the manifest own `genesis_authority` field and
    /// its recomputed commitment digest exactly match
    /// [`TrustedAdapterConfig::genesis_authority_public_key`]/
    /// [`TrustedAdapterConfig::genesis_manifest_digest`]: this instance
    /// only ever installs the one genesis it was deployed to install.
    #[wasm_bindgen(js_name = installGenesis)]
    pub fn install_genesis(&self, manifest_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        let manifest = decode_genesis_manifest(manifest_bytes).map_err(AdapterError::Genesis)?;
        if manifest.genesis_authority != *self.config.genesis_authority_public_key() {
            return Err(AdapterError::GenesisAuthorityMismatch.into());
        }
        let commitment = genesis_manifest_commitment(&self.resolver, &manifest)
            .map_err(AdapterError::Genesis)?;
        if commitment != *self.config.genesis_manifest_digest() {
            return Err(AdapterError::GenesisDigestMismatch.into());
        }
        let expected = self.expected_context()?;
        if *manifest.context() != expected {
            return Err(AdapterError::GenesisDigestMismatch.into());
        }
        if manifest.fee_policy != *self.config.paid_fee_policy() {
            return Err(AdapterError::FeePolicyMismatch.into());
        }
        let derived_public_key: [u8; 32] = VerificationKey::from(&self.signer.signing_key).into();
        let is_registered = manifest.validator_set.validators.iter().any(|entry| {
            entry.id == self.signer.validator_id
                && entry.signature_scheme == SignatureSchemeId::Ed25519
                && entry.public_key == derived_public_key.to_vec()
        });
        if !is_registered {
            return Err(AdapterError::ValidatorNotRegistered.into());
        }
        let context = self.build_operation_context()?;
        let outcome = install_genesis(
            &self.engine,
            &context,
            self.config.domain(),
            &self.resolver,
            &manifest,
            self.config.created_checkpoint(),
        )
        .map_err(AdapterError::Genesis)?;
        let (tag, marker) = match outcome {
            GenesisInstallOutcome::FreshInstall { marker, .. } => (1_u8, marker),
            GenesisInstallOutcome::VerifiedExisting { marker, .. } => (2_u8, marker),
        };
        let mut out = vec![tag];
        out.extend_from_slice(
            &encode_genesis_install_marker(&marker).map_err(AdapterError::Genesis)?,
        );
        if !self.verify_committed_genesis()? {
            return Err(AdapterError::GenesisNotInstalled.into());
        }
        self.genesis_confirmed.set(true);
        Ok(out)
    }

    /// Dispatches one request to its bounded, node-core-backed handler by
    /// exact selector path, matching `node-wire`/`native-http`'s own
    /// accepted routes. Every query path (all of them except
    /// [`PATH_FASTVOTE_PREPARE`]/[`PATH_FASTVOTE_APPLY`]) requires an
    /// empty body, exactly like the GET requests they answer for the
    /// native HTTP transport.
    pub fn dispatch(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, JsValue> {
        if path == PATH_FASTVOTE_PREPARE {
            return self.dispatch_fastvote_prepare(body);
        }
        if path == PATH_FASTVOTE_APPLY {
            return self.dispatch_fastvote_apply(body);
        }
        if !body.is_empty() {
            return Err(AdapterError::NonEmptyQueryBody.into());
        }
        if path == PATH_CONTEXT {
            return self.dispatch_query_context();
        }
        if path == PATH_PAID_FEE_POLICY {
            return self.dispatch_query_paid_fee_policy();
        }
        if let Some(selector) = path.strip_prefix(PATH_OBJECTS_PREFIX) {
            return self.dispatch_query_object(selector);
        }
        if let Some(selector) = path.strip_prefix(PATH_RECEIPTS_PREFIX) {
            return self.dispatch_query_receipt(selector);
        }
        if let Some(rest) = path.strip_prefix(PATH_SENDERS_PREFIX) {
            if let Some(selector) = rest.strip_suffix(PATH_NEXT_NONCE_SUFFIX) {
                return self.dispatch_query_next_nonce(selector);
            }
            return Err(AdapterError::UnknownPath.into());
        }
        if let Some(rest) = path.strip_prefix(PATH_PUBLICATIONS_PREFIX) {
            return self.dispatch_query_publication(rest);
        }
        if let Some(rest) = path.strip_prefix(PATH_INSTANCES_PREFIX) {
            return self.dispatch_query_instance(rest);
        }
        Err(AdapterError::UnknownPath.into())
    }
}

impl ValidatorHost {
    fn dispatch_query_context(&self) -> Result<Vec<u8>, JsValue> {
        let context = self.build_operation_context()?;
        let current_epoch = self.require_current_committed_epoch(&context)?;
        let mut protocol_config = ProtocolConfig::genesis();
        protocol_config.protocol_version = self.config.protocol_version();
        protocol_config.domain_placement = Some(
            DomainPlacementManifest::single_domain(1, self.config.domain(), Epoch::new(0))
                .map_err(|_| AdapterError::OperationContext("domain placement".to_owned()))?,
        );
        protocol_config.transaction_auth_profile =
            Some(TransactionAuthProfile::ed25519_canonical_prime_order_address_is_public_key());
        let profile = resolve_transaction_auth_profile(&protocol_config)
            .map_err(|_| AdapterError::OperationContext("transaction auth profile".to_owned()))?;
        let protocol_config_bytes = protocol_config
            .canonical_bytes()
            .map_err(|_| AdapterError::OperationContext("protocol config encoding".to_owned()))?;
        let result = HttpContextQueryResult::new(
            self.config.chain_id().clone(),
            self.config.protocol_version(),
            current_epoch,
            protocol_config.hash_suite_id,
            profile.profile_id(),
            profile.signature_scheme_id().as_u16(),
            profile.address_binding().as_u16(),
            self.config.domain(),
            protocol_config_bytes,
        )
        .map_err(|_| AdapterError::OperationContext("context result".to_owned()))?;
        result.encode().map_err(|_| {
            AdapterError::OperationContext("context result encoding".to_owned()).into()
        })
    }

    /// Reads the durably committed paid fee policy and requires it be
    /// byte-exact with its own re-encoding (corruption guard, exactly
    /// `native-http::paid_execution::query_policy`'s own check) and equal
    /// to [`TrustedAdapterConfig::paid_fee_policy`] -- this closed
    /// profile installs exactly one pinned policy and never reports a
    /// fabricated or drifted one.
    fn dispatch_query_paid_fee_policy(&self) -> Result<Vec<u8>, JsValue> {
        let context = self.build_operation_context()?;
        let current_epoch = self.require_current_committed_epoch(&context)?;
        let current_context = PublicationContext::new(
            self.config.chain_id().clone(),
            self.config.protocol_version(),
            current_epoch,
        )
        .map_err(|_| AdapterError::OperationContext("current context".to_owned()))?;
        let key = paid_fee_policy_key(&current_context)
            .map_err(|error| AdapterError::OperationContext(format!("{error}")))?;
        let observed = self
            .engine
            .get_versioned_durable(&context, self.config.domain(), &key)
            .map_err(|error| AdapterError::OperationContext(format!("{error:?}")))?;
        let bytes = observed
            .value()
            .ok_or(AdapterError::FeePolicyNotInstalled)?;
        let policy =
            decode_paid_fee_policy(bytes).map_err(|_| AdapterError::FeePolicyNotInstalled)?;
        if policy.context != current_context || policy != *self.config.paid_fee_policy() {
            return Err(AdapterError::FeePolicyMismatch.into());
        }
        let encoded = execution::paid_execution::encode_paid_fee_policy(&policy)
            .map_err(|_| AdapterError::FeePolicyNotInstalled)?;
        if encoded != bytes {
            return Err(AdapterError::FeePolicyNotInstalled.into());
        }
        Ok(encoded)
    }

    fn dispatch_query_object(&self, selector: &str) -> Result<Vec<u8>, JsValue> {
        let object_id_bytes =
            decode_hex64_selector(selector).ok_or(AdapterError::InvalidSelector)?;
        let context = self.build_operation_context()?;
        Ok(dispatch::dispatch_query_object(
            &self.engine,
            &context,
            self.config.domain(),
            self.config.chain_id(),
            ObjectId::new(object_id_bytes),
        )
        .map_err(AdapterError::Query)?)
    }

    fn dispatch_query_receipt(&self, selector: &str) -> Result<Vec<u8>, JsValue> {
        let request_id_bytes =
            decode_hex64_selector(selector).ok_or(AdapterError::InvalidSelector)?;
        let request_id =
            RequestId::new(request_id_bytes).map_err(|_| AdapterError::InvalidRequestBody)?;
        let context = self.build_operation_context()?;
        Ok(dispatch::dispatch_query_request_receipt(
            &self.engine,
            &context,
            self.config.domain(),
            request_id,
        )
        .map_err(AdapterError::Query)?)
    }

    fn dispatch_query_next_nonce(&self, selector: &str) -> Result<Vec<u8>, JsValue> {
        let sender = decode_hex64_selector(selector).ok_or(AdapterError::InvalidSelector)?;
        let context = self.build_operation_context()?;
        let current_epoch = self.require_current_committed_epoch(&context)?;
        Ok(dispatch::dispatch_query_sender_next_nonce(
            &self.engine,
            &context,
            self.config.domain(),
            self.config.chain_id().clone(),
            self.config.protocol_version(),
            current_epoch,
            sender,
        )
        .map_err(AdapterError::Query)?)
    }

    fn dispatch_query_publication(&self, selectors: &str) -> Result<Vec<u8>, JsValue> {
        let (publisher, seed) =
            decode_two_hex64_segments(selectors).ok_or(AdapterError::InvalidSelector)?;
        let origin = abi::package_types::PackageOrigin::unverified(
            self.config.chain_id().clone(),
            publisher,
            seed,
        )
        .map_err(|_| AdapterError::InvalidSelector)?;
        let context = self.build_operation_context()?;
        let result = node_core::publication::query_publication_with_history(
            &self.engine,
            &context,
            self.config.domain(),
            &self.resolver,
            &[],
            &origin,
        )
        .map_err(|_| AdapterError::OperationContext("publication query".to_owned()))?;
        let record = result.ok_or(AdapterError::PublicationNotFound)?;
        node_core::publication::encode_publication_query_result(&record).map_err(|_| {
            AdapterError::OperationContext("publication result encoding".to_owned()).into()
        })
    }

    fn dispatch_query_instance(&self, selectors: &str) -> Result<Vec<u8>, JsValue> {
        let (creator, seed) =
            decode_two_hex64_segments(selectors).ok_or(AdapterError::InvalidSelector)?;
        let context = self.build_operation_context()?;
        let result = node_core::local_execution::query_local_instance(
            &self.engine,
            &context,
            self.config.domain(),
            &self.resolver,
            &[],
            self.config.chain_id(),
            creator,
            seed,
        )
        .map_err(|_| AdapterError::OperationContext("instance query".to_owned()))?;
        let record = result.ok_or(AdapterError::InstanceNotFound)?;
        execution::local_execution::encode_instance_record(&record).map_err(|_| {
            AdapterError::OperationContext("instance result encoding".to_owned()).into()
        })
    }

    fn dispatch_fastvote_prepare(&self, body: &[u8]) -> Result<Vec<u8>, JsValue> {
        if !self.genesis_confirmed.get() {
            return Err(AdapterError::GenesisNotInstalled.into());
        }
        // Authenticate the exact signed bytes against their own declared
        // chain/protocol/epoch BEFORE any clock read, correlation-id
        // allocation, or storage access -- matching
        // `crates/native-http/src/fastvote.rs::submit_prepare`'s own
        // documented ordering exactly. `fast_path::prepare` still
        // re-authenticates and re-fences internally; this pre-check only
        // rejects a malformed/wrong-context/badly signed request before
        // any of that I/O, never replaces it.
        let signed =
            decode_signed_paid_intent(body).map_err(|_| AdapterError::InvalidRequestBody)?;
        let expected = PublicationContext::new(
            self.config.chain_id().clone(),
            self.config.protocol_version(),
            signed.intent.context.epoch(),
        )
        .map_err(|_| AdapterError::InvalidRequestBody)?;
        if let Err(error) = authenticate_paid_execution(&self.resolver, &expected, body) {
            let (status, code) = categorize_admission_error(&error);
            return Err(AdapterError::FastPath(status, code).into());
        }
        let base_policy = LocalExecutionPolicy::generic_object_results(expected.clone());
        let context = self.build_operation_context()?;
        let engine = LocalWasmExecutionEngine::new();
        let vote = fast_path::prepare(
            &self.engine,
            &self.blobs,
            &context,
            self.config.domain(),
            &self.resolver,
            &[],
            &expected,
            &base_policy,
            self.config.paid_fee_policy(),
            &engine,
            &self.signer,
            body,
            self.config.created_checkpoint(),
        )
        .map_err(|error| {
            let (status, code) = categorize_fast_path_error(&error);
            AdapterError::FastPath(status, code)
        })?;
        encode_fast_vote(&vote).map_err(|_| AdapterError::InvalidRequestBody.into())
    }

    fn dispatch_fastvote_apply(&self, body: &[u8]) -> Result<Vec<u8>, JsValue> {
        if !self.genesis_confirmed.get() {
            return Err(AdapterError::GenesisNotInstalled.into());
        }
        let request =
            FastVoteApplyRequest::decode(body).map_err(|_| AdapterError::InvalidRequestBody)?;
        // Same authenticate-before-clock/identity/storage ordering as
        // `dispatch_fastvote_prepare`, matching
        // `crates/native-http/src/fastvote.rs::submit_apply` exactly.
        // `fast_path::apply_with_recovery` reconciles the exact receipt
        // first internally, so a historical request still replays
        // correctly even if the epoch has since advanced; this pre-check
        // never reorders that.
        let signed = decode_signed_paid_intent(&request.signed_paid_intent)
            .map_err(|_| AdapterError::InvalidRequestBody)?;
        let expected = PublicationContext::new(
            self.config.chain_id().clone(),
            self.config.protocol_version(),
            signed.intent.context.epoch(),
        )
        .map_err(|_| AdapterError::InvalidRequestBody)?;
        if let Err(error) =
            authenticate_paid_execution(&self.resolver, &expected, &request.signed_paid_intent)
        {
            let (status, code) = categorize_admission_error(&error);
            return Err(AdapterError::FastPath(status, code).into());
        }
        let base_policy = LocalExecutionPolicy::generic_object_results(expected.clone());
        let context = self.build_operation_context()?;
        let engine = LocalWasmExecutionEngine::new();
        let output = fast_path::apply_with_recovery(
            &self.engine,
            &self.blobs,
            &context,
            self.config.domain(),
            &self.resolver,
            &[],
            &expected,
            &base_policy,
            self.config.paid_fee_policy(),
            &engine,
            &request.signed_paid_intent,
            &request.certificate,
            self.config.created_checkpoint(),
        )
        .map_err(|error| {
            let (status, code) = categorize_fast_path_error(&error);
            AdapterError::FastPath(status, code)
        })?;
        let request_id = RequestId::new(signed.intent.request_id)
            .map_err(|_| AdapterError::InvalidRequestBody)?;
        let result = HttpNodeResult::new(request_id, output.responses().to_vec())
            .map_err(|_| AdapterError::InvalidRequestBody)?;
        result
            .encode()
            .map_err(|_| AdapterError::InvalidRequestBody.into())
    }
}
