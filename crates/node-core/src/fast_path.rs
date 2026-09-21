//! DR-0130 phase 1: certified paid `Call` execution with durable prepare
//! locks/vote and certificate apply.
//!
//! This is the node-core wiring for `consensus::FastPathCertifier`
//! (DR-0129's "phase 0" canonical vote/certificate library, which has no
//! `node-core` dependency or durable persistence of its own). Two entry
//! points, [`prepare`] and [`apply`], both call
//! [`paid_execution::build_paid_admission`] -- the exact same admission and
//! execution pipeline [`paid_execution::handle_paid_execution`] (the
//! ordinary direct commit path) uses -- so a fast-path request is admitted
//! and executed identically to a direct one; neither this module nor the
//! direct path duplicates that pipeline.
//!
//! Phase 1 scope, deliberately narrow:
//!
//! * Only [`execution::paid_execution::PaidApplication::Call`] over
//!   sender-owned objects (already a structural invariant of
//!   [`paid_execution::build_paid_admission`], not special-cased here) takes
//!   the fast path. `Instantiate` and `Publish` fail closed in both
//!   [`prepare`] and [`apply`].
//! * [`prepare`] authenticates, admits and executes exactly like a direct
//!   commit, but only asserts the current sender nonce and commits a durable
//!   sender/epoch nonce lock, one
//!   [`records::FastPathPreparedRecord`], and one exclusive
//!   [`local_instance_state::FastPathLockRecord`] per input object
//!   (including the fee source). It never applies object or application
//!   state effects and never writes the final user receipt.
//! * [`apply`] requires that local prepared record, verifies a
//!   [`consensus::FastCertificate`] against the durably installed static
//!   validator set ([`install_validator_set`]) and the exact commitment
//!   [`prepare`] voted on, re-runs the identical admission/execution
//!   pipeline in a mode that verifies the prepared nonce lock, and
//!   atomically applies every object/application effect plus the final
//!   receipt, a [`records::FastPathCertificateRecord`], a
//!   [`records::FastPathSettlementRecord`], and every lock delete, in one
//!   commit. A certificate/final record that already exists returns the
//!   exact final receipt idempotently, without re-executing.
//! * Locks have no expiry in phase 1: the only way to release one is a
//!   successful [`apply`] of the same request. A prepared request whose
//!   certificate can never be formed, or whose durably re-derived
//!   commitment no longer matches what was voted on, stays locked; there is
//!   no rollback or timeout mechanism in this phase.
//!
//! Production installation is part of the closed, signed
//! [`genesis::GenesisManifest`]; the crate-private [`install_validator_set`]
//! helper exists only for focused tests. Nothing here accepts an unsigned
//! operator-memory validator set as consensus authority.
//!
//! `FastPathError` mirrors `paid_execution::PaidExecutionAdmissionError`'s
//! own shape (a thin wrapper around each layer's own error type); like that
//! type, it is not boxed, consistent with this crate's one existing
//! `clippy::result_large_err` precedent
//! (`crates/node-core/tests/local_inventory.rs`).
#![allow(clippy::result_large_err)]
use super::*;
use canonical_encoding::{decode_digest32, encode_digest32};
use consensus::{ConsensusError, ConsensusSigner, ConsensusVerifier, FastCertificate, FastVote};
use crypto::{Ed25519Verifier, SignatureVerifier};
use execution::local_execution::{CreatedObjectAuthority, LocalExecutionPolicy};
use execution::paid_execution::{PaidApplication, PaidContractEngine, PaidFeePolicy};
use execution::publication::{
    PublicationContext, decode_publication_context, encode_publication_context,
};
use local_instance_state::{
    FastPathLockRecord, FastPathNonceLockRecord, encode_fastpath_lock_record,
    encode_fastpath_nonce_lock_record, fastpath_certificate_key, fastpath_lock_key,
    fastpath_nonce_lock_key, fastpath_prepared_record_key, fastpath_settlement_key,
    fastpath_synthetic_prepare_request_id, fastpath_validator_set_key,
};
use paid_execution::{
    NonceMode, PaidAdmissionOutput, PaidExecutionAdmissionError, authenticate_and_identify,
    build_paid_admission,
};
use protocol_types::{SignatureSchemeId, ValidatorId};
use validator_set::{ValidatorInfo, ValidatorSet, ValidatorSetError};

mod commitment;
pub mod records;

#[cfg(test)]
mod tests;

pub use records::{
    FastPathCertificateRecord, FastPathPreparedRecord, FastPathSettlementRecord,
    FastPathValidatorEntry, FastPathValidatorSetRecord,
};

/// Fail-closed DR-0130 fast-path errors.
#[derive(Debug)]
pub enum FastPathError {
    /// Shared admission/execution pipeline failure.
    Admission(PaidExecutionAdmissionError),
    /// `consensus::FastPathCertifier` vote/certificate failure.
    Consensus(ConsensusError),
    /// Storage or node boundary failure.
    Node(NodeCoreError),
    /// Fast-path-specific invariant failed.
    Invalid(&'static str),
}
impl fmt::Display for FastPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => error.fmt(f),
            Self::Consensus(error) => error.fmt(f),
            Self::Node(error) => error.fmt(f),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}
impl Error for FastPathError {}
impl From<PaidExecutionAdmissionError> for FastPathError {
    fn from(error: PaidExecutionAdmissionError) -> Self {
        Self::Admission(error)
    }
}
impl From<ConsensusError> for FastPathError {
    fn from(error: ConsensusError) -> Self {
        Self::Consensus(error)
    }
}
impl From<NodeCoreError> for FastPathError {
    fn from(error: NodeCoreError) -> Self {
        Self::Node(error)
    }
}
impl From<DurableReadError> for FastPathError {
    fn from(error: DurableReadError) -> Self {
        Self::Node(error.into())
    }
}
impl From<RuntimeError> for FastPathError {
    fn from(error: RuntimeError) -> Self {
        Self::Node(error.into())
    }
}
impl From<DurableInvocationError> for FastPathError {
    fn from(error: DurableInvocationError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalEncodingError> for FastPathError {
    fn from(error: CanonicalEncodingError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalDecodingError> for FastPathError {
    fn from(error: CanonicalDecodingError) -> Self {
        Self::Node(NodeCoreError::CanonicalDecoding(error))
    }
}
impl From<HashingError> for FastPathError {
    fn from(error: HashingError) -> Self {
        Self::Node(error.into())
    }
}
impl From<ValidatorSetError> for FastPathError {
    fn from(error: ValidatorSetError) -> Self {
        Self::Node(NodeCoreError::PersistenceInvariant(match error {
            ValidatorSetError::Empty => "fast-path validator set empty",
            ValidatorSetError::TooManyValidators(_) => "fast-path validator set too large",
            ValidatorSetError::ZeroVotingPower(_) => "fast-path validator zero voting power",
            ValidatorSetError::EmptyPublicKey(_) => "fast-path validator empty public key",
            ValidatorSetError::PublicKeyTooLarge { .. } => {
                "fast-path validator public key too large"
            }
            ValidatorSetError::DuplicateValidator(_) => "fast-path duplicate validator",
            ValidatorSetError::VotingPowerOverflow => "fast-path voting power overflow",
            ValidatorSetError::CanonicalEncoding(_) => "fast-path validator set encoding",
            ValidatorSetError::Hashing(_) => "fast-path validator set hashing",
        }))
    }
}

type FastPathResult<T> = Result<T, FastPathError>;

fn invalid<T>(message: &'static str) -> FastPathResult<T> {
    Err(FastPathError::Invalid(message))
}

/// Phase 1 gate: only `Call` takes the fast path.
fn require_call(application: &PaidApplication) -> FastPathResult<()> {
    match application {
        PaidApplication::Call(_) => Ok(()),
        PaidApplication::Instantiate(_) | PaidApplication::Publish(_) => {
            invalid("fast path phase 1 supports only PaidApplication::Call")
        }
    }
}

/// A [`ConsensusVerifier`] backed by the pinned Ed25519 verifier. Phase 1's
/// durable validator set is restricted to Ed25519 members
/// ([`install_validator_set`]); any other scheme fails closed here too, as
/// defense in depth.
#[derive(Clone, Copy, Debug, Default)]
pub struct FastPathEd25519Verifier;

impl ConsensusVerifier for FastPathEd25519Verifier {
    fn verify_framed(
        &self,
        _validator: ValidatorId,
        scheme: SignatureSchemeId,
        public_key: &[u8],
        framed: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        if scheme != SignatureSchemeId::Ed25519 {
            return Err("fast-path phase 1 supports only Ed25519".to_string());
        }
        let verifier: Ed25519Verifier = Ed25519Verifier::from_verifying_key_bytes(public_key)
            .map_err(|error| error.to_string())?;
        verifier
            .verify_framed(framed, signature)
            .map_err(|error| error.to_string())
    }
}

fn load_validator_set<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    validator_context: &PublicationContext,
) -> FastPathResult<ValidatorSet> {
    let key: Vec<u8> = fastpath_validator_set_key(validator_context)?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    let bytes: &[u8] = observed.value().ok_or(FastPathError::Invalid(
        "fast-path validator set not installed",
    ))?;
    let record: FastPathValidatorSetRecord = records::decode_fastpath_validator_set_record(bytes)?;
    if record.context != *validator_context {
        return invalid("fast-path validator set context mismatch");
    }
    let mut info: Vec<ValidatorInfo> = Vec::with_capacity(record.validators.len());
    for validator in &record.validators {
        if validator.signature_scheme != SignatureSchemeId::Ed25519 {
            return invalid("fast-path validator set supports only Ed25519");
        }
        info.push(ValidatorInfo {
            id: validator.id,
            voting_power: validator.voting_power,
            signature_scheme: validator.signature_scheme,
            public_key: validator.public_key.clone(),
        });
    }
    Ok(ValidatorSet::new(validator_context.epoch(), info)?)
}

/// Strict test helper: idempotent for byte-identical validators and fail
/// closed on a conflicting reinstall. Production installation is atomic with
/// the signed [`genesis::GenesisManifest`].
#[cfg(test)]
pub(crate) fn install_validator_set<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    validator_context: PublicationContext,
    validators: Vec<FastPathValidatorEntry>,
) -> FastPathResult<()> {
    let info: Vec<ValidatorInfo> = validators
        .iter()
        .map(|validator| {
            if validator.signature_scheme != SignatureSchemeId::Ed25519 {
                return Err(FastPathError::Invalid(
                    "fast-path validator set supports only Ed25519",
                ));
            }
            Ok(ValidatorInfo {
                id: validator.id,
                voting_power: validator.voting_power,
                signature_scheme: validator.signature_scheme,
                public_key: validator.public_key.clone(),
            })
        })
        .collect::<FastPathResult<Vec<ValidatorInfo>>>()?;
    // Structural validation only (bounds, no duplicates, no zero power/keys);
    // the resulting `ValidatorSet` is not itself persisted, only used to
    // prove these durable bytes are actually usable by `FastPathCertifier`.
    let _: ValidatorSet = ValidatorSet::new(validator_context.epoch(), info)?;

    let record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
        context: validator_context.clone(),
        validators,
    };
    let bytes: Vec<u8> = records::encode_fastpath_validator_set_record(&record)?;
    let key: Vec<u8> = fastpath_validator_set_key(&validator_context)?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if let Some(existing) = observed.value() {
        return if existing == bytes.as_slice() {
            Ok(())
        } else {
            invalid("fast-path validator set already installed with different bytes")
        };
    }
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![StateReadAssertion::new(
            key.clone(),
            observed.revision(),
        )?])?,
        AtomicStateMutationSet::new(vec![StateMutationEntry::new(
            key,
            StateMutation::Put(bytes),
        )?])?,
    )?;
    match store.commit_durable(context, transaction) {
        DurableCommitOutcome::Committed => Ok(()),
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::Conflict { .. }
            | DurableCommitRejection::RequestAlreadyCommitted,
        ) => Err(FastPathError::Node(NodeCoreError::StateConflict)),
        DurableCommitOutcome::Rejected(reason) => Err(FastPathError::Node(
            NodeCoreError::DurableCommitRejected(reason),
        )),
        DurableCommitOutcome::Indeterminate(reason) => Err(FastPathError::Node(
            NodeCoreError::DurableCommitIndeterminate(reason),
        )),
    }
}

/// Authenticates, admits, executes and durably commits one fast-path
/// prepare: an exact sender-nonce assertion and lock, one
/// [`records::FastPathPreparedRecord`]
/// and one exclusive lock per input object. Returns the cast
/// [`consensus::FastVote`] for `(signed_intent_digest, commitment)`; exact
/// replay of the same request id and signed bytes returns the identical
/// stored vote without re-executing anything. A conflicting replay, an
/// `Instantiate`/`Publish` application, or an input locked by a different
/// request id all fail closed and write nothing.
#[allow(clippy::too_many_arguments)]
pub fn prepare<S, E, C>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    base_policy: &LocalExecutionPolicy,
    fee_policy: &PaidFeePolicy,
    engine: &E,
    signer: &C,
    signed_bytes: &[u8],
    created_checkpoint: u64,
) -> FastPathResult<FastVote>
where
    S: StructuredDurableDomainStateStore,
    E: PaidContractEngine + ?Sized,
    C: ConsensusSigner,
{
    if history.len() > publication::MAX_PUBLICATION_HISTORY {
        return invalid("resolver history bound");
    }
    let (authenticated, event_digest, request_id) =
        authenticate_and_identify(resolver, expected, signed_bytes)?;
    require_call(&authenticated.intent().application)?;
    let chain: ChainId = authenticated.intent().context.chain_id().clone();
    let intent_context: PublicationContext = authenticated.intent().context.clone();
    let original_request_id: [u8; 32] = authenticated.intent().request_id;
    let sender: [u8; 32] = authenticated.intent().sender;
    let pending_nonce: u64 = authenticated.intent().nonce;

    // Reconcile an existing prepared record before any nonce, policy or
    // object read: exact replay returns the stored vote unchanged, and a
    // conflicting replay (a different request digest under the same
    // request id) fails closed here, before anything else is touched.
    let prepared_key: Vec<u8> = fastpath_prepared_record_key(&chain, &original_request_id)?;
    let observed_prepared: VersionedStateValue =
        store.get_versioned_durable(context, domain, &prepared_key)?;
    if let Some(bytes) = observed_prepared.value() {
        let existing: FastPathPreparedRecord = records::decode_fastpath_prepared_record(bytes)?;
        if existing.signed_intent_digest != event_digest {
            return invalid("conflicting fast-path prepared record");
        }
        if existing.context != intent_context
            || existing.request_id != original_request_id
            || existing.pending_nonce != pending_nonce
        {
            return invalid("fast-path prepared replay metadata mismatch");
        }
        let vote: FastVote = consensus::decode_fast_vote(&existing.vote)?;
        if vote.chain_id != chain
            || vote.protocol_version != intent_context.protocol_version()
            || vote.epoch != intent_context.epoch()
            || vote.tx_hash != event_digest
            || vote.execution_effects_hash != existing.commitment
            || vote.validator != signer.validator_id()
            || vote.signature_scheme != signer.signature_scheme()
        {
            return invalid("fast-path prepared replay vote mismatch");
        }
        let validator_set: ValidatorSet =
            load_validator_set(store, context, domain, &intent_context)?;
        let certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
            chain.clone(),
            intent_context.protocol_version(),
            intent_context.epoch(),
            validator_set,
        )?;
        certifier.verify_vote(&vote, &FastPathEd25519Verifier)?;
        return Ok(vote);
    }

    // A request that already finalized through the ordinary paid path must
    // not be prepared after the fact. Reconcile this before nonce, policy,
    // module, object or engine work so a conflicting request-id reuse keeps
    // the existing fail-closed error and an exact direct-path replay never
    // creates fast-path locks for an already committed transaction.
    if durable_reconciliation::reconcile_receipt(store, context, domain, request_id, event_digest)?
        .is_some()
    {
        return invalid("paid intent already finalized outside the fast path");
    }

    let validator_set: ValidatorSet = load_validator_set(store, context, domain, &intent_context)?;
    let certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        chain.clone(),
        intent_context.protocol_version(),
        intent_context.epoch(),
        validator_set,
    )?;

    let admission: PaidAdmissionOutput = build_paid_admission(
        store,
        blob_store,
        context,
        domain,
        resolver,
        history,
        base_policy,
        fee_policy,
        engine,
        authenticated,
        event_digest,
        created_checkpoint,
        NonceMode::Fresh,
    )?;

    let pending_nonce_write: &PendingSenderNonceWrite =
        admission
            .nonce_write
            .as_ref()
            .ok_or(FastPathError::Invalid(
                "fast-path prepare always reserves a fresh nonce",
            ))?;
    let pending_nonce_bytes: Vec<u8> = pending_nonce_write.record.encode()?;
    let commitment: Digest32 = commitment::compute(
        resolver,
        intent_context.epoch(),
        admission.event_digest,
        &admission.result_bytes,
        &admission.outcome.created_authorities,
        &admission.head_reads,
        &admission.object_mutations,
        &admission.reads,
        &admission.state_mutations,
        &pending_nonce_write.key,
        pending_nonce_write.read_revision,
        &pending_nonce_bytes,
    )?;

    let vote: FastVote = certifier.cast_vote(event_digest, commitment, signer)?;
    let vote_bytes: Vec<u8> = consensus::encode_fast_vote(&vote)?;

    let nonce: PendingSenderNonceWrite = admission.nonce_write.ok_or(FastPathError::Invalid(
        "fast-path prepare always reserves a fresh nonce",
    ))?;

    let prepared_record: FastPathPreparedRecord = FastPathPreparedRecord {
        context: intent_context.clone(),
        request_id: original_request_id,
        signed_intent_digest: event_digest,
        commitment,
        vote: vote_bytes,
        locked_objects: admission.locked_objects.clone(),
        pending_nonce,
        created_checkpoint,
    };
    let prepared_bytes: Vec<u8> = records::encode_fastpath_prepared_record(&prepared_record)?;

    // Assemble the prepare-only commit: an assertion over the unchanged
    // ordinary nonce row, its sender/epoch lock, one lock per
    // input object (their absence was already proven by
    // `build_paid_admission`'s own lock-ownership reads, reused here as the
    // CAS precondition for each lock write) and the prepared record. Every
    // other staged mutation `build_paid_admission` computed (object/
    // application effects) fed only the commitment above and is discarded
    // here: prepare never applies them.
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = admission.reads;
    reads.insert(nonce.key.clone(), nonce.read_revision);
    reads.insert(prepared_key.clone(), observed_prepared.revision());
    let mut mutations: Vec<StateMutationEntry> = Vec::new();
    let nonce_lock_key: Vec<u8> = fastpath_nonce_lock_key(&chain, &sender, intent_context.epoch())?;
    let nonce_lock: FastPathNonceLockRecord = FastPathNonceLockRecord {
        request_id: original_request_id,
        sender,
        epoch: intent_context.epoch(),
        nonce: pending_nonce,
    };
    mutations.push(StateMutationEntry::new(
        nonce_lock_key,
        StateMutation::Put(encode_fastpath_nonce_lock_record(&nonce_lock)?),
    )?);
    for object in &admission.locked_objects {
        let lock_key: Vec<u8> = fastpath_lock_key(&chain, object.id)?;
        let lock: FastPathLockRecord = FastPathLockRecord {
            request_id: original_request_id,
            object: object.clone(),
        };
        mutations.push(StateMutationEntry::new(
            lock_key,
            StateMutation::Put(encode_fastpath_lock_record(&lock)?),
        )?);
    }
    mutations.push(StateMutationEntry::new(
        prepared_key,
        StateMutation::Put(prepared_bytes),
    )?);

    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<_, RuntimeError>>()?;
    let state: DurableStateTransaction =
        DurableStateTransaction::new(domain, AtomicStateReadSet::new(assertions)?, mutations)?;

    let synthetic_id: [u8; 32] = fastpath_synthetic_prepare_request_id(
        resolver,
        intent_context.epoch(),
        &original_request_id,
    )?;
    let synthetic_receipt_payload: NodeDedupRecord =
        NodeDedupRecord::new(RequestId::new(synthetic_id)?, commitment, Vec::new())?;
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new(synthetic_id)
            .map_err(|_| FastPathError::Invalid("synthetic prepare receipt id"))?,
        commitment,
        synthetic_receipt_payload.encode()?,
    )?;
    let transaction: DurableInvocationTransaction = DurableInvocationTransaction::new(
        domain,
        Some(state),
        DurableObjectChanges::new(admission.head_reads, Vec::new())?,
        receipt,
        None,
    )?;
    match store.commit_invocation(context, transaction) {
        DurableCommitOutcome::Committed => Ok(vote),
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::Conflict { .. }
            | DurableCommitRejection::RequestAlreadyCommitted,
        ) => Err(FastPathError::Node(NodeCoreError::StateConflict)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ObjectConflict {
            object_id,
            ..
        }) => Err(FastPathError::Node(NodeCoreError::ObjectConflict {
            object_id,
        })),
        DurableCommitOutcome::Rejected(reason) => Err(FastPathError::Node(
            NodeCoreError::DurableCommitRejected(reason),
        )),
        DurableCommitOutcome::Indeterminate(reason) => Err(FastPathError::Node(
            NodeCoreError::DurableCommitIndeterminate(reason),
        )),
    }
}

/// Requires a local prepared record, verifies `certificate_bytes` against
/// the durable validator set and the exact locally derived commitment, then
/// re-runs the identical admission/execution pipeline (recognizing the
/// nonce lock installed by prepare) and atomically applies every effect,
/// the final receipt, a [`records::FastPathCertificateRecord`], a
/// [`records::FastPathSettlementRecord`] and every lock delete. If the
/// final receipt already exists (a prior apply, direct commit under the
/// same request id, or a duplicate/reordered certificate for the same
/// request) it is returned unchanged without re-executing anything.
///
/// `created_checkpoint` is only sanity-checked against the checkpoint
/// [`prepare`] originally bound on [`records::FastPathPreparedRecord`]; the
/// admission and commitment re-derivation below always use that prepared
/// value, never this fresh one, so a later apply observing a higher
/// (chain-progressed) checkpoint cannot change the recomputed commitment out
/// from under an already-cast vote.
#[allow(clippy::too_many_arguments)]
pub fn apply<S, E>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    base_policy: &LocalExecutionPolicy,
    fee_policy: &PaidFeePolicy,
    engine: &E,
    signed_bytes: &[u8],
    certificate_bytes: &[u8],
    created_checkpoint: u64,
) -> FastPathResult<NodeOutput>
where
    S: StructuredDurableDomainStateStore,
    E: PaidContractEngine + ?Sized,
{
    if history.len() > publication::MAX_PUBLICATION_HISTORY {
        return invalid("resolver history bound");
    }
    let (authenticated, event_digest, request_id) =
        authenticate_and_identify(resolver, expected, signed_bytes)?;
    require_call(&authenticated.intent().application)?;
    if let Some(output) =
        durable_reconciliation::reconcile_receipt(store, context, domain, request_id, event_digest)?
    {
        return Ok(output);
    }

    let chain: ChainId = authenticated.intent().context.chain_id().clone();
    let intent_context: PublicationContext = authenticated.intent().context.clone();
    let original_request_id: [u8; 32] = authenticated.intent().request_id;
    let intent_sender: [u8; 32] = authenticated.intent().sender;
    let intent_nonce: u64 = authenticated.intent().nonce;

    let prepared_key: Vec<u8> = fastpath_prepared_record_key(&chain, &original_request_id)?;
    let observed_prepared: VersionedStateValue =
        store.get_versioned_durable(context, domain, &prepared_key)?;
    let prepared: FastPathPreparedRecord = records::decode_fastpath_prepared_record(
        observed_prepared
            .value()
            .ok_or(FastPathError::Invalid("no local fast-path prepared record"))?,
    )?;
    if prepared.signed_intent_digest != event_digest {
        return invalid("fast-path prepared record does not match signed bytes");
    }
    if prepared.context != intent_context
        || prepared.request_id != original_request_id
        || prepared.pending_nonce != intent_nonce
    {
        return invalid("fast-path prepared record metadata mismatch");
    }
    // `created_checkpoint` is not bound in the signed intent: it is trusted
    // node composition (chain-progress) input, not caller intent, and it
    // naturally advances between prepare and a later apply. The commitment
    // `prepare` voted on was derived using prepare's own checkpoint value,
    // folded into every created object version record; apply must reuse
    // that exact value below, not the caller's fresh one, or it re-derives
    // a different commitment and rejects its own matching certificate
    // permanently (phase 1 has no lock rollback or timeout). The caller's
    // value is only sanity-checked here for the non-decreasing invariant
    // every `created_checkpoint` caller must already uphold.
    if created_checkpoint < prepared.created_checkpoint {
        return invalid("fast-path apply checkpoint regressed below the prepared checkpoint");
    }

    let certificate: FastCertificate = consensus::decode_fast_certificate(certificate_bytes)?;
    let validator_set: ValidatorSet = load_validator_set(store, context, domain, &intent_context)?;
    let certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        chain.clone(),
        intent_context.protocol_version(),
        intent_context.epoch(),
        validator_set,
    )?;
    certifier.verify_certificate(&certificate, &FastPathEd25519Verifier)?;
    if certificate.chain_id != chain
        || certificate.protocol_version != intent_context.protocol_version()
        || certificate.epoch != intent_context.epoch()
        || certificate.tx_hash != event_digest
        || certificate.execution_effects_hash != prepared.commitment
    {
        return invalid("fast-path certificate does not match the locally prepared commitment");
    }

    let admission: PaidAdmissionOutput = build_paid_admission(
        store,
        blob_store,
        context,
        domain,
        resolver,
        history,
        base_policy,
        fee_policy,
        engine,
        authenticated,
        event_digest,
        prepared.created_checkpoint,
        NonceMode::PreparedApply,
    )?;
    if admission.locked_objects != prepared.locked_objects {
        return invalid("fast-path prepared lock set mismatch");
    }

    // Final, independent binding: the commitment re-derived from *this*
    // fresh admission run must still equal what the certificate attests to.
    // If Phase 1's exclusive locks somehow failed to keep the underlying
    // state frozen since prepare, this fails closed rather than applying
    // effects that were never actually certified; the request's locks stay
    // held (Phase 1 has no rollback or expiry) rather than silently
    // diverging from the certified outcome.
    let pending_nonce_write: &PendingSenderNonceWrite =
        admission
            .nonce_write
            .as_ref()
            .ok_or(FastPathError::Invalid(
                "fast-path apply must advance the prepared nonce",
            ))?;
    let pending_nonce_bytes: Vec<u8> = pending_nonce_write.record.encode()?;
    let fresh_commitment: Digest32 = commitment::compute(
        resolver,
        intent_context.epoch(),
        admission.event_digest,
        &admission.result_bytes,
        &admission.outcome.created_authorities,
        &admission.head_reads,
        &admission.object_mutations,
        &admission.reads,
        &admission.state_mutations,
        &pending_nonce_write.key,
        pending_nonce_write.read_revision,
        &pending_nonce_bytes,
    )?;
    if fresh_commitment != prepared.commitment {
        return invalid("fast-path re-derived commitment no longer matches the certificate");
    }

    let PaidAdmissionOutput {
        result_bytes,
        success,
        reads: admission_reads,
        head_reads,
        state_mutations: mut mutations,
        object_mutations,
        outcome,
        nonce_write,
        ..
    } = admission;

    let mut reads: BTreeMap<Vec<u8>, StateRevision> = admission_reads;
    reads.insert(prepared_key, observed_prepared.revision());

    let nonce: PendingSenderNonceWrite = nonce_write.ok_or(FastPathError::Invalid(
        "fast-path apply must advance the prepared nonce",
    ))?;
    reads.insert(nonce.key.clone(), nonce.read_revision);
    mutations.push(StateMutationEntry::new(
        nonce.key,
        StateMutation::Put(nonce.record.encode()?),
    )?);
    let nonce_lock_key: Vec<u8> =
        fastpath_nonce_lock_key(&chain, &intent_sender, intent_context.epoch())?;
    if !reads.contains_key(&nonce_lock_key) {
        return invalid("fast-path apply missing nonce-lock read");
    }
    mutations.push(StateMutationEntry::new(
        nonce_lock_key,
        StateMutation::Delete,
    )?);

    for object in &prepared.locked_objects {
        let lock_key: Vec<u8> = fastpath_lock_key(&chain, object.id)?;
        // Read already present from this admission's own lock-ownership
        // check; reused as the CAS precondition for the delete below.
        if !reads.contains_key(&lock_key) {
            return invalid("fast-path apply missing lock read for a locked object");
        }
        mutations.push(StateMutationEntry::new(lock_key, StateMutation::Delete)?);
    }

    let certificate_key: Vec<u8> = fastpath_certificate_key(&chain, &original_request_id)?;
    let observed_certificate: VersionedStateValue =
        store.get_versioned_durable(context, domain, &certificate_key)?;
    if observed_certificate.value().is_some() {
        return invalid("fast-path certificate record already exists");
    }
    reads.insert(certificate_key.clone(), observed_certificate.revision());
    let certificate_record: FastPathCertificateRecord = FastPathCertificateRecord {
        request_id: original_request_id,
        certificate: certificate_bytes.to_vec(),
    };
    mutations.push(StateMutationEntry::new(
        certificate_key,
        StateMutation::Put(records::encode_fastpath_certificate_record(
            &certificate_record,
        )?),
    )?);

    let settlement_key: Vec<u8> = fastpath_settlement_key(&chain, &original_request_id)?;
    let observed_settlement: VersionedStateValue =
        store.get_versioned_durable(context, domain, &settlement_key)?;
    if observed_settlement.value().is_some() {
        return invalid("fast-path settlement record already exists");
    }
    reads.insert(settlement_key.clone(), observed_settlement.revision());
    let settlement_record: FastPathSettlementRecord = FastPathSettlementRecord {
        request_id: original_request_id,
        fee_output: outcome
            .result
            .charged
            .as_ref()
            .map(|charged| charged.fee_output.clone()),
        actual_amount: outcome
            .result
            .charged
            .as_ref()
            .map(|charged| charged.actual.get()),
        signer_ids: certificate
            .votes
            .iter()
            .map(|vote| vote.validator)
            .collect(),
    };
    mutations.push(StateMutationEntry::new(
        settlement_key,
        StateMutation::Put(records::encode_fastpath_settlement_record(
            &settlement_record,
        )?),
    )?);

    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<_, RuntimeError>>()?;
    let state: DurableStateTransaction =
        DurableStateTransaction::new(domain, AtomicStateReadSet::new(assertions)?, mutations)?;
    let output: NodeOutput = NodeOutput::new(
        vec![NodeResponse::new(
            request_id,
            if success {
                NodeResponseStatus::Accepted
            } else {
                NodeResponseStatus::Rejected
            },
            Some(result_bytes),
        )?],
        Vec::new(),
    )?;
    let dedup: NodeDedupRecord =
        NodeDedupRecord::new(request_id, event_digest, output.responses().to_vec())?;
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new(*request_id.as_bytes())
            .map_err(|_| FastPathError::Invalid("request id"))?,
        event_digest,
        dedup.encode()?,
    )?;
    let transaction: DurableInvocationTransaction = DurableInvocationTransaction::new(
        domain,
        Some(state),
        DurableObjectChanges::new(head_reads, object_mutations)?,
        receipt,
        None,
    )?;
    match store.commit_invocation(context, transaction) {
        DurableCommitOutcome::Committed => Ok(output),
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::Conflict { .. }
            | DurableCommitRejection::RequestAlreadyCommitted,
        ) => Err(FastPathError::Node(NodeCoreError::StateConflict)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ObjectConflict {
            object_id,
            ..
        }) => Err(FastPathError::Node(NodeCoreError::ObjectConflict {
            object_id,
        })),
        DurableCommitOutcome::Rejected(reason) => Err(FastPathError::Node(
            NodeCoreError::DurableCommitRejected(reason),
        )),
        DurableCommitOutcome::Indeterminate(reason) => Err(FastPathError::Node(
            NodeCoreError::DurableCommitIndeterminate(reason),
        )),
    }
}
