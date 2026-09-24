//! DR-0132 FastVote Phase 2 Slice 2: the outgoing-set-certified `e -> e+1`
//! epoch transition.
//!
//! [`propose_and_vote`] and [`activate`] are in-process, validator-
//! authorized node-core functions -- the same authorization class as
//! [`crate::fast_path::prepare`]/[`crate::fast_path::apply`] -- with no new
//! externally reachable event family. `next_validators` is operator-supplied
//! but authorized only by the outgoing-set quorum certificate that
//! `propose_and_vote`'s callers independently produce: an operator acting
//! alone cannot change the active set (see "Unresolved risks" in
//! `docs/architecture/decisions/0132-fastvote-epoch-transition.md`).
//!
//! [`FastPathEpochTransitionRecord`] (`0x6427`) is a permanent per-`next_epoch`
//! audit row: the exact verified certificate plus the fields it attests to,
//! kept forever so [`crate::genesis::install_genesis_with_history`]'s
//! restart-verify (DR-0132 §7, correction C1) can re-decode, re-load, and
//! re-verify every historical step rather than trusting a live record that
//! merely changed.
//!
//! [`FastPathEpochActivationSet`] (`0x6428`) is never stored; it exists only
//! as the exact preimage [`activation_digest`](FastPathEpochTransitionRecord::activation_digest)
//! is computed over, both at proposal/activation time
//! ([`derive_activation_set`]) and again, read back from already-installed
//! bytes, at restart-verify time.
#![allow(clippy::result_large_err)]
use super::*;
use crate::economics::{FastPathEconomicsPolicy, decode_fastpath_economics_policy};
use bonds::BondResourceId;
use canonical_encoding::{CanonicalDecodingError, decode_digest32, encode_digest32};
use consensus::{
    ConsensusError, ConsensusSigner, EpochTransitionCertificate, EpochTransitionCertifier,
    EpochTransitionVote, decode_epoch_transition_certificate,
};
use execution::local_execution::{LocalExecutionError, LocalExecutionPolicy};
use execution::paid_execution::{PaidExecutionError, PaidFeePolicy, decode_paid_fee_policy};
use execution::publication::{PublicationContext, PublicationError};
use fast_path::records::{
    FastPathBondRecord, FastPathBondState, FastPathValidatorEntry, FastPathValidatorSetRecord,
    decode_fastpath_bond_record,
};
use fast_path::{FastPathEd25519Verifier, load_validator_set};
use local_instance_state::FastPathEpochRecord;
use protocol_types::SignatureSchemeId;
use publication::{LocalPublicationPolicy, PublicationAdmissionError};
use validator_set::{ValidatorInfo, ValidatorSet, ValidatorSetError};

#[cfg(test)]
pub(crate) mod tests;

const FASTPATH_EPOCH_TRANSITION_RECORD_TYPE: u16 = 0x6427;
const FASTPATH_EPOCH_ACTIVATION_SET_TYPE: u16 = 0x6428;
const ENCODING_VERSION: u16 = 1;

/// Fail-closed DR-0132 epoch-transition errors.
#[derive(Debug)]
pub enum EpochTransitionError {
    /// Storage or node boundary failure.
    Node(NodeCoreError),
    /// `consensus::EpochTransitionCertifier` vote/certificate failure.
    Consensus(ConsensusError),
    /// Outgoing or incoming validator-set construction failed.
    ValidatorSet(ValidatorSetError),
    /// Publication context construction failed.
    Publication(PublicationError),
    /// Publication-policy encoding failed.
    PublicationAdmission(PublicationAdmissionError),
    /// Paid fee policy decode/encode failed.
    PaidExecution(PaidExecutionError),
    /// Local execution policy encode/digest failed.
    LocalExecution(LocalExecutionError),
    /// Epoch-transition-specific invariant failed.
    Invalid(&'static str),
}
impl fmt::Display for EpochTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(error) => error.fmt(f),
            Self::Consensus(error) => error.fmt(f),
            Self::ValidatorSet(error) => error.fmt(f),
            Self::Publication(error) => error.fmt(f),
            Self::PublicationAdmission(error) => error.fmt(f),
            Self::PaidExecution(error) => error.fmt(f),
            Self::LocalExecution(error) => error.fmt(f),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}
impl Error for EpochTransitionError {}
impl From<NodeCoreError> for EpochTransitionError {
    fn from(error: NodeCoreError) -> Self {
        Self::Node(error)
    }
}
impl From<ConsensusError> for EpochTransitionError {
    fn from(error: ConsensusError) -> Self {
        Self::Consensus(error)
    }
}
impl From<ValidatorSetError> for EpochTransitionError {
    fn from(error: ValidatorSetError) -> Self {
        Self::ValidatorSet(error)
    }
}
impl From<PublicationError> for EpochTransitionError {
    fn from(error: PublicationError) -> Self {
        Self::Publication(error)
    }
}
impl From<PublicationAdmissionError> for EpochTransitionError {
    fn from(error: PublicationAdmissionError) -> Self {
        Self::PublicationAdmission(error)
    }
}
impl From<PaidExecutionError> for EpochTransitionError {
    fn from(error: PaidExecutionError) -> Self {
        Self::PaidExecution(error)
    }
}
impl From<LocalExecutionError> for EpochTransitionError {
    fn from(error: LocalExecutionError) -> Self {
        Self::LocalExecution(error)
    }
}
impl From<DurableReadError> for EpochTransitionError {
    fn from(error: DurableReadError) -> Self {
        Self::Node(error.into())
    }
}
impl From<RuntimeError> for EpochTransitionError {
    fn from(error: RuntimeError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalEncodingError> for EpochTransitionError {
    fn from(error: CanonicalEncodingError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalDecodingError> for EpochTransitionError {
    fn from(error: CanonicalDecodingError) -> Self {
        Self::Node(NodeCoreError::CanonicalDecoding(error))
    }
}
impl From<HashingError> for EpochTransitionError {
    fn from(error: HashingError) -> Self {
        Self::Node(error.into())
    }
}
/// `crate::fast_path::load_validator_set` returns `FastPathError`; only its
/// `Consensus`/`Node`/`Invalid` arms are ever actually produced by that
/// function (it never runs paid admission), but the conversion is total.
impl From<fast_path::FastPathError> for EpochTransitionError {
    fn from(error: fast_path::FastPathError) -> Self {
        match error {
            fast_path::FastPathError::Admission(_) => {
                Self::Invalid("unexpected paid-admission error while loading a validator set")
            }
            fast_path::FastPathError::Consensus(error) => Self::Consensus(error),
            fast_path::FastPathError::Node(error) => Self::Node(error),
            fast_path::FastPathError::Invalid(message) => Self::Invalid(message),
        }
    }
}

type EtResult<T> = Result<T, EpochTransitionError>;

fn invalid<T>(message: &'static str) -> EtResult<T> {
    Err(EpochTransitionError::Invalid(message))
}

/// Frame `0x6427/v1`: the permanent per-`next_epoch` audit record of one
/// completed `e -> e+1` transition, keyed by
/// [`local_instance_state::fastpath_epoch_transition_key`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathEpochTransitionRecord {
    /// The outgoing epoch `e`.
    pub from_epoch: Epoch,
    /// The incoming epoch, `e + 1`.
    pub to_epoch: Epoch,
    /// The certified outgoing validator-set digest.
    pub previous_validator_set_digest: Digest32,
    /// The certified incoming validator-set digest.
    pub next_validator_set_digest: Digest32,
    /// The certified activation-write-set digest.
    pub activation_digest: Digest32,
    /// The exact verified [`consensus::EpochTransitionCertificate`] bytes,
    /// kept as a permanent audit trail: C1's restart chain and Phase 3
    /// slashing both read it.
    pub certificate: Vec<u8>,
    /// Local per-node checkpoint marker, the same convention
    /// `GenesisInstallMarker::installed_at_checkpoint` uses. Deliberately
    /// excluded from `activation_digest` and therefore free to diverge
    /// across validators.
    pub activated_at_checkpoint: u64,
}

/// Encodes Frame `0x6427/v1`.
pub fn encode_fastpath_epoch_transition_record(
    record: &FastPathEpochTransitionRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(FASTPATH_EPOCH_TRANSITION_RECORD_TYPE, ENCODING_VERSION);
    frame.field_u64(1, record.from_epoch.get())?;
    frame.field_u64(2, record.to_epoch.get())?;
    frame.field_bytes(3, encode_digest32(&record.previous_validator_set_digest)?)?;
    frame.field_bytes(4, encode_digest32(&record.next_validator_set_digest)?)?;
    frame.field_bytes(5, encode_digest32(&record.activation_digest)?)?;
    frame.field_bytes(6, record.certificate.clone())?;
    frame.field_u64(7, record.activated_at_checkpoint)?;
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x6427/v1`.
pub fn decode_fastpath_epoch_transition_record(
    bytes: &[u8],
) -> Result<FastPathEpochTransitionRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_EPOCH_TRANSITION_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7])?;
    let record: FastPathEpochTransitionRecord = FastPathEpochTransitionRecord {
        from_epoch: Epoch::new(frame.required_u64(1)?),
        to_epoch: Epoch::new(frame.required_u64(2)?),
        previous_validator_set_digest: decode_digest32(frame.required_field(3)?)?,
        next_validator_set_digest: decode_digest32(frame.required_field(4)?)?,
        activation_digest: decode_digest32(frame.required_field(5)?)?,
        certificate: frame.required_field(6)?.to_vec(),
        activated_at_checkpoint: frame.required_u64(7)?,
    };
    if encode_fastpath_epoch_transition_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fast-path epoch transition record",
        ));
    }
    Ok(record)
}

/// Frame `0x6428/v1`: the exact byte-exact activation write set
/// [`FastPathEpochTransitionRecord::activation_digest`] is hashed over.
/// Never durably stored under its own key; either freshly assembled by
/// [`derive_activation_set`] or reconstructed at restart-verify time from
/// the four already-installed rows it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathEpochActivationSet {
    /// `ctx@e+1`.
    pub next_context: PublicationContext,
    /// Exact `0x641F` bytes installed at `ctx@e+1`.
    pub validator_set_record: Vec<u8>,
    /// Exact `LocalExecutionPolicy::generic_object_results(ctx@e+1).encode()` bytes.
    pub execution_policy: Vec<u8>,
    /// Exact re-derived `PaidFeePolicy` bytes installed at `ctx@e+1`.
    pub paid_fee_policy: Vec<u8>,
    /// Exact `LocalPublicationPolicy::object_results(ctx@e+1, ..).encode()` bytes.
    pub publication_policy: Vec<u8>,
}

/// Encodes Frame `0x6428/v1`. There is no corresponding decode function:
/// this frame is a digest preimage only, never itself stored.
pub fn encode_fastpath_epoch_activation_set(
    set: &FastPathEpochActivationSet,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(FASTPATH_EPOCH_ACTIVATION_SET_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        execution::publication::encode_publication_context(&set.next_context).map_err(|_| {
            NodeCoreError::PersistenceInvariant("invalid epoch activation set context")
        })?,
    )?;
    frame.field_bytes(2, set.validator_set_record.clone())?;
    frame.field_bytes(3, set.execution_policy.clone())?;
    frame.field_bytes(4, set.paid_fee_policy.clone())?;
    frame.field_bytes(5, set.publication_policy.clone())?;
    Ok(frame.finish()?)
}

/// The deterministic result of deriving one `e -> e+1` activation set (DR-0132 §3.A).
///
/// Deliberately carries no bond-eligibility information: a certificate that
/// already exists was validly formed (every signer independently ran
/// [`derive_eligibility_reads`] before voting -- see [`propose_and_vote`]),
/// and applying it in [`activate`] must be a pure function of the
/// certificate and this struct's own byte-stable fields, never of live
/// mutable bond state that a concurrent [`crate::bond_lifecycle::slash`]
/// could change between certificate formation and activation. Coupling
/// activation to eligibility would let whether a slash happened to commit
/// first change whether an already-quorum-certified transition applies,
/// which is exactly the divergence DR-0137 unit 3 must not introduce.
#[derive(Debug)]
pub(crate) struct DerivedActivation {
    pub(crate) next_validator_set_digest: Digest32,
    pub(crate) activation_digest: Digest32,
    pub(crate) activation_set: FastPathEpochActivationSet,
    /// The outgoing epoch fee-policy row whose configuration is carried
    /// forward. Activation must CAS-fence this exact revision so a
    /// concurrent policy write cannot be silently copied into `e + 1` from
    /// bytes different from those the certificate committed to.
    pub(crate) current_fee_policy_key: Vec<u8>,
    pub(crate) current_fee_policy_revision: StateRevision,
}

/// Reads the committed economics policy and every `next_validators` row's
/// committed [`FastPathBondRecord`] at `current_epoch`, and requires each
/// entry to be `Active`/live, bound to the exact chain and validator id,
/// committed no later than `current_epoch`, signed with the exact
/// registered authorization scheme/key, and amount-eligible under the
/// current committed policy (the resource enabled, the amount at least the
/// current minimum and at most the current maximum exposure).
///
/// Called from [`propose_and_vote`] alone, strictly before a vote is cast: a
/// candidate failing this check is never voted on, so it can never enter a
/// legitimately quorum-certified `next_validators` set in the first place.
/// [`activate`]/[`derive_activation_set`] deliberately never call this --
/// once a certificate exists, applying it is a pure derivation of the
/// certificate's own bytes (DR-0137 unit 3: "certificate-wins ordering").
/// This is a pure eligibility gate, not a CAS: unlike
/// [`bond_lifecycle::read_economics_policy`], it returns nothing a caller
/// could use to fence a later write against the rows it reads, and no test
/// consumes its local reads either. The local revision map exists purely as
/// bookkeeping while iterating `next_validators` -- each visited bond row's
/// `StateRevision` is recorded once per unique key (duplicate bond/policy
/// keys cannot occur here: `next_validators` was already validated
/// duplicate-free by `ValidatorSet::new` inside [`derive_activation_set`],
/// and `policy_cache` avoids re-fetching a shared resource context) -- and
/// is discarded once this call returns.
fn derive_eligibility_reads<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    current_epoch: Epoch,
    next_validators: &[FastPathValidatorEntry],
) -> EtResult<()> {
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    // Small linear cache keyed by each bond's own genesis-pinned resource
    // context (never the transitioning `current_epoch`'s context, exactly
    // like `bond_lifecycle::read_economics_policy` reads it) -- in practice
    // one entry, since every bond shares one resource context, but a bond
    // cannot be assumed to.
    let mut policy_cache: Vec<(PublicationContext, FastPathEconomicsPolicy)> = Vec::new();

    let mut sorted_validators: Vec<&FastPathValidatorEntry> = next_validators.iter().collect();
    sorted_validators.sort_by_key(|validator| validator.id);
    for validator in sorted_validators {
        let bond_key: Vec<u8> =
            local_instance_state::fastpath_bond_record_key(chain, &validator.id)?;
        let bond_observed: VersionedStateValue =
            store.get_versioned_durable(context, domain, &bond_key)?;
        let bond_bytes: &[u8] = bond_observed.value().ok_or(EpochTransitionError::Invalid(
            "fast-path next validator set requires a committed, eligible bond",
        ))?;
        let bond: FastPathBondRecord = decode_fastpath_bond_record(bond_bytes)?;
        // A fresh `Deposit`/`Reactivate` at `current_epoch` legitimately
        // carries `slashable_from_epoch == current_epoch + 1`: that is
        // exactly the next set this candidate is being considered for, and
        // its liability begins precisely when it joins. Any larger value
        // could never have been produced by any closed DR-0137 operation
        // (see `FastPathBondRecord`'s own encode-time invariant) and is
        // rejected here as corrupt/forged state rather than silently
        // admitted as an over-conservative floor.
        let max_slashable_from_epoch: Option<u64> = current_epoch.get().checked_add(1);
        if bond.context.chain_id() != chain
            || bond.validator_id != validator.id
            || bond.state != FastPathBondState::Active
            || bond.lifecycle_epoch.get() > current_epoch.get()
            || max_slashable_from_epoch.is_none_or(|bound| bond.slashable_from_epoch.get() > bound)
            || bond.authorization_scheme != validator.signature_scheme
            || bond.authorization_key.as_slice() != validator.public_key.as_slice()
        {
            return invalid("fast-path next validator set requires a committed, eligible bond");
        }
        reads.insert(bond_key, bond_observed.revision());

        let policy_index: usize = match policy_cache
            .iter()
            .position(|(policy_context, _)| *policy_context == bond.context)
        {
            Some(index) => index,
            None => {
                let policy_key: Vec<u8> =
                    local_instance_state::fastpath_economics_policy_key(&bond.context)?;
                let policy_observed: VersionedStateValue =
                    store.get_versioned_durable(context, domain, &policy_key)?;
                let policy_bytes: &[u8] =
                    policy_observed
                        .value()
                        .ok_or(EpochTransitionError::Invalid(
                            "fast-path next validator set requires a committed, eligible bond",
                        ))?;
                let policy: FastPathEconomicsPolicy =
                    decode_fastpath_economics_policy(policy_bytes)?;
                reads.insert(policy_key, policy_observed.revision());
                policy_cache.push((bond.context.clone(), policy));
                policy_cache.len() - 1
            }
        };
        let policy: &FastPathEconomicsPolicy = &policy_cache[policy_index].1;

        let resource_id: BondResourceId = BondResourceId::new(bond.resource_domain, bond.resource)
            .map_err(|_| {
                EpochTransitionError::Invalid(
                    "fast-path next validator set requires a committed, eligible bond",
                )
            })?;
        let resource = policy
            .resources
            .binary_search_by_key(&resource_id, |candidate| candidate.resource_id)
            .ok()
            .map(|index: usize| &policy.resources[index])
            .ok_or(EpochTransitionError::Invalid(
                "fast-path next validator set requires a committed, eligible bond",
            ))?;
        let bond_cfg = resource.bond.as_ref().ok_or(EpochTransitionError::Invalid(
            "fast-path next validator set requires a committed, eligible bond",
        ))?;
        if !bond_cfg.enabled
            || bond.amount < bond_cfg.min_bond.get()
            || bond_cfg
                .max_validator_exposure
                .is_some_and(|max| bond.amount > max.get())
        {
            return invalid("fast-path next validator set requires a committed, eligible bond");
        }
    }
    Ok(())
}

/// Deterministically derives the activation write set for `current_epoch ->
/// next_epoch` (DR-0132 §3.A): identical on every node that reads the same
/// committed `ctx@current_epoch` `PaidFeePolicy`. Requires every incoming
/// validator to use Ed25519, matching [`fast_path::load_validator_set`].
///
/// `next_validators` is canonicalized by [`ValidatorId`] before anything is
/// encoded or hashed (DR-0132 §3.A), so equivalent permutations of the same
/// operator-supplied set -- which independent callers/nodes have no other
/// way to agree on the order of -- always produce the exact same
/// `FastPathValidatorSetRecord` bytes and therefore the same
/// `activation_digest`, not merely the same `next_validator_set_digest`
/// (which [`ValidatorSet::new`] already canonicalizes internally).
#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_activation_set<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    protocol_version: ProtocolVersion,
    current_epoch: Epoch,
    next_epoch: Epoch,
    next_validators: &[FastPathValidatorEntry],
) -> EtResult<DerivedActivation> {
    if next_validators.len() > fast_path::records::MAX_FASTPATH_ACTIVE_VALIDATORS {
        return invalid("fast-path next validator set exceeds the fee-claim capacity bound");
    }
    let next_context: PublicationContext =
        PublicationContext::new(chain.clone(), protocol_version, next_epoch)?;

    let mut canonical_validators: Vec<FastPathValidatorEntry> = next_validators.to_vec();
    canonical_validators.sort_by_key(|validator| validator.id);

    let mut info: Vec<ValidatorInfo> = Vec::with_capacity(canonical_validators.len());
    for validator in &canonical_validators {
        if validator.signature_scheme != SignatureSchemeId::Ed25519 {
            return invalid("fast-path next validator set supports only Ed25519");
        }
        info.push(ValidatorInfo {
            id: validator.id,
            voting_power: validator.voting_power,
            signature_scheme: validator.signature_scheme,
            public_key: validator.public_key.clone(),
        });
    }
    // `ValidatorSet::new` validates on the now-canonical order (duplicate
    // IDs/keys are rejected either way), and its own digest was already
    // order-invariant; canonicalizing `info` too keeps this loop and
    // `ValidatorSet::new` operating on identical, already-sorted input.
    let next_validator_set_digest: Digest32 =
        ValidatorSet::new(next_epoch, info)?.digest(resolver)?;

    let validator_set_record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
        context: next_context.clone(),
        validators: canonical_validators,
    };
    let validator_set_bytes: Vec<u8> =
        fast_path::records::encode_fastpath_validator_set_record(&validator_set_record)?;

    let next_execution_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(next_context.clone());
    let execution_policy_bytes: Vec<u8> = next_execution_policy.encode()?;

    let current_context: PublicationContext =
        PublicationContext::new(chain.clone(), protocol_version, current_epoch)?;
    let fee_policy_key: Vec<u8> = local_instance_state::paid_fee_policy_key(&current_context)?;
    let observed_fee_policy: VersionedStateValue =
        store.get_versioned_durable(context, domain, &fee_policy_key)?;
    let current_fee_policy_bytes: &[u8] =
        observed_fee_policy
            .value()
            .ok_or(EpochTransitionError::Invalid(
                "committed paid fee policy absent at the outgoing epoch",
            ))?;
    let current_fee_policy: PaidFeePolicy = decode_paid_fee_policy(current_fee_policy_bytes)?;
    if current_fee_policy.context != current_context {
        return invalid("committed paid fee policy is bound to a different outgoing context");
    }
    let next_base_policy_digest: Digest32 = next_execution_policy.digest(resolver)?;
    let next_fee_policy: PaidFeePolicy = PaidFeePolicy {
        context: next_context.clone(),
        base_policy_digest: next_base_policy_digest,
        ..current_fee_policy
    };
    let paid_fee_policy_bytes: Vec<u8> =
        execution::paid_execution::encode_paid_fee_policy(&next_fee_policy)?;

    let publication_semantics: Digest32 =
        execution::local_execution::generic_object_result_semantics(resolver, &next_context)?;
    let next_publication_policy: LocalPublicationPolicy =
        LocalPublicationPolicy::object_results(next_context.clone(), publication_semantics);
    let publication_policy_bytes: Vec<u8> = next_publication_policy.encode()?;

    let activation_set: FastPathEpochActivationSet = FastPathEpochActivationSet {
        next_context: next_context.clone(),
        validator_set_record: validator_set_bytes,
        execution_policy: execution_policy_bytes,
        paid_fee_policy: paid_fee_policy_bytes,
        publication_policy: publication_policy_bytes,
    };
    let activation_digest: Digest32 = resolver.hash_for_purpose(
        next_epoch,
        HashPurpose::NodeEvent,
        &encode_fastpath_epoch_activation_set(&activation_set)?,
    )?;

    Ok(DerivedActivation {
        next_validator_set_digest,
        activation_digest,
        activation_set,
        current_fee_policy_key: fee_policy_key,
        current_fee_policy_revision: observed_fee_policy.revision(),
    })
}

/// Derives the activation set for the committed current epoch's successor
/// and casts one outgoing-set [`consensus::EpochTransitionVote`] over it
/// (DR-0132 §3.B). Persists nothing: byte-stability comes from the
/// determinism of [`derive_activation_set`] plus Ed25519 determinism, not
/// from a durable record.
///
/// [`activate`] installs the live [`FastPathEpochRecord`] and the
/// `next_epoch` transition row atomically in one `commit_durable`, so the two
/// are never independently observable *in the same commit*. But this
/// function's own reads are not atomic with each other: it fences
/// `current_epoch` first and only reads the `current_epoch + 1` transition
/// row afterwards, so a concurrent `activate` can commit in between. If that
/// happens, this call observes a transition row at `current_epoch + 1`
/// alongside a *now-stale* `current_epoch` it already fenced. To tell that
/// benign interleaving apart from genuinely partial or corrupt prior state,
/// it re-reads the live epoch record at that point:
/// * if the live epoch has advanced beyond `current_epoch`, the transition
///   row belongs to a concurrent activation sequence, not an orphan --
///   returns the retryable [`NodeCoreError::StateConflict`] so the caller
///   re-proposes against the new epoch;
/// * otherwise (the live epoch still reads `current_epoch`, or regressed),
///   the transition row cannot correspond to any real
///   activation and this fails closed with [`EpochTransitionError::Invalid`]
///   (for example, a non-atomic write that should never exist, or on-disk
///   tampering).
///
/// This is the one and only place DR-0137 unit 3 gates next-set candidate
/// bond eligibility ([`derive_eligibility_reads`]): a candidate that is
/// jailed, unbonding, exited, below the minimum, above the maximum
/// exposure, disabled by policy, key-mismatched or altogether absent fails
/// this call closed, so no vote is ever cast over it and it can never enter
/// a legitimately quorum-certified set. [`activate`] never repeats this
/// check -- see [`DerivedActivation`].
#[allow(clippy::too_many_arguments)]
pub fn propose_and_vote<S, C>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    protocol_version: ProtocolVersion,
    next_validators: Vec<FastPathValidatorEntry>,
    signer: &C,
) -> EtResult<EpochTransitionVote>
where
    S: StructuredDurableDomainStateStore,
    C: ConsensusSigner,
{
    let mut fence_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let epoch_record: FastPathEpochRecord =
        mutation_fence::fence_epoch_state(store, context, domain, chain, &mut fence_reads)?;
    let current_epoch: Epoch = epoch_record.current_epoch;
    let current_context: PublicationContext =
        PublicationContext::new(chain.clone(), protocol_version, current_epoch)?;
    let outgoing_validator_set: ValidatorSet = load_validator_set(
        store,
        context,
        domain,
        resolver,
        &current_context,
        &epoch_record,
        &mut fence_reads,
    )?;

    let next_epoch_number: u64 =
        current_epoch
            .get()
            .checked_add(1)
            .ok_or(EpochTransitionError::Consensus(
                ConsensusError::ArithmeticOverflow,
            ))?;
    let next_epoch: Epoch = Epoch::new(next_epoch_number);

    let transition_key: Vec<u8> =
        local_instance_state::fastpath_epoch_transition_key(chain, next_epoch)?;
    let observed_transition: VersionedStateValue =
        store.get_versioned_durable(context, domain, &transition_key)?;
    if observed_transition.value().is_some() {
        // A concurrent `activate` may have committed between the epoch fence
        // above and this read: re-read the live epoch record before
        // deciding whether this is that benign race or orphan state.
        let epoch_record_key: Vec<u8> = local_instance_state::fastpath_epoch_record_key(chain)?;
        let live_observed: VersionedStateValue =
            store.get_versioned_durable(context, domain, &epoch_record_key)?;
        let live_epoch_record: FastPathEpochRecord =
            local_instance_state::decode_fastpath_epoch_record(live_observed.value().ok_or(
                NodeCoreError::PersistenceInvariant("fast-path epoch record not installed"),
            )?)?;
        if live_epoch_record.current_epoch > current_epoch {
            return Err(EpochTransitionError::Node(NodeCoreError::StateConflict));
        }
        return invalid(
            "fast-path epoch transition record exists at current_epoch + 1 while the live epoch \
             record has not advanced beyond current_epoch: partial or corrupt prior state",
        );
    }

    let derived: DerivedActivation = derive_activation_set(
        store,
        context,
        domain,
        resolver,
        chain,
        protocol_version,
        current_epoch,
        next_epoch,
        &next_validators,
    )?;

    // Gate candidate bond eligibility here, strictly after the incoming set
    // is already known structurally valid (`ValidatorSet::new`, inside
    // `derive_activation_set`) and strictly before a vote is cast -- never
    // inside `derive_activation_set`/`activate` (see `DerivedActivation`'s
    // doc comment).
    derive_eligibility_reads(
        store,
        context,
        domain,
        chain,
        current_epoch,
        &next_validators,
    )?;

    let certifier: EpochTransitionCertifier = EpochTransitionCertifier::new(
        chain.clone(),
        protocol_version,
        current_epoch,
        outgoing_validator_set,
    )?;
    certifier
        .cast_vote(
            next_epoch,
            epoch_record.current_validator_set_digest,
            derived.next_validator_set_digest,
            derived.activation_digest,
            signer,
        )
        .map_err(EpochTransitionError::Consensus)
}

/// Result of [`activate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EpochActivationOutcome {
    /// The transition was freshly, atomically installed.
    Activated(FastPathEpochTransitionRecord),
    /// The identical transition was already activated; nothing was mutated.
    AlreadyActivated(FastPathEpochTransitionRecord),
}

/// Verifies an outgoing-set [`consensus::EpochTransitionCertificate`] and
/// atomically installs its `e+1` activation write set plus the rewritten
/// [`FastPathEpochRecord`] and the permanent
/// [`FastPathEpochTransitionRecord`] audit row (DR-0132 §3.C).
///
/// `next_validators` must be the exact same operator-supplied set the
/// certificate's signers voted on; this function independently re-derives
/// the activation set from it and requires the result to match the
/// certificate exactly (§3.C.6) -- a node never installs bytes it did not
/// itself derive.
///
/// Deliberately does not re-check next-set bond eligibility
/// ([`derive_eligibility_reads`] runs only in [`propose_and_vote`], before a
/// vote is ever cast): a certificate that verifies here was already validly
/// formed, and applying it is a pure derivation of the certificate's own
/// bytes plus the current committed policy/validator-set state needed to
/// reproduce [`FastPathEpochActivationSet`] -- never of a next-set
/// validator's live bond state. A `handle_bond_slash` that commits at any
/// point relative to this call therefore cannot change whether this exact
/// certificate activates; jailing a validator here only ever affects which
/// candidates the *next* `propose_and_vote` round is willing to vote on.
#[allow(clippy::too_many_arguments)]
pub fn activate<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    protocol_version: ProtocolVersion,
    next_validators: Vec<FastPathValidatorEntry>,
    certificate_bytes: &[u8],
    checkpoint: u64,
) -> EtResult<EpochActivationOutcome> {
    // 1. Decode the certificate (pure).
    let certificate: EpochTransitionCertificate =
        decode_epoch_transition_certificate(certificate_bytes)?;
    if &certificate.chain_id != chain || certificate.protocol_version != protocol_version {
        return Err(EpochTransitionError::Consensus(
            ConsensusError::ContextMismatch,
        ));
    }

    // 2. Fence the committed epoch record.
    let mut fence_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let epoch_record: FastPathEpochRecord =
        mutation_fence::fence_epoch_state(store, context, domain, chain, &mut fence_reads)?;

    // 3. Already-activated branch: full transition-identity comparison, not
    //    `activation_digest` alone (§3.C.3; `activation_digest`'s own
    //    preimage excludes `from_epoch` and both validator-set digests).
    if epoch_record.current_epoch == certificate.next_epoch {
        let transition_key: Vec<u8> =
            local_instance_state::fastpath_epoch_transition_key(chain, certificate.next_epoch)?;
        let observed: VersionedStateValue =
            store.get_versioned_durable(context, domain, &transition_key)?;
        let stored_bytes: &[u8] = observed.value().ok_or(EpochTransitionError::Invalid(
            "epoch already advanced but its transition record is missing",
        ))?;
        let record: FastPathEpochTransitionRecord =
            decode_fastpath_epoch_transition_record(stored_bytes)?;
        if record.from_epoch == certificate.epoch
            && record.to_epoch == certificate.next_epoch
            && record.previous_validator_set_digest == certificate.current_validator_set_digest
            && record.next_validator_set_digest == certificate.next_validator_set_digest
            && record.activation_digest == certificate.activation_digest
        {
            return Ok(EpochActivationOutcome::AlreadyActivated(record));
        }
        return invalid("conflicting epoch transition already activated");
    }

    // 4. Otherwise require the certificate's outgoing epoch to be exactly
    //    the committed current epoch.
    if epoch_record.current_epoch != certificate.epoch {
        return Err(EpochTransitionError::Node(NodeCoreError::EpochMismatch {
            expected: epoch_record.current_epoch,
            actual: certificate.epoch,
        }));
    }

    // 5. Cryptographically verify the certificate under the fenced outgoing
    //    set and require its digest to match the committed record.
    let current_context: PublicationContext =
        PublicationContext::new(chain.clone(), protocol_version, certificate.epoch)?;
    let outgoing_validator_set: ValidatorSet = load_validator_set(
        store,
        context,
        domain,
        resolver,
        &current_context,
        &epoch_record,
        &mut fence_reads,
    )?;
    let certifier: EpochTransitionCertifier = EpochTransitionCertifier::new(
        chain.clone(),
        protocol_version,
        certificate.epoch,
        outgoing_validator_set,
    )?;
    certifier.verify_certificate(&certificate, &FastPathEd25519Verifier)?;
    if certificate.current_validator_set_digest != epoch_record.current_validator_set_digest {
        return invalid(
            "epoch transition certificate outgoing validator-set digest does not match the committed epoch record",
        );
    }

    // 6. Re-derive the activation set locally; a node never installs bytes
    //    it did not itself derive.
    let derived: DerivedActivation = derive_activation_set(
        store,
        context,
        domain,
        resolver,
        chain,
        protocol_version,
        certificate.epoch,
        certificate.next_epoch,
        &next_validators,
    )?;
    if derived.activation_digest != certificate.activation_digest {
        return invalid(
            "locally derived epoch activation set does not match the certificate's activation digest",
        );
    }
    if derived.next_validator_set_digest != certificate.next_validator_set_digest {
        return invalid("locally derived next validator-set digest does not match the certificate");
    }

    // 7. CAS-assert absence of all five target rows.
    let next_context: PublicationContext =
        PublicationContext::new(chain.clone(), protocol_version, certificate.next_epoch)?;
    let validator_set_key: Vec<u8> =
        local_instance_state::fastpath_validator_set_key(&next_context)?;
    let execution_policy_key: Vec<u8> =
        local_instance_state::execution_policy_key_for_profile(&next_context, 4)?;
    let paid_fee_policy_key: Vec<u8> = local_instance_state::paid_fee_policy_key(&next_context)?;
    let publication_policy_key: Vec<u8> =
        publication::publication_policy_key_for_profile(&next_context, 4)?;
    let transition_key: Vec<u8> =
        local_instance_state::fastpath_epoch_transition_key(chain, certificate.next_epoch)?;

    let mut reads: BTreeMap<Vec<u8>, StateRevision> = fence_reads;
    reads.insert(
        derived.current_fee_policy_key.clone(),
        derived.current_fee_policy_revision,
    );
    for key in [
        &validator_set_key,
        &execution_policy_key,
        &paid_fee_policy_key,
        &publication_policy_key,
        &transition_key,
    ] {
        let observed: VersionedStateValue = store.get_versioned_durable(context, domain, key)?;
        if observed.value().is_some() {
            return invalid("partial prior state already exists at the next-epoch context");
        }
        reads.insert(key.clone(), observed.revision());
    }

    // 8. One commit_durable: five Puts plus the rewritten FastPathEpochRecord.
    let transition_record: FastPathEpochTransitionRecord = FastPathEpochTransitionRecord {
        from_epoch: certificate.epoch,
        to_epoch: certificate.next_epoch,
        previous_validator_set_digest: certificate.current_validator_set_digest,
        next_validator_set_digest: certificate.next_validator_set_digest,
        activation_digest: certificate.activation_digest,
        certificate: certificate_bytes.to_vec(),
        activated_at_checkpoint: checkpoint,
    };
    let transition_bytes: Vec<u8> = encode_fastpath_epoch_transition_record(&transition_record)?;

    let new_epoch_record: FastPathEpochRecord = FastPathEpochRecord {
        current_epoch: certificate.next_epoch,
        current_validator_set_digest: certificate.next_validator_set_digest,
        previous_epoch: Some(certificate.epoch),
        activated_at_checkpoint: checkpoint,
    };
    let epoch_record_key: Vec<u8> = local_instance_state::fastpath_epoch_record_key(chain)?;
    let epoch_record_bytes: Vec<u8> =
        local_instance_state::encode_fastpath_epoch_record(&new_epoch_record)?;

    let mutations: Vec<StateMutationEntry> = vec![
        StateMutationEntry::new(
            validator_set_key,
            StateMutation::Put(derived.activation_set.validator_set_record.clone()),
        )?,
        StateMutationEntry::new(
            execution_policy_key,
            StateMutation::Put(derived.activation_set.execution_policy.clone()),
        )?,
        StateMutationEntry::new(
            paid_fee_policy_key,
            StateMutation::Put(derived.activation_set.paid_fee_policy.clone()),
        )?,
        StateMutationEntry::new(
            publication_policy_key,
            StateMutation::Put(derived.activation_set.publication_policy.clone()),
        )?,
        StateMutationEntry::new(transition_key, StateMutation::Put(transition_bytes))?,
        StateMutationEntry::new(epoch_record_key, StateMutation::Put(epoch_record_bytes))?,
    ];
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<_, RuntimeError>>()?;
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(assertions)?,
        AtomicStateMutationSet::new(mutations)?,
    )?;
    match store.commit_durable(context, transaction) {
        DurableCommitOutcome::Committed => Ok(EpochActivationOutcome::Activated(transition_record)),
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::Conflict { .. }
            | DurableCommitRejection::RequestAlreadyCommitted,
        ) => Err(EpochTransitionError::Node(NodeCoreError::StateConflict)),
        DurableCommitOutcome::Rejected(reason) => Err(EpochTransitionError::Node(
            NodeCoreError::DurableCommitRejected(reason),
        )),
        DurableCommitOutcome::Indeterminate(reason) => Err(EpochTransitionError::Node(
            NodeCoreError::DurableCommitIndeterminate(reason),
        )),
    }
}
