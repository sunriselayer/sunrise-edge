//! DR-0137 implementation unit 2: the closed post-genesis bond lifecycle.
//!
//! One canonical envelope (`BondLifecycleIntent` `0x642F/v1`, signed as
//! `0x6430/v1`) authorizes exactly one of four closed operations against the
//! single authoritative [`crate::fast_path::records::FastPathBondRecord`]
//! row for one validator:
//!
//! * [`BondLifecycleOperation::Deposit`]: `Exited -> Active`, moving one
//!   exact sender-owned object into the validator's `BondCollateral` scope.
//! * [`BondLifecycleOperation::Replace`]: `Active -> Active`, an atomic
//!   same-sender two-leg swap (consecutive nonces) that deposits a new
//!   object and releases the old one to a validator-authorized recipient.
//!   The new amount must be at least the previous live bond amount (and no
//!   more than the committed maximum): any reduction must go through
//!   [`BondLifecycleOperation::Unbond`]/[`BondLifecycleOperation::Withdraw`]
//!   instead, so it observes their unlock delay rather than instantly
//!   evading forfeiture on the released amount.
//! * [`BondLifecycleOperation::Unbond`]: `Active -> Unbonding`, recording an
//!   unlock epoch and signed recipient. No contract execution.
//! * [`BondLifecycleOperation::Withdraw`]: `Unbonding -> Exited`, releasing
//!   the custody object to the recorded recipient once the delay has
//!   elapsed and the validator is absent from the committed live set.
//!
//! The envelope is signed exactly once, by the exact committed validator
//! authorization key carried on the current bond row
//! ([`crate::phase3_authorization`] documents this authority matrix). Every
//! embedded `SignedLocalExecutionIntent` "leg" is independently authenticated
//! through the existing `ExecuteLocalContract` domain
//! ([`execution::local_execution::authenticate_local_execution`]) and
//! executed through [`crate::local_execution::admit_and_execute_leg`] with a
//! narrowly scoped [`execution::protocol_custody::ProtocolCustodyCapability`]
//! -- the same generic path ordinary zero-fee local execution uses, never a
//! parallel implementation. [`effects`] then validates the contract-produced
//! effects generically: exactly one whole-object `Mutated` effect, exact
//! identity/type/schema/body, and an exact owner transition observed only
//! through the signed executable ABI.
//!
//! Authentication and replay order follows DR-0137 exactly: bounded
//! canonical decode, every inner leg's own signature, the reserved-id guard,
//! the envelope digest, exact/conflicting replay reconciliation, the
//! committed-epoch fence, the committed bond row and its validator signature
//! -- all before any policy, live-set, nonce, lock, publication, object or
//! execution work. One atomic [`DurableInvocationTransaction`] commits every
//! touched object head, the new bond row, the new (never overwritten)
//! [`crate::fast_path::records::FastPathBondTransitionRecord`], the sender
//! nonce range, stale lock cleanup and the one outer request receipt. A
//! trapped leg or a rejected invariant returns an error and commits nothing:
//! unlike ordinary local execution, there is no "rejected but committed"
//! receipt here.
#![allow(clippy::result_large_err)]
use super::*;
use crate::economics::{
    FastPathEconomicsPolicy, FastPathEconomicsResourcePolicy, decode_fastpath_economics_policy,
};
use crate::fast_path::records::{
    BondTransitionAuthorization, FastPathBondLifecycleOperation, FastPathBondRecord,
    FastPathBondState, FastPathBondTransitionRecord, decode_fastpath_bond_record,
    encode_fastpath_bond_record, encode_fastpath_bond_transition_record,
};
use crate::local_execution::{AdmittedLeg, LocalExecutionAdmissionError, admit_and_execute_leg};
use bonds::{BondError, BondResourceConfig, BondResourceId, decode_bond_resource_id};
use canonical_encoding::{decode_digest32, encode_digest32};
use crypto::{Ed25519Verifier, SignatureDomain, SignatureMessageType, SignatureVerifier};
use execution::local_execution::{
    AuthenticatedLocalExecutionIntent, LocalContractEngine, LocalExecutionError,
    LocalExecutionPolicy, MAX_LOCAL_EXECUTION_INTENT_BYTES, authenticate_local_execution,
    local_execution_event_digest,
};
use execution::protocol_custody::{
    ProtocolCustodyCapability, ProtocolCustodyDirection, ProtocolCustodyTarget,
};
use execution::publication::PublicationContext;
use objects::{ProtocolCustodyPurpose, ProtocolCustodyScope};
use protocol_types::{SignatureSchemeId, ValidatorId};
use validator_set::ValidatorSet;

mod effects;
pub mod slash;
#[cfg(test)]
mod tests;

const BOND_LIFECYCLE_INTENT_TYPE: u16 = 0x642F;
const SIGNED_BOND_LIFECYCLE_INTENT_TYPE: u16 = 0x6430;
const ENCODING_VERSION: u16 = 1;
/// Bounds the complete signed envelope, including up to two embedded legs.
const MAX_BOND_LIFECYCLE_INTENT_BYTES: usize = 2 * MAX_LOCAL_EXECUTION_INTENT_BYTES + 4_096;

const OPERATION_TAG_DEPOSIT: u16 = 1;
const OPERATION_TAG_REPLACE: u16 = 2;
const OPERATION_TAG_UNBOND: u16 = 3;
const OPERATION_TAG_WITHDRAW: u16 = 4;
const OPERATION_TAG_REACTIVATE: u16 = 5;

/// Fail-closed DR-0137 bond-lifecycle errors.
#[derive(Debug)]
pub enum BondLifecycleError {
    /// Shared leg-admission/execution pipeline failure.
    Admission(LocalExecutionAdmissionError),
    /// `execution` crate typed-WASM or capability-construction failure.
    Execution(LocalExecutionError),
    /// Storage or node boundary failure.
    Node(NodeCoreError),
    /// Bond policy/state-machine invariant failure.
    Bond(BondError),
    /// Bond-lifecycle-specific invariant failed.
    Invalid(&'static str),
}
impl fmt::Display for BondLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => error.fmt(f),
            Self::Execution(error) => error.fmt(f),
            Self::Node(error) => error.fmt(f),
            Self::Bond(error) => error.fmt(f),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}
impl Error for BondLifecycleError {}
impl From<LocalExecutionAdmissionError> for BondLifecycleError {
    fn from(error: LocalExecutionAdmissionError) -> Self {
        Self::Admission(error)
    }
}
impl From<LocalExecutionError> for BondLifecycleError {
    fn from(error: LocalExecutionError) -> Self {
        Self::Execution(error)
    }
}
impl From<NodeCoreError> for BondLifecycleError {
    fn from(error: NodeCoreError) -> Self {
        Self::Node(error)
    }
}
impl From<BondError> for BondLifecycleError {
    fn from(error: BondError) -> Self {
        Self::Bond(error)
    }
}
impl From<DurableReadError> for BondLifecycleError {
    fn from(error: DurableReadError) -> Self {
        Self::Node(error.into())
    }
}
impl From<RuntimeError> for BondLifecycleError {
    fn from(error: RuntimeError) -> Self {
        Self::Node(error.into())
    }
}
impl From<DurableInvocationError> for BondLifecycleError {
    fn from(error: DurableInvocationError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalEncodingError> for BondLifecycleError {
    fn from(error: CanonicalEncodingError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalDecodingError> for BondLifecycleError {
    fn from(error: CanonicalDecodingError) -> Self {
        Self::Node(NodeCoreError::CanonicalDecoding(error))
    }
}
impl From<HashingError> for BondLifecycleError {
    fn from(error: HashingError) -> Self {
        Self::Node(error.into())
    }
}
impl From<crypto::CryptoError> for BondLifecycleError {
    fn from(error: crypto::CryptoError) -> Self {
        Self::Node(NodeCoreError::PersistenceInvariant(match error {
            crypto::CryptoError::InvalidVerificationKeyLength(_) => {
                "bond lifecycle authorization key length"
            }
            crypto::CryptoError::MalformedVerificationKey => {
                "bond lifecycle authorization key malformed"
            }
            crypto::CryptoError::InvalidSignatureLength(_) => "bond lifecycle signature length",
            _ => "bond lifecycle cryptographic failure",
        }))
    }
}

/// One closed DR-0137 bond-lifecycle operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BondLifecycleOperation {
    /// `Exited -> Active`. `leg` is the exact canonical `0x6406/v1` bytes of
    /// one signed local-execution call moving a sender-owned object into
    /// this validator's `BondCollateral` scope.
    Deposit {
        /// The deposit's signed local-execution leg (raw canonical bytes).
        leg: Vec<u8>,
    },
    /// `Active -> Active`. Same-sender, consecutive-nonce two-leg swap. The
    /// new object's amount must be non-decreasing relative to the previous
    /// live bond amount (see the module-level documentation).
    Replace {
        /// The new object's signed deposit leg.
        deposit_leg: Vec<u8>,
        /// The old custody object's signed release leg.
        release_leg: Vec<u8>,
        /// Validator-authorized explicit recipient of the released object.
        release_recipient: Address,
    },
    /// `Active -> Unbonding`. No contract execution.
    Unbond {
        /// Exact signed recipient recorded for the later withdrawal.
        recipient: Address,
    },
    /// `Unbonding -> Exited`. `leg` releases the current custody object to
    /// the exact recipient already recorded by [`Self::Unbond`].
    Withdraw {
        /// The release leg (raw canonical bytes).
        leg: Vec<u8>,
    },
    /// `Jailed -> Active`. Reuses [`Self::Deposit`]'s exact mechanics: `leg`
    /// is the exact canonical `0x6406/v1` bytes of one signed local-execution
    /// call moving a fresh sender-owned object into this validator's
    /// `BondCollateral` scope, checked against the current committed
    /// enabled/min/max policy exactly as a deposit is.
    Reactivate {
        /// The reactivation deposit's signed local-execution leg (raw
        /// canonical bytes).
        leg: Vec<u8>,
    },
}

impl BondLifecycleOperation {
    pub(crate) const fn tag(&self) -> u16 {
        match self {
            Self::Deposit { .. } => OPERATION_TAG_DEPOSIT,
            Self::Replace { .. } => OPERATION_TAG_REPLACE,
            Self::Unbond { .. } => OPERATION_TAG_UNBOND,
            Self::Withdraw { .. } => OPERATION_TAG_WITHDRAW,
            Self::Reactivate { .. } => OPERATION_TAG_REACTIVATE,
        }
    }
}

/// Single signed payload authorizing one closed bond-lifecycle operation.
///
/// [`Self::expected_generation`], [`Self::expected_previous_row_digest`] and
/// [`Self::expected_next_row_digest`] make the transition chain
/// cryptographically non-forgeable: the signer commits, ahead of execution,
/// to the exact generation and row digests this operation must observe and
/// produce. Node core verifies the first two immediately after reading the
/// committed row and the third immediately after deterministically building
/// the resulting row, before ever committing -- so a delayed resubmission
/// against a since-advanced row, or any coordinated rewrite of a
/// transition/final row, fails a plain equality check instead of merely
/// hoping downstream validation catches it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondLifecycleIntent {
    /// Expected replay context.
    pub context: PublicationContext,
    /// Exact replay identity covered by the signature. Every embedded leg's
    /// own `CallIntent::request_id` must equal this exact value too.
    pub request_id: [u8; 32],
    /// Validator this operation is committed against.
    pub validator_id: ValidatorId,
    /// Exact resource identity the signer expects the committed bond row to
    /// carry.
    pub resource_id: BondResourceId,
    /// Exact current (pre-transition) generation the signer expects the
    /// committed bond row to carry.
    pub expected_generation: u64,
    /// Exact digest of the current (pre-transition) row the signer expects,
    /// computed the same way [`bond_row_digest`] is: at that row's own
    /// `lifecycle_epoch`.
    pub expected_previous_row_digest: Digest32,
    /// Exact digest of the deterministically resulting row this operation
    /// must produce, computed the same way.
    pub expected_next_row_digest: Digest32,
    /// The closed operation and its embedded legs/recipients.
    pub operation: BondLifecycleOperation,
}

/// Unverified `bond_lifecycle` submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBondLifecycleIntent {
    /// Exact signed payload.
    pub intent: BondLifecycleIntent,
    /// Ed25519 signature in the `FastPathBondLifecycle` domain, verified
    /// only against the committed bond row's own authorization key.
    pub signature: [u8; 64],
}

/// Encodes closed bond-lifecycle intent `0x642F/v1`.
pub fn encode_bond_lifecycle_intent(
    intent: &BondLifecycleIntent,
) -> Result<Vec<u8>, BondLifecycleError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(BOND_LIFECYCLE_INTENT_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        execution::publication::encode_publication_context(&intent.context)
            .map_err(|_| BondLifecycleError::Invalid("invalid bond lifecycle context"))?,
    )?;
    frame.field_bytes(2, intent.request_id.to_vec())?;
    frame.field_bytes(3, intent.validator_id.as_bytes().to_vec())?;
    frame.field_u16(4, intent.operation.tag())?;
    match &intent.operation {
        BondLifecycleOperation::Deposit { leg }
        | BondLifecycleOperation::Withdraw { leg }
        | BondLifecycleOperation::Reactivate { leg } => {
            frame.field_bytes(5, leg.clone())?;
        }
        BondLifecycleOperation::Replace {
            deposit_leg,
            release_leg,
            release_recipient,
        } => {
            frame.field_bytes(6, deposit_leg.clone())?;
            frame.field_bytes(7, release_leg.clone())?;
            frame.field_bytes(8, release_recipient.as_bytes().to_vec())?;
        }
        BondLifecycleOperation::Unbond { recipient } => {
            frame.field_bytes(9, recipient.as_bytes().to_vec())?;
        }
    }
    frame.field_bytes(
        10,
        bonds::encode_bond_resource_id(intent.resource_id)
            .map_err(|_| BondLifecycleError::Invalid("bond lifecycle resource id"))?,
    )?;
    frame.field_u64(11, intent.expected_generation)?;
    frame.field_bytes(12, encode_digest32(&intent.expected_previous_row_digest)?)?;
    frame.field_bytes(13, encode_digest32(&intent.expected_next_row_digest)?)?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_BOND_LIFECYCLE_INTENT_BYTES {
        return Err(BondLifecycleError::Invalid("bond lifecycle intent bytes"));
    }
    Ok(bytes)
}

/// Strictly decodes bond-lifecycle intent `0x642F/v1`.
pub fn decode_bond_lifecycle_intent(
    bytes: &[u8],
) -> Result<BondLifecycleIntent, BondLifecycleError> {
    if bytes.len() > MAX_BOND_LIFECYCLE_INTENT_BYTES {
        return Err(BondLifecycleError::Invalid("bond lifecycle intent bytes"));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(BOND_LIFECYCLE_INTENT_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let context: PublicationContext =
        execution::publication::decode_publication_context(frame.required_field(1)?)
            .map_err(|_| BondLifecycleError::Invalid("invalid bond lifecycle context"))?;
    let request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| BondLifecycleError::Invalid("bond lifecycle request id length"))?;
    let validator_bytes: [u8; 32] = frame
        .required_field(3)?
        .try_into()
        .map_err(|_| BondLifecycleError::Invalid("bond lifecycle validator id length"))?;
    let validator_id: ValidatorId = ValidatorId::new(validator_bytes);
    let tag: u16 = frame.required_u16(4)?;
    let fixed_fields: &[u16] = &[1, 2, 3, 4, 10, 11, 12, 13];
    let operation: BondLifecycleOperation = match tag {
        OPERATION_TAG_DEPOSIT => {
            frame.require_only_fields(&[fixed_fields, &[5]].concat())?;
            BondLifecycleOperation::Deposit {
                leg: frame.required_field(5)?.to_vec(),
            }
        }
        OPERATION_TAG_WITHDRAW => {
            frame.require_only_fields(&[fixed_fields, &[5]].concat())?;
            BondLifecycleOperation::Withdraw {
                leg: frame.required_field(5)?.to_vec(),
            }
        }
        OPERATION_TAG_REACTIVATE => {
            frame.require_only_fields(&[fixed_fields, &[5]].concat())?;
            BondLifecycleOperation::Reactivate {
                leg: frame.required_field(5)?.to_vec(),
            }
        }
        OPERATION_TAG_REPLACE => {
            frame.require_only_fields(&[fixed_fields, &[6, 7, 8]].concat())?;
            let recipient_bytes: [u8; 32] = frame
                .required_field(8)?
                .try_into()
                .map_err(|_| BondLifecycleError::Invalid("bond lifecycle recipient length"))?;
            BondLifecycleOperation::Replace {
                deposit_leg: frame.required_field(6)?.to_vec(),
                release_leg: frame.required_field(7)?.to_vec(),
                release_recipient: Address::new(recipient_bytes),
            }
        }
        OPERATION_TAG_UNBOND => {
            frame.require_only_fields(&[fixed_fields, &[9]].concat())?;
            let recipient_bytes: [u8; 32] = frame
                .required_field(9)?
                .try_into()
                .map_err(|_| BondLifecycleError::Invalid("bond lifecycle recipient length"))?;
            BondLifecycleOperation::Unbond {
                recipient: Address::new(recipient_bytes),
            }
        }
        _ => {
            return Err(BondLifecycleError::Invalid(
                "unknown bond lifecycle operation",
            ));
        }
    };
    let resource_id: BondResourceId = decode_bond_resource_id(frame.required_field(10)?)
        .map_err(|_| BondLifecycleError::Invalid("bond lifecycle resource id"))?;
    let intent: BondLifecycleIntent = BondLifecycleIntent {
        context,
        request_id,
        validator_id,
        resource_id,
        expected_generation: frame.required_u64(11)?,
        expected_previous_row_digest: decode_digest32(frame.required_field(12)?)?,
        expected_next_row_digest: decode_digest32(frame.required_field(13)?)?,
        operation,
    };
    if encode_bond_lifecycle_intent(&intent)? != bytes {
        return Err(BondLifecycleError::Invalid(
            "noncanonical bond lifecycle intent",
        ));
    }
    Ok(intent)
}

/// Encodes signed bond-lifecycle intent `0x6430/v1`.
pub fn encode_signed_bond_lifecycle_intent(
    signed: &SignedBondLifecycleIntent,
) -> Result<Vec<u8>, BondLifecycleError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(SIGNED_BOND_LIFECYCLE_INTENT_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_bond_lifecycle_intent(&signed.intent)?)?;
    frame.field_bytes(2, signed.signature.to_vec())?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_BOND_LIFECYCLE_INTENT_BYTES {
        return Err(BondLifecycleError::Invalid("signed bond lifecycle bytes"));
    }
    Ok(bytes)
}

/// Strictly decodes signed bond-lifecycle intent `0x6430/v1`. Performs no
/// signature verification: DR-0137 requires the committed bond row
/// (unavailable until after epoch fencing and replay reconciliation) before
/// the validator's own authorization key is known.
pub fn decode_signed_bond_lifecycle_intent(
    bytes: &[u8],
) -> Result<SignedBondLifecycleIntent, BondLifecycleError> {
    if bytes.len() > MAX_BOND_LIFECYCLE_INTENT_BYTES {
        return Err(BondLifecycleError::Invalid("signed bond lifecycle bytes"));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(SIGNED_BOND_LIFECYCLE_INTENT_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let signed: SignedBondLifecycleIntent = SignedBondLifecycleIntent {
        intent: decode_bond_lifecycle_intent(frame.required_field(1)?)?,
        signature: frame
            .required_field(2)?
            .try_into()
            .map_err(|_| BondLifecycleError::Invalid("bond lifecycle signature length"))?,
    };
    if encode_signed_bond_lifecycle_intent(&signed)? != bytes {
        return Err(BondLifecycleError::Invalid(
            "noncanonical signed bond lifecycle intent",
        ));
    }
    Ok(signed)
}

/// Digest of the exact canonical (unsigned) intent bytes alone: the exact
/// payload the validator's signature covers
/// ([`bond_lifecycle_signing_frame`]). Never used for receipt/replay
/// idempotency (see [`bond_lifecycle_receipt_digest`]): two different valid
/// signatures over an identical intent would otherwise hash identically and
/// let an unauthenticated second signature silently "replay" against the
/// first's receipt.
pub(crate) fn bond_lifecycle_intent_digest(
    resolver: &HashSuiteResolver,
    intent: &BondLifecycleIntent,
) -> Result<Digest32, BondLifecycleError> {
    let context: &PublicationContext = &intent.context;
    if resolver.chain_id() != context.chain_id()
        || resolver.protocol_version() != context.protocol_version()
    {
        return Err(BondLifecycleError::Invalid("bond lifecycle hash context"));
    }
    Ok(resolver.hash_for_purpose(
        context.epoch(),
        HashPurpose::NodeEvent,
        &encode_bond_lifecycle_intent(intent)?,
    )?)
}

/// Digest of the exact canonical *signed* envelope bytes (intent and
/// signature together): the receipt/replay idempotency key. Hashing the
/// signature too means a resubmission carrying a different (even if
/// cryptographically valid, differently-produced) signature byte string
/// over an identical intent is treated as a conflicting replay -- not a
/// silently accepted duplicate -- since [`durable_reconciliation::reconcile_receipt`]
/// requires an exact digest match against the stored receipt.
fn bond_lifecycle_receipt_digest(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    signed_bytes: &[u8],
) -> Result<Digest32, BondLifecycleError> {
    if resolver.chain_id() != context.chain_id()
        || resolver.protocol_version() != context.protocol_version()
    {
        return Err(BondLifecycleError::Invalid("bond lifecycle hash context"));
    }
    Ok(resolver.hash_for_purpose(context.epoch(), HashPurpose::NodeEvent, signed_bytes)?)
}

/// One shared Ed25519 domain for every bond-lifecycle envelope, regardless
/// of operation. Signs the 32-byte intent digest, not the raw intent bytes,
/// so the exact signed frame is independently re-derivable from nothing
/// more than `(context, intent_digest)` -- see
/// [`bond_lifecycle_intent_digest`].
pub(crate) fn bond_lifecycle_signing_frame(
    context: &PublicationContext,
    intent_digest: Digest32,
) -> Result<Vec<u8>, BondLifecycleError> {
    let domain: SignatureDomain = SignatureDomain {
        chain_id: context.chain_id().clone(),
        protocol_version: context.protocol_version(),
        epoch: context.epoch(),
        message_type: SignatureMessageType::new("FastPathBondLifecycle")
            .map_err(|_| BondLifecycleError::Invalid("bond lifecycle message type"))?,
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    Ok(crypto::frame_signature_message(
        &domain,
        intent_digest.bytes().as_slice(),
    )?)
}

/// Digest binding one exact [`FastPathBondRecord`] generation into the
/// transition chain [`genesis::verify_fastpath_bond_chain`] later re-walks.
pub(crate) fn bond_row_digest(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    bytes: &[u8],
) -> Result<Digest32, NodeCoreError> {
    Ok(resolver.hash_for_purpose(epoch, HashPurpose::ExecutionEffects, bytes)?)
}

/// One authenticated leg, or explicit absence, per operation shape.
#[allow(clippy::large_enum_variant)]
enum OperationLegs {
    Deposit {
        leg: AuthenticatedLocalExecutionIntent,
    },
    Replace {
        deposit_leg: AuthenticatedLocalExecutionIntent,
        release_leg: AuthenticatedLocalExecutionIntent,
        release_recipient: Address,
    },
    Unbond {
        recipient: Address,
    },
    Withdraw {
        leg: AuthenticatedLocalExecutionIntent,
    },
    Reactivate {
        leg: AuthenticatedLocalExecutionIntent,
    },
}

impl OperationLegs {
    fn iter(&self) -> Vec<&AuthenticatedLocalExecutionIntent> {
        match self {
            Self::Deposit { leg } | Self::Withdraw { leg } | Self::Reactivate { leg } => {
                vec![leg]
            }
            Self::Replace {
                deposit_leg,
                release_leg,
                ..
            } => vec![deposit_leg, release_leg],
            Self::Unbond { .. } => Vec::new(),
        }
    }
}

/// Authenticates every embedded leg through the exact existing
/// `ExecuteLocalContract` domain, before any storage read.
fn authenticate_legs(
    resolver: &HashSuiteResolver,
    leg_policy: &LocalExecutionPolicy,
    operation: &BondLifecycleOperation,
) -> Result<OperationLegs, BondLifecycleError> {
    let authenticate =
        |bytes: &[u8]| -> Result<AuthenticatedLocalExecutionIntent, BondLifecycleError> {
            Ok(authenticate_local_execution(resolver, leg_policy, bytes)?)
        };
    Ok(match operation {
        BondLifecycleOperation::Deposit { leg } => OperationLegs::Deposit {
            leg: authenticate(leg)?,
        },
        BondLifecycleOperation::Withdraw { leg } => OperationLegs::Withdraw {
            leg: authenticate(leg)?,
        },
        BondLifecycleOperation::Reactivate { leg } => OperationLegs::Reactivate {
            leg: authenticate(leg)?,
        },
        BondLifecycleOperation::Replace {
            deposit_leg,
            release_leg,
            release_recipient,
        } => OperationLegs::Replace {
            deposit_leg: authenticate(deposit_leg)?,
            release_leg: authenticate(release_leg)?,
            release_recipient: *release_recipient,
        },
        BondLifecycleOperation::Unbond { recipient } => OperationLegs::Unbond {
            recipient: *recipient,
        },
    })
}

/// Reads the signed `0x642C/v1` economics policy installed under the
/// resource's own genesis-pinned publication context -- never the current
/// operation's epoch-varying context.
fn read_economics_policy<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resource_context: &PublicationContext,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<FastPathEconomicsPolicy, BondLifecycleError> {
    let key: Vec<u8> = local_instance_state::fastpath_economics_policy_key(resource_context)?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if let Some(old) = reads.insert(key, observed.revision())
        && old != observed.revision()
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    let bytes: &[u8] = observed.value().ok_or(BondLifecycleError::Invalid(
        "fast-path economics policy not installed",
    ))?;
    Ok(decode_fastpath_economics_policy(bytes)?)
}

fn resource_policy(
    policy: &FastPathEconomicsPolicy,
    resource_domain: u16,
    resource: [u8; 32],
) -> Result<&FastPathEconomicsResourcePolicy, BondLifecycleError> {
    let resource_id: BondResourceId = BondResourceId::new(resource_domain, resource)?;
    policy
        .resources
        .binary_search_by_key(&resource_id, |candidate| candidate.resource_id)
        .ok()
        .map(|index: usize| &policy.resources[index])
        .ok_or(BondLifecycleError::Invalid(
            "bond resource absent from economics policy",
        ))
}

fn bond_config(
    resource: &FastPathEconomicsResourcePolicy,
) -> Result<&BondResourceConfig, BondLifecycleError> {
    resource.bond.as_ref().ok_or(BondLifecycleError::Invalid(
        "bond resource is not bond-enabled",
    ))
}

fn custody_scope(
    resource_context: &PublicationContext,
    validator_id: ValidatorId,
    resource: [u8; 32],
) -> ProtocolCustodyScope {
    ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::BondCollateral,
        chain_id: resource_context.chain_id().clone(),
        subject: *validator_id.as_bytes(),
        resource,
    }
}

/// Constructs the deposit-direction capability and returns it with the
/// exact sender-owned source object the leg declared.
fn deposit_capability(
    resolver: &HashSuiteResolver,
    current_context: &PublicationContext,
    resource: &FastPathEconomicsResourcePolicy,
    scope: ProtocolCustodyScope,
    leg: &AuthenticatedLocalExecutionIntent,
) -> Result<(ProtocolCustodyCapability, ObjectId, Digest32), BondLifecycleError> {
    let call = &leg.intent().call;
    if call.context != *current_context
        || call.access.entries.len() != 1
        || call.access.entries[0].mode != AccessMode::Write
        || call.entrypoint != resource.transfer_entrypoint
        || call.code != resource.code
        || call.instance != resource.instance
    {
        return Err(BondLifecycleError::Invalid("bond deposit leg target"));
    }
    let source: ObjectId = call.access.entries[0].object_ref.id;
    let target: ProtocolCustodyTarget = ProtocolCustodyTarget::new(
        resource.instance.clone(),
        resource.code.clone(),
        resource.ty.clone(),
        resource.schema,
        resource.transfer_entrypoint.clone(),
    )?;
    let event_digest: Digest32 = local_execution_event_digest(resolver, leg.signed())?;
    let capability: ProtocolCustodyCapability = ProtocolCustodyCapability::new(
        resolver,
        current_context.clone(),
        target,
        ProtocolCustodyDirection::Deposit { source, scope },
        call.sender,
        event_digest,
    )?;
    Ok((capability, source, event_digest))
}

/// Constructs the release-direction capability for the exact current
/// custody object and validator-authorized recipient.
#[allow(clippy::too_many_arguments)]
fn release_capability(
    resolver: &HashSuiteResolver,
    current_context: &PublicationContext,
    resource: &FastPathEconomicsResourcePolicy,
    scope: ProtocolCustodyScope,
    custody: ObjectId,
    recipient: Address,
    leg: &AuthenticatedLocalExecutionIntent,
) -> Result<(ProtocolCustodyCapability, Digest32), BondLifecycleError> {
    let call = &leg.intent().call;
    if call.context != *current_context
        || call.access.entries.len() != 1
        || call.access.entries[0].mode != AccessMode::Write
        || call.access.entries[0].object_ref.id != custody
        || call.entrypoint != resource.transfer_entrypoint
        || call.code != resource.code
        || call.instance != resource.instance
    {
        return Err(BondLifecycleError::Invalid("bond release leg target"));
    }
    let target: ProtocolCustodyTarget = ProtocolCustodyTarget::new(
        resource.instance.clone(),
        resource.code.clone(),
        resource.ty.clone(),
        resource.schema,
        resource.transfer_entrypoint.clone(),
    )?;
    let event_digest: Digest32 = local_execution_event_digest(resolver, leg.signed())?;
    let capability: ProtocolCustodyCapability = ProtocolCustodyCapability::new(
        resolver,
        current_context.clone(),
        target,
        ProtocolCustodyDirection::Release {
            custody,
            scope,
            recipient,
        },
        call.sender,
        event_digest,
    )?;
    Ok((capability, event_digest))
}

/// Shared context threaded through every operation branch. `bond` is the
/// exact row read and signature-checked before dispatch; every branch
/// mutates it into `new_bond` and hands both to [`commit`].
#[allow(clippy::too_many_arguments)]
struct Preamble<'a, S: StructuredDurableDomainStateStore, E: LocalContractEngine + ?Sized> {
    store: &'a S,
    blob_store: &'a dyn BlobStore,
    context: &'a DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &'a HashSuiteResolver,
    history: &'a [HashSuiteResolver],
    leg_policy: &'a LocalExecutionPolicy,
    engine: &'a E,
    created_checkpoint: u64,
    current_context: PublicationContext,
    request_id: RequestId,
    signed: SignedBondLifecycleIntent,
    signed_bytes: Vec<u8>,
    receipt_digest: Digest32,
    bond_key: Vec<u8>,
    bond_row_revision: StateRevision,
    previous_bond_bytes: Vec<u8>,
    bond: FastPathBondRecord,
    validator_set: ValidatorSet,
    reads: BTreeMap<Vec<u8>, StateRevision>,
}

/// Authenticates then reconciles replay before any epoch, policy, object,
/// ABI or other storage read; only then reads the committed bond row and
/// verifies its own committed validator signature. Dispatches into exactly
/// one of [`deposit`], [`replace`], [`unbond`] or [`withdraw`], each of
/// which performs its own policy/live-set/nonce/lock/publication/object/
/// execution work and commits through [`commit`].
#[allow(clippy::too_many_arguments)]
pub fn handle_bond_lifecycle<S, E>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    leg_policy: &LocalExecutionPolicy,
    engine: &E,
    signed_bytes: &[u8],
    created_checkpoint: u64,
) -> Result<NodeOutput, BondLifecycleError>
where
    S: StructuredDurableDomainStateStore,
    E: LocalContractEngine + ?Sized,
{
    if history.len() > publication::MAX_PUBLICATION_HISTORY {
        return Err(BondLifecycleError::Invalid("resolver history bound"));
    }
    // 1. bounded canonical decode and structural checks.
    let signed: SignedBondLifecycleIntent = decode_signed_bond_lifecycle_intent(signed_bytes)?;
    if signed.intent.context != *expected {
        return Err(BondLifecycleError::Invalid("bond lifecycle context"));
    }

    // 2. authenticate every inner local-execution leg.
    let legs: OperationLegs = authenticate_legs(resolver, leg_policy, &signed.intent.operation)?;

    // 2b. every leg's own signed request id must equal the outer intent's:
    // this closes ordinary-path/outer-path dedup, since both share the same
    // `DurableRequestId` namespace -- whichever path commits first for this
    // request id makes any later replay of the same leg bytes through the
    // other path fail closed as a conflicting receipt.
    for leg in legs.iter() {
        if leg.intent().call.request_id != signed.intent.request_id {
            return Err(BondLifecycleError::Invalid(
                "bond lifecycle leg request id mismatch",
            ));
        }
    }

    // 3. reject reserved request id -- outer envelope and every leg.
    local_instance_state::reject_reserved_request_id(&signed.intent.request_id)
        .map_err(BondLifecycleError::Invalid)?;
    for leg in legs.iter() {
        local_instance_state::reject_reserved_request_id(&leg.intent().call.request_id)
            .map_err(BondLifecycleError::Invalid)?;
    }

    // 4. hash the exact canonical *signed* envelope bytes (intent and
    // signature together) for receipt/replay idempotency -- distinct from
    // the unsigned intent digest the signature itself covers (see
    // `bond_lifecycle_intent_digest`/`bond_lifecycle_receipt_digest`).
    let receipt_digest: Digest32 =
        bond_lifecycle_receipt_digest(resolver, &signed.intent.context, signed_bytes)?;
    let request_id: RequestId = RequestId::new(signed.intent.request_id)?;

    // 5. reconcile exact/conflicting replay before any epoch/policy/object/
    // ABI/storage read.
    if let Some(output) = durable_reconciliation::reconcile_receipt(
        store,
        context,
        domain,
        request_id,
        receipt_digest,
    )? {
        return Ok(output);
    }

    // 6. current epoch fence.
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let epoch_record: local_instance_state::FastPathEpochRecord =
        mutation_fence::fence_current_epoch(
            store,
            context,
            domain,
            signed.intent.context.chain_id(),
            signed.intent.context.epoch(),
            &mut reads,
        )?;

    // 7. read the committed bond row, then verify the validator signature
    // against its own committed authorization key.
    let bond_key: Vec<u8> = local_instance_state::fastpath_bond_record_key(
        signed.intent.context.chain_id(),
        &signed.intent.validator_id,
    )?;
    let bond_observed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &bond_key)?;
    let bond_row_revision: StateRevision = bond_observed.revision();
    reads.insert(bond_key.clone(), bond_row_revision);
    let previous_bond_bytes: Vec<u8> = bond_observed
        .value()
        .ok_or(BondLifecycleError::Invalid(
            "first-ever post-genesis bonding requires an existing committed bond row",
        ))?
        .to_vec();
    let bond: FastPathBondRecord = decode_fastpath_bond_record(&previous_bond_bytes)?;
    if bond.context.chain_id() != signed.intent.context.chain_id()
        || bond.validator_id != signed.intent.validator_id
    {
        return Err(BondLifecycleError::Invalid("bond row identity mismatch"));
    }
    let intent_digest: Digest32 = bond_lifecycle_intent_digest(resolver, &signed.intent)?;
    let framed: Vec<u8> = bond_lifecycle_signing_frame(&signed.intent.context, intent_digest)?;
    let verifier: Ed25519Verifier =
        Ed25519Verifier::from_verifying_key_bytes(&bond.authorization_key)?;
    if bond.authorization_scheme != SignatureSchemeId::Ed25519
        || !verifier.verify_framed(&framed, &signed.signature)?
    {
        return Err(BondLifecycleError::Invalid(
            "bond lifecycle envelope signature",
        ));
    }
    // Every transition out of `Jailed` is rejected except `Reactivate`,
    // which is the only operation this closed state machine permits from
    // `Jailed`. Evidence-driven jail itself is `handle_bond_slash`, not this
    // signed-envelope path.
    if matches!(bond.state, FastPathBondState::Jailed { .. })
        && !matches!(
            signed.intent.operation,
            BondLifecycleOperation::Reactivate { .. }
        )
    {
        return Err(BondLifecycleError::Invalid("bond is jailed"));
    }

    // The transition chain is cryptographically non-forgeable: the signer
    // committed, ahead of time, to the exact resource, current generation
    // and current row digest this operation must observe. A delayed
    // resubmission against a since-advanced row fails here.
    let resource_id: BondResourceId = BondResourceId::new(bond.resource_domain, bond.resource)
        .map_err(|_| BondLifecycleError::Invalid("bond resource invalid"))?;
    if signed.intent.resource_id != resource_id {
        return Err(BondLifecycleError::Invalid(
            "bond lifecycle resource mismatch",
        ));
    }
    if signed.intent.expected_generation != bond.generation {
        return Err(BondLifecycleError::Invalid(
            "bond lifecycle stale expected generation",
        ));
    }
    let previous_row_digest: Digest32 =
        bond_row_digest(resolver, bond.lifecycle_epoch, &previous_bond_bytes)?;
    if signed.intent.expected_previous_row_digest != previous_row_digest {
        return Err(BondLifecycleError::Invalid(
            "bond lifecycle stale expected previous row digest",
        ));
    }

    // While the validator is present in the committed current live set,
    // its registered signature scheme/key must exactly match the committed
    // bond row's own authorization scheme/key. `withdraw` additionally,
    // separately requires absence.
    let validator_set: ValidatorSet = fast_path::load_validator_set(
        store,
        context,
        domain,
        resolver,
        &signed.intent.context,
        &epoch_record,
        &mut reads,
    )
    .map_err(|_| BondLifecycleError::Invalid("bond lifecycle validator set unavailable"))?;
    if let Some(info) = validator_set.get(signed.intent.validator_id)
        && (info.signature_scheme != bond.authorization_scheme
            || info.public_key.as_slice() != bond.authorization_key.as_slice())
    {
        return Err(BondLifecycleError::Invalid(
            "bond authorization key diverges from the committed live validator set",
        ));
    }

    // 8. only now: policy/live-set/nonce/lock/publication/object/execution work.
    let preamble: Preamble<'_, S, E> = Preamble {
        store,
        blob_store,
        context,
        domain,
        resolver,
        history,
        leg_policy,
        engine,
        created_checkpoint,
        current_context: signed.intent.context.clone(),
        request_id,
        signed,
        signed_bytes: signed_bytes.to_vec(),
        receipt_digest,
        bond_key,
        bond_row_revision,
        previous_bond_bytes,
        bond,
        validator_set,
        reads,
    };
    match legs {
        OperationLegs::Deposit { leg } => deposit(preamble, leg),
        OperationLegs::Replace {
            deposit_leg,
            release_leg,
            release_recipient,
        } => replace(preamble, deposit_leg, release_leg, release_recipient),
        OperationLegs::Unbond { recipient } => unbond(preamble, recipient),
        OperationLegs::Withdraw { leg } => withdraw(preamble, leg),
        OperationLegs::Reactivate { leg } => reactivate(preamble, leg),
    }
}

/// One atomic commit: every touched object head, the new bond row, the new
/// (never overwritten) transition record, and the one outer receipt. The
/// response payload is the canonical encoded next bond row. Thin wrapper
/// over [`commit_bond_transition`] for the four validator-signed lifecycle
/// operations; [`slash::handle_bond_slash`] calls
/// [`commit_bond_transition`] directly since it has no [`Preamble`].
fn commit<S, E>(
    preamble: Preamble<'_, S, E>,
    operation: FastPathBondLifecycleOperation,
    new_bond: FastPathBondRecord,
    head_reads: Vec<DurableObjectHeadRead>,
    object_mutations: Vec<DurableObjectMutationEntry>,
    state_mutations: Vec<StateMutationEntry>,
) -> Result<NodeOutput, BondLifecycleError>
where
    S: StructuredDurableDomainStateStore,
    E: LocalContractEngine + ?Sized,
{
    let Preamble {
        store,
        context,
        domain,
        resolver,
        request_id,
        signed,
        signed_bytes,
        receipt_digest,
        bond_key,
        bond_row_revision,
        previous_bond_bytes,
        bond: previous_bond,
        created_checkpoint,
        reads,
        ..
    } = preamble;
    let expected_next_row_digest: Digest32 = signed.intent.expected_next_row_digest;
    commit_bond_transition(
        store,
        context,
        domain,
        resolver,
        request_id,
        receipt_digest,
        bond_key,
        bond_row_revision,
        previous_bond_bytes,
        previous_bond,
        created_checkpoint,
        reads,
        signed.intent.context.clone(),
        operation,
        BondTransitionAuthorization::ValidatorEnvelope {
            signed_envelope: signed_bytes,
        },
        Some(expected_next_row_digest),
        new_bond,
        head_reads,
        object_mutations,
        state_mutations,
    )
}

/// The shared atomic commit every DR-0137 bond transition -- lifecycle or
/// slash -- goes through: every touched object head, the new bond row, the
/// new (never overwritten) transition record, and the one outer receipt. The
/// response payload is the canonical encoded next bond row.
///
/// `expected_next_row_digest` is `Some` for every validator-signed lifecycle
/// transition (the signer cryptographically pinned the exact resulting row
/// ahead of execution, so deterministic execution must reproduce it exactly
/// or this fails closed before anything commits -- no coordinated rewrite of
/// this row, or any later one, can ever match a signature that was never
/// issued for it) and `None` for evidence-driven `Slash`, which has no
/// signer to pin a row ahead of time: the caller instead deterministically
/// derives `new_bond` from the committed previous row and independently
/// re-verified evidence alone, so there is nothing an attacker could
/// substitute a different resulting row against.
#[allow(clippy::too_many_arguments)]
fn commit_bond_transition<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    request_id: RequestId,
    receipt_digest: Digest32,
    bond_key: Vec<u8>,
    bond_row_revision: StateRevision,
    previous_bond_bytes: Vec<u8>,
    previous_bond: FastPathBondRecord,
    created_checkpoint: u64,
    mut reads: BTreeMap<Vec<u8>, StateRevision>,
    transition_context: PublicationContext,
    operation: FastPathBondLifecycleOperation,
    authorization: BondTransitionAuthorization,
    expected_next_row_digest: Option<Digest32>,
    new_bond: FastPathBondRecord,
    head_reads: Vec<DurableObjectHeadRead>,
    object_mutations: Vec<DurableObjectMutationEntry>,
    mut state_mutations: Vec<StateMutationEntry>,
) -> Result<NodeOutput, BondLifecycleError> {
    let new_bond_bytes: Vec<u8> = encode_fastpath_bond_record(&new_bond)?;
    // Each row's digest is hashed at its own `lifecycle_epoch`, not the
    // committing transition's epoch: this makes a row's digest a pure,
    // self-describing function of its own bytes, so
    // `genesis::verify_fastpath_bond_chain` can recompute it purely from
    // durably stored/manifest-derived bytes without tracking a separate
    // "epoch used to hash" side channel.
    let previous_digest: Digest32 = bond_row_digest(
        resolver,
        previous_bond.lifecycle_epoch,
        &previous_bond_bytes,
    )?;
    let current_digest: Digest32 =
        bond_row_digest(resolver, new_bond.lifecycle_epoch, &new_bond_bytes)?;
    if let Some(expected) = expected_next_row_digest
        && current_digest != expected
    {
        return Err(BondLifecycleError::Invalid(
            "bond lifecycle next row digest mismatch",
        ));
    }
    let transition: FastPathBondTransitionRecord = FastPathBondTransitionRecord {
        context: transition_context,
        validator_id: new_bond.validator_id,
        generation: new_bond.generation,
        previous_row_digest: previous_digest,
        current_row_digest: current_digest,
        operation,
        committed_at_checkpoint: created_checkpoint,
        authorization,
        resulting_row: new_bond_bytes.clone(),
    };
    let transition_bytes: Vec<u8> = encode_fastpath_bond_transition_record(&transition)?;
    let transition_key: Vec<u8> = local_instance_state::fastpath_bond_transition_key(
        new_bond.context.chain_id(),
        &new_bond.validator_id,
        new_bond.generation,
    )?;
    let transition_observed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &transition_key)?;
    if transition_observed.value().is_some() {
        return Err(BondLifecycleError::Invalid(
            "bond transition record already exists",
        ));
    }
    reads.insert(transition_key.clone(), transition_observed.revision());
    reads.insert(bond_key.clone(), bond_row_revision);
    state_mutations.push(StateMutationEntry::new(
        bond_key,
        StateMutation::Put(new_bond_bytes.clone()),
    )?);
    state_mutations.push(StateMutationEntry::new(
        transition_key,
        StateMutation::Put(transition_bytes),
    )?);
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(k, r)| StateReadAssertion::new(k, r))
        .collect::<Result<_, RuntimeError>>()?;
    let state: DurableStateTransaction = DurableStateTransaction::new(
        domain,
        AtomicStateReadSet::new(assertions)?,
        state_mutations,
    )?;
    let output: NodeOutput = NodeOutput::new(
        vec![NodeResponse::new(
            request_id,
            NodeResponseStatus::Accepted,
            Some(new_bond_bytes),
        )?],
        Vec::new(),
    )?;
    let dedup: NodeDedupRecord =
        NodeDedupRecord::new(request_id, receipt_digest, output.responses().to_vec())?;
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new(*request_id.as_bytes())
            .map_err(|_| BondLifecycleError::Invalid("request id"))?,
        receipt_digest,
        dedup.encode()?,
    )?;
    let transaction: DurableInvocationTransaction = DurableInvocationTransaction::new(
        domain,
        Some(state),
        DurableObjectChanges::new(head_reads, object_mutations)?,
        receipt,
        None,
    )?;
    Ok(durable_reconciliation::committed_output(
        store.commit_invocation(context, transaction),
        output,
    )?)
}

/// [`deposit`] and [`reactivate`] share identical mechanics -- a fresh
/// sender-owned whole object checked against the current committed
/// enabled/min/max policy -- and differ only in the required previous state
/// and the recorded [`FastPathBondLifecycleOperation`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DepositKind {
    /// `Exited -> Active`.
    Deposit,
    /// `Jailed -> Active`.
    Reactivate,
}

impl DepositKind {
    fn accepts(self, state: &FastPathBondState) -> bool {
        match self {
            Self::Deposit => *state == FastPathBondState::Exited,
            Self::Reactivate => matches!(state, FastPathBondState::Jailed { .. }),
        }
    }

    const fn invalid_state_message(self) -> &'static str {
        match self {
            Self::Deposit => "bond deposit requires an exited bond",
            Self::Reactivate => "bond reactivate requires a jailed bond",
        }
    }

    const fn operation(self) -> FastPathBondLifecycleOperation {
        match self {
            Self::Deposit => FastPathBondLifecycleOperation::Deposit,
            Self::Reactivate => FastPathBondLifecycleOperation::Reactivate,
        }
    }
}

/// `Exited -> Active`. Rejects a validator with no committed bond row
/// before this point ever runs (the shared preamble already required one).
fn deposit<S, E>(
    preamble: Preamble<'_, S, E>,
    leg: AuthenticatedLocalExecutionIntent,
) -> Result<NodeOutput, BondLifecycleError>
where
    S: StructuredDurableDomainStateStore,
    E: LocalContractEngine + ?Sized,
{
    deposit_or_reactivate(preamble, leg, DepositKind::Deposit)
}

/// `Jailed -> Active`. Reuses [`deposit`]'s exact mechanics: a fresh
/// sender-owned whole object, checked against the current committed
/// enabled/min/max policy exactly as a deposit is.
fn reactivate<S, E>(
    preamble: Preamble<'_, S, E>,
    leg: AuthenticatedLocalExecutionIntent,
) -> Result<NodeOutput, BondLifecycleError>
where
    S: StructuredDurableDomainStateStore,
    E: LocalContractEngine + ?Sized,
{
    deposit_or_reactivate(preamble, leg, DepositKind::Reactivate)
}

fn deposit_or_reactivate<S, E>(
    mut preamble: Preamble<'_, S, E>,
    leg: AuthenticatedLocalExecutionIntent,
    kind: DepositKind,
) -> Result<NodeOutput, BondLifecycleError>
where
    S: StructuredDurableDomainStateStore,
    E: LocalContractEngine + ?Sized,
{
    if !kind.accepts(&preamble.bond.state) {
        return Err(BondLifecycleError::Invalid(kind.invalid_state_message()));
    }
    let resource_context: PublicationContext = preamble.bond.context.clone();
    let policy: FastPathEconomicsPolicy = read_economics_policy(
        preamble.store,
        preamble.context,
        preamble.domain,
        &resource_context,
        &mut preamble.reads,
    )?;
    let resource: &FastPathEconomicsResourcePolicy = resource_policy(
        &policy,
        preamble.bond.resource_domain,
        preamble.bond.resource,
    )?;
    let bond_cfg: &BondResourceConfig = bond_config(resource)?;
    if !bond_cfg.enabled {
        return Err(BondLifecycleError::Invalid(
            "bond resource is disabled by the committed economics policy",
        ));
    }
    let scope: ProtocolCustodyScope = custody_scope(
        &resource_context,
        preamble.bond.validator_id,
        preamble.bond.resource,
    );
    let (capability, source, leg_event_digest) = deposit_capability(
        preamble.resolver,
        &preamble.current_context,
        resource,
        scope.clone(),
        &leg,
    )?;
    let call = leg.intent().call.clone();
    let nonce: PendingSenderNonceWrite = durable_reconciliation::reserve_sender_nonce_range(
        preamble.store,
        preamble.context,
        preamble.domain,
        &PersistenceLayout::new(
            preamble.current_context.chain_id().clone(),
            preamble.current_context.protocol_version(),
        ),
        SenderNonceReservation {
            sender: call.sender,
            epoch: preamble.current_context.epoch(),
            nonce: call.nonce,
        },
        1,
    )?;
    let mut head_reads: Vec<DurableObjectHeadRead> = Vec::new();
    let mut state_mutations: Vec<StateMutationEntry> = Vec::new();
    let admitted: AdmittedLeg = admit_and_execute_leg(
        preamble.store,
        preamble.blob_store,
        preamble.context,
        preamble.domain,
        preamble.resolver,
        preamble.history,
        preamble.leg_policy,
        preamble.engine,
        &leg,
        leg_event_digest,
        Some(&capability),
        preamble.created_checkpoint,
        &mut preamble.reads,
        &mut head_reads,
        &mut state_mutations,
    )?;
    if !admitted.success {
        return Err(BondLifecycleError::Invalid("bond deposit leg trapped"));
    }
    if !admitted.created_authorities.is_empty() {
        return Err(BondLifecycleError::Invalid(
            "bond deposit leg created an object",
        ));
    }
    let owner_before: Owner = Owner::Address(Address::new(call.sender));
    let owner_after: Owner = Owner::ProtocolCustody(scope);
    let snapshot: &object_snapshots::ObjectSnapshot = admitted
        .snapshots
        .get(&source)
        .ok_or(BondLifecycleError::Invalid("bond deposit source missing"))?;
    let input = admitted
        .inputs
        .iter()
        .find(|input| input.resolved.object.id == source)
        .ok_or(BondLifecycleError::Invalid("bond deposit input missing"))?;
    let (new_object, amount) = effects::validate(
        &admitted.interface,
        &input.authority,
        &effects::ExpectedCustodyTransfer {
            object_id: source,
            owner_before: &owner_before,
            owner_after: &owner_after,
        },
        preamble.created_checkpoint,
        snapshot,
        &admitted.effects,
    )?;
    if amount < bond_cfg.min_bond.get() {
        return Err(BondLifecycleError::Invalid(
            "bond deposit amount below the committed minimum",
        ));
    }
    if let Some(max_exposure) = bond_cfg.max_validator_exposure
        && amount > max_exposure.get()
    {
        return Err(BondLifecycleError::Invalid(
            "bond deposit amount exceeds the committed max validator exposure",
        ));
    }
    let (mutation_entry, digest) = effects::build_mutation_entry(
        preamble.resolver,
        &preamble.current_context,
        preamble.created_checkpoint,
        snapshot,
        &new_object,
    )?;
    reads_insert_nonce(&mut preamble.reads, &nonce);
    state_mutations.push(StateMutationEntry::new(
        nonce.key,
        StateMutation::Put(nonce.record.encode()?),
    )?);
    let deposit_epoch: Epoch = preamble.current_context.epoch();
    // Fresh collateral can only ever join the *next* validator set (DR-0137
    // eligibility gates on the *committed current* epoch, strictly before
    // this one activates): its liability floor is therefore the committing
    // epoch plus one, never the committing epoch itself, so evidence dated
    // at or before the deposit cannot forfeit collateral that was not yet
    // posted when the misbehavior happened.
    let slashable_from_epoch: Epoch = Epoch::new(
        deposit_epoch
            .get()
            .checked_add(1)
            .ok_or(BondLifecycleError::Invalid("bond slashable epoch overflow"))?,
    );
    let new_bond: FastPathBondRecord = FastPathBondRecord {
        context: resource_context,
        validator_id: preamble.bond.validator_id,
        resource_domain: preamble.bond.resource_domain,
        resource: preamble.bond.resource,
        custody_object: ObjectRef {
            id: new_object.id,
            version: new_object.version,
            digest,
        },
        // This deposit/reactivate leg mints the fresh object ref this row
        // now carries, at exactly the committing epoch.
        custody_object_epoch: deposit_epoch,
        authority: input.authority.clone(),
        amount,
        committed_at_checkpoint: preamble.created_checkpoint,
        generation: preamble
            .bond
            .generation
            .checked_add(1)
            .ok_or(BondLifecycleError::Invalid("bond generation overflow"))?,
        lifecycle_epoch: deposit_epoch,
        slashable_from_epoch,
        required_minimum: bond_cfg.min_bond.get(),
        state: FastPathBondState::Active,
        authorization_scheme: preamble.bond.authorization_scheme,
        authorization_key: preamble.bond.authorization_key,
    };
    commit(
        preamble,
        kind.operation(),
        new_bond,
        head_reads,
        vec![mutation_entry],
        state_mutations,
    )
}

fn reads_insert_nonce(
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    nonce: &PendingSenderNonceWrite,
) {
    reads.insert(nonce.key.clone(), nonce.read_revision);
}

/// `Active -> Active`. An atomic same-sender, consecutive-nonce two-leg
/// swap: `deposit_leg` brings in the new object, `release_leg` releases the
/// exact current custody object to the validator-authorized
/// `release_recipient`.
fn replace<S, E>(
    mut preamble: Preamble<'_, S, E>,
    deposit_leg: AuthenticatedLocalExecutionIntent,
    release_leg: AuthenticatedLocalExecutionIntent,
    release_recipient: Address,
) -> Result<NodeOutput, BondLifecycleError>
where
    S: StructuredDurableDomainStateStore,
    E: LocalContractEngine + ?Sized,
{
    if preamble.bond.state != FastPathBondState::Active {
        return Err(BondLifecycleError::Invalid(
            "bond replace requires an active bond",
        ));
    }
    let deposit_call = deposit_leg.intent().call.clone();
    let release_call = release_leg.intent().call.clone();
    if deposit_call.sender != release_call.sender {
        return Err(BondLifecycleError::Invalid(
            "bond replace legs must share the same sender",
        ));
    }
    let release_nonce: u64 = deposit_call
        .nonce
        .checked_add(1)
        .ok_or(BondLifecycleError::Invalid("bond replace nonce overflow"))?;
    if release_call.nonce != release_nonce {
        return Err(BondLifecycleError::Invalid(
            "bond replace legs require consecutive nonces",
        ));
    }
    let resource_context: PublicationContext = preamble.bond.context.clone();
    let policy: FastPathEconomicsPolicy = read_economics_policy(
        preamble.store,
        preamble.context,
        preamble.domain,
        &resource_context,
        &mut preamble.reads,
    )?;
    let resource: &FastPathEconomicsResourcePolicy = resource_policy(
        &policy,
        preamble.bond.resource_domain,
        preamble.bond.resource,
    )?;
    let bond_cfg: &BondResourceConfig = bond_config(resource)?;
    if !bond_cfg.enabled {
        return Err(BondLifecycleError::Invalid(
            "bond resource is disabled by the committed economics policy",
        ));
    }
    let deposit_scope: ProtocolCustodyScope = custody_scope(
        &resource_context,
        preamble.bond.validator_id,
        preamble.bond.resource,
    );
    let release_scope: ProtocolCustodyScope = deposit_scope.clone();
    let old_custody: ObjectId = preamble.bond.custody_object.id;
    let (deposit_capability, new_source, deposit_event_digest) = deposit_capability(
        preamble.resolver,
        &preamble.current_context,
        resource,
        deposit_scope.clone(),
        &deposit_leg,
    )?;
    let (release_capability, release_event_digest) = release_capability(
        preamble.resolver,
        &preamble.current_context,
        resource,
        release_scope.clone(),
        old_custody,
        release_recipient,
        &release_leg,
    )?;
    let nonce: PendingSenderNonceWrite = durable_reconciliation::reserve_sender_nonce_range(
        preamble.store,
        preamble.context,
        preamble.domain,
        &PersistenceLayout::new(
            preamble.current_context.chain_id().clone(),
            preamble.current_context.protocol_version(),
        ),
        SenderNonceReservation {
            sender: deposit_call.sender,
            epoch: preamble.current_context.epoch(),
            nonce: deposit_call.nonce,
        },
        2,
    )?;
    let mut head_reads: Vec<DurableObjectHeadRead> = Vec::new();
    let mut state_mutations: Vec<StateMutationEntry> = Vec::new();
    let admitted_deposit: AdmittedLeg = admit_and_execute_leg(
        preamble.store,
        preamble.blob_store,
        preamble.context,
        preamble.domain,
        preamble.resolver,
        preamble.history,
        preamble.leg_policy,
        preamble.engine,
        &deposit_leg,
        deposit_event_digest,
        Some(&deposit_capability),
        preamble.created_checkpoint,
        &mut preamble.reads,
        &mut head_reads,
        &mut state_mutations,
    )?;
    if !admitted_deposit.success {
        return Err(BondLifecycleError::Invalid(
            "bond replace deposit leg trapped",
        ));
    }
    if !admitted_deposit.created_authorities.is_empty() {
        return Err(BondLifecycleError::Invalid(
            "bond replace deposit leg created an object",
        ));
    }
    let admitted_release: AdmittedLeg = admit_and_execute_leg(
        preamble.store,
        preamble.blob_store,
        preamble.context,
        preamble.domain,
        preamble.resolver,
        preamble.history,
        preamble.leg_policy,
        preamble.engine,
        &release_leg,
        release_event_digest,
        Some(&release_capability),
        preamble.created_checkpoint,
        &mut preamble.reads,
        &mut head_reads,
        &mut state_mutations,
    )?;
    if !admitted_release.success {
        return Err(BondLifecycleError::Invalid(
            "bond replace release leg trapped",
        ));
    }
    if !admitted_release.created_authorities.is_empty() {
        return Err(BondLifecycleError::Invalid(
            "bond replace release leg created an object",
        ));
    }
    let deposit_owner_before: Owner = Owner::Address(Address::new(deposit_call.sender));
    let deposit_owner_after: Owner = Owner::ProtocolCustody(deposit_scope);
    let deposit_snapshot: &object_snapshots::ObjectSnapshot = admitted_deposit
        .snapshots
        .get(&new_source)
        .ok_or(BondLifecycleError::Invalid(
            "bond replace new source missing",
        ))?;
    let deposit_input = admitted_deposit
        .inputs
        .iter()
        .find(|input| input.resolved.object.id == new_source)
        .ok_or(BondLifecycleError::Invalid(
            "bond replace new input missing",
        ))?;
    let (new_object, amount) = effects::validate(
        &admitted_deposit.interface,
        &deposit_input.authority,
        &effects::ExpectedCustodyTransfer {
            object_id: new_source,
            owner_before: &deposit_owner_before,
            owner_after: &deposit_owner_after,
        },
        preamble.created_checkpoint,
        deposit_snapshot,
        &admitted_deposit.effects,
    )?;
    if amount < bond_cfg.min_bond.get() {
        return Err(BondLifecycleError::Invalid(
            "bond replace amount below the committed minimum",
        ));
    }
    if let Some(max_exposure) = bond_cfg.max_validator_exposure
        && amount > max_exposure.get()
    {
        return Err(BondLifecycleError::Invalid(
            "bond replace amount exceeds the committed max validator exposure",
        ));
    }
    // Non-decreasing: `Replace` releases the *entire* old collateral object
    // (see `release_leg` below), so permitting a smaller replacement amount
    // -- while still passing the committed minimum -- would let a validator
    // reduce its live collateral instantly and without the `Unbond`/
    // `Withdraw` delay, evading full forfeiture for any pre-existing
    // liability window on the released amount. Any legitimate reduction
    // must go through `Unbond`/`Withdraw` instead.
    if amount < preamble.bond.amount {
        return Err(BondLifecycleError::Invalid(
            "bond replace amount below the previous live bond amount",
        ));
    }
    let release_owner_before: Owner = Owner::ProtocolCustody(release_scope);
    let release_owner_after: Owner = Owner::Address(release_recipient);
    let release_snapshot: &object_snapshots::ObjectSnapshot = admitted_release
        .snapshots
        .get(&old_custody)
        .ok_or(BondLifecycleError::Invalid(
            "bond replace old custody object missing",
        ))?;
    let release_input = admitted_release
        .inputs
        .iter()
        .find(|input| input.resolved.object.id == old_custody)
        .ok_or(BondLifecycleError::Invalid(
            "bond replace old custody input missing",
        ))?;
    let (released_object, _released_amount) = effects::validate(
        &admitted_release.interface,
        &release_input.authority,
        &effects::ExpectedCustodyTransfer {
            object_id: old_custody,
            owner_before: &release_owner_before,
            owner_after: &release_owner_after,
        },
        preamble.created_checkpoint,
        release_snapshot,
        &admitted_release.effects,
    )?;
    let (deposit_mutation, deposit_digest) = effects::build_mutation_entry(
        preamble.resolver,
        &preamble.current_context,
        preamble.created_checkpoint,
        deposit_snapshot,
        &new_object,
    )?;
    let (release_mutation, _release_digest) = effects::build_mutation_entry(
        preamble.resolver,
        &preamble.current_context,
        preamble.created_checkpoint,
        release_snapshot,
        &released_object,
    )?;
    reads_insert_nonce(&mut preamble.reads, &nonce);
    state_mutations.push(StateMutationEntry::new(
        nonce.key,
        StateMutation::Put(nonce.record.encode()?),
    )?);
    let new_bond: FastPathBondRecord = FastPathBondRecord {
        context: resource_context,
        validator_id: preamble.bond.validator_id,
        resource_domain: preamble.bond.resource_domain,
        resource: preamble.bond.resource,
        custody_object: ObjectRef {
            id: new_object.id,
            version: new_object.version,
            digest: deposit_digest,
        },
        // Replace mints a fresh object ref at exactly the committing epoch.
        custody_object_epoch: preamble.current_context.epoch(),
        authority: deposit_input.authority.clone(),
        amount,
        committed_at_checkpoint: preamble.created_checkpoint,
        generation: preamble
            .bond
            .generation
            .checked_add(1)
            .ok_or(BondLifecycleError::Invalid("bond generation overflow"))?,
        lifecycle_epoch: preamble.current_context.epoch(),
        // Liability provenance survives a same-state collateral swap:
        // `Replace` preserves the previous row's floor exactly rather than
        // resetting it, since the validator's underlying liability window
        // never closed.
        slashable_from_epoch: preamble.bond.slashable_from_epoch,
        required_minimum: bond_cfg.min_bond.get(),
        state: FastPathBondState::Active,
        authorization_scheme: preamble.bond.authorization_scheme,
        authorization_key: preamble.bond.authorization_key,
    };
    commit(
        preamble,
        FastPathBondLifecycleOperation::Replace,
        new_bond,
        head_reads,
        vec![deposit_mutation, release_mutation],
        state_mutations,
    )
}

/// `Active -> Unbonding`. No contract execution: the custody object and its
/// authority are carried forward unchanged.
fn unbond<S, E>(
    mut preamble: Preamble<'_, S, E>,
    recipient: Address,
) -> Result<NodeOutput, BondLifecycleError>
where
    S: StructuredDurableDomainStateStore,
    E: LocalContractEngine + ?Sized,
{
    if preamble.bond.state != FastPathBondState::Active {
        return Err(BondLifecycleError::Invalid(
            "bond unbond requires an active bond",
        ));
    }
    validate_ed25519_owner_address(
        recipient.as_bytes(),
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )
    .map_err(|_| BondLifecycleError::Invalid("bond unbond recipient address"))?;
    let resource_context: PublicationContext = preamble.bond.context.clone();
    let policy: FastPathEconomicsPolicy = read_economics_policy(
        preamble.store,
        preamble.context,
        preamble.domain,
        &resource_context,
        &mut preamble.reads,
    )?;
    let resource: &FastPathEconomicsResourcePolicy = resource_policy(
        &policy,
        preamble.bond.resource_domain,
        preamble.bond.resource,
    )?;
    let bond_cfg: &BondResourceConfig = bond_config(resource)?;
    let current_epoch: Epoch = preamble.current_context.epoch();
    let unlock_epoch: Epoch = Epoch::new(
        current_epoch
            .get()
            .checked_add(bond_cfg.unbonding_epochs)
            .ok_or(BondLifecycleError::Invalid("bond unlock epoch overflow"))?,
    );
    let new_bond: FastPathBondRecord = FastPathBondRecord {
        context: resource_context,
        validator_id: preamble.bond.validator_id,
        resource_domain: preamble.bond.resource_domain,
        resource: preamble.bond.resource,
        custody_object: preamble.bond.custody_object.clone(),
        // `Unbond` executes no leg and never touches the custody object: the
        // digest-provenance epoch is carried forward unchanged even though
        // `lifecycle_epoch` itself advances to this transition's own epoch.
        custody_object_epoch: preamble.bond.custody_object_epoch,
        authority: preamble.bond.authority.clone(),
        amount: preamble.bond.amount,
        committed_at_checkpoint: preamble.created_checkpoint,
        generation: preamble
            .bond
            .generation
            .checked_add(1)
            .ok_or(BondLifecycleError::Invalid("bond generation overflow"))?,
        lifecycle_epoch: current_epoch,
        // Preserved exactly from the current row: liability provenance
        // survives entering `Unbonding`, and a later policy minimum raise
        // must not strand an existing, already-eligible bond.
        slashable_from_epoch: preamble.bond.slashable_from_epoch,
        required_minimum: preamble.bond.required_minimum,
        state: FastPathBondState::Unbonding {
            unlock_epoch,
            recipient: *recipient.as_bytes(),
        },
        authorization_scheme: preamble.bond.authorization_scheme,
        authorization_key: preamble.bond.authorization_key,
    };
    commit(
        preamble,
        FastPathBondLifecycleOperation::Unbond,
        new_bond,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

/// `Unbonding -> Exited`. Requires the unlock delay to have elapsed and the
/// validator to be absent from the committed live validator set, then
/// releases the current custody object to the exact recipient already
/// recorded by [`unbond`].
fn withdraw<S, E>(
    mut preamble: Preamble<'_, S, E>,
    leg: AuthenticatedLocalExecutionIntent,
) -> Result<NodeOutput, BondLifecycleError>
where
    S: StructuredDurableDomainStateStore,
    E: LocalContractEngine + ?Sized,
{
    let (unlock_epoch, recorded_recipient): (Epoch, [u8; 32]) = match preamble.bond.state {
        FastPathBondState::Unbonding {
            unlock_epoch,
            recipient,
        } => (unlock_epoch, recipient),
        _ => {
            return Err(BondLifecycleError::Invalid(
                "bond withdraw requires an unbonding bond",
            ));
        }
    };
    let current_epoch: Epoch = preamble.current_context.epoch();
    if current_epoch.get() < unlock_epoch.get() {
        return Err(BondLifecycleError::Invalid(
            "bond withdraw before the unlock epoch",
        ));
    }
    // The shared preamble already loaded the committed live validator set
    // (and cross-checked its key when present); withdraw's own additional
    // requirement is the validator's exact absence from it.
    if preamble
        .validator_set
        .get(preamble.bond.validator_id)
        .is_some()
    {
        return Err(BondLifecycleError::Invalid(
            "bond withdraw requires absence from the committed live validator set",
        ));
    }
    let recipient: Address = Address::new(recorded_recipient);
    let resource_context: PublicationContext = preamble.bond.context.clone();
    let policy: FastPathEconomicsPolicy = read_economics_policy(
        preamble.store,
        preamble.context,
        preamble.domain,
        &resource_context,
        &mut preamble.reads,
    )?;
    // Deliberately does not require `resource.bond` to still be enabled: a
    // later policy change disabling this resource for new bonds must not
    // strand a validator that is already exiting through it.
    let resource: &FastPathEconomicsResourcePolicy = resource_policy(
        &policy,
        preamble.bond.resource_domain,
        preamble.bond.resource,
    )?;
    let scope: ProtocolCustodyScope = custody_scope(
        &resource_context,
        preamble.bond.validator_id,
        preamble.bond.resource,
    );
    let custody: ObjectId = preamble.bond.custody_object.id;
    let (capability, leg_event_digest) = release_capability(
        preamble.resolver,
        &preamble.current_context,
        resource,
        scope.clone(),
        custody,
        recipient,
        &leg,
    )?;
    let call = leg.intent().call.clone();
    let nonce: PendingSenderNonceWrite = durable_reconciliation::reserve_sender_nonce_range(
        preamble.store,
        preamble.context,
        preamble.domain,
        &PersistenceLayout::new(
            preamble.current_context.chain_id().clone(),
            preamble.current_context.protocol_version(),
        ),
        SenderNonceReservation {
            sender: call.sender,
            epoch: preamble.current_context.epoch(),
            nonce: call.nonce,
        },
        1,
    )?;
    let mut head_reads: Vec<DurableObjectHeadRead> = Vec::new();
    let mut state_mutations: Vec<StateMutationEntry> = Vec::new();
    let admitted: AdmittedLeg = admit_and_execute_leg(
        preamble.store,
        preamble.blob_store,
        preamble.context,
        preamble.domain,
        preamble.resolver,
        preamble.history,
        preamble.leg_policy,
        preamble.engine,
        &leg,
        leg_event_digest,
        Some(&capability),
        preamble.created_checkpoint,
        &mut preamble.reads,
        &mut head_reads,
        &mut state_mutations,
    )?;
    if !admitted.success {
        return Err(BondLifecycleError::Invalid("bond withdraw leg trapped"));
    }
    if !admitted.created_authorities.is_empty() {
        return Err(BondLifecycleError::Invalid(
            "bond withdraw leg created an object",
        ));
    }
    let owner_before: Owner = Owner::ProtocolCustody(scope);
    let owner_after: Owner = Owner::Address(recipient);
    let snapshot: &object_snapshots::ObjectSnapshot = admitted
        .snapshots
        .get(&custody)
        .ok_or(BondLifecycleError::Invalid("bond withdraw custody missing"))?;
    let input = admitted
        .inputs
        .iter()
        .find(|input| input.resolved.object.id == custody)
        .ok_or(BondLifecycleError::Invalid("bond withdraw input missing"))?;
    let (new_object, _amount) = effects::validate(
        &admitted.interface,
        &input.authority,
        &effects::ExpectedCustodyTransfer {
            object_id: custody,
            owner_before: &owner_before,
            owner_after: &owner_after,
        },
        preamble.created_checkpoint,
        snapshot,
        &admitted.effects,
    )?;
    let (mutation_entry, digest) = effects::build_mutation_entry(
        preamble.resolver,
        &preamble.current_context,
        preamble.created_checkpoint,
        snapshot,
        &new_object,
    )?;
    reads_insert_nonce(&mut preamble.reads, &nonce);
    state_mutations.push(StateMutationEntry::new(
        nonce.key,
        StateMutation::Put(nonce.record.encode()?),
    )?);
    let new_bond: FastPathBondRecord = FastPathBondRecord {
        context: resource_context,
        validator_id: preamble.bond.validator_id,
        resource_domain: preamble.bond.resource_domain,
        resource: preamble.bond.resource,
        custody_object: ObjectRef {
            id: new_object.id,
            version: new_object.version,
            digest,
        },
        // The release leg mints a fresh (owner-changed) object ref at
        // exactly the committing epoch, even though the object leaves
        // custody: `FastPathBondRecord::custody_object` on an `Exited` row
        // is a historical audit pointer only (see its own doc comment).
        custody_object_epoch: current_epoch,
        authority: input.authority.clone(),
        amount: preamble.bond.amount,
        committed_at_checkpoint: preamble.created_checkpoint,
        generation: preamble
            .bond
            .generation
            .checked_add(1)
            .ok_or(BondLifecycleError::Invalid("bond generation overflow"))?,
        lifecycle_epoch: current_epoch,
        // Preserved exactly from the current row, purely as audit data now
        // that the bond is no longer live -- see the `unbond` comment.
        slashable_from_epoch: preamble.bond.slashable_from_epoch,
        required_minimum: preamble.bond.required_minimum,
        state: FastPathBondState::Exited,
        authorization_scheme: preamble.bond.authorization_scheme,
        authorization_key: preamble.bond.authorization_key,
    };
    commit(
        preamble,
        FastPathBondLifecycleOperation::Withdraw,
        new_bond,
        head_reads,
        vec![mutation_entry],
        state_mutations,
    )
}
