//! DR-0137 implementation unit 4 (claim half): the closed, bounded
//! per-signer fee-claim state machine against one certified
//! [`crate::fast_path::records::FastPathSettlementRecord`] escrow row (see
//! `docs/architecture/decisions/0137-fastvote-release-authority.md`,
//! "Certified fee escrow and claims").
//!
//! One canonical envelope ([`codec::FeeClaimIntent`] `0x6437/v1`, signed as
//! `0x6438/v1`) authorizes exactly one of three closed operations against
//! the single authoritative settlement row for one certificate:
//!
//! * [`codec::FeeClaimOperation::ZeroShare`]: a zero-amount entitlement,
//!   finalized without any object or nonce I/O.
//! * [`codec::FeeClaimOperation::Split`]: a partial positive claim through
//!   the policy-pinned `split` entrypoint, releasing exactly the signed
//!   share while the escrow retains custody of every other unclaimed
//!   positive share.
//! * [`codec::FeeClaimOperation::FinalTransfer`]: the last positive claim,
//!   through the policy-pinned `transfer` entrypoint, moving the complete
//!   remaining escrow value to the signer's recipient.
//!
//! [`handle_fee_claim`] never trusts the signed envelope's own operation
//! tag: it independently derives which of the three shapes applies from the
//! committed settlement row's own remaining unclaimed positive shares (this
//! claim's own signed `share_amount`, and whether any *other* share in the
//! row remains unclaimed and positive), and rejects a signed envelope whose
//! declared operation does not match that derivation.
//!
//! Authentication and replay order follows DR-0137 exactly: bounded
//! canonical decode, the embedded leg's own signature (when present), the
//! reserved-id guard, the exact signed-envelope receipt digest, exact/
//! conflicting replay reconciliation, the committed-epoch fence, the
//! committed settlement row and its exact identity/generation/output
//! against the signed intent -- all before the chain-anchored historical
//! validator set *at the signed certificate epoch* (never current
//! membership or bond state) is loaded and the claimant's signature is
//! verified under it, which itself happens before any economics-policy,
//! object or execution work. A positive claim executes its leg through
//! [`crate::local_execution::admit_and_execute_leg`] with a narrowly scoped
//! [`execution::protocol_custody::ProtocolCustodyCapability`] (`FeeClaim`
//! direction) in [`crate::local_execution::CustodyEffectMode::Translate`]
//! mode -- the same generic path ordinary execution uses -- and [`effects`]
//! then independently validates the produced effects: exact shape, exact
//! recipient, and `u64` value conservation against the row's own currently
//! unclaimed positive share total, observed only through the signed
//! executable ABI. One atomic [`DurableInvocationTransaction`] commits every
//! touched object head, the new settlement row, the sender-nonce range (for
//! a positive claim only) and the one outer request receipt.
//!
//! The certificate-epoch paid fee policy pins the defining code context.
//! The economics policy is read at that genesis-pinned context, rather than
//! assuming the certificate was issued in the genesis epoch.
#![allow(clippy::result_large_err)]
use super::*;
use crate::economics::{
    FastPathEconomicsPolicy, FastPathEconomicsResourcePolicy, decode_fastpath_economics_policy,
};
use crate::fast_path::records::{
    FastPathFeeShare, FastPathSettlementRecord, decode_fastpath_settlement_record,
    encode_fastpath_settlement_record,
};
use crate::local_execution::{
    AdmittedLeg, CustodyEffectMode, LocalExecutionAdmissionError, admit_and_execute_leg,
};
use bonds::BondResourceId;
use crypto::{Ed25519Verifier, SignatureDomain, SignatureMessageType, SignatureVerifier};
use execution::local_execution::{
    AuthenticatedLocalExecutionIntent, LocalContractEngine, LocalExecutionError,
    LocalExecutionPolicy, authenticate_local_execution, local_execution_event_digest,
};
use execution::paid_execution::{PaidFeePolicy, decode_paid_fee_policy};
use execution::protocol_custody::{
    ProtocolCustodyCapability, ProtocolCustodyDirection, ProtocolCustodyTarget,
};
use execution::publication::PublicationContext;
use objects::{ProtocolCustodyPurpose, ProtocolCustodyScope};
use protocol_types::SignatureSchemeId;
use validator_set::ValidatorSet;

pub mod codec;
mod effects;
mod inventory;
mod verify;

pub use inventory::{
    FeeEscrowInventoryPage, FeeEscrowInventorySweep, verify_fee_escrow_inventory_all,
    verify_fee_escrow_inventory_page,
};

#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
pub(crate) mod tests;

use codec::{
    FeeClaimIntent, FeeClaimOperation, SignedFeeClaimIntent, decode_signed_fee_claim_intent,
};

/// Fail-closed DR-0137 fee-claim errors.
#[derive(Debug)]
pub enum FeeClaimError {
    /// Shared leg-admission/execution pipeline failure.
    Admission(LocalExecutionAdmissionError),
    /// `execution` crate typed-WASM or capability-construction failure.
    Execution(LocalExecutionError),
    /// Storage or node boundary failure.
    Node(NodeCoreError),
    /// DR-0133 historical-validator-set reload/re-verification failure.
    Equivocation(equivocation::EquivocationEvidenceError),
    /// Fee-claim-specific invariant failed.
    Invalid(&'static str),
}
impl fmt::Display for FeeClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => error.fmt(f),
            Self::Execution(error) => error.fmt(f),
            Self::Node(error) => error.fmt(f),
            Self::Equivocation(error) => error.fmt(f),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}
impl Error for FeeClaimError {}
impl From<LocalExecutionAdmissionError> for FeeClaimError {
    fn from(error: LocalExecutionAdmissionError) -> Self {
        Self::Admission(error)
    }
}
impl From<LocalExecutionError> for FeeClaimError {
    fn from(error: LocalExecutionError) -> Self {
        Self::Execution(error)
    }
}
impl From<NodeCoreError> for FeeClaimError {
    fn from(error: NodeCoreError) -> Self {
        Self::Node(error)
    }
}
impl From<equivocation::EquivocationEvidenceError> for FeeClaimError {
    fn from(error: equivocation::EquivocationEvidenceError) -> Self {
        Self::Equivocation(error)
    }
}
impl From<codec::FeeClaimCodecError> for FeeClaimError {
    fn from(error: codec::FeeClaimCodecError) -> Self {
        Self::Node(error.into())
    }
}
impl From<DurableReadError> for FeeClaimError {
    fn from(error: DurableReadError) -> Self {
        Self::Node(error.into())
    }
}
impl From<RuntimeError> for FeeClaimError {
    fn from(error: RuntimeError) -> Self {
        Self::Node(error.into())
    }
}
impl From<DurableInvocationError> for FeeClaimError {
    fn from(error: DurableInvocationError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalEncodingError> for FeeClaimError {
    fn from(error: CanonicalEncodingError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalDecodingError> for FeeClaimError {
    fn from(error: CanonicalDecodingError) -> Self {
        Self::Node(NodeCoreError::CanonicalDecoding(error))
    }
}
impl From<HashingError> for FeeClaimError {
    fn from(error: HashingError) -> Self {
        Self::Node(error.into())
    }
}
impl From<crypto::CryptoError> for FeeClaimError {
    fn from(error: crypto::CryptoError) -> Self {
        Self::Node(NodeCoreError::PersistenceInvariant(match error {
            crypto::CryptoError::InvalidVerificationKeyLength(_) => {
                "fee claim authorization key length"
            }
            crypto::CryptoError::MalformedVerificationKey => {
                "fee claim authorization key malformed"
            }
            crypto::CryptoError::InvalidSignatureLength(_) => "fee claim signature length",
            _ => "fee claim cryptographic failure",
        }))
    }
}

/// Digest of the exact canonical (unsigned) intent bytes alone: the exact
/// payload the claimant's signature covers ([`fee_claim_signing_frame`]).
/// Never used for receipt/replay idempotency (see [`fee_claim_receipt_digest`]).
pub(crate) fn fee_claim_intent_digest(
    resolver: &HashSuiteResolver,
    intent: &FeeClaimIntent,
) -> Result<Digest32, FeeClaimError> {
    let context: &PublicationContext = &intent.context;
    if resolver.chain_id() != context.chain_id()
        || resolver.protocol_version() != context.protocol_version()
    {
        return Err(FeeClaimError::Invalid("fee claim hash context"));
    }
    Ok(resolver.hash_for_purpose(
        context.epoch(),
        HashPurpose::NodeEvent,
        &codec::encode_fee_claim_intent(intent)?,
    )?)
}

/// Digest of the exact canonical *signed* envelope bytes (intent and
/// signature together): the receipt/replay idempotency key, kept distinct
/// from the signing digest exactly like
/// [`crate::bond_lifecycle::bond_lifecycle_receipt_digest`].
fn fee_claim_receipt_digest(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    signed_bytes: &[u8],
) -> Result<Digest32, FeeClaimError> {
    if resolver.chain_id() != context.chain_id()
        || resolver.protocol_version() != context.protocol_version()
    {
        return Err(FeeClaimError::Invalid("fee claim hash context"));
    }
    Ok(resolver.hash_for_purpose(context.epoch(), HashPurpose::NodeEvent, signed_bytes)?)
}

/// One shared Ed25519 domain for every fee-claim envelope, distinct from
/// every other FastVote signing domain (in particular
/// [`crate::bond_lifecycle::bond_lifecycle_signing_frame`]'s
/// `"FastPathBondLifecycle"`).
pub(crate) fn fee_claim_signing_frame(
    context: &PublicationContext,
    intent_digest: Digest32,
) -> Result<Vec<u8>, FeeClaimError> {
    let domain: SignatureDomain = SignatureDomain {
        chain_id: context.chain_id().clone(),
        protocol_version: context.protocol_version(),
        epoch: context.epoch(),
        message_type: SignatureMessageType::new("FastPathFeeClaim")
            .map_err(|_| FeeClaimError::Invalid("fee claim message type"))?,
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    Ok(crypto::frame_signature_message(
        &domain,
        intent_digest.bytes().as_slice(),
    )?)
}

/// Digest binding one exact settlement-row generation, hashed at the row's
/// own (fixed, certificate) context epoch -- never the current claim's
/// epoch -- so it is independently re-derivable from stored bytes alone,
/// exactly like [`crate::bond_lifecycle::bond_row_digest`].
pub(crate) fn fee_claim_row_digest(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    bytes: &[u8],
) -> Result<Digest32, NodeCoreError> {
    Ok(resolver.hash_for_purpose(epoch, HashPurpose::ExecutionEffects, bytes)?)
}

/// Derives the only permitted claim shape from the previously committed row.
/// The signed operation tag is an assertion, never the source of authority.
fn derive_claim_kind(
    settlement: &FastPathSettlementRecord,
    intent: &FeeClaimIntent,
) -> Result<(usize, u64, bool), FeeClaimError> {
    let share_index: usize = settlement
        .shares
        .iter()
        .position(|share: &FastPathFeeShare| share.validator_id == intent.validator_id)
        .ok_or(FeeClaimError::Invalid(
            "fee claim validator has no assigned share",
        ))?;
    let share: &FastPathFeeShare = &settlement.shares[share_index];
    if share.amount != intent.share_amount {
        return Err(FeeClaimError::Invalid("fee claim share amount mismatch"));
    }
    if share.claimed {
        return Err(FeeClaimError::Invalid("fee claim share already claimed"));
    }
    let mut unclaimed_positive_total: u64 = 0;
    let mut other_unclaimed_positive_remains: bool = false;
    for (index, other) in settlement.shares.iter().enumerate() {
        if other.claimed || other.amount == 0 {
            continue;
        }
        unclaimed_positive_total = unclaimed_positive_total
            .checked_add(other.amount)
            .ok_or(FeeClaimError::Invalid("fee claim unclaimed total overflow"))?;
        if index != share_index {
            other_unclaimed_positive_remains = true;
        }
    }
    let is_zero: bool = intent.share_amount == 0;
    let is_final: bool = match (&intent.operation, is_zero, other_unclaimed_positive_remains) {
        (FeeClaimOperation::ZeroShare, true, _) => false,
        (FeeClaimOperation::Split { .. }, false, true) => false,
        (FeeClaimOperation::FinalTransfer { .. }, false, false) => true,
        _ => {
            return Err(FeeClaimError::Invalid(
                "fee claim operation does not match the settlement row's derived kind",
            ));
        }
    };
    Ok((share_index, unclaimed_positive_total, is_final))
}

fn resource_policy(
    policy: &FastPathEconomicsPolicy,
    resource_id: BondResourceId,
) -> Result<&FastPathEconomicsResourcePolicy, FeeClaimError> {
    policy
        .resources
        .binary_search_by_key(&resource_id, |candidate| candidate.resource_id)
        .ok()
        .map(|index: usize| &policy.resources[index])
        .ok_or(FeeClaimError::Invalid(
            "fee resource absent from economics policy",
        ))
}

/// Reads the paid policy at the certificate epoch, then the signed
/// `0x642C/v1` economics policy at the defining code's pinned context.
/// Both reads are fenced into the claim commit.
fn read_economics_policy<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    certificate_context: &PublicationContext,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(PaidFeePolicy, FastPathEconomicsPolicy), FeeClaimError> {
    let fee_key: Vec<u8> = local_instance_state::paid_fee_policy_key(certificate_context)?;
    let fee_observed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &fee_key)?;
    if let Some(old) = reads.insert(fee_key, fee_observed.revision())
        && old != fee_observed.revision()
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    let fee_policy: PaidFeePolicy = decode_paid_fee_policy(fee_observed.value().ok_or(
        FeeClaimError::Invalid("certificate-epoch paid fee policy not installed"),
    )?)
    .map_err(|_| FeeClaimError::Invalid("certificate-epoch paid fee policy invalid"))?;
    if fee_policy.context != *certificate_context {
        return Err(FeeClaimError::Invalid(
            "certificate-epoch paid fee policy context",
        ));
    }
    let resource_context: &PublicationContext = fee_policy.code.context();
    let key: Vec<u8> = local_instance_state::fastpath_economics_policy_key(resource_context)?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if let Some(old) = reads.insert(key, observed.revision())
        && old != observed.revision()
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    let bytes: &[u8] = observed.value().ok_or(FeeClaimError::Invalid(
        "fast-path economics policy not installed",
    ))?;
    let economics: FastPathEconomicsPolicy = decode_fastpath_economics_policy(bytes)?;
    if economics.context != *resource_context {
        return Err(FeeClaimError::Invalid("fee economics policy context"));
    }
    Ok((fee_policy, economics))
}

/// Result of a read-only verification for one explicitly identified
/// certified fee escrow. This is not a scan of all escrows on a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeClaimVerificationReport {
    pub final_generation: u64,
    pub verified_claims: u64,
    pub verified_positive_claims: u64,
    /// Split payout objects verified against the claimant-signed exact ref.
    pub verified_payouts: u64,
}

/// Reconstructs the initial settlement from a quorum-certified commitment
/// witness, then independently verifies the retained signed claim chain and
/// its historical escrow-object versions and signed split payout refs after
/// a store reopen. This has no mutation and takes an explicit escrow request
/// id; use the separate typed inventory page to enumerate escrows.
///
/// Thin wrapper over [`verify_fee_claim_history_shared`], supplying the
/// point-read strategy for both the uncharged-row orphan check and the
/// retained claim chain walk; see [`inventory::verify_fee_claim_history_scanned`]
/// for the scanner-backed sibling that supplies the bounded-scan strategy
/// instead. Every other check -- certificate/witness/economics/origin -- is
/// the exact same shared code in both cases.
#[allow(clippy::too_many_arguments)]
pub fn verify_fee_claim_history<S: StructuredDurableDomainStateStore>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    chain: &ChainId,
    escrow_request_id: &[u8; 32],
) -> Result<FeeClaimVerificationReport, FeeClaimError> {
    verify_fee_claim_history_shared(
        store,
        blob_store,
        context,
        domain,
        resolver,
        history,
        chain,
        escrow_request_id,
        || {
            verify_uncharged_claim_absence_by_point_read(
                store,
                context,
                domain,
                chain,
                escrow_request_id,
            )
        },
        |trusted_resolver, validator_set, resource_abi, interface, initial, initial_bytes| {
            verify::verify_fee_claim_chain(
                store,
                blob_store,
                context,
                domain,
                trusted_resolver,
                history,
                validator_set,
                resource_abi,
                interface,
                initial,
                initial_bytes,
            )
        },
    )
}

/// Proves no fee-claim envelope was ever recorded for an uncharged
/// settlement row, using up to
/// 257 point reads (the active-validator bound plus one sentinel read)
/// each expected to observe absence. Mirrors
/// [`verify::verify_no_orphan_claims_by_point_read`]'s strategy (an uncharged
/// row is the `target_generation == 0` case) without depending on that
/// function's private visibility.
fn verify_uncharged_claim_absence_by_point_read<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    escrow_request_id: &[u8; 32],
) -> Result<(), FeeClaimError> {
    let max_claim_generation: u64 =
        u64::try_from(crate::fast_path::records::MAX_FASTPATH_ACTIVE_VALIDATORS)
            .map_err(|_| FeeClaimError::Invalid("fee claim generation bound"))?
            .checked_add(2)
            .ok_or(FeeClaimError::Invalid("fee claim generation bound"))?;
    for generation in 2..=max_claim_generation {
        let impossible_claim_key: Vec<u8> =
            local_instance_state::fastpath_fee_claim_key(chain, escrow_request_id, generation)?;
        let impossible_claim: VersionedStateValue =
            store.get_versioned_durable(context, domain, &impossible_claim_key)?;
        if impossible_claim.revision() != StateRevision::INITIAL
            || impossible_claim.value().is_some()
        {
            return Err(FeeClaimError::Invalid(
                "uncharged settlement has a claim record",
            ));
        }
    }
    Ok(())
}

/// Shared implementation behind [`verify_fee_claim_history`] and
/// [`inventory::verify_fee_claim_history_scanned`]: every certificate,
/// commitment-witness, economics-policy, code-origin, instance and escrow
/// authority check the two entry points perform is this one function's own
/// code, executed exactly once. The only two places their behavior actually
/// differs -- proving an uncharged row retains no claim record, and walking
/// plus verifying the retained claim chain -- are the two caller-supplied
/// hooks, each of which is either a point-read (the original strategy, used
/// by every non-inventory caller including a protocol transition) or a
/// single bounded scanner page (used only by the read-only inventory sweep).
#[allow(clippy::too_many_arguments)]
fn verify_fee_claim_history_shared<S, UnchargedCheck, ChainVerify>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    chain: &ChainId,
    escrow_request_id: &[u8; 32],
    verify_uncharged_claim_keys: UnchargedCheck,
    verify_claim_chain: ChainVerify,
) -> Result<FeeClaimVerificationReport, FeeClaimError>
where
    S: StructuredDurableDomainStateStore,
    UnchargedCheck: FnOnce() -> Result<(), FeeClaimError>,
    ChainVerify: FnOnce(
        &HashSuiteResolver,
        &ValidatorSet,
        &verify::FeeEscrowResourceAbi,
        &execution::publication::VerifiedPublicationInterface,
        &FastPathSettlementRecord,
        &[u8],
    ) -> Result<verify::FeeClaimChainReport, FeeClaimError>,
{
    if history.len() > publication::MAX_PUBLICATION_HISTORY {
        return Err(FeeClaimError::Invalid("resolver history bound"));
    }
    let settlement_key: Vec<u8> =
        local_instance_state::fastpath_settlement_key(chain, escrow_request_id)?;
    let installed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &settlement_key)?;
    let installed_bytes: &[u8] = installed
        .value()
        .ok_or(FeeClaimError::Invalid("fee claim settlement missing"))?;
    let installed_row: FastPathSettlementRecord =
        decode_fastpath_settlement_record(installed_bytes)?;
    if installed_row.request_id != *escrow_request_id || installed_row.context.chain_id() != chain {
        return Err(FeeClaimError::Invalid("fee claim settlement identity"));
    }
    let trusted_resolver: &HashSuiteResolver = std::iter::once(resolver)
        .chain(history)
        .find(|candidate: &&HashSuiteResolver| {
            candidate.chain_id() == chain
                && candidate.protocol_version() == installed_row.context.protocol_version()
        })
        .ok_or(FeeClaimError::Invalid(
            "fee claim historical resolver unavailable",
        ))?;

    let certificate_key: Vec<u8> =
        local_instance_state::fastpath_certificate_key(chain, escrow_request_id)?;
    let certificate_observed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &certificate_key)?;
    let certificate_record: crate::fast_path::records::FastPathCertificateRecord =
        crate::fast_path::records::decode_fastpath_certificate_record(
            certificate_observed
                .value()
                .ok_or(FeeClaimError::Invalid("fee claim certificate missing"))?,
        )?;
    if certificate_record.request_id != *escrow_request_id {
        return Err(FeeClaimError::Invalid("fee claim certificate request id"));
    }
    let certificate: consensus::FastCertificate =
        consensus::decode_fast_certificate(&certificate_record.certificate)
            .map_err(|_| FeeClaimError::Invalid("fee claim certificate encoding"))?;
    if certificate.chain_id != *chain
        || certificate.protocol_version != installed_row.context.protocol_version()
        || certificate.epoch != installed_row.context.epoch()
    {
        return Err(FeeClaimError::Invalid("fee claim certificate context"));
    }
    let certificate_context: PublicationContext = PublicationContext::new(
        certificate.chain_id.clone(),
        certificate.protocol_version,
        certificate.epoch,
    )
    .map_err(|_| FeeClaimError::Invalid("fee claim certificate context"))?;
    let validator_set: ValidatorSet = equivocation::load_historical_validator_set(
        store,
        context,
        domain,
        trusted_resolver,
        chain,
        certificate.protocol_version,
        certificate.epoch,
    )?;
    let certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        chain.clone(),
        certificate.protocol_version,
        certificate.epoch,
        validator_set.clone(),
    )
    .map_err(|_| FeeClaimError::Invalid("fee claim certificate validator set"))?;
    certifier
        .verify_certificate(&certificate, &crate::fast_path::FastPathEd25519Verifier)
        .map_err(|_| FeeClaimError::Invalid("fee claim certificate quorum signature"))?;

    let witness_key: Vec<u8> =
        local_instance_state::fastpath_commitment_witness_key(chain, escrow_request_id)?;
    let witness_observed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &witness_key)?;
    let witness_bytes: &[u8] = witness_observed.value().ok_or(FeeClaimError::Invalid(
        "fee claim commitment witness missing",
    ))?;
    let witness: crate::fast_path::commitment::DecodedCommitmentWitness =
        crate::fast_path::commitment::decode_witness(witness_bytes)?;
    let witness_digest: Digest32 = crate::fast_path::commitment::hash_witness_bytes(
        trusted_resolver,
        certificate.epoch,
        witness_bytes,
    )?;
    if witness_digest != certificate.execution_effects_hash
        || witness.event_digest != certificate.tx_hash
        || witness.paid_execution_result.request_id != *escrow_request_id
    {
        return Err(FeeClaimError::Invalid(
            "fee claim certified witness mismatch",
        ));
    }

    let charged: Option<&execution::paid_execution::PaidChargedOutcome> =
        witness.paid_execution_result.charged.as_ref();
    let Some(charged) = charged else {
        let empty_row: FastPathSettlementRecord = FastPathSettlementRecord {
            context: certificate_context,
            request_id: *escrow_request_id,
            generation: 0,
            resource_id: None,
            fee_output: None,
            fee_output_epoch: None,
            total_amount: None,
            shares: Vec::new(),
        };
        if encode_fastpath_settlement_record(&empty_row)? != installed_bytes {
            return Err(FeeClaimError::Invalid(
                "fee claim uncharged settlement mismatch",
            ));
        }
        verify_uncharged_claim_keys()?;
        return Ok(FeeClaimVerificationReport {
            final_generation: 0,
            verified_claims: 0,
            verified_positive_claims: 0,
            verified_payouts: 0,
        });
    };

    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let (fee_policy, economics): (PaidFeePolicy, FastPathEconomicsPolicy) =
        read_economics_policy(store, context, domain, &certificate_context, &mut reads)?;
    let resource_id: BondResourceId = crate::fast_path::fee_resource_id(&fee_policy)
        .map_err(|_| FeeClaimError::Invalid("fee claim certified fee resource"))?;
    let resource: &FastPathEconomicsResourcePolicy = resource_policy(&economics, resource_id)?;
    if !resource.fee_escrow
        || resource.context != *fee_policy.code.context()
        || resource.code != fee_policy.code
        || resource.instance != fee_policy.instance
        || resource.ty != fee_policy.asset_type
        || resource.schema != fee_policy.schema
    {
        return Err(FeeClaimError::Invalid(
            "fee claim economics resource mismatch",
        ));
    }
    let initial_shares: Vec<FastPathFeeShare> =
        crate::fast_path::validator_fee_shares(&validator_set, charged.actual.get())
            .map_err(|_| FeeClaimError::Invalid("fee claim initial share distribution"))?;
    let initial: FastPathSettlementRecord = FastPathSettlementRecord {
        context: certificate_context.clone(),
        request_id: *escrow_request_id,
        generation: 1,
        resource_id: Some(resource_id),
        fee_output: Some(charged.fee_output.clone()),
        fee_output_epoch: Some(certificate.epoch),
        total_amount: Some(charged.actual.get()),
        shares: initial_shares,
    };
    let initial_bytes: Vec<u8> = encode_fastpath_settlement_record(&initial)?;

    let loaded: publication::VerifiedDurablePublication = publication::load_verified_publication(
        store,
        context,
        domain,
        trusted_resolver,
        history,
        resource.code.origin(),
    )
    .map_err(|_| FeeClaimError::Invalid("fee claim code publication"))?
    .ok_or(FeeClaimError::Invalid("fee claim code publication missing"))?;
    local_execution::validate_closure(trusted_resolver, history, &loaded.interface)
        .map_err(|_| FeeClaimError::Invalid("fee claim code closure"))?;
    if !local_execution::reference_matches(&resource.code, &loaded.interface) {
        return Err(FeeClaimError::Invalid("fee claim code reference"));
    }
    let instance: execution::local_execution::InstanceRecord =
        local_execution::query_local_instance(
            store,
            context,
            domain,
            trusted_resolver,
            history,
            chain,
            resource.instance.creator,
            resource.instance.seed,
        )?
        .ok_or(FeeClaimError::Invalid(
            "fee claim resource instance missing",
        ))?;
    if instance.context != resource.context
        || instance.code != resource.code
        || execution::local_execution::instance_target(
            local_execution::original_resolver(trusted_resolver, history, &instance.context)?,
            &instance,
        )? != resource.instance
    {
        return Err(FeeClaimError::Invalid(
            "fee claim resource instance mismatch",
        ));
    }
    verify::verify_escrow_authority(
        store,
        context,
        domain,
        resource,
        &instance,
        charged.fee_output.id,
    )?;
    let resource_abi: verify::FeeEscrowResourceAbi = verify::FeeEscrowResourceAbi {
        ty: resource.ty.clone(),
        schema_version: resource.schema,
    };
    let result: verify::FeeClaimChainReport = verify_claim_chain(
        trusted_resolver,
        &validator_set,
        &resource_abi,
        &loaded.interface,
        &initial,
        &initial_bytes,
    )?;
    let verified_payouts: u64 = verify_retained_claim_legs(
        store,
        blob_store,
        context,
        domain,
        trusted_resolver,
        history,
        resource,
        &instance,
        &loaded.interface,
        &certificate_context,
        escrow_request_id,
        result.final_generation,
    )?;
    Ok(FeeClaimVerificationReport {
        final_generation: result.final_generation,
        verified_claims: result.verified_claims,
        verified_positive_claims: result.verified_positive_claims,
        verified_payouts,
    })
}

/// Re-authenticates each positive embedded leg and rechecks its exact
/// policy-pinned target. The row/object walk above proves effects on the
/// retained escrow, while this pass proves the signed leg was one the live
/// handler could have admitted at its recorded claim context.
#[allow(clippy::too_many_arguments)]
fn verify_retained_claim_legs<S: StructuredDurableDomainStateStore>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    resource: &FastPathEconomicsResourcePolicy,
    instance: &execution::local_execution::InstanceRecord,
    interface: &execution::publication::VerifiedPublicationInterface,
    certificate_context: &PublicationContext,
    escrow_request_id: &[u8; 32],
    final_generation: u64,
) -> Result<u64, FeeClaimError> {
    let mut verified_payouts: u64 = 0;
    for generation in 2..=final_generation {
        let key: Vec<u8> = local_instance_state::fastpath_fee_claim_key(
            certificate_context.chain_id(),
            escrow_request_id,
            generation,
        )?;
        let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
        let signed: SignedFeeClaimIntent = decode_signed_fee_claim_intent(
            observed
                .value()
                .ok_or(FeeClaimError::Invalid("fee claim leg envelope missing"))?,
        )?;
        let (leg_bytes, entrypoint): (&[u8], &str) = match &signed.intent.operation {
            FeeClaimOperation::ZeroShare => continue,
            FeeClaimOperation::Split { leg, .. } => (leg, &resource.split_entrypoint),
            FeeClaimOperation::FinalTransfer { leg } => (leg, &resource.transfer_entrypoint),
        };
        let decoded: execution::local_execution::SignedLocalExecutionIntent =
            execution::local_execution::decode_signed_local_execution(leg_bytes)?;
        let claim_context: PublicationContext = signed.intent.context.clone();
        let candidates: [LocalExecutionPolicy; 3] = [
            LocalExecutionPolicy::new(claim_context.clone()),
            LocalExecutionPolicy::general(claim_context.clone()),
            LocalExecutionPolicy::generic_object_results(claim_context),
        ];
        let mut matching_policy: Option<LocalExecutionPolicy> = None;
        for candidate in candidates {
            if candidate.digest(resolver)? == decoded.intent.policy_digest {
                matching_policy = Some(candidate);
                break;
            }
        }
        let policy: LocalExecutionPolicy = matching_policy.ok_or(FeeClaimError::Invalid(
            "fee claim historical leg policy digest",
        ))?;
        let policy_key: Vec<u8> = local_instance_state::execution_policy_key_for_profile(
            policy.context(),
            policy.profile(),
        )?;
        let policy_observed: VersionedStateValue =
            store.get_versioned_durable(context, domain, &policy_key)?;
        if policy_observed.value() != Some(policy.encode()?.as_slice()) {
            return Err(FeeClaimError::Invalid(
                "fee claim historical leg policy absent or different",
            ));
        }
        let leg: AuthenticatedLocalExecutionIntent =
            authenticate_local_execution(resolver, &policy, leg_bytes)?;
        if leg.intent().call.request_id != signed.intent.request_id {
            return Err(FeeClaimError::Invalid("fee claim leg request id mismatch"));
        }
        let scope: ProtocolCustodyScope = fee_escrow_scope(
            certificate_context,
            *escrow_request_id,
            signed.intent.resource_id,
        );
        let (_, event_digest): (ProtocolCustodyCapability, Digest32) = fee_claim_capability(
            resolver,
            &signed.intent.context,
            resource,
            scope,
            &signed.intent.expected_fee_output,
            signed.intent.recipient,
            entrypoint,
            &leg,
        )?;
        let payouts: u64 = verify::verify_signed_payout(
            store,
            blob_store,
            context,
            domain,
            resolver,
            history,
            resource,
            instance,
            interface,
            &signed.intent,
            event_digest,
        )?;
        verified_payouts = verified_payouts
            .checked_add(payouts)
            .ok_or(FeeClaimError::Invalid("fee claim payout count overflow"))?;
    }
    Ok(verified_payouts)
}

fn fee_escrow_scope(
    certificate_context: &PublicationContext,
    escrow_request_id: [u8; 32],
    resource_id: BondResourceId,
) -> ProtocolCustodyScope {
    ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::FeeEscrow,
        chain_id: certificate_context.chain_id().clone(),
        subject: escrow_request_id,
        resource: *resource_id.value(),
    }
}

/// Constructs the `FeeClaim`-direction capability for the exact current
/// escrow object and claimant-signed recipient, and checks the leg targets
/// exactly the policy-pinned resource/entrypoint before any execution.
#[allow(clippy::too_many_arguments)]
fn fee_claim_capability(
    resolver: &HashSuiteResolver,
    current_context: &PublicationContext,
    resource: &FastPathEconomicsResourcePolicy,
    scope: ProtocolCustodyScope,
    escrow: &ObjectRef,
    recipient: Address,
    entrypoint: &str,
    leg: &AuthenticatedLocalExecutionIntent,
) -> Result<(ProtocolCustodyCapability, Digest32), FeeClaimError> {
    let call = &leg.intent().call;
    if call.context != *current_context
        || call.access.entries.len() != 1
        || call.access.entries[0].mode != AccessMode::Write
        || call.access.entries[0].object_ref != *escrow
        || call.entrypoint != entrypoint
        || call.code != resource.code
        || call.instance != resource.instance
    {
        return Err(FeeClaimError::Invalid("fee claim leg target"));
    }
    let target: ProtocolCustodyTarget = ProtocolCustodyTarget::new(
        resource.instance.clone(),
        resource.code.clone(),
        resource.ty.clone(),
        resource.schema,
        entrypoint.to_owned(),
    )?;
    let event_digest: Digest32 = local_execution_event_digest(resolver, leg.signed())?;
    let capability: ProtocolCustodyCapability = ProtocolCustodyCapability::new(
        resolver,
        current_context.clone(),
        target,
        ProtocolCustodyDirection::FeeClaim {
            custody: escrow.id,
            scope,
            recipient,
        },
        call.sender,
        event_digest,
    )?;
    Ok((capability, event_digest))
}

/// Authenticates then reconciles replay before any epoch, policy, object,
/// ABI or other storage read; only then reads the committed settlement row,
/// derives the exact claim kind from its own bookkeeping, and loads and
/// verifies against the chain-anchored historical validator set at the
/// signed certificate epoch. Dispatches into a zero-I/O claim or a
/// leg-executing positive claim, each committing through [`commit`].
#[allow(clippy::too_many_arguments)]
pub fn handle_fee_claim<S, E>(
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
) -> Result<NodeOutput, FeeClaimError>
where
    S: StructuredDurableDomainStateStore,
    E: LocalContractEngine + ?Sized,
{
    if history.len() > publication::MAX_PUBLICATION_HISTORY {
        return Err(FeeClaimError::Invalid("resolver history bound"));
    }

    // 1. bounded canonical decode and structural checks.
    let signed: SignedFeeClaimIntent = decode_signed_fee_claim_intent(signed_bytes)?;
    if signed.intent.context != *expected {
        return Err(FeeClaimError::Invalid("fee claim context"));
    }

    // 2. authenticate the embedded leg, if any, through the exact existing
    // `ExecuteLocalContract` domain, before any storage read.
    let leg: Option<AuthenticatedLocalExecutionIntent> = match &signed.intent.operation {
        FeeClaimOperation::ZeroShare => None,
        FeeClaimOperation::Split { leg, .. } | FeeClaimOperation::FinalTransfer { leg } => {
            Some(authenticate_local_execution(resolver, leg_policy, leg)?)
        }
    };

    // 2b. the leg's own signed request id must equal the outer intent's:
    // this closes ordinary-path/outer-path dedup exactly like
    // `bond_lifecycle`'s identical requirement.
    if let Some(leg) = &leg
        && leg.intent().call.request_id != signed.intent.request_id
    {
        return Err(FeeClaimError::Invalid("fee claim leg request id mismatch"));
    }

    // 3. reject reserved request id -- outer envelope and the leg.
    local_instance_state::reject_reserved_request_id(&signed.intent.request_id)
        .map_err(FeeClaimError::Invalid)?;
    if let Some(leg) = &leg {
        local_instance_state::reject_reserved_request_id(&leg.intent().call.request_id)
            .map_err(FeeClaimError::Invalid)?;
    }

    // 4. hash the exact canonical *signed* envelope bytes (intent and
    // signature together) for receipt/replay idempotency.
    let receipt_digest: Digest32 =
        fee_claim_receipt_digest(resolver, &signed.intent.context, signed_bytes)?;
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
    // Keep this v1 Split refusal *after* reconciliation: an exact replay of
    // a previously committed v1 claim must return its old receipt, while a
    // fresh v1 Split can no longer create an unprovable payout.
    if matches!(
        signed.intent.operation,
        FeeClaimOperation::Split {
            expected_payout: None,
            ..
        }
    ) {
        return Err(FeeClaimError::Invalid("legacy split payout is not signed"));
    }

    // 6. current epoch fence.
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    mutation_fence::fence_current_epoch(
        store,
        context,
        domain,
        signed.intent.context.chain_id(),
        signed.intent.context.epoch(),
        &mut reads,
    )?;

    // 7. read + CAS-fence the committed settlement row.
    let settlement_key: Vec<u8> = local_instance_state::fastpath_settlement_key(
        signed.intent.context.chain_id(),
        &signed.intent.escrow_request_id,
    )?;
    let settlement_observed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &settlement_key)?;
    let settlement_row_revision: StateRevision = settlement_observed.revision();
    reads.insert(settlement_key.clone(), settlement_row_revision);
    let previous_settlement_bytes: Vec<u8> = settlement_observed
        .value()
        .ok_or(FeeClaimError::Invalid(
            "fee claim requires an existing committed settlement row",
        ))?
        .to_vec();
    let settlement: FastPathSettlementRecord =
        decode_fastpath_settlement_record(&previous_settlement_bytes)?;

    // 8. exact row context/certificate-epoch/request-id/generation against
    // the signed intent, and the row must actually be charged.
    if settlement.request_id != signed.intent.escrow_request_id
        || settlement.context.chain_id() != signed.intent.context.chain_id()
        || settlement.context.protocol_version() != signed.intent.context.protocol_version()
        || settlement.context.epoch() != signed.intent.certificate_epoch
        || settlement.generation != signed.intent.expected_generation
    {
        return Err(FeeClaimError::Invalid(
            "fee claim settlement identity mismatch",
        ));
    }
    let (resource_id, fee_output): (BondResourceId, ObjectRef) = match (
        settlement.resource_id,
        settlement.fee_output.clone(),
        settlement.fee_output_epoch,
        settlement.total_amount,
    ) {
        (Some(resource_id), Some(fee_output), Some(_), Some(_)) => (resource_id, fee_output),
        _ => {
            return Err(FeeClaimError::Invalid(
                "fee claim against an uncharged settlement row",
            ));
        }
    };
    if resource_id != signed.intent.resource_id || fee_output != signed.intent.expected_fee_output {
        return Err(FeeClaimError::Invalid(
            "fee claim settlement resource or output mismatch",
        ));
    }

    // Cryptographically non-forgeable transition chain: the signer commits
    // ahead of execution to the exact previous row digest it observed,
    // exactly like `bond_lifecycle::BondLifecycleIntent`.
    let previous_row_digest: Digest32 = fee_claim_row_digest(
        resolver,
        settlement.context.epoch(),
        &previous_settlement_bytes,
    )?;
    if previous_row_digest != signed.intent.expected_previous_row_digest {
        return Err(FeeClaimError::Invalid(
            "fee claim stale expected previous row digest",
        ));
    }

    // 9. exact share lookup, unclaimed positive total and the derived
    // operation kind -- never trusting the signed envelope's own tag.
    let (share_index, unclaimed_positive_total, is_final): (usize, u64, bool) =
        derive_claim_kind(&settlement, &signed.intent)?;
    let is_zero: bool = signed.intent.share_amount == 0;

    // 10. chain-anchored historical validator set at the signed certificate
    // epoch, fenced into this same commit -- never current membership or
    // bond state.
    let validator_set: ValidatorSet = equivocation::load_historical_validator_set_fenced(
        store,
        context,
        domain,
        resolver,
        signed.intent.context.chain_id(),
        signed.intent.context.protocol_version(),
        signed.intent.certificate_epoch,
        &mut reads,
    )?;
    let validator = validator_set
        .get(signed.intent.validator_id)
        .ok_or(FeeClaimError::Invalid(
            "fee claim validator absent from the certificate-epoch set",
        ))?;

    // 11. verify the claim signature under the distinct `FastPathFeeClaim`
    // domain, against the validator's historical (not current) key.
    let intent_digest: Digest32 = fee_claim_intent_digest(resolver, &signed.intent)?;
    let framed: Vec<u8> = fee_claim_signing_frame(&signed.intent.context, intent_digest)?;
    if validator.signature_scheme != SignatureSchemeId::Ed25519 {
        return Err(FeeClaimError::Invalid(
            "fee claim validator signature scheme",
        ));
    }
    let verifier: Ed25519Verifier =
        Ed25519Verifier::from_verifying_key_bytes(&validator.public_key)?;
    if !verifier.verify_framed(&framed, &signed.signature)? {
        return Err(FeeClaimError::Invalid("fee claim envelope signature"));
    }

    // 12. only now: policy/object/execution work, and only for a positive claim.
    if is_zero {
        let mut new_shares: Vec<FastPathFeeShare> = settlement.shares.clone();
        new_shares[share_index].claimed = true;
        let new_settlement: FastPathSettlementRecord = FastPathSettlementRecord {
            generation: settlement
                .generation
                .checked_add(1)
                .ok_or(FeeClaimError::Invalid("fee claim generation overflow"))?,
            shares: new_shares,
            ..settlement
        };
        return commit(
            store,
            context,
            domain,
            resolver,
            request_id,
            receipt_digest,
            settlement_key,
            settlement_row_revision,
            reads,
            new_settlement,
            signed.intent.expected_next_row_digest,
            signed_bytes,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
    }

    let leg: AuthenticatedLocalExecutionIntent =
        leg.ok_or(FeeClaimError::Invalid("positive fee claim requires a leg"))?;
    let (fee_policy, policy): (PaidFeePolicy, FastPathEconomicsPolicy) =
        read_economics_policy(store, context, domain, &settlement.context, &mut reads)?;
    let resource: &FastPathEconomicsResourcePolicy = resource_policy(&policy, resource_id)?;
    if !resource.fee_escrow
        || resource.context != *fee_policy.code.context()
        || resource.code != fee_policy.code
        || resource.instance != fee_policy.instance
        || resource.ty != fee_policy.asset_type
        || resource.schema != fee_policy.schema
    {
        return Err(FeeClaimError::Invalid(
            "fee resource is not fee-escrow enabled by the committed economics policy",
        ));
    }
    let scope: ProtocolCustodyScope =
        fee_escrow_scope(&settlement.context, settlement.request_id, resource_id);
    let entrypoint: &str = if is_final {
        &resource.transfer_entrypoint
    } else {
        &resource.split_entrypoint
    };
    let (capability, leg_event_digest) = fee_claim_capability(
        resolver,
        &signed.intent.context,
        resource,
        scope.clone(),
        &fee_output,
        signed.intent.recipient,
        entrypoint,
        &leg,
    )?;
    let call = leg.intent().call.clone();
    let nonce: PendingSenderNonceWrite = durable_reconciliation::reserve_sender_nonce_range(
        store,
        context,
        domain,
        &PersistenceLayout::new(
            signed.intent.context.chain_id().clone(),
            signed.intent.context.protocol_version(),
        ),
        SenderNonceReservation {
            sender: call.sender,
            epoch: signed.intent.context.epoch(),
            nonce: call.nonce,
        },
        1,
    )?;
    let mut head_reads: Vec<DurableObjectHeadRead> = Vec::new();
    let mut state_mutations: Vec<StateMutationEntry> = Vec::new();
    let allowed_output: Option<(ObjectId, &ProtocolCustodyScope)> = if is_final {
        None
    } else {
        Some((fee_output.id, &scope))
    };
    let admitted: AdmittedLeg = admit_and_execute_leg(
        store,
        blob_store,
        context,
        domain,
        resolver,
        history,
        leg_policy,
        engine,
        &leg,
        leg_event_digest,
        Some(&capability),
        CustodyEffectMode::Translate {
            allowed_protocol_custody_output: allowed_output,
        },
        created_checkpoint,
        &mut reads,
        &mut head_reads,
        &mut state_mutations,
    )?;
    if !admitted.success {
        return Err(FeeClaimError::Invalid("fee claim leg trapped"));
    }
    let snapshot: &object_snapshots::ObjectSnapshot = admitted
        .snapshots
        .get(&fee_output.id)
        .ok_or(FeeClaimError::Invalid("fee claim escrow snapshot missing"))?;
    let input = admitted
        .inputs
        .iter()
        .find(|input| input.resolved.object.id == fee_output.id)
        .ok_or(FeeClaimError::Invalid("fee claim escrow input missing"))?;
    let expected_transfer = effects::ExpectedFeeClaim {
        escrow_id: fee_output.id,
        escrow_scope: &scope,
        resource_authority: &input.authority,
        recipient: signed.intent.recipient,
        unclaimed_before: unclaimed_positive_total,
        claim_amount: signed.intent.share_amount,
    };
    let validated: effects::ValidatedFeeClaim = effects::validate(
        &admitted.interface,
        &admitted.created_authorities,
        &expected_transfer,
        created_checkpoint,
        snapshot,
        &admitted.effects,
        is_final,
    )?;
    let resulting_object: Object = match validated {
        effects::ValidatedFeeClaim::Split { retained, released } => {
            let expected_payout: &ObjectRef = match &signed.intent.operation {
                FeeClaimOperation::Split {
                    expected_payout: Some(expected_payout),
                    ..
                } => expected_payout,
                _ => return Err(FeeClaimError::Invalid("split payout ref missing")),
            };
            let released_bytes: Vec<u8> = objects::encode_object(&released)
                .map_err(|_| FeeClaimError::Invalid("invalid fee claim payout encoding"))?;
            let released_digest: Digest32 = resolver.hash_for_purpose(
                signed.intent.context.epoch(),
                HashPurpose::Object,
                &released_bytes,
            )?;
            let actual_payout: ObjectRef = ObjectRef {
                id: released.id,
                version: released.version,
                digest: released_digest,
            };
            if &actual_payout != expected_payout {
                return Err(FeeClaimError::Invalid("signed payout ref mismatch"));
            }
            retained
        }
        effects::ValidatedFeeClaim::Final { transferred } => transferred,
    };
    let canonical: Vec<u8> = objects::encode_object(&resulting_object)
        .map_err(|_| FeeClaimError::Invalid("invalid fee claim output encoding"))?;
    let new_digest: Digest32 = resolver.hash_for_purpose(
        signed.intent.context.epoch(),
        HashPurpose::Object,
        &canonical,
    )?;
    let new_fee_output: ObjectRef = ObjectRef {
        id: resulting_object.id,
        version: resulting_object.version,
        digest: new_digest,
    };

    let mut new_shares: Vec<FastPathFeeShare> = settlement.shares.clone();
    new_shares[share_index].claimed = true;
    let new_settlement: FastPathSettlementRecord = FastPathSettlementRecord {
        generation: settlement
            .generation
            .checked_add(1)
            .ok_or(FeeClaimError::Invalid("fee claim generation overflow"))?,
        fee_output: Some(new_fee_output),
        fee_output_epoch: Some(signed.intent.context.epoch()),
        shares: new_shares,
        ..settlement
    };
    if let Some(previous) = reads.insert(nonce.key.clone(), nonce.read_revision)
        && previous != nonce.read_revision
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    state_mutations.push(StateMutationEntry::new(
        nonce.key,
        StateMutation::Put(nonce.record.encode()?),
    )?);

    commit(
        store,
        context,
        domain,
        resolver,
        request_id,
        receipt_digest,
        settlement_key,
        settlement_row_revision,
        reads,
        new_settlement,
        signed.intent.expected_next_row_digest,
        signed_bytes,
        head_reads,
        admitted.object_mutations,
        state_mutations,
    )
}

/// One atomic commit: every touched object head, the new settlement row
/// (CAS-fenced against the exact previously read revision), every other
/// fenced read (epoch, historical validator-set rows, economics policy, the
/// sender-nonce range for a positive claim), and the one outer receipt.
#[allow(clippy::too_many_arguments)]
fn commit<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    request_id: RequestId,
    receipt_digest: Digest32,
    settlement_key: Vec<u8>,
    settlement_row_revision: StateRevision,
    mut reads: BTreeMap<Vec<u8>, StateRevision>,
    new_settlement: FastPathSettlementRecord,
    expected_next_row_digest: Digest32,
    signed_bytes: &[u8],
    head_reads: Vec<DurableObjectHeadRead>,
    object_mutations: Vec<DurableObjectMutationEntry>,
    mut state_mutations: Vec<StateMutationEntry>,
) -> Result<NodeOutput, FeeClaimError> {
    let new_settlement_bytes: Vec<u8> = encode_fastpath_settlement_record(&new_settlement)?;
    // Hashed at the row's own (fixed, certificate) context epoch, exactly
    // like the previous-row digest check above.
    let next_row_digest: Digest32 = fee_claim_row_digest(
        resolver,
        new_settlement.context.epoch(),
        &new_settlement_bytes,
    )?;
    if next_row_digest != expected_next_row_digest {
        return Err(FeeClaimError::Invalid("fee claim next row digest mismatch"));
    }
    let claim_key: Vec<u8> = local_instance_state::fastpath_fee_claim_key(
        new_settlement.context.chain_id(),
        &new_settlement.request_id,
        new_settlement.generation,
    )?;
    let claim_observed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &claim_key)?;
    if claim_observed.revision() != StateRevision::INITIAL || claim_observed.value().is_some() {
        return Err(FeeClaimError::Invalid(
            "fee claim generation already recorded",
        ));
    }
    reads.insert(claim_key.clone(), claim_observed.revision());
    state_mutations.push(StateMutationEntry::new(
        claim_key,
        StateMutation::Put(signed_bytes.to_vec()),
    )?);
    reads.insert(settlement_key.clone(), settlement_row_revision);
    state_mutations.push(StateMutationEntry::new(
        settlement_key,
        StateMutation::Put(new_settlement_bytes.clone()),
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
            Some(new_settlement_bytes),
        )?],
        Vec::new(),
    )?;
    let dedup: NodeDedupRecord =
        NodeDedupRecord::new(request_id, receipt_digest, output.responses().to_vec())?;
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new(*request_id.as_bytes())
            .map_err(|_| FeeClaimError::Invalid("request id"))?,
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

/// Focused coverage for [`verify_uncharged_claim_absence_by_point_read`] in
/// isolation -- the hook [`verify_fee_claim_history`] supplies to
/// [`verify_fee_claim_history_shared`] for an uncharged (generation-0) row --
/// without needing a full certified escrow fixture. The scanner-backed
/// sibling of this same check ([`verify::verify_claim_key_range_scanned`]
/// with `target_generation == 0`) has its own equivalent coverage in
/// `verify_tests.rs`.
#[cfg(test)]
mod uncharged_claim_absence_tests {
    use super::*;
    use crate::genesis::tests::{chain, context, domain};
    use runtime::{
        AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
        DurableDomainStateStore, MemoryDurableStateStore, StateMutation, StateMutationEntry,
        StateReadAssertion, WriterFenceGeneration,
    };

    fn store() -> MemoryDurableStateStore {
        MemoryDurableStateStore::new_bound(domain(), WriterFenceGeneration::new(1).unwrap())
    }

    fn write_key(store: &MemoryDurableStateStore, key: Vec<u8>, mutation: StateMutation) {
        let observed = store
            .get_versioned_durable(&context(1), domain(), &key)
            .unwrap();
        let transaction = AtomicStateTransaction::new(
            domain(),
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![StateMutationEntry::new(key, mutation).unwrap()])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context(1), transaction),
            DurableCommitOutcome::Committed
        );
    }

    #[test]
    fn accepts_a_fully_absent_claim_key_range() {
        let store: MemoryDurableStateStore = store();
        verify_uncharged_claim_absence_by_point_read(
            &store,
            &context(1),
            domain(),
            &chain(),
            &[0x11; 32],
        )
        .unwrap();
    }

    #[test]
    fn rejects_an_orphan_claim_key_at_generation_two() {
        let store: MemoryDurableStateStore = store();
        let request_id: [u8; 32] = [0x12; 32];
        let key: Vec<u8> =
            local_instance_state::fastpath_fee_claim_key(&chain(), &request_id, 2).unwrap();
        write_key(&store, key, StateMutation::Put(vec![0xFF]));
        let error: FeeClaimError = verify_uncharged_claim_absence_by_point_read(
            &store,
            &context(1),
            domain(),
            &chain(),
            &request_id,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FeeClaimError::Invalid("uncharged settlement has a claim record")
        ));
    }

    #[test]
    fn rejects_an_orphan_claim_key_at_the_far_bound() {
        let store: MemoryDurableStateStore = store();
        let request_id: [u8; 32] = [0x13; 32];
        let far_generation: u64 =
            u64::try_from(crate::fast_path::records::MAX_FASTPATH_ACTIVE_VALIDATORS).unwrap() + 2;
        let key: Vec<u8> =
            local_instance_state::fastpath_fee_claim_key(&chain(), &request_id, far_generation)
                .unwrap();
        write_key(&store, key, StateMutation::Put(vec![0xFF]));
        let error: FeeClaimError = verify_uncharged_claim_absence_by_point_read(
            &store,
            &context(1),
            domain(),
            &chain(),
            &request_id,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FeeClaimError::Invalid("uncharged settlement has a claim record")
        ));
    }
}
