//! DR-0178 sole producer of a durably retained conditional readiness vote.
//! Private full reconstruction and complete inactive-target comparison precede
//! every new signature and cached return. This grants no serving authority.
#![allow(clippy::result_large_err)]

use crate::{
    business_reconstruction::{
        BusinessReconstructionPlan,
        cut::SavedBusinessCut,
        inactive_import::{BusinessImportError, VerifiedImportPlan, verify_saved_business_import},
    },
    epoch_transition::{NextSetEligibilityError, check_next_set_eligibility},
    fast_path::records::FastPathValidatorEntry,
};
use consensus::readiness::{
    ReadinessCertifier, ReadinessError, ReadinessSubject, ReadinessVote, decode_readiness_vote,
    encode_readiness_vote, readiness_schedule_digest, readiness_signing_frame,
    validate_readiness_set,
};
use ed25519_zebra::{SigningKey, VerificationKey};
use hashing::HashSuiteResolver;
use protocol_types::{Epoch, SignatureSchemeId, ValidatorId};
use runtime::portable::{PortableBlobRepository, PortableSnapshotError, PortableSnapshotToken};
use runtime::{
    DurableCommitOutcome, DurableCommitRejection, DurableOperationContext,
    IndeterminateCommitReason, ReadinessRecord, ReadinessRetentionRepository, ReadinessSlot,
    ReadinessSlotObservation,
};
use std::{
    error::Error,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};
use validator_set::{ValidatorInfo, ValidatorSet};

/// Owns the actual software key; no public/private pair asserted by a caller.
/// It is usable only by this readiness owner, not a ConsensusSigner adapter.
pub struct ReadinessSigningKey {
    validator: ValidatorId,
    key: SigningKey,
    created: AtomicU64,
}
impl ReadinessSigningKey {
    #[must_use]
    pub fn new(validator: ValidatorId, key: SigningKey) -> Self {
        Self {
            validator,
            key,
            created: AtomicU64::new(0),
        }
    }
    #[must_use]
    pub const fn validator_id(&self) -> ValidatorId {
        self.validator
    }
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        VerificationKey::from(&self.key).into()
    }
    /// Diagnostics only, never storage or admission authority.
    #[must_use]
    pub fn signatures_created(&self) -> u64 {
        self.created.load(Ordering::Relaxed)
    }
    fn sign(&self, subject: &ReadinessSubject) -> Result<[u8; 64], ReadinessError> {
        let frame: Vec<u8> = readiness_signing_frame(subject, self.validator)?;
        self.created.fetch_add(1, Ordering::Relaxed);
        Ok(self.key.sign(&frame).into())
    }
}

#[derive(Debug)]
pub enum ConditionalReadinessError {
    Import(BusinessImportError),
    Protocol(ReadinessError),
    Ineligible,
    EligibilityPrerequisite,
    Node(Box<crate::NodeCoreError>),
    Snapshot(PortableSnapshotError),
    Rejected(DurableCommitRejection),
    Indeterminate(IndeterminateCommitReason),
    Invalid(&'static str),
}
impl fmt::Display for ConditionalReadinessError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Import(error) => error.fmt(out),
            Self::Protocol(error) => error.fmt(out),
            Self::Ineligible => out.write_str("readiness successor is not eligible"),
            Self::EligibilityPrerequisite => {
                out.write_str("readiness eligibility prerequisite is invalid or missing")
            }
            Self::Node(error) => error.fmt(out),
            Self::Snapshot(error) => error.fmt(out),
            Self::Rejected(error) => write!(out, "readiness storage refused: {error:?}"),
            Self::Indeterminate(error) => {
                write!(out, "readiness retention is indeterminate: {error:?}")
            }
            Self::Invalid(message) => out.write_str(message),
        }
    }
}
impl Error for ConditionalReadinessError {}
impl From<BusinessImportError> for ConditionalReadinessError {
    fn from(error: BusinessImportError) -> Self {
        Self::Import(error)
    }
}
impl From<ReadinessError> for ConditionalReadinessError {
    fn from(error: ReadinessError) -> Self {
        Self::Protocol(error)
    }
}
impl From<NextSetEligibilityError> for ConditionalReadinessError {
    fn from(error: NextSetEligibilityError) -> Self {
        match error {
            NextSetEligibilityError::Ineligible => Self::Ineligible,
            NextSetEligibilityError::Prerequisite => Self::EligibilityPrerequisite,
            NextSetEligibilityError::Node(error) => Self::Node(Box::new(error)),
        }
    }
}
impl From<PortableSnapshotError> for ConditionalReadinessError {
    fn from(error: PortableSnapshotError) -> Self {
        Self::Snapshot(error)
    }
}

fn check_retained(
    record: &ReadinessRecord,
    expected: &ReadinessSlot,
    import: &VerifiedImportPlan,
    progress: &runtime::ImportProgress,
    token: &PortableSnapshotToken,
    owner: &ReadinessCertifier<'_>,
) -> Result<ReadinessVote, ConditionalReadinessError> {
    if &record.slot != expected
        || &record.binding != import.binding()
        || &record.progress != progress
        || record.creation_token.namespace() != token.namespace()
        || record.creation_token.domain() != token.domain()
        || record.creation_token.writer_fence() > token.writer_fence()
        || record.creation_token.mutation_sequence() >= token.mutation_sequence()
    {
        return Err(ConditionalReadinessError::Invalid(
            "readiness retained local linkage mismatch",
        ));
    }
    let vote: ReadinessVote = decode_readiness_vote(&record.vote_bytes)?;
    if vote.signer != expected.signer {
        return Err(ConditionalReadinessError::Invalid(
            "readiness retained signer differs from slot",
        ));
    }
    owner.verify_vote(&vote)?;
    Ok(vote)
}

/// Pure public subject computation from a claimed binding and candidate set.
/// This verifies configuration/shape, not completeness, eligibility or origin.
/// It is useful for checking saved output before invoking the private producer.
pub fn readiness_subject_for_candidate(
    binding: &runtime::ImportBinding,
    resolver: &HashSuiteResolver,
    next_set: &ValidatorSet,
) -> Result<ReadinessSubject, ReadinessError> {
    let epoch: Epoch = binding.context.epoch;
    let next_epoch: Epoch = Epoch::new(epoch.get().checked_add(1).ok_or(
        ReadinessError::Invalid("readiness successor epoch overflow"),
    )?);
    let subject: ReadinessSubject = ReadinessSubject {
        chain_id: binding.context.chain_id.clone(),
        protocol_version: binding.context.protocol_version,
        epoch,
        genesis_digest: binding.genesis_digest,
        domain: binding.domain,
        outgoing_set_digest: binding.validator_set_digest,
        cut_digest: binding.cut_digest,
        next_epoch,
        next_set_digest: next_set.digest(resolver)?,
        schedule_digest: readiness_schedule_digest(resolver, epoch)?,
    };
    ReadinessCertifier::new(resolver, &subject, next_set)?;
    Ok(subject)
}

/// A private producer, not a method that signs caller assertions. The supplied
/// successor list is merely a candidate; all membership/bond/key/configuration
/// checks precede signing. Corrected candidates are nonexclusive before Seal.
#[allow(clippy::too_many_arguments)]
pub fn retain_conditional_readiness<S, B>(
    plan: BusinessReconstructionPlan<'_>,
    saved: &SavedBusinessCut,
    destination: &S,
    blobs: &B,
    operation: &DurableOperationContext,
    next_members: &[FastPathValidatorEntry],
    signer: &ReadinessSigningKey,
) -> Result<ReadinessVote, ConditionalReadinessError>
where
    S: ReadinessRetentionRepository,
    B: PortableBlobRepository,
{
    let resolver: &HashSuiteResolver = plan.resolver;
    let epoch: Epoch = plan.genesis.context().epoch();
    let import: VerifiedImportPlan = verify_saved_business_import(plan, saved)?;
    let (progress, token): (runtime::ImportProgress, PortableSnapshotToken) =
        import.observe_complete(destination, blobs, operation)?;
    if !(1..=consensus::readiness::MAX_READINESS_MEMBERS).contains(&next_members.len()) {
        return Err(ConditionalReadinessError::Invalid(
            "readiness successor member bound",
        ));
    }
    let next_epoch: Epoch = Epoch::new(epoch.get().checked_add(1).ok_or(
        ConditionalReadinessError::Invalid("readiness successor epoch overflow"),
    )?);
    if next_members
        .iter()
        .any(|member: &FastPathValidatorEntry| member.public_key.len() != 32)
    {
        return Err(ConditionalReadinessError::Invalid(
            "readiness successor key byte bound",
        ));
    }
    let entries: Vec<ValidatorInfo> = next_members
        .iter()
        .map(|member: &FastPathValidatorEntry| ValidatorInfo {
            id: member.id,
            voting_power: member.voting_power,
            signature_scheme: member.signature_scheme,
            public_key: member.public_key.clone(),
        })
        .collect();
    let next_set: ValidatorSet =
        ValidatorSet::new(next_epoch, entries).map_err(ReadinessError::from)?;
    validate_readiness_set(&next_set)?;
    let member = next_set
        .get(signer.validator_id())
        .ok_or(ConditionalReadinessError::Invalid(
            "readiness local signer not a successor member",
        ))?;
    if member.signature_scheme != SignatureSchemeId::Ed25519
        || member.public_key.as_slice() != signer.public_key()
    {
        return Err(ConditionalReadinessError::Invalid(
            "readiness actual signing key mismatch",
        ));
    }
    check_next_set_eligibility(
        destination,
        operation,
        import.binding().domain,
        &import.binding().context.chain_id,
        epoch,
        next_members,
    )?;
    destination.check_portable_outbox_empty_at(operation, import.binding().domain, &token)?;
    let subject: ReadinessSubject =
        readiness_subject_for_candidate(import.binding(), resolver, &next_set)?;
    let owner: ReadinessCertifier<'_> = ReadinessCertifier::new(resolver, &subject, &next_set)?;
    let slot: ReadinessSlot = ReadinessSlot {
        identity: subject.identity(resolver)?,
        signer: signer.validator_id(),
    };
    let observed: ReadinessSlotObservation = destination.read_ready_slot_at(
        operation,
        subject.domain,
        import.binding(),
        &progress,
        &token,
        &slot,
    )?;
    let record: ReadinessRecord = match &observed {
        ReadinessSlotObservation::Absent => {
            destination.check_portable_outbox_empty_at(operation, subject.domain, &token)?;
            let vote: ReadinessVote = ReadinessVote {
                subject: subject.clone(),
                signer: signer.validator_id(),
                scheme: SignatureSchemeId::Ed25519,
                signature: signer.sign(&subject)?,
            };
            owner.verify_vote(&vote)?;
            ReadinessRecord {
                slot: slot.clone(),
                binding: import.binding().clone(),
                progress: progress.clone(),
                creation_token: token.clone(),
                vote_bytes: encode_readiness_vote(&vote)?,
            }
        }
        ReadinessSlotObservation::Present(record) => {
            check_retained(record, &slot, &import, &progress, &token, &owner)?;
            record.clone()
        }
        ReadinessSlotObservation::Tombstoned => {
            return Err(ConditionalReadinessError::Invalid(
                "readiness retained slot is tombstoned",
            ));
        }
    };
    let outcome: DurableCommitOutcome = destination.retain_ready_slot(
        operation,
        subject.domain,
        import.binding(),
        &progress,
        &token,
        &observed,
        &record,
    );
    match outcome {
        DurableCommitOutcome::Rejected(reason) => {
            return Err(ConditionalReadinessError::Rejected(reason));
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            // Full fresh verification observes this exact landed record, never
            // blindly retries an uncertain write or returns a computed vote.
            let (fresh_progress, fresh_token): (runtime::ImportProgress, PortableSnapshotToken) =
                import.observe_complete(destination, blobs, operation)?;
            let fresh: ReadinessSlotObservation = destination.read_ready_slot_at(
                operation,
                subject.domain,
                import.binding(),
                &fresh_progress,
                &fresh_token,
                &slot,
            )?;
            if fresh != ReadinessSlotObservation::Present(record.clone()) {
                return Err(ConditionalReadinessError::Indeterminate(reason));
            }
            return check_retained(
                &record,
                &slot,
                &import,
                &fresh_progress,
                &fresh_token,
                &owner,
            );
        }
        DurableCommitOutcome::Committed => {}
    }
    // Confirmed atomic retain is an observation of exact signed bytes, not a
    // signal permitting activation. Decode once more for the bounded output.
    Ok(decode_readiness_vote(&record.vote_bytes)?)
}
