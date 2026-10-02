//! One pure FastVote record-to-committee structural validation owner.

use super::records::FastPathValidatorSetRecord;
use core::fmt;
use execution::publication::PublicationContext;
use protocol_types::{SignatureSchemeId, ValidatorId};
use std::error::Error;
use validator_set::{ValidatorInfo, ValidatorSet, ValidatorSetError};

/// Structural failures for an explicitly expected FastVote record context.
/// These errors establish no genesis, historical or live serving authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FastVoteCommitteeError {
    /// The record's chain, protocol version or epoch differs from expectation.
    ContextMismatch,
    /// FastVote's current verifier supports only Ed25519 registrations.
    UnsupportedSignatureScheme {
        /// The member carrying the unsupported registration.
        validator_id: ValidatorId,
        /// The exact scheme from the record, without fallback or negotiation.
        scheme: SignatureSchemeId,
    },
    /// Existing generic membership, power, uniqueness, key or size validation.
    InvalidSet(ValidatorSetError),
}

impl fmt::Display for FastVoteCommitteeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContextMismatch => formatter.write_str("FastVote committee context mismatch"),
            Self::UnsupportedSignatureScheme {
                validator_id,
                scheme,
            } => write!(
                formatter,
                "FastVote committee validator {validator_id} uses unsupported scheme {scheme:?}; only Ed25519 is supported"
            ),
            Self::InvalidSet(error) => error.fmt(formatter),
        }
    }
}

impl Error for FastVoteCommitteeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidSet(error) => Some(error),
            Self::ContextMismatch | Self::UnsupportedSignatureScheme { .. } => None,
        }
    }
}

/// Validates one FastVote record's structure for an explicit expected context.
///
/// Context mismatch precedes unsupported member schemes, which precede the
/// existing [`ValidatorSet::new`] checks. Canonical member ordering and all
/// generic limits stay with that defining primitive. No additional key length
/// or cryptographic key policy is imposed here, and genesis fee-claim capacity
/// is deliberately not a live/historical record limit.
///
/// The result is not authenticated genesis, an installed historical digest,
/// a current epoch, signer membership proof or serving authority. Those remain
/// with the caller's independently pinned and fenced owners. Byte callers must
/// first use the existing bounded record decoder.
pub fn validate_fastvote_validator_set_record(
    record: &FastPathValidatorSetRecord,
    expected_context: &PublicationContext,
) -> Result<ValidatorSet, FastVoteCommitteeError> {
    if record.context != *expected_context {
        return Err(FastVoteCommitteeError::ContextMismatch);
    }
    let mut validators: Vec<ValidatorInfo> = Vec::with_capacity(record.validators.len());
    for member in &record.validators {
        if member.signature_scheme != SignatureSchemeId::Ed25519 {
            return Err(FastVoteCommitteeError::UnsupportedSignatureScheme {
                validator_id: member.id,
                scheme: member.signature_scheme,
            });
        }
        validators.push(ValidatorInfo {
            id: member.id,
            voting_power: member.voting_power,
            signature_scheme: member.signature_scheme,
            public_key: member.public_key.clone(),
        });
    }
    ValidatorSet::new(expected_context.epoch(), validators)
        .map_err(FastVoteCommitteeError::InvalidSet)
}

#[cfg(test)]
mod tests;
