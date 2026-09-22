//! Outgoing-set-certified `e -> e+1` FastVote epoch transition canonical
//! types (DR-0132, phase 2 slice 2).
//!
//! Structurally mirrors [`crate::fast_vote`]: an [`EpochTransitionCertifier`]
//! is a stateless, epoch-scoped signer/verifier bound to one outgoing
//! [`ValidatorSet`] snapshot, with the identical quorum rule, canonical
//! [`ValidatorId`] order, duplicate rejection, smallest-signature tie-break,
//! and explicit vote-exclusion policy `try_form_certificate` documents. It is
//! deliberately a distinct type family under a distinct signature domain
//! (`"fast-path-epoch-transition-v1"`) and distinct frame ids (`0xD009`-
//! `0xD00B`): overloading `FastVote`'s `tx_hash`/`execution_effects_hash`
//! slots would make a transition certificate structurally indistinguishable
//! from a transaction certificate (DR-0132 correction C6).
//!
//! This module only proves that a resulting [`EpochTransitionCertificate`]
//! carries a canonically ordered, minimal-by-canonical-order quorum of valid
//! signatures over one exact `(next_epoch, current_validator_set_digest,
//! next_validator_set_digest, activation_digest)` tuple, cast by the
//! *outgoing* epoch's validator set. It does not derive the activation set,
//! install anything durably, or decide what `next_epoch`'s validators are --
//! that is `crate::node_core`-side (see
//! `docs/architecture/decisions/0132-fastvote-epoch-transition.md`).

use crate::{ConsensusError, ConsensusSigner, ConsensusVerifier, validate_signature_length};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalStruct, decode_canonical_frame, decode_digest32,
    encode_digest32,
};
use crypto::{SignatureDomain, SignatureMessageType, frame_signature_message};
use protocol_types::{ChainId, Digest32, Epoch, ProtocolVersion, SignatureSchemeId, ValidatorId};
use std::collections::BTreeMap;
use validator_set::ValidatorSet;

const EPOCH_TRANSITION_VOTE_PAYLOAD_TYPE_ID: u16 = 0xD009;
const EPOCH_TRANSITION_VOTE_TYPE_ID: u16 = 0xD00A;
const EPOCH_TRANSITION_CERTIFICATE_TYPE_ID: u16 = 0xD00B;
const ENCODING_VERSION: u16 = 1;
const EPOCH_TRANSITION_MESSAGE_TYPE: &str = "fast-path-epoch-transition-v1";

/// Matches [`validator_set`]'s own bound on one epoch snapshot; a
/// [`EpochTransitionCertificate`] can never carry more votes than there are
/// outgoing validators.
const MAX_EPOCH_TRANSITION_CERTIFICATE_VOTES: usize = 10_000;

/// One outgoing-epoch validator's signed attestation that it would (or did)
/// authorize the exact `e -> e+1` transition identified by this payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochTransitionVote {
    /// Chain replay boundary.
    pub chain_id: ChainId,
    /// Protocol replay boundary, pinned unchanged across the transition.
    pub protocol_version: ProtocolVersion,
    /// The outgoing epoch `e`; the replay boundary and the signing set's own
    /// epoch.
    pub epoch: Epoch,
    /// Must equal `epoch + 1` at construction and at decode.
    pub next_epoch: Epoch,
    /// Binds *which* outgoing set authorized this, not merely an equal-epoch
    /// set.
    pub current_validator_set_digest: Digest32,
    /// `ValidatorSet::digest(resolver)` of the `e+1` set, computed at epoch
    /// `e+1`.
    pub next_validator_set_digest: Digest32,
    /// One digest over the complete byte-exact activation write set; makes
    /// the vote byte-stable across independently deriving validators.
    pub activation_digest: Digest32,
    /// Voting (outgoing-epoch) validator.
    pub validator: ValidatorId,
    /// Signature scheme registered for `validator` in the outgoing set.
    pub signature_scheme: SignatureSchemeId,
    /// Signature over the domain-framed vote payload.
    pub signature: Vec<u8>,
}

/// A minimal, canonically ordered outgoing-set quorum of
/// [`EpochTransitionVote`]s for one `e -> e+1` transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochTransitionCertificate {
    /// Chain replay boundary.
    pub chain_id: ChainId,
    /// Protocol replay boundary.
    pub protocol_version: ProtocolVersion,
    /// The outgoing epoch `e`.
    pub epoch: Epoch,
    /// The incoming epoch, always `epoch + 1`.
    pub next_epoch: Epoch,
    /// Certified outgoing validator-set digest.
    pub current_validator_set_digest: Digest32,
    /// Certified incoming validator-set digest.
    pub next_validator_set_digest: Digest32,
    /// Certified activation-write-set digest.
    pub activation_digest: Digest32,
    /// Canonically validator-ID-ordered, deduplicated votes.
    pub votes: Vec<EpochTransitionVote>,
}

/// Stateless epoch-scoped signer/verifier for outgoing-set-certified epoch
/// transitions. A structural mirror of [`crate::FastPathCertifier`]: every
/// method is a pure function of its arguments and the immutable `(chain_id,
/// protocol_version, outgoing_epoch, outgoing_validator_set)` context
/// captured at construction.
#[derive(Clone, Debug)]
pub struct EpochTransitionCertifier {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set: ValidatorSet,
}

impl EpochTransitionCertifier {
    /// Creates a certifier bound to one outgoing epoch's validator-set
    /// snapshot.
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        validator_set: ValidatorSet,
    ) -> Result<Self, ConsensusError> {
        if validator_set.epoch() != epoch {
            return Err(ConsensusError::ValidatorSetEpochMismatch {
                expected: epoch,
                actual: validator_set.epoch(),
            });
        }
        Ok(Self {
            chain_id,
            protocol_version,
            epoch,
            validator_set,
        })
    }

    /// Returns the bound chain replay boundary.
    #[must_use]
    pub const fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the bound protocol replay boundary.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the bound outgoing epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the bound outgoing validator-set snapshot.
    #[must_use]
    pub const fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Returns the strict quorum threshold of the bound outgoing set.
    #[must_use]
    pub const fn quorum_threshold(&self) -> u64 {
        self.validator_set.quorum_threshold()
    }

    /// Signs and returns one [`EpochTransitionVote`] for the exact
    /// `(next_epoch, current_validator_set_digest, next_validator_set_digest,
    /// activation_digest)` tuple. Fails closed with
    /// [`ConsensusError::NonSuccessiveEpoch`] before signing anything if
    /// `next_epoch` is not exactly `epoch + 1`.
    pub fn cast_vote<S: ConsensusSigner>(
        &self,
        next_epoch: Epoch,
        current_validator_set_digest: Digest32,
        next_validator_set_digest: Digest32,
        activation_digest: Digest32,
        signer: &S,
    ) -> Result<EpochTransitionVote, ConsensusError> {
        self.ensure_successive(next_epoch)?;
        self.ensure_registered_scheme(signer.validator_id(), signer.signature_scheme())?;
        let mut vote = EpochTransitionVote {
            chain_id: self.chain_id.clone(),
            protocol_version: self.protocol_version,
            epoch: self.epoch,
            next_epoch,
            current_validator_set_digest,
            next_validator_set_digest,
            activation_digest,
            validator: signer.validator_id(),
            signature_scheme: signer.signature_scheme(),
            signature: Vec::new(),
        };
        let framed = self.signature_frame(
            vote.signature_scheme,
            &encode_epoch_transition_vote_payload(&vote)?,
        )?;
        vote.signature = signer
            .sign_framed(&framed)
            .map_err(ConsensusError::Authenticator)?;
        validate_signature_length(&vote.signature)?;
        Ok(vote)
    }

    /// Validates one [`EpochTransitionVote`]'s context, successive-epoch
    /// structure, registered scheme, and signature.
    pub fn verify_vote<V: ConsensusVerifier>(
        &self,
        vote: &EpochTransitionVote,
        verifier: &V,
    ) -> Result<(), ConsensusError> {
        self.ensure_context(&vote.chain_id, vote.protocol_version, vote.epoch)?;
        self.ensure_successive(vote.next_epoch)?;
        self.ensure_registered_scheme(vote.validator, vote.signature_scheme)?;
        validate_signature_length(&vote.signature)?;
        let info = self
            .validator_set
            .get(vote.validator)
            .ok_or(ConsensusError::UnknownValidator(vote.validator))?;
        let framed = self.signature_frame(
            vote.signature_scheme,
            &encode_epoch_transition_vote_payload(vote)?,
        )?;
        let valid = verifier
            .verify_framed(
                vote.validator,
                vote.signature_scheme,
                &info.public_key,
                &framed,
                &vote.signature,
            )
            .map_err(ConsensusError::Authenticator)?;
        if !valid {
            return Err(ConsensusError::InvalidSignature(vote.validator));
        }
        Ok(())
    }

    /// Deterministically forms the minimal canonically ordered certificate
    /// for the exact target tuple, or `None` if `votes` does not carry
    /// quorum voting power for it.
    ///
    /// Applies the identical exclusion policy
    /// [`crate::FastPathCertifier::try_form_certificate`] documents: a vote
    /// whose header does not match this call's target tuple is unrelated
    /// relay noise and is excluded without being verified; a vote that *is*
    /// addressed to this exact target but fails [`Self::verify_vote`] with
    /// [`ConsensusError::UnknownValidator`],
    /// [`ConsensusError::SignatureSchemeMismatch`],
    /// [`ConsensusError::InvalidSignatureLength`],
    /// [`ConsensusError::InvalidSignature`],
    /// [`ConsensusError::ContextMismatch`], or
    /// [`ConsensusError::NonSuccessiveEpoch`] is malformed or
    /// cryptographically invalid and is excluded under the same policy; any
    /// other error (in particular [`ConsensusError::Authenticator`]) is not
    /// swallowed and fails the whole call closed.
    #[allow(clippy::too_many_arguments)]
    pub fn try_form_certificate<V: ConsensusVerifier>(
        &self,
        next_epoch: Epoch,
        current_validator_set_digest: Digest32,
        next_validator_set_digest: Digest32,
        activation_digest: Digest32,
        votes: &[EpochTransitionVote],
        verifier: &V,
    ) -> Result<Option<EpochTransitionCertificate>, ConsensusError> {
        self.ensure_successive(next_epoch)?;
        let mut by_validator: BTreeMap<ValidatorId, &EpochTransitionVote> = BTreeMap::new();
        for vote in votes {
            if vote.next_epoch != next_epoch
                || vote.current_validator_set_digest != current_validator_set_digest
                || vote.next_validator_set_digest != next_validator_set_digest
                || vote.activation_digest != activation_digest
            {
                continue;
            }
            if vote.chain_id != self.chain_id
                || vote.protocol_version != self.protocol_version
                || vote.epoch != self.epoch
            {
                continue;
            }
            match self.verify_vote(vote, verifier) {
                Ok(()) => {}
                Err(
                    ConsensusError::UnknownValidator(_)
                    | ConsensusError::SignatureSchemeMismatch(_)
                    | ConsensusError::InvalidSignatureLength(_)
                    | ConsensusError::InvalidSignature(_)
                    | ConsensusError::ContextMismatch
                    | ConsensusError::NonSuccessiveEpoch { .. },
                ) => continue,
                Err(other) => return Err(other),
            }
            by_validator
                .entry(vote.validator)
                .and_modify(|current: &mut &EpochTransitionVote| {
                    if vote.signature < current.signature {
                        *current = vote;
                    }
                })
                .or_insert(vote);
        }

        let mut power = 0u64;
        let mut selected: Vec<EpochTransitionVote> = Vec::new();
        for (validator, vote) in by_validator {
            let info = self
                .validator_set
                .get(validator)
                .ok_or(ConsensusError::UnknownValidator(validator))?;
            power = power
                .checked_add(info.voting_power)
                .ok_or(ConsensusError::ArithmeticOverflow)?;
            selected.push(vote.clone());
            if power >= self.quorum_threshold() {
                return Ok(Some(EpochTransitionCertificate {
                    chain_id: self.chain_id.clone(),
                    protocol_version: self.protocol_version,
                    epoch: self.epoch,
                    next_epoch,
                    current_validator_set_digest,
                    next_validator_set_digest,
                    activation_digest,
                    votes: selected,
                }));
            }
        }
        Ok(None)
    }

    /// Validates an [`EpochTransitionCertificate`]'s context, successive-
    /// epoch structure, canonical vote order, per-vote signatures, and
    /// quorum voting power.
    ///
    /// Does not require minimality: any canonically ordered, quorum-carrying,
    /// duplicate-free vote set for the same header verifies.
    pub fn verify_certificate<V: ConsensusVerifier>(
        &self,
        certificate: &EpochTransitionCertificate,
        verifier: &V,
    ) -> Result<(), ConsensusError> {
        self.ensure_context(
            &certificate.chain_id,
            certificate.protocol_version,
            certificate.epoch,
        )?;
        self.ensure_successive(certificate.next_epoch)?;
        let mut previous: Option<ValidatorId> = None;
        let mut power = 0u64;
        for vote in &certificate.votes {
            if previous.is_some_and(|id| id >= vote.validator) {
                return Err(ConsensusError::NonCanonicalCertificateVotes);
            }
            previous = Some(vote.validator);
            if vote.chain_id != certificate.chain_id
                || vote.protocol_version != certificate.protocol_version
                || vote.epoch != certificate.epoch
                || vote.next_epoch != certificate.next_epoch
                || vote.current_validator_set_digest != certificate.current_validator_set_digest
                || vote.next_validator_set_digest != certificate.next_validator_set_digest
                || vote.activation_digest != certificate.activation_digest
            {
                return Err(ConsensusError::CertificateVoteMismatch);
            }
            self.verify_vote(vote, verifier)?;
            let info = self
                .validator_set
                .get(vote.validator)
                .ok_or(ConsensusError::UnknownValidator(vote.validator))?;
            power = power
                .checked_add(info.voting_power)
                .ok_or(ConsensusError::ArithmeticOverflow)?;
        }
        let required = self.quorum_threshold();
        if power < required {
            return Err(ConsensusError::InsufficientQuorum {
                actual: power,
                required,
            });
        }
        Ok(())
    }

    fn ensure_context(
        &self,
        chain_id: &ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
    ) -> Result<(), ConsensusError> {
        if chain_id != &self.chain_id
            || protocol_version != self.protocol_version
            || epoch != self.epoch
        {
            return Err(ConsensusError::ContextMismatch);
        }
        Ok(())
    }

    fn ensure_successive(&self, next_epoch: Epoch) -> Result<(), ConsensusError> {
        let expected = self
            .epoch
            .get()
            .checked_add(1)
            .ok_or(ConsensusError::ArithmeticOverflow)?;
        if next_epoch.get() != expected {
            return Err(ConsensusError::NonSuccessiveEpoch {
                current: self.epoch,
                next: next_epoch,
            });
        }
        Ok(())
    }

    fn ensure_registered_scheme(
        &self,
        validator: ValidatorId,
        scheme: SignatureSchemeId,
    ) -> Result<(), ConsensusError> {
        let info = self
            .validator_set
            .get(validator)
            .ok_or(ConsensusError::UnknownValidator(validator))?;
        if info.signature_scheme != scheme {
            return Err(ConsensusError::SignatureSchemeMismatch(validator));
        }
        Ok(())
    }

    fn signature_frame(
        &self,
        signature_scheme_id: SignatureSchemeId,
        payload: &[u8],
    ) -> Result<Vec<u8>, ConsensusError> {
        Ok(frame_signature_message(
            &SignatureDomain {
                chain_id: self.chain_id.clone(),
                protocol_version: self.protocol_version,
                epoch: self.epoch,
                message_type: SignatureMessageType::new(EPOCH_TRANSITION_MESSAGE_TYPE)?,
                signature_scheme_id,
            },
            payload,
        )?)
    }
}

/// Encodes the signable [`EpochTransitionVote`] payload without its
/// signature (frame `0xD009/v1`).
pub fn encode_epoch_transition_vote_payload(
    vote: &EpochTransitionVote,
) -> Result<Vec<u8>, ConsensusError> {
    let mut canonical =
        CanonicalStruct::new(EPOCH_TRANSITION_VOTE_PAYLOAD_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, vote.chain_id.as_str())?;
    canonical.field_u32(2, vote.protocol_version.get())?;
    canonical.field_u64(3, vote.epoch.get())?;
    canonical.field_u64(4, vote.next_epoch.get())?;
    canonical.field_bytes(5, encode_digest32(&vote.current_validator_set_digest)?)?;
    canonical.field_bytes(6, encode_digest32(&vote.next_validator_set_digest)?)?;
    canonical.field_bytes(7, encode_digest32(&vote.activation_digest)?)?;
    canonical.field_bytes(8, vote.validator.as_bytes())?;
    canonical.field_u16(9, vote.signature_scheme.as_u16())?;
    Ok(canonical.finish()?)
}

/// Encodes a complete signed [`EpochTransitionVote`] (frame `0xD00A/v1`).
pub fn encode_epoch_transition_vote(vote: &EpochTransitionVote) -> Result<Vec<u8>, ConsensusError> {
    validate_signature_length(&vote.signature)?;
    let mut canonical = CanonicalStruct::new(EPOCH_TRANSITION_VOTE_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_epoch_transition_vote_payload(vote)?)?;
    canonical.field_bytes(2, vote.signature.clone())?;
    Ok(canonical.finish()?)
}

/// Decodes and strictly re-validates one canonical [`EpochTransitionVote`].
///
/// Beyond the shared canonical-frame guarantees, this requires the
/// epoch-transition-vote type id/encoding version, exactly fields 1-9 in the
/// nested payload frame and 1-2 in the outer frame, a non-empty bounded
/// signature, `next_epoch == epoch + 1`, and byte-exact re-encoding of the
/// decoded value. Signature and validator-set membership verification still
/// belong to [`EpochTransitionCertifier::verify_vote`].
pub fn decode_epoch_transition_vote(input: &[u8]) -> Result<EpochTransitionVote, ConsensusError> {
    let outer = decode_canonical_frame(input)?;
    outer.require_type(EPOCH_TRANSITION_VOTE_TYPE_ID)?;
    outer.require_version(ENCODING_VERSION)?;
    outer.require_only_fields(&[1, 2])?;
    let payload_bytes = outer.required_field(1)?;
    let signature = outer.required_field(2)?.to_vec();

    let payload = decode_canonical_frame(payload_bytes)?;
    payload.require_type(EPOCH_TRANSITION_VOTE_PAYLOAD_TYPE_ID)?;
    payload.require_version(ENCODING_VERSION)?;
    payload.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9])?;

    let chain_id =
        ChainId::new(payload.required_str(1)?.to_owned()).map_err(ConsensusError::ProtocolType)?;
    let protocol_version = ProtocolVersion::new(payload.required_u32(2)?);
    let epoch = Epoch::new(payload.required_u64(3)?);
    let next_epoch = Epoch::new(payload.required_u64(4)?);
    let current_validator_set_digest = decode_digest32(payload.required_field(5)?)?;
    let next_validator_set_digest = decode_digest32(payload.required_field(6)?)?;
    let activation_digest = decode_digest32(payload.required_field(7)?)?;
    let validator_field = payload.required_field(8)?;
    let validator_bytes: [u8; 32] = validator_field.try_into().map_err(|_| {
        ConsensusError::CanonicalDecoding(CanonicalDecodingError::InvalidFieldLength {
            field_id: 8,
            expected: 32,
            actual: validator_field.len(),
        })
    })?;
    let signature_scheme = SignatureSchemeId::try_from(payload.required_u16(9)?)
        .map_err(ConsensusError::ProtocolType)?;

    let vote = EpochTransitionVote {
        chain_id,
        protocol_version,
        epoch,
        next_epoch,
        current_validator_set_digest,
        next_validator_set_digest,
        activation_digest,
        validator: ValidatorId::new(validator_bytes),
        signature_scheme,
        signature,
    };
    let expected_next_epoch: u64 = vote
        .epoch
        .get()
        .checked_add(1)
        .ok_or(ConsensusError::ArithmeticOverflow)?;
    if vote.next_epoch.get() != expected_next_epoch {
        return Err(ConsensusError::NonSuccessiveEpoch {
            current: vote.epoch,
            next: vote.next_epoch,
        });
    }
    if encode_epoch_transition_vote(&vote)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    Ok(vote)
}

/// Encodes an [`EpochTransitionCertificate`] with its votes in the caller's
/// given order (frame `0xD00B/v1`).
///
/// Callers that want the canonical, arrival-order-independent representation
/// must pass votes already sorted by [`ValidatorId`] (as
/// [`EpochTransitionCertifier::try_form_certificate`] always returns them).
pub fn encode_epoch_transition_certificate(
    certificate: &EpochTransitionCertificate,
) -> Result<Vec<u8>, ConsensusError> {
    if certificate.votes.len() > MAX_EPOCH_TRANSITION_CERTIFICATE_VOTES {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    let mut canonical =
        CanonicalStruct::new(EPOCH_TRANSITION_CERTIFICATE_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, certificate.chain_id.as_str())?;
    canonical.field_u32(2, certificate.protocol_version.get())?;
    canonical.field_u64(3, certificate.epoch.get())?;
    canonical.field_u64(4, certificate.next_epoch.get())?;
    canonical.field_bytes(
        5,
        encode_digest32(&certificate.current_validator_set_digest)?,
    )?;
    canonical.field_bytes(6, encode_digest32(&certificate.next_validator_set_digest)?)?;
    canonical.field_bytes(7, encode_digest32(&certificate.activation_digest)?)?;
    canonical.field_u32(
        8,
        u32::try_from(certificate.votes.len())
            .map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?,
    )?;
    for (index, vote) in certificate.votes.iter().enumerate() {
        let field =
            u16::try_from(index + 9).map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?;
        canonical.field_bytes(field, encode_epoch_transition_vote(vote)?)?;
    }
    Ok(canonical.finish()?)
}

/// Decodes and strictly re-validates one canonical
/// [`EpochTransitionCertificate`].
///
/// Beyond the shared canonical-frame guarantees, this requires the
/// epoch-transition-certificate type id/encoding version, an exact declared
/// vote count bounded by [`MAX_EPOCH_TRANSITION_CERTIFICATE_VOTES`], every
/// nested [`EpochTransitionVote`] to decode under
/// [`decode_epoch_transition_vote`], and byte-exact re-encoding of the
/// decoded value, and `next_epoch == epoch + 1`. It does not verify
/// signatures or quorum; callers must still call
/// [`EpochTransitionCertifier::verify_certificate`].
pub fn decode_epoch_transition_certificate(
    input: &[u8],
) -> Result<EpochTransitionCertificate, ConsensusError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(EPOCH_TRANSITION_CERTIFICATE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;

    let chain_id =
        ChainId::new(frame.required_str(1)?.to_owned()).map_err(ConsensusError::ProtocolType)?;
    let protocol_version = ProtocolVersion::new(frame.required_u32(2)?);
    let epoch = Epoch::new(frame.required_u64(3)?);
    let next_epoch = Epoch::new(frame.required_u64(4)?);
    let expected_next_epoch: u64 = epoch
        .get()
        .checked_add(1)
        .ok_or(ConsensusError::ArithmeticOverflow)?;
    if next_epoch.get() != expected_next_epoch {
        return Err(ConsensusError::NonSuccessiveEpoch {
            current: epoch,
            next: next_epoch,
        });
    }
    let current_validator_set_digest = decode_digest32(frame.required_field(5)?)?;
    let next_validator_set_digest = decode_digest32(frame.required_field(6)?)?;
    let activation_digest = decode_digest32(frame.required_field(7)?)?;
    let count = usize::try_from(frame.required_u32(8)?)
        .map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?;
    if count > MAX_EPOCH_TRANSITION_CERTIFICATE_VOTES {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    let expected_field_count = count
        .checked_add(8)
        .ok_or(ConsensusError::NonCanonicalCertificateVotes)?;
    if frame.field_count() != expected_field_count {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    let mut votes = Vec::with_capacity(count);
    let mut previous: Option<ValidatorId> = None;
    for index in 0..count {
        let field =
            u16::try_from(index + 9).map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?;
        let vote = decode_epoch_transition_vote(frame.required_field(field)?)?;
        if previous.is_some_and(|validator| validator >= vote.validator) {
            return Err(ConsensusError::NonCanonicalCertificateVotes);
        }
        previous = Some(vote.validator);
        votes.push(vote);
    }

    let certificate = EpochTransitionCertificate {
        chain_id,
        protocol_version,
        epoch,
        next_epoch,
        current_validator_set_digest,
        next_validator_set_digest,
        activation_digest,
        votes,
    };
    if encode_epoch_transition_certificate(&certificate)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    Ok(certificate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_zebra::{Signature, SigningKey, VerificationKey};
    use protocol_types::HashAlgorithmId;
    use validator_set::ValidatorInfo;

    fn chain() -> ChainId {
        ChainId::new("epoch-transition-test-chain").unwrap()
    }
    fn protocol_version() -> ProtocolVersion {
        ProtocolVersion::new(7)
    }
    fn epoch() -> Epoch {
        Epoch::new(42)
    }
    fn next_epoch() -> Epoch {
        Epoch::new(43)
    }
    fn current_digest() -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32])
    }
    fn next_digest() -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32])
    }
    fn activation_digest() -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32])
    }
    fn validator_id(byte: u8) -> ValidatorId {
        ValidatorId::new([byte; 32])
    }
    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from([byte; 32])
    }
    fn public_key_bytes(key: &SigningKey) -> Vec<u8> {
        VerificationKey::from(key).as_ref().to_vec()
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[derive(Clone)]
    struct Ed25519TestSigner {
        id: ValidatorId,
        key: SigningKey,
    }
    impl ConsensusSigner for Ed25519TestSigner {
        fn validator_id(&self) -> ValidatorId {
            self.id
        }
        fn signature_scheme(&self) -> SignatureSchemeId {
            SignatureSchemeId::Ed25519
        }
        fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
            Ok(self.key.sign(framed).to_bytes().to_vec())
        }
    }

    struct Ed25519TestVerifier;
    impl ConsensusVerifier for Ed25519TestVerifier {
        fn verify_framed(
            &self,
            _validator: ValidatorId,
            _scheme: SignatureSchemeId,
            public_key: &[u8],
            framed: &[u8],
            signature: &[u8],
        ) -> Result<bool, String> {
            let verification_key =
                VerificationKey::try_from(public_key).map_err(|error| error.to_string())?;
            let signature_bytes: [u8; 64] = signature
                .try_into()
                .map_err(|_| "signature is not 64 bytes".to_string())?;
            Ok(verification_key
                .verify(&Signature::from(signature_bytes), framed)
                .is_ok())
        }
    }

    struct FailingInfraVerifier;
    impl ConsensusVerifier for FailingInfraVerifier {
        fn verify_framed(
            &self,
            _validator: ValidatorId,
            _scheme: SignatureSchemeId,
            _public_key: &[u8],
            _framed: &[u8],
            _signature: &[u8],
        ) -> Result<bool, String> {
            Err("verifier backend unavailable".to_string())
        }
    }

    fn validator_set(count: u8) -> ValidatorSet {
        let validators: Vec<ValidatorInfo> = (1..=count)
            .map(|byte| ValidatorInfo {
                id: validator_id(byte),
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: public_key_bytes(&signing_key(byte)),
            })
            .collect();
        ValidatorSet::new(epoch(), validators).unwrap()
    }

    fn certifier(count: u8) -> EpochTransitionCertifier {
        EpochTransitionCertifier::new(chain(), protocol_version(), epoch(), validator_set(count))
            .unwrap()
    }

    fn signer(byte: u8) -> Ed25519TestSigner {
        Ed25519TestSigner {
            id: validator_id(byte),
            key: signing_key(byte),
        }
    }

    fn cast(certifier: &EpochTransitionCertifier, byte: u8) -> EpochTransitionVote {
        certifier
            .cast_vote(
                next_epoch(),
                current_digest(),
                next_digest(),
                activation_digest(),
                &signer(byte),
            )
            .unwrap()
    }

    fn quorum_certificate(certifier: &EpochTransitionCertifier) -> EpochTransitionCertificate {
        let votes: Vec<EpochTransitionVote> = (1..=4).map(|byte| cast(certifier, byte)).collect();
        certifier
            .try_form_certificate(
                next_epoch(),
                current_digest(),
                next_digest(),
                activation_digest(),
                &votes,
                &Ed25519TestVerifier,
            )
            .unwrap()
            .expect("4 equal-power validators exceed the 3-of-4 quorum threshold")
    }

    #[test]
    fn cast_vote_signs_and_verify_vote_accepts_a_real_ed25519_signature() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        assert_eq!(vote.signature.len(), 64);
        assert_eq!(certifier.verify_vote(&vote, &Ed25519TestVerifier), Ok(()));
    }

    #[test]
    fn cast_vote_rejects_a_non_successive_next_epoch() {
        let certifier = certifier(4);
        for bad in [
            epoch(),
            Epoch::new(epoch().get() - 1),
            Epoch::new(epoch().get() + 2),
        ] {
            assert_eq!(
                certifier.cast_vote(
                    bad,
                    current_digest(),
                    next_digest(),
                    activation_digest(),
                    &signer(1)
                ),
                Err(ConsensusError::NonSuccessiveEpoch {
                    current: epoch(),
                    next: bad
                })
            );
        }
    }

    #[test]
    fn cast_vote_rejects_next_epoch_overflow() {
        let certifier = EpochTransitionCertifier::new(
            chain(),
            protocol_version(),
            Epoch::new(u64::MAX),
            ValidatorSet::new(
                Epoch::new(u64::MAX),
                vec![ValidatorInfo {
                    id: validator_id(1),
                    voting_power: 1,
                    signature_scheme: SignatureSchemeId::Ed25519,
                    public_key: public_key_bytes(&signing_key(1)),
                }],
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            certifier.cast_vote(
                Epoch::new(0),
                current_digest(),
                next_digest(),
                activation_digest(),
                &signer(1)
            ),
            Err(ConsensusError::ArithmeticOverflow)
        );
    }

    #[test]
    fn verify_vote_rejects_wrong_chain_id() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.chain_id = ChainId::new("a-different-chain").unwrap();
        assert_eq!(
            certifier.verify_vote(&vote, &Ed25519TestVerifier),
            Err(ConsensusError::ContextMismatch)
        );
    }

    #[test]
    fn verify_vote_rejects_wrong_protocol_version() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.protocol_version = ProtocolVersion::new(vote.protocol_version.get() + 1);
        assert_eq!(
            certifier.verify_vote(&vote, &Ed25519TestVerifier),
            Err(ConsensusError::ContextMismatch)
        );
    }

    #[test]
    fn verify_vote_rejects_wrong_epoch() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.epoch = Epoch::new(vote.epoch.get() + 1);
        assert_eq!(
            certifier.verify_vote(&vote, &Ed25519TestVerifier),
            Err(ConsensusError::ContextMismatch)
        );
    }

    #[test]
    fn verify_vote_rejects_a_tampered_next_epoch() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.next_epoch = Epoch::new(vote.next_epoch.get() + 1);
        assert_eq!(
            certifier.verify_vote(&vote, &Ed25519TestVerifier),
            Err(ConsensusError::NonSuccessiveEpoch {
                current: epoch(),
                next: Epoch::new(next_epoch().get() + 1)
            })
        );
    }

    #[test]
    fn verify_vote_rejects_a_member_not_in_the_validator_set() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.validator = validator_id(99);
        assert_eq!(
            certifier.verify_vote(&vote, &Ed25519TestVerifier),
            Err(ConsensusError::UnknownValidator(validator_id(99)))
        );
    }

    #[test]
    fn verify_vote_rejects_wrong_signature_scheme() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.signature_scheme = SignatureSchemeId::Secp256k1;
        assert_eq!(
            certifier.verify_vote(&vote, &Ed25519TestVerifier),
            Err(ConsensusError::SignatureSchemeMismatch(validator_id(1)))
        );
    }

    #[test]
    fn verify_vote_rejects_a_tampered_signature() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.signature[0] ^= 0xFF;
        assert_eq!(
            certifier.verify_vote(&vote, &Ed25519TestVerifier),
            Err(ConsensusError::InvalidSignature(validator_id(1)))
        );
    }

    #[test]
    fn epoch_transition_signature_cannot_be_replayed_into_the_fast_path_vote_domain() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        // Real-sign the digest32 material framed as a `FastVote` payload
        // instead of an `EpochTransitionVote` payload, under `FastVote`'s own
        // real `"fast-path-vote-v1"` domain.
        let fast_vote = crate::FastVote {
            chain_id: chain(),
            protocol_version: protocol_version(),
            epoch: epoch(),
            tx_hash: vote.current_validator_set_digest,
            execution_effects_hash: vote.activation_digest,
            validator: validator_id(1),
            signature_scheme: SignatureSchemeId::Ed25519,
            locked_objects_digest: vote.next_validator_set_digest,
            signature: Vec::new(),
        };
        let payload = crate::encode_fast_vote_payload(&fast_vote).unwrap();
        let wrong_domain_framed = frame_signature_message(
            &SignatureDomain {
                chain_id: chain(),
                protocol_version: protocol_version(),
                epoch: epoch(),
                message_type: SignatureMessageType::new("fast-path-vote-v1").unwrap(),
                signature_scheme_id: SignatureSchemeId::Ed25519,
            },
            &payload,
        )
        .unwrap();
        let mut cross_family_vote = vote;
        cross_family_vote.signature = signing_key(1)
            .sign(&wrong_domain_framed)
            .to_bytes()
            .to_vec();
        assert_eq!(
            certifier.verify_vote(&cross_family_vote, &Ed25519TestVerifier),
            Err(ConsensusError::InvalidSignature(validator_id(1)))
        );
    }

    /// Converse of the test above: a *genuine* `EpochTransitionVote`
    /// signature -- real-signed under `"fast-path-epoch-transition-v1"`
    /// over the real `EpochTransitionVote` payload -- must not verify as a
    /// `FastVote` either, even when every field value is copied across
    /// (`tx_hash`/`execution_effects_hash` populated from the transition
    /// vote's own digests) and the same validator/scheme/signature bytes
    /// are reused. Proves the cross-domain rejection holds in both
    /// directions, not just the one DR-0132 C6 was written to prevent.
    #[test]
    fn a_genuine_epoch_transition_signature_cannot_verify_as_a_fast_vote() {
        let transition_certifier = certifier(4);
        let vote = cast(&transition_certifier, 1);
        let fast_certifier: crate::FastPathCertifier =
            crate::FastPathCertifier::new(chain(), protocol_version(), epoch(), validator_set(4))
                .unwrap();
        let fake_fast_vote = crate::FastVote {
            chain_id: chain(),
            protocol_version: protocol_version(),
            epoch: epoch(),
            tx_hash: vote.current_validator_set_digest,
            execution_effects_hash: vote.activation_digest,
            validator: vote.validator,
            signature_scheme: vote.signature_scheme,
            locked_objects_digest: vote.next_validator_set_digest,
            signature: vote.signature.clone(),
        };
        assert_eq!(
            fast_certifier.verify_vote(&fake_fast_vote, &Ed25519TestVerifier),
            Err(ConsensusError::InvalidSignature(validator_id(1)))
        );
    }

    #[test]
    fn try_form_certificate_returns_none_below_quorum() {
        let certifier = certifier(4);
        let votes: Vec<EpochTransitionVote> = (1..=2).map(|byte| cast(&certifier, byte)).collect();
        assert_eq!(
            certifier
                .try_form_certificate(
                    next_epoch(),
                    current_digest(),
                    next_digest(),
                    activation_digest(),
                    &votes,
                    &Ed25519TestVerifier
                )
                .unwrap(),
            None
        );
    }

    #[test]
    fn try_form_certificate_rejects_a_non_successive_next_epoch_target() {
        let certifier = certifier(4);
        let votes: Vec<EpochTransitionVote> = (1..=4).map(|byte| cast(&certifier, byte)).collect();
        assert_eq!(
            certifier.try_form_certificate(
                Epoch::new(epoch().get() + 5),
                current_digest(),
                next_digest(),
                activation_digest(),
                &votes,
                &Ed25519TestVerifier
            ),
            Err(ConsensusError::NonSuccessiveEpoch {
                current: epoch(),
                next: Epoch::new(epoch().get() + 5)
            })
        );
    }

    #[test]
    fn try_form_certificate_is_deterministic_and_minimal_independent_of_arrival_order() {
        let certifier = certifier(4);
        let mut votes: Vec<EpochTransitionVote> =
            (1..=4).map(|byte| cast(&certifier, byte)).collect();
        let forward = certifier
            .try_form_certificate(
                next_epoch(),
                current_digest(),
                next_digest(),
                activation_digest(),
                &votes,
                &Ed25519TestVerifier,
            )
            .unwrap()
            .expect("quorum reached");
        votes.reverse();
        let reversed = certifier
            .try_form_certificate(
                next_epoch(),
                current_digest(),
                next_digest(),
                activation_digest(),
                &votes,
                &Ed25519TestVerifier,
            )
            .unwrap()
            .expect("quorum reached");

        assert_eq!(forward.votes.len(), 3);
        assert_eq!(
            encode_epoch_transition_certificate(&forward).unwrap(),
            encode_epoch_transition_certificate(&reversed).unwrap()
        );
        assert_eq!(
            forward
                .votes
                .iter()
                .map(|vote| vote.validator)
                .collect::<Vec<_>>(),
            vec![validator_id(1), validator_id(2), validator_id(3)]
        );
    }

    #[test]
    fn verify_certificate_accepts_an_alternate_valid_quorum_subset() {
        let certifier = certifier(4);
        let votes: Vec<EpochTransitionVote> = (1..=4).map(|byte| cast(&certifier, byte)).collect();
        let minimal = certifier
            .try_form_certificate(
                next_epoch(),
                current_digest(),
                next_digest(),
                activation_digest(),
                &votes,
                &Ed25519TestVerifier,
            )
            .unwrap()
            .expect("quorum reached");
        let alternate = certifier
            .try_form_certificate(
                next_epoch(),
                current_digest(),
                next_digest(),
                activation_digest(),
                &votes[1..4],
                &Ed25519TestVerifier,
            )
            .unwrap()
            .expect("quorum reached from the other 3 votes");
        assert_ne!(
            encode_epoch_transition_certificate(&minimal).unwrap(),
            encode_epoch_transition_certificate(&alternate).unwrap()
        );
        assert_eq!(
            certifier.verify_certificate(&minimal, &Ed25519TestVerifier),
            Ok(())
        );
        assert_eq!(
            certifier.verify_certificate(&alternate, &Ed25519TestVerifier),
            Ok(())
        );
    }

    #[test]
    fn verify_certificate_rejects_noncanonical_vote_order() {
        let certifier = certifier(4);
        let mut certificate = quorum_certificate(&certifier);
        certificate.votes.reverse();
        assert_eq!(
            certifier.verify_certificate(&certificate, &Ed25519TestVerifier),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    #[test]
    fn verify_certificate_rejects_duplicate_validator_votes() {
        let certifier = certifier(4);
        let mut certificate = quorum_certificate(&certifier);
        certificate.votes[1] = certificate.votes[0].clone();
        assert_eq!(
            certifier.verify_certificate(&certificate, &Ed25519TestVerifier),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    #[test]
    fn verify_certificate_rejects_a_certificate_signed_by_the_incoming_set() {
        // A validator absent from the *outgoing* set (e.g. only in the
        // incoming e+1 set) can never contribute to this certifier's quorum.
        let certifier = certifier(4);
        let mut certificate = quorum_certificate(&certifier);
        let outsider_key = signing_key(99);
        let mut outsider_vote = certificate.votes[0].clone();
        outsider_vote.validator = validator_id(99);
        let payload = encode_epoch_transition_vote_payload(&outsider_vote).unwrap();
        let framed = frame_signature_message(
            &SignatureDomain {
                chain_id: chain(),
                protocol_version: protocol_version(),
                epoch: epoch(),
                message_type: SignatureMessageType::new(EPOCH_TRANSITION_MESSAGE_TYPE).unwrap(),
                signature_scheme_id: SignatureSchemeId::Ed25519,
            },
            &payload,
        )
        .unwrap();
        outsider_vote.signature = outsider_key.sign(&framed).to_bytes().to_vec();
        certificate.votes[0] = outsider_vote;
        certificate.votes.sort_by_key(|vote| vote.validator);
        assert_eq!(
            certifier.verify_certificate(&certificate, &Ed25519TestVerifier),
            Err(ConsensusError::UnknownValidator(validator_id(99)))
        );
    }

    #[test]
    fn try_form_certificate_propagates_verifier_infrastructure_errors_instead_of_excluding_votes() {
        let certifier = certifier(4);
        let votes: Vec<EpochTransitionVote> = (1..=4).map(|byte| cast(&certifier, byte)).collect();
        assert_eq!(
            certifier.try_form_certificate(
                next_epoch(),
                current_digest(),
                next_digest(),
                activation_digest(),
                &votes,
                &FailingInfraVerifier
            ),
            Err(ConsensusError::Authenticator(
                "verifier backend unavailable".to_string()
            ))
        );
    }

    #[test]
    fn try_form_certificate_excludes_an_invalid_signature_vote_under_the_documented_policy() {
        let certifier = certifier(4);
        let mut votes: Vec<EpochTransitionVote> =
            (1..=4).map(|byte| cast(&certifier, byte)).collect();
        votes[0].signature[0] ^= 0xFF;
        let certificate = certifier
            .try_form_certificate(
                next_epoch(),
                current_digest(),
                next_digest(),
                activation_digest(),
                &votes,
                &Ed25519TestVerifier,
            )
            .unwrap()
            .expect("quorum reached from the 3 remaining valid votes");
        assert_eq!(
            certificate
                .votes
                .iter()
                .map(|vote| vote.validator)
                .collect::<Vec<_>>(),
            vec![validator_id(2), validator_id(3), validator_id(4)]
        );
    }

    #[test]
    fn epoch_transition_vote_encode_decode_round_trips() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let encoded = encode_epoch_transition_vote(&vote).unwrap();
        assert_eq!(decode_epoch_transition_vote(&encoded), Ok(vote));
    }

    #[test]
    fn epoch_transition_certificate_encode_decode_round_trips() {
        let certifier = certifier(4);
        let certificate = quorum_certificate(&certifier);
        let encoded = encode_epoch_transition_certificate(&certificate).unwrap();
        assert_eq!(
            decode_epoch_transition_certificate(&encoded),
            Ok(certificate)
        );
    }

    #[test]
    fn decode_epoch_transition_vote_rejects_a_non_successive_epoch() {
        let mut vote = vector_vote();
        vote.next_epoch = Epoch::new(vote.epoch.get() + 2);
        let encoded = encode_epoch_transition_vote(&vote).unwrap();
        assert!(matches!(
            decode_epoch_transition_vote(&encoded),
            Err(ConsensusError::NonSuccessiveEpoch { current, next })
                if current == vote.epoch && next == vote.next_epoch
        ));
    }

    #[test]
    fn decode_epoch_transition_certificate_rejects_a_non_successive_epoch() {
        let certifier = certifier(4);
        let mut certificate = quorum_certificate(&certifier);
        certificate.next_epoch = Epoch::new(certificate.epoch.get() + 2);
        let encoded = encode_epoch_transition_certificate(&certificate).unwrap();
        assert!(matches!(
            decode_epoch_transition_certificate(&encoded),
            Err(ConsensusError::NonSuccessiveEpoch { current, next })
                if current == certificate.epoch && next == certificate.next_epoch
        ));
    }

    #[test]
    fn decode_epoch_transition_vote_rejects_wrong_type_id() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let mut bytes = encode_epoch_transition_vote(&vote).unwrap();
        bytes[4] ^= 0xFF;
        assert!(matches!(
            decode_epoch_transition_vote(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId {
                    expected: EPOCH_TRANSITION_VOTE_TYPE_ID,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn decode_epoch_transition_vote_rejects_wrong_version() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let mut bytes = encode_epoch_transition_vote(&vote).unwrap();
        bytes[6] ^= 0xFF;
        assert!(matches!(
            decode_epoch_transition_vote(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedVersion {
                    expected: ENCODING_VERSION,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn decode_epoch_transition_vote_rejects_an_extra_field() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let mut frame = CanonicalStruct::new(EPOCH_TRANSITION_VOTE_TYPE_ID, ENCODING_VERSION);
        frame
            .field_bytes(1, encode_epoch_transition_vote_payload(&vote).unwrap())
            .unwrap();
        frame.field_bytes(2, vote.signature.clone()).unwrap();
        frame.field_bytes(3, vec![0u8]).unwrap();
        let bytes = frame.finish().unwrap();
        assert_eq!(
            decode_epoch_transition_vote(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(3)
            ))
        );
    }

    #[test]
    fn decode_epoch_transition_vote_rejects_a_missing_field() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let mut frame = CanonicalStruct::new(EPOCH_TRANSITION_VOTE_TYPE_ID, ENCODING_VERSION);
        frame
            .field_bytes(1, encode_epoch_transition_vote_payload(&vote).unwrap())
            .unwrap();
        let bytes = frame.finish().unwrap();
        assert_eq!(
            decode_epoch_transition_vote(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::MissingField(2)
            ))
        );
    }

    #[test]
    fn decode_epoch_transition_vote_reports_the_actual_invalid_validator_id_length() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let mut payload =
            CanonicalStruct::new(EPOCH_TRANSITION_VOTE_PAYLOAD_TYPE_ID, ENCODING_VERSION);
        payload.field_str(1, vote.chain_id.as_str()).unwrap();
        payload.field_u32(2, vote.protocol_version.get()).unwrap();
        payload.field_u64(3, vote.epoch.get()).unwrap();
        payload.field_u64(4, vote.next_epoch.get()).unwrap();
        payload
            .field_bytes(
                5,
                encode_digest32(&vote.current_validator_set_digest).unwrap(),
            )
            .unwrap();
        payload
            .field_bytes(6, encode_digest32(&vote.next_validator_set_digest).unwrap())
            .unwrap();
        payload
            .field_bytes(7, encode_digest32(&vote.activation_digest).unwrap())
            .unwrap();
        payload.field_bytes(8, vec![0u8; 31]).unwrap();
        payload
            .field_u16(9, vote.signature_scheme.as_u16())
            .unwrap();
        let mut outer = CanonicalStruct::new(EPOCH_TRANSITION_VOTE_TYPE_ID, ENCODING_VERSION);
        outer.field_bytes(1, payload.finish().unwrap()).unwrap();
        outer.field_bytes(2, vote.signature).unwrap();
        assert_eq!(
            decode_epoch_transition_vote(&outer.finish().unwrap()),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::InvalidFieldLength {
                    field_id: 8,
                    expected: 32,
                    actual: 31,
                }
            ))
        );
    }

    #[test]
    fn decode_epoch_transition_certificate_rejects_wrong_type_id() {
        let certifier = certifier(4);
        let mut bytes =
            encode_epoch_transition_certificate(&quorum_certificate(&certifier)).unwrap();
        bytes[4] ^= 0xFF;
        assert!(matches!(
            decode_epoch_transition_certificate(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId {
                    expected: EPOCH_TRANSITION_CERTIFICATE_TYPE_ID,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn decode_epoch_transition_certificate_rejects_wrong_version() {
        let certifier = certifier(4);
        let mut bytes =
            encode_epoch_transition_certificate(&quorum_certificate(&certifier)).unwrap();
        bytes[6] ^= 0xFF;
        assert!(matches!(
            decode_epoch_transition_certificate(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedVersion {
                    expected: ENCODING_VERSION,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn decode_epoch_transition_certificate_rejects_noncanonical_vote_order() {
        let certifier = certifier(4);
        let mut certificate = quorum_certificate(&certifier);
        certificate.votes.reverse();
        let bytes = encode_epoch_transition_certificate(&certificate).unwrap();
        assert_eq!(
            decode_epoch_transition_certificate(&bytes),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    #[test]
    fn decode_epoch_transition_certificate_rejects_duplicate_validator_votes() {
        let certifier = certifier(4);
        let mut certificate = quorum_certificate(&certifier);
        certificate.votes[1] = certificate.votes[0].clone();
        let bytes = encode_epoch_transition_certificate(&certificate).unwrap();
        assert_eq!(
            decode_epoch_transition_certificate(&bytes),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    #[test]
    fn decode_epoch_transition_certificate_rejects_a_declared_count_that_disagrees_with_the_fields_present()
     {
        let certifier = certifier(4);
        let certificate = quorum_certificate(&certifier);
        let mut frame =
            CanonicalStruct::new(EPOCH_TRANSITION_CERTIFICATE_TYPE_ID, ENCODING_VERSION);
        frame.field_str(1, certificate.chain_id.as_str()).unwrap();
        frame
            .field_u32(2, certificate.protocol_version.get())
            .unwrap();
        frame.field_u64(3, certificate.epoch.get()).unwrap();
        frame.field_u64(4, certificate.next_epoch.get()).unwrap();
        frame
            .field_bytes(
                5,
                encode_digest32(&certificate.current_validator_set_digest).unwrap(),
            )
            .unwrap();
        frame
            .field_bytes(
                6,
                encode_digest32(&certificate.next_validator_set_digest).unwrap(),
            )
            .unwrap();
        frame
            .field_bytes(7, encode_digest32(&certificate.activation_digest).unwrap())
            .unwrap();
        frame
            .field_u32(8, u32::try_from(certificate.votes.len()).unwrap() + 1)
            .unwrap();
        for (index, vote) in certificate.votes.iter().enumerate() {
            frame
                .field_bytes(
                    u16::try_from(index + 9).unwrap(),
                    encode_epoch_transition_vote(vote).unwrap(),
                )
                .unwrap();
        }
        let bytes = frame.finish().unwrap();
        assert_eq!(
            decode_epoch_transition_certificate(&bytes),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    #[test]
    fn decode_epoch_transition_certificate_rejects_a_declared_count_over_the_bound() {
        let certifier = certifier(4);
        let certificate = quorum_certificate(&certifier);
        let mut frame =
            CanonicalStruct::new(EPOCH_TRANSITION_CERTIFICATE_TYPE_ID, ENCODING_VERSION);
        frame.field_str(1, certificate.chain_id.as_str()).unwrap();
        frame
            .field_u32(2, certificate.protocol_version.get())
            .unwrap();
        frame.field_u64(3, certificate.epoch.get()).unwrap();
        frame.field_u64(4, certificate.next_epoch.get()).unwrap();
        frame
            .field_bytes(
                5,
                encode_digest32(&certificate.current_validator_set_digest).unwrap(),
            )
            .unwrap();
        frame
            .field_bytes(
                6,
                encode_digest32(&certificate.next_validator_set_digest).unwrap(),
            )
            .unwrap();
        frame
            .field_bytes(7, encode_digest32(&certificate.activation_digest).unwrap())
            .unwrap();
        frame
            .field_u32(
                8,
                u32::try_from(MAX_EPOCH_TRANSITION_CERTIFICATE_VOTES + 1).unwrap(),
            )
            .unwrap();
        let bytes = frame.finish().unwrap();
        assert_eq!(
            decode_epoch_transition_certificate(&bytes),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    // Pinned literal vectors for the 3 type ids this module allocates
    // (`0xD009`-`0xD00B`), independently reconstructed byte-for-byte by
    // `scripts/fast-vote-vectors.mjs` without invoking this Rust encoder.

    fn vector_vote() -> EpochTransitionVote {
        EpochTransitionVote {
            chain_id: ChainId::new("dr0132-vectors").unwrap(),
            protocol_version: ProtocolVersion::new(3),
            epoch: Epoch::new(9),
            next_epoch: Epoch::new(10),
            current_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xAA; 32]),
            next_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xBB; 32]),
            activation_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xCC; 32]),
            validator: ValidatorId::new([0x01; 32]),
            signature_scheme: SignatureSchemeId::Ed25519,
            signature: vec![0x5A; 64],
        }
    }

    #[test]
    fn epoch_transition_vote_payload_encoding_vector_0xd009_is_stable() {
        let bytes = encode_epoch_transition_vote_payload(&vector_vote()).unwrap();
        assert_eq!(
            hex(&bytes),
            "534e524509d00100090001000e0000006472303133322d766563746f72730200040000000300000003000800000009000000000000000400080000000a00000000000000050038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa060038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb070038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc08002000000001010101010101010101010101010101010101010101010101010101010101010900020000000100"
        );
    }

    #[test]
    fn epoch_transition_vote_encoding_vector_0xd00a_is_stable() {
        let bytes = encode_epoch_transition_vote(&vector_vote()).unwrap();
        assert_eq!(
            hex(&bytes),
            "534e52450ad00100020001002c010000534e524509d00100090001000e0000006472303133322d766563746f72730200040000000300000003000800000009000000000000000400080000000a00000000000000050038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa060038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb070038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc080020000000010101010101010101010101010101010101010101010101010101010101010109000200000001000200400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
        );
    }

    #[test]
    fn epoch_transition_certificate_encoding_vector_0xd00b_is_stable() {
        let vote_a = vector_vote();
        let mut vote_b = vector_vote();
        vote_b.validator = ValidatorId::new([0x02; 32]);
        vote_b.signature = vec![0x7C; 64];
        let certificate = EpochTransitionCertificate {
            chain_id: vote_a.chain_id.clone(),
            protocol_version: vote_a.protocol_version,
            epoch: vote_a.epoch,
            next_epoch: vote_a.next_epoch,
            current_validator_set_digest: vote_a.current_validator_set_digest,
            next_validator_set_digest: vote_a.next_validator_set_digest,
            activation_digest: vote_a.activation_digest,
            votes: vec![vote_a, vote_b],
        };
        let bytes = encode_epoch_transition_certificate(&certificate).unwrap();
        assert_eq!(
            hex(&bytes),
            "534e52450bd001000a0001000e0000006472303133322d766563746f72730200040000000300000003000800000009000000000000000400080000000a00000000000000050038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa060038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb070038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc08000400000002000000090082010000534e52450ad00100020001002c010000534e524509d00100090001000e0000006472303133322d766563746f72730200040000000300000003000800000009000000000000000400080000000a00000000000000050038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa060038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb070038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc080020000000010101010101010101010101010101010101010101010101010101010101010109000200000001000200400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0a0082010000534e52450ad00100020001002c010000534e524509d00100090001000e0000006472303133322d766563746f72730200040000000300000003000800000009000000000000000400080000000a00000000000000050038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa060038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb070038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc080020000000020202020202020202020202020202020202020202020202020202020202020209000200000001000200400000007c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c"
        );
    }
}
