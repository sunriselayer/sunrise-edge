//! Owned-object FastVote / FastCertificate canonical types (DR-0129 phase 0).
//!
//! This module is deliberately independent of [`ChainedHotStuff`](crate::ChainedHotStuff):
//! there is no proposal, view, height, or persisted chain state, and its
//! signature domain (`"fast-path-vote-v1"`) is distinct from
//! `ChainedHotStuff`'s, so a signature can never be replayed across the two
//! families. A [`FastPathCertifier`] is a stateless, epoch-scoped
//! signer/verifier bound to one immutable [`ValidatorSet`] snapshot (a
//! static permissioned epoch, not a later shared-object/validator-set-change
//! design). Callers are responsible for collecting [`FastVote`]s from an
//! untrusted relay and for deciding, out of band, which `(tx_hash,
//! execution_effects_hash)` pair they are trying to certify; this module only
//! proves that a resulting [`FastCertificate`] carries a canonically ordered,
//! minimal-by-canonical-order quorum of valid signatures over that exact
//! pair. See [`FastPathCertifier::try_form_certificate`] for the exact,
//! narrow policy under which an untrusted candidate vote may be excluded
//! rather than causing the whole call to fail.
//!
//! Certificate formation is deterministic and vote-order independent: votes
//! are always canonically sorted by [`ValidatorId`] before being counted, and
//! [`FastPathCertifier::try_form_certificate`] stops accumulating as soon as
//! the quorum threshold is met, so two callers who observe the same valid
//! vote set in different arrival orders produce byte-identical certificates.
//!
//! **Scope (DR-0129 phase 0):** this module provides only the canonical
//! types, wire codec, and signature/quorum aggregation library described
//! above. It does not lock objects, apply effects, publish anything durably,
//! or wire into any HTTP/CLI ingress — validator-side execution, per-object
//! locking, atomic certificate publication, and any live activation are a
//! separate, not-yet-designed follow-up. See `TODO.md` and
//! `docs/architecture/decisions/0129-fastvote-fastcertificate-fast-path.md`.

use crate::{ConsensusError, ConsensusSigner, ConsensusVerifier, validate_signature_length};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalStruct, decode_canonical_frame, decode_digest32,
    encode_digest32,
};
use crypto::{SignatureDomain, SignatureMessageType, frame_signature_message};
use protocol_types::{ChainId, Digest32, Epoch, ProtocolVersion, SignatureSchemeId, ValidatorId};
use std::collections::BTreeMap;
use validator_set::ValidatorSet;

const FAST_VOTE_PAYLOAD_TYPE_ID: u16 = 0xD006;
const FAST_VOTE_TYPE_ID: u16 = 0xD007;
const FAST_CERTIFICATE_TYPE_ID: u16 = 0xD008;
const ENCODING_VERSION: u16 = 1;
const FAST_VOTE_MESSAGE_TYPE: &str = "fast-path-vote-v1";

/// Matches [`validator_set`]'s own bound on one epoch snapshot; a
/// [`FastCertificate`] can never carry more votes than there are validators.
const MAX_FAST_CERTIFICATE_VOTES: usize = 10_000;

/// A single validator's signed attestation that it would (or did) apply an
/// owned-object transaction with exactly this transaction hash and execution
/// effects hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastVote {
    /// Chain replay boundary.
    pub chain_id: ChainId,
    /// Protocol replay boundary.
    pub protocol_version: ProtocolVersion,
    /// Epoch replay boundary.
    pub epoch: Epoch,
    /// `execution::hash_transaction` digest of the certified transaction.
    pub tx_hash: Digest32,
    /// `execution::hash_execution_effects` digest of the certified effects.
    pub execution_effects_hash: Digest32,
    /// Voting validator.
    pub validator: ValidatorId,
    /// Signature scheme registered for `validator` in the active set.
    pub signature_scheme: SignatureSchemeId,
    /// Signature over the domain-framed vote payload.
    pub signature: Vec<u8>,
}

/// A minimal, canonically ordered quorum of [`FastVote`]s for one
/// `(tx_hash, execution_effects_hash)` pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastCertificate {
    /// Chain replay boundary.
    pub chain_id: ChainId,
    /// Protocol replay boundary.
    pub protocol_version: ProtocolVersion,
    /// Epoch replay boundary.
    pub epoch: Epoch,
    /// Certified transaction hash.
    pub tx_hash: Digest32,
    /// Certified execution effects hash.
    pub execution_effects_hash: Digest32,
    /// Canonically validator-ID-ordered, deduplicated votes.
    pub votes: Vec<FastVote>,
}

/// Stateless epoch-scoped signer/verifier for owned-object fast-path votes.
///
/// Unlike [`ChainedHotStuff`](crate::ChainedHotStuff), this type persists no
/// view/height/lock state: every method is a pure function of its arguments
/// and the immutable `(chain_id, protocol_version, epoch, validator_set)`
/// context captured at construction.
#[derive(Clone, Debug)]
pub struct FastPathCertifier {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set: ValidatorSet,
}

impl FastPathCertifier {
    /// Creates a certifier bound to one epoch's validator-set snapshot.
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

    /// Returns the bound epoch replay boundary.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the bound validator-set snapshot.
    #[must_use]
    pub const fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Returns the strict quorum threshold of the bound validator set.
    #[must_use]
    pub const fn quorum_threshold(&self) -> u64 {
        self.validator_set.quorum_threshold()
    }

    /// Signs and returns one [`FastVote`] for `(tx_hash, execution_effects_hash)`.
    pub fn cast_vote<S: ConsensusSigner>(
        &self,
        tx_hash: Digest32,
        execution_effects_hash: Digest32,
        signer: &S,
    ) -> Result<FastVote, ConsensusError> {
        self.ensure_registered_scheme(signer.validator_id(), signer.signature_scheme())?;
        let mut vote = FastVote {
            chain_id: self.chain_id.clone(),
            protocol_version: self.protocol_version,
            epoch: self.epoch,
            tx_hash,
            execution_effects_hash,
            validator: signer.validator_id(),
            signature_scheme: signer.signature_scheme(),
            signature: Vec::new(),
        };
        let framed =
            self.signature_frame(vote.signature_scheme, &encode_fast_vote_payload(&vote)?)?;
        vote.signature = signer
            .sign_framed(&framed)
            .map_err(ConsensusError::Authenticator)?;
        validate_signature_length(&vote.signature)?;
        Ok(vote)
    }

    /// Validates one [`FastVote`]'s context, registered scheme, and signature.
    pub fn verify_vote<V: ConsensusVerifier>(
        &self,
        vote: &FastVote,
        verifier: &V,
    ) -> Result<(), ConsensusError> {
        self.ensure_context(&vote.chain_id, vote.protocol_version, vote.epoch)?;
        self.ensure_registered_scheme(vote.validator, vote.signature_scheme)?;
        validate_signature_length(&vote.signature)?;
        let info = self
            .validator_set
            .get(vote.validator)
            .ok_or(ConsensusError::UnknownValidator(vote.validator))?;
        let framed =
            self.signature_frame(vote.signature_scheme, &encode_fast_vote_payload(vote)?)?;
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

    /// Deterministically forms the minimal canonically ordered certificate for
    /// `(tx_hash, execution_effects_hash)`, or `None` if `votes` does not
    /// carry quorum voting power for that exact pair.
    ///
    /// `votes` is untrusted relay input that may mix in messages for other
    /// pairs or other contexts. This method applies exactly one explicit,
    /// documented exclusion policy and otherwise fails closed:
    ///
    /// * A vote whose `(tx_hash, execution_effects_hash, chain_id,
    ///   protocol_version, epoch)` header does not match this call's target
    ///   is unrelated relay noise and is excluded without being verified at
    ///   all.
    /// * A vote that *is* addressed to this exact pair and context but fails
    ///   [`Self::verify_vote`] with [`ConsensusError::UnknownValidator`],
    ///   [`ConsensusError::SignatureSchemeMismatch`],
    ///   [`ConsensusError::InvalidSignatureLength`],
    ///   [`ConsensusError::InvalidSignature`], or
    ///   [`ConsensusError::ContextMismatch`] is itself malformed or
    ///   cryptographically invalid — not a sign of infrastructure failure —
    ///   and is excluded under this same policy.
    /// * Any other [`verify_vote`](Self::verify_vote) error (in particular
    ///   [`ConsensusError::Authenticator`], which signals that the caller's
    ///   own [`ConsensusVerifier`] adapter itself failed, not that a
    ///   signature was checked and found invalid) is **not** swallowed: this
    ///   method returns that error immediately, failing closed rather than
    ///   silently forming a certificate over a possibly-unverified vote set.
    ///
    /// If one validator supplies multiple valid signatures for the same
    /// payload, the lexicographically smallest signature is retained. This
    /// keeps formation independent of arrival order even for a future
    /// signature scheme that permits more than one valid representation.
    /// The result depends only on the *set* of valid matching votes, never on
    /// `votes`'s order.
    pub fn try_form_certificate<V: ConsensusVerifier>(
        &self,
        tx_hash: Digest32,
        execution_effects_hash: Digest32,
        votes: &[FastVote],
        verifier: &V,
    ) -> Result<Option<FastCertificate>, ConsensusError> {
        let mut by_validator: BTreeMap<ValidatorId, &FastVote> = BTreeMap::new();
        for vote in votes {
            if vote.tx_hash != tx_hash || vote.execution_effects_hash != execution_effects_hash {
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
                    | ConsensusError::ContextMismatch,
                ) => continue,
                Err(other) => return Err(other),
            }
            by_validator
                .entry(vote.validator)
                .and_modify(|current: &mut &FastVote| {
                    if vote.signature < current.signature {
                        *current = vote;
                    }
                })
                .or_insert(vote);
        }

        let mut power = 0u64;
        let mut selected: Vec<FastVote> = Vec::new();
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
                return Ok(Some(FastCertificate {
                    chain_id: self.chain_id.clone(),
                    protocol_version: self.protocol_version,
                    epoch: self.epoch,
                    tx_hash,
                    execution_effects_hash,
                    votes: selected,
                }));
            }
        }
        Ok(None)
    }

    /// Validates a [`FastCertificate`]'s context, canonical vote order,
    /// per-vote signatures, and quorum voting power.
    ///
    /// Does not require minimality: any canonically ordered, quorum-carrying,
    /// duplicate-free vote set for the same header verifies. Minimality is a
    /// [`Self::try_form_certificate`] formation property, not a safety
    /// requirement, so an "alternate valid" certificate for the same
    /// `(tx_hash, execution_effects_hash)` with a different (still quorum)
    /// vote subset also verifies.
    pub fn verify_certificate<V: ConsensusVerifier>(
        &self,
        certificate: &FastCertificate,
        verifier: &V,
    ) -> Result<(), ConsensusError> {
        self.ensure_context(
            &certificate.chain_id,
            certificate.protocol_version,
            certificate.epoch,
        )?;
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
                || vote.tx_hash != certificate.tx_hash
                || vote.execution_effects_hash != certificate.execution_effects_hash
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
                message_type: SignatureMessageType::new(FAST_VOTE_MESSAGE_TYPE)?,
                signature_scheme_id,
            },
            payload,
        )?)
    }
}

/// Encodes the signable [`FastVote`] payload without its signature.
pub fn encode_fast_vote_payload(vote: &FastVote) -> Result<Vec<u8>, ConsensusError> {
    let mut canonical = CanonicalStruct::new(FAST_VOTE_PAYLOAD_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, vote.chain_id.as_str())?;
    canonical.field_u32(2, vote.protocol_version.get())?;
    canonical.field_u64(3, vote.epoch.get())?;
    canonical.field_bytes(4, encode_digest32(&vote.tx_hash)?)?;
    canonical.field_bytes(5, encode_digest32(&vote.execution_effects_hash)?)?;
    canonical.field_bytes(6, vote.validator.as_bytes())?;
    canonical.field_u16(7, vote.signature_scheme.as_u16())?;
    Ok(canonical.finish()?)
}

/// Encodes a complete signed [`FastVote`].
pub fn encode_fast_vote(vote: &FastVote) -> Result<Vec<u8>, ConsensusError> {
    validate_signature_length(&vote.signature)?;
    let mut canonical = CanonicalStruct::new(FAST_VOTE_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_fast_vote_payload(vote)?)?;
    canonical.field_bytes(2, vote.signature.clone())?;
    Ok(canonical.finish()?)
}

/// Decodes and strictly re-validates one canonical [`FastVote`].
///
/// Beyond the shared canonical-frame guarantees, this requires the fast-vote
/// type id/encoding version, exactly fields 1-7 in the nested payload frame
/// and 1-2 in the outer frame, a non-empty bounded signature, and byte-exact
/// re-encoding of the decoded value.
pub fn decode_fast_vote(input: &[u8]) -> Result<FastVote, ConsensusError> {
    let outer = decode_canonical_frame(input)?;
    outer.require_type(FAST_VOTE_TYPE_ID)?;
    outer.require_version(ENCODING_VERSION)?;
    outer.require_only_fields(&[1, 2])?;
    let payload_bytes = outer.required_field(1)?;
    let signature = outer.required_field(2)?.to_vec();

    let payload = decode_canonical_frame(payload_bytes)?;
    payload.require_type(FAST_VOTE_PAYLOAD_TYPE_ID)?;
    payload.require_version(ENCODING_VERSION)?;
    payload.require_only_fields(&[1, 2, 3, 4, 5, 6, 7])?;

    let chain_id =
        ChainId::new(payload.required_str(1)?.to_owned()).map_err(ConsensusError::ProtocolType)?;
    let protocol_version = ProtocolVersion::new(payload.required_u32(2)?);
    let epoch = Epoch::new(payload.required_u64(3)?);
    let tx_hash = decode_digest32(payload.required_field(4)?)?;
    let execution_effects_hash = decode_digest32(payload.required_field(5)?)?;
    let validator_field = payload.required_field(6)?;
    let validator_bytes: [u8; 32] = validator_field.try_into().map_err(|_| {
        ConsensusError::CanonicalDecoding(CanonicalDecodingError::InvalidFieldLength {
            field_id: 6,
            expected: 32,
            actual: validator_field.len(),
        })
    })?;
    let signature_scheme = SignatureSchemeId::try_from(payload.required_u16(7)?)
        .map_err(ConsensusError::ProtocolType)?;

    let vote = FastVote {
        chain_id,
        protocol_version,
        epoch,
        tx_hash,
        execution_effects_hash,
        validator: ValidatorId::new(validator_bytes),
        signature_scheme,
        signature,
    };
    if encode_fast_vote(&vote)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    Ok(vote)
}

/// Encodes a [`FastCertificate`] with its votes in the caller's given order.
///
/// Callers that want the canonical, arrival-order-independent representation
/// must pass votes already sorted by [`ValidatorId`] (as
/// [`FastPathCertifier::try_form_certificate`] always returns them).
pub fn encode_fast_certificate(certificate: &FastCertificate) -> Result<Vec<u8>, ConsensusError> {
    if certificate.votes.len() > MAX_FAST_CERTIFICATE_VOTES {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    let mut canonical = CanonicalStruct::new(FAST_CERTIFICATE_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, certificate.chain_id.as_str())?;
    canonical.field_u32(2, certificate.protocol_version.get())?;
    canonical.field_u64(3, certificate.epoch.get())?;
    canonical.field_bytes(4, encode_digest32(&certificate.tx_hash)?)?;
    canonical.field_bytes(5, encode_digest32(&certificate.execution_effects_hash)?)?;
    canonical.field_u32(
        6,
        u32::try_from(certificate.votes.len())
            .map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?,
    )?;
    for (index, vote) in certificate.votes.iter().enumerate() {
        let field =
            u16::try_from(index + 7).map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?;
        canonical.field_bytes(field, encode_fast_vote(vote)?)?;
    }
    Ok(canonical.finish()?)
}

/// Decodes and strictly re-validates one canonical [`FastCertificate`].
///
/// Beyond the shared canonical-frame guarantees, this requires the
/// fast-certificate type id/encoding version, an exact declared vote count
/// bounded by [`MAX_FAST_CERTIFICATE_VOTES`], every nested [`FastVote`] to
/// decode under [`decode_fast_vote`], and byte-exact re-encoding of the
/// decoded value. It does not verify signatures or quorum; callers must
/// still call [`FastPathCertifier::verify_certificate`].
pub fn decode_fast_certificate(input: &[u8]) -> Result<FastCertificate, ConsensusError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(FAST_CERTIFICATE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;

    let chain_id =
        ChainId::new(frame.required_str(1)?.to_owned()).map_err(ConsensusError::ProtocolType)?;
    let protocol_version = ProtocolVersion::new(frame.required_u32(2)?);
    let epoch = Epoch::new(frame.required_u64(3)?);
    let tx_hash = decode_digest32(frame.required_field(4)?)?;
    let execution_effects_hash = decode_digest32(frame.required_field(5)?)?;
    let count = usize::try_from(frame.required_u32(6)?)
        .map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?;
    if count > MAX_FAST_CERTIFICATE_VOTES {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    let expected_field_count = count
        .checked_add(6)
        .ok_or(ConsensusError::NonCanonicalCertificateVotes)?;
    if frame.field_count() != expected_field_count {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    let mut votes = Vec::with_capacity(count);
    let mut previous: Option<ValidatorId> = None;
    for index in 0..count {
        let field =
            u16::try_from(index + 7).map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?;
        let vote = decode_fast_vote(frame.required_field(field)?)?;
        if previous.is_some_and(|validator| validator >= vote.validator) {
            return Err(ConsensusError::NonCanonicalCertificateVotes);
        }
        previous = Some(vote.validator);
        votes.push(vote);
    }

    let certificate = FastCertificate {
        chain_id,
        protocol_version,
        epoch,
        tx_hash,
        execution_effects_hash,
        votes,
    };
    if encode_fast_certificate(&certificate)?.as_slice() != input {
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
        ChainId::new("fast-vote-test-chain").unwrap()
    }
    fn protocol_version() -> ProtocolVersion {
        ProtocolVersion::new(7)
    }
    fn epoch() -> Epoch {
        Epoch::new(42)
    }
    fn tx_hash() -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32])
    }
    fn effects_hash() -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32])
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

    /// A real Ed25519 [`ConsensusSigner`] backed by `ed25519-zebra`, the
    /// same crate `crypto::Ed25519Verifier` pins for consensus-deterministic
    /// verification.
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

    /// A real Ed25519 [`ConsensusVerifier`] that performs a genuine
    /// accept/reject cryptographic decision (never a canned answer).
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

    /// A verifier that always fails with an infrastructure error and never
    /// reaches a genuine accept/reject decision, modelling a broken adapter
    /// (for example an unreachable HSM or crashed verifier process) rather
    /// than a cryptographically invalid vote.
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

    /// Accepts any structurally valid candidate so duplicate-signature
    /// selection can be tested independently of Ed25519's deterministic
    /// signature representation.
    struct AcceptingVerifier;
    impl ConsensusVerifier for AcceptingVerifier {
        fn verify_framed(
            &self,
            _validator: ValidatorId,
            _scheme: SignatureSchemeId,
            _public_key: &[u8],
            _framed: &[u8],
            _signature: &[u8],
        ) -> Result<bool, String> {
            Ok(true)
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

    fn certifier(count: u8) -> FastPathCertifier {
        FastPathCertifier::new(chain(), protocol_version(), epoch(), validator_set(count)).unwrap()
    }

    fn signer(byte: u8) -> Ed25519TestSigner {
        Ed25519TestSigner {
            id: validator_id(byte),
            key: signing_key(byte),
        }
    }

    fn cast(certifier: &FastPathCertifier, byte: u8) -> FastVote {
        certifier
            .cast_vote(tx_hash(), effects_hash(), &signer(byte))
            .unwrap()
    }

    /// Forms the deterministic minimal 3-of-4 quorum certificate over the 4
    /// standard test validators.
    fn quorum_certificate(certifier: &FastPathCertifier) -> FastCertificate {
        let votes: Vec<FastVote> = (1..=4).map(|byte| cast(certifier, byte)).collect();
        certifier
            .try_form_certificate(tx_hash(), effects_hash(), &votes, &Ed25519TestVerifier)
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
    fn fast_vote_signature_cannot_be_replayed_across_the_hotstuff_vote_domain() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let payload = encode_fast_vote_payload(&vote).unwrap();

        // Real-sign the identical canonical FastVote payload bytes, but
        // under `ChainedHotStuff`'s own real vote message-type domain
        // instead of `fast-path-vote-v1`.
        let wrong_domain_framed = frame_signature_message(
            &SignatureDomain {
                chain_id: chain(),
                protocol_version: protocol_version(),
                epoch: epoch(),
                message_type: SignatureMessageType::new(crate::VOTE_MESSAGE_TYPE).unwrap(),
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

    #[test]
    fn try_form_certificate_returns_none_below_quorum() {
        let certifier = certifier(4);
        let votes: Vec<FastVote> = (1..=2).map(|byte| cast(&certifier, byte)).collect();
        assert_eq!(
            certifier
                .try_form_certificate(tx_hash(), effects_hash(), &votes, &Ed25519TestVerifier)
                .unwrap(),
            None
        );
    }

    #[test]
    fn try_form_certificate_is_deterministic_and_minimal_independent_of_arrival_order() {
        let certifier = certifier(4);
        let mut votes: Vec<FastVote> = (1..=4).map(|byte| cast(&certifier, byte)).collect();
        let forward = certifier
            .try_form_certificate(tx_hash(), effects_hash(), &votes, &Ed25519TestVerifier)
            .unwrap()
            .expect("quorum reached");
        votes.reverse();
        let reversed = certifier
            .try_form_certificate(tx_hash(), effects_hash(), &votes, &Ed25519TestVerifier)
            .unwrap()
            .expect("quorum reached");

        assert_eq!(forward.votes.len(), 3);
        assert_eq!(
            encode_fast_certificate(&forward).unwrap(),
            encode_fast_certificate(&reversed).unwrap()
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
    fn try_form_certificate_selects_duplicate_valid_signatures_independent_of_arrival_order() {
        let certifier = certifier(4);
        let mut votes: Vec<FastVote> = (1..=4).map(|byte| cast(&certifier, byte)).collect();
        let mut alternate = votes[0].clone();
        alternate.signature = vec![0xFF; 64];
        votes.push(alternate);

        let forward = certifier
            .try_form_certificate(tx_hash(), effects_hash(), &votes, &AcceptingVerifier)
            .unwrap()
            .expect("quorum reached");
        votes.reverse();
        let reversed = certifier
            .try_form_certificate(tx_hash(), effects_hash(), &votes, &AcceptingVerifier)
            .unwrap()
            .expect("quorum reached");

        assert_eq!(
            encode_fast_certificate(&forward).unwrap(),
            encode_fast_certificate(&reversed).unwrap()
        );
        assert_ne!(forward.votes[0].signature, vec![0xFF; 64]);
    }

    #[test]
    fn verify_certificate_accepts_an_alternate_valid_quorum_subset() {
        let certifier = certifier(4);
        let votes: Vec<FastVote> = (1..=4).map(|byte| cast(&certifier, byte)).collect();
        let minimal = certifier
            .try_form_certificate(tx_hash(), effects_hash(), &votes, &Ed25519TestVerifier)
            .unwrap()
            .expect("quorum reached");
        let alternate = certifier
            .try_form_certificate(
                tx_hash(),
                effects_hash(),
                &votes[1..4],
                &Ed25519TestVerifier,
            )
            .unwrap()
            .expect("quorum reached from the other 3 votes");

        assert_ne!(
            encode_fast_certificate(&minimal).unwrap(),
            encode_fast_certificate(&alternate).unwrap()
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
    fn try_form_certificate_propagates_verifier_infrastructure_errors_instead_of_excluding_votes() {
        let certifier = certifier(4);
        let votes: Vec<FastVote> = (1..=4).map(|byte| cast(&certifier, byte)).collect();
        assert_eq!(
            certifier.try_form_certificate(
                tx_hash(),
                effects_hash(),
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
        let mut votes: Vec<FastVote> = (1..=4).map(|byte| cast(&certifier, byte)).collect();
        votes[0].signature[0] ^= 0xFF;

        let certificate = certifier
            .try_form_certificate(tx_hash(), effects_hash(), &votes, &Ed25519TestVerifier)
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
    fn fast_vote_encode_decode_round_trips() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let encoded = encode_fast_vote(&vote).unwrap();
        assert_eq!(decode_fast_vote(&encoded), Ok(vote));
    }

    #[test]
    fn fast_certificate_encode_decode_round_trips() {
        let certifier = certifier(4);
        let certificate = quorum_certificate(&certifier);
        let encoded = encode_fast_certificate(&certificate).unwrap();
        assert_eq!(decode_fast_certificate(&encoded), Ok(certificate));
    }

    #[test]
    fn decode_fast_vote_rejects_wrong_type_id() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let mut bytes = encode_fast_vote(&vote).unwrap();
        bytes[4] ^= 0xFF;
        assert!(matches!(
            decode_fast_vote(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId {
                    expected: FAST_VOTE_TYPE_ID,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn decode_fast_vote_rejects_wrong_version() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let mut bytes = encode_fast_vote(&vote).unwrap();
        bytes[6] ^= 0xFF;
        assert!(matches!(
            decode_fast_vote(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedVersion {
                    expected: ENCODING_VERSION,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn decode_fast_vote_rejects_an_extra_field() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let mut frame = CanonicalStruct::new(FAST_VOTE_TYPE_ID, ENCODING_VERSION);
        frame
            .field_bytes(1, encode_fast_vote_payload(&vote).unwrap())
            .unwrap();
        frame.field_bytes(2, vote.signature.clone()).unwrap();
        frame.field_bytes(3, vec![0u8]).unwrap();
        let bytes = frame.finish().unwrap();
        assert_eq!(
            decode_fast_vote(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(3)
            ))
        );
    }

    #[test]
    fn decode_fast_vote_rejects_a_missing_field() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let mut frame = CanonicalStruct::new(FAST_VOTE_TYPE_ID, ENCODING_VERSION);
        frame
            .field_bytes(1, encode_fast_vote_payload(&vote).unwrap())
            .unwrap();
        let bytes = frame.finish().unwrap();
        assert_eq!(
            decode_fast_vote(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::MissingField(2)
            ))
        );
    }

    #[test]
    fn decode_fast_vote_reports_the_actual_invalid_validator_id_length() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let mut payload = CanonicalStruct::new(FAST_VOTE_PAYLOAD_TYPE_ID, ENCODING_VERSION);
        payload.field_str(1, vote.chain_id.as_str()).unwrap();
        payload.field_u32(2, vote.protocol_version.get()).unwrap();
        payload.field_u64(3, vote.epoch.get()).unwrap();
        payload
            .field_bytes(4, encode_digest32(&vote.tx_hash).unwrap())
            .unwrap();
        payload
            .field_bytes(5, encode_digest32(&vote.execution_effects_hash).unwrap())
            .unwrap();
        payload.field_bytes(6, vec![0u8; 31]).unwrap();
        payload
            .field_u16(7, vote.signature_scheme.as_u16())
            .unwrap();
        let mut outer = CanonicalStruct::new(FAST_VOTE_TYPE_ID, ENCODING_VERSION);
        outer.field_bytes(1, payload.finish().unwrap()).unwrap();
        outer.field_bytes(2, vote.signature).unwrap();

        assert_eq!(
            decode_fast_vote(&outer.finish().unwrap()),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::InvalidFieldLength {
                    field_id: 6,
                    expected: 32,
                    actual: 31,
                }
            ))
        );
    }

    #[test]
    fn decode_fast_certificate_rejects_wrong_type_id() {
        let certifier = certifier(4);
        let mut bytes = encode_fast_certificate(&quorum_certificate(&certifier)).unwrap();
        bytes[4] ^= 0xFF;
        assert!(matches!(
            decode_fast_certificate(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId {
                    expected: FAST_CERTIFICATE_TYPE_ID,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn decode_fast_certificate_rejects_wrong_version() {
        let certifier = certifier(4);
        let mut bytes = encode_fast_certificate(&quorum_certificate(&certifier)).unwrap();
        bytes[6] ^= 0xFF;
        assert!(matches!(
            decode_fast_certificate(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedVersion {
                    expected: ENCODING_VERSION,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn decode_fast_certificate_rejects_noncanonical_vote_order() {
        let certifier = certifier(4);
        let mut certificate = quorum_certificate(&certifier);
        certificate.votes.reverse();
        let bytes = encode_fast_certificate(&certificate).unwrap();
        assert_eq!(
            decode_fast_certificate(&bytes),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    #[test]
    fn decode_fast_certificate_rejects_duplicate_validator_votes() {
        let certifier = certifier(4);
        let mut certificate = quorum_certificate(&certifier);
        certificate.votes[1] = certificate.votes[0].clone();
        let bytes = encode_fast_certificate(&certificate).unwrap();
        assert_eq!(
            decode_fast_certificate(&bytes),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    #[test]
    fn decode_fast_certificate_rejects_a_declared_count_that_disagrees_with_the_fields_present() {
        let certifier = certifier(4);
        let certificate = quorum_certificate(&certifier);
        let mut frame = CanonicalStruct::new(FAST_CERTIFICATE_TYPE_ID, ENCODING_VERSION);
        frame.field_str(1, certificate.chain_id.as_str()).unwrap();
        frame
            .field_u32(2, certificate.protocol_version.get())
            .unwrap();
        frame.field_u64(3, certificate.epoch.get()).unwrap();
        frame
            .field_bytes(4, encode_digest32(&certificate.tx_hash).unwrap())
            .unwrap();
        frame
            .field_bytes(
                5,
                encode_digest32(&certificate.execution_effects_hash).unwrap(),
            )
            .unwrap();
        // Declares one more vote than the 3 actually present.
        frame
            .field_u32(6, u32::try_from(certificate.votes.len()).unwrap() + 1)
            .unwrap();
        for (index, vote) in certificate.votes.iter().enumerate() {
            frame
                .field_bytes(
                    u16::try_from(index + 7).unwrap(),
                    encode_fast_vote(vote).unwrap(),
                )
                .unwrap();
        }
        let bytes = frame.finish().unwrap();
        assert_eq!(
            decode_fast_certificate(&bytes),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    #[test]
    fn decode_fast_certificate_rejects_a_declared_count_over_the_bound() {
        let certifier = certifier(4);
        let certificate = quorum_certificate(&certifier);
        let mut frame = CanonicalStruct::new(FAST_CERTIFICATE_TYPE_ID, ENCODING_VERSION);
        frame.field_str(1, certificate.chain_id.as_str()).unwrap();
        frame
            .field_u32(2, certificate.protocol_version.get())
            .unwrap();
        frame.field_u64(3, certificate.epoch.get()).unwrap();
        frame
            .field_bytes(4, encode_digest32(&certificate.tx_hash).unwrap())
            .unwrap();
        frame
            .field_bytes(
                5,
                encode_digest32(&certificate.execution_effects_hash).unwrap(),
            )
            .unwrap();
        frame
            .field_u32(6, u32::try_from(MAX_FAST_CERTIFICATE_VOTES + 1).unwrap())
            .unwrap();
        let bytes = frame.finish().unwrap();
        assert_eq!(
            decode_fast_certificate(&bytes),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    // Pinned literal vectors for the 3 type ids this module allocates
    // (`0xD006`-`0xD008`), independently reconstructed byte-for-byte by
    // `scripts/fast-vote-vectors.mjs` without invoking this Rust encoder.
    // Fixed, non-cryptographic signature bytes are used here deliberately:
    // these vectors pin the *canonical framing*, which does not depend on
    // signature validity (see the real-Ed25519 tests above for that).

    fn vector_vote() -> FastVote {
        FastVote {
            chain_id: ChainId::new("dr0129-vectors").unwrap(),
            protocol_version: ProtocolVersion::new(3),
            epoch: Epoch::new(9),
            tx_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0xAA; 32]),
            execution_effects_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0xBB; 32]),
            validator: ValidatorId::new([0x01; 32]),
            signature_scheme: SignatureSchemeId::Ed25519,
            signature: vec![0x5A; 64],
        }
    }

    #[test]
    fn fast_vote_payload_encoding_vector_0xd006_is_stable() {
        let bytes = encode_fast_vote_payload(&vector_vote()).unwrap();
        assert_eq!(
            hex(&bytes),
            "534e524506d00100070001000e0000006472303132392d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa050038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb06002000000001010101010101010101010101010101010101010101010101010101010101010700020000000100"
        );
    }

    #[test]
    fn fast_vote_encoding_vector_0xd007_is_stable() {
        let bytes = encode_fast_vote(&vector_vote()).unwrap();
        assert_eq!(
            hex(&bytes),
            "534e524507d0010002000100e0000000534e524506d00100070001000e0000006472303132392d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa050038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb060020000000010101010101010101010101010101010101010101010101010101010101010107000200000001000200400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
        );
    }

    #[test]
    fn fast_certificate_encoding_vector_0xd008_is_stable() {
        let vote_a = vector_vote();
        let mut vote_b = vector_vote();
        vote_b.validator = ValidatorId::new([0x02; 32]);
        vote_b.signature = vec![0x7C; 64];
        let certificate = FastCertificate {
            chain_id: vote_a.chain_id.clone(),
            protocol_version: vote_a.protocol_version,
            epoch: vote_a.epoch,
            tx_hash: vote_a.tx_hash,
            execution_effects_hash: vote_a.execution_effects_hash,
            votes: vec![vote_a, vote_b],
        };
        let bytes = encode_fast_certificate(&certificate).unwrap();
        assert_eq!(
            hex(&bytes),
            "534e524508d00100080001000e0000006472303132392d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa050038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb06000400000002000000070036010000534e524507d0010002000100e0000000534e524506d00100070001000e0000006472303132392d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa050038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb060020000000010101010101010101010101010101010101010101010101010101010101010107000200000001000200400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a080036010000534e524507d0010002000100e0000000534e524506d00100070001000e0000006472303132392d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa050038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb060020000000020202020202020202020202020202020202020202020202020202020202020207000200000001000200400000007c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c"
        );
    }
}
