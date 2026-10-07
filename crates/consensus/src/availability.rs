//! Pure availability-certificate type family (DR-0154 / `epoch-handoff.md`).
//!
//! [`docs/architecture/epoch-handoff.md`](../../../docs/architecture/epoch-handoff.md)
//! and [DR-0154](../../../docs/architecture/decisions/0154-complete-epoch-handoff.md)
//! require one execution-free quorum publication round, ahead of any owned
//! application, over the exact facts a joining/recovering validator would
//! need to independently reconstruct a cut. This module provides only the
//! canonical types, wire codec, and signature/quorum aggregation library for
//! that round's certificate family, mirroring [`crate::fast_vote`]'s
//! stateless, epoch-scoped design.
//!
//! An [`AvailabilityIdentity`] is a caller-constructed statement that one
//! atomicity domain's request carries specific signed-intent, execution, and
//! semantic-artifact digests at an exact `(chain_id, protocol_version,
//! epoch)`. It deliberately excludes anything that a [`crate::FastCertificate`]
//! already carries (its signer subset or proof bytes), any physical
//! checkpoint counter, database revision, or storage/provider coordinate:
//! DR-0154 requires deterministic authenticated *semantic* execution
//! generations plus their certified observations -- not physical
//! creation/admission checkpoints, and not the generation digest alone. This
//! module
//! signs and aggregates that exact identity; it does not decide what belongs
//! in one, does not retain anything durably, and does not decide when an
//! `AvailabilityCertificate` may be used to admit an apply. **Casting or
//! verifying an [`AvailabilityVote`]/[`AvailabilityCertificate`] proves only
//! that a quorum of registered validators signed one exact identity. It does
//! not by itself prove durable retention of the identity's referenced
//! artifacts, and it does not authorize any apply.** Callers remain fully
//! responsible for retention and for any admission policy built on top of
//! this library. This stateless library also does not persist a validator's
//! first ACK identity or detect/evidence conflicting availability votes for
//! the same `(domain, request_id)`; the later handoff implementation must do so.
//!
//! Its signature domain (`"fast-path-availability-v1"`) is distinct from
//! [`crate::ChainedHotStuff`]'s, [`crate::fast_vote`]'s, and
//! [`crate::epoch_transition`]'s, so a signature can never be replayed across
//! families. Certificate formation is deterministic and vote-order
//! independent, exactly as documented on
//! [`AvailabilityCertifier::try_form_certificate`].
//!
//! **Scope:** this module provides only the canonical types, wire codec, and
//! signature/quorum aggregation library described above. It does not decide
//! retention, apply admission, freeze/drain/seal sequencing, or any
//! HTTP/CLI ingress. Freeze/drain/seal sequencing and ingress are designed
//! in the accepted DR-0154, but **not implemented here** -- implementing
//! them is a separate follow-up. See `TODO.md` and DR-0154.

use crate::{ConsensusError, ConsensusSigner, ConsensusVerifier, validate_signature_length};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalStruct, MAX_CANONICAL_FRAME_BYTES, decode_canonical_frame,
    decode_digest32, encode_digest32,
};
use crypto::{SignatureDomain, SignatureMessageType, frame_signature_message};
use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, Epoch, ProtocolVersion, SignatureSchemeId, ValidatorId,
};
use std::collections::BTreeMap;
use validator_set::ValidatorSet;

/// The canonical v2 full-certificate publication bundle this identity family
/// is derived from (DR-0154 / `epoch-handoff.md`). Deriving an identity from
/// a verified bundle is the only supported way to obtain one for a real
/// operation; this parent module keeps the identity/vote/certificate codec
/// itself free of any bundle dependency.
pub mod bundle;
pub mod frontier;
pub mod union;
pub use frontier::{
    FrontierError, FrozenFrontierAccumulator, FrozenFrontierCertifier, FrozenFrontierIdentity,
    FrozenFrontierPage, FrozenFrontierPageVerifier, FrozenFrontierVote,
    MAX_FROZEN_FRONTIER_PAGE_BYTES, MAX_FROZEN_FRONTIER_PAGE_ENTRIES,
    decode_frozen_frontier_identity, decode_frozen_frontier_page, decode_frozen_frontier_vote,
    encode_frozen_frontier_identity, encode_frozen_frontier_page, encode_frozen_frontier_vote,
    verify_frozen_frontier, verify_frozen_frontier_quorum,
};

const AVAILABILITY_IDENTITY_TYPE_ID: u16 = 0xD030;
const AVAILABILITY_VOTE_TYPE_ID: u16 = 0xD031;
const AVAILABILITY_CERTIFICATE_TYPE_ID: u16 = 0xD032;
const ENCODING_VERSION: u16 = 1;
const AVAILABILITY_VOTE_MESSAGE_TYPE: &str = "fast-path-availability-v1";

/// Matches [`validator_set`]'s own bound on one epoch snapshot; an
/// [`AvailabilityCertificate`] can never carry more votes than there are
/// validators.
const MAX_AVAILABILITY_CERTIFICATE_VOTES: usize = 10_000;

/// Matches the repo-wide chain-id length convention already used by
/// `node_core::MAX_CHAIN_ID_BYTES`, `execution::MAX_TRANSACTION_CHAIN_ID_BYTES`,
/// and `abi::MAX_PACKAGE_CHAIN_ID_BYTES` (all 128). `protocol_types::ChainId::new`
/// itself enforces only non-emptiness, so this module imposes its own explicit
/// bound rather than relying on an unbounded caller-supplied string.
const MAX_CHAIN_ID_BYTES: usize = 128;

/// Explicit outer-byte-length caps checked *before* [`decode_canonical_frame`]
/// is ever invoked, mirroring [`crate::durable`]'s
/// `MAX_ENCODED_VOTE_BYTES`/`MAX_ENCODED_CERTIFICATE_BYTES` pattern. An
/// identity or vote never legitimately needs more than a few KiB even at
/// [`MAX_CHAIN_ID_BYTES`] and the existing [`MAX_SIGNATURE_BYTES`](crate)
/// bound. The certificate bound intentionally equals
/// [`MAX_CANONICAL_FRAME_BYTES`] rather than a tighter value: a certificate
/// carrying [`MAX_AVAILABILITY_CERTIFICATE_VOTES`] (10,000) 64-byte signatures
/// already needs several megabytes. Larger otherwise valid signatures can
/// exceed this shared ceiling; not every legal validator count and signature
/// length combination is guaranteed to fit in one canonical frame.
/// Complete encoded availability identity ceiling, reusable by transport guards.
pub const MAX_ENCODED_IDENTITY_BYTES: usize = 2 * 1024;
/// Complete encoded availability vote ceiling, distinct from a durable vote.
pub const MAX_ENCODED_VOTE_BYTES: usize = 8 * 1024;
const MAX_ENCODED_CERTIFICATE_BYTES: usize = MAX_CANONICAL_FRAME_BYTES;

/// Bound on the `votes` slice a caller may pass to
/// [`AvailabilityCertifier::try_form_certificate`], checked before any
/// signature verification, deterministic sort, or vote scan -- including
/// votes that turn out to be irrelevant (a different identity) or duplicate.
/// Mirrors `durable::MAX_CERTIFICATE_FROM_VOTES_INPUT`: double
/// [`MAX_AVAILABILITY_CERTIFICATE_VOTES`] to tolerate redundant/duplicate
/// relay submissions from independent observers while still rejecting an
/// unbounded caller-supplied slice up front.
const MAX_TRY_FORM_CERTIFICATE_VOTES_INPUT: usize = 2 * MAX_AVAILABILITY_CERTIFICATE_VOTES;

/// A caller-constructed, validator-independent statement of exactly which
/// signed intent, execution commitment, and semantic-artifact set one
/// atomicity domain's request carries, at an exact `(chain_id,
/// protocol_version, epoch)`.
///
/// This is the signed payload of an [`AvailabilityVote`]: it excludes the
/// voting validator, the signature scheme, and the signature itself, so
/// every honest validator that agrees produces a signature over
/// byte-identical bytes. It also excludes any [`crate::FastCertificate`]
/// signer subset or proof bytes, physical checkpoint counters, database
/// revisions, or storage/provider coordinates -- those are caller-side
/// concerns this library never inspects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilityIdentity {
    /// Chain replay boundary.
    pub chain_id: ChainId,
    /// Protocol replay boundary.
    pub protocol_version: ProtocolVersion,
    /// Epoch replay boundary.
    pub epoch: Epoch,
    /// The atomicity domain this identity's request belongs to.
    pub domain: AtomicityDomainId,
    /// Caller-chosen unique identifier for the exact request being attested.
    pub request_id: [u8; 32],
    /// Digest of the original signed intent this identity attests.
    pub signed_intent_digest: Digest32,
    /// Digest of the *whole* logical execution commitment this identity
    /// attests: the deterministic authenticated semantic execution
    /// generation together with its certified observations (DR-0154: not a
    /// physical creation/admission checkpoint, and not merely the
    /// generation digest alone).
    pub execution_commitment: Digest32,
    /// Digest of the required replay artifact set this identity attests.
    pub semantic_artifacts_digest: Digest32,
}

/// A single validator's signed attestation of exactly one
/// [`AvailabilityIdentity`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilityVote {
    /// The attested identity.
    pub identity: AvailabilityIdentity,
    /// Voting validator.
    pub validator: ValidatorId,
    /// Signature scheme registered for `validator` in the active set.
    pub signature_scheme: SignatureSchemeId,
    /// Signature over the domain-framed identity payload.
    pub signature: Vec<u8>,
}

/// A minimal, canonically ordered quorum of [`AvailabilityVote`]s for one
/// [`AvailabilityIdentity`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilityCertificate {
    /// The certified identity.
    pub identity: AvailabilityIdentity,
    /// Canonically validator-ID-ordered, deduplicated votes.
    pub votes: Vec<AvailabilityVote>,
}

/// Stateless epoch-scoped signer/verifier for [`AvailabilityIdentity`]
/// availability votes.
///
/// Like [`crate::FastPathCertifier`], this type persists no view/height/lock
/// state: every method is a pure function of its arguments and the immutable
/// `(chain_id, protocol_version, epoch, validator_set)` context captured at
/// construction. It makes no durability or admission decision; see the
/// module documentation.
#[derive(Clone, Debug)]
pub struct AvailabilityCertifier {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set: ValidatorSet,
}

impl AvailabilityCertifier {
    /// Creates a certifier bound to one epoch's validator-set snapshot.
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        validator_set: ValidatorSet,
    ) -> Result<Self, ConsensusError> {
        ensure_chain_id_bound(&chain_id)?;
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

    /// Returns the strict quorum threshold of the bound validator set
    /// (`T - floor((T-1)/3)` over total voting power).
    #[must_use]
    pub const fn quorum_threshold(&self) -> u64 {
        self.validator_set.quorum_threshold()
    }

    /// Signs and returns one [`AvailabilityVote`] for `identity`.
    ///
    /// `identity`'s own `(chain_id, protocol_version, epoch)` must match this
    /// certifier's bound context, and its `chain_id` must fit
    /// [`MAX_CHAIN_ID_BYTES`], both checked before any encoding or signing
    /// work.
    pub fn cast_vote<S: ConsensusSigner>(
        &self,
        identity: AvailabilityIdentity,
        signer: &S,
    ) -> Result<AvailabilityVote, ConsensusError> {
        self.ensure_context(
            &identity.chain_id,
            identity.protocol_version,
            identity.epoch,
        )?;
        ensure_chain_id_bound(&identity.chain_id)?;
        ensure_request_id_nonzero(&identity.request_id)?;
        self.ensure_registered_scheme(signer.validator_id(), signer.signature_scheme())?;
        let framed = self.signature_frame(
            signer.signature_scheme(),
            &encode_availability_identity(&identity)?,
        )?;
        let signature = signer
            .sign_framed(&framed)
            .map_err(ConsensusError::Authenticator)?;
        validate_signature_length(&signature)?;
        Ok(AvailabilityVote {
            identity,
            validator: signer.validator_id(),
            signature_scheme: signer.signature_scheme(),
            signature,
        })
    }

    /// Validates one [`AvailabilityVote`]'s context, `chain_id` bound,
    /// registered scheme, and signature.
    pub fn verify_vote<V: ConsensusVerifier>(
        &self,
        vote: &AvailabilityVote,
        verifier: &V,
    ) -> Result<(), ConsensusError> {
        self.ensure_context(
            &vote.identity.chain_id,
            vote.identity.protocol_version,
            vote.identity.epoch,
        )?;
        ensure_chain_id_bound(&vote.identity.chain_id)?;
        ensure_request_id_nonzero(&vote.identity.request_id)?;
        self.ensure_registered_scheme(vote.validator, vote.signature_scheme)?;
        validate_signature_length(&vote.signature)?;
        let info = self
            .validator_set
            .get(vote.validator)
            .ok_or(ConsensusError::UnknownValidator(vote.validator))?;
        let framed = self.signature_frame(
            vote.signature_scheme,
            &encode_availability_identity(&vote.identity)?,
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
    /// for `identity`, or `Ok(None)` if `votes` does not carry quorum voting
    /// power for that exact identity.
    ///
    /// Rejects a `votes` slice longer than
    /// [`MAX_TRY_FORM_CERTIFICATE_VOTES_INPUT`], and an `identity` whose
    /// `chain_id` exceeds [`MAX_CHAIN_ID_BYTES`], before any signature
    /// verification, deterministic sort/map, or scan of `votes` -- including
    /// votes that later turn out to be irrelevant or duplicate.
    ///
    /// The prospective encoded certificate size is also bounded to
    /// [`MAX_ENCODED_CERTIFICATE_BYTES`], but -- unlike the pre-crypto input
    /// and `chain_id` gates above, and unlike [`Self::verify_certificate`]
    /// and [`encode_availability_certificate`], which both bound *before*
    /// any crypto or cloning -- this gate runs incrementally *during*
    /// formation: after each candidate vote has already passed
    /// [`Self::verify_vote`], but before that vote is cloned into the
    /// accumulated result or handed to an encoder. It stops formation
    /// early rather than letting an otherwise-valid vote set assemble past
    /// the shared canonical-frame ceiling.
    ///
    /// `votes` is otherwise untrusted relay input that may mix in messages
    /// for other identities or other contexts. This method applies exactly
    /// one explicit, documented exclusion policy per candidate vote and
    /// otherwise fails closed:
    ///
    /// * A vote whose `identity` does not exactly equal this call's target
    ///   `identity` is unrelated relay noise and is excluded without being
    ///   verified at all.
    /// * A vote that *is* addressed to this exact identity but fails
    ///   [`Self::verify_vote`] with [`ConsensusError::UnknownValidator`],
    ///   [`ConsensusError::SignatureSchemeMismatch`],
    ///   [`ConsensusError::InvalidSignatureLength`], or
    ///   [`ConsensusError::InvalidSignature`] is itself malformed or
    ///   cryptographically invalid -- not a sign of infrastructure failure --
    ///   and is excluded under this same policy. (`ConsensusError::ContextMismatch`
    ///   is not reachable here: every vote reaching this check already has
    ///   `vote.identity == identity`, and `identity`'s own context was
    ///   already checked against this certifier above.)
    /// * Any other [`verify_vote`](Self::verify_vote) error (in particular
    ///   [`ConsensusError::Authenticator`], which signals that the caller's
    ///   own [`ConsensusVerifier`] adapter itself failed, not that a
    ///   signature was checked and found invalid) is **not** swallowed: this
    ///   method returns that error immediately, failing closed rather than
    ///   silently forming a certificate over a possibly-unverified vote set.
    ///   [`ConsensusVerifier`] implementors should therefore classify a
    ///   per-vote cryptographic condition -- including a registered
    ///   validator's public key that this adapter cannot itself decode --
    ///   as an invalid signature (`Ok(false)`), not as `Err(..)`: an `Err`
    ///   return is reserved for adapter/infrastructure failure (for example
    ///   an unreachable HSM or crashed verifier backend) and aborts
    ///   formation for the whole call rather than merely excluding that one
    ///   vote.
    /// * If one validator supplies multiple valid signatures for the same
    ///   identity (a genuine duplicate), the lexicographically smallest
    ///   signature is retained; the other is discarded, not an error.
    ///
    /// Surviving votes are accumulated in ascending [`ValidatorId`] order --
    /// the same canonical order [`encode_availability_certificate`] requires
    /// -- stopping as soon as the quorum threshold is met, so two callers
    /// given the same valid vote set in different arrival orders always
    /// produce byte-identical certificates. The result depends only on the
    /// *set* of valid matching votes, never on `votes`'s order.
    pub fn try_form_certificate<V: ConsensusVerifier>(
        &self,
        identity: &AvailabilityIdentity,
        votes: &[AvailabilityVote],
        verifier: &V,
    ) -> Result<Option<AvailabilityCertificate>, ConsensusError> {
        if votes.len() > MAX_TRY_FORM_CERTIFICATE_VOTES_INPUT {
            return Err(ConsensusError::StateCollectionTooLarge {
                field: "availability input votes",
                actual: votes.len(),
                max: MAX_TRY_FORM_CERTIFICATE_VOTES_INPUT,
            });
        }
        self.ensure_context(
            &identity.chain_id,
            identity.protocol_version,
            identity.epoch,
        )?;
        ensure_chain_id_bound(&identity.chain_id)?;
        ensure_request_id_nonzero(&identity.request_id)?;

        let mut by_validator: BTreeMap<ValidatorId, &AvailabilityVote> = BTreeMap::new();
        for vote in votes {
            if &vote.identity != identity {
                continue;
            }
            match self.verify_vote(vote, verifier) {
                Ok(()) => {}
                Err(
                    ConsensusError::UnknownValidator(_)
                    | ConsensusError::SignatureSchemeMismatch(_)
                    | ConsensusError::InvalidSignatureLength(_)
                    | ConsensusError::InvalidSignature(_),
                ) => continue,
                Err(other) => return Err(other),
            }
            by_validator
                .entry(vote.validator)
                .and_modify(|current: &mut &AvailabilityVote| {
                    if vote.signature < current.signature {
                        *current = vote;
                    }
                })
                .or_insert(vote);
        }

        let mut power = 0u64;
        let mut selected: Vec<AvailabilityVote> = Vec::new();
        let mut encoded_size: usize = 26 + encoded_identity_length(identity)?;
        for (validator, vote) in by_validator {
            let info = self
                .validator_set
                .get(validator)
                .ok_or(ConsensusError::UnknownValidator(validator))?;
            power = power
                .checked_add(info.voting_power)
                .ok_or(ConsensusError::ArithmeticOverflow)?;
            encoded_size = encoded_size
                .checked_add(74 + encoded_identity_length(&vote.identity)? + vote.signature.len())
                .ok_or(ConsensusError::ArithmeticOverflow)?;
            ensure_encoded_bound(
                "availability certificate",
                encoded_size,
                MAX_ENCODED_CERTIFICATE_BYTES,
            )?;
            selected.push(vote.clone());
            if power >= self.quorum_threshold() {
                return Ok(Some(AvailabilityCertificate {
                    identity: identity.clone(),
                    votes: selected,
                }));
            }
        }
        Ok(None)
    }

    /// Validates an [`AvailabilityCertificate`]'s context, `chain_id`
    /// bound, canonical vote order, per-vote signatures, and quorum voting
    /// power.
    ///
    /// Does not require minimality: any canonically ordered, quorum-carrying,
    /// duplicate-free vote set for the same identity verifies. This proves
    /// only that a quorum of registered validators signed the exact
    /// [`AvailabilityIdentity`]; see the module documentation for what it
    /// does **not** prove.
    pub fn verify_certificate<V: ConsensusVerifier>(
        &self,
        certificate: &AvailabilityCertificate,
        verifier: &V,
    ) -> Result<(), ConsensusError> {
        certificate_encoded_length(certificate)?;
        self.ensure_context(
            &certificate.identity.chain_id,
            certificate.identity.protocol_version,
            certificate.identity.epoch,
        )?;
        ensure_chain_id_bound(&certificate.identity.chain_id)?;
        if certificate.votes.len() > self.validator_set.validators().len() {
            return Err(ConsensusError::NonCanonicalCertificateVotes);
        }
        let mut previous: Option<ValidatorId> = None;
        let mut power = 0u64;
        for vote in &certificate.votes {
            if previous.is_some_and(|id| id >= vote.validator) {
                return Err(ConsensusError::NonCanonicalCertificateVotes);
            }
            previous = Some(vote.validator);
            if vote.identity != certificate.identity {
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
                message_type: SignatureMessageType::new(AVAILABILITY_VOTE_MESSAGE_TYPE)?,
                signature_scheme_id,
            },
            payload,
        )?)
    }
}

/// Bounds one declared outer frame length before [`decode_canonical_frame`]
/// (or any other allocation) is attempted.
fn ensure_encoded_bound(
    kind: &'static str,
    actual: usize,
    max: usize,
) -> Result<(), ConsensusError> {
    if actual > max {
        return Err(ConsensusError::EncodedFrameTooLarge { kind, actual, max });
    }
    Ok(())
}

/// Bounds one [`ChainId`]'s byte length to [`MAX_CHAIN_ID_BYTES`] before it
/// is compared, encoded, or used to frame a signature. `chain_id` is the
/// only variable-length field of an [`AvailabilityIdentity`]; bounding it
/// here transitively bounds the identity's total encoded size everywhere
/// this helper is called before encoding/crypto work.
fn ensure_chain_id_bound(chain_id: &ChainId) -> Result<(), ConsensusError> {
    let actual: usize = chain_id.as_str().len();
    ensure_chain_id_bound_str_inner(actual)
}

/// Bounds a raw candidate chain-id string's byte length to
/// [`MAX_CHAIN_ID_BYTES`] before it is copied into an owned [`ChainId`].
fn ensure_chain_id_bound_str(candidate: &str) -> Result<(), ConsensusError> {
    ensure_chain_id_bound_str_inner(candidate.len())
}

fn ensure_chain_id_bound_str_inner(actual: usize) -> Result<(), ConsensusError> {
    if actual > MAX_CHAIN_ID_BYTES {
        return Err(ConsensusError::EncodedFrameTooLarge {
            kind: "availability identity chain_id",
            actual,
            max: MAX_CHAIN_ID_BYTES,
        });
    }
    Ok(())
}

fn ensure_request_id_nonzero(request_id: &[u8; 32]) -> Result<(), ConsensusError> {
    if *request_id == [0u8; 32] {
        return Err(ConsensusError::ZeroAvailabilityRequestId);
    }
    Ok(())
}

/// Exact v1 size: 10-byte frame header, eight 6-byte field headers,
/// chain + u32/u64 + two 32-byte IDs + three 56-byte Digest32 frames.
fn encoded_identity_length(identity: &AvailabilityIdentity) -> Result<usize, ConsensusError> {
    ensure_chain_id_bound(&identity.chain_id)?;
    ensure_request_id_nonzero(&identity.request_id)?;
    Ok(302 + identity.chain_id.as_str().len())
}

/// Preflight all nested lengths before any encoding allocations or crypto.
/// The common canonical frame's 32-MiB ceiling remains a protocol bound even
/// when each individual vote is legal. This does not change historical codecs.
fn certificate_encoded_length(
    certificate: &AvailabilityCertificate,
) -> Result<usize, ConsensusError> {
    if certificate.votes.len() > MAX_AVAILABILITY_CERTIFICATE_VOTES {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    let mut total: usize = 26 + encoded_identity_length(&certificate.identity)?;
    for vote in &certificate.votes {
        validate_signature_length(&vote.signature)?;
        total = total
            .checked_add(74 + encoded_identity_length(&vote.identity)? + vote.signature.len())
            .ok_or(ConsensusError::ArithmeticOverflow)?;
        ensure_encoded_bound(
            "availability certificate",
            total,
            MAX_ENCODED_CERTIFICATE_BYTES,
        )?;
    }
    Ok(total)
}

/// Encodes an [`AvailabilityIdentity`] into its canonical wire frame
/// (`0xD030/v1`). This is also the exact signable payload of an
/// [`AvailabilityVote`] -- see [`AvailabilityCertifier::cast_vote`].
///
/// Rejects a `chain_id` longer than [`MAX_CHAIN_ID_BYTES`] before any field
/// is written into the canonical frame.
pub fn encode_availability_identity(
    identity: &AvailabilityIdentity,
) -> Result<Vec<u8>, ConsensusError> {
    ensure_chain_id_bound(&identity.chain_id)?;
    ensure_request_id_nonzero(&identity.request_id)?;
    let mut canonical = CanonicalStruct::new(AVAILABILITY_IDENTITY_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, identity.chain_id.as_str())?;
    canonical.field_u32(2, identity.protocol_version.get())?;
    canonical.field_u64(3, identity.epoch.get())?;
    canonical.field_bytes(4, identity.domain.as_bytes().to_vec())?;
    canonical.field_bytes(5, identity.request_id.to_vec())?;
    canonical.field_bytes(6, encode_digest32(&identity.signed_intent_digest)?)?;
    canonical.field_bytes(7, encode_digest32(&identity.execution_commitment)?)?;
    canonical.field_bytes(8, encode_digest32(&identity.semantic_artifacts_digest)?)?;
    Ok(canonical.finish()?)
}

/// Decodes and strictly re-validates one canonical [`AvailabilityCertificate`].
///
/// Requires the input to fit [`MAX_ENCODED_CERTIFICATE_BYTES`] before any
/// parsing, the certificate type id/encoding version, an exact declared vote
/// count bounded by [`MAX_AVAILABILITY_CERTIFICATE_VOTES`] (checked before
/// any nested vote is decoded), every nested [`AvailabilityVote`] to decode
/// under [`decode_availability_vote`], strictly ascending validator order,
/// and byte-exact re-encoding of the decoded value. It does not verify
/// signatures, quorum, or that each vote's identity matches the
/// certificate's identity; callers must still call
/// [`AvailabilityCertifier::verify_certificate`].
pub fn decode_availability_certificate(
    input: &[u8],
) -> Result<AvailabilityCertificate, ConsensusError> {
    ensure_encoded_bound(
        "availability certificate",
        input.len(),
        MAX_ENCODED_CERTIFICATE_BYTES,
    )?;
    let frame = decode_canonical_frame(input)?;
    frame.require_type(AVAILABILITY_CERTIFICATE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;

    let identity = decode_availability_identity(frame.required_field(1)?)?;
    let count = usize::try_from(frame.required_u32(2)?)
        .map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?;
    if count > MAX_AVAILABILITY_CERTIFICATE_VOTES {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    let expected_field_count = count
        .checked_add(2)
        .ok_or(ConsensusError::NonCanonicalCertificateVotes)?;
    if frame.field_count() != expected_field_count {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    let mut votes = Vec::with_capacity(count);
    let mut previous: Option<ValidatorId> = None;
    for index in 0..count {
        let field =
            u16::try_from(index + 3).map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?;
        let vote = decode_availability_vote(frame.required_field(field)?)?;
        if previous.is_some_and(|validator| validator >= vote.validator) {
            return Err(ConsensusError::NonCanonicalCertificateVotes);
        }
        previous = Some(vote.validator);
        votes.push(vote);
    }

    let certificate = AvailabilityCertificate { identity, votes };
    if encode_availability_certificate(&certificate)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    Ok(certificate)
}

/// Decodes and strictly re-validates one canonical [`AvailabilityIdentity`].
///
/// Requires the input to fit [`MAX_ENCODED_IDENTITY_BYTES`] before any
/// parsing, the identity type id/encoding version, exactly fields 1-8, a
/// `chain_id` no longer than [`MAX_CHAIN_ID_BYTES`] before it is copied into
/// an owned [`ChainId`], a non-zero [`AtomicityDomainId`] and request ID, and byte-exact
/// re-encoding of the decoded value.
pub fn decode_availability_identity(input: &[u8]) -> Result<AvailabilityIdentity, ConsensusError> {
    ensure_encoded_bound(
        "availability identity",
        input.len(),
        MAX_ENCODED_IDENTITY_BYTES,
    )?;
    let frame = decode_canonical_frame(input)?;
    frame.require_type(AVAILABILITY_IDENTITY_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8])?;

    let chain_id_str: &str = frame.required_str(1)?;
    ensure_chain_id_bound_str(chain_id_str)?;
    let chain_id = ChainId::new(chain_id_str.to_owned()).map_err(ConsensusError::ProtocolType)?;
    let protocol_version = ProtocolVersion::new(frame.required_u32(2)?);
    let epoch = Epoch::new(frame.required_u64(3)?);
    let domain_field = frame.required_field(4)?;
    let domain_bytes: [u8; 32] = domain_field.try_into().map_err(|_| {
        ConsensusError::CanonicalDecoding(CanonicalDecodingError::InvalidFieldLength {
            field_id: 4,
            expected: 32,
            actual: domain_field.len(),
        })
    })?;
    let domain = AtomicityDomainId::new(domain_bytes).map_err(ConsensusError::ProtocolType)?;
    let request_id_field = frame.required_field(5)?;
    let request_id: [u8; 32] = request_id_field.try_into().map_err(|_| {
        ConsensusError::CanonicalDecoding(CanonicalDecodingError::InvalidFieldLength {
            field_id: 5,
            expected: 32,
            actual: request_id_field.len(),
        })
    })?;
    ensure_request_id_nonzero(&request_id)?;
    let signed_intent_digest = decode_digest32(frame.required_field(6)?)?;
    let execution_commitment = decode_digest32(frame.required_field(7)?)?;
    let semantic_artifacts_digest = decode_digest32(frame.required_field(8)?)?;

    let identity = AvailabilityIdentity {
        chain_id,
        protocol_version,
        epoch,
        domain,
        request_id,
        signed_intent_digest,
        execution_commitment,
        semantic_artifacts_digest,
    };
    if encode_availability_identity(&identity)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    Ok(identity)
}

/// Encodes a complete signed [`AvailabilityVote`] (`0xD031/v1`): the nested
/// identity frame plus `validator`, `signature_scheme`, and `signature`.
pub fn encode_availability_vote(vote: &AvailabilityVote) -> Result<Vec<u8>, ConsensusError> {
    validate_signature_length(&vote.signature)?;
    let mut canonical = CanonicalStruct::new(AVAILABILITY_VOTE_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_availability_identity(&vote.identity)?)?;
    canonical.field_bytes(2, vote.validator.as_bytes())?;
    canonical.field_u16(3, vote.signature_scheme.as_u16())?;
    canonical.field_bytes(4, vote.signature.clone())?;
    Ok(canonical.finish()?)
}

/// Decodes and strictly re-validates one canonical [`AvailabilityVote`].
///
/// Requires the input to fit [`MAX_ENCODED_VOTE_BYTES`] before any parsing,
/// the vote type id/encoding version, exactly fields 1-4, a nested
/// [`AvailabilityIdentity`] that decodes under [`decode_availability_identity`],
/// a signature no longer than the crate's existing signature bound before it
/// is copied into an owned `Vec`, and byte-exact re-encoding of the decoded
/// value. It does not verify the signature; callers must still call
/// [`AvailabilityCertifier::verify_vote`].
pub fn decode_availability_vote(input: &[u8]) -> Result<AvailabilityVote, ConsensusError> {
    ensure_encoded_bound("availability vote", input.len(), MAX_ENCODED_VOTE_BYTES)?;
    let frame = decode_canonical_frame(input)?;
    frame.require_type(AVAILABILITY_VOTE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;

    let identity = decode_availability_identity(frame.required_field(1)?)?;
    let validator_field = frame.required_field(2)?;
    let validator_bytes: [u8; 32] = validator_field.try_into().map_err(|_| {
        ConsensusError::CanonicalDecoding(CanonicalDecodingError::InvalidFieldLength {
            field_id: 2,
            expected: 32,
            actual: validator_field.len(),
        })
    })?;
    let signature_scheme = SignatureSchemeId::try_from(frame.required_u16(3)?)
        .map_err(ConsensusError::ProtocolType)?;
    let signature_field: &[u8] = frame.required_field(4)?;
    validate_signature_length(signature_field)?;
    let signature = signature_field.to_vec();

    let vote = AvailabilityVote {
        identity,
        validator: ValidatorId::new(validator_bytes),
        signature_scheme,
        signature,
    };
    if encode_availability_vote(&vote)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    Ok(vote)
}

/// Encodes an [`AvailabilityCertificate`] with its votes in the caller's
/// given order (`0xD032/v1`). Rejects more than
/// [`MAX_AVAILABILITY_CERTIFICATE_VOTES`] votes before any field is written.
///
/// Callers that want the canonical, arrival-order-independent representation
/// must pass votes already sorted by [`ValidatorId`], as
/// [`AvailabilityCertifier::try_form_certificate`] always returns them.
pub fn encode_availability_certificate(
    certificate: &AvailabilityCertificate,
) -> Result<Vec<u8>, ConsensusError> {
    certificate_encoded_length(certificate)?;
    if certificate.votes.len() > MAX_AVAILABILITY_CERTIFICATE_VOTES {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    let mut canonical = CanonicalStruct::new(AVAILABILITY_CERTIFICATE_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_availability_identity(&certificate.identity)?)?;
    canonical.field_u32(
        2,
        u32::try_from(certificate.votes.len())
            .map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?,
    )?;
    for (index, vote) in certificate.votes.iter().enumerate() {
        let field =
            u16::try_from(index + 3).map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?;
        canonical.field_bytes(field, encode_availability_vote(vote)?)?;
    }
    Ok(canonical.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_zebra::{Signature, SigningKey, VerificationKey};
    use protocol_types::HashAlgorithmId;
    use validator_set::ValidatorInfo;

    #[test]
    fn decode_availability_identity_rejects_garbage_bytes() {
        assert!(decode_availability_identity(&[0u8; 4]).is_err());
    }

    #[test]
    fn quorum_threshold_matches_strict_t_minus_floor_t_minus_1_over_3() {
        assert_eq!(certifier(4).quorum_threshold(), 3);
        assert_eq!(certifier(7).quorum_threshold(), 5);
        assert_eq!(certifier(10).quorum_threshold(), 7);
    }

    #[test]
    fn cast_vote_signs_and_verify_vote_accepts_a_real_ed25519_signature() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        assert_eq!(vote.signature.len(), 64);
        assert_eq!(certifier.verify_vote(&vote, &Ed25519TestVerifier), Ok(()));
    }

    #[test]
    fn verify_vote_rejects_wrong_epoch() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.identity.epoch = Epoch::new(vote.identity.epoch.get() + 1);
        assert_eq!(
            certifier.verify_vote(&vote, &Ed25519TestVerifier),
            Err(ConsensusError::ContextMismatch)
        );
    }

    #[test]
    fn try_form_certificate_is_deterministic_and_minimal_independent_of_arrival_order() {
        let certifier = certifier(4);
        let mut votes: Vec<AvailabilityVote> = (1..=4).map(|byte| cast(&certifier, byte)).collect();
        let forward = certifier
            .try_form_certificate(&identity(), &votes, &Ed25519TestVerifier)
            .unwrap()
            .expect("quorum reached");
        votes.reverse();
        let reversed = certifier
            .try_form_certificate(&identity(), &votes, &Ed25519TestVerifier)
            .unwrap()
            .expect("quorum reached");
        assert_eq!(forward.votes.len(), 3);
        assert_eq!(
            encode_availability_certificate(&forward).unwrap(),
            encode_availability_certificate(&reversed).unwrap()
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
    fn try_form_certificate_selects_the_smallest_duplicate_signature_accepted_by_the_fixture_independent_of_arrival_order()
     {
        let certifier = certifier(4);
        let mut votes: Vec<AvailabilityVote> = (1..=4).map(|byte| cast(&certifier, byte)).collect();
        let mut alternate = votes[0].clone();
        alternate.signature = vec![0xFF; 64];
        votes.push(alternate);
        let forward = certifier
            .try_form_certificate(&identity(), &votes, &AcceptingVerifier)
            .unwrap()
            .expect("quorum reached");
        votes.reverse();
        let reversed = certifier
            .try_form_certificate(&identity(), &votes, &AcceptingVerifier)
            .unwrap()
            .expect("quorum reached");
        assert_eq!(
            encode_availability_certificate(&forward).unwrap(),
            encode_availability_certificate(&reversed).unwrap()
        );
        assert_ne!(forward.votes[0].signature, vec![0xFF; 64]);
    }

    #[test]
    fn try_form_certificate_propagates_verifier_infrastructure_errors_instead_of_excluding_votes() {
        let certifier = certifier(4);
        let votes: Vec<AvailabilityVote> = (1..=4).map(|byte| cast(&certifier, byte)).collect();
        assert_eq!(
            certifier.try_form_certificate(&identity(), &votes, &FailingInfraVerifier),
            Err(ConsensusError::Authenticator(String::new()))
        );
    }

    #[test]
    fn try_form_certificate_excludes_an_invalid_signature_vote_under_the_documented_policy() {
        let certifier = certifier(4);
        let mut votes: Vec<AvailabilityVote> = (1..=4).map(|byte| cast(&certifier, byte)).collect();
        votes[0].signature[0] ^= 0xFF;
        let certificate = certifier
            .try_form_certificate(&identity(), &votes, &Ed25519TestVerifier)
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
    fn try_form_certificate_respects_a_weighted_quorum_boundary() {
        let certifier = AvailabilityCertifier::new(
            identity().chain_id,
            protocol_version(),
            epoch(),
            weighted_validator_set(),
        )
        .unwrap();
        assert_eq!(certifier.quorum_threshold(), 7);
        let below_boundary_votes: Vec<AvailabilityVote> = [1u8, 4]
            .into_iter()
            .map(|byte| cast(&certifier, byte))
            .collect();
        assert_eq!(
            certifier
                .try_form_certificate(&identity(), &below_boundary_votes, &Ed25519TestVerifier)
                .unwrap(),
            None,
            "power 3+2=5 is below the threshold of 7"
        );
        let at_boundary_votes: Vec<AvailabilityVote> = [1u8, 2, 3]
            .into_iter()
            .map(|byte| cast(&certifier, byte))
            .collect();
        let certificate = certifier
            .try_form_certificate(&identity(), &at_boundary_votes, &Ed25519TestVerifier)
            .unwrap()
            .expect("power 3+3+2=8 reaches the threshold of 7");
        assert_eq!(certificate.votes.len(), 3);
    }

    #[test]
    fn verify_certificate_accepts_an_alternate_valid_quorum_subset() {
        let certifier = certifier(4);
        let votes: Vec<AvailabilityVote> = (1..=4).map(|byte| cast(&certifier, byte)).collect();
        let minimal = certifier
            .try_form_certificate(&identity(), &votes, &Ed25519TestVerifier)
            .unwrap()
            .expect("quorum reached");
        let alternate = certifier
            .try_form_certificate(&identity(), &votes[1..4], &Ed25519TestVerifier)
            .unwrap()
            .expect("quorum reached from the other 3 votes");
        assert_ne!(
            encode_availability_certificate(&minimal).unwrap(),
            encode_availability_certificate(&alternate).unwrap()
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

    fn vector_identity() -> AvailabilityIdentity {
        AvailabilityIdentity {
            chain_id: ChainId::new("dr0154-vectors").unwrap(),
            protocol_version: ProtocolVersion::new(3),
            epoch: Epoch::new(9),
            domain: AtomicityDomainId::new([0x44; 32]).unwrap(),
            request_id: [0x55; 32],
            signed_intent_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xaa; 32]),
            execution_commitment: Digest32::new(HashAlgorithmId::Sha2_256, [0xbb; 32]),
            semantic_artifacts_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xcc; 32]),
        }
    }

    fn vector_vote() -> AvailabilityVote {
        AvailabilityVote {
            identity: vector_identity(),
            validator: ValidatorId::new([0x01; 32]),
            signature_scheme: SignatureSchemeId::Ed25519,
            signature: vec![0x5A; 64],
        }
    }

    /// Decodes a literal lowercase hex string into bytes. Used only to hold
    /// the `0xD031`/`0xD032` pinned vectors below as plain data, never to
    /// derive expected bytes from this crate's own encoder or type-id
    /// constants (see `scripts/availability-vectors.mjs` for the
    /// independent, non-Rust reconstruction
    /// these literals are cross-checked against).
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        assert!(hex.len().is_multiple_of(2), "odd-length hex literal");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex digit pair"))
            .collect()
    }

    #[test]
    fn availability_identity_encoding_vector_0xd030_is_stable() {
        let bytes = encode_availability_identity(&vector_identity()).unwrap();
        assert_eq!(
            bytes,
            vec![
                83, 78, 82, 69, 48, 208, 1, 0, 8, 0, 1, 0, 14, 0, 0, 0, 100, 114, 48, 49, 53, 52,
                45, 118, 101, 99, 116, 111, 114, 115, 2, 0, 4, 0, 0, 0, 3, 0, 0, 0, 3, 0, 8, 0, 0,
                0, 9, 0, 0, 0, 0, 0, 0, 0, 4, 0, 32, 0, 0, 0, 68, 68, 68, 68, 68, 68, 68, 68, 68,
                68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68,
                68, 68, 5, 0, 32, 0, 0, 0, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
                85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 6, 0, 56,
                0, 0, 0, 83, 78, 82, 69, 3, 1, 1, 0, 2, 0, 1, 0, 2, 0, 0, 0, 1, 0, 2, 0, 32, 0, 0,
                0, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
                170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 7,
                0, 56, 0, 0, 0, 83, 78, 82, 69, 3, 1, 1, 0, 2, 0, 1, 0, 2, 0, 0, 0, 1, 0, 2, 0, 32,
                0, 0, 0, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
                187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
                187, 8, 0, 56, 0, 0, 0, 83, 78, 82, 69, 3, 1, 1, 0, 2, 0, 1, 0, 2, 0, 0, 0, 1, 0,
                2, 0, 32, 0, 0, 0, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
                204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
                204, 204, 204,
            ]
        );
    }

    #[test]
    fn availability_vote_encoding_vector_0xd031_is_stable() {
        let bytes = encode_availability_vote(&vector_vote()).unwrap();
        // Independent literal vector: reconstructed by
        // `scripts/availability-vectors.mjs` (Node, no Rust encoder
        // involved), not derived from this module's constants or encoders.
        let expected: Vec<u8> = hex_to_bytes(
            "534e524531d00100040001003c010000534e524530d00100080001000e0000006472303135342d766563746f727302000400000003000000030008000000090000000000000004002000000044444444444444444444444444444444444444444444444444444444444444440500200000005555555555555555555555555555555555555555555555555555555555555555060038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa070038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb080038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc020020000000010101010101010101010101010101010101010101010101010101010101010103000200000001000400400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        );
        assert_eq!(bytes, expected);
    }

    #[test]
    fn availability_certificate_encoding_vector_0xd032_is_stable() {
        let vote_a = vector_vote();
        let mut vote_b = vector_vote();
        vote_b.validator = ValidatorId::new([0x02; 32]);
        vote_b.signature = vec![0x7C; 64];
        let certificate = AvailabilityCertificate {
            identity: vote_a.identity.clone(),
            votes: vec![vote_a.clone(), vote_b.clone()],
        };
        let bytes = encode_availability_certificate(&certificate).unwrap();
        // Independent literal vector: reconstructed by
        // `scripts/availability-vectors.mjs` (Node, no Rust encoder
        // involved), not derived from this module's constants or encoders.
        let expected: Vec<u8> = hex_to_bytes(
            "534e524532d00100040001003c010000534e524530d00100080001000e0000006472303135342d766563746f727302000400000003000000030008000000090000000000000004002000000044444444444444444444444444444444444444444444444444444444444444440500200000005555555555555555555555555555555555555555555555555555555555555555060038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa070038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb080038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc020004000000020000000300c0010000534e524531d00100040001003c010000534e524530d00100080001000e0000006472303135342d766563746f727302000400000003000000030008000000090000000000000004002000000044444444444444444444444444444444444444444444444444444444444444440500200000005555555555555555555555555555555555555555555555555555555555555555060038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa070038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb080038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc020020000000010101010101010101010101010101010101010101010101010101010101010103000200000001000400400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0400c0010000534e524531d00100040001003c010000534e524530d00100080001000e0000006472303135342d766563746f727302000400000003000000030008000000090000000000000004002000000044444444444444444444444444444444444444444444444444444444444444440500200000005555555555555555555555555555555555555555555555555555555555555555060038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa070038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb080038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc020020000000020202020202020202020202020202020202020202020202020202020202020203000200000001000400400000007c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c",
        );
        assert_eq!(bytes, expected);
    }

    #[test]
    fn decode_availability_certificate_rejects_a_declared_count_over_the_bound() {
        let certifier = certifier(4);
        let certificate = quorum_certificate(&certifier);
        let mut frame = CanonicalStruct::new(AVAILABILITY_CERTIFICATE_TYPE_ID, ENCODING_VERSION);
        frame
            .field_bytes(
                1,
                encode_availability_identity(&certificate.identity).unwrap(),
            )
            .unwrap();
        frame
            .field_u32(
                2,
                u32::try_from(MAX_AVAILABILITY_CERTIFICATE_VOTES + 1).unwrap(),
            )
            .unwrap();
        let bytes = frame.finish().unwrap();
        assert_eq!(
            decode_availability_certificate(&bytes),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    #[test]
    fn decode_availability_certificate_rejects_a_declared_count_that_disagrees_with_the_fields_present()
     {
        let certifier = certifier(4);
        let certificate = quorum_certificate(&certifier);
        let mut frame = CanonicalStruct::new(AVAILABILITY_CERTIFICATE_TYPE_ID, ENCODING_VERSION);
        frame
            .field_bytes(
                1,
                encode_availability_identity(&certificate.identity).unwrap(),
            )
            .unwrap();
        frame
            .field_u32(2, u32::try_from(certificate.votes.len()).unwrap() + 1)
            .unwrap();
        for (index, vote) in certificate.votes.iter().enumerate() {
            frame
                .field_bytes(
                    u16::try_from(index + 3).unwrap(),
                    encode_availability_vote(vote).unwrap(),
                )
                .unwrap();
        }
        let bytes = frame.finish().unwrap();
        assert_eq!(
            decode_availability_certificate(&bytes),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    #[test]
    fn decode_availability_certificate_rejects_duplicate_validator_votes() {
        let certifier = certifier(4);
        let mut certificate = quorum_certificate(&certifier);
        certificate.votes[1] = certificate.votes[0].clone();
        let bytes = encode_availability_certificate(&certificate).unwrap();
        assert_eq!(
            decode_availability_certificate(&bytes),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    #[test]
    fn availability_identity_encode_decode_round_trips() {
        let bytes = encode_availability_identity(&identity()).unwrap();
        assert_eq!(decode_availability_identity(&bytes), Ok(identity()));
    }

    #[test]
    fn availability_vote_encode_decode_round_trips() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let encoded = encode_availability_vote(&vote).unwrap();
        assert_eq!(decode_availability_vote(&encoded), Ok(vote));
    }

    #[test]
    fn availability_certificate_encode_decode_round_trips() {
        let certifier = certifier(4);
        let certificate = quorum_certificate(&certifier);
        let encoded = encode_availability_certificate(&certificate).unwrap();
        assert_eq!(decode_availability_certificate(&encoded), Ok(certificate));
    }

    #[test]
    fn decode_availability_identity_rejects_wrong_type_id() {
        let mut bytes = encode_availability_identity(&identity()).unwrap();
        bytes[4] ^= 0xFF;
        assert!(matches!(
            decode_availability_identity(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId {
                    expected: AVAILABILITY_IDENTITY_TYPE_ID,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn decode_availability_certificate_rejects_noncanonical_vote_order() {
        let certifier = certifier(4);
        let mut certificate = quorum_certificate(&certifier);
        certificate.votes.reverse();
        let bytes = encode_availability_certificate(&certificate).unwrap();
        assert_eq!(
            decode_availability_certificate(&bytes),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    #[test]
    fn decode_availability_vote_reports_the_actual_invalid_validator_id_length() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let mut outer = CanonicalStruct::new(AVAILABILITY_VOTE_TYPE_ID, ENCODING_VERSION);
        outer
            .field_bytes(1, encode_availability_identity(&vote.identity).unwrap())
            .unwrap();
        outer.field_bytes(2, vec![0u8; 31]).unwrap();
        outer.field_u16(3, vote.signature_scheme.as_u16()).unwrap();
        outer.field_bytes(4, vote.signature).unwrap();
        assert_eq!(
            decode_availability_vote(&outer.finish().unwrap()),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::InvalidFieldLength {
                    field_id: 2,
                    expected: 32,
                    actual: 31,
                }
            ))
        );
    }

    #[test]
    fn decode_availability_certificate_rejects_wrong_type_id() {
        let certifier = certifier(4);
        let mut bytes = encode_availability_certificate(&quorum_certificate(&certifier)).unwrap();
        bytes[4] ^= 0xFF;
        assert!(matches!(
            decode_availability_certificate(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId {
                    expected: AVAILABILITY_CERTIFICATE_TYPE_ID,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn decode_availability_identity_rejects_an_extra_field() {
        let id = identity();
        let mut frame = CanonicalStruct::new(AVAILABILITY_IDENTITY_TYPE_ID, ENCODING_VERSION);
        frame.field_str(1, id.chain_id.as_str()).unwrap();
        frame.field_u32(2, id.protocol_version.get()).unwrap();
        frame.field_u64(3, id.epoch.get()).unwrap();
        frame.field_bytes(4, id.domain.as_bytes().to_vec()).unwrap();
        frame.field_bytes(5, id.request_id.to_vec()).unwrap();
        frame
            .field_bytes(6, encode_digest32(&id.signed_intent_digest).unwrap())
            .unwrap();
        frame
            .field_bytes(7, encode_digest32(&id.execution_commitment).unwrap())
            .unwrap();
        frame
            .field_bytes(8, encode_digest32(&id.semantic_artifacts_digest).unwrap())
            .unwrap();
        frame.field_bytes(9, vec![0u8]).unwrap();
        let bytes = frame.finish().unwrap();
        assert_eq!(
            decode_availability_identity(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(9)
            ))
        );
    }

    #[test]
    fn decode_availability_identity_rejects_a_missing_field() {
        let id = identity();
        let mut frame = CanonicalStruct::new(AVAILABILITY_IDENTITY_TYPE_ID, ENCODING_VERSION);
        frame.field_str(1, id.chain_id.as_str()).unwrap();
        frame.field_u32(2, id.protocol_version.get()).unwrap();
        frame.field_u64(3, id.epoch.get()).unwrap();
        frame.field_bytes(4, id.domain.as_bytes().to_vec()).unwrap();
        frame.field_bytes(5, id.request_id.to_vec()).unwrap();
        frame
            .field_bytes(6, encode_digest32(&id.signed_intent_digest).unwrap())
            .unwrap();
        frame
            .field_bytes(7, encode_digest32(&id.execution_commitment).unwrap())
            .unwrap();
        let bytes = frame.finish().unwrap();
        assert_eq!(
            decode_availability_identity(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::MissingField(8)
            ))
        );
    }

    #[test]
    fn decode_availability_identity_rejects_a_zero_atomicity_domain() {
        let id = identity();
        let mut frame = CanonicalStruct::new(AVAILABILITY_IDENTITY_TYPE_ID, ENCODING_VERSION);
        frame.field_str(1, id.chain_id.as_str()).unwrap();
        frame.field_u32(2, id.protocol_version.get()).unwrap();
        frame.field_u64(3, id.epoch.get()).unwrap();
        frame.field_bytes(4, vec![0u8; 32]).unwrap();
        frame.field_bytes(5, id.request_id.to_vec()).unwrap();
        frame
            .field_bytes(6, encode_digest32(&id.signed_intent_digest).unwrap())
            .unwrap();
        frame
            .field_bytes(7, encode_digest32(&id.execution_commitment).unwrap())
            .unwrap();
        frame
            .field_bytes(8, encode_digest32(&id.semantic_artifacts_digest).unwrap())
            .unwrap();
        let bytes = frame.finish().unwrap();
        assert_eq!(
            decode_availability_identity(&bytes),
            Err(ConsensusError::ProtocolType(
                protocol_types::TypeError::ZeroAtomicityDomainId
            ))
        );
    }

    #[test]
    fn zero_availability_request_id_rejects_encode_sign_and_decode() {
        let mut id: AvailabilityIdentity = identity();
        id.request_id = [0u8; 32];
        assert_eq!(
            encode_availability_identity(&id),
            Err(ConsensusError::ZeroAvailabilityRequestId)
        );

        let certifier: AvailabilityCertifier = certifier(4);
        let signer: CountingSigner = CountingSigner::default();
        assert_eq!(
            certifier.cast_vote(id.clone(), &signer),
            Err(ConsensusError::ZeroAvailabilityRequestId)
        );
        assert_eq!(signer.call_count(), 0);

        let mut frame: CanonicalStruct =
            CanonicalStruct::new(AVAILABILITY_IDENTITY_TYPE_ID, ENCODING_VERSION);
        frame.field_str(1, id.chain_id.as_str()).unwrap();
        frame.field_u32(2, id.protocol_version.get()).unwrap();
        frame.field_u64(3, id.epoch.get()).unwrap();
        frame.field_bytes(4, id.domain.as_bytes().to_vec()).unwrap();
        frame.field_bytes(5, id.request_id.to_vec()).unwrap();
        frame
            .field_bytes(6, encode_digest32(&id.signed_intent_digest).unwrap())
            .unwrap();
        frame
            .field_bytes(7, encode_digest32(&id.execution_commitment).unwrap())
            .unwrap();
        frame
            .field_bytes(8, encode_digest32(&id.semantic_artifacts_digest).unwrap())
            .unwrap();
        let bytes: Vec<u8> = frame.finish().unwrap();
        assert_eq!(
            decode_availability_identity(&bytes),
            Err(ConsensusError::ZeroAvailabilityRequestId)
        );
    }

    #[test]
    fn decode_availability_vote_rejects_wrong_type_id() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let mut bytes = encode_availability_vote(&vote).unwrap();
        bytes[4] ^= 0xFF;
        assert!(matches!(
            decode_availability_vote(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId {
                    expected: AVAILABILITY_VOTE_TYPE_ID,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn decode_availability_identity_rejects_wrong_version() {
        let mut bytes = encode_availability_identity(&identity()).unwrap();
        bytes[6] ^= 0xFF;
        assert!(matches!(
            decode_availability_identity(&bytes),
            Err(ConsensusError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedVersion {
                    expected: ENCODING_VERSION,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn verify_certificate_rejects_a_vote_for_a_different_identity() {
        let certifier = certifier(4);
        let mut certificate = quorum_certificate(&certifier);
        let mut other = identity();
        other.request_id = request_id(0x77);
        certificate.votes[0] = certifier.cast_vote(other, &signer(1)).unwrap();
        assert_eq!(
            certifier.verify_certificate(&certificate, &Ed25519TestVerifier),
            Err(ConsensusError::CertificateVoteMismatch)
        );
    }

    #[test]
    fn verify_certificate_rejects_below_quorum_power() {
        let certifier = certifier(4);
        let certificate = AvailabilityCertificate {
            identity: identity(),
            votes: vec![cast(&certifier, 1), cast(&certifier, 2)],
        };
        assert_eq!(
            certifier.verify_certificate(&certificate, &Ed25519TestVerifier),
            Err(ConsensusError::InsufficientQuorum {
                actual: 2,
                required: 3,
            })
        );
    }

    #[test]
    fn verify_certificate_rejects_an_oversized_in_memory_vote_list() {
        let certifier = certifier(4);
        let one_vote = cast(&certifier, 1);
        let certificate = AvailabilityCertificate {
            identity: identity(),
            votes: vec![one_vote; 5],
        };
        assert_eq!(
            certifier.verify_certificate(&certificate, &Ed25519TestVerifier),
            Err(ConsensusError::NonCanonicalCertificateVotes)
        );
    }

    #[test]
    fn try_form_certificate_rejects_an_oversized_votes_input_before_any_crypto_call() {
        let certifier = certifier(4);
        let one_vote = cast(&certifier, 1);
        let oversized: Vec<AvailabilityVote> =
            vec![one_vote; MAX_TRY_FORM_CERTIFICATE_VOTES_INPUT + 1];
        let counting = CountingVerifier::default();
        assert!(
            certifier
                .try_form_certificate(&identity(), &oversized, &counting)
                .is_err()
        );
        assert_eq!(counting.call_count(), 0);
    }

    #[test]
    fn cast_vote_rejects_an_oversized_chain_id_before_any_signing_call() {
        let n: usize = MAX_CHAIN_ID_BYTES + 1;
        let long_chain_id: ChainId = ChainId::new("x".repeat(n)).unwrap();
        let certifier: AvailabilityCertifier = certifier(4);
        let mut oversized_identity = identity();
        oversized_identity.chain_id = long_chain_id;
        let counting = CountingSigner::default();
        assert!(certifier.cast_vote(oversized_identity, &counting).is_err());
        assert_eq!(counting.call_count(), 0);
    }

    #[test]
    fn verify_vote_rejects_an_oversized_signature_before_any_verify_call() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.signature = vec![0u8; crate::MAX_SIGNATURE_BYTES + 1];
        let counting = CountingVerifier::default();
        assert!(certifier.verify_vote(&vote, &counting).is_err());
        assert_eq!(counting.call_count(), 0);
    }

    #[test]
    fn decode_availability_identity_rejects_an_oversized_total_frame_before_parsing() {
        let oversized = vec![0u8; MAX_ENCODED_IDENTITY_BYTES + 1];
        assert!(matches!(
            decode_availability_identity(&oversized),
            Err(ConsensusError::EncodedFrameTooLarge { .. })
        ));
    }

    #[test]
    fn decode_availability_vote_rejects_an_oversized_total_frame_before_parsing() {
        let oversized = vec![0u8; MAX_ENCODED_VOTE_BYTES + 1];
        assert!(matches!(
            decode_availability_vote(&oversized),
            Err(ConsensusError::EncodedFrameTooLarge { .. })
        ));
    }

    #[test]
    fn decode_availability_certificate_rejects_an_oversized_total_frame_before_parsing() {
        let oversized = vec![0u8; MAX_ENCODED_CERTIFICATE_BYTES + 1];
        assert!(matches!(
            decode_availability_certificate(&oversized),
            Err(ConsensusError::EncodedFrameTooLarge { .. })
        ));
    }

    #[test]
    fn verify_vote_does_not_reject_a_maximum_legal_signature_length() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.signature = vec![0xAB; crate::MAX_SIGNATURE_BYTES];
        assert_eq!(certifier.verify_vote(&vote, &AcceptingVerifier), Ok(()));
    }

    #[test]
    fn certificate_aggregate_bytes_are_bounded_before_encoding_or_crypto() {
        let certifier: AvailabilityCertifier = certifier(4);
        let mut vote: AvailabilityVote = vector_vote();
        vote.signature = vec![0x5a; crate::MAX_SIGNATURE_BYTES];
        let certificate: AvailabilityCertificate = AvailabilityCertificate {
            identity: vector_identity(),
            votes: vec![vote; 8_000],
        };
        let verifier: CountingVerifier = CountingVerifier::default();
        assert!(matches!(
            encode_availability_certificate(&certificate),
            Err(ConsensusError::EncodedFrameTooLarge { .. })
        ));
        assert!(matches!(
            certifier.verify_certificate(&certificate, &verifier),
            Err(ConsensusError::EncodedFrameTooLarge { .. })
        ));
        assert_eq!(verifier.call_count(), 0);
    }

    #[test]
    fn wire_size_preflight_matches_the_fixed_v1_codecs() {
        let identity: AvailabilityIdentity = vector_identity();
        assert_eq!(
            encoded_identity_length(&identity).unwrap(),
            encode_availability_identity(&identity).unwrap().len()
        );
        let certificate: AvailabilityCertificate = AvailabilityCertificate {
            identity,
            votes: vec![vector_vote()],
        };
        assert_eq!(
            certificate_encoded_length(&certificate).unwrap(),
            encode_availability_certificate(&certificate).unwrap().len()
        );
        assert!(
            AvailabilityCertifier::new(
                ChainId::new("x".repeat(MAX_CHAIN_ID_BYTES + 1)).unwrap(),
                protocol_version(),
                epoch(),
                validator_set(4)
            )
            .is_err()
        );
    }

    #[test]
    fn a_full_ten_thousand_validator_certificate_with_64_byte_signatures_fits_the_frame_bound() {
        let count = MAX_AVAILABILITY_CERTIFICATE_VOTES;
        let validators: Vec<ValidatorInfo> = (0..count)
            .map(|index| {
                let mut id_bytes = [0u8; 32];
                id_bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
                ValidatorInfo {
                    id: ValidatorId::new(id_bytes),
                    voting_power: 1,
                    signature_scheme: SignatureSchemeId::Ed25519,
                    public_key: id_bytes.to_vec(),
                }
            })
            .collect();
        let validator_set = ValidatorSet::new(epoch(), validators.clone()).unwrap();
        let certifier = AvailabilityCertifier::new(
            identity().chain_id,
            protocol_version(),
            epoch(),
            validator_set,
        )
        .unwrap();
        let votes: Vec<AvailabilityVote> = validators
            .iter()
            .map(|validator_info| AvailabilityVote {
                identity: identity(),
                validator: validator_info.id,
                signature_scheme: SignatureSchemeId::Ed25519,
                // Dummy 64-byte (real-Ed25519-length) placeholder, not a
                // genuine signature; accepted only by `AcceptingVerifier`
                // below. This proves the *byte bounds*, not 10,000 real
                // cryptographic verifications.
                signature: vec![0xCD; 64],
            })
            .collect();
        let certificate = AvailabilityCertificate {
            identity: identity(),
            votes,
        };
        assert_eq!(
            certifier.verify_certificate(&certificate, &AcceptingVerifier),
            Ok(())
        );
        assert_eq!(certificate.votes.len(), count);
        let encoded = encode_availability_certificate(&certificate).unwrap();
        assert_eq!(decode_availability_certificate(&encoded), Ok(certificate));
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
    fn verify_vote_rejects_a_foreign_domain_signature() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.identity.domain = domain(0x99);
        assert_eq!(
            certifier.verify_vote(&vote, &Ed25519TestVerifier),
            Err(ConsensusError::InvalidSignature(validator_id(1)))
        );
    }

    #[test]
    fn try_form_certificate_returns_none_below_quorum() {
        let certifier = certifier(4);
        let votes: Vec<AvailabilityVote> = (1..=2).map(|byte| cast(&certifier, byte)).collect();
        assert_eq!(
            certifier
                .try_form_certificate(&identity(), &votes, &Ed25519TestVerifier)
                .unwrap(),
            None
        );
    }

    #[test]
    fn try_form_certificate_rejects_a_target_identity_outside_the_certifier_context() {
        let certifier = certifier(4);
        let mut foreign = identity();
        foreign.epoch = Epoch::new(foreign.epoch.get() + 1);
        assert_eq!(
            certifier.try_form_certificate(&foreign, &[], &Ed25519TestVerifier),
            Err(ConsensusError::ContextMismatch)
        );
    }

    #[test]
    fn try_form_certificate_excludes_votes_for_a_different_identity_as_relay_noise() {
        let certifier = certifier(4);
        let mut other = identity();
        other.request_id = request_id(0x77);
        let votes: Vec<AvailabilityVote> = (1..=4)
            .map(|byte| certifier.cast_vote(other.clone(), &signer(byte)).unwrap())
            .collect();
        assert_eq!(
            certifier
                .try_form_certificate(&identity(), &votes, &Ed25519TestVerifier)
                .unwrap(),
            None
        );
    }

    #[test]
    fn availability_vote_signature_cannot_be_replayed_across_the_epoch_transition_domain() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let payload = encode_availability_identity(&vote.identity).unwrap();
        let scheme = SignatureMessageType::new("fast-path-epoch-transition-v1").unwrap();
        let sig_domain = SignatureDomain {
            chain_id: vote.identity.chain_id.clone(),
            protocol_version: vote.identity.protocol_version,
            epoch: vote.identity.epoch,
            message_type: scheme,
            signature_scheme_id: SignatureSchemeId::Ed25519,
        };
        let wrong_domain_framed = frame_signature_message(&sig_domain, &payload).unwrap();
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
    fn availability_vote_signature_cannot_be_replayed_across_the_fast_vote_domain() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let payload = encode_availability_identity(&vote.identity).unwrap();
        let scheme = SignatureMessageType::new("fast-path-vote-v1").unwrap();
        let sig_domain = SignatureDomain {
            chain_id: vote.identity.chain_id.clone(),
            protocol_version: vote.identity.protocol_version,
            epoch: vote.identity.epoch,
            message_type: scheme,
            signature_scheme_id: SignatureSchemeId::Ed25519,
        };
        let wrong_domain_framed = frame_signature_message(&sig_domain, &payload).unwrap();
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
    fn availability_vote_signature_cannot_be_replayed_across_the_hotstuff_vote_domain() {
        let certifier = certifier(4);
        let vote = cast(&certifier, 1);
        let payload = encode_availability_identity(&vote.identity).unwrap();
        let wrong_domain_framed = frame_signature_message(
            &SignatureDomain {
                chain_id: vote.identity.chain_id.clone(),
                protocol_version: vote.identity.protocol_version,
                epoch: vote.identity.epoch,
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
    fn verify_vote_rejects_a_foreign_semantic_artifacts_digest_signature() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.identity.semantic_artifacts_digest =
            Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]);
        assert_eq!(
            certifier.verify_vote(&vote, &Ed25519TestVerifier),
            Err(ConsensusError::InvalidSignature(validator_id(1)))
        );
    }

    #[test]
    fn verify_vote_rejects_a_foreign_execution_commitment_signature() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.identity.execution_commitment = Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]);
        assert_eq!(
            certifier.verify_vote(&vote, &Ed25519TestVerifier),
            Err(ConsensusError::InvalidSignature(validator_id(1)))
        );
    }

    #[test]
    fn verify_vote_rejects_a_foreign_request_id_signature() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.identity.request_id = request_id(0x99);
        assert_eq!(
            certifier.verify_vote(&vote, &Ed25519TestVerifier),
            Err(ConsensusError::InvalidSignature(validator_id(1)))
        );
    }

    #[test]
    fn verify_vote_rejects_wrong_protocol_version() {
        let certifier = certifier(4);
        let mut vote = cast(&certifier, 1);
        vote.identity.protocol_version =
            ProtocolVersion::new(vote.identity.protocol_version.get() + 1);
        assert_eq!(
            certifier.verify_vote(&vote, &Ed25519TestVerifier),
            Err(ConsensusError::ContextMismatch)
        );
    }

    fn protocol_version() -> ProtocolVersion {
        ProtocolVersion::new(7)
    }
    fn epoch() -> Epoch {
        Epoch::new(42)
    }

    fn domain(byte: u8) -> AtomicityDomainId {
        AtomicityDomainId::new([byte; 32]).unwrap()
    }
    fn request_id(byte: u8) -> [u8; 32] {
        [byte; 32]
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
            Err(String::new())
        }
    }

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

    /// Counts every real `verify_framed`/`sign_framed` call so a bound
    /// check can be proven to fail closed *before* any crypto work, not
    /// merely to return the correct error.
    #[derive(Default)]
    struct CountingVerifier {
        calls: std::cell::Cell<u32>,
    }
    impl CountingVerifier {
        fn call_count(&self) -> u32 {
            self.calls.get()
        }
    }
    impl ConsensusVerifier for CountingVerifier {
        fn verify_framed(
            &self,
            _validator: ValidatorId,
            _scheme: SignatureSchemeId,
            _public_key: &[u8],
            _framed: &[u8],
            _signature: &[u8],
        ) -> Result<bool, String> {
            self.calls.set(self.calls.get() + 1);
            Ok(true)
        }
    }

    #[derive(Default)]
    struct CountingSigner {
        calls: std::cell::Cell<u32>,
    }
    impl CountingSigner {
        fn call_count(&self) -> u32 {
            self.calls.get()
        }
    }
    impl ConsensusSigner for CountingSigner {
        fn validator_id(&self) -> ValidatorId {
            validator_id(1)
        }
        fn signature_scheme(&self) -> SignatureSchemeId {
            SignatureSchemeId::Ed25519
        }
        fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
            self.calls.set(self.calls.get() + 1);
            Ok(signing_key(1).sign(framed).to_bytes().to_vec())
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

    fn certifier(count: u8) -> AvailabilityCertifier {
        AvailabilityCertifier::new(
            identity().chain_id,
            protocol_version(),
            epoch(),
            validator_set(count),
        )
        .unwrap()
    }

    fn signer(byte: u8) -> Ed25519TestSigner {
        Ed25519TestSigner {
            id: validator_id(byte),
            key: signing_key(byte),
        }
    }

    fn cast(certifier: &AvailabilityCertifier, byte: u8) -> AvailabilityVote {
        certifier.cast_vote(identity(), &signer(byte)).unwrap()
    }

    fn quorum_certificate(certifier: &AvailabilityCertifier) -> AvailabilityCertificate {
        let votes: Vec<AvailabilityVote> = (1..=4).map(|byte| cast(certifier, byte)).collect();
        certifier
            .try_form_certificate(&identity(), &votes, &Ed25519TestVerifier)
            .unwrap()
            .expect("4 equal-power validators exceed the 3-of-4 quorum threshold")
    }

    fn weighted_validator_set() -> ValidatorSet {
        let powers = [(1u8, 3u64), (2, 3), (3, 2), (4, 2)];
        let validators: Vec<ValidatorInfo> = powers
            .into_iter()
            .map(|(byte, voting_power)| ValidatorInfo {
                id: validator_id(byte),
                voting_power,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: public_key_bytes(&signing_key(byte)),
            })
            .collect();
        ValidatorSet::new(epoch(), validators).unwrap()
    }
    fn identity() -> AvailabilityIdentity {
        let chain_id: ChainId = ChainId::new("availability-test-chain").unwrap();
        let digest_a = Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32]);
        let digest_b = Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]);
        let digest_c = Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]);
        AvailabilityIdentity {
            chain_id,
            protocol_version: protocol_version(),
            epoch: epoch(),
            domain: domain(0x44),
            request_id: request_id(0x55),
            signed_intent_digest: digest_a,
            execution_commitment: digest_b,
            semantic_artifacts_digest: digest_c,
        }
    }
}
