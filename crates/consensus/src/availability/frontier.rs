//! Incremental, signed frozen-publication frontiers for DR-0154.
//!
//! A frontier commits to the retained full-certificate identities on one
//! validator at one committed ordered Freeze. This module owns only the
//! deterministic accumulator, canonical identity/vote bytes and stateless
//! signatures. It cannot establish that a store enumerated every publication,
//! retained the corresponding artifacts, or crossed a quorum: those are
//! node-core and DrainSet obligations, respectively.

use super::{
    AvailabilityCertifier, AvailabilityIdentity, encode_availability_identity,
    ensure_chain_id_bound, ensure_request_id_nonzero,
};
use crate::{ConsensusError, ConsensusSigner, ConsensusVerifier, validate_signature_length};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalStruct, decode_canonical_frame, decode_digest32,
    encode_digest32,
};
use crypto::{SignatureDomain, SignatureMessageType, frame_signature_message};
use hashing::{HashSuiteResolver, HashingError};
use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, Epoch, HashPurpose, ProtocolVersion, SignatureSchemeId,
    ValidatorId,
};
use std::error::Error;
use std::fmt;
use validator_set::ValidatorSet;

const FRONTIER_IDENTITY_TYPE_ID: u16 = 0xD036;
const FRONTIER_VOTE_TYPE_ID: u16 = 0xD037;
const FRONTIER_ACCUMULATOR_TYPE_ID: u16 = 0xD038;
const ENCODING_VERSION: u16 = 1;
const FRONTIER_VOTE_MESSAGE_TYPE: &str = "epoch-frozen-frontier-v1";
const MAX_FRONTIER_IDENTITY_BYTES: usize = 2 * 1024;
const MAX_FRONTIER_VOTE_BYTES: usize = 8 * 1024;

/// A deterministic commitment to one replica's complete, immutable frozen
/// publication log. The digest includes the exact Freeze identity and every
/// retained operation in strictly ascending request-ID order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenFrontierIdentity {
    pub chain_id: ChainId,
    pub protocol_version: ProtocolVersion,
    pub epoch: Epoch,
    pub domain: AtomicityDomainId,
    pub closure_request_id: [u8; 32],
    pub closure_height: u64,
    pub entry_count: u64,
    pub entries_digest: Digest32,
}

/// One registered validator's signature over exactly one frozen frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenFrontierVote {
    pub identity: FrozenFrontierIdentity,
    pub validator: ValidatorId,
    pub signature_scheme: SignatureSchemeId,
    pub signature: Vec<u8>,
}

/// Fail-closed errors for frontier construction and validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrontierError {
    Consensus(ConsensusError),
    Hashing(HashingError),
    Invalid(&'static str),
}

impl fmt::Display for FrontierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consensus(error) => error.fmt(formatter),
            Self::Hashing(error) => error.fmt(formatter),
            Self::Invalid(reason) => formatter.write_str(reason),
        }
    }
}

impl Error for FrontierError {}

impl From<ConsensusError> for FrontierError {
    fn from(error: ConsensusError) -> Self {
        Self::Consensus(error)
    }
}

impl From<HashingError> for FrontierError {
    fn from(error: HashingError) -> Self {
        Self::Hashing(error)
    }
}

/// Incremental commitment. One invocation may feed a bounded page and save
/// this constant-size state; there is no whole-frontier entry limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenFrontierAccumulator {
    identity: FrozenFrontierIdentity,
    last_request_id: Option<[u8; 32]>,
}

impl FrozenFrontierAccumulator {
    /// Starts with a context-bound empty-frontier seed. The resolver must be
    /// the committed chain/protocol schedule, not caller-selected metadata.
    pub fn new(
        resolver: &HashSuiteResolver,
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        domain: AtomicityDomainId,
        closure_request_id: [u8; 32],
        closure_height: u64,
    ) -> Result<Self, FrontierError> {
        ensure_chain_id_bound(&chain_id)?;
        ensure_request_id_nonzero(&closure_request_id)?;
        if closure_height == 0 {
            return Err(FrontierError::Invalid("zero Freeze block height"));
        }
        if resolver.chain_id() != &chain_id || resolver.protocol_version() != protocol_version {
            return Err(FrontierError::Invalid(
                "frontier hash resolver context mismatch",
            ));
        }
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(FRONTIER_ACCUMULATOR_TYPE_ID, ENCODING_VERSION);
        frame.field_u16(1, 0)?;
        frame.field_str(2, chain_id.as_str())?;
        frame.field_u32(3, protocol_version.get())?;
        frame.field_u64(4, epoch.get())?;
        frame.field_bytes(5, domain.as_bytes().to_vec())?;
        frame.field_bytes(6, closure_request_id.to_vec())?;
        frame.field_u64(7, closure_height)?;
        let entries_digest: Digest32 =
            resolver.hash_for_purpose(epoch, HashPurpose::ExecutionEffects, &frame.finish()?)?;
        Ok(Self {
            identity: FrozenFrontierIdentity {
                chain_id,
                protocol_version,
                epoch,
                domain,
                closure_request_id,
                closure_height,
                entry_count: 0,
                entries_digest,
            },
            last_request_id: None,
        })
    }

    /// Restores the last CAS-committed local progress row. This trusts the
    /// storage transition that produced its running digest, not an untrusted
    /// network cursor; callers must never accept a remote row here.
    pub fn resume(
        resolver: &HashSuiteResolver,
        identity: FrozenFrontierIdentity,
        last_request_id: Option<[u8; 32]>,
    ) -> Result<Self, FrontierError> {
        encode_frozen_frontier_identity(&identity)?;
        if resolver.chain_id() != &identity.chain_id
            || resolver.protocol_version() != identity.protocol_version
            || !resolver.is_algorithm_trusted_for_purpose(
                HashPurpose::ExecutionEffects,
                identity.epoch,
                identity.entries_digest.algorithm(),
            )
        {
            return Err(FrontierError::Invalid(
                "frontier cursor hash context mismatch",
            ));
        }
        if (identity.entry_count == 0) != last_request_id.is_none()
            || last_request_id == Some([0; 32])
        {
            return Err(FrontierError::Invalid(
                "frontier cursor count and key mismatch",
            ));
        }
        if identity.entry_count == 0 {
            let seed: Self = Self::new(
                resolver,
                identity.chain_id.clone(),
                identity.protocol_version,
                identity.epoch,
                identity.domain,
                identity.closure_request_id,
                identity.closure_height,
            )?;
            if seed.identity != identity {
                return Err(FrontierError::Invalid(
                    "empty frontier cursor digest mismatch",
                ));
            }
        }
        Ok(Self {
            identity,
            last_request_id,
        })
    }

    /// Adds exactly the next canonical retained availability identity.
    pub fn push(
        &mut self,
        resolver: &HashSuiteResolver,
        entry: &AvailabilityIdentity,
    ) -> Result<(), FrontierError> {
        if resolver.chain_id() != &self.identity.chain_id
            || resolver.protocol_version() != self.identity.protocol_version
        {
            return Err(FrontierError::Invalid(
                "frontier hash resolver context mismatch",
            ));
        }
        if entry.chain_id != self.identity.chain_id
            || entry.protocol_version != self.identity.protocol_version
            || entry.epoch != self.identity.epoch
            || entry.domain != self.identity.domain
        {
            return Err(FrontierError::Invalid(
                "foreign publication identity in frontier",
            ));
        }
        ensure_request_id_nonzero(&entry.request_id)?;
        if self
            .last_request_id
            .is_some_and(|previous| previous >= entry.request_id)
        {
            return Err(FrontierError::Invalid(
                "frontier request IDs are not strictly ordered",
            ));
        }
        let next_count: u64 = self
            .identity
            .entry_count
            .checked_add(1)
            .ok_or(FrontierError::Invalid("frontier count overflow"))?;
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(FRONTIER_ACCUMULATOR_TYPE_ID, ENCODING_VERSION);
        frame.field_u16(1, 1)?;
        frame.field_bytes(2, encode_digest32(&self.identity.entries_digest)?)?;
        frame.field_u64(3, next_count)?;
        frame.field_bytes(4, encode_availability_identity(entry)?)?;
        let next_digest: Digest32 = resolver.hash_for_purpose(
            self.identity.epoch,
            HashPurpose::ExecutionEffects,
            &frame.finish()?,
        )?;
        self.identity.entry_count = next_count;
        self.identity.entries_digest = next_digest;
        self.last_request_id = Some(entry.request_id);
        Ok(())
    }

    #[must_use]
    pub const fn identity(&self) -> &FrozenFrontierIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn last_request_id(&self) -> Option<[u8; 32]> {
        self.last_request_id
    }

    #[must_use]
    pub fn into_identity(self) -> FrozenFrontierIdentity {
        self.identity
    }
}

/// Independently reconstructs the claimed frontier from an ordered stream of
/// identities. Page transport must additionally prove a closed range; this
/// function cannot infer that a source store omitted a row.
pub fn verify_frozen_frontier<'a>(
    resolver: &HashSuiteResolver,
    claimed: &FrozenFrontierIdentity,
    entries: impl IntoIterator<Item = &'a AvailabilityIdentity>,
) -> Result<(), FrontierError> {
    let mut accumulator: FrozenFrontierAccumulator = FrozenFrontierAccumulator::new(
        resolver,
        claimed.chain_id.clone(),
        claimed.protocol_version,
        claimed.epoch,
        claimed.domain,
        claimed.closure_request_id,
        claimed.closure_height,
    )?;
    for entry in entries {
        accumulator.push(resolver, entry)?;
    }
    if accumulator.identity() != claimed {
        return Err(FrontierError::Invalid("frontier count or digest mismatch"));
    }
    Ok(())
}

/// Canonical `0xD036/v1` identity bytes.
pub fn encode_frozen_frontier_identity(
    identity: &FrozenFrontierIdentity,
) -> Result<Vec<u8>, FrontierError> {
    ensure_chain_id_bound(&identity.chain_id)?;
    ensure_request_id_nonzero(&identity.closure_request_id)?;
    if identity.closure_height == 0 {
        return Err(FrontierError::Invalid("zero Freeze block height"));
    }
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(FRONTIER_IDENTITY_TYPE_ID, ENCODING_VERSION);
    frame.field_str(1, identity.chain_id.as_str())?;
    frame.field_u32(2, identity.protocol_version.get())?;
    frame.field_u64(3, identity.epoch.get())?;
    frame.field_bytes(4, identity.domain.as_bytes().to_vec())?;
    frame.field_bytes(5, identity.closure_request_id.to_vec())?;
    frame.field_u64(6, identity.closure_height)?;
    frame.field_u64(7, identity.entry_count)?;
    frame.field_bytes(8, encode_digest32(&identity.entries_digest)?)?;
    let encoded: Vec<u8> = frame.finish()?;
    if encoded.len() > MAX_FRONTIER_IDENTITY_BYTES {
        return Err(FrontierError::Invalid(
            "frontier identity frame exceeds bound",
        ));
    }
    Ok(encoded)
}

/// Strict canonical decode of a frozen frontier identity.
pub fn decode_frozen_frontier_identity(
    input: &[u8],
) -> Result<FrozenFrontierIdentity, FrontierError> {
    if input.len() > MAX_FRONTIER_IDENTITY_BYTES {
        return Err(FrontierError::Invalid(
            "frontier identity frame exceeds bound",
        ));
    }
    let frame = decode_canonical_frame(input)?;
    frame.require_type(FRONTIER_IDENTITY_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8])?;
    let chain_str: &str = frame.required_str(1)?;
    if chain_str.len() > 128 {
        return Err(FrontierError::Invalid("frontier chain id exceeds bound"));
    }
    let domain_bytes: [u8; 32] = frame
        .required_field(4)?
        .try_into()
        .map_err(|_| FrontierError::Invalid("frontier domain length"))?;
    let closure_request_id: [u8; 32] = frame
        .required_field(5)?
        .try_into()
        .map_err(|_| FrontierError::Invalid("frontier closure request id length"))?;
    let identity = FrozenFrontierIdentity {
        chain_id: ChainId::new(chain_str.to_owned()).map_err(ConsensusError::ProtocolType)?,
        protocol_version: ProtocolVersion::new(frame.required_u32(2)?),
        epoch: Epoch::new(frame.required_u64(3)?),
        domain: AtomicityDomainId::new(domain_bytes).map_err(ConsensusError::ProtocolType)?,
        closure_request_id,
        closure_height: frame.required_u64(6)?,
        entry_count: frame.required_u64(7)?,
        entries_digest: decode_digest32(frame.required_field(8)?)?,
    };
    if encode_frozen_frontier_identity(&identity)?.as_slice() != input {
        return Err(FrontierError::Invalid("noncanonical frontier identity"));
    }
    Ok(identity)
}

/// Canonical `0xD037/v1` vote bytes.
pub fn encode_frozen_frontier_vote(vote: &FrozenFrontierVote) -> Result<Vec<u8>, FrontierError> {
    validate_signature_length(&vote.signature)?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(FRONTIER_VOTE_TYPE_ID, ENCODING_VERSION);
    frame.field_bytes(1, encode_frozen_frontier_identity(&vote.identity)?)?;
    frame.field_bytes(2, vote.validator.as_bytes())?;
    frame.field_u16(3, vote.signature_scheme.as_u16())?;
    frame.field_bytes(4, vote.signature.clone())?;
    let encoded: Vec<u8> = frame.finish()?;
    if encoded.len() > MAX_FRONTIER_VOTE_BYTES {
        return Err(FrontierError::Invalid("frontier vote frame exceeds bound"));
    }
    Ok(encoded)
}

/// Strict canonical decode of a frozen frontier vote; cryptographic
/// verification remains a separate required step.
pub fn decode_frozen_frontier_vote(input: &[u8]) -> Result<FrozenFrontierVote, FrontierError> {
    if input.len() > MAX_FRONTIER_VOTE_BYTES {
        return Err(FrontierError::Invalid("frontier vote frame exceeds bound"));
    }
    let frame = decode_canonical_frame(input)?;
    frame.require_type(FRONTIER_VOTE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let validator: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| FrontierError::Invalid("frontier validator id length"))?;
    let vote = FrozenFrontierVote {
        identity: decode_frozen_frontier_identity(frame.required_field(1)?)?,
        validator: ValidatorId::new(validator),
        signature_scheme: SignatureSchemeId::try_from(frame.required_u16(3)?)
            .map_err(ConsensusError::ProtocolType)?,
        signature: frame.required_field(4)?.to_vec(),
    };
    if encode_frozen_frontier_vote(&vote)?.as_slice() != input {
        return Err(FrontierError::Invalid("noncanonical frontier vote"));
    }
    Ok(vote)
}

/// Stateless signer/verifier bound to the outgoing committee. A vote is only
/// valid after the caller has durably fixed and independently verified the
/// underlying frontier; this type never checks persistence.
#[derive(Clone, Debug)]
pub struct FrozenFrontierCertifier {
    inner: AvailabilityCertifier,
}

impl FrozenFrontierCertifier {
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        validator_set: ValidatorSet,
    ) -> Result<Self, FrontierError> {
        Ok(Self {
            inner: AvailabilityCertifier::new(chain_id, protocol_version, epoch, validator_set)?,
        })
    }

    pub fn cast_vote<S: ConsensusSigner>(
        &self,
        identity: FrozenFrontierIdentity,
        signer: &S,
    ) -> Result<FrozenFrontierVote, FrontierError> {
        self.validate_context(&identity)?;
        self.inner
            .ensure_registered_scheme(signer.validator_id(), signer.signature_scheme())?;
        let frame: Vec<u8> = self.signature_frame(signer.signature_scheme(), &identity)?;
        let signature: Vec<u8> = signer
            .sign_framed(&frame)
            .map_err(ConsensusError::Authenticator)?;
        validate_signature_length(&signature)?;
        Ok(FrozenFrontierVote {
            identity,
            validator: signer.validator_id(),
            signature_scheme: signer.signature_scheme(),
            signature,
        })
    }

    pub fn verify_vote<V: ConsensusVerifier>(
        &self,
        vote: &FrozenFrontierVote,
        verifier: &V,
    ) -> Result<(), FrontierError> {
        self.validate_context(&vote.identity)?;
        self.inner
            .ensure_registered_scheme(vote.validator, vote.signature_scheme)?;
        validate_signature_length(&vote.signature)?;
        let info = self
            .inner
            .validator_set()
            .get(vote.validator)
            .ok_or(ConsensusError::UnknownValidator(vote.validator))?;
        let frame: Vec<u8> = self.signature_frame(vote.signature_scheme, &vote.identity)?;
        let valid: bool = verifier
            .verify_framed(
                vote.validator,
                vote.signature_scheme,
                &info.public_key,
                &frame,
                &vote.signature,
            )
            .map_err(ConsensusError::Authenticator)?;
        if !valid {
            return Err(ConsensusError::InvalidSignature(vote.validator).into());
        }
        Ok(())
    }

    fn validate_context(&self, identity: &FrozenFrontierIdentity) -> Result<(), FrontierError> {
        self.inner.ensure_context(
            &identity.chain_id,
            identity.protocol_version,
            identity.epoch,
        )?;
        encode_frozen_frontier_identity(identity)?;
        Ok(())
    }

    fn signature_frame(
        &self,
        scheme: SignatureSchemeId,
        identity: &FrozenFrontierIdentity,
    ) -> Result<Vec<u8>, FrontierError> {
        Ok(frame_signature_message(
            &SignatureDomain {
                chain_id: self.inner.chain_id().clone(),
                protocol_version: self.inner.protocol_version(),
                epoch: self.inner.epoch(),
                message_type: SignatureMessageType::new(FRONTIER_VOTE_MESSAGE_TYPE)?,
                signature_scheme_id: scheme,
            },
            &encode_frozen_frontier_identity(identity)?,
        )?)
    }
}

impl From<canonical_encoding::CanonicalEncodingError> for FrontierError {
    fn from(error: canonical_encoding::CanonicalEncodingError) -> Self {
        Self::Consensus(ConsensusError::CanonicalEncoding(error))
    }
}

impl From<CanonicalDecodingError> for FrontierError {
    fn from(error: CanonicalDecodingError) -> Self {
        Self::Consensus(ConsensusError::CanonicalDecoding(error))
    }
}

impl From<crypto::CryptoError> for FrontierError {
    fn from(error: crypto::CryptoError) -> Self {
        Self::Consensus(ConsensusError::Crypto(error))
    }
}

#[cfg(test)]
mod tests;
