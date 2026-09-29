//! Deterministic local DrainSet-union reconstruction (DR-0154 / DR-0156).
//!
//! This module owns only a pure, stateless accumulator over the canonically
//! ascending, unique confirmed availability identities selected across a
//! weighted outgoing quorum of frozen-frontier signers, plus its exposed
//! commitment type. It does not read storage, select a quorum, verify a
//! signature, decide which signers are complete, or decide DrainSet
//! readiness: those remain node-core obligations (see
//! `node_core::ordered_economics::drain_union`). It deliberately reuses
//! [`super::frontier::FrontierError`] rather than defining a parallel error
//! type, since the failure modes are identical. Its digest domain is
//! distinct from [`super::frontier`]'s own accumulator/identity family
//! purely through this module's own canonical frame type IDs -- there is no
//! signed vote here at all: DR-0156 deliberately never signs, ACKs or
//! otherwise authorizes this reconstruction, so callers must not treat a
//! [`DrainUnionIdentity`] as anything beyond one replica's own local
//! progress.

use super::frontier::FrontierError;
use super::{AvailabilityIdentity, encode_availability_identity, ensure_chain_id_bound};
use crate::ConsensusError;
use canonical_encoding::{
    CanonicalStruct, decode_canonical_frame, decode_digest32, encode_digest32,
};
use hashing::HashSuiteResolver;
use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, Epoch, HashPurpose, ProtocolVersion, ValidatorId,
};

const DRAIN_UNION_ACCUMULATOR_TYPE_ID: u16 = 0xD03A;
const DRAIN_UNION_IDENTITY_TYPE_ID: u16 = 0xD03B;
const ENCODING_VERSION: u16 = 1;
const MAX_DRAIN_UNION_IDENTITY_BYTES: usize = 4 * 1024;
/// Matches `validator_set::MAX_VALIDATORS`; a selected quorum can never
/// legitimately name more signers than exist in one outgoing epoch's set.
pub const MAX_DRAIN_UNION_SIGNERS: usize = 10_000;

fn ensure_member_request_id_nonzero(request_id: &[u8; 32]) -> Result<(), FrontierError> {
    if *request_id == [0; 32] {
        return Err(FrontierError::Invalid("zero drain union request id"));
    }
    Ok(())
}

/// A deterministic commitment to one replica's own selected-quorum DrainSet
/// union: the exact committed Freeze it is scoped to, the exact ascending
/// selected-signer roster it was reconstructed from, and every distinct
/// confirmed member identity folded in strictly ascending request-ID order.
/// This is local progress, never a signed or transferable cut fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainUnionIdentity {
    pub chain_id: ChainId,
    pub protocol_version: ProtocolVersion,
    pub epoch: Epoch,
    pub domain: AtomicityDomainId,
    pub closure_request_id: [u8; 32],
    pub closure_height: u64,
    pub signer_count: u64,
    pub member_count: u64,
    pub entries_digest: Digest32,
}

/// Incremental commitment. Exactly one member may be folded per call; there
/// is no whole-union entry limit beyond the protocol's own validator-set
/// bound on the selected-signer roster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainUnionAccumulator {
    identity: DrainUnionIdentity,
    last_request_id: Option<[u8; 32]>,
}

impl DrainUnionAccumulator {
    /// Starts a context- and roster-bound empty-union seed. `selected_signers`
    /// must already be the exact strictly ascending, unique, quorum-verified
    /// roster: this constructor re-checks ordering/uniqueness for its own
    /// self-containment but does not itself verify quorum power or
    /// signatures.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resolver: &HashSuiteResolver,
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        domain: AtomicityDomainId,
        closure_request_id: [u8; 32],
        closure_height: u64,
        selected_signers: &[ValidatorId],
    ) -> Result<Self, FrontierError> {
        ensure_chain_id_bound(&chain_id)?;
        ensure_member_request_id_nonzero(&closure_request_id)?;
        if closure_height == 0 {
            return Err(FrontierError::Invalid("zero Freeze block height"));
        }
        if selected_signers.is_empty() || selected_signers.len() > MAX_DRAIN_UNION_SIGNERS {
            return Err(FrontierError::Invalid("drain union signer count"));
        }
        for pair in selected_signers.windows(2) {
            if pair[0] >= pair[1] {
                return Err(FrontierError::Invalid("drain union signer order"));
            }
        }
        if resolver.chain_id() != &chain_id || resolver.protocol_version() != protocol_version {
            return Err(FrontierError::Invalid(
                "drain union hash resolver context mismatch",
            ));
        }
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(DRAIN_UNION_ACCUMULATOR_TYPE_ID, ENCODING_VERSION);
        frame.field_u16(1, 0)?;
        frame.field_str(2, chain_id.as_str())?;
        frame.field_u32(3, protocol_version.get())?;
        frame.field_u64(4, epoch.get())?;
        frame.field_bytes(5, domain.as_bytes().to_vec())?;
        frame.field_bytes(6, closure_request_id.to_vec())?;
        frame.field_u64(7, closure_height)?;
        let signer_count: u64 = u64::try_from(selected_signers.len())
            .map_err(|_| FrontierError::Invalid("drain union signer count overflow"))?;
        frame.field_u64(8, signer_count)?;
        for (index, signer) in selected_signers.iter().enumerate() {
            let field: u16 = u16::try_from(index + 9)
                .map_err(|_| FrontierError::Invalid("drain union signer field overflow"))?;
            frame.field_bytes(field, signer.as_bytes())?;
        }
        let entries_digest: Digest32 =
            resolver.hash_for_purpose(epoch, HashPurpose::ExecutionEffects, &frame.finish()?)?;
        Ok(Self {
            identity: DrainUnionIdentity {
                chain_id,
                protocol_version,
                epoch,
                domain,
                closure_request_id,
                closure_height,
                signer_count,
                member_count: 0,
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
        identity: DrainUnionIdentity,
        last_request_id: Option<[u8; 32]>,
        selected_signers: &[ValidatorId],
    ) -> Result<Self, FrontierError> {
        encode_drain_union_identity(&identity)?;
        if resolver.chain_id() != &identity.chain_id
            || resolver.protocol_version() != identity.protocol_version
            || !resolver.is_algorithm_trusted_for_purpose(
                HashPurpose::ExecutionEffects,
                identity.epoch,
                identity.entries_digest.algorithm(),
            )
        {
            return Err(FrontierError::Invalid(
                "drain union cursor hash context mismatch",
            ));
        }
        if (identity.member_count == 0) != last_request_id.is_none()
            || last_request_id == Some([0; 32])
        {
            return Err(FrontierError::Invalid(
                "drain union cursor count and key mismatch",
            ));
        }
        let signer_count: u64 = u64::try_from(selected_signers.len())
            .map_err(|_| FrontierError::Invalid("drain union signer count overflow"))?;
        if identity.signer_count != signer_count {
            return Err(FrontierError::Invalid("drain union signer count mismatch"));
        }
        if identity.member_count == 0 {
            let seed: Self = Self::new(
                resolver,
                identity.chain_id.clone(),
                identity.protocol_version,
                identity.epoch,
                identity.domain,
                identity.closure_request_id,
                identity.closure_height,
                selected_signers,
            )?;
            if seed.identity != identity {
                return Err(FrontierError::Invalid(
                    "empty drain union cursor digest mismatch",
                ));
            }
        }
        Ok(Self {
            identity,
            last_request_id,
        })
    }

    /// Folds exactly the next canonical confirmed availability identity.
    /// Callers must dedupe identical cross-signer identities and detect
    /// same-request-ID conflicts *before* calling this: it only enforces
    /// strict ascending, unique request-ID order for whatever single stream
    /// of members it is given.
    pub fn push_member(
        &mut self,
        resolver: &HashSuiteResolver,
        entry: &AvailabilityIdentity,
    ) -> Result<(), FrontierError> {
        if resolver.chain_id() != &self.identity.chain_id
            || resolver.protocol_version() != self.identity.protocol_version
        {
            return Err(FrontierError::Invalid(
                "drain union hash resolver context mismatch",
            ));
        }
        if entry.chain_id != self.identity.chain_id
            || entry.protocol_version != self.identity.protocol_version
            || entry.epoch != self.identity.epoch
            || entry.domain != self.identity.domain
        {
            return Err(FrontierError::Invalid(
                "foreign availability identity in drain union",
            ));
        }
        ensure_member_request_id_nonzero(&entry.request_id)?;
        if self
            .last_request_id
            .is_some_and(|previous| previous >= entry.request_id)
        {
            return Err(FrontierError::Invalid(
                "drain union request IDs are not strictly ordered",
            ));
        }
        let next_count: u64 = self
            .identity
            .member_count
            .checked_add(1)
            .ok_or(FrontierError::Invalid("drain union member count overflow"))?;
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(DRAIN_UNION_ACCUMULATOR_TYPE_ID, ENCODING_VERSION);
        frame.field_u16(1, 1)?;
        frame.field_bytes(2, encode_digest32(&self.identity.entries_digest)?)?;
        frame.field_u64(3, next_count)?;
        frame.field_bytes(4, encode_availability_identity(entry)?)?;
        let next_digest: Digest32 = resolver.hash_for_purpose(
            self.identity.epoch,
            HashPurpose::ExecutionEffects,
            &frame.finish()?,
        )?;
        self.identity.member_count = next_count;
        self.identity.entries_digest = next_digest;
        self.last_request_id = Some(entry.request_id);
        Ok(())
    }

    #[must_use]
    pub const fn identity(&self) -> &DrainUnionIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn last_request_id(&self) -> Option<[u8; 32]> {
        self.last_request_id
    }

    #[must_use]
    pub fn into_identity(self) -> DrainUnionIdentity {
        self.identity
    }
}

/// Canonical `0xD03B/v1` identity bytes.
pub fn encode_drain_union_identity(
    identity: &DrainUnionIdentity,
) -> Result<Vec<u8>, FrontierError> {
    ensure_chain_id_bound(&identity.chain_id)?;
    ensure_member_request_id_nonzero(&identity.closure_request_id)?;
    if identity.closure_height == 0 {
        return Err(FrontierError::Invalid("zero Freeze block height"));
    }
    if identity.signer_count == 0 || identity.signer_count > MAX_DRAIN_UNION_SIGNERS as u64 {
        return Err(FrontierError::Invalid("drain union identity signer count"));
    }
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(DRAIN_UNION_IDENTITY_TYPE_ID, ENCODING_VERSION);
    frame.field_str(1, identity.chain_id.as_str())?;
    frame.field_u32(2, identity.protocol_version.get())?;
    frame.field_u64(3, identity.epoch.get())?;
    frame.field_bytes(4, identity.domain.as_bytes().to_vec())?;
    frame.field_bytes(5, identity.closure_request_id.to_vec())?;
    frame.field_u64(6, identity.closure_height)?;
    frame.field_u64(7, identity.signer_count)?;
    frame.field_u64(8, identity.member_count)?;
    frame.field_bytes(9, encode_digest32(&identity.entries_digest)?)?;
    let encoded: Vec<u8> = frame.finish()?;
    if encoded.len() > MAX_DRAIN_UNION_IDENTITY_BYTES {
        return Err(FrontierError::Invalid(
            "drain union identity frame exceeds bound",
        ));
    }
    Ok(encoded)
}

/// Strict canonical decode of a drain-union identity.
pub fn decode_drain_union_identity(input: &[u8]) -> Result<DrainUnionIdentity, FrontierError> {
    if input.len() > MAX_DRAIN_UNION_IDENTITY_BYTES {
        return Err(FrontierError::Invalid(
            "drain union identity frame exceeds bound",
        ));
    }
    let frame = decode_canonical_frame(input)?;
    frame.require_type(DRAIN_UNION_IDENTITY_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    let chain_str: &str = frame.required_str(1)?;
    if chain_str.len() > 128 {
        return Err(FrontierError::Invalid("drain union chain id exceeds bound"));
    }
    let domain_bytes: [u8; 32] = frame
        .required_field(4)?
        .try_into()
        .map_err(|_| FrontierError::Invalid("drain union domain length"))?;
    let closure_request_id: [u8; 32] = frame
        .required_field(5)?
        .try_into()
        .map_err(|_| FrontierError::Invalid("drain union closure request id length"))?;
    let identity = DrainUnionIdentity {
        chain_id: ChainId::new(chain_str.to_owned()).map_err(ConsensusError::ProtocolType)?,
        protocol_version: ProtocolVersion::new(frame.required_u32(2)?),
        epoch: Epoch::new(frame.required_u64(3)?),
        domain: AtomicityDomainId::new(domain_bytes).map_err(ConsensusError::ProtocolType)?,
        closure_request_id,
        closure_height: frame.required_u64(6)?,
        signer_count: frame.required_u64(7)?,
        member_count: frame.required_u64(8)?,
        entries_digest: decode_digest32(frame.required_field(9)?)?,
    };
    if encode_drain_union_identity(&identity)?.as_slice() != input {
        return Err(FrontierError::Invalid("noncanonical drain union identity"));
    }
    Ok(identity)
}

#[cfg(test)]
mod tests;
