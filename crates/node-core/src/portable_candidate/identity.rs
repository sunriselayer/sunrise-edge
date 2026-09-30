//! `PortableCandidateIdentity` (frame `0x6490`): the exact root binding every
//! other DR-0166 frame carries. It never embeds the source's physical
//! `PortableSnapshotToken`: that token is a local storage fence, folded only
//! into the non-root progress envelope (`super::progress`), never into this
//! identity or any digest derived from it.
use super::*;

const PORTABLE_CANDIDATE_IDENTITY_TYPE: u16 = 0x6490;
const ENCODING_VERSION: u16 = 1;
pub const MAX_ENCODED_PORTABLE_CANDIDATE_IDENTITY_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableCandidateIdentity {
    pub drain_identity: DrainUnionIdentity,
    pub terminal_height: u64,
    pub terminal_digest: Digest32,
    pub terminal_proof_digest: Digest32,
}

impl PortableCandidateIdentity {
    /// Binds identity to an already-derived, already-verified terminal
    /// witness. Performs no storage I/O and no re-verification.
    pub fn bind(
        resolver: &HashSuiteResolver,
        terminal: &CandidateFreeTerminalWitness,
    ) -> Result<Self, PortableCandidateError> {
        if terminal.height() == 0 {
            return Err(PortableCandidateError::Invalid(
                "candidate-free terminal height is zero",
            ));
        }
        let proof_bytes: Vec<u8> = match encode_committed_block_proof(terminal.proof()) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(PortableCandidateError::Invalid(
                    "terminal proof re-encoding failed",
                ));
            }
        };
        let terminal_proof_digest: Digest32 = resolver.hash_for_purpose(
            terminal.drain_identity().epoch,
            HashPurpose::ExecutionEffects,
            &proof_bytes,
        )?;
        Ok(Self {
            drain_identity: terminal.drain_identity().clone(),
            terminal_height: terminal.height(),
            terminal_digest: terminal.digest(),
            terminal_proof_digest,
        })
    }

    /// The exact root digest every other DR-0166 frame binds to.
    pub fn digest(&self, resolver: &HashSuiteResolver) -> Result<Digest32, PortableCandidateError> {
        if &self.drain_identity.chain_id != resolver.chain_id()
            || self.drain_identity.protocol_version != resolver.protocol_version()
        {
            return Err(PortableCandidateError::Invalid(
                "candidate identity resolver context mismatch",
            ));
        }
        let bytes: Vec<u8> = encode_portable_candidate_identity(self)?;
        Ok(resolver.hash_for_purpose(
            self.drain_identity.epoch,
            HashPurpose::ExecutionEffects,
            &bytes,
        )?)
    }
}

pub fn encode_portable_candidate_identity(
    identity: &PortableCandidateIdentity,
) -> Result<Vec<u8>, PortableCandidateError> {
    if identity.terminal_height <= identity.drain_identity.closure_height {
        return Err(PortableCandidateError::Invalid(
            "candidate terminal is not after Freeze closure",
        ));
    }
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(PORTABLE_CANDIDATE_IDENTITY_TYPE, ENCODING_VERSION);
    let drain_bytes: Vec<u8> = match encode_drain_union_identity(&identity.drain_identity) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(PortableCandidateError::Invalid(
                "drain identity encoding failed",
            ));
        }
    };
    frame.field_bytes(1, drain_bytes)?;
    frame.field_u64(2, identity.terminal_height)?;
    frame.field_bytes(
        3,
        canonical_encoding::encode_digest32(&identity.terminal_digest)?,
    )?;
    frame.field_bytes(
        4,
        canonical_encoding::encode_digest32(&identity.terminal_proof_digest)?,
    )?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_ENCODED_PORTABLE_CANDIDATE_IDENTITY_BYTES {
        return Err(PortableCandidateError::Invalid(
            "candidate identity frame too large",
        ));
    }
    Ok(bytes)
}

pub fn decode_portable_candidate_identity(
    input: &[u8],
) -> Result<PortableCandidateIdentity, PortableCandidateError> {
    if input.len() > MAX_ENCODED_PORTABLE_CANDIDATE_IDENTITY_BYTES {
        return Err(PortableCandidateError::Invalid(
            "candidate identity frame too large",
        ));
    }
    let frame = decode_canonical_frame(input)?;
    frame.require_type(PORTABLE_CANDIDATE_IDENTITY_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let drain_identity: DrainUnionIdentity =
        match decode_drain_union_identity(frame.required_field(1)?) {
            Ok(identity) => identity,
            Err(_) => {
                return Err(PortableCandidateError::Invalid(
                    "drain identity decoding failed",
                ));
            }
        };
    let terminal_height: u64 = frame.required_u64(2)?;
    if terminal_height == 0 {
        return Err(PortableCandidateError::Invalid(
            "candidate identity terminal height is zero",
        ));
    }
    let terminal_digest: Digest32 = canonical_encoding::decode_digest32(frame.required_field(3)?)?;
    let terminal_proof_digest: Digest32 =
        canonical_encoding::decode_digest32(frame.required_field(4)?)?;
    let identity = PortableCandidateIdentity {
        drain_identity,
        terminal_height,
        terminal_digest,
        terminal_proof_digest,
    };
    if encode_portable_candidate_identity(&identity)? != input {
        return Err(PortableCandidateError::Invalid(
            "noncanonical portable candidate identity",
        ));
    }
    Ok(identity)
}
