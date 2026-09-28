//! Strict decoders for the handoff-capable `0x6424/v2` commitment witness's
//! signed operand lists, and the required replay-artifact closure derived from
//! them (DR-0154 / `epoch-handoff.md`, "Execution-free publication").
//!
//! The design requires a retainer to "strictly decode every witness field and
//! derive the required artifact set from its signed read, object and mutation
//! operands", rather than trusting a caller-chosen list of hashes. These
//! decoders mirror [`super::super::commitment`]'s encoders exactly and are
//! pinned to them by a round-trip test over a real admission's envelope.
//!
//! # Why the closure is complete
//!
//! Admission itself already performed every read this operation needed --
//! including the transitive code/ABI/publication/instance closure a paid
//! application resolves before it can execute -- and every one of those reads
//! is a signed operand of the v2 envelope. The required artifact set is
//! therefore exactly:
//!
//! * one [`ArtifactKind::StateValue`] per signed generic state read whose
//!   observation is `StatePresent`, identified by the state key and bound to
//!   that observation's own content digest (this is where code, ABI,
//!   publication and instance records live);
//! * one [`ArtifactKind::ObjectBody`] per signed durable object head read
//!   observed `Current`, identified by `(object id, object version)` and bound
//!   to that head's object digest;
//! * one [`ArtifactKind::ObjectBody`] per signed object mutation whose staged
//!   version is blob-backed, since those body bytes are *not* inside the
//!   witness. An inline staged version carries its bytes in the witness
//!   itself and needs no separate artifact.
//!
//! A `StateDeleted` observation, a `Tombstoned` head and a never-written
//! subject are all explicitly *not* artifacts, and they stay distinguishable
//! from each other in the signed operand, so a claimed tombstone can never be
//! presented as absence (or vice versa) without changing the witness -- and
//! therefore the certificate.
//!
//! Any two required entries that name the same `(kind, identity)` must agree
//! on the content digest; a contradiction is a refusal, never a silent
//! last-writer-wins merge.

use super::super::commitment;
use super::{ArtifactKind, PublicationRetentionError, RequiredArtifacts};
use crate::logical_generation::{self, LogicalObservation};
use protocol_types::{Digest32, HashAlgorithmId};

/// A bounded forward-only reader over one operand buffer.
///
/// Every read is length-checked before it is performed, and
/// [`Cursor::finish`] refuses trailing bytes, so a truncated, padded or
/// otherwise non-canonical operand is rejected rather than partially parsed.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    what: &'static str,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8], what: &'static str) -> Self {
        Self {
            bytes,
            offset: 0,
            what,
        }
    }

    fn malformed(&self) -> PublicationRetentionError {
        PublicationRetentionError::MalformedWitnessOperand(self.what)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PublicationRetentionError> {
        let end: usize = self
            .offset
            .checked_add(length)
            .ok_or_else(|| self.malformed())?;
        if end > self.bytes.len() {
            return Err(self.malformed());
        }
        let slice: &[u8] = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8, PublicationRetentionError> {
        Ok(self.take(1)?[0])
    }

    fn take_u32(&mut self) -> Result<u32, PublicationRetentionError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| self.malformed())?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn take_u64(&mut self) -> Result<u64, PublicationRetentionError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| self.malformed())?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn take_digest_bytes(&mut self) -> Result<[u8; 32], PublicationRetentionError> {
        self.take(32)?.try_into().map_err(|_| self.malformed())
    }

    /// Reads one `push_length_prefixed` value.
    fn take_length_prefixed(&mut self) -> Result<&'a [u8], PublicationRetentionError> {
        let length: usize = usize::try_from(self.take_u32()?).map_err(|_| self.malformed())?;
        self.take(length)
    }

    /// Reads one `push_optional_bytes` value and discards it: owner/routing
    /// projections are body-free routing metadata, never replay artifacts.
    fn skip_optional_bytes(&mut self) -> Result<(), PublicationRetentionError> {
        match self.take_u8()? {
            0 => Ok(()),
            1 => {
                let _ = self.take_length_prefixed()?;
                Ok(())
            }
            _ => Err(self.malformed()),
        }
    }

    fn finish(self) -> Result<(), PublicationRetentionError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PublicationRetentionError::MalformedWitnessOperand(
                self.what,
            ))
        }
    }
}

/// Reads one `encode_list` header and returns the declared item count,
/// bounded by the same ceiling the encoder enforces before any allocation.
fn take_list_count(cursor: &mut Cursor<'_>) -> Result<usize, PublicationRetentionError> {
    let count: usize = usize::try_from(cursor.take_u32()?).map_err(|_| cursor.malformed())?;
    if count > commitment::MAX_WITNESS_LIST_ITEMS {
        return Err(PublicationRetentionError::WitnessListTooLarge {
            what: cursor.what,
            actual: count,
            max: commitment::MAX_WITNESS_LIST_ITEMS,
        });
    }
    Ok(count)
}

/// The exact `(tag, total operand length)` shape one observation variant
/// encodes as, derived at runtime from `logical_generation`'s own encoder so
/// this decoder never restates that module's private tag constants.
fn observation_shape(observation: LogicalObservation) -> (u16, usize) {
    let operand: Vec<u8> = logical_generation::observation_operand(Some(observation));
    let tag: u16 = u16::from_be_bytes([
        operand.first().copied().unwrap_or_default(),
        operand.get(1).copied().unwrap_or_default(),
    ]);
    (tag, operand.len())
}

/// A placeholder digest used only to measure an operand's encoded shape. The
/// operand encoder writes a `Digest32`'s raw bytes and never its algorithm, so
/// any value produces the same length.
fn shape_digest() -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [0u8; 32])
}

/// The closed set of observation shapes a signed generic state read may carry.
///
/// A read operand whose tag is outside this set, or whose length disagrees
/// with its tag's fixed shape, is a refusal: an unknown observation must never
/// be skipped as "not an artifact".
fn classify_observation(operand: &[u8]) -> Result<ObservedRead, PublicationRetentionError> {
    if operand == [0u8] {
        return Ok(ObservedRead::NeverWritten);
    }
    let (present_tag, present_len) = observation_shape(LogicalObservation::StatePresent {
        content_digest: shape_digest(),
    });
    let (deleted_tag, deleted_len) = observation_shape(LogicalObservation::StateDeleted);
    if operand.len() < 2 {
        return Err(PublicationRetentionError::MalformedWitnessOperand(
            "state read observation",
        ));
    }
    let tag: u16 = u16::from_be_bytes([operand[0], operand[1]]);
    if tag == present_tag {
        if operand.len() != present_len {
            return Err(PublicationRetentionError::MalformedWitnessOperand(
                "state read observation",
            ));
        }
        let digest: [u8; 32] = operand[2..present_len].try_into().map_err(|_| {
            PublicationRetentionError::MalformedWitnessOperand("state read observation")
        })?;
        return Ok(ObservedRead::Present { digest });
    }
    if tag == deleted_tag {
        if operand.len() != deleted_len {
            return Err(PublicationRetentionError::MalformedWitnessOperand(
                "state read observation",
            ));
        }
        return Ok(ObservedRead::Deleted);
    }
    // An object or nonce observation cannot legally be paired with a generic
    // state-key subject (`logical_generation::require_pairing`), and an
    // unrecognized tag is unknown future material. Both fail closed.
    Err(PublicationRetentionError::UnsupportedReadObservation(tag))
}

/// What one signed generic state read observed.
enum ObservedRead {
    /// Present value bound by its content digest: a required artifact.
    Present {
        /// Raw content digest bytes of the exact canonical stored value.
        digest: [u8; 32],
    },
    /// Tombstone: authenticated, and explicitly not absence. No artifact.
    Deleted,
    /// Never-written subject. No artifact.
    NeverWritten,
}

/// Derives the complete required replay-artifact closure from one verified
/// `0x6424/v2` witness, together with the signed intent digest that envelope
/// carries.
///
/// Refuses a historical `0x6424/v1` witness, any malformed or trailing operand
/// byte, an over-bound list, an unknown observation or payload tag, and two
/// required entries that name the same `(kind, identity)` with different
/// content digests.
pub(crate) fn required_artifacts(
    witness: &[u8],
) -> Result<(Digest32, RequiredArtifacts), PublicationRetentionError> {
    let operands =
        commitment::logical_witness_operands(witness).map_err(PublicationRetentionError::Node)?;
    let mut required: RequiredArtifacts = RequiredArtifacts::default();

    decode_state_reads(operands.state_reads, &mut required)?;
    decode_head_reads(operands.head_reads, &mut required)?;
    decode_object_mutations(operands.object_mutations, &mut required)?;
    validate_dependencies(operands.dependencies)?;

    Ok((operands.event_digest, required))
}

fn decode_state_reads(
    bytes: &[u8],
    required: &mut RequiredArtifacts,
) -> Result<(), PublicationRetentionError> {
    let mut cursor: Cursor<'_> = Cursor::new(bytes, "state reads");
    let count: usize = take_list_count(&mut cursor)?;
    for _ in 0..count {
        let item: &[u8] = cursor.take_length_prefixed()?;
        let mut entry: Cursor<'_> = Cursor::new(item, "state read");
        let key: &[u8] = entry.take_length_prefixed()?;
        let operand: &[u8] = entry.take_length_prefixed()?;
        match entry.take_u8()? {
            0 => {}
            1 => {
                let _ = entry.take_u64()?;
            }
            _ => {
                return Err(PublicationRetentionError::MalformedWitnessOperand(
                    "state read generation",
                ));
            }
        }
        entry.finish()?;
        if let ObservedRead::Present { digest } = classify_observation(operand)? {
            required.insert(ArtifactKind::StateValue, key.to_vec(), digest)?;
        }
    }
    cursor.finish()
}

fn decode_head_reads(
    bytes: &[u8],
    required: &mut RequiredArtifacts,
) -> Result<(), PublicationRetentionError> {
    let mut cursor: Cursor<'_> = Cursor::new(bytes, "object head reads");
    let count: usize = take_list_count(&mut cursor)?;
    for _ in 0..count {
        let item: &[u8] = cursor.take_length_prefixed()?;
        let mut entry: Cursor<'_> = Cursor::new(item, "object head read");
        let object_id: [u8; 32] = entry.take_digest_bytes()?;
        match entry.take_u8()? {
            // Absent: no artifact, and never confusable with a tombstone.
            0 => {}
            // Tombstoned: the last logical version is signed; there is no body
            // to replay.
            1 => {
                let _ = entry.take_u64()?;
            }
            // Current: the exact input object body is a required artifact.
            2 => {
                let object_version: u64 = entry.take_u64()?;
                let digest: [u8; 32] = entry.take_digest_bytes()?;
                entry.skip_optional_bytes()?;
                entry.skip_optional_bytes()?;
                required.insert(
                    ArtifactKind::ObjectBody,
                    object_body_identity(object_id, object_version),
                    digest,
                )?;
            }
            _ => {
                return Err(PublicationRetentionError::MalformedWitnessOperand(
                    "object head read",
                ));
            }
        }
        entry.finish()?;
    }
    cursor.finish()
}

fn decode_object_mutations(
    bytes: &[u8],
    required: &mut RequiredArtifacts,
) -> Result<(), PublicationRetentionError> {
    let mut cursor: Cursor<'_> = Cursor::new(bytes, "object mutations");
    let count: usize = take_list_count(&mut cursor)?;
    for _ in 0..count {
        let item: &[u8] = cursor.take_length_prefixed()?;
        let mut entry: Cursor<'_> = Cursor::new(item, "object mutation");
        let _object_id: [u8; 32] = entry.take_digest_bytes()?;
        match entry.take_u8()? {
            // Delete: no body.
            0 => {}
            // Create or Update: a blob-backed staged version's bytes are not
            // in the witness and must be supplied; an inline one already is.
            1 | 2 => {
                let version: &[u8] = entry.take_length_prefixed()?;
                entry.skip_optional_bytes()?;
                entry.skip_optional_bytes()?;
                decode_version_record(version, required)?;
            }
            _ => {
                return Err(PublicationRetentionError::MalformedWitnessOperand(
                    "object mutation",
                ));
            }
        }
        entry.finish()?;
    }
    cursor.finish()
}

fn decode_version_record(
    bytes: &[u8],
    required: &mut RequiredArtifacts,
) -> Result<(), PublicationRetentionError> {
    let mut cursor: Cursor<'_> = Cursor::new(bytes, "object version record");
    let object_id: [u8; 32] = cursor.take_digest_bytes()?;
    let object_version: u64 = cursor.take_u64()?;
    let digest: [u8; 32] = cursor.take_digest_bytes()?;
    // schema version, chain id, protocol version: signed provenance this
    // decoder does not need, but must consume exactly.
    let _schema_version: u32 = cursor.take_u32()?;
    let _chain_id: &[u8] = cursor.take_length_prefixed()?;
    let _protocol_version: u32 = cursor.take_u32()?;
    match cursor.take_u8()? {
        0 => {
            let _inline: &[u8] = cursor.take_length_prefixed()?;
        }
        1 => {
            let blob_digest: [u8; 32] = cursor.take_digest_bytes()?;
            if blob_digest != digest {
                return Err(PublicationRetentionError::MalformedWitnessOperand(
                    "blob-backed object version digest",
                ));
            }
            required.insert(
                ArtifactKind::ObjectBody,
                object_body_identity(object_id, object_version),
                digest,
            )?;
        }
        _ => {
            return Err(PublicationRetentionError::MalformedWitnessOperand(
                "object version payload",
            ));
        }
    }
    cursor.finish()
}

/// Structurally validates the signed dependency list: bounded count and one
/// exactly consumed `(subject operand, generation)` pair per item.
///
/// Dependencies carry authenticated causal generations, not content, so they
/// contribute no artifacts. They are still decoded rather than skipped: a
/// malformed or over-bound list must refuse the ACK, not pass unexamined.
fn validate_dependencies(bytes: &[u8]) -> Result<(), PublicationRetentionError> {
    let mut cursor: Cursor<'_> = Cursor::new(bytes, "dependencies");
    let count: usize = take_list_count(&mut cursor)?;
    for _ in 0..count {
        let item: &[u8] = cursor.take_length_prefixed()?;
        let mut entry: Cursor<'_> = Cursor::new(item, "dependency");
        let _subject: &[u8] = entry.take_length_prefixed()?;
        let _generation: u64 = entry.take_u64()?;
        entry.finish()?;
    }
    cursor.finish()
}

/// The stable manifest identity of one immutable object body: its 32-byte
/// object id followed by the big-endian logical object version.
pub(crate) fn object_body_identity(object_id: [u8; 32], object_version: u64) -> Vec<u8> {
    let mut identity: Vec<u8> = object_id.to_vec();
    identity.extend_from_slice(&object_version.to_be_bytes());
    identity
}
