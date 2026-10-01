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
use crate::logical_generation::LogicalSubject;
use execution::{
    local_execution::{CreatedObjectAuthority, decode_object_authority},
    paid_execution::{PaidExecutionResult, encode_paid_execution_result},
};
use objects::ObjectId;
use protocol_types::{Digest32, Epoch, ExecutionGeneration, ProtocolVersion};
use runtime::{
    DurableObjectOwnerProjection, DurableObjectRoutingProjection, MAX_DURABLE_INLINE_OBJECT_BYTES,
    MAX_DURABLE_OBJECT_PROJECTION_BYTES, MAX_STATE_KEY_BYTES, MAX_STATE_VALUE_BYTES, StateMutation,
};
use std::cmp::Ordering;

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

    fn take_u16(&mut self) -> Result<u16, PublicationRetentionError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| self.malformed())?;
        Ok(u16::from_be_bytes(bytes))
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

    fn take_optional_bytes(&mut self) -> Result<Option<&'a [u8]>, PublicationRetentionError> {
        match self.take_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.take_length_prefixed()?)),
            _ => Err(self.malformed()),
        }
    }

    /// Reads one `push_optional_bytes` value, preserving absent versus present
    /// empty bytes. Owner/routing projections are not replay artifacts.
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

/// Untrusted, fully decoded fields of an existing logical-generation v2
/// commitment witness. This value is data only: callers must separately
/// authenticate the witness against a certificate, context and artifact
/// closure before assigning any authority to its operands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedLogicalWitness {
    pub(crate) event_digest: Digest32,
    pub(crate) paid_execution_result_bytes: Vec<u8>,
    pub(crate) paid_execution_result: PaidExecutionResult,
    pub(crate) created_authorities: Vec<CreatedObjectAuthority>,
    pub(crate) head_reads: Vec<DecodedObjectHeadRead>,
    pub(crate) object_mutations: Vec<DecodedObjectMutation>,
    pub(crate) state_reads: Vec<DecodedStateRead>,
    pub(crate) state_mutations: Vec<DecodedStateMutation>,
    pub(crate) nonce: DecodedNonceOperand,
    pub(crate) generation: ExecutionGeneration,
    pub(crate) dependencies: Vec<DecodedDependency>,
}

/// A semantic object-head input. V2 intentionally has no physical head revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedObjectHeadRead {
    pub(crate) object_id: ObjectId,
    pub(crate) observation: DecodedObjectHeadObservation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DecodedObjectHeadObservation {
    Absent,
    Tombstoned {
        last_object_version: u64,
    },
    Current {
        object_version: u64,
        digest: [u8; 32],
        owner_projection: DurableObjectOwnerProjection,
        routing_projection: DurableObjectRoutingProjection,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedObjectMutation {
    pub(crate) object_id: ObjectId,
    pub(crate) mutation: DecodedObjectMutationKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DecodedObjectMutationKind {
    Delete,
    Create {
        version: DecodedObjectVersion,
        owner_projection: DurableObjectOwnerProjection,
        routing_projection: DurableObjectRoutingProjection,
    },
    Update {
        version: DecodedObjectVersion,
        owner_projection: DurableObjectOwnerProjection,
        routing_projection: DurableObjectRoutingProjection,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedObjectVersion {
    pub(crate) object_id: ObjectId,
    pub(crate) object_version: u64,
    pub(crate) digest: [u8; 32],
    pub(crate) schema_version: u32,
    pub(crate) chain_id: protocol_types::ChainId,
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) payload: DecodedObjectPayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DecodedObjectPayload {
    InlineCanonicalObject(Vec<u8>),
    BlobReference([u8; 32]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedStateRead {
    pub(crate) key: Vec<u8>,
    pub(crate) observation: DecodedStateObservation,
    pub(crate) generation: Option<ExecutionGeneration>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecodedStateObservation {
    NeverWritten,
    Present { content_digest: [u8; 32] },
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedStateMutation {
    pub(crate) key: Vec<u8>,
    pub(crate) mutation: StateMutation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedNonceOperand {
    pub(crate) key: Vec<u8>,
    pub(crate) sender: [u8; 32],
    pub(crate) epoch: Epoch,
    pub(crate) next_nonce: u64,
    pub(crate) canonical_value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedDependency {
    pub(crate) subject: LogicalSubject,
    pub(crate) generation: ExecutionGeneration,
}

/// Strictly decodes every operand of the existing `0x6424/v2` frame. It adds
/// no trust: QCs authenticate the candidate identity, not these result bytes.
pub(crate) fn decode_logical_witness(
    witness: &[u8],
) -> Result<DecodedLogicalWitness, PublicationRetentionError> {
    if witness.len() > MAX_STATE_VALUE_BYTES {
        return Err(PublicationRetentionError::MalformedWitnessOperand(
            "witness bound",
        ));
    }
    let operands =
        commitment::logical_witness_operands(witness).map_err(PublicationRetentionError::Node)?;
    let frame = canonical_encoding::decode_canonical_frame(witness)
        .map_err(|_| PublicationRetentionError::MalformedWitnessOperand("witness frame"))?;
    let decoded = commitment::decode_witness(witness).map_err(PublicationRetentionError::Node)?;
    let paid_execution_result_bytes = frame
        .required_field(2)
        .map_err(|_| PublicationRetentionError::MalformedWitnessOperand("paid result"))?
        .to_vec();
    if encode_paid_execution_result(&decoded.paid_execution_result)
        .map_err(|_| PublicationRetentionError::MalformedWitnessOperand("paid result"))?
        != paid_execution_result_bytes
    {
        return Err(PublicationRetentionError::MalformedWitnessOperand(
            "paid result canonical bytes",
        ));
    }
    let created_authorities =
        decode_created_authorities(frame.required_field(3).map_err(|_| {
            PublicationRetentionError::MalformedWitnessOperand("created authorities")
        })?)?;
    let head_reads = decode_head_reads(operands.head_reads)?;
    let object_mutations = decode_object_mutations(operands.object_mutations)?;
    let state_reads = decode_state_reads(operands.state_reads)?;
    let state_mutations = decode_state_mutations(
        frame
            .required_field(7)
            .map_err(|_| PublicationRetentionError::MalformedWitnessOperand("state mutations"))?,
    )?;
    let nonce_key = frame
        .required_field(8)
        .map_err(|_| PublicationRetentionError::MalformedWitnessOperand("nonce key"))?;
    if nonce_key.is_empty() || nonce_key.len() > MAX_STATE_KEY_BYTES {
        return Err(PublicationRetentionError::MalformedWitnessOperand(
            "nonce key",
        ));
    }
    let canonical_nonce = frame
        .required_field(10)
        .map_err(|_| PublicationRetentionError::MalformedWitnessOperand("nonce value"))?;
    let nonce_record = crate::SenderNonceRecord::decode(canonical_nonce)
        .map_err(PublicationRetentionError::Node)?;
    let nonce = DecodedNonceOperand {
        key: nonce_key.to_vec(),
        sender: nonce_record.sender,
        epoch: nonce_record.epoch,
        next_nonce: nonce_record.next_nonce,
        canonical_value: canonical_nonce.to_vec(),
    };
    let generation = ExecutionGeneration::new(
        frame
            .required_u64(11)
            .map_err(|_| PublicationRetentionError::MalformedWitnessOperand("generation"))?,
    );
    let dependencies = decode_dependencies(operands.dependencies)?;
    Ok(DecodedLogicalWitness {
        event_digest: operands.event_digest,
        paid_execution_result_bytes,
        paid_execution_result: decoded.paid_execution_result,
        created_authorities,
        head_reads,
        object_mutations,
        state_reads,
        state_mutations,
        nonce,
        generation,
        dependencies,
    })
}

/// Derives the publication closure from the shared typed decoder, so source
/// artifact discovery cannot drift into a second operand parser.
pub(crate) fn required_artifacts(
    witness: &[u8],
) -> Result<(Digest32, RequiredArtifacts), PublicationRetentionError> {
    let decoded = decode_logical_witness(witness)?;
    let mut required = RequiredArtifacts::default();
    for read in &decoded.state_reads {
        if let DecodedStateObservation::Present { content_digest } = &read.observation {
            required.insert(ArtifactKind::StateValue, read.key.clone(), *content_digest)?;
        }
    }
    for read in &decoded.head_reads {
        if let DecodedObjectHeadObservation::Current {
            object_version,
            digest,
            ..
        } = &read.observation
        {
            required.insert(
                ArtifactKind::ObjectBody,
                object_body_identity(*read.object_id.as_bytes(), *object_version),
                *digest,
            )?;
        }
    }
    for mutation in &decoded.object_mutations {
        let version = match &mutation.mutation {
            DecodedObjectMutationKind::Delete => None,
            DecodedObjectMutationKind::Create { version, .. }
            | DecodedObjectMutationKind::Update { version, .. } => Some(version),
        };
        if let Some(DecodedObjectVersion {
            object_version,
            digest,
            payload: DecodedObjectPayload::BlobReference(_),
            ..
        }) = version
        {
            required.insert(
                ArtifactKind::ObjectBody,
                object_body_identity(*mutation.object_id.as_bytes(), *object_version),
                *digest,
            )?;
        }
    }
    Ok((decoded.event_digest, required))
}

fn validate_key(key: &[u8], what: &'static str) -> Result<(), PublicationRetentionError> {
    if key.is_empty() || key.len() > MAX_STATE_KEY_BYTES {
        Err(PublicationRetentionError::MalformedWitnessOperand(what))
    } else {
        Ok(())
    }
}

fn decode_created_authorities(
    bytes: &[u8],
) -> Result<Vec<CreatedObjectAuthority>, PublicationRetentionError> {
    let mut cursor = Cursor::new(bytes, "created authorities");
    let count = take_list_count(&mut cursor)?;
    let mut result = Vec::with_capacity(count);
    let mut previous: Option<u32> = None;
    for _ in 0..count {
        let item = cursor.take_length_prefixed()?;
        let mut entry = Cursor::new(item, "created authority");
        let creation_ordinal = entry.take_u32()?;
        if previous.is_some_and(|value| creation_ordinal <= value) {
            return Err(entry.malformed());
        }
        previous = Some(creation_ordinal);
        let authority = decode_object_authority(entry.take_length_prefixed()?)
            .map_err(|_| PublicationRetentionError::MalformedWitnessOperand("created authority"))?;
        entry.finish()?;
        result.push(CreatedObjectAuthority {
            creation_ordinal,
            authority,
        });
    }
    cursor.finish()?;
    Ok(result)
}

fn decode_head_reads(
    bytes: &[u8],
) -> Result<Vec<DecodedObjectHeadRead>, PublicationRetentionError> {
    let mut cursor = Cursor::new(bytes, "object head reads");
    let count = take_list_count(&mut cursor)?;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let mut entry = Cursor::new(cursor.take_length_prefixed()?, "object head read");
        let object_id = ObjectId::new(entry.take_digest_bytes()?);
        let observation = match entry.take_u8()? {
            0 => DecodedObjectHeadObservation::Absent,
            1 => DecodedObjectHeadObservation::Tombstoned {
                last_object_version: require_nonzero(entry.take_u64()?, "head object version")?,
            },
            2 => {
                let object_version = require_nonzero(entry.take_u64()?, "head object version")?;
                let digest = entry.take_digest_bytes()?;
                let owner_bytes = entry.take_optional_bytes()?.map(ToOwned::to_owned);
                let routing_bytes = entry.take_optional_bytes()?.map(ToOwned::to_owned);
                if owner_bytes
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_DURABLE_OBJECT_PROJECTION_BYTES)
                    || routing_bytes
                        .as_ref()
                        .is_some_and(|value| value.len() > MAX_DURABLE_OBJECT_PROJECTION_BYTES)
                {
                    return Err(entry.malformed());
                }
                let owner_projection =
                    DurableObjectOwnerProjection::from_canonical_bytes(owner_bytes)
                        .map_err(|_| entry.malformed())?;
                let routing_projection = DurableObjectRoutingProjection::new(routing_bytes)
                    .map_err(|_| entry.malformed())?;
                DecodedObjectHeadObservation::Current {
                    object_version,
                    digest,
                    owner_projection,
                    routing_projection,
                }
            }
            _ => {
                return Err(PublicationRetentionError::MalformedWitnessOperand(
                    "object head read",
                ));
            }
        };
        entry.finish()?;
        result.push(DecodedObjectHeadRead {
            object_id,
            observation,
        });
    }
    cursor.finish()?;
    Ok(result)
}

fn decode_object_mutations(
    bytes: &[u8],
) -> Result<Vec<DecodedObjectMutation>, PublicationRetentionError> {
    let mut cursor = Cursor::new(bytes, "object mutations");
    let count = take_list_count(&mut cursor)?;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let mut entry = Cursor::new(cursor.take_length_prefixed()?, "object mutation");
        let object_id = ObjectId::new(entry.take_digest_bytes()?);
        let mutation = match entry.take_u8()? {
            0 => DecodedObjectMutationKind::Delete,
            tag @ (1 | 2) => {
                let version = decode_version_record(entry.take_length_prefixed()?)?;
                if version.object_id != object_id {
                    return Err(entry.malformed());
                }
                let owner_bytes = entry.take_optional_bytes()?.map(ToOwned::to_owned);
                let routing_bytes = entry.take_optional_bytes()?.map(ToOwned::to_owned);
                let owner_projection =
                    DurableObjectOwnerProjection::from_canonical_bytes(owner_bytes)
                        .map_err(|_| entry.malformed())?;
                let routing_projection = DurableObjectRoutingProjection::new(routing_bytes)
                    .map_err(|_| entry.malformed())?;
                if tag == 1 {
                    DecodedObjectMutationKind::Create {
                        version,
                        owner_projection,
                        routing_projection,
                    }
                } else {
                    DecodedObjectMutationKind::Update {
                        version,
                        owner_projection,
                        routing_projection,
                    }
                }
            }
            _ => {
                return Err(PublicationRetentionError::MalformedWitnessOperand(
                    "object mutation",
                ));
            }
        };
        entry.finish()?;
        result.push(DecodedObjectMutation {
            object_id,
            mutation,
        });
    }
    cursor.finish()?;
    Ok(result)
}

fn decode_version_record(bytes: &[u8]) -> Result<DecodedObjectVersion, PublicationRetentionError> {
    let mut cursor = Cursor::new(bytes, "object version record");
    let object_id = ObjectId::new(cursor.take_digest_bytes()?);
    let object_version = require_nonzero(cursor.take_u64()?, "object version")?;
    let digest = cursor.take_digest_bytes()?;
    let schema_version = cursor.take_u32()?;
    let chain_id_bytes = cursor.take_length_prefixed()?;
    let chain_id_frame = canonical_encoding::decode_canonical_frame(chain_id_bytes)
        .map_err(|_| cursor.malformed())?;
    chain_id_frame
        .require_type(0x0105)
        .map_err(|_| cursor.malformed())?;
    chain_id_frame
        .require_version(1)
        .map_err(|_| cursor.malformed())?;
    chain_id_frame
        .require_only_fields(&[1])
        .map_err(|_| cursor.malformed())?;
    let chain_id_value = chain_id_frame
        .required_str(1)
        .map_err(|_| cursor.malformed())?;
    let chain_id = protocol_types::ChainId::new(chain_id_value).map_err(|_| cursor.malformed())?;
    if canonical_encoding::encode_chain_id(&chain_id).map_err(|_| cursor.malformed())?
        != chain_id_bytes
    {
        return Err(cursor.malformed());
    }
    let protocol_version = ProtocolVersion::new(cursor.take_u32()?);
    let payload = match cursor.take_u8()? {
        0 => {
            let bytes = cursor.take_length_prefixed()?.to_vec();
            if bytes.len() > MAX_DURABLE_INLINE_OBJECT_BYTES {
                return Err(cursor.malformed());
            }
            let object = objects::decode_object(&bytes).map_err(|_| cursor.malformed())?;
            if objects::encode_object(&object).map_err(|_| cursor.malformed())? != bytes
                || object.id != object_id
                || object.version != object_version
                || object.schema_version != schema_version
            {
                return Err(cursor.malformed());
            }
            DecodedObjectPayload::InlineCanonicalObject(bytes)
        }
        1 => {
            let blob_digest = cursor.take_digest_bytes()?;
            if blob_digest != digest {
                return Err(PublicationRetentionError::MalformedWitnessOperand(
                    "blob-backed object version digest",
                ));
            }
            DecodedObjectPayload::BlobReference(blob_digest)
        }
        _ => {
            return Err(PublicationRetentionError::MalformedWitnessOperand(
                "object version payload",
            ));
        }
    };
    cursor.finish()?;
    Ok(DecodedObjectVersion {
        object_id,
        object_version,
        digest,
        schema_version,
        chain_id,
        protocol_version,
        payload,
    })
}

fn decode_state_reads(bytes: &[u8]) -> Result<Vec<DecodedStateRead>, PublicationRetentionError> {
    let mut cursor = Cursor::new(bytes, "state reads");
    let count = take_list_count(&mut cursor)?;
    let mut result = Vec::with_capacity(count);
    let mut previous: Option<Vec<u8>> = None;
    for _ in 0..count {
        let mut entry = Cursor::new(cursor.take_length_prefixed()?, "state read");
        let key = entry.take_length_prefixed()?.to_vec();
        validate_key(&key, "state read key")?;
        if previous.as_ref().is_some_and(|value| value >= &key) {
            return Err(entry.malformed());
        }
        previous = Some(key.clone());
        let observation_bytes = entry.take_length_prefixed()?;
        let observation = decode_state_observation(observation_bytes)?;
        let generation = match entry.take_u8()? {
            0 => None,
            1 => Some(ExecutionGeneration::new(entry.take_u64()?)),
            _ => {
                return Err(PublicationRetentionError::MalformedWitnessOperand(
                    "state read generation",
                ));
            }
        };
        if matches!(observation, DecodedStateObservation::NeverWritten) != generation.is_none() {
            return Err(PublicationRetentionError::MalformedWitnessOperand(
                "state read generation/observation pairing",
            ));
        }
        entry.finish()?;
        result.push(DecodedStateRead {
            key,
            observation,
            generation,
        });
    }
    cursor.finish()?;
    Ok(result)
}

fn decode_state_observation(
    bytes: &[u8],
) -> Result<DecodedStateObservation, PublicationRetentionError> {
    if bytes == [0] {
        return Ok(DecodedStateObservation::NeverWritten);
    }
    let mut cursor = Cursor::new(bytes, "state read observation");
    let tag = cursor.take_u16()?;
    let observation = match tag {
        1 => DecodedStateObservation::Present {
            content_digest: cursor.take_digest_bytes()?,
        },
        2 => DecodedStateObservation::Deleted,
        other => return Err(PublicationRetentionError::UnsupportedReadObservation(other)),
    };
    cursor.finish()?;
    Ok(observation)
}

fn decode_state_mutations(
    bytes: &[u8],
) -> Result<Vec<DecodedStateMutation>, PublicationRetentionError> {
    let mut cursor = Cursor::new(bytes, "state mutations");
    let count = take_list_count(&mut cursor)?;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let mut entry = Cursor::new(cursor.take_length_prefixed()?, "state mutation");
        let key = entry.take_length_prefixed()?.to_vec();
        validate_key(&key, "state mutation key")?;
        let mutation = match entry.take_u8()? {
            0 => StateMutation::Assert,
            1 => {
                let value = entry.take_length_prefixed()?.to_vec();
                if value.len() > MAX_STATE_VALUE_BYTES {
                    return Err(entry.malformed());
                }
                StateMutation::Put(value)
            }
            2 => StateMutation::Delete,
            _ => {
                return Err(PublicationRetentionError::MalformedWitnessOperand(
                    "state mutation",
                ));
            }
        };
        entry.finish()?;
        result.push(DecodedStateMutation { key, mutation });
    }
    cursor.finish()?;
    Ok(result)
}

fn decode_dependencies(bytes: &[u8]) -> Result<Vec<DecodedDependency>, PublicationRetentionError> {
    let mut cursor = Cursor::new(bytes, "dependencies");
    let count = take_list_count(&mut cursor)?;
    let mut result = Vec::with_capacity(count);
    let mut previous: Option<LogicalSubject> = None;
    for _ in 0..count {
        let mut entry = Cursor::new(cursor.take_length_prefixed()?, "dependency");
        let subject = decode_subject(entry.take_length_prefixed()?)?;
        if previous
            .as_ref()
            .is_some_and(|value| value.cmp(&subject) != Ordering::Less)
        {
            return Err(entry.malformed());
        }
        previous = Some(subject.clone());
        let generation = ExecutionGeneration::new(entry.take_u64()?);
        entry.finish()?;
        result.push(DecodedDependency {
            subject,
            generation,
        });
    }
    cursor.finish()?;
    Ok(result)
}

fn decode_subject(bytes: &[u8]) -> Result<LogicalSubject, PublicationRetentionError> {
    let mut cursor = Cursor::new(bytes, "dependency subject");
    let subject = match cursor.take_u8()? {
        1 => {
            let key = cursor.take_length_prefixed()?.to_vec();
            validate_key(&key, "dependency state key")?;
            LogicalSubject::StateKey(key)
        }
        2 => LogicalSubject::Object(ObjectId::new(cursor.take_digest_bytes()?)),
        3 => {
            let sender = cursor.take_digest_bytes()?;
            let epoch = Epoch::new(cursor.take_u64()?);
            LogicalSubject::SenderNonce { sender, epoch }
        }
        _ => return Err(cursor.malformed()),
    };
    cursor.finish()?;
    Ok(subject)
}

fn require_nonzero(value: u64, what: &'static str) -> Result<u64, PublicationRetentionError> {
    if value == 0 {
        Err(PublicationRetentionError::MalformedWitnessOperand(what))
    } else {
        Ok(value)
    }
}

/// The stable manifest identity of one immutable object body: its 32-byte
/// object id followed by the big-endian logical object version.
pub(crate) fn object_body_identity(object_id: [u8; 32], object_version: u64) -> Vec<u8> {
    let mut identity: Vec<u8> = object_id.to_vec();
    identity.extend_from_slice(&object_version.to_be_bytes());
    identity
}

#[cfg(test)]
mod tests;
