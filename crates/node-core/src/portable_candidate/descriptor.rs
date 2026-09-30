//! `PortableCandidateDescriptor` (frame `0x6491`): a body-free semantic
//! projection of one [`DurableRecordDescriptor`]. It drops every physical
//! storage fact (`StateRevision`, `ObjectHeadRevision`, `created_checkpoint`)
//! while preserving every semantic fact a later import must see: presence
//! versus deletion, schema version, provenance, digests, owner/routing
//! projections and blob references. A blob reference alone is never blob
//! content: see `runtime::portable::PortableBlobRepository`.
use super::*;
use protocol_types::TypeError;

const PORTABLE_CANDIDATE_DESCRIPTOR_TYPE: u16 = 0x6491;
const ENCODING_VERSION: u16 = 1;
pub const MAX_ENCODED_PORTABLE_CANDIDATE_DESCRIPTOR_BYTES: usize = 16 * 1024;

/// Revision-free projection of [`DurableObjectHead`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableObjectHeadProjection {
    Tombstoned {
        last_object_version: DurableObjectVersion,
    },
    Current {
        object_version: DurableObjectVersion,
        digest: Digest32,
        owner_projection: Option<Vec<u8>>,
        routing_projection: Option<Vec<u8>>,
    },
}

/// Inline versus content-addressed payload, without the inline length (the
/// row transfer's own chunk stream carries that).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableCandidatePayloadKind {
    Inline,
    BlobReference(Digest32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableCandidateDescriptor {
    /// `deleted` distinguishes a tombstone (revision advanced, no value) from
    /// a present row; a present, empty value is `deleted: false` with a
    /// zero-length terminal chunk in the row transfer.
    State {
        deleted: bool,
    },
    Receipt {
        event_digest: Digest32,
    },
    ObjectHead(PortableObjectHeadProjection),
    ObjectVersion {
        digest: Digest32,
        schema_version: u32,
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        payload: PortableCandidatePayloadKind,
    },
}

/// Pure projection: no storage I/O, no re-derivation of physical facts.
pub fn project_portable_candidate_descriptor(
    descriptor: &DurableRecordDescriptor,
) -> Result<PortableCandidateDescriptor, PortableCandidateError> {
    Ok(match descriptor.metadata() {
        DurableRecordMetadata::State { value_length, .. } => PortableCandidateDescriptor::State {
            deleted: value_length.is_none(),
        },
        DurableRecordMetadata::Receipt { event_digest, .. } => {
            PortableCandidateDescriptor::Receipt {
                event_digest: *event_digest,
            }
        }
        DurableRecordMetadata::ObjectHead(head) => {
            PortableCandidateDescriptor::ObjectHead(match head {
                DurableObjectHead::Tombstoned {
                    last_object_version,
                    ..
                } => PortableObjectHeadProjection::Tombstoned {
                    last_object_version: *last_object_version,
                },
                DurableObjectHead::Current {
                    object_version,
                    digest,
                    owner_projection,
                    routing_projection,
                    ..
                } => PortableObjectHeadProjection::Current {
                    object_version: *object_version,
                    digest: *digest,
                    owner_projection: owner_projection.bytes().map(<[u8]>::to_vec),
                    routing_projection: routing_projection.bytes().map(<[u8]>::to_vec),
                },
                DurableObjectHead::Absent => {
                    return Err(PortableCandidateError::Invalid(
                        "absent object head has no portable candidate descriptor",
                    ));
                }
            })
        }
        DurableRecordMetadata::ObjectVersion {
            digest,
            schema_version,
            provenance,
            payload,
            ..
        } => PortableCandidateDescriptor::ObjectVersion {
            digest: *digest,
            schema_version: *schema_version,
            chain_id: provenance.chain_id().clone(),
            protocol_version: provenance.protocol_version(),
            payload: match payload {
                DurablePayloadDescriptor::Inline(_) => PortableCandidatePayloadKind::Inline,
                DurablePayloadDescriptor::BlobReference(digest) => {
                    PortableCandidatePayloadKind::BlobReference(*digest)
                }
            },
        },
    })
}

pub fn encode_portable_candidate_descriptor(
    descriptor: &PortableCandidateDescriptor,
) -> Result<Vec<u8>, PortableCandidateError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(PORTABLE_CANDIDATE_DESCRIPTOR_TYPE, ENCODING_VERSION);
    match descriptor {
        PortableCandidateDescriptor::State { deleted } => {
            frame.field_u16(1, 1)?;
            frame.field_u16(2, u16::from(*deleted))?;
        }
        PortableCandidateDescriptor::Receipt { event_digest } => {
            frame.field_u16(1, 2)?;
            frame.field_bytes(3, canonical_encoding::encode_digest32(event_digest)?)?;
        }
        PortableCandidateDescriptor::ObjectHead(projection) => {
            frame.field_u16(1, 3)?;
            match projection {
                PortableObjectHeadProjection::Tombstoned {
                    last_object_version,
                } => {
                    frame.field_u16(4, 0)?;
                    frame.field_u64(11, last_object_version.get())?;
                }
                PortableObjectHeadProjection::Current {
                    object_version,
                    digest,
                    owner_projection,
                    routing_projection,
                } => {
                    if owner_projection.as_ref().is_some_and(|bytes| {
                        bytes.len() > MAX_ENCODED_PORTABLE_CANDIDATE_DESCRIPTOR_BYTES
                    }) || routing_projection.as_ref().is_some_and(|bytes| {
                        bytes.len() > MAX_ENCODED_PORTABLE_CANDIDATE_DESCRIPTOR_BYTES
                    }) {
                        return Err(PortableCandidateError::Invalid("oversized head projection"));
                    }
                    frame.field_u16(4, 1)?;
                    frame.field_u64(11, object_version.get())?;
                    frame.field_bytes(12, canonical_encoding::encode_digest32(digest)?)?;
                    if let Some(bytes) = owner_projection {
                        frame.field_bytes(13, bytes.clone())?;
                    }
                    if let Some(bytes) = routing_projection {
                        frame.field_bytes(14, bytes.clone())?;
                    }
                }
            }
        }
        PortableCandidateDescriptor::ObjectVersion {
            digest,
            schema_version,
            chain_id,
            protocol_version,
            payload,
        } => {
            if chain_id.as_str().len() > runtime::portable::MAX_PORTABLE_CHAIN_ID_BYTES {
                return Err(PortableCandidateError::Invalid(
                    "object version chain id too long",
                ));
            }
            frame.field_u16(1, 4)?;
            frame.field_bytes(5, canonical_encoding::encode_digest32(digest)?)?;
            frame.field_u32(6, *schema_version)?;
            frame.field_str(7, chain_id.as_str())?;
            frame.field_u32(8, protocol_version.get())?;
            match payload {
                PortableCandidatePayloadKind::Inline => {
                    frame.field_u16(9, 0)?;
                }
                PortableCandidatePayloadKind::BlobReference(digest) => {
                    frame.field_u16(9, 1)?;
                    frame.field_bytes(10, canonical_encoding::encode_digest32(digest)?)?;
                }
            }
        }
    }
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_ENCODED_PORTABLE_CANDIDATE_DESCRIPTOR_BYTES {
        return Err(PortableCandidateError::Invalid(
            "candidate descriptor frame too large",
        ));
    }
    Ok(bytes)
}

pub fn decode_portable_candidate_descriptor(
    input: &[u8],
) -> Result<PortableCandidateDescriptor, PortableCandidateError> {
    if input.len() > MAX_ENCODED_PORTABLE_CANDIDATE_DESCRIPTOR_BYTES {
        return Err(PortableCandidateError::Invalid(
            "candidate descriptor frame too large",
        ));
    }
    let frame = decode_canonical_frame(input)?;
    frame.require_type(PORTABLE_CANDIDATE_DESCRIPTOR_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let kind: u16 = frame.required_u16(1)?;
    let descriptor: PortableCandidateDescriptor = match kind {
        1 => {
            frame.require_only_fields(&[1, 2])?;
            PortableCandidateDescriptor::State {
                deleted: frame.required_u16(2)? != 0,
            }
        }
        2 => {
            frame.require_only_fields(&[1, 3])?;
            PortableCandidateDescriptor::Receipt {
                event_digest: canonical_encoding::decode_digest32(frame.required_field(3)?)?,
            }
        }
        3 => {
            let version: DurableObjectVersion = DurableObjectVersion::new(frame.required_u64(11)?)
                .ok_or(PortableCandidateError::Invalid("zero object head version"))?;
            let projection: PortableObjectHeadProjection = match frame.required_u16(4)? {
                0 => {
                    frame.require_only_fields(&[1, 4, 11])?;
                    PortableObjectHeadProjection::Tombstoned {
                        last_object_version: version,
                    }
                }
                1 => {
                    frame.require_only_fields(&[1, 4, 11, 12, 13, 14])?;
                    PortableObjectHeadProjection::Current {
                        object_version: version,
                        digest: canonical_encoding::decode_digest32(frame.required_field(12)?)?,
                        owner_projection: frame.field(13).map(<[u8]>::to_vec),
                        routing_projection: frame.field(14).map(<[u8]>::to_vec),
                    }
                }
                _ => {
                    return Err(PortableCandidateError::Invalid(
                        "unknown object head status",
                    ));
                }
            };
            PortableCandidateDescriptor::ObjectHead(projection)
        }
        4 => {
            frame.require_only_fields(&[1, 5, 6, 7, 8, 9, 10])?;
            let chain_id: ChainId = ChainId::new(frame.required_str(7)?)
                .map_err(|_: TypeError| PortableCandidateError::Invalid("invalid chain id"))?;
            if chain_id.as_str().len() > runtime::portable::MAX_PORTABLE_CHAIN_ID_BYTES {
                return Err(PortableCandidateError::Invalid(
                    "object version chain id too long",
                ));
            }
            let payload: PortableCandidatePayloadKind = match frame.required_u16(9)? {
                0 => PortableCandidatePayloadKind::Inline,
                1 => PortableCandidatePayloadKind::BlobReference(
                    canonical_encoding::decode_digest32(frame.required_field(10)?)?,
                ),
                _ => {
                    return Err(PortableCandidateError::Invalid(
                        "unknown object version payload kind",
                    ));
                }
            };
            PortableCandidateDescriptor::ObjectVersion {
                digest: canonical_encoding::decode_digest32(frame.required_field(5)?)?,
                schema_version: frame.required_u32(6)?,
                chain_id,
                protocol_version: ProtocolVersion::new(frame.required_u32(8)?),
                payload,
            }
        }
        _ => {
            return Err(PortableCandidateError::Invalid(
                "unknown candidate descriptor kind",
            ));
        }
    };
    if encode_portable_candidate_descriptor(&descriptor)? != input {
        return Err(PortableCandidateError::Invalid(
            "noncanonical portable candidate descriptor",
        ));
    }
    Ok(descriptor)
}
