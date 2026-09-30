//! `PortableCandidateManifest` (frame `0x6493`): the externally pinned root a
//! [`super::verifier::PortableCandidateVerifier`] checks an incremental
//! transfer against. It is not itself authority to import, serve or activate
//! anything -- see `docs/architecture/decisions/0166-portable-candidate-snapshot.md`.
use super::*;

const PORTABLE_CANDIDATE_MANIFEST_TYPE: u16 = 0x6493;
const ENCODING_VERSION: u16 = 1;
pub const MAX_ENCODED_PORTABLE_CANDIDATE_MANIFEST_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableCandidateManifest {
    pub identity: PortableCandidateIdentity,
    /// Exact emitted row count per [`PORTABLE_CANDIDATE_COLLECTION_ORDER`]
    /// position; index `i` is that position's collection.
    pub row_counts: [u64; 4],
    /// The hash-step accumulator (frame `0x6495`) after the very last item.
    pub final_hash_step: Digest32,
}

impl PortableCandidateManifest {
    #[must_use]
    pub fn row_count(&self, collection: DurableCollection) -> u64 {
        let index: usize = usize::from(collection_tag(collection) - 1);
        self.row_counts[index]
    }
}

pub fn encode_portable_candidate_manifest(
    manifest: &PortableCandidateManifest,
) -> Result<Vec<u8>, PortableCandidateError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(PORTABLE_CANDIDATE_MANIFEST_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_portable_candidate_identity(&manifest.identity)?)?;
    for (offset, count) in manifest.row_counts.iter().enumerate() {
        let field_id: u16 = u16::try_from(offset)
            .map_err(|_| PortableCandidateError::Invalid("manifest row count field id"))?
            + 2;
        frame.field_u64(field_id, *count)?;
    }
    frame.field_bytes(
        6,
        canonical_encoding::encode_digest32(&manifest.final_hash_step)?,
    )?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_ENCODED_PORTABLE_CANDIDATE_MANIFEST_BYTES {
        return Err(PortableCandidateError::Invalid(
            "candidate manifest frame too large",
        ));
    }
    Ok(bytes)
}

pub fn decode_portable_candidate_manifest(
    input: &[u8],
) -> Result<PortableCandidateManifest, PortableCandidateError> {
    if input.len() > MAX_ENCODED_PORTABLE_CANDIDATE_MANIFEST_BYTES {
        return Err(PortableCandidateError::Invalid(
            "candidate manifest frame too large",
        ));
    }
    let frame = decode_canonical_frame(input)?;
    frame.require_type(PORTABLE_CANDIDATE_MANIFEST_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;
    let identity: PortableCandidateIdentity =
        decode_portable_candidate_identity(frame.required_field(1)?)?;
    let mut row_counts: [u64; 4] = [0; 4];
    for (offset, slot) in row_counts.iter_mut().enumerate() {
        let field_id: u16 = u16::try_from(offset)
            .map_err(|_| PortableCandidateError::Invalid("manifest row count field id"))?
            + 2;
        *slot = frame.required_u64(field_id)?;
    }
    let final_hash_step: Digest32 = canonical_encoding::decode_digest32(frame.required_field(6)?)?;
    let manifest = PortableCandidateManifest {
        identity,
        row_counts,
        final_hash_step,
    };
    if encode_portable_candidate_manifest(&manifest)? != input {
        return Err(PortableCandidateError::Invalid(
            "noncanonical portable candidate manifest",
        ));
    }
    Ok(manifest)
}
