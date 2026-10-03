//! DR-0154 handoff-capable prepare-side retention (`epoch-handoff.md`,
//! "Execution-free publication").
//!
//! For a handoff-capable (`0x6424/v2`) admission, [`super::prepare`] must
//! durably retain the exact logical commitment witness it is about to vote
//! on, and every content-addressed replay artifact that witness's signed
//! read/object/mutation operands require, **before** it exposes a
//! [`consensus::FastVote`] -- not merely a digest. [`stage_prepared_material`]
//! verifies and stages that material in the same invocation transaction as
//! the prepared record and every object/nonce lock. No separate commit may
//! overwrite the witness backing a concurrently committed vote, and a failed
//! prepare exposes no partially retained material. The complete transaction
//! must fit the existing store bounds before signing.
//!
//! It writes under its own `fastpath/prepared-witness/` and
//! `fastpath/prepared-artifact/` key families, deliberately distinct from
//! [`super::local_instance_state::fastpath_commitment_witness_key`] (written
//! only by a successful [`super::apply`]) and from
//! [`super::publication::fastpath_publication_artifact_key`] (written only by
//! a successful [`super::publication::retain_publication`]): this row records
//! what *this replica's own prepare* verified and retained locally, before
//! any certificate exists, not a cross-validator-verified publication and not
//! an applied commitment witness.
//!
//! # What is retained, and how it is verified
//!
//! One [`ArtifactKind::StateValue`] entry per signed present generic state
//! read, and one [`ArtifactKind::ObjectBody`] entry per signed current object
//! head read or blob-backed staged object mutation -- exactly the closure
//! [`super::publication::witness::required_artifacts`] derives from the
//! witness's own signed operands, the identical decoder
//! [`super::publication::retain_publication`] uses to check a quorum-verified
//! bundle's manifest. Each artifact's actual bytes are read fresh from
//! `store`/`blob_store` (the same durable material admission itself just
//! observed under the still-held locks) and independently re-hashed under
//! `kind.hash_purpose()`; a mismatch against the witness-signed digest is a
//! refusal, never a silent substitution.
use super::publication::witness::required_artifacts;
use super::publication::{MAX_RETAINED_ARTIFACTS, PublicationRetentionError};
use super::*;
use consensus::bundle::ArtifactKind;
use runtime::VersionedStateReader;
use std::collections::BTreeMap;

/// One durably retained prepare-side commitment witness, keyed by the
/// original signed request id. Present only for a handoff-capable
/// (`0x6424/v2`) prepare.
pub(crate) fn fastpath_prepared_witness_key(
    chain: &ChainId,
    request_id: &[u8; 32],
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = local_instance_state::FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"prepared-witness/");
    key.extend(canonical_encoding::encode_chain_id(chain)?);
    key.extend_from_slice(request_id);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// One durably retained prepare-side replay artifact, content-addressed by
/// its kind and verified content digest so an identical artifact required by
/// different identities within one witness shares one storage row within
/// that request.
pub(crate) fn fastpath_prepared_artifact_key(
    chain: &ChainId,
    request_id: &[u8; 32],
    kind: ArtifactKind,
    content_digest: &[u8; 32],
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = local_instance_state::FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"prepared-artifact/");
    key.extend(canonical_encoding::encode_chain_id(chain)?);
    key.extend_from_slice(request_id);
    key.extend_from_slice(&kind.as_u16().to_be_bytes());
    key.extend_from_slice(content_digest);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

fn decode_object_body_identity(
    identity: &[u8],
) -> FastPathResult<(ObjectId, DurableObjectVersion)> {
    let bytes: [u8; 40] = identity
        .try_into()
        .map_err(|_| FastPathError::Invalid("fast-path object artifact identity length"))?;
    let object_bytes: [u8; 32] = bytes[..32]
        .try_into()
        .map_err(|_| FastPathError::Invalid("fast-path object artifact id length"))?;
    let version_bytes: [u8; 8] = bytes[32..40]
        .try_into()
        .map_err(|_| FastPathError::Invalid("fast-path object artifact version length"))?;
    let object_id: ObjectId = ObjectId::new(object_bytes);
    let version: u64 = u64::from_be_bytes(version_bytes);
    let version: DurableObjectVersion = DurableObjectVersion::new(version)
        .ok_or(FastPathError::Invalid("fast-path object artifact version"))?;
    Ok((object_id, version))
}

/// Reads one required artifact's actual current bytes from durable storage,
/// never from the witness itself (which carries only its digest).
fn fetch_artifact_content<S: StructuredDurableDomainStateStore>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    kind: ArtifactKind,
    identity: &[u8],
) -> FastPathResult<Vec<u8>> {
    match kind {
        ArtifactKind::StateValue => {
            let observed: VersionedStateValue =
                store.get_versioned_durable(context, domain, identity)?;
            observed
                .value()
                .map(<[u8]>::to_vec)
                .ok_or(FastPathError::Invalid(
                    "fast-path prepare required state artifact is absent",
                ))
        }
        ArtifactKind::ObjectBody => {
            let (object_id, version): (ObjectId, DurableObjectVersion) =
                decode_object_body_identity(identity)?;
            let record: DurableObjectVersionRecord = store
                .get_object_version(context, domain, object_id, version)?
                .ok_or(FastPathError::Invalid(
                    "fast-path prepare required object artifact is absent",
                ))?;
            match record.payload() {
                DurableObjectPayload::Inline(inline) => Ok(inline.canonical_bytes().to_vec()),
                DurableObjectPayload::BlobReference(blob_digest) => blob_store
                    .get_blob(blob_digest)
                    .map_err(NodeCoreError::Runtime)?
                    .ok_or(FastPathError::Invalid(
                        "fast-path prepare required object blob is absent",
                    )),
            }
        }
    }
}

/// Derives the required replay-artifact closure from `witness_bytes` (the
/// exact `0x6424/v2` envelope [`super::prepare`] is about to vote on),
/// refuses a closure over [`MAX_RETAINED_ARTIFACTS`] before anything is
/// staged, fetches and re-verifies every artifact's actual bytes, and stages
/// the witness and every artifact with destination revision assertions.
///
/// Existing destination bytes must match exactly. The caller commits these
/// rows only with the prepared record and locks, never independently.
#[allow(clippy::too_many_arguments)]
pub(crate) fn stage_prepared_material<S: StructuredDurableDomainStateStore>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    request_id: &[u8; 32],
    epoch: Epoch,
    witness_bytes: &[u8],
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    mutations: &mut Vec<StateMutationEntry>,
) -> FastPathResult<()> {
    let (_event_digest, required): (Digest32, publication::RequiredArtifacts) =
        required_artifacts(witness_bytes).map_err(FastPathError::from)?;
    if required.len() > MAX_RETAINED_ARTIFACTS {
        return Err(FastPathError::from(
            PublicationRetentionError::ClosureTooLarge {
                actual: required.len(),
                max: MAX_RETAINED_ARTIFACTS,
            },
        ));
    }

    // Content-addressed by storage key first: two required entries that
    // happen to share `(kind, content_digest)` (from different identities)
    // are staged once, mirroring `publication::stage_publication_artifacts`.
    let mut staged: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for ((kind_tag, identity), digest) in required.iter() {
        let kind: ArtifactKind = ArtifactKind::from_u16(*kind_tag)
            .map_err(|error| FastPathError::from(PublicationRetentionError::Bundle(error)))?;
        let content: Vec<u8> =
            fetch_artifact_content(store, blob_store, context, domain, kind, identity)?;
        let content_digest: Digest32 =
            resolver.hash_for_purpose(epoch, kind.hash_purpose(), &content)?;
        if content_digest.bytes() != *digest {
            return invalid(
                "fast-path prepare artifact content does not match the signed witness digest",
            );
        }
        let key: Vec<u8> = fastpath_prepared_artifact_key(chain, request_id, kind, digest)?;
        staged.insert(key, content);
    }

    let witness_key: Vec<u8> = fastpath_prepared_witness_key(chain, request_id)?;
    staged.insert(witness_key, witness_bytes.to_vec());
    for (key, content) in staged {
        let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
        if observed
            .value()
            .is_some_and(|existing: &[u8]| existing != content)
        {
            return invalid("fast-path retained prepare material mismatch");
        }
        if reads
            .insert(key.clone(), observed.revision())
            .is_some_and(|revision: StateRevision| revision != observed.revision())
        {
            return Err(NodeCoreError::StateConflict.into());
        }
        if observed.value().is_none() {
            mutations.push(StateMutationEntry::new(key, StateMutation::Put(content))?);
        }
    }
    Ok(())
}

/// Re-verifies the complete retained closure before replay exposes a Logical
/// vote. A missing or corrupt row fails closed; replay never repairs it from
/// current state, which may already have advanced since prepare.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_prepared_material<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    prepared: &FastPathPreparedRecord,
) -> FastPathResult<()> {
    let witness_key: Vec<u8> =
        fastpath_prepared_witness_key(prepared.context.chain_id(), &prepared.request_id)?;
    let witness: VersionedStateValue = store.read_versioned_state(context, domain, &witness_key)?;
    let witness_bytes: &[u8] = witness.value().ok_or(FastPathError::Invalid(
        "fast-path retained prepare witness is absent",
    ))?;
    if commitment::hash_witness_bytes(resolver, prepared.context.epoch(), witness_bytes)?
        != prepared.commitment
    {
        return invalid("fast-path retained prepare witness commitment mismatch");
    }
    let (event_digest, required): (Digest32, publication::RequiredArtifacts) =
        required_artifacts(witness_bytes)?;
    if event_digest != prepared.signed_intent_digest {
        return invalid("fast-path retained prepare witness intent mismatch");
    }
    if required.len() > MAX_RETAINED_ARTIFACTS {
        return Err(PublicationRetentionError::ClosureTooLarge {
            actual: required.len(),
            max: MAX_RETAINED_ARTIFACTS,
        }
        .into());
    }
    for ((kind_tag, _identity), digest) in required.iter() {
        let kind: ArtifactKind =
            ArtifactKind::from_u16(*kind_tag).map_err(PublicationRetentionError::Bundle)?;
        let key: Vec<u8> = fastpath_prepared_artifact_key(
            prepared.context.chain_id(),
            &prepared.request_id,
            kind,
            digest,
        )?;
        let observed: VersionedStateValue = store.read_versioned_state(context, domain, &key)?;
        let content: &[u8] = observed.value().ok_or(FastPathError::Invalid(
            "fast-path retained prepare artifact is absent",
        ))?;
        let matches: bool = std::iter::once(resolver).chain(history).any(|candidate| {
            candidate
                .hash_for_purpose(prepared.context.epoch(), kind.hash_purpose(), content)
                .is_ok_and(|computed: Digest32| computed.bytes() == *digest)
        });
        if !matches {
            return invalid("fast-path retained prepare artifact digest mismatch");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
