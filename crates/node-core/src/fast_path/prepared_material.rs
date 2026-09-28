//! DR-0154 handoff-capable prepare-side retention (`epoch-handoff.md`,
//! "Execution-free publication").
//!
//! For a handoff-capable (`0x6424/v2`) admission, [`super::prepare`] must
//! durably retain the exact logical commitment witness it is about to vote
//! on, and every content-addressed replay artifact that witness's signed
//! read/object/mutation operands require, **before** it exposes a
//! [`consensus::FastVote`] -- not merely a digest. [`retain_prepared_material`]
//! is that step, called from [`super::prepare`] after the witness envelope is
//! computed and before any object/nonce lock is staged or the vote is cast.
//!
//! # Why this is a separate atomic commit, at a separate key family
//!
//! It commits independently of [`super::prepare`]'s own lock/nonce/prepared-
//! record commit, and strictly *before* it (never after): a crash between the
//! two leaves at most a harmless orphaned witness/artifact row (deterministic
//! from admission and safely rewritten byte-identical by a retry), never a
//! cast vote whose backing material was not actually retained. It also keeps
//! this closure's own bound
//! ([`super::publication::MAX_RETAINED_ARTIFACTS`]) from competing with
//! admission's own staged-mutation budget inside one transaction.
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
/// two different requests (or two different identities within one witness)
/// shares one storage row.
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
    let object_id: ObjectId = ObjectId::new(bytes[..32].try_into().expect("32-byte slice"));
    let version: u64 = u64::from_be_bytes(bytes[32..40].try_into().expect("8-byte slice"));
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
/// staged, fetches and re-verifies every artifact's actual bytes, and
/// durably retains the witness and every artifact in one atomic commit.
///
/// Called from [`super::prepare`] strictly before any object/nonce lock is
/// staged and before the [`consensus::FastVote`] is cast: this is the
/// "before exposing a `FastVote`" ordering `epoch-handoff.md` requires.
#[allow(clippy::too_many_arguments)]
pub(crate) fn retain_prepared_material<S: StructuredDurableDomainStateStore>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    request_id: &[u8; 32],
    epoch: Epoch,
    witness_bytes: &[u8],
) -> FastPathResult<()> {
    let (_event_digest, required) =
        required_artifacts(witness_bytes).map_err(FastPathError::Publication)?;
    if required.len() > MAX_RETAINED_ARTIFACTS {
        return Err(FastPathError::Publication(
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
        let kind: ArtifactKind = ArtifactKind::from_u16(*kind_tag).map_err(|error| {
            FastPathError::Publication(PublicationRetentionError::Bundle(error))
        })?;
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

    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let mut mutations: Vec<StateMutationEntry> = Vec::new();
    for (key, content) in staged {
        let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
        reads.insert(key.clone(), observed.revision());
        mutations.push(StateMutationEntry::new(key, StateMutation::Put(content))?);
    }
    let witness_key: Vec<u8> = fastpath_prepared_witness_key(chain, request_id)?;
    let observed_witness: VersionedStateValue =
        store.get_versioned_durable(context, domain, &witness_key)?;
    reads.insert(witness_key.clone(), observed_witness.revision());
    mutations.push(StateMutationEntry::new(
        witness_key,
        StateMutation::Put(witness_bytes.to_vec()),
    )?);

    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<_, RuntimeError>>()?;
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(assertions)?,
        AtomicStateMutationSet::new(mutations)?,
    )?;
    match store.commit_durable(context, transaction) {
        DurableCommitOutcome::Committed => Ok(()),
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::Conflict { .. }
            | DurableCommitRejection::RequestAlreadyCommitted,
        ) => Err(NodeCoreError::StateConflict.into()),
        DurableCommitOutcome::Rejected(reason) => {
            Err(NodeCoreError::DurableCommitRejected(reason).into())
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            Err(NodeCoreError::DurableCommitIndeterminate(reason).into())
        }
    }
}

#[cfg(test)]
mod tests;
