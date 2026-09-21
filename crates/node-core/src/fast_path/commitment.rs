//! DR-0130 fast-path staged-commit commitment.
//!
//! The commitment a [`consensus::FastVote`]/[`consensus::FastCertificate`]
//! binds to (their `execution_effects_hash`) must cover the *entire* staged
//! commit a successful apply will later durably write, not only
//! [`execution::ExecutionEffects`]: the signed intent digest, the canonical
//! paid result, every created object authority, every durable object head
//! assertion and mutation, every application state read assertion and
//! mutation, and the exact pending sender-nonce CAS/write. Only fast-path
//! bookkeeping (lock reads/writes and prepare's own synthetic receipt) is
//! excluded.
//!
//! [`compute`] hashes this deterministically from the same
//! [`crate::paid_execution::PaidAdmissionOutput`] both `prepare` and `apply`
//! independently derive by calling
//! [`crate::paid_execution::build_paid_admission`]; it never decodes back,
//! so it uses a simple length-prefixed byte framing rather than a
//! [`canonical_encoding::CanonicalStruct`] nested-list dance, while staying
//! fully deterministic, unambiguous (every variable-length field is
//! length-prefixed) and strictly bounded.
use super::*;

const COMMITMENT_ENVELOPE_TYPE: u16 = 0x6424;
const ENCODING_VERSION: u16 = 1;

/// Bounds the number of items folded into any one length-prefixed list
/// below; matches the ceilings admission itself already enforces
/// (`MAX_EXECUTION_SCOPES`-derived object/authority counts, and the runtime
/// crate's own `MAX_DURABLE_OBJECT_READS`/`MAX_DURABLE_OBJECT_MUTATIONS`/
/// `MAX_ATOMIC_STATE_READS`/`MAX_ATOMIC_STATE_WRITES`), so a request that
/// already admitted successfully can never overflow this bound.
const MAX_COMMITMENT_LIST_ITEMS: usize = 4096;

fn push_length_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_optional_bytes(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        None => out.push(0),
        Some(bytes) => {
            out.push(1);
            push_length_prefixed(out, bytes);
        }
    }
}

fn encode_list<T>(
    items: &[T],
    encode_item: impl Fn(&T) -> Result<Vec<u8>, NodeCoreError>,
) -> Result<Vec<u8>, NodeCoreError> {
    if items.len() > MAX_COMMITMENT_LIST_ITEMS {
        return Err(NodeCoreError::PersistenceInvariant(
            "fast-path commitment list too large",
        ));
    }
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for item in items {
        push_length_prefixed(&mut out, &encode_item(item)?);
    }
    Ok(out)
}

fn encode_created_authority(item: &CreatedObjectAuthority) -> Result<Vec<u8>, NodeCoreError> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&item.creation_ordinal.to_be_bytes());
    push_length_prefixed(
        &mut out,
        &execution::local_execution::encode_object_authority(&item.authority)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid created authority"))?,
    );
    Ok(out)
}

fn encode_durable_object_version_record(
    version: &DurableObjectVersionRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(version.object_id().as_bytes());
    out.extend_from_slice(&version.object_version().get().to_be_bytes());
    out.extend_from_slice(&version.digest().bytes());
    out.extend_from_slice(&version.schema_version().to_be_bytes());
    push_length_prefixed(
        &mut out,
        &canonical_encoding::encode_chain_id(version.provenance().chain_id())
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid object version chain id"))?,
    );
    out.extend_from_slice(&version.provenance().protocol_version().get().to_be_bytes());
    out.extend_from_slice(&version.created_checkpoint().to_be_bytes());
    match version.payload() {
        DurableObjectPayload::Inline(inline) => {
            out.push(0);
            push_length_prefixed(&mut out, inline.canonical_bytes());
        }
        DurableObjectPayload::BlobReference(digest) => {
            out.push(1);
            out.extend_from_slice(&digest.bytes());
        }
    }
    Ok(out)
}

fn encode_durable_object_head(head: &DurableObjectHead) -> Vec<u8> {
    match head {
        DurableObjectHead::Absent => vec![0u8],
        DurableObjectHead::Tombstoned {
            head_revision,
            last_object_version,
        } => {
            let mut out: Vec<u8> = vec![1u8];
            out.extend_from_slice(&head_revision.get().to_be_bytes());
            out.extend_from_slice(&last_object_version.get().to_be_bytes());
            out
        }
        DurableObjectHead::Current {
            head_revision,
            object_version,
            digest,
            owner_projection,
            routing_projection,
        } => {
            let mut out: Vec<u8> = vec![2u8];
            out.extend_from_slice(&head_revision.get().to_be_bytes());
            out.extend_from_slice(&object_version.get().to_be_bytes());
            out.extend_from_slice(&digest.bytes());
            push_optional_bytes(&mut out, owner_projection.bytes());
            push_optional_bytes(&mut out, routing_projection.bytes());
            out
        }
    }
}

fn encode_head_read(item: &DurableObjectHeadRead) -> Result<Vec<u8>, NodeCoreError> {
    let mut out: Vec<u8> = item.object_id().as_bytes().to_vec();
    out.extend_from_slice(&encode_durable_object_head(item.expected()));
    Ok(out)
}

fn encode_object_mutation(item: &DurableObjectMutationEntry) -> Result<Vec<u8>, NodeCoreError> {
    let mut out: Vec<u8> = item.object_id().as_bytes().to_vec();
    match item.mutation() {
        DurableObjectMutation::Delete => out.push(0),
        DurableObjectMutation::Create {
            version,
            owner_projection,
            routing_projection,
        } => {
            out.push(1);
            push_length_prefixed(&mut out, &encode_durable_object_version_record(version)?);
            push_optional_bytes(&mut out, owner_projection.bytes());
            push_optional_bytes(&mut out, routing_projection.bytes());
        }
        DurableObjectMutation::Update {
            version,
            owner_projection,
            routing_projection,
        } => {
            out.push(2);
            push_length_prefixed(&mut out, &encode_durable_object_version_record(version)?);
            push_optional_bytes(&mut out, owner_projection.bytes());
            push_optional_bytes(&mut out, routing_projection.bytes());
        }
    }
    Ok(out)
}

/// True for a state key that is fast-path bookkeeping excluded from the
/// commitment. The ordinary sender-nonce row is intentionally carried by
/// the three explicit nonce arguments instead of the generic read/mutation
/// maps.
fn is_excluded_from_commitment(key: &[u8]) -> bool {
    key.starts_with(local_instance_state::FASTPATH_STATE_PREFIX)
}

fn encode_state_read(key: &[u8], revision: StateRevision) -> Result<Vec<u8>, NodeCoreError> {
    let mut out: Vec<u8> = Vec::new();
    push_length_prefixed(&mut out, key);
    out.extend_from_slice(&revision.get().to_be_bytes());
    Ok(out)
}

fn encode_state_mutation(item: &StateMutationEntry) -> Result<Vec<u8>, NodeCoreError> {
    let mut out: Vec<u8> = Vec::new();
    push_length_prefixed(&mut out, item.key());
    match item.mutation() {
        StateMutation::Assert => out.push(0),
        StateMutation::Put(value) => {
            out.push(1);
            push_length_prefixed(&mut out, value);
        }
        StateMutation::Delete => out.push(2),
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn encode_envelope(
    event_digest: Digest32,
    result_bytes: &[u8],
    created_authorities: &[CreatedObjectAuthority],
    head_reads: &[DurableObjectHeadRead],
    object_mutations: &[DurableObjectMutationEntry],
    reads: &BTreeMap<Vec<u8>, StateRevision>,
    state_mutations: &[StateMutationEntry],
    nonce_key: &[u8],
    nonce_revision: StateRevision,
    nonce_value: &[u8],
) -> Result<Vec<u8>, NodeCoreError> {
    let filtered_reads: Vec<(&Vec<u8>, &StateRevision)> = reads
        .iter()
        .filter(|(key, _)| !is_excluded_from_commitment(key))
        .collect();
    let filtered_mutations: Vec<&StateMutationEntry> = state_mutations
        .iter()
        .filter(|entry| !is_excluded_from_commitment(entry.key()))
        .collect();

    let mut envelope: CanonicalStruct =
        CanonicalStruct::new(COMMITMENT_ENVELOPE_TYPE, ENCODING_VERSION);
    envelope.field_bytes(1, canonical_encoding::encode_digest32(&event_digest)?)?;
    envelope.field_bytes(2, result_bytes.to_vec())?;
    envelope.field_bytes(
        3,
        encode_list(created_authorities, encode_created_authority)?,
    )?;
    envelope.field_bytes(4, encode_list(head_reads, encode_head_read)?)?;
    envelope.field_bytes(5, encode_list(object_mutations, encode_object_mutation)?)?;
    envelope.field_bytes(
        6,
        encode_list(&filtered_reads, |(key, revision)| {
            encode_state_read(key, **revision)
        })?,
    )?;
    envelope.field_bytes(
        7,
        encode_list(&filtered_mutations, |entry| encode_state_mutation(entry))?,
    )?;
    envelope.field_bytes(8, nonce_key.to_vec())?;
    envelope.field_u64(9, nonce_revision.get())?;
    envelope.field_bytes(10, nonce_value.to_vec())?;
    Ok(envelope.finish()?)
}

/// Deterministically hashes the full staged fast-path commit envelope under
/// `HashPurpose::ExecutionEffects` (an existing purpose; DR-0130
/// deliberately reuses it rather than widening `HashSuite`/genesis
/// vectors). Both `prepare` and `apply` call this from their own
/// independently derived [`crate::paid_execution::PaidAdmissionOutput`];
/// byte-identical results from byte-identical admission is exactly the
/// property a fast-path certificate's safety depends on.
#[allow(clippy::too_many_arguments)]
pub(super) fn compute(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    event_digest: Digest32,
    result_bytes: &[u8],
    created_authorities: &[CreatedObjectAuthority],
    head_reads: &[DurableObjectHeadRead],
    object_mutations: &[DurableObjectMutationEntry],
    reads: &BTreeMap<Vec<u8>, StateRevision>,
    state_mutations: &[StateMutationEntry],
    nonce_key: &[u8],
    nonce_revision: StateRevision,
    nonce_value: &[u8],
) -> Result<Digest32, NodeCoreError> {
    let bytes: Vec<u8> = encode_envelope(
        event_digest,
        result_bytes,
        created_authorities,
        head_reads,
        object_mutations,
        reads,
        state_mutations,
        nonce_key,
        nonce_revision,
        nonce_value,
    )?;
    resolver
        .hash_for_purpose(epoch, HashPurpose::ExecutionEffects, &bytes)
        .map_err(NodeCoreError::Hashing)
}
