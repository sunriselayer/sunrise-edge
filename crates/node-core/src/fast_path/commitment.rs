//! DR-0130 fast-path staged-commit commitment.
//!
//! The commitment a [`consensus::FastVote`]/[`consensus::FastCertificate`]
//! binds to (their `execution_effects_hash`) must cover the *entire* staged
//! commit a successful apply will later durably write, not only
//! [`execution::ExecutionEffects`]: the signed intent digest, the canonical
//! paid result, every created object authority, every durable object head
//! assertion and mutation, every application state read assertion and
//! mutation, and the exact pending sender-nonce CAS/write. Only fast-path
//! bookkeeping is excluded: lock reads/writes, prepare's own synthetic
//! receipt, and -- as of DR-0131 -- the CAS-fenced
//! [`crate::local_instance_state::FastPathEpochRecord`] read
//! ([`crate::mutation_fence::fence_current_epoch`]) and, for
//! validator-authorized prepare/apply, the active per-epoch `ValidatorSet`
//! row read (`crate::fast_path::load_validator_set`). Neither read's
//! *content* varies within one committed epoch -- every honest node
//! observes the identical row -- so hashing it into the commitment would add
//! nothing a certificate signer doesn't already imply by admitting under
//! that same committed epoch; and its *durable-store CAS revision* is a
//! per-node, per-attempt artifact, not transaction content, so folding it in
//! would make one logical vote hash differently depending on unrelated
//! concurrent activity against that row. This exclusion does not weaken the
//! fence: apply still independently CAS-fences both records in its own
//! commit ([`crate::mutation_fence::fence_current_epoch`] and
//! `crate::fast_path::load_validator_set`'s digest check), so a concurrent
//! Slice 2 transition landing between prepare and apply is still rejected
//! there -- just never through this commitment.
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
    let (_, digest): (Vec<u8>, Digest32) = compute_with_envelope(
        resolver,
        epoch,
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
    Ok(digest)
}

/// Identical to [`compute`], but also returns the exact canonical `0x6424/v1`
/// envelope bytes the digest was computed over. [`crate::fast_path::apply`]
/// uses this (instead of [`compute`]) so it can durably persist those exact
/// bytes as a request-scoped commitment witness: a [`consensus::FastCertificate`]
/// signs only `execution_effects_hash` (this envelope's digest, DR-0130) and
/// never retains the preimage, so without a durably persisted copy of these
/// bytes a later verifier could never recover the committed
/// [`execution::paid_execution::PaidExecutionResult`] (field 2) -- in
/// particular the charged outcome that fixed the initial settlement total
/// and fee output -- from the certificate alone. See [`decode_witness`] and
/// [`hash_witness_bytes`], the paired verifier-facing helpers over a
/// persisted copy of these bytes.
#[allow(clippy::too_many_arguments)]
pub(super) fn compute_with_envelope(
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
) -> Result<(Vec<u8>, Digest32), NodeCoreError> {
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
    let digest: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::ExecutionEffects, &bytes)
        .map_err(NodeCoreError::Hashing)?;
    Ok((bytes, digest))
}

/// The two facts a persisted commitment witness exists to recover, since
/// neither is retained anywhere else once a [`consensus::FastCertificate`]
/// has been formed and applied: the exact signed-intent digest the
/// certificate's own `tx_hash` attests to, and the canonical
/// [`execution::paid_execution::PaidExecutionResult`] whose `charged` field
/// (when present) fixed the initial settlement total and fee output.
///
/// `#[allow(dead_code)]`: this bounded unit persists the witness row and
/// proves it decodes correctly in its own tests; the fee-claim verifier that
/// will read it in production is separate, not-yet-wired follow-up work.
#[allow(dead_code)]
pub(crate) struct DecodedCommitmentWitness {
    pub(crate) event_digest: Digest32,
    pub(crate) paid_execution_result: execution::paid_execution::PaidExecutionResult,
}

/// Strictly and boundedly decodes a persisted commitment-witness row: the
/// exact canonical `0x6424/v1` envelope [`compute_with_envelope`] produced at
/// a successful [`crate::fast_path::apply`]. Unlike [`compute`]/
/// [`compute_with_envelope`] (which build this frame from live
/// [`crate::paid_execution::PaidAdmissionOutput`] components), this is the
/// verifier-facing direction: decode ONLY, never re-derive.
///
/// Requires the frame to be exactly type `0x6424` version `1` and to carry
/// exactly fields `1..=10` (no fewer, no more) -- the same closed field set
/// [`encode_envelope`] always writes. Fields 3..8 and 10 (the created
/// authorities, durable head reads/mutations, state reads/mutations and
/// nonce key/value lists) are bounded and extracted only as their own raw
/// bytes: this witness's sole job is field 1 (event digest) and field 2
/// (`PaidExecutionResult`), so those other fields are never semantically
/// decoded, only proven to round-trip byte-for-byte through a fresh
/// [`CanonicalStruct`] rebuilt from their extracted raw values -- the same
/// canonical re-encoding discipline `decode_paid_execution_result` and every
/// `decode_fastpath_*` record in [`crate::local_instance_state`] already
/// apply to their own frames. A truncated, reordered, padded, duplicated or
/// otherwise non-canonical witness is rejected here rather than silently
/// accepted.
///
/// `#[allow(dead_code)]`: exercised today by this module's own tests; the
/// production fee-claim verifier consumer is separate follow-up work.
#[allow(dead_code)]
pub(crate) fn decode_witness(bytes: &[u8]) -> Result<DecodedCommitmentWitness, NodeCoreError> {
    let frame = canonical_encoding::decode_canonical_frame(bytes)?;
    frame.require_type(COMMITMENT_ENVELOPE_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;

    let field1: &[u8] = frame.required_field(1)?;
    let field2: &[u8] = frame.required_field(2)?;
    let field3: &[u8] = frame.required_field(3)?;
    let field4: &[u8] = frame.required_field(4)?;
    let field5: &[u8] = frame.required_field(5)?;
    let field6: &[u8] = frame.required_field(6)?;
    let field7: &[u8] = frame.required_field(7)?;
    let field8: &[u8] = frame.required_field(8)?;
    let field9: u64 = frame.required_u64(9)?;
    let field10: &[u8] = frame.required_field(10)?;

    let mut rebuilt: CanonicalStruct =
        CanonicalStruct::new(COMMITMENT_ENVELOPE_TYPE, ENCODING_VERSION);
    rebuilt.field_bytes(1, field1.to_vec())?;
    rebuilt.field_bytes(2, field2.to_vec())?;
    rebuilt.field_bytes(3, field3.to_vec())?;
    rebuilt.field_bytes(4, field4.to_vec())?;
    rebuilt.field_bytes(5, field5.to_vec())?;
    rebuilt.field_bytes(6, field6.to_vec())?;
    rebuilt.field_bytes(7, field7.to_vec())?;
    rebuilt.field_bytes(8, field8.to_vec())?;
    rebuilt.field_u64(9, field9)?;
    rebuilt.field_bytes(10, field10.to_vec())?;
    if rebuilt.finish()? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fast-path commitment witness",
        ));
    }

    let event_digest: Digest32 = canonical_encoding::decode_digest32(field1)?;
    let paid_execution_result: execution::paid_execution::PaidExecutionResult =
        execution::paid_execution::decode_paid_execution_result(field2).map_err(|_| {
            NodeCoreError::PersistenceInvariant(
                "fast-path commitment witness paid execution result",
            )
        })?;
    Ok(DecodedCommitmentWitness {
        event_digest,
        paid_execution_result,
    })
}

/// Hashes already-persisted (or otherwise already-encoded) exact `0x6424/v1`
/// envelope bytes under `HashPurpose::ExecutionEffects` at `epoch` -- the
/// identical purpose and preimage [`compute`]/[`compute_with_envelope`] use,
/// exposed separately so a later verifier holding only a persisted
/// [`decode_witness`]-shaped row (never a live
/// [`crate::paid_execution::PaidAdmissionOutput`]) can re-derive the same
/// digest a [`consensus::FastCertificate::execution_effects_hash`] commits
/// to, and so confirm the persisted bytes are exactly what that certificate
/// certified, without re-deriving the envelope from its components.
///
/// `#[allow(dead_code)]`: exercised today by this module's own tests; the
/// production fee-claim verifier consumer is separate follow-up work.
#[allow(dead_code)]
pub(crate) fn hash_witness_bytes(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    bytes: &[u8],
) -> Result<Digest32, NodeCoreError> {
    resolver
        .hash_for_purpose(epoch, HashPurpose::ExecutionEffects, bytes)
        .map_err(NodeCoreError::Hashing)
}
