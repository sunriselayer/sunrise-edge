//! Independent, read-only re-verification of one DR-0137 fee-claim chain
//! (see `docs/architecture/decisions/0137-fastvote-release-authority.md`,
//! "Certified fee escrow and claims") from durable storage alone.
//!
//! [`handle_fee_claim`](super::handle_fee_claim) already authenticates and
//! commits one claim at a time, against whatever settlement row happens to
//! be installed at that moment. It proves nothing, after the fact, about the
//! *whole* chain of claims that produced the row currently installed: a
//! party that did not itself apply every claim has no way to confirm that
//! every generation 2..N was individually signed by the validator it names,
//! bound to the exact previous/next row digests, and backed by a real,
//! correctly transitioning escrow object -- as opposed to, say, a storage
//! layer that silently overwrote the settlement row out of band.
//!
//! [`verify_fee_claim_chain`] closes that gap for one escrow row. Given only
//! an already independently authenticated generation-1
//! [`FastPathSettlementRecord`] (the caller's anchor -- typically the
//! certificate-apply commit itself) and its exact encoded bytes, it walks
//! every retained signed `0x6438/v1` envelope forward
//! (`local_instance_state::fastpath_fee_claim_key` generations `2..=N`,
//! where `N` is the currently installed row's own generation) and
//! independently re-derives the identical row chain [`super::handle_fee_claim`]
//! would have produced, checking at each step:
//!
//! * the bounded generation count (at most
//!   [`MAX_FASTPATH_ACTIVE_VALIDATORS`] claims beyond generation 1, itself
//!   bounding the caller-supplied historical validator set to the same
//!   ceiling);
//! * identity/context/protocol-version/certificate-epoch and the
//!   resource/output the envelope expects, against the *previous*
//!   reconstructed row -- never the installed row directly;
//! * the previous and (once reconstructed) next row digests, hashed at the
//!   row's own fixed certificate-context epoch exactly like
//!   [`super::fee_claim_row_digest`];
//! * the claimant's Ed25519 signature, verified against the
//!   caller-supplied chain-anchored historical validator set at the
//!   certificate epoch -- never a current or ambient set;
//! * the claim kind (`ZeroShare`/`Split`/`FinalTransfer`) and share amount,
//!   re-derived from the previous row's own bookkeeping exactly like
//!   [`super::handle_fee_claim`]'s own step 9, never trusted from the
//!   envelope's own tag; and, for a positive claim only,
//! * the escrow object's own historical transition: an immutable durable
//!   object version is loaded directly (inline or blob-backed, either way
//!   with its digest and nominal type independently re-verified against the
//!   caller-supplied [`VerifiedPublicationInterface`] and
//!   [`FeeEscrowResourceAbi`]), and its owner, version (`previous + 1`),
//!   type and schema are checked against the previous version, and its
//!   ABI-observed `u64` nominal value is checked to conserve the previous
//!   value minus the claimed share (`Split`) or to conserve it exactly while
//!   exhausting it (`FinalTransfer`).
//!
//! Every reconstructed row is compared byte-for-byte against the *next*
//! envelope's own `expected_previous_row_digest`/`expected_fee_output`
//! commitments as that next envelope is processed, and the final
//! reconstructed row is compared byte-for-byte against the row this
//! function itself reads from durable storage. A mismatch anywhere, a
//! decode failure, or a missing generation between `2` and `N` (a "missing
//! envelope") all fail closed with [`FeeClaimError::Invalid`].
//!
//! # Explicit scope gap: a `Split` claim's payout object is not verified
//!
//! A `Split` claim's leg creates a *second*, brand-new object -- the
//! recipient's payout -- distinct from the escrow object this function
//! tracks. Unlike the escrow's own continuation (whose identity, version
//! and resulting digest are all pinned by the signed intent's
//! `expected_fee_output`/`expected_next_row_digest` chain and independently
//! re-derivable from durable storage alone, exactly as this function does),
//! the payout object's identity is host-assigned at execution time and is
//! not recorded anywhere in the closed [`FeeClaimIntent`](codec::FeeClaimIntent) or the
//! settlement row. This function therefore proves the escrow's own
//! object-transition chain and value conservation on the *retained* side
//! only; it does **not** independently confirm that a correctly owned,
//! correctly valued payout object was ever actually created for the
//! recipient. Re-establishing that would require either re-executing the
//! claim's leg (out of this module's scope: it does no execution, holds no
//! [`crate::local_execution::LocalContractEngine`], and performs no state
//! mutation) or the caller separately supplying and anchoring the payout
//! object's own identity, which today's `0x6437/v1` envelope does not carry.
//! Callers must not read a successful [`verify_fee_claim_chain`] result as
//! proof that every historical payout landed correctly.
//!
//! This module also does not verify that the escrow object's protocol
//! custody was originally authorized by the exact code/instance the
//! certified economics policy pins (`ObjectAuthority.code`/`instance`): it
//! checks only the object's [`Owner`] variant/scope and its ABI-observed
//! nominal type/value, which the caller-supplied [`FeeEscrowResourceAbi`]
//! and [`VerifiedPublicationInterface`] must already themselves be trusted
//! for. Wiring the full economics-policy/code provenance chain into this
//! check is left to the parent that constructs those trusted inputs.
//!
//! This module performs no global scan and holds no startup hook: every
//! read is a single targeted key (one settlement row, one signed envelope
//! per generation, one immutable object version per positive claim), and
//! the walk is bounded by [`MAX_FASTPATH_ACTIVE_VALIDATORS`] before a single
//! envelope is read.
use super::*;
use crate::fast_path::records::MAX_FASTPATH_ACTIVE_VALIDATORS;
use abi::package_types::{ScopedTypeTag, verify_scoped_type_id};
use execution::publication::{VerifiedPublicationInterface, observe_nominal_value};
use runtime::DurableObjectProvenance;

#[cfg(test)]
#[path = "verify_tests.rs"]
mod verify_tests;

/// The caller-verified ABI identity of the fee-escrow resource this chain's
/// generation-1 row was charged against: the exact nominal type and schema
/// version [`super::fee_claim_capability`] pins the escrow object to for the
/// life of the row. Mirrors the relevant fields of
/// [`crate::economics::FastPathEconomicsResourcePolicy`] without this module
/// depending on decoding the signed economics policy itself; the caller
/// (which already has the policy for other reasons) is responsible for
/// supplying values that actually match it.
pub(super) struct FeeEscrowResourceAbi {
    /// Exact nominal type every escrow object version carries.
    pub(super) ty: ScopedTypeTag,
    /// Exact schema version every escrow object version carries.
    pub(super) schema_version: u32,
}

/// What [`verify_fee_claim_chain`] independently established. `final_generation`
/// is the currently installed row's own generation (`1` when no claim has
/// ever been made against this row); `verified_claims`/`verified_positive_claims`
/// count the signed envelopes this call itself walked and checked, not
/// generation 1 itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FeeClaimChainReport {
    pub(super) final_generation: u64,
    pub(super) verified_claims: u64,
    pub(super) verified_positive_claims: u64,
}

/// One escrow object version, loaded directly by `(id, version)` rather than
/// through the current head, with its digest, provenance and decoded body
/// already independently verified. Mirrors the relevant checks of
/// [`object_snapshots::load_object_snapshot`], which cannot be reused here
/// because it requires the requested version to equal the *current* head --
/// wrong for every escrow version except the last.
struct HistoricalObjectVersion {
    object: Object,
    digest: Digest32,
    provenance: DurableObjectProvenance,
}

#[allow(clippy::too_many_arguments)]
fn load_historical_object_version<S: StructuredDurableDomainStateStore>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    creating_epoch: Epoch,
    chain_id: &ChainId,
    object_id: ObjectId,
    version: u64,
) -> Result<HistoricalObjectVersion, FeeClaimError> {
    let object_version: DurableObjectVersion = DurableObjectVersion::new(version).ok_or(
        FeeClaimError::Invalid("fee claim chain escrow object version"),
    )?;
    let record: DurableObjectVersionRecord = store
        .get_object_version(context, domain, object_id, object_version)?
        .ok_or(NodeCoreError::ObjectRecordMissing { object_id })?;
    if record.object_id() != object_id || record.object_version() != object_version {
        return Err(NodeCoreError::ObjectRecordMismatch { object_id }.into());
    }
    // Objects never migrate chains (see `object_snapshots::load_object_snapshot`'s
    // identical check): checked before any blob-store I/O.
    if record.provenance().chain_id() != chain_id
        || record.provenance().protocol_version() != resolver.protocol_version()
    {
        return Err(NodeCoreError::ObjectProvenanceMismatch { object_id }.into());
    }
    let loaded: LoadedObjectBody<'_> = match record.payload() {
        DurableObjectPayload::Inline(inline) => LoadedObjectBody::Inline(inline),
        DurableObjectPayload::BlobReference(blob_digest) => {
            let blob_digest: Digest32 = *blob_digest;
            let bytes: Vec<u8> = blob_store
                .get_blob(&blob_digest)
                .map_err(NodeCoreError::Runtime)?
                .ok_or(NodeCoreError::ObjectBlobMissing {
                    object_id,
                    blob_digest,
                })?;
            if bytes.len() > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
                return Err(NodeCoreError::ObjectBodyTooLarge {
                    object_id,
                    actual: bytes.len(),
                    maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
                }
                .into());
            }
            let blob_verified: bool = hashing::verify_digest(
                &blob_digest,
                HashPurpose::Object,
                record.provenance().protocol_version(),
                record.provenance().chain_id(),
                &bytes,
            )
            .map_err(|error| match error {
                HashingError::UnsupportedAlgorithm(algorithm) => {
                    NodeCoreError::ObjectDigestUnverifiable {
                        object_id,
                        algorithm,
                    }
                }
                other => NodeCoreError::Hashing(other),
            })?;
            if !blob_verified {
                return Err(NodeCoreError::ObjectBlobDigestMismatch {
                    object_id,
                    blob_digest,
                }
                .into());
            }
            let object: Object = decode_object(&bytes)
                .map_err(DurableInvocationError::from)
                .map_err(NodeCoreError::from)?;
            LoadedObjectBody::Blob {
                bytes,
                object: Box::new(object),
            }
        }
    };
    let object: &Object = loaded.object();
    if object.id != object_id
        || object.version != version
        || record.schema_version() != object.schema_version
    {
        return Err(NodeCoreError::ObjectRecordMismatch { object_id }.into());
    }
    if loaded.canonical_bytes().len() > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
        return Err(NodeCoreError::ObjectBodyTooLarge {
            object_id,
            actual: loaded.canonical_bytes().len(),
            maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        }
        .into());
    }
    let verified: bool = hashing::verify_digest(
        &record.digest(),
        HashPurpose::Object,
        record.provenance().protocol_version(),
        record.provenance().chain_id(),
        loaded.canonical_bytes(),
    )
    .map_err(|error| match error {
        HashingError::UnsupportedAlgorithm(algorithm) => NodeCoreError::ObjectDigestUnverifiable {
            object_id,
            algorithm,
        },
        other => NodeCoreError::Hashing(other),
    })?;
    if !verified {
        return Err(NodeCoreError::ObjectBodyDigestMismatch { object_id }.into());
    }
    let expected_digest: Digest32 = resolver.hash_for_purpose(
        creating_epoch,
        HashPurpose::Object,
        loaded.canonical_bytes(),
    )?;
    if expected_digest != record.digest() {
        return Err(FeeClaimError::Invalid(
            "fee claim chain escrow digest does not use the creating epoch suite",
        ));
    }
    Ok(HistoricalObjectVersion {
        object: object.clone(),
        digest: record.digest(),
        provenance: record.provenance().clone(),
    })
}

/// Observes one `u64` nominal value through the caller-supplied verified
/// interface, exactly like [`super::effects`]'s own (module-private,
/// unreachable from here) `observe` helper.
fn observe_u64(
    interface: &VerifiedPublicationInterface,
    ty: &ScopedTypeTag,
    schema_version: u32,
    data: &[u8],
) -> Result<u64, FeeClaimError> {
    match observe_nominal_value(interface, ty, schema_version, data)
        .map_err(|_| FeeClaimError::Invalid("fee claim chain value observation"))?
    {
        abi::call_values::CallValue::U64(value) => Ok(value),
        _ => Err(FeeClaimError::Invalid("fee claim chain value must be u64")),
    }
}

/// Independently checks one historical escrow object version's identity
/// (owner, version, unchanged type/schema) against the previous version, and
/// returns its ABI-observed nominal value.
#[allow(clippy::too_many_arguments)]
fn check_escrow_transition(
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    escrow_resource: &FeeEscrowResourceAbi,
    interface: &VerifiedPublicationInterface,
    escrow_id: ObjectId,
    previous: &Object,
    current: &HistoricalObjectVersion,
    type_check_epoch: Epoch,
    expected_owner: &Owner,
) -> Result<u64, FeeClaimError> {
    if current.object.id != escrow_id
        || current.object.version
            != previous
                .version
                .checked_add(1)
                .ok_or(FeeClaimError::Invalid(
                    "fee claim chain escrow version overflow",
                ))?
        || current.object.type_hash != previous.type_hash
        || current.object.schema_version != previous.schema_version
        || current.object.schema_version != escrow_resource.schema_version
    {
        return Err(FeeClaimError::Invalid(
            "fee claim chain escrow mutation identity, version, type or schema changed",
        ));
    }
    if &current.object.owner != expected_owner {
        return Err(FeeClaimError::Invalid("fee claim chain escrow owner"));
    }
    let type_resolver: &HashSuiteResolver = object_snapshots::historical_resolver_for_provenance(
        resolver,
        history,
        escrow_id,
        &current.provenance,
    )?;
    let type_valid: bool = verify_scoped_type_id(
        type_resolver,
        &current.object.type_hash,
        type_check_epoch,
        &escrow_resource.ty,
    )
    .map_err(|_| FeeClaimError::Invalid("fee claim chain escrow type identity"))?;
    if !type_valid {
        return Err(FeeClaimError::Invalid(
            "fee claim chain escrow type identity",
        ));
    }
    observe_u64(
        interface,
        &escrow_resource.ty,
        current.object.schema_version,
        &current.object.data,
    )
}

/// Independently re-verifies every signed fee-claim envelope retained for
/// one escrow row, from the caller-authenticated generation-1
/// [`FastPathSettlementRecord`] up to whatever generation is currently
/// installed. See the module documentation for exactly what this proves and
/// the one payout-object gap it does not close.
#[allow(clippy::too_many_arguments)]
pub(super) fn verify_fee_claim_chain<S: StructuredDurableDomainStateStore>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    validator_set: &ValidatorSet,
    escrow_resource: &FeeEscrowResourceAbi,
    interface: &VerifiedPublicationInterface,
    genesis_row: &FastPathSettlementRecord,
    genesis_row_bytes: &[u8],
) -> Result<FeeClaimChainReport, FeeClaimError> {
    if history.len() > publication::MAX_PUBLICATION_HISTORY {
        return Err(FeeClaimError::Invalid(
            "fee claim chain resolver history bound",
        ));
    }
    if genesis_row.generation != 1
        || genesis_row.fee_output_epoch != Some(genesis_row.context.epoch())
    {
        return Err(FeeClaimError::Invalid("fee claim chain genesis generation"));
    }
    if encode_fastpath_settlement_record(genesis_row)? != genesis_row_bytes {
        return Err(FeeClaimError::Invalid("fee claim chain genesis row bytes"));
    }
    let (resource_id, genesis_fee_output, genesis_fee_output_epoch, total_amount): (
        BondResourceId,
        ObjectRef,
        Epoch,
        u64,
    ) = match (
        genesis_row.resource_id,
        genesis_row.fee_output.clone(),
        genesis_row.fee_output_epoch,
        genesis_row.total_amount,
    ) {
        (Some(resource_id), Some(fee_output), Some(fee_output_epoch), Some(total_amount)) => {
            (resource_id, fee_output, fee_output_epoch, total_amount)
        }
        _ => {
            return Err(FeeClaimError::Invalid(
                "fee claim chain genesis row is uncharged",
            ));
        }
    };
    let escrow_id: ObjectId = genesis_fee_output.id;
    let chain_id: ChainId = genesis_row.context.chain_id().clone();

    if validator_set.validators().len() > MAX_FASTPATH_ACTIVE_VALIDATORS {
        return Err(FeeClaimError::Invalid(
            "fee claim chain validator set exceeds the active bound",
        ));
    }
    if genesis_row.shares.len() > MAX_FASTPATH_ACTIVE_VALIDATORS {
        return Err(FeeClaimError::Invalid(
            "fee claim chain share count exceeds the active bound",
        ));
    }

    // Read the currently installed row directly: one targeted key, never a
    // scan. Its own generation is this walk's exact, pre-known upper bound.
    let settlement_key: Vec<u8> =
        local_instance_state::fastpath_settlement_key(&chain_id, &genesis_row.request_id)?;
    let installed_observed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &settlement_key)?;
    let installed_bytes: &[u8] = installed_observed.value().ok_or(FeeClaimError::Invalid(
        "fee claim chain installed settlement row missing",
    ))?;

    let installed_row: FastPathSettlementRecord =
        decode_fastpath_settlement_record(installed_bytes)?;
    if installed_row.context != genesis_row.context
        || installed_row.request_id != genesis_row.request_id
        || installed_row.resource_id != genesis_row.resource_id
        || installed_row.total_amount != genesis_row.total_amount
        || installed_row.generation < genesis_row.generation
    {
        return Err(FeeClaimError::Invalid(
            "fee claim chain installed row identity mismatch",
        ));
    }
    let target_generation: u64 = installed_row.generation;
    let max_generation: u64 = (MAX_FASTPATH_ACTIVE_VALIDATORS as u64)
        .checked_add(1)
        .ok_or(FeeClaimError::Invalid("fee claim chain generation bound"))?;
    if target_generation > max_generation {
        return Err(FeeClaimError::Invalid(
            "fee claim chain generation exceeds the active bound",
        ));
    }

    // Seed the escrow object cache from the caller-authenticated genesis
    // anchor: the full charged total must actually sit in the escrow object
    // the row claims, under the pinned nominal type/schema and custody scope.
    let genesis_object: HistoricalObjectVersion = load_historical_object_version(
        store,
        blob_store,
        context,
        domain,
        resolver,
        genesis_fee_output_epoch,
        &chain_id,
        escrow_id,
        genesis_fee_output.version,
    )?;
    if genesis_object.digest != genesis_fee_output.digest {
        return Err(FeeClaimError::Invalid(
            "fee claim chain genesis escrow digest mismatch",
        ));
    }
    let escrow_scope: ProtocolCustodyScope =
        fee_escrow_scope(&genesis_row.context, genesis_row.request_id, resource_id);
    if genesis_object.object.owner != Owner::ProtocolCustody(escrow_scope.clone())
        || genesis_object.object.schema_version != escrow_resource.schema_version
    {
        return Err(FeeClaimError::Invalid(
            "fee claim chain genesis escrow owner",
        ));
    }
    let genesis_type_resolver: &HashSuiteResolver =
        object_snapshots::historical_resolver_for_provenance(
            resolver,
            history,
            escrow_id,
            &genesis_object.provenance,
        )?;
    let genesis_type_valid: bool = verify_scoped_type_id(
        genesis_type_resolver,
        &genesis_object.object.type_hash,
        genesis_fee_output_epoch,
        &escrow_resource.ty,
    )
    .map_err(|_| FeeClaimError::Invalid("fee claim chain genesis escrow type identity"))?;
    if !genesis_type_valid {
        return Err(FeeClaimError::Invalid(
            "fee claim chain genesis escrow type identity",
        ));
    }
    let genesis_value: u64 = observe_u64(
        interface,
        &escrow_resource.ty,
        genesis_object.object.schema_version,
        &genesis_object.object.data,
    )?;
    if genesis_value != total_amount {
        return Err(FeeClaimError::Invalid(
            "fee claim chain genesis escrow value does not equal the charged total",
        ));
    }

    let mut previous_row: FastPathSettlementRecord = genesis_row.clone();
    let mut previous_bytes: Vec<u8> = genesis_row_bytes.to_vec();
    let mut escrow_object: Object = genesis_object.object;
    let mut escrow_value: u64 = genesis_value;
    // Once a `FinalTransfer` moves the whole remaining balance to its
    // recipient, the escrow object leaves custody for good: `escrow_value`
    // stops tracking anything meaningful, and every remaining generation can
    // only be a `ZeroShare` claim (the live handler's `derive_claim_kind`
    // only permits `FinalTransfer` when no other positive share remains
    // unclaimed). Comparing `unclaimed_positive_total` against a stale
    // `escrow_value` after that point would reject a valid certified
    // history.
    let mut escrow_finalized: bool = false;
    let mut verified_positive_claims: u64 = 0;

    let mut generation: u64 = 1;
    while generation < target_generation {
        let next_generation: u64 = generation.checked_add(1).ok_or(FeeClaimError::Invalid(
            "fee claim chain generation overflow",
        ))?;
        let claim_key: Vec<u8> = local_instance_state::fastpath_fee_claim_key(
            &chain_id,
            &genesis_row.request_id,
            next_generation,
        )?;
        let claim_observed: VersionedStateValue =
            store.get_versioned_durable(context, domain, &claim_key)?;
        let claim_bytes: &[u8] = claim_observed.value().ok_or(FeeClaimError::Invalid(
            "fee claim chain missing or orphaned envelope",
        ))?;
        let signed: SignedFeeClaimIntent = decode_signed_fee_claim_intent(claim_bytes)?;

        if previous_row.context.chain_id() != signed.intent.context.chain_id()
            || previous_row.context.protocol_version() != signed.intent.context.protocol_version()
            || previous_row.context.epoch() != signed.intent.certificate_epoch
            || previous_row.request_id != signed.intent.escrow_request_id
            || previous_row.generation != signed.intent.expected_generation
        {
            return Err(FeeClaimError::Invalid(
                "fee claim chain envelope identity mismatch",
            ));
        }
        let previous_resource_id: BondResourceId = previous_row.resource_id.ok_or(
            FeeClaimError::Invalid("fee claim chain previous row is uncharged"),
        )?;
        let previous_fee_output: ObjectRef =
            previous_row
                .fee_output
                .clone()
                .ok_or(FeeClaimError::Invalid(
                    "fee claim chain previous row is uncharged",
                ))?;
        if previous_resource_id != signed.intent.resource_id
            || previous_fee_output != signed.intent.expected_fee_output
        {
            return Err(FeeClaimError::Invalid(
                "fee claim chain envelope resource or output mismatch",
            ));
        }

        let previous_row_digest: Digest32 =
            fee_claim_row_digest(resolver, previous_row.context.epoch(), &previous_bytes)?;
        if previous_row_digest != signed.intent.expected_previous_row_digest {
            return Err(FeeClaimError::Invalid(
                "fee claim chain stale expected previous row digest",
            ));
        }

        // One shared derivation with the live handler: no drift in which
        // signed operation shape the previous row permits.
        let (share_index, unclaimed_positive_total, is_final): (usize, u64, bool) =
            derive_claim_kind(&previous_row, &signed.intent)?;
        if !escrow_finalized && unclaimed_positive_total != escrow_value {
            return Err(FeeClaimError::Invalid(
                "fee claim chain escrow value does not equal unclaimed shares",
            ));
        }
        let is_zero: bool = signed.intent.share_amount == 0;

        // Chain-anchored historical validator signature, over the exact
        // recomputed intent digest -- never a stored/summary signature.
        let validator =
            validator_set
                .get(signed.intent.validator_id)
                .ok_or(FeeClaimError::Invalid(
                    "fee claim chain validator absent from the certificate epoch set",
                ))?;
        if validator.signature_scheme != SignatureSchemeId::Ed25519 {
            return Err(FeeClaimError::Invalid(
                "fee claim chain validator signature scheme",
            ));
        }
        let verifier: Ed25519Verifier =
            Ed25519Verifier::from_verifying_key_bytes(&validator.public_key)?;
        let intent_digest: Digest32 = fee_claim_intent_digest(resolver, &signed.intent)?;
        let framed: Vec<u8> = fee_claim_signing_frame(&signed.intent.context, intent_digest)?;
        if !verifier.verify_framed(&framed, &signed.signature)? {
            return Err(FeeClaimError::Invalid("fee claim chain envelope signature"));
        }

        let mut new_shares: Vec<FastPathFeeShare> = previous_row.shares.clone();
        new_shares[share_index].claimed = true;

        let (new_fee_output, new_fee_output_epoch): (ObjectRef, Epoch) = if is_zero {
            let unchanged_epoch: Epoch = previous_row.fee_output_epoch.ok_or(
                FeeClaimError::Invalid("fee claim chain previous row is uncharged"),
            )?;
            (previous_fee_output, unchanged_epoch)
        } else {
            let claim_epoch: Epoch = signed.intent.context.epoch();
            let new_version: u64 =
                previous_fee_output
                    .version
                    .checked_add(1)
                    .ok_or(FeeClaimError::Invalid(
                        "fee claim chain escrow version overflow",
                    ))?;
            let loaded: HistoricalObjectVersion = load_historical_object_version(
                store,
                blob_store,
                context,
                domain,
                resolver,
                claim_epoch,
                &chain_id,
                escrow_id,
                new_version,
            )?;
            let expected_owner: Owner = if is_final {
                Owner::Address(signed.intent.recipient)
            } else {
                Owner::ProtocolCustody(escrow_scope.clone())
            };
            let after: u64 = check_escrow_transition(
                resolver,
                history,
                escrow_resource,
                interface,
                escrow_id,
                &escrow_object,
                &loaded,
                claim_epoch,
                &expected_owner,
            )?;
            let expected_after: u64 = if is_final {
                escrow_value
            } else {
                escrow_value.checked_sub(signed.intent.share_amount).ok_or(
                    FeeClaimError::Invalid("fee claim chain escrow value underflow"),
                )?
            };
            if after != expected_after || (!is_final && after == 0) {
                return Err(FeeClaimError::Invalid(
                    "fee claim chain escrow value does not conserve the unclaimed total",
                ));
            }
            if is_final && signed.intent.share_amount != escrow_value {
                return Err(FeeClaimError::Invalid(
                    "fee claim chain final claim does not exhaust the unclaimed total",
                ));
            }
            escrow_object = loaded.object;
            escrow_value = after;
            if is_final {
                escrow_finalized = true;
            }
            verified_positive_claims =
                verified_positive_claims
                    .checked_add(1)
                    .ok_or(FeeClaimError::Invalid(
                        "fee claim chain positive claim count overflow",
                    ))?;
            (
                ObjectRef {
                    id: escrow_id,
                    version: new_version,
                    digest: loaded.digest,
                },
                claim_epoch,
            )
        };

        let reconstructed: FastPathSettlementRecord = FastPathSettlementRecord {
            context: previous_row.context.clone(),
            request_id: previous_row.request_id,
            generation: next_generation,
            resource_id: Some(previous_resource_id),
            fee_output: Some(new_fee_output),
            fee_output_epoch: Some(new_fee_output_epoch),
            total_amount: previous_row.total_amount,
            shares: new_shares,
        };
        let reconstructed_bytes: Vec<u8> = encode_fastpath_settlement_record(&reconstructed)?;
        let next_row_digest: Digest32 = fee_claim_row_digest(
            resolver,
            reconstructed.context.epoch(),
            &reconstructed_bytes,
        )?;
        if next_row_digest != signed.intent.expected_next_row_digest {
            return Err(FeeClaimError::Invalid(
                "fee claim chain next row digest mismatch",
            ));
        }

        previous_row = reconstructed;
        previous_bytes = reconstructed_bytes;
        generation = next_generation;
    }

    if previous_bytes != installed_bytes {
        return Err(FeeClaimError::Invalid(
            "fee claim chain final row does not match the installed row",
        ));
    }
    let first_orphan_generation: u64 =
        target_generation
            .checked_add(1)
            .ok_or(FeeClaimError::Invalid(
                "fee claim chain generation overflow",
            ))?;
    let first_impossible_generation: u64 = max_generation.checked_add(1).ok_or(
        FeeClaimError::Invalid("fee claim chain generation overflow"),
    )?;
    for orphan_generation in first_orphan_generation..=first_impossible_generation {
        let orphan_key: Vec<u8> = local_instance_state::fastpath_fee_claim_key(
            &chain_id,
            &genesis_row.request_id,
            orphan_generation,
        )?;
        let orphan: VersionedStateValue =
            store.get_versioned_durable(context, domain, &orphan_key)?;
        if orphan.revision() != StateRevision::INITIAL || orphan.value().is_some() {
            return Err(FeeClaimError::Invalid("fee claim chain orphan envelope"));
        }
    }

    Ok(FeeClaimChainReport {
        final_generation: target_generation,
        verified_claims: target_generation.saturating_sub(genesis_row.generation),
        verified_positive_claims,
    })
}
