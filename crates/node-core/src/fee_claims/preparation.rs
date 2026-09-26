//! DR-0149 read-only, offline escrow inspection and exact claim preparation.
//! No result reserves a generation or nonce. Callers must exclude writers;
//! claim apply repeats all admission, signatures, execution and CAS checks.
use super::*;
use canonical_encoding::encode_chain_id;
use execution::local_execution::InstanceRecord;
use execution::publication::VerifiedPublicationInterface;
use protocol_types::ValidatorId;
use runtime::{DurableStateKeyScanner, StateKeyPage, StateKeyScan};
use std::num::NonZeroUsize;

/// The only operation an unclaimed entitlement currently permits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeClaimKind {
    /// Finalize an assigned zero share without executing a leg.
    ZeroShare,
    /// Release a positive share while other positive shares remain.
    Split,
    /// Transfer the last positive share's complete escrow object.
    FinalTransfer,
}

/// One entitlement under the authenticated certificate-epoch validator key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeClaimEntitlement {
    pub validator_id: ValidatorId,
    pub authorization_key: [u8; 32],
    pub amount: u64,
    pub claimed: bool,
    /// `None` for an already claimed entitlement.
    pub kind: Option<FeeClaimKind>,
}

/// A certified history and the exact current row it authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeEscrowInspection {
    pub canonical_settlement: Vec<u8>,
    pub settlement: FastPathSettlementRecord,
    pub verification: FeeClaimVerificationReport,
    pub claimants: Vec<FeeClaimEntitlement>,
}

/// Trusted public code/ABI/object inputs for building a positive signed leg.
#[derive(Clone, Debug)]
pub struct FeeClaimExecutionView {
    pub resource: FastPathEconomicsResourcePolicy,
    pub instance: InstanceRecord,
    pub interface: VerifiedPublicationInterface,
    pub policy: LocalExecutionPolicy,
    pub fee_output: Object,
    pub next_nonce: u64,
    /// A later execution checkpoint must not predate the loaded version.
    pub minimum_checkpoint: u64,
}

/// Detailed view of one selected historical claimant.
#[derive(Clone, Debug)]
pub struct FeeClaimInspection {
    pub escrow: FeeEscrowInspection,
    pub entitlement: FeeClaimEntitlement,
    /// Absent for zero shares and already claimed shares. Certified history
    /// verification still checks historical objects, but no current object
    /// head or sender nonce is loaded for these cases.
    pub execution: Option<FeeClaimExecutionView>,
}

/// One bounded present-key discovery page, not a multi-page snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeEscrowDiscoveryPage {
    pub escrows: Vec<FeeEscrowInspection>,
    pub continuation_cursor: Option<Vec<u8>>,
}

/// Explicit operator inputs. The public key must match the selected
/// certificate-epoch validator. A signed leg is required only for positives.
pub struct FeeClaimPreparationRequest<'a> {
    pub escrow_request_id: [u8; 32],
    pub request_id: [u8; 32],
    pub validator_id: ValidatorId,
    pub claimant_public_key: [u8; 32],
    pub recipient: Address,
    pub signed_leg: Option<&'a [u8]>,
}

/// An unsigned proposal. Sign `intent` with the historical validator key;
/// apply the saved signed bytes through `handle_fee_claim` without re-signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedFeeClaim {
    pub intent: FeeClaimIntent,
    pub next_settlement: FastPathSettlementRecord,
    pub expected_payout: Option<ObjectRef>,
}

fn require_preparation_context(
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
) -> Result<(), FeeClaimError> {
    if history.len() > publication::MAX_PUBLICATION_HISTORY
        || resolver.chain_id() != expected.chain_id()
        || resolver.protocol_version() != expected.protocol_version()
    {
        return Err(FeeClaimError::Invalid("fee preparation resolver context"));
    }
    Ok(())
}

fn kind_for_share(row: &FastPathSettlementRecord, index: usize) -> Option<FeeClaimKind> {
    let share: &FastPathFeeShare = &row.shares[index];
    if share.claimed {
        None
    } else if share.amount == 0 {
        Some(FeeClaimKind::ZeroShare)
    } else if row
        .shares
        .iter()
        .enumerate()
        .any(|(other_index, other)| other_index != index && !other.claimed && other.amount > 0)
    {
        Some(FeeClaimKind::Split)
    } else {
        Some(FeeClaimKind::FinalTransfer)
    }
}

/// Verifies the full certified history and returns its exact installed row.
/// Requires a current, locally pinned context and an offline fenced store.
/// The caller must ensure quiescence: these separate reads are not a shared
/// database snapshot, and a writer fence alone does not exclude new writers.
#[allow(clippy::too_many_arguments)]
pub fn inspect_fee_escrow<S: StructuredDurableDomainStateStore>(
    store: &S,
    blob_store: &dyn BlobStore,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    escrow_request_id: [u8; 32],
) -> Result<FeeEscrowInspection, FeeClaimError> {
    inspect_fee_escrow_with_verifier(
        store,
        operation,
        domain,
        resolver,
        history,
        expected,
        escrow_request_id,
        || {
            verify_fee_claim_history(
                store,
                blob_store,
                operation,
                domain,
                resolver,
                history,
                expected.chain_id(),
                &escrow_request_id,
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn inspect_fee_escrow_with_verifier<S, Verify>(
    store: &S,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    escrow_request_id: [u8; 32],
    verify: Verify,
) -> Result<FeeEscrowInspection, FeeClaimError>
where
    S: StructuredDurableDomainStateStore,
    Verify: FnOnce() -> Result<FeeClaimVerificationReport, FeeClaimError>,
{
    require_preparation_context(resolver, history, expected)?;
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    mutation_fence::fence_current_epoch(
        store,
        operation,
        domain,
        expected.chain_id(),
        expected.epoch(),
        &mut reads,
    )?;
    let key: Vec<u8> =
        local_instance_state::fastpath_settlement_key(expected.chain_id(), &escrow_request_id)?;
    let before: VersionedStateValue = store.get_versioned_durable(operation, domain, &key)?;
    let canonical_settlement: Vec<u8> = before
        .value()
        .ok_or(FeeClaimError::Invalid("fee claim settlement missing"))?
        .to_vec();
    let settlement: FastPathSettlementRecord =
        decode_fastpath_settlement_record(&canonical_settlement)?;
    if settlement.context.chain_id() != expected.chain_id()
        || settlement.context.protocol_version() != expected.protocol_version()
        || settlement.request_id != escrow_request_id
    {
        return Err(FeeClaimError::Invalid("fee inspection settlement context"));
    }
    let verification: FeeClaimVerificationReport = verify()?;
    let validator_set: ValidatorSet = equivocation::load_historical_validator_set(
        store,
        operation,
        domain,
        resolver,
        expected.chain_id(),
        expected.protocol_version(),
        settlement.context.epoch(),
    )?;
    let mut claimants: Vec<FeeClaimEntitlement> = Vec::with_capacity(settlement.shares.len());
    for (index, share) in settlement.shares.iter().enumerate() {
        let validator = validator_set
            .get(share.validator_id)
            .ok_or(FeeClaimError::Invalid(
                "fee inspection claimant absent from historical set",
            ))?;
        if validator.signature_scheme != SignatureSchemeId::Ed25519 {
            return Err(FeeClaimError::Invalid("fee inspection claimant scheme"));
        }
        let authorization_key: [u8; 32] = validator
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| FeeClaimError::Invalid("fee inspection claimant key length"))?;
        let _: Ed25519Verifier = Ed25519Verifier::from_verifying_key_bytes(&authorization_key)?;
        claimants.push(FeeClaimEntitlement {
            validator_id: share.validator_id,
            authorization_key,
            amount: share.amount,
            claimed: share.claimed,
            kind: kind_for_share(&settlement, index),
        });
    }
    let after: VersionedStateValue = store.get_versioned_durable(operation, domain, &key)?;
    if after.revision() != before.revision()
        || after.value() != Some(canonical_settlement.as_slice())
        || verification.final_generation != settlement.generation
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    Ok(FeeEscrowInspection {
        canonical_settlement,
        settlement,
        verification,
        claimants,
    })
}

/// Inspects one claimant and the public ABI inputs needed to sign a leg.
/// `leg_sender` selects a nonce; it is not the historical claimant authority.
/// As with escrow inspection, the caller must exclude concurrent writers;
/// returned inputs are observations and reserve neither nonce nor generation.
#[allow(clippy::too_many_arguments)]
pub fn inspect_fee_claim<S: StructuredDurableDomainStateStore>(
    store: &S,
    blob_store: &dyn BlobStore,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    escrow_request_id: [u8; 32],
    validator_id: ValidatorId,
    leg_sender: [u8; 32],
    leg_policy: &LocalExecutionPolicy,
) -> Result<FeeClaimInspection, FeeClaimError> {
    let escrow: FeeEscrowInspection = inspect_fee_escrow(
        store,
        blob_store,
        operation,
        domain,
        resolver,
        history,
        expected,
        escrow_request_id,
    )?;
    let entitlement: FeeClaimEntitlement = escrow
        .claimants
        .iter()
        .find(|claimant| claimant.validator_id == validator_id)
        .ok_or(FeeClaimError::Invalid(
            "fee inspection validator has no assigned share",
        ))?
        .clone();
    let execution: Option<FeeClaimExecutionView> = if matches!(
        entitlement.kind,
        Some(FeeClaimKind::Split | FeeClaimKind::FinalTransfer)
    ) {
        if leg_policy.context() != expected {
            return Err(FeeClaimError::Invalid("fee inspection leg policy context"));
        }
        let policy_key: Vec<u8> =
            local_instance_state::execution_policy_key_for_profile(expected, leg_policy.profile())?;
        let policy_observed: VersionedStateValue =
            store.get_versioned_durable(operation, domain, &policy_key)?;
        if policy_observed.value() != Some(leg_policy.encode()?.as_slice()) {
            return Err(FeeClaimError::Invalid(
                "fee inspection leg policy not installed",
            ));
        }
        let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
        let (fee_policy, economics): (PaidFeePolicy, FastPathEconomicsPolicy) =
            read_economics_policy(
                store,
                operation,
                domain,
                &escrow.settlement.context,
                &mut reads,
            )?;
        let resource_id: BondResourceId = escrow
            .settlement
            .resource_id
            .ok_or(FeeClaimError::Invalid("fee inspection uncharged escrow"))?;
        let resource: FastPathEconomicsResourcePolicy =
            resource_policy(&economics, resource_id)?.clone();
        require_fee_resource(&resource, &fee_policy)?;
        let loaded: publication::VerifiedDurablePublication =
            publication::load_verified_publication(
                store,
                operation,
                domain,
                resolver,
                history,
                resource.code.origin(),
            )
            .map_err(|_| FeeClaimError::Invalid("fee inspection code publication"))?
            .ok_or(FeeClaimError::Invalid("fee inspection code missing"))?;
        local_execution::validate_closure(resolver, history, &loaded.interface)?;
        if !local_execution::reference_matches(&resource.code, &loaded.interface) {
            return Err(FeeClaimError::Invalid("fee inspection code reference"));
        }
        let instance: InstanceRecord = local_execution::query_local_instance(
            store,
            operation,
            domain,
            resolver,
            history,
            expected.chain_id(),
            resource.instance.creator,
            resource.instance.seed,
        )?
        .ok_or(FeeClaimError::Invalid("fee inspection instance missing"))?;
        if instance.context != resource.context
            || instance.code != resource.code
            || execution::local_execution::instance_target(
                local_execution::original_resolver(resolver, history, &instance.context)?,
                &instance,
            )? != resource.instance
        {
            return Err(FeeClaimError::Invalid("fee inspection instance target"));
        }
        let reference: &ObjectRef = escrow
            .settlement
            .fee_output
            .as_ref()
            .ok_or(FeeClaimError::Invalid("fee inspection output missing"))?;
        let mut total_body_bytes: usize = 0;
        let snapshot: object_snapshots::ObjectSnapshot = object_snapshots::load_object_snapshot(
            store,
            blob_store,
            operation,
            domain,
            expected.chain_id(),
            reference,
            &mut total_body_bytes,
        )?;
        let next_nonce: u64 = query::query_sender_next_nonce(
            store,
            operation,
            domain,
            expected.chain_id().clone(),
            expected.protocol_version(),
            expected.epoch(),
            leg_sender,
        )?;
        Some(FeeClaimExecutionView {
            resource,
            instance,
            interface: loaded.interface,
            policy: leg_policy.clone(),
            fee_output: snapshot.object,
            next_nonce,
            minimum_checkpoint: snapshot.created_checkpoint,
        })
    } else {
        None
    };
    Ok(FeeClaimInspection {
        escrow,
        entitlement,
        execution,
    })
}

/// Discovers and independently verifies exact chain-scoped settlement keys.
/// A page can miss keys inserted behind its cursor; require quiescence and
/// restart the sweep after any writer activity. Deletion/rollback is unproved.
#[allow(clippy::too_many_arguments)]
pub fn discover_fee_escrows_page<S: DurableStateKeyScanner>(
    store: &S,
    blob_store: &dyn BlobStore,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    after: Option<Vec<u8>>,
    limit: NonZeroUsize,
) -> Result<FeeEscrowDiscoveryPage, FeeClaimError> {
    require_preparation_context(resolver, history, expected)?;
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    mutation_fence::fence_current_epoch(
        store,
        operation,
        domain,
        expected.chain_id(),
        expected.epoch(),
        &mut reads,
    )?;
    let mut prefix: Vec<u8> = local_instance_state::FASTPATH_STATE_PREFIX.to_vec();
    prefix.extend_from_slice(b"settlement/");
    prefix.extend(encode_chain_id(expected.chain_id())?);
    let scan: StateKeyScan = StateKeyScan::new(prefix.clone(), after, limit)?;
    let page: StateKeyPage = store.scan_durable_keys(operation, domain, &scan)?;
    let mut escrows: Vec<FeeEscrowInspection> = Vec::with_capacity(page.keys().len());
    for key in page.keys() {
        let request_id: [u8; 32] = key
            .strip_prefix(prefix.as_slice())
            .ok_or(FeeClaimError::Invalid("fee discovery key prefix"))?
            .try_into()
            .map_err(|_| FeeClaimError::Invalid("fee discovery key shape"))?;
        if key != &local_instance_state::fastpath_settlement_key(expected.chain_id(), &request_id)?
        {
            return Err(FeeClaimError::Invalid("fee discovery key mismatch"));
        }
        escrows.push(inspect_fee_escrow_with_verifier(
            store,
            operation,
            domain,
            resolver,
            history,
            expected,
            request_id,
            || {
                inventory::verify_fee_claim_history_scanned(
                    store,
                    blob_store,
                    operation,
                    domain,
                    resolver,
                    history,
                    expected.chain_id(),
                    &request_id,
                )
            },
        )?);
    }
    Ok(FeeEscrowDiscoveryPage {
        escrows,
        continuation_cursor: page.continuation_cursor().map(<[u8]>::to_vec),
    })
}

pub(super) fn require_fee_resource(
    resource: &FastPathEconomicsResourcePolicy,
    fee_policy: &PaidFeePolicy,
) -> Result<(), FeeClaimError> {
    if !resource.fee_escrow
        || resource.context != *fee_policy.code.context()
        || resource.code != fee_policy.code
        || resource.instance != fee_policy.instance
        || resource.ty != fee_policy.asset_type
        || resource.schema != fee_policy.schema
    {
        return Err(FeeClaimError::Invalid(
            "fee resource is not fee-escrow enabled by the committed economics policy",
        ));
    }
    Ok(())
}

pub(super) fn advance_claim_row(
    settlement: &FastPathSettlementRecord,
    share_index: usize,
    output: Option<(ObjectRef, Epoch)>,
) -> Result<FastPathSettlementRecord, FeeClaimError> {
    let mut next: FastPathSettlementRecord = settlement.clone();
    next.generation = next
        .generation
        .checked_add(1)
        .ok_or(FeeClaimError::Invalid("fee claim generation overflow"))?;
    next.shares[share_index].claimed = true;
    if let Some((reference, epoch)) = output {
        next.fee_output = Some(reference);
        next.fee_output_epoch = Some(epoch);
    }
    Ok(next)
}

pub(super) struct ExecutedFeeClaim {
    pub(super) next_settlement: FastPathSettlementRecord,
    pub(super) payout: Option<ObjectRef>,
    pub(super) head_reads: Vec<DurableObjectHeadRead>,
    pub(super) object_mutations: Vec<DurableObjectMutationEntry>,
    pub(super) state_mutations: Vec<StateMutationEntry>,
}

fn reference_from_effect(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    object: &Object,
) -> Result<ObjectRef, FeeClaimError> {
    let bytes: Vec<u8> = objects::encode_object(object)
        .map_err(|_| FeeClaimError::Invalid("invalid fee claim output encoding"))?;
    Ok(ObjectRef {
        id: object.id,
        version: object.version,
        digest: resolver.hash_for_purpose(epoch, HashPurpose::Object, &bytes)?,
    })
}

/// Shared actual execution/effect derivation. Builds pending writes only;
/// preparation discards them and apply puts them in its independent CAS.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute_positive_claim<S, E>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    leg_policy: &LocalExecutionPolicy,
    engine: &E,
    intent: &FeeClaimIntent,
    settlement: &FastPathSettlementRecord,
    leg: &AuthenticatedLocalExecutionIntent,
    share_index: usize,
    unclaimed_positive_total: u64,
    is_final: bool,
    created_checkpoint: u64,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<ExecutedFeeClaim, FeeClaimError>
where
    S: StructuredDurableDomainStateStore,
    E: LocalContractEngine + ?Sized,
{
    let (fee_policy, policy): (PaidFeePolicy, FastPathEconomicsPolicy) =
        read_economics_policy(store, context, domain, &settlement.context, reads)?;
    let resource: &FastPathEconomicsResourcePolicy = resource_policy(&policy, intent.resource_id)?;
    require_fee_resource(resource, &fee_policy)?;
    let fee_output: &ObjectRef = settlement
        .fee_output
        .as_ref()
        .ok_or(FeeClaimError::Invalid("fee claim output missing"))?;
    let scope: ProtocolCustodyScope = fee_escrow_scope(
        &settlement.context,
        settlement.request_id,
        intent.resource_id,
    );
    let entrypoint: &str = if is_final {
        &resource.transfer_entrypoint
    } else {
        &resource.split_entrypoint
    };
    let (capability, leg_event_digest): (ProtocolCustodyCapability, Digest32) =
        fee_claim_capability(
            resolver,
            &intent.context,
            resource,
            scope.clone(),
            fee_output,
            intent.recipient,
            entrypoint,
            leg,
        )?;
    let call = &leg.intent().call;
    let nonce: PendingSenderNonceWrite = durable_reconciliation::reserve_sender_nonce_range(
        store,
        context,
        domain,
        &PersistenceLayout::new(
            intent.context.chain_id().clone(),
            intent.context.protocol_version(),
        ),
        SenderNonceReservation {
            sender: call.sender,
            epoch: intent.context.epoch(),
            nonce: call.nonce,
        },
        1,
    )?;
    let mut head_reads: Vec<DurableObjectHeadRead> = Vec::new();
    let mut state_mutations: Vec<StateMutationEntry> = Vec::new();
    let allowed_output: Option<(ObjectId, &ProtocolCustodyScope)> = if is_final {
        None
    } else {
        Some((fee_output.id, &scope))
    };
    let admitted: AdmittedLeg = admit_and_execute_leg(
        store,
        blob_store,
        context,
        domain,
        resolver,
        history,
        leg_policy,
        engine,
        leg,
        leg_event_digest,
        Some(&capability),
        CustodyEffectMode::Translate {
            allowed_protocol_custody_output: allowed_output,
        },
        created_checkpoint,
        reads,
        &mut head_reads,
        &mut state_mutations,
    )?;
    if !admitted.success {
        return Err(FeeClaimError::Invalid("fee claim leg trapped"));
    }
    let snapshot: &object_snapshots::ObjectSnapshot = admitted
        .snapshots
        .get(&fee_output.id)
        .ok_or(FeeClaimError::Invalid("fee claim escrow snapshot missing"))?;
    let input = admitted
        .inputs
        .iter()
        .find(|input| input.resolved.object.id == fee_output.id)
        .ok_or(FeeClaimError::Invalid("fee claim escrow input missing"))?;
    let expected_transfer: effects::ExpectedFeeClaim<'_> = effects::ExpectedFeeClaim {
        escrow_id: fee_output.id,
        escrow_scope: &scope,
        resource_authority: &input.authority,
        recipient: intent.recipient,
        unclaimed_before: unclaimed_positive_total,
        claim_amount: intent.share_amount,
    };
    let validated: effects::ValidatedFeeClaim = effects::validate(
        &admitted.interface,
        &admitted.created_authorities,
        &expected_transfer,
        created_checkpoint,
        snapshot,
        &admitted.effects,
        is_final,
    )?;
    let (resulting_object, payout): (Object, Option<ObjectRef>) = match validated {
        effects::ValidatedFeeClaim::Split { retained, released } => (
            retained,
            Some(reference_from_effect(
                resolver,
                intent.context.epoch(),
                &released,
            )?),
        ),
        effects::ValidatedFeeClaim::Final { transferred } => (transferred, None),
    };
    let output: ObjectRef =
        reference_from_effect(resolver, intent.context.epoch(), &resulting_object)?;
    let next_settlement: FastPathSettlementRecord = advance_claim_row(
        settlement,
        share_index,
        Some((output, intent.context.epoch())),
    )?;
    if let Some(previous) = reads.insert(nonce.key.clone(), nonce.read_revision)
        && previous != nonce.read_revision
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    state_mutations.push(StateMutationEntry::new(
        nonce.key,
        StateMutation::Put(nonce.record.encode()?),
    )?);
    Ok(ExecutedFeeClaim {
        next_settlement,
        payout,
        head_reads,
        object_mutations: admitted.object_mutations,
        state_mutations,
    })
}

/// Executes the defining public contract provisionally and constructs the
/// exact unsigned claim. Does not write or reserve any durable state. Even
/// a successful preview must be independently authenticated and applied.
#[allow(clippy::too_many_arguments)]
pub fn prepare_fee_claim<S, E>(
    store: &S,
    blob_store: &dyn BlobStore,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    leg_policy: &LocalExecutionPolicy,
    engine: &E,
    request: FeeClaimPreparationRequest<'_>,
    created_checkpoint: u64,
) -> Result<PreparedFeeClaim, FeeClaimError>
where
    S: StructuredDurableDomainStateStore,
    E: LocalContractEngine + ?Sized,
{
    require_preparation_context(resolver, history, expected)?;
    local_instance_state::reject_reserved_request_id(&request.request_id)
        .map_err(FeeClaimError::Invalid)?;
    if let Some(bytes) = request.signed_leg
        && (bytes.is_empty()
            || bytes.len() > execution::local_execution::MAX_LOCAL_EXECUTION_INTENT_BYTES)
    {
        return Err(FeeClaimError::Invalid("fee preparation leg byte bound"));
    }
    validate_ed25519_owner_address(
        request.recipient.as_bytes(),
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )
    .map_err(|_| FeeClaimError::Invalid("fee preparation recipient address"))?;
    let escrow: FeeEscrowInspection = inspect_fee_escrow(
        store,
        blob_store,
        operation,
        domain,
        resolver,
        history,
        expected,
        request.escrow_request_id,
    )?;
    let claimant: &FeeClaimEntitlement = escrow
        .claimants
        .iter()
        .find(|share| share.validator_id == request.validator_id)
        .ok_or(FeeClaimError::Invalid(
            "fee preparation validator has no share",
        ))?;
    if claimant.authorization_key != request.claimant_public_key {
        return Err(FeeClaimError::Invalid(
            "fee preparation historical claimant key",
        ));
    }
    let kind: FeeClaimKind = claimant.kind.ok_or(FeeClaimError::Invalid(
        "fee preparation share already claimed",
    ))?;
    let request_id: DurableRequestId = DurableRequestId::new(request.request_id)
        .map_err(|_| FeeClaimError::Invalid("fee preparation request id"))?;
    if store
        .get_request_receipt(operation, domain, request_id)?
        .is_some()
    {
        return Err(FeeClaimError::Invalid(
            "fee preparation request id already used; replay original artifact",
        ));
    }
    let claim_operation: FeeClaimOperation = match (kind, request.signed_leg) {
        (FeeClaimKind::ZeroShare, None) => FeeClaimOperation::ZeroShare,
        (FeeClaimKind::Split, Some(bytes)) => FeeClaimOperation::Split {
            leg: bytes.to_vec(),
            expected_payout: None,
        },
        (FeeClaimKind::FinalTransfer, Some(bytes)) => FeeClaimOperation::FinalTransfer {
            leg: bytes.to_vec(),
        },
        _ => {
            return Err(FeeClaimError::Invalid(
                "fee preparation leg does not match derived kind",
            ));
        }
    };
    let previous_digest: Digest32 = fee_claim_row_digest(
        resolver,
        escrow.settlement.context.epoch(),
        &escrow.canonical_settlement,
    )?;
    let mut intent: FeeClaimIntent = FeeClaimIntent {
        context: expected.clone(),
        request_id: request.request_id,
        escrow_request_id: request.escrow_request_id,
        certificate_epoch: escrow.settlement.context.epoch(),
        validator_id: request.validator_id,
        resource_id: escrow.settlement.resource_id.ok_or(FeeClaimError::Invalid(
            "fee preparation uncharged settlement",
        ))?,
        expected_generation: escrow.settlement.generation,
        expected_fee_output: escrow
            .settlement
            .fee_output
            .clone()
            .ok_or(FeeClaimError::Invalid("fee preparation output missing"))?,
        expected_previous_row_digest: previous_digest,
        expected_next_row_digest: previous_digest,
        share_amount: claimant.amount,
        recipient: request.recipient,
        operation: claim_operation,
    };
    let (share_index, unclaimed_total, is_final): (usize, u64, bool) =
        derive_claim_kind(&escrow.settlement, &intent)?;
    let (next_settlement, expected_payout): (FastPathSettlementRecord, Option<ObjectRef>) =
        if kind == FeeClaimKind::ZeroShare {
            (
                advance_claim_row(&escrow.settlement, share_index, None)?,
                None,
            )
        } else {
            let bytes: &[u8] = request
                .signed_leg
                .ok_or(FeeClaimError::Invalid("fee preparation leg missing"))?;
            let leg: AuthenticatedLocalExecutionIntent =
                authenticate_local_execution(resolver, leg_policy, bytes)?;
            if leg.intent().call.request_id != request.request_id {
                return Err(FeeClaimError::Invalid("fee claim leg request id mismatch"));
            }
            let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
            let executed: ExecutedFeeClaim = execute_positive_claim(
                store,
                blob_store,
                operation,
                domain,
                resolver,
                history,
                leg_policy,
                engine,
                &intent,
                &escrow.settlement,
                &leg,
                share_index,
                unclaimed_total,
                is_final,
                created_checkpoint,
                &mut reads,
            )?;
            (executed.next_settlement, executed.payout)
        };
    if let FeeClaimOperation::Split {
        expected_payout: field,
        ..
    } = &mut intent.operation
    {
        *field = expected_payout.clone();
    }
    intent.expected_next_row_digest = fee_claim_row_digest(
        resolver,
        escrow.settlement.context.epoch(),
        &encode_fastpath_settlement_record(&next_settlement)?,
    )?;
    let _: Vec<u8> = codec::encode_fee_claim_intent(&intent)?;
    Ok(PreparedFeeClaim {
        intent,
        next_settlement,
        expected_payout,
    })
}
