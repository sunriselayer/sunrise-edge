//! DR-0153 §"Shared ordering and owned reservations are different".
//!
//! An economic leg can consume *address-owned* input objects and a sender
//! nonce. Admission reserves precisely those inputs using the **same durable
//! lock keys and record layouts FastVote itself uses**
//! ([`local_instance_state::FastPathLockRecord`] at
//! [`local_instance_state::fastpath_lock_key`], and
//! [`local_instance_state::FastPathNonceLockRecord`] at
//! [`local_instance_state::fastpath_nonce_lock_key`]), atomically with the
//! candidate/vote record. That is what stops a fast transaction from racing
//! an ordered leg.
//!
//! What is deliberately **never** reserved:
//!
//! * a protocol-custody object (the bond custody object a `Withdraw`,
//!   `Replace` release or slash forfeiture leg spends, or the fee-escrow
//!   output a fee claim spends). Those mutations happen only in the ordered
//!   execution path and must stay orderable between competing legitimate
//!   claimants;
//! * a settlement/bond row generation;
//! * any global "first candidate wins" gate.
//!
//! Which inputs are address-owned is decided *structurally* from DR-0153's
//! closed operation set, not by guessing from storage: only a bond
//! deposit/reactivate leg (and `Replace`'s deposit leg) spends a
//! sender-owned source object. Every other leg's single write entry is the
//! protocol-custody object by construction, and the existing handler proves
//! that with its own custody capability.
use super::*;
use canonical_encoding::{encode_chain_id, encode_digest32};
use execution::local_execution::{AuthenticatedLocalExecutionIntent, authenticate_local_execution};
use fee_claims::codec::{FeeClaimOperation, decode_signed_fee_claim_intent};
use local_instance_state::{
    FastPathLockRecord, FastPathNonceLockRecord, decode_fastpath_lock_record,
    decode_fastpath_nonce_lock_record, encode_fastpath_lock_record,
    encode_fastpath_nonce_lock_record, fastpath_lock_key, fastpath_nonce_lock_key,
};
use runtime::DurableObjectHeadRead;

const ORDERED_RESERVATION_RECORD_TYPE: u16 = 0x644A;
const ENCODING_VERSION: u16 = 1;

/// The exact sender/epoch nonce range one admitted ordered candidate holds.
///
/// `first_nonce` is the value actually stored in the FastVote nonce-lock row.
/// `count` is how many *consecutive* nonces the signed operation covers: one
/// for every single-leg operation, two for
/// [`bond_lifecycle::BondLifecycleOperation::Replace`]'s consecutive
/// deposit/release legs. The second leg therefore authorizes against
/// `first_nonce + 1` while the lock row still records `first_nonce` -- which
/// is why [`Self::covers`] checks range membership instead of requiring every
/// leg to start at the same nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OrderedNonceLockHeld {
    pub(crate) sender: [u8; 32],
    pub(crate) epoch: Epoch,
    pub(crate) first_nonce: u64,
    pub(crate) count: u64,
}

impl OrderedNonceLockHeld {
    /// Whether `nonce` falls inside the exact signed, reserved range for this
    /// sender/epoch.
    fn covers(&self, sender: &[u8; 32], epoch: Epoch, nonce: u64) -> bool {
        let Some(end) = self.first_nonce.checked_add(self.count) else {
            return false;
        };
        &self.sender == sender && self.epoch == epoch && nonce >= self.first_nonce && nonce < end
    }
}

/// One admitted candidate's complete reservation set, derived purely from its
/// own canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct OrderedReservationPlan {
    /// Exact address-owned object refs to lock, in leg order.
    pub(crate) objects: Vec<ObjectRef>,
    /// Exact sender/epoch nonce range to lock, when the operation has a leg.
    pub(crate) nonce: Option<OrderedNonceLockHeld>,
}

impl OrderedReservationPlan {
    pub(crate) fn is_empty(&self) -> bool {
        self.objects.is_empty() && self.nonce.is_none()
    }
}

/// A private capability proving that one exact ordered candidate already
/// holds exactly these FastVote reservations, under its own request id.
///
/// Threading this into `local_execution::admit_and_execute_leg` is the *only*
/// way an ordered leg may fence a lock as
/// [`crate::mutation_fence::LockMode::OwnedByRequest`] rather than
/// [`crate::mutation_fence::LockMode::Fresh`]. It authorizes nothing beyond
/// the exact `ObjectRef`s and the exact nonce range listed here, and only
/// under the same `request_id`: it is not a blanket lock bypass and it masks
/// no storage value.
pub(crate) struct OrderedLegAdmission<'a> {
    /// The exact admitted candidate's request id, which must equal the
    /// authorizing leg's own signed `CallIntent::request_id`.
    pub(crate) request_id: [u8; 32],
    /// Exact object refs whose current-epoch FastVote locks this request
    /// holds.
    pub(crate) objects: &'a [ObjectRef],
    /// Exact sender/epoch nonce range this request holds.
    pub(crate) nonce: Option<OrderedNonceLockHeld>,
}

impl OrderedLegAdmission<'_> {
    /// Whether this admission authorizes owned-lock reuse for exactly
    /// `object_ref` under exactly `request_id`.
    pub(crate) fn owns_object(&self, request_id: &[u8; 32], object_ref: &ObjectRef) -> bool {
        &self.request_id == request_id && self.objects.iter().any(|held| held == object_ref)
    }

    /// Returns the nonce-lock row's recorded first nonce when this admission
    /// authorizes owned-lock reuse for exactly `(sender, epoch, nonce)` under
    /// exactly `request_id`, else `None`.
    pub(crate) fn owned_nonce_lock_value(
        &self,
        request_id: &[u8; 32],
        sender: &[u8; 32],
        epoch: Epoch,
        nonce: u64,
    ) -> Option<u64> {
        if &self.request_id != request_id {
            return None;
        }
        let held: OrderedNonceLockHeld = self.nonce?;
        held.covers(sender, epoch, nonce)
            .then_some(held.first_nonce)
    }
}

/// Internal bookkeeping identity only. Its typed receipt carries no business
/// output and never represents completion of the original Ordered request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OrderedAdmissionStage {
    LeaderProposal = 1,
    Vote = 2,
}

/// Pure authenticated selectors for isolated causal reconstruction. These
/// are required producer observations, never authority to seed source rows.
pub(crate) struct OrderedCausalRequirements {
    pub(crate) objects: Vec<ObjectRef>,
    pub(crate) nonce: Option<OrderedNonceLockHeld>,
    pub(crate) legs: Vec<AuthenticatedLocalExecutionIntent>,
    pub(crate) fee_escrow_request_id: Option<[u8; 32]>,
}

pub(crate) fn ordered_causal_requirements(
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) -> Result<OrderedCausalRequirements, OrderedEconomicsError> {
    authenticate_candidate(env, candidate)?;
    let plan: OrderedReservationPlan = reservation_plan(env, candidate)?;
    let mut legs: Vec<Vec<u8>> = Vec::new();
    let mut fee_escrow_request_id: Option<[u8; 32]> = None;
    match candidate.kind {
        OrderedOperationKind::FeeClaim => {
            let signed = decode_signed_fee_claim_intent(&candidate.intent).map_err(|_| {
                OrderedEconomicsError::Unauthenticated("invalid fee claim candidate")
            })?;
            fee_escrow_request_id = Some(signed.intent.escrow_request_id);
            match signed.intent.operation {
                FeeClaimOperation::ZeroShare => {}
                FeeClaimOperation::Split { leg, .. } | FeeClaimOperation::FinalTransfer { leg } => {
                    legs.push(leg)
                }
            }
        }
        OrderedOperationKind::BondLifecycle => {
            let signed = bond_lifecycle::decode_signed_bond_lifecycle_intent(&candidate.intent)
                .map_err(|_| OrderedEconomicsError::Unauthenticated("invalid bond candidate"))?;
            legs.extend(
                policy::bond_lifecycle_legs(&signed.intent.operation)
                    .into_iter()
                    .map(<[u8]>::to_vec),
            );
        }
        OrderedOperationKind::BondRegistration => {
            let signed = bond_lifecycle::registration::decode_signed_bond_registration_intent(
                &candidate.intent,
            )
            .map_err(|_| {
                OrderedEconomicsError::Unauthenticated("invalid registration candidate")
            })?;
            legs.push(signed.intent.leg);
        }
        OrderedOperationKind::BondSlash => {
            let intent = bond_lifecycle::slash::decode_slash_intent(&candidate.intent)
                .map_err(|_| OrderedEconomicsError::Unauthenticated("invalid slash candidate"))?;
            legs.push(intent.leg);
        }
        OrderedOperationKind::Evidence
        | OrderedOperationKind::Freeze
        | OrderedOperationKind::DrainSet => {}
    }
    let authenticated: Vec<AuthenticatedLocalExecutionIntent> = legs
        .into_iter()
        .map(|bytes| {
            authenticate_local_execution(env.resolver(), env.leg_policy, &bytes).map_err(|_| {
                OrderedEconomicsError::Unauthenticated("invalid causal prerequisite leg")
            })
        })
        .collect::<Result<Vec<_>, OrderedEconomicsError>>()?;
    Ok(OrderedCausalRequirements {
        objects: plan.objects,
        nonce: plan.nonce,
        legs: authenticated,
        fee_escrow_request_id,
    })
}

/// Distinct from the unchanged owned prepare derivation. All suffix fields
/// have fixed widths; the resolver supplies the trusted chain/protocol hash
/// domain and the epoch is also explicit, not only suite selection.
pub(crate) fn ordered_admission_request_id(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    original: &[u8; 32],
    candidate_digest: Digest32,
    stage: OrderedAdmissionStage,
    view: u64,
) -> Result<[u8; 32], NodeCoreError> {
    let mut preimage: Vec<u8> = b"se-ordered-admission-receipt-v1".to_vec();
    preimage.extend_from_slice(&epoch.get().to_be_bytes());
    preimage.extend_from_slice(original);
    preimage.extend(encode_digest32(&candidate_digest)?);
    preimage.push(stage as u8);
    preimage.extend_from_slice(&view.to_be_bytes());
    let digest: Digest32 = resolver.hash_for_purpose(epoch, HashPurpose::NodeEvent, &preimage)?;
    let tag: &[u8; 8] = &local_instance_state::FASTPATH_SYNTHETIC_REQUEST_ID_TAG;
    let mut request_id: [u8; 32] = [0; 32];
    request_id[..tag.len()].copy_from_slice(tag);
    request_id[tag.len()..].copy_from_slice(&digest.bytes()[tag.len()..]);
    Ok(request_id)
}

/// Captures exact committed cross-lane admission prerequisites, never effects.
/// Missing, future or incompatible observations stop before reservations or
/// signatures. Prefix-derived custody/economics are deliberately not locked.
pub(crate) fn verify_causal_prerequisites<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    plan: &OrderedReservationPlan,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    head_reads: &mut Vec<DurableObjectHeadRead>,
) -> Result<(), OrderedEconomicsError> {
    if let Some(nonce) = plan.nonce {
        let layout: PersistenceLayout = PersistenceLayout::new(
            env.policy.context().chain_id().clone(),
            env.policy.context().protocol_version(),
        );
        let pending: PendingSenderNonceWrite = durable_reconciliation::reserve_sender_nonce_range(
            store, context, env.policy.domain(), &layout,
            SenderNonceReservation {
                sender: nonce.sender, epoch: nonce.epoch, nonce: nonce.first_nonce,
            }, nonce.count,
        ).map_err(|error| match error {
            NodeCoreError::SenderNonceMismatch { .. } => OrderedEconomicsError::Prerequisite(
                "ordered admission requires the exact committed next nonce; verified recovery required",
            ),
            other => OrderedEconomicsError::Node(other),
        })?;
        if reads
            .insert(pending.key, pending.read_revision)
            .is_some_and(|previous| previous != pending.read_revision)
        {
            return Err(NodeCoreError::StateConflict.into());
        }
    }
    match candidate.kind {
        OrderedOperationKind::FeeClaim => {
            let signed = decode_signed_fee_claim_intent(&candidate.intent).map_err(|_| {
                OrderedEconomicsError::Unauthenticated("invalid fee claim candidate intent")
            })?;
            // Owned leg bytes below are borrowed from this local decoded
            // value, so perform their verification inside this branch.
            match &signed.intent.operation {
                FeeClaimOperation::ZeroShare => {}
                FeeClaimOperation::Split { leg, .. } | FeeClaimOperation::FinalTransfer { leg } => {
                    verify_causal_leg(store, context, env, leg, plan, reads, head_reads)?;
                }
            }
        }
        OrderedOperationKind::BondLifecycle => {
            let signed = bond_lifecycle::decode_signed_bond_lifecycle_intent(&candidate.intent)
                .map_err(|_| {
                    OrderedEconomicsError::Unauthenticated("invalid bond lifecycle candidate")
                })?;
            for leg in policy::bond_lifecycle_legs(&signed.intent.operation) {
                verify_causal_leg(store, context, env, leg, plan, reads, head_reads)?;
            }
        }
        OrderedOperationKind::BondSlash => {
            let intent = bond_lifecycle::slash::decode_slash_intent(&candidate.intent)
                .map_err(|_| OrderedEconomicsError::Unauthenticated("invalid slash candidate"))?;
            verify_causal_leg(store, context, env, &intent.leg, plan, reads, head_reads)?;
        }
        OrderedOperationKind::BondRegistration => {
            use bond_lifecycle::registration::{BondRegistrationError, BondRegistrationRefusal};
            match bond_lifecycle::registration::verify_registration_admission(
                store, context, env, candidate, reads,
            ) {
                Ok(())
                | Err(BondRegistrationError::Refused(BondRegistrationRefusal::AlreadyRegistered)) =>
                    {}
                Err(error) => return Err(bond_registration_failure(&error)),
            }
            let signed = bond_lifecycle::registration::decode_signed_bond_registration_intent(
                &candidate.intent,
            )
            .map_err(|_| {
                OrderedEconomicsError::Unauthenticated("invalid registration candidate")
            })?;
            verify_causal_leg(
                store,
                context,
                env,
                &signed.intent.leg,
                plan,
                reads,
                head_reads,
            )?;
        }
        OrderedOperationKind::Evidence
        | OrderedOperationKind::Freeze
        | OrderedOperationKind::DrainSet => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_causal_leg<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    bytes: &[u8],
    plan: &OrderedReservationPlan,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    head_reads: &mut Vec<DurableObjectHeadRead>,
) -> Result<(), OrderedEconomicsError> {
    let leg: AuthenticatedLocalExecutionIntent =
        authenticate_local_execution(env.resolver(), env.leg_policy, bytes)
            .map_err(|_| OrderedEconomicsError::Unauthenticated("invalid ordered candidate leg"))?;
    let reserved: Vec<ObjectRef> = plan
        .objects
        .iter()
        .filter(|reference| {
            leg.intent()
                .call
                .access
                .entries
                .iter()
                .any(|entry| &entry.object_ref == *reference)
        })
        .cloned()
        .collect();
    crate::local_execution::verify_ordered_leg_prerequisites(
        store, env.blobs, context, env.policy.domain(), env.resolver(), env.history,
        env.leg_policy, &leg, &reserved, reads, head_reads,
    ).map_err(|_| OrderedEconomicsError::Prerequisite(
        "ordered admission requires verified exact executable/source material; recovery required",
    ))
}

/// Purely derives the exact reservation set one candidate needs.
///
/// Called only after [`super::authenticate_candidate`] has already proven
/// every embedded leg's signature, request id and context, so re-decoding
/// here cannot admit an unauthenticated leg.
pub(crate) fn reservation_plan(
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) -> Result<OrderedReservationPlan, OrderedEconomicsError> {
    let epoch: Epoch = candidate.context.epoch();
    let authenticate =
        |leg: &[u8]| -> Result<AuthenticatedLocalExecutionIntent, OrderedEconomicsError> {
            authenticate_local_execution(env.resolver(), env.leg_policy, leg).map_err(|_| {
                OrderedEconomicsError::Unauthenticated("invalid ordered candidate leg signature")
            })
        };
    /// The single address-owned `Write`/`Consume` source object one bond
    /// deposit leg declares. Any other shape is not a deposit leg and is
    /// rejected purely rather than silently reserved.
    fn deposit_source(
        leg: &AuthenticatedLocalExecutionIntent,
    ) -> Result<ObjectRef, OrderedEconomicsError> {
        let entries = &leg.intent().call.access.entries;
        match entries.as_slice() {
            [entry] if entry.mode == AccessMode::Write => Ok(entry.object_ref.clone()),
            _ => Err(OrderedEconomicsError::Unauthenticated(
                "bond deposit leg must declare exactly one write input",
            )),
        }
    }
    let plan: OrderedReservationPlan = match candidate.kind {
        OrderedOperationKind::FeeClaim => {
            let signed = decode_signed_fee_claim_intent(&candidate.intent).map_err(|_| {
                OrderedEconomicsError::Unauthenticated("invalid fee claim candidate intent")
            })?;
            match &signed.intent.operation {
                // A zero-share claim executes no leg at all: nothing to
                // reserve, and in particular no nonce to hold.
                FeeClaimOperation::ZeroShare => OrderedReservationPlan::default(),
                FeeClaimOperation::Split { leg, .. } | FeeClaimOperation::FinalTransfer { leg } => {
                    let authenticated = authenticate(leg)?;
                    let call = &authenticated.intent().call;
                    // The claim's input is the protocol-custody fee output,
                    // never the claimant's own object: reserve the nonce
                    // only.
                    OrderedReservationPlan {
                        objects: Vec::new(),
                        nonce: Some(OrderedNonceLockHeld {
                            sender: call.sender,
                            epoch,
                            first_nonce: call.nonce,
                            count: 1,
                        }),
                    }
                }
            }
        }
        OrderedOperationKind::BondRegistration => {
            let signed = bond_lifecycle::registration::decode_signed_bond_registration_intent(
                &candidate.intent,
            )
            .map_err(|_| {
                OrderedEconomicsError::Unauthenticated("invalid registration candidate")
            })?;
            let authenticated = authenticate(&signed.intent.leg)?;
            let call = &authenticated.intent().call;
            OrderedReservationPlan {
                objects: vec![deposit_source(&authenticated)?],
                nonce: Some(OrderedNonceLockHeld {
                    sender: call.sender,
                    epoch,
                    first_nonce: call.nonce,
                    count: 1,
                }),
            }
        }
        OrderedOperationKind::BondLifecycle => {
            let signed = bond_lifecycle::decode_signed_bond_lifecycle_intent(&candidate.intent)
                .map_err(|_| {
                    OrderedEconomicsError::Unauthenticated(
                        "invalid bond lifecycle candidate intent",
                    )
                })?;
            match &signed.intent.operation {
                // No leg, no contract execution, no sender nonce.
                bond_lifecycle::BondLifecycleOperation::Unbond { .. } => {
                    OrderedReservationPlan::default()
                }
                bond_lifecycle::BondLifecycleOperation::Deposit { leg }
                | bond_lifecycle::BondLifecycleOperation::Reactivate { leg } => {
                    let authenticated = authenticate(leg)?;
                    let call = &authenticated.intent().call;
                    OrderedReservationPlan {
                        objects: vec![deposit_source(&authenticated)?],
                        nonce: Some(OrderedNonceLockHeld {
                            sender: call.sender,
                            epoch,
                            first_nonce: call.nonce,
                            count: 1,
                        }),
                    }
                }
                // The release leg spends the protocol-custody object: only
                // the deposit leg's own source is reserved. Both legs share
                // one consecutive two-nonce range under one lock row.
                bond_lifecycle::BondLifecycleOperation::Replace { deposit_leg, .. } => {
                    let authenticated = authenticate(deposit_leg)?;
                    let call = &authenticated.intent().call;
                    OrderedReservationPlan {
                        objects: vec![deposit_source(&authenticated)?],
                        nonce: Some(OrderedNonceLockHeld {
                            sender: call.sender,
                            epoch,
                            first_nonce: call.nonce,
                            count: 2,
                        }),
                    }
                }
                // Releases the protocol-custody object: nonce only.
                bond_lifecycle::BondLifecycleOperation::Withdraw { leg } => {
                    let authenticated = authenticate(leg)?;
                    let call = &authenticated.intent().call;
                    OrderedReservationPlan {
                        objects: Vec::new(),
                        nonce: Some(OrderedNonceLockHeld {
                            sender: call.sender,
                            epoch,
                            first_nonce: call.nonce,
                            count: 1,
                        }),
                    }
                }
            }
        }
        OrderedOperationKind::BondSlash => {
            let intent =
                bond_lifecycle::slash::decode_slash_intent(&candidate.intent).map_err(|_| {
                    OrderedEconomicsError::Unauthenticated("invalid bond slash candidate intent")
                })?;
            let authenticated = authenticate(&intent.leg)?;
            let call = &authenticated.intent().call;
            // The forfeiture leg spends protocol custody; its submitter only
            // spends its own nonce.
            OrderedReservationPlan {
                objects: Vec::new(),
                nonce: Some(OrderedNonceLockHeld {
                    sender: call.sender,
                    epoch,
                    first_nonce: call.nonce,
                    count: 1,
                }),
            }
        }
        // Evidence admission commits through a content-addressed absence
        // fence and consumes neither an object nor a nonce.
        OrderedOperationKind::Evidence => OrderedReservationPlan::default(),
        // Freeze and DrainSet are pure control: no address-owned input, no
        // sender nonce.
        OrderedOperationKind::Freeze | OrderedOperationKind::DrainSet => {
            OrderedReservationPlan::default()
        }
    };
    if plan.objects.len() > MAX_ORDERED_RESERVED_OBJECTS {
        return Err(OrderedEconomicsError::Unauthenticated(
            "ordered candidate reserves too many objects",
        ));
    }
    Ok(plan)
}

// --- durable reservation record -------------------------------------------

pub(crate) fn ordered_reservation_key(
    chain: &ChainId,
    request_id: &[u8; 32],
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = super::engine::ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"reservation/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(request_id);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

fn invalid(message: &'static str) -> NodeCoreError {
    NodeCoreError::PersistenceInvariant(message)
}

/// Encodes frame `0x644A/v1`.
pub(crate) fn encode_ordered_reservation(
    plan: &OrderedReservationPlan,
) -> Result<Vec<u8>, NodeCoreError> {
    if plan.objects.len() > MAX_ORDERED_RESERVED_OBJECTS {
        return Err(invalid("ordered reservation object count"));
    }
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(ORDERED_RESERVATION_RECORD_TYPE, ENCODING_VERSION);
    frame.field_u32(
        1,
        u32::try_from(plan.objects.len()).map_err(|_| invalid("ordered reservation objects"))?,
    )?;
    for (index, object_ref) in plan.objects.iter().enumerate() {
        let field: u16 =
            u16::try_from(index + 2).map_err(|_| invalid("ordered reservation objects"))?;
        frame.field_bytes(
            field,
            objects::encode_object_ref(object_ref)
                .map_err(|_| invalid("ordered reservation object ref"))?,
        )?;
    }
    if let Some(nonce) = &plan.nonce {
        frame.field_bytes(10, nonce.sender.to_vec())?;
        frame.field_u64(11, nonce.epoch.get())?;
        frame.field_u64(12, nonce.first_nonce)?;
        frame.field_u64(13, nonce.count)?;
    }
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x644A/v1`.
pub(crate) fn decode_ordered_reservation(
    bytes: &[u8],
) -> Result<OrderedReservationPlan, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(ORDERED_RESERVATION_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let count: usize = frame.required_u32(1)? as usize;
    if count > MAX_ORDERED_RESERVED_OBJECTS {
        return Err(invalid("ordered reservation object count"));
    }
    let mut fields: Vec<u16> = vec![1];
    let mut object_refs: Vec<ObjectRef> = Vec::with_capacity(count);
    for index in 0..count {
        let field: u16 =
            u16::try_from(index + 2).map_err(|_| invalid("ordered reservation objects"))?;
        fields.push(field);
        object_refs.push(
            objects::decode_object_ref(frame.required_field(field)?)
                .map_err(|_| invalid("ordered reservation object ref"))?,
        );
    }
    let nonce: Option<OrderedNonceLockHeld> = if frame.field(10).is_some() {
        fields.extend_from_slice(&[10, 11, 12, 13]);
        let sender: [u8; 32] = frame
            .required_field(10)?
            .try_into()
            .map_err(|_| invalid("ordered reservation sender length"))?;
        Some(OrderedNonceLockHeld {
            sender,
            epoch: Epoch::new(frame.required_u64(11)?),
            first_nonce: frame.required_u64(12)?,
            count: frame.required_u64(13)?,
        })
    } else {
        None
    };
    frame.require_only_fields(&fields)?;
    let plan: OrderedReservationPlan = OrderedReservationPlan {
        objects: object_refs,
        nonce,
    };
    if plan
        .nonce
        .is_some_and(|nonce| nonce.count == 0 || nonce.count > 2)
    {
        return Err(invalid("ordered reservation nonce range"));
    }
    if encode_ordered_reservation(&plan)? != bytes {
        return Err(invalid("noncanonical ordered reservation"));
    }
    Ok(plan)
}

/// One pending durable write discovered while reconciling reservations.
pub(crate) type PendingWrite = (Vec<u8>, StateRevision, StateMutation);

/// Reads and CAS-fences the exact reservation rows one candidate needs, and
/// returns the writes that would create them.
///
/// Idempotent: if the reservation record already exists it must equal `plan`
/// exactly (an exact retained admitted candidate under the same request id),
/// and every lock row must already be held by this exact request -- in which
/// case nothing is written at all, so an exact re-admission never rewrites a
/// row or increments its revision.
///
/// Fails closed (as a stop, never a rejection) when a lock is currently held
/// by any *other* request: that is a live FastVote prepare or another ordered
/// admission, i.e. a fence, not a semantic outcome.
pub(crate) fn acquire_reservations<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    plan: &OrderedReservationPlan,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<Vec<PendingWrite>, OrderedEconomicsError> {
    let chain: &ChainId = env.policy.context().chain_id();
    let domain: AtomicityDomainId = env.policy.domain();
    let epoch: Epoch = env.policy.context().epoch();
    let record_key: Vec<u8> = ordered_reservation_key(chain, &candidate.request_id)?;
    let observed_record: VersionedStateValue =
        store.read_versioned_state(context, domain, &record_key)?;
    reads.insert(record_key.clone(), observed_record.revision());
    if let Some(bytes) = observed_record.value() {
        let retained: OrderedReservationPlan = decode_ordered_reservation(bytes)?;
        if retained != *plan {
            return Err(OrderedEconomicsError::Prerequisite(
                "retained ordered reservation disagrees with this candidate's own plan",
            ));
        }
        // Exact retained admission: prove every lock is still held by this
        // exact request, then write nothing.
        verify_retained_reservations(store, context, env, candidate, plan, reads)?;
        return Ok(Vec::new());
    }
    if plan.is_empty() {
        return Ok(Vec::new());
    }
    let mut writes: Vec<PendingWrite> = Vec::new();
    for object_ref in &plan.objects {
        let key: Vec<u8> = fastpath_lock_key(chain, object_ref.id)?;
        let observed: VersionedStateValue = store.read_versioned_state(context, domain, &key)?;
        if let Some(bytes) = observed.value() {
            let held: FastPathLockRecord = decode_fastpath_lock_record(bytes)?;
            if held.locked_epoch >= epoch {
                // Current-epoch lock held by someone else, or a lock stamped
                // a future epoch (a storage invariant violation). Either way
                // this admission stops; it never steals a lock.
                return Err(OrderedEconomicsError::Prerequisite(
                    "ordered candidate input is locked by another request",
                ));
            }
            // Strictly older epoch: reclaimable exactly as
            // `mutation_fence::fence_object_lock` under `LockMode::Fresh`
            // already permits, by overwriting under this CAS revision.
        }
        let record: FastPathLockRecord = FastPathLockRecord {
            request_id: candidate.request_id,
            object: object_ref.clone(),
            locked_epoch: epoch,
        };
        writes.push((
            key,
            observed.revision(),
            StateMutation::Put(encode_fastpath_lock_record(&record)?),
        ));
    }
    if let Some(nonce) = &plan.nonce {
        let key: Vec<u8> = fastpath_nonce_lock_key(chain, &nonce.sender, nonce.epoch)?;
        let observed: VersionedStateValue = store.read_versioned_state(context, domain, &key)?;
        if observed.value().is_some() {
            return Err(OrderedEconomicsError::Prerequisite(
                "ordered candidate sender nonce is locked by another request",
            ));
        }
        let record: FastPathNonceLockRecord = FastPathNonceLockRecord {
            request_id: candidate.request_id,
            sender: nonce.sender,
            epoch: nonce.epoch,
            nonce: nonce.first_nonce,
        };
        writes.push((
            key,
            observed.revision(),
            StateMutation::Put(encode_fastpath_nonce_lock_record(&record)?),
        ));
    }
    writes.push((
        record_key,
        observed_record.revision(),
        StateMutation::Put(encode_ordered_reservation(plan)?),
    ));
    Ok(writes)
}

/// Proves every lock row named by a retained reservation is still held by
/// exactly this request id, at exactly this epoch, over exactly this object
/// ref/nonce. Anything else is a stop.
fn verify_retained_reservations<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    plan: &OrderedReservationPlan,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), OrderedEconomicsError> {
    let chain: &ChainId = env.policy.context().chain_id();
    let domain: AtomicityDomainId = env.policy.domain();
    let epoch: Epoch = env.policy.context().epoch();
    for object_ref in &plan.objects {
        let key: Vec<u8> = fastpath_lock_key(chain, object_ref.id)?;
        let observed: VersionedStateValue = store.read_versioned_state(context, domain, &key)?;
        reads.insert(key, observed.revision());
        let bytes: &[u8] = observed.value().ok_or(OrderedEconomicsError::Prerequisite(
            "retained ordered object reservation is absent",
        ))?;
        let held: FastPathLockRecord = decode_fastpath_lock_record(bytes)?;
        if held.request_id != candidate.request_id
            || &held.object != object_ref
            || held.locked_epoch != epoch
        {
            return Err(OrderedEconomicsError::Prerequisite(
                "retained ordered object reservation is not owned by this request",
            ));
        }
    }
    if let Some(nonce) = &plan.nonce {
        let key: Vec<u8> = fastpath_nonce_lock_key(chain, &nonce.sender, nonce.epoch)?;
        let observed: VersionedStateValue = store.read_versioned_state(context, domain, &key)?;
        reads.insert(key, observed.revision());
        let bytes: &[u8] = observed.value().ok_or(OrderedEconomicsError::Prerequisite(
            "retained ordered nonce reservation is absent",
        ))?;
        let held: FastPathNonceLockRecord = decode_fastpath_nonce_lock_record(bytes)?;
        if held.request_id != candidate.request_id
            || held.sender != nonce.sender
            || held.epoch != nonce.epoch
            || held.nonce != nonce.first_nonce
        {
            return Err(OrderedEconomicsError::Prerequisite(
                "retained ordered nonce reservation is not owned by this request",
            ));
        }
    }
    Ok(())
}

/// Loads the reservation this replica durably holds for `request_id`, if any.
/// Returns `None` when this replica never admitted the candidate (for example
/// a signerless observer), in which case every existing handler keeps its
/// ordinary [`crate::mutation_fence::LockMode::Fresh`] behaviour.
pub(crate) fn load_reservation<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    request_id: &[u8; 32],
) -> Result<Option<(OrderedReservationPlan, Vec<u8>, StateRevision)>, OrderedEconomicsError> {
    let key: Vec<u8> = ordered_reservation_key(env.policy.context().chain_id(), request_id)?;
    let observed: VersionedStateValue =
        store.read_versioned_state(context, env.policy.domain(), &key)?;
    match observed.value() {
        None => Ok(None),
        Some(bytes) => Ok(Some((
            decode_ordered_reservation(bytes)?,
            key,
            observed.revision(),
        ))),
    }
}

/// Precisely releases exactly the reservations one retained plan names: one
/// `Delete` per held lock row plus the reservation record itself. Every
/// returned write carries the CAS revision it was read at, so the release is
/// atomic with the business/order commit it is merged into.
///
/// Used both on acceptance and on a typed refusal (a refused candidate must
/// release its own reservations and nothing else). Never used on a stop.
pub(crate) fn release_reservations<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    plan: &OrderedReservationPlan,
    record_key: Vec<u8>,
    record_revision: StateRevision,
) -> Result<Vec<PendingWrite>, OrderedEconomicsError> {
    let chain: &ChainId = env.policy.context().chain_id();
    let domain: AtomicityDomainId = env.policy.domain();
    let mut writes: Vec<PendingWrite> = Vec::new();
    for object_ref in &plan.objects {
        let key: Vec<u8> = fastpath_lock_key(chain, object_ref.id)?;
        let observed: VersionedStateValue = store.read_versioned_state(context, domain, &key)?;
        if observed.value().is_some() {
            writes.push((key, observed.revision(), StateMutation::Delete));
        }
    }
    if let Some(nonce) = &plan.nonce {
        let key: Vec<u8> = fastpath_nonce_lock_key(chain, &nonce.sender, nonce.epoch)?;
        let observed: VersionedStateValue = store.read_versioned_state(context, domain, &key)?;
        if observed.value().is_some() {
            writes.push((key, observed.revision(), StateMutation::Delete));
        }
    }
    writes.push((record_key, record_revision, StateMutation::Delete));
    Ok(writes)
}
