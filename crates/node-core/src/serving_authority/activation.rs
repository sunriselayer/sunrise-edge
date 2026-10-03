//! DR-0189 Sections 6 and 7: the one atomic target activation producer and
//! its reconciliation. No outgoing signature is created: the readiness
//! signing key is reused only to prove the local member identity.

use super::closure::{
    SuccessorRows, derive_successor_rows, require_installed_closure, require_installed_record,
    require_local_member, seal_request_id,
};
use super::*;
use crate::conditional_readiness::ReadinessSigningKey;
use crate::fast_path::records::{
    FastPathBondRecord, FastPathBondState, decode_fastpath_bond_record,
};
use crate::genesis::VerifiedGenesisRoot;
use crate::local_instance_state::{
    FastPathEpochRecord, decode_fastpath_epoch_record, fastpath_bond_record_key,
    fastpath_epoch_transition_key,
};
use crate::logical_generation::{
    GenerationScope, InstalledCommitmentProfile, LogicalDerivation, LogicalWrite, derive_scoped,
    fence_commitment_profile, provenance_mutations_scoped, staged_writes,
};
use crate::ordered_economics::engine::{
    ordered_candidate_record_key, ordered_committed_proof_key, ordered_outcome_key,
    ordered_request_header_key, scoped_applied_height_key, scoped_state_key, scoped_vote_high_key,
};
use crate::ordered_economics::{OrderedEconomicsPolicy, OrderedKeyScope};
use consensus::encode_consensus_state;
use protocol_types::{SignatureSchemeId, ValidatorId};
use runtime::inactive_import::{ImportProgress, InactiveImportRepository, NamespaceLifecycle};
use runtime::portable::{PortableBlobRepository, PortableSnapshotToken};
use runtime::{
    AtomicStateReadSet, DurableCommitOutcome, DurableInvocationTransaction, DurableObjectChanges,
    DurableRequestReceipt, DurableStateTransaction, StateMutation, StateMutationEntry,
    StateReadAssertion, StructuredDurableDomainStateStore, SuccessorServingRecord,
    SuccessorServingRepository, SuccessorServingSlot, VersionedStateReader, VersionedStateValue,
    encode_successor_serving_record,
};

fn invalid(message: &'static str) -> SuccessorActivationError {
    SuccessorActivationError::Invalid(message)
}

fn too_large<E>(_error: E) -> SuccessorActivationError {
    SuccessorActivationError::ActivationTooLarge
}

/// The one producer of a first-successor installation (Section 6.2).
///
/// Steps, all before any write: the full source-free evidence; the
/// protected slot (Serving goes to reconciliation); the full complete
/// inventory comparison returning the fresh creation token; the physical
/// namespace validator, verified member key and Active bond under that key;
/// the activation warrant and generation scope; the complete preflighted
/// transaction and 0x64D5 record; and one port call whose existing outcome
/// is mapped exactly. No signature is created.
#[allow(clippy::too_many_arguments)]
pub fn activate_successor<S, B>(
    plan: BusinessReconstructionPlan<'_>,
    manifest_identity: &OrderedHistoryIdentity,
    artifacts: &mut dyn SuccessorArtifactSource,
    destination: &S,
    destination_blobs: &B,
    operation: &DurableOperationContext,
    signer: &ReadinessSigningKey,
    now_unix_millis: u64,
) -> Result<SuccessorActivationOutcome, SuccessorActivationError>
where
    S: StructuredDurableDomainStateStore + InactiveImportRepository,
    B: PortableBlobRepository,
{
    let root: &VerifiedGenesisRoot = plan.genesis_root;
    // Step 1.
    let evidence: VerifiedSuccessorActivation =
        verify::verify_successor_activation(plan, manifest_identity, artifacts)?;
    let domain: AtomicityDomainId = evidence.policy_inputs.domain;
    // Step 2.
    if let SuccessorServingSlot::Serving(observation) =
        destination.get_successor_serving(operation, domain)?
    {
        return reconcile_serving(
            root,
            &evidence,
            destination,
            operation,
            signer,
            &observation,
        );
    }
    // Step 3.
    let (progress, token): (ImportProgress, PortableSnapshotToken) = evidence
        .import
        .observe_complete(destination, destination_blobs, operation)?;
    if &progress != evidence.import.complete_progress() {
        return Err(invalid("destination completion is not the verified plan"));
    }
    // Step 4.
    let repository: &dyn SuccessorServingRepository = destination
        .successor_serving_repository()
        .ok_or(SuccessorActivationError::Unsupported(
            "destination exposes no successor serving repository",
        ))?;
    let namespace_validator: ValidatorId =
        repository.read_namespace_validator(operation, domain)?;
    if signer.validator_id() != namespace_validator {
        return Err(invalid(
            "physical namespace validator differs from the local signer",
        ));
    }
    let public_key: [u8; 32] = signer.public_key();
    require_local_member(&evidence, namespace_validator, public_key)?;
    let bond: (Vec<u8>, StateRevision) = require_local_bond(
        destination,
        operation,
        &evidence,
        namespace_validator,
        public_key,
    )?;
    // Step 5.
    let warrant: ActivationWarrant = ActivationWarrant {
        evidence,
        progress,
        token,
        namespace_validator,
        public_key,
    };
    // Step 6.
    let transaction: DurableInvocationTransaction = activation_transaction(
        root,
        destination,
        operation,
        &warrant,
        bond,
        now_unix_millis,
    )?;
    let record: Vec<u8> = activation_record(&warrant)?;
    let subject: Digest32 = warrant.evidence.subject_digest;
    let manifest: Digest32 = warrant.evidence.manifest_digest;
    let outcome: DurableCommitOutcome = repository.commit_successor_activation(
        operation,
        domain,
        warrant.evidence.import.binding(),
        &warrant.progress,
        &warrant.token,
        &record,
        transaction,
    );
    // Step 7.
    match outcome {
        DurableCommitOutcome::Committed => {
            Ok(SuccessorActivationOutcome::Activated { subject, manifest })
        }
        DurableCommitOutcome::Rejected(reason) => Err(SuccessorActivationError::Rejected(reason)),
        DurableCommitOutcome::Indeterminate(reason) => {
            // A fresh slot showing this exact record is only a candidate
            // answer: the full immutable reconciliation (origin, barrier,
            // member, record, set, policies, epoch and Seal closure) must
            // also pass before the activation is reported.
            match destination.get_successor_serving(operation, domain) {
                Ok(SuccessorServingSlot::Serving(observation)) if observation.record == record => {
                    reconcile_serving(
                        root,
                        &warrant.evidence,
                        destination,
                        operation,
                        signer,
                        &observation,
                    )?;
                    Ok(SuccessorActivationOutcome::Activated { subject, manifest })
                }
                _ => Err(SuccessorActivationError::Indeterminate(reason)),
            }
        }
    }
}

/// Section 7, Serving slot: rerun the evidence in full (already done by the
/// caller), then compare only immutable authority and the unmodified
/// original import and Seal evidence. The raw plan is never compared with
/// the now-mutable inventory, the used creation token is never compared with
/// a fresh one, the singleton safety rows are never compared, and nothing
/// is written. A different record refuses with no overwrite or repair.
fn reconcile_serving<S: StructuredDurableDomainStateStore + ?Sized>(
    root: &VerifiedGenesisRoot,
    evidence: &VerifiedSuccessorActivation,
    destination: &S,
    operation: &DurableOperationContext,
    signer: &ReadinessSigningKey,
    observation: &SuccessorServingObservation,
) -> Result<SuccessorActivationOutcome, SuccessorActivationError> {
    let domain: AtomicityDomainId = evidence.policy_inputs.domain;
    if destination.get_outgoing_barrier(operation, domain)? != runtime::OutgoingBarrier::Unsealed {
        return Err(invalid("serving successor namespace is not unsealed"));
    }
    match destination.get_namespace_lifecycle(operation, domain)? {
        NamespaceLifecycle::CompleteInactive { binding, progress }
            if &binding == evidence.import.binding()
                && binding == observation.binding
                && progress == observation.progress => {}
        _ => {
            return Err(invalid(
                "serving successor origin differs from its protected observation",
            ));
        }
    }
    let repository: &dyn SuccessorServingRepository = destination
        .successor_serving_repository()
        .ok_or(SuccessorActivationError::Unsupported(
            "destination exposes no successor serving repository",
        ))?;
    let namespace_validator: ValidatorId =
        repository.read_namespace_validator(operation, domain)?;
    if signer.validator_id() != namespace_validator {
        return Err(invalid(
            "physical namespace validator differs from the local signer",
        ));
    }
    let public_key: [u8; 32] = signer.public_key();
    require_local_member(evidence, namespace_validator, public_key)?;
    require_installed_record(evidence, observation, namespace_validator, public_key)?;
    let rows: SuccessorRows = derive_successor_rows(destination, operation, root, evidence)?;
    require_installed_closure(destination, operation, evidence, &rows)?;
    Ok(SuccessorActivationOutcome::AlreadyActivated {
        subject: evidence.subject_digest,
        manifest: evidence.manifest_digest,
    })
}

/// Result of [`activate_successor`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuccessorActivationOutcome {
    /// This invocation atomically installed the successor.
    Activated {
        /// Verified 0xD054 subject digest.
        subject: Digest32,
        /// Verified 0xD055 manifest digest.
        manifest: Digest32,
    },
    /// The exact same successor was already installed; nothing was written.
    AlreadyActivated {
        /// Verified 0xD054 subject digest.
        subject: Digest32,
        /// Verified 0xD055 manifest digest.
        manifest: Digest32,
    },
}

fn add_read(
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    key: Vec<u8>,
    revision: StateRevision,
) -> Result<(), SuccessorActivationError> {
    match reads.insert(key, revision) {
        Some(previous) if previous != revision => Err(SuccessorActivationError::Node(Box::new(
            NodeCoreError::StateConflict,
        ))),
        _ => Ok(()),
    }
}

fn require_absent<S: VersionedStateReader + ?Sized>(
    store: &S,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    key: &[u8],
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    message: &'static str,
) -> Result<(), SuccessorActivationError> {
    let observed: VersionedStateValue = store.read_versioned_state(operation, domain, key)?;
    if observed.value().is_some() || observed.revision() != StateRevision::INITIAL {
        return Err(invalid(message));
    }
    add_read(reads, key.to_vec(), StateRevision::INITIAL)
}

fn put(key: Vec<u8>, value: Vec<u8>) -> Result<StateMutationEntry, SuccessorActivationError> {
    StateMutationEntry::new(key, StateMutation::Put(value)).map_err(too_large)
}

/// Section 6.2 step 4: the local bond must be Active under exactly the
/// member key, and its revision becomes a CAS read of the activation.
fn require_local_bond<S: VersionedStateReader + ?Sized>(
    store: &S,
    operation: &DurableOperationContext,
    evidence: &VerifiedSuccessorActivation,
    validator: ValidatorId,
    public_key: [u8; 32],
) -> Result<(Vec<u8>, StateRevision), SuccessorActivationError> {
    let key: Vec<u8> = fastpath_bond_record_key(evidence.outgoing_context.chain_id(), &validator)?;
    let observed: VersionedStateValue =
        store.read_versioned_state(operation, evidence.policy_inputs.domain, &key)?;
    let bond: FastPathBondRecord = decode_fastpath_bond_record(
        observed
            .value()
            .ok_or(invalid("local successor bond row is absent"))?,
    )?;
    if bond.validator_id != validator
        || bond.state != FastPathBondState::Active
        || bond.authorization_scheme != SignatureSchemeId::Ed25519
        || bond.authorization_key != public_key
    {
        return Err(invalid(
            "local successor bond is not active under the member key",
        ));
    }
    Ok((key, observed.revision()))
}

/// Exact 0x64D5 record: field 5 is the step 3 token, field 7 the physical
/// namespace validator and field 8 the local signer key.
fn activation_record(warrant: &ActivationWarrant) -> Result<Vec<u8>, SuccessorActivationError> {
    let record: SuccessorServingRecord = SuccessorServingRecord {
        subject: warrant.evidence.subject_digest,
        manifest: warrant.evidence.manifest_digest,
        binding: warrant.evidence.import.binding().clone(),
        progress: warrant.progress.clone(),
        activation_token: warrant.token.clone(),
        anchor: warrant.evidence.policy_inputs.anchor,
        validator: warrant.namespace_validator,
        public_key: warrant.public_key,
    };
    Ok(encode_successor_serving_record(&record)?)
}

/// The three e+1 policy rows with logical provenance at a generation derived
/// above the verified cut binding floor. The fold set is exactly the one
/// real dependency, the carried-forward epoch-e paid fee policy row; every
/// provenance read it fences joins the CAS set, and the three provenance
/// rows must be absent.
fn policy_rows_with_provenance<S: StructuredDurableDomainStateStore + ?Sized>(
    root: &VerifiedGenesisRoot,
    store: &S,
    operation: &DurableOperationContext,
    warrant: &ActivationWarrant,
    rows: &SuccessorRows,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<Vec<StateMutationEntry>, SuccessorActivationError> {
    let inputs: &SuccessorPolicyInputs = warrant.policy_inputs();
    let domain: AtomicityDomainId = inputs.domain;
    let resolver: &hashing::HashSuiteResolver = root.genesis_resolver();
    let scope: GenerationScope = GenerationScope::for_activation(warrant);
    let mut config_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let InstalledCommitmentProfile::Logical(profile) = fence_commitment_profile(
        store,
        operation,
        domain,
        warrant.evidence.outgoing_context.chain_id(),
        &mut config_reads,
    )?
    else {
        return Err(invalid(
            "successor activation requires the installed logical profile",
        ));
    };
    let mut fold: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    fold.insert(
        rows.derived.current_fee_policy_key.clone(),
        rows.derived.current_fee_policy_revision,
    );
    let derivation: LogicalDerivation = derive_scoped(
        &scope,
        store,
        operation,
        domain,
        resolver,
        &profile,
        &[],
        None,
        &mut fold,
    )?;
    let mut mutations: Vec<StateMutationEntry> = Vec::with_capacity(6);
    for (key, value) in &rows.next_rows[1..] {
        require_absent(
            store,
            operation,
            domain,
            key,
            reads,
            "successor policy row already exists",
        )?;
        mutations.push(put(key.clone(), value.clone())?);
    }
    let writes: Vec<LogicalWrite> =
        staged_writes(resolver, inputs.context.epoch(), &mutations, &[], &[], None)?;
    if writes.len() != 3 {
        return Err(invalid(
            "successor policy rows must carry exactly three provenance subjects",
        ));
    }
    let provenance: Vec<StateMutationEntry> = provenance_mutations_scoped(
        &scope,
        store,
        operation,
        domain,
        resolver,
        &profile,
        inputs.context.epoch(),
        &derivation,
        &writes,
        &mut fold,
    )?;
    for entry in &provenance {
        if fold.get(entry.key()) != Some(&StateRevision::INITIAL) {
            return Err(invalid("successor policy provenance row already exists"));
        }
    }
    for (key, revision) in fold.into_iter().chain(config_reads) {
        add_read(reads, key, revision)?;
    }
    mutations.extend(provenance);
    Ok(mutations)
}

/// Section 6.3: the one complete activation transaction, built and
/// preflighted through the existing constructors before any port call.
fn activation_transaction<S: StructuredDurableDomainStateStore + ?Sized>(
    root: &VerifiedGenesisRoot,
    store: &S,
    operation: &DurableOperationContext,
    warrant: &ActivationWarrant,
    bond: (Vec<u8>, StateRevision),
    now_unix_millis: u64,
) -> Result<DurableInvocationTransaction, SuccessorActivationError> {
    let evidence: &VerifiedSuccessorActivation = &warrant.evidence;
    let domain: AtomicityDomainId = evidence.policy_inputs.domain;
    let chain: &protocol_types::ChainId = evidence.outgoing_context.chain_id();
    let outgoing: protocol_types::Epoch = evidence.outgoing_context.epoch();
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_successor(root, warrant.policy_inputs())?;
    let rows: SuccessorRows = derive_successor_rows(store, operation, root, evidence)?;
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let mut mutations: Vec<StateMutationEntry> = Vec::new();
    // The live epoch record is exactly the outgoing epoch, then replaced by
    // the exact verified successor record.
    let epoch_observed: VersionedStateValue =
        store.read_versioned_state(operation, domain, &rows.epoch_record_key)?;
    let current: FastPathEpochRecord = decode_fastpath_epoch_record(
        epoch_observed
            .value()
            .ok_or(invalid("destination epoch record is not installed"))?,
    )?;
    if current.current_epoch != outgoing {
        return Err(invalid(
            "destination epoch record is not the outgoing epoch",
        ));
    }
    add_read(
        &mut reads,
        rows.epoch_record_key.clone(),
        epoch_observed.revision(),
    )?;
    mutations.push(put(
        rows.epoch_record_key.clone(),
        rows.epoch_record.clone(),
    )?);
    add_read(&mut reads, bond.0, bond.1)?;
    // The e+1 validator set and the three provenance-carrying policy rows.
    let (set_key, set_value): &(Vec<u8>, Vec<u8>) = &rows.next_rows[0];
    require_absent(
        store,
        operation,
        domain,
        set_key,
        &mut reads,
        "successor validator set row already exists",
    )?;
    mutations.push(put(set_key.clone(), set_value.clone())?);
    mutations.extend(policy_rows_with_provenance(
        root, store, operation, warrant, &rows, &mut reads,
    )?);
    require_absent(
        store,
        operation,
        domain,
        &fastpath_epoch_transition_key(chain, warrant.policy_inputs().context.epoch())?,
        &mut reads,
        "legacy transition row exists at the successor epoch",
    )?;
    // Exactly three virgin singleton roots. Only the epoch-state root is
    // written, with the successor engine genesis state.
    let scope: &OrderedKeyScope = policy.key_scope();
    let state_key: Vec<u8> = scoped_state_key(scope, chain)?;
    for key in [
        state_key.clone(),
        scoped_applied_height_key(scope, chain)?,
        scoped_vote_high_key(scope, chain)?,
    ] {
        require_absent(
            store,
            operation,
            domain,
            &key,
            &mut reads,
            "successor singleton safety root is not virgin",
        )?;
    }
    let genesis_state: Vec<u8> =
        encode_consensus_state(&policy.engine().genesis_state(now_unix_millis))
            .map_err(|_| invalid("successor genesis consensus state does not encode"))?;
    mutations.push(put(state_key, genesis_state)?);
    // The exact verified Seal suffix and closure, all must-absent.
    for (height, bytes) in &evidence.suffix_proofs {
        let key: Vec<u8> = ordered_committed_proof_key(chain, outgoing, *height)?;
        require_absent(
            store,
            operation,
            domain,
            &key,
            &mut reads,
            "Seal suffix proof already exists",
        )?;
        mutations.push(put(key, bytes.clone())?);
    }
    let seal: &SealClosure = &evidence.seal;
    for (key, bytes) in [
        (
            ordered_candidate_record_key(chain, seal.candidate_digest)?,
            &seal.candidate,
        ),
        (
            ordered_request_header_key(chain, &seal.request_id)?,
            &seal.header,
        ),
        (ordered_outcome_key(chain, &seal.request_id)?, &seal.outcome),
    ] {
        require_absent(
            store,
            operation,
            domain,
            &key,
            &mut reads,
            "Seal closure row already exists",
        )?;
        mutations.push(put(key, bytes.clone())?);
    }
    // The original Seal receipt, never a synthesized activation receipt.
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        seal_request_id(evidence)?,
        seal.receipt_event_digest,
        seal.receipt.clone(),
    )
    .map_err(too_large)?;
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<Vec<StateReadAssertion>, RuntimeError>>()
        .map_err(too_large)?;
    let state: DurableStateTransaction = DurableStateTransaction::new(
        domain,
        AtomicStateReadSet::new(assertions).map_err(too_large)?,
        mutations,
    )
    .map_err(too_large)?;
    DurableInvocationTransaction::new(
        domain,
        Some(state),
        DurableObjectChanges::empty(),
        receipt,
        None,
    )
    .map_err(too_large)
}
