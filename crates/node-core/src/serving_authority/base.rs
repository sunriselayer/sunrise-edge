//! DR-0191 Section 3: the private reconstruction-base bootstrap of link k
//! over verified link k-1. It is built only from the link k-1 verified
//! import plan (its exact batches, binding and bodies), the shared
//! `activation_mutations` read through that fixture, and the one real Seal
//! receipt. Nothing here is a restore, a Serving slot or a namespace
//! validator: the fixture is an ordinary in-memory data store whose replay
//! authority comes only from the private issuer-bound replay scope.

use super::activation::{ActivationMutations, activation_mutations};
use super::*;
use crate::business_reconstruction::cut::{CaptureScopes, capture_scoped_target};
use crate::business_reconstruction::inactive_import::raw_rows;
use crate::genesis::VerifiedGenesisRoot;
use crate::ordered_economics::{OrderedEconomicsPolicy, OrderedKeyScope};
use runtime::inactive_import::ImportRow;
use runtime::{
    AtomicStateReadSet, BlobStore, DurableCommitOutcome, DurableInvocationTransaction,
    DurableObjectChanges, DurableStateTransaction, MemoryBlobStore, MemoryDurableStateStore,
    StateMutation, StateReadAssertion, StructuredDurableDomainStateStore, VersionedStateReader,
};

fn invalid(message: &'static str) -> SuccessorActivationError {
    SuccessorActivationError::Invalid(message)
}

/// The base of a reconstruction, minted only by the verified chain owner.
/// The original root always remains the source of immutable economics and
/// profile values; the successor carries the prior verified import only.
#[derive(Clone, Copy)]
pub(crate) struct ReconstructionBase<'c>(Base<'c>);

#[derive(Clone, Copy)]
enum Base<'c> {
    Genesis(&'c VerifiedGenesisRoot),
    Successor {
        root: &'c VerifiedGenesisRoot,
        predecessor: &'c VerifiedSuccessorActivation,
        committees: &'c std::sync::Arc<VerifiedCommitteeHistory>,
        owners: &'c std::sync::Arc<VerifiedOwnerRegistry>,
    },
}

impl<'c> ReconstructionBase<'c> {
    pub(crate) const fn genesis(root: &'c VerifiedGenesisRoot) -> Self {
        Self(Base::Genesis(root))
    }

    pub(super) const fn successor(
        root: &'c VerifiedGenesisRoot,
        predecessor: &'c VerifiedSuccessorActivation,
        committees: &'c std::sync::Arc<VerifiedCommitteeHistory>,
        owners: &'c std::sync::Arc<VerifiedOwnerRegistry>,
    ) -> Self {
        Self(Base::Successor {
            root,
            predecessor,
            committees,
            owners,
        })
    }

    pub(crate) fn context(self) -> &'c PublicationContext {
        match self.0 {
            Base::Genesis(root) => root.genesis_context(),
            Base::Successor { predecessor, .. } => &predecessor.policy_inputs.context,
        }
    }

    pub(crate) const fn committee(self) -> &'c ValidatorSet {
        match self.0 {
            Base::Genesis(root) => root.genesis_committee(),
            Base::Successor { predecessor, .. } => &predecessor.policy_inputs.validator_set,
        }
    }

    pub(crate) const fn is_successor(self) -> bool {
        matches!(self.0, Base::Successor { .. })
    }

    pub(crate) const fn floor(self) -> Option<ExecutionGeneration> {
        match self.0 {
            Base::Genesis(_) => None,
            Base::Successor { predecessor, .. } => Some(predecessor.policy_inputs.generation_floor),
        }
    }

    pub(crate) fn histories(
        self,
    ) -> Option<(&'c VerifiedCommitteeHistory, &'c VerifiedOwnerRegistry)> {
        match self.0 {
            Base::Genesis(_) => None,
            Base::Successor {
                committees, owners, ..
            } => Some((committees, owners)),
        }
    }

    pub(crate) fn scopes(
        self,
        domain: AtomicityDomainId,
    ) -> Result<Vec<OrderedKeyScope>, SuccessorActivationError> {
        match self.0 {
            Base::Genesis(root) => Ok(vec![
                OrderedEconomicsPolicy::from_genesis_root(root, domain)?
                    .key_scope()
                    .clone(),
            ]),
            Base::Successor {
                root, committees, ..
            } => committees.scopes(root, domain),
        }
    }

    pub(crate) fn require_policy(
        self,
        policy: &OrderedEconomicsPolicy,
        domain: AtomicityDomainId,
    ) -> Result<(), SuccessorActivationError> {
        match self.0 {
            Base::Genesis(_) if !policy.key_scope().is_successor() => Ok(()),
            Base::Successor {
                root,
                predecessor,
                committees,
                owners,
            } => {
                let expected: OrderedEconomicsPolicy =
                    OrderedEconomicsPolicy::from_successor_chain(
                        root,
                        &predecessor.policy_inputs,
                        std::sync::Arc::clone(committees),
                        std::sync::Arc::clone(owners),
                    )?;
                if expected.context() != policy.context()
                    || expected.domain() != domain
                    || policy.domain() != domain
                    || expected.anchor() != policy.anchor()
                    || expected.genesis_digest() != policy.genesis_digest()
                    || expected.engine().validator_set() != policy.engine().validator_set()
                    || expected.key_scope() != policy.key_scope()
                {
                    return Err(invalid(
                        "reconstruction policy differs from the verified base",
                    ));
                }
                Ok(())
            }
            _ => Err(invalid("genesis reconstruction has a successor policy")),
        }
    }

    pub(crate) fn bootstrap(
        self,
        operation: &DurableOperationContext,
    ) -> Result<Option<BootstrappedBase>, SuccessorActivationError> {
        match self.0 {
            Base::Genesis(_) => Ok(None),
            Base::Successor {
                root,
                predecessor,
                committees,
                owners,
            } => bootstrap(root, predecessor, committees, owners, operation).map(Some),
        }
    }
}

/// One bootstrapped base: the ordinary memory data store and its bodies at
/// exactly the activated e_k state, before any e_k history is replayed.
pub(crate) struct BootstrappedBase {
    pub(crate) store: MemoryDurableStateStore,
    pub(crate) blobs: MemoryBlobStore,
    pub(crate) snapshot: crate::business_reconstruction::SourceBusinessSnapshot,
    /// The S_k scope of the activated epoch.
    scope: OrderedKeyScope,
}

impl BootstrappedBase {
    /// The base serves exactly the activated epoch of `link`: its live epoch
    /// record names e_k and its S_k epoch-state root is installed.
    pub(super) fn require_activated(
        &self,
        operation: &DurableOperationContext,
        link: &VerifiedSuccessorActivation,
    ) -> Result<(), SuccessorActivationError> {
        let chain: &protocol_types::ChainId = link.outgoing_context.chain_id();
        let domain: AtomicityDomainId = link.policy_inputs.domain;
        let record: crate::local_instance_state::FastPathEpochRecord =
            crate::local_instance_state::decode_fastpath_epoch_record(
                self.store
                    .read_versioned_state(
                        operation,
                        domain,
                        &crate::local_instance_state::fastpath_epoch_record_key(chain)?,
                    )?
                    .value()
                    .ok_or(invalid("bootstrapped base has no epoch record"))?,
            )?;
        if record.current_epoch != link.policy_inputs.context.epoch() {
            return Err(invalid("bootstrapped base is not at the activated epoch"));
        }
        let state_key: Vec<u8> =
            crate::ordered_economics::engine::scoped_state_key(&self.scope, chain)?;
        if self
            .store
            .read_versioned_state(operation, domain, &state_key)?
            .value()
            .is_none()
        {
            return Err(invalid("bootstrapped base has no successor state root"));
        }
        Ok(())
    }
}

/// The expected logical inventory after bootstrap: the plan rows merged in
/// locator order with the activation puts (a put replaces the plan State row
/// at the same key, never adding a second row) and the one Seal receipt.
fn expected_rows(
    plan: &[ImportRow],
    activation: &ActivationMutations,
) -> Result<Vec<ImportRow>, SuccessorActivationError> {
    let mut rows: BTreeMap<Vec<u8>, ImportRow> = BTreeMap::new();
    for row in plan {
        if rows.insert(row.locator(), row.clone()).is_some() {
            return Err(invalid("verified plan repeats a locator"));
        }
    }
    for entry in &activation.mutations {
        let StateMutation::Put(value) = entry.mutation() else {
            return Err(invalid("activation mutation is not a put"));
        };
        let row: ImportRow = ImportRow::State {
            key: entry.key().to_vec(),
            value: Some(value.clone()),
        };
        rows.insert(row.locator(), row);
    }
    let receipt: ImportRow = ImportRow::Receipt(activation.receipt.clone());
    if rows.insert(receipt.locator(), receipt).is_some() {
        return Err(invalid("Seal receipt already exists in the verified plan"));
    }
    Ok(rows.into_values().collect())
}

/// Bootstraps the e_k base from verified link k-1 (`link`). `now = 0` for
/// the S_k epoch-state root, as genesis install uses 0.
pub(super) fn bootstrap(
    root: &VerifiedGenesisRoot,
    link: &VerifiedSuccessorActivation,
    committees: &std::sync::Arc<VerifiedCommitteeHistory>,
    owners: &std::sync::Arc<VerifiedOwnerRegistry>,
    operation: &DurableOperationContext,
) -> Result<BootstrappedBase, SuccessorActivationError> {
    let binding: &runtime::inactive_import::ImportBinding = link.import.binding();
    let domain: AtomicityDomainId = binding.domain;
    if domain != link.policy_inputs.domain {
        return Err(invalid("bootstrap binding domain differs from the link"));
    }
    // 1. Plan: the exact verified batches and their referenced bodies.
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new_bound_from_import_batches(
        binding,
        operation.writer_fence(),
        link.import.batches(),
    )
    .map_err(SuccessorActivationError::Rejected)?;
    let blobs: MemoryBlobStore = MemoryBlobStore::default();
    for (digest, bytes) in link.import.blobs() {
        blobs.put_blob(*digest, bytes.clone())?;
    }
    // 2. Activation rows through the fixture reader, exactly as the
    //    destination activation derives them, and the one real receipt.
    let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::from_successor_chain(
        root,
        &link.policy_inputs,
        std::sync::Arc::clone(committees),
        std::sync::Arc::clone(owners),
    )?;
    let activation: ActivationMutations =
        activation_mutations(root, &store, operation, link, &policy, 0)?;
    let expected: Vec<ImportRow> = expected_rows(link.import.rows(), &activation)?;
    let assertions: Vec<StateReadAssertion> = activation
        .reads
        .iter()
        .map(|(key, revision)| StateReadAssertion::new(key.clone(), *revision))
        .collect::<Result<Vec<StateReadAssertion>, RuntimeError>>()?;
    let transaction: DurableInvocationTransaction = DurableInvocationTransaction::new(
        domain,
        Some(DurableStateTransaction::new(
            domain,
            AtomicStateReadSet::new(assertions)?,
            activation.mutations.clone(),
        )?),
        DurableObjectChanges::empty(),
        activation.receipt.clone(),
        None,
    )
    .map_err(NodeCoreError::from)?;
    match store.commit_invocation(operation, transaction) {
        DurableCommitOutcome::Committed => {}
        DurableCommitOutcome::Rejected(reason) => {
            return Err(SuccessorActivationError::Rejected(reason));
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            return Err(SuccessorActivationError::Indeterminate(reason));
        }
    }
    // 3. Postcondition: exact logical equality, excluding only physical
    //    state and head revisions; bodies must equal the plan bodies.
    let scope: OrderedKeyScope = policy.key_scope().clone();
    let verified_scopes: Vec<OrderedKeyScope> = committees.scopes(root, domain)?;
    let scopes: CaptureScopes<'_> = CaptureScopes {
        chain: link.outgoing_context.chain_id(),
        verified: &verified_scopes,
    };
    let snapshot = capture_scoped_target(&store, &blobs, operation, domain, &scopes)
        .map_err(|_| invalid("bootstrapped base capture refused"))?;
    let actual: Vec<ImportRow> = raw_rows(&snapshot, false)?;
    if actual != expected {
        return Err(invalid(
            "bootstrapped base differs from the verified plan and activation rows",
        ));
    }
    if &snapshot.referenced_blobs != link.import.blobs() {
        return Err(invalid(
            "bootstrapped base bodies differ from the verified plan",
        ));
    }
    let bootstrapped: BootstrappedBase = BootstrappedBase {
        store,
        blobs,
        snapshot,
        scope,
    };
    bootstrapped.require_activated(operation, link)?;
    Ok(bootstrapped)
}
