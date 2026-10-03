//! Physical CAS observations for one writer-free ordered attempt.
//!
//! This scope neither derives logical business operands nor provides a stable
//! snapshot. The owner still supplies its exact object-head assertions and
//! immutable body validation. A consuming finish checks every sticky local
//! observation failure before any handler/preflight error is propagated.

use super::{OrderedEconomicsError, engine::state_assembly_error};
use runtime::{
    AtomicityDomainId, DurableObjectHead, DurableObjectVersion, DurableObjectVersionRecord,
    DurableOperationContext, DurableReadError, DurableRequestId, DurableRequestReceipt,
    NamespaceLifecycle, RuntimeError, StateAssemblyError, StateObservationSet, StateReadAssertion,
    StructuredStateReader, VersionedStateReader, VersionedStateValue,
};
use std::cell::RefCell;

struct Observations {
    state: StateObservationSet,
    poison: Option<StateAssemblyError>,
}

/// An owning read scope, not a store or an admission capability. It deliberately
/// implements no durable write trait and cannot acknowledge a proposed commit.
pub(super) struct ObservedBusinessReadView<'a, S: StructuredStateReader + ?Sized> {
    inner: &'a S,
    observations: RefCell<Observations>,
}

impl<'a, S: StructuredStateReader + ?Sized> ObservedBusinessReadView<'a, S> {
    pub(super) fn new(inner: &'a S, domain: AtomicityDomainId) -> Self {
        Self {
            inner,
            observations: RefCell::new(Observations {
                state: StateObservationSet::new(domain),
                poison: None,
            }),
        }
    }

    fn require_domain(&self, domain: AtomicityDomainId) -> Result<(), DurableReadError> {
        let mut observations: std::cell::RefMut<'_, Observations> = self.observations.borrow_mut();
        if let Some(error) = &observations.poison {
            return Err(local_read_rejection(error));
        }
        if observations.state.domain() != domain {
            let error: StateAssemblyError = RuntimeError::AtomicityDomainMismatch.into();
            let rejected: DurableReadError = local_read_rejection(&error);
            observations.poison = Some(error);
            return Err(rejected);
        }
        Ok(())
    }

    /// Consuming this scope is required even after an unsuccessful owner call.
    /// A backend read error is unchanged when there was no local poison.
    pub(super) fn finish(self) -> Result<StateObservationSet, OrderedEconomicsError> {
        let observations: Observations = self.observations.into_inner();
        match observations.poison {
            Some(error) => Err(state_assembly_error(error)),
            None => Ok(observations.state),
        }
    }

    pub(super) fn finish_with<T>(
        self,
        result: Result<T, OrderedEconomicsError>,
    ) -> Result<(StateObservationSet, T), OrderedEconomicsError> {
        // Do not move `result?` ahead of finish: the error may have been derived
        // from disagreeing reads, or may have propagated our local rejection.
        let observations: StateObservationSet = self.finish()?;
        Ok((observations, result?))
    }
}

// A synchronous private read rejection never represents an actual commit or
// backend ambiguity. The consuming finish exposes its precise sticky cause.
fn local_read_rejection(error: &StateAssemblyError) -> DurableReadError {
    match error {
        StateAssemblyError::Runtime(error) => DurableReadError::InvalidRequest(error.clone()),
        StateAssemblyError::ConflictingObservation { .. }
        | StateAssemblyError::ConflictingMutation { .. } => DurableReadError::InvalidPersistedState,
    }
}

impl<S: StructuredStateReader + ?Sized> VersionedStateReader for ObservedBusinessReadView<'_, S> {
    fn read_versioned_state(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.require_domain(domain)?;
        let observed: VersionedStateValue =
            self.inner.read_versioned_state(context, domain, key)?;
        let assertion: StateReadAssertion =
            match StateReadAssertion::new(key.to_vec(), observed.revision()) {
                Ok(assertion) => assertion,
                Err(error) => {
                    let rejected: DurableReadError =
                        DurableReadError::InvalidRequest(error.clone());
                    self.observations.borrow_mut().poison = Some(error.into());
                    return Err(rejected);
                }
            };
        let mut observations: std::cell::RefMut<'_, Observations> = self.observations.borrow_mut();
        if let Err(error) = observations.state.observe(assertion) {
            let rejected: DurableReadError = local_read_rejection(&error);
            observations.poison = Some(error);
            return Err(rejected);
        }
        Ok(observed)
    }
}

impl<S: StructuredStateReader + ?Sized> StructuredStateReader for ObservedBusinessReadView<'_, S> {
    fn read_outgoing_barrier(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, DurableReadError> {
        self.require_domain(domain)?;
        self.inner.read_outgoing_barrier(context, domain)
    }

    fn read_namespace_lifecycle(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError> {
        self.require_domain(domain)?;
        self.inner.read_namespace_lifecycle(context, domain)
    }

    fn read_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: objects::ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.require_domain(domain)?;
        self.inner.read_object_head(context, domain, object_id)
    }

    fn read_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: objects::ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.require_domain(domain)?;
        self.inner
            .read_object_version(context, domain, object_id, object_version)
    }

    fn read_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.require_domain(domain)?;
        self.inner.read_request_receipt(context, domain, request_id)
    }
}

#[cfg(test)]
mod tests;
