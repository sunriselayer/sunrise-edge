//! Reader-only capability proving preparation compiles without a durable
//! writer trait. This adapter deliberately implements only observation
//! ports; calling an actual durable commit on it is a compile error, not a
//! test stub. Shared by fee, bond lifecycle and slash preparation tests.

use objects::ObjectId;
use runtime::{
    AtomicityDomainId, DurableObjectHead, DurableObjectVersion, DurableObjectVersionRecord,
    DurableOperationContext, DurableReadError, DurableRequestId, DurableRequestReceipt,
    NamespaceLifecycle, StructuredStateReader, VersionedStateReader, VersionedStateValue,
};

pub(crate) struct WriterFreeView<'a, S: StructuredStateReader> {
    source: &'a S,
}

impl<'a, S: StructuredStateReader> WriterFreeView<'a, S> {
    pub(crate) const fn new(source: &'a S) -> Self {
        Self { source }
    }
}

impl<S: StructuredStateReader> VersionedStateReader for WriterFreeView<'_, S> {
    fn read_versioned_state(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.source.read_versioned_state(context, domain, key)
    }
}

impl<S: StructuredStateReader> StructuredStateReader for WriterFreeView<'_, S> {
    fn read_outgoing_barrier(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, DurableReadError> {
        self.source.read_outgoing_barrier(context, domain)
    }

    fn read_namespace_lifecycle(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError> {
        self.source.read_namespace_lifecycle(context, domain)
    }

    fn read_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.source.read_object_head(context, domain, object_id)
    }

    fn read_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.source
            .read_object_version(context, domain, object_id, object_version)
    }

    fn read_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.source
            .read_request_receipt(context, domain, request_id)
    }
}
