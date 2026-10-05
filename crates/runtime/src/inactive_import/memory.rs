//! Atomic, bounded memory implementation; no full-store clone per batch.
use super::*;

impl MemoryDurableStateStore {
    /// Creates a genuinely fresh import-only store using its own local fence.
    /// This cannot convert an existing ordinary store or copy a source token.
    pub fn new_import_target(
        binding: ImportBinding,
        own_writer_fence: WriterFenceGeneration,
    ) -> Result<Self, RuntimeError> {
        encode_import_binding(&binding)?;
        let store: Self = Self::new_bound(binding.domain, own_writer_fence);
        store
            .inner
            .write()
            .map_err(|_| RuntimeError::DurableStoreUnavailable)?
            .lifecycle = NamespaceLifecycle::FreshImport(binding);
        Ok(store)
    }

    /// Reconstruction-only ordinary ephemeral data fixture, preloaded from
    /// already-checked import batches (DR-0191 Section 3). Never a provider
    /// restore or a fake Serving/protected import origin: the resulting
    /// lifecycle is Ordinary, the barrier Unsealed, the slot Inactive, with
    /// no successor namespace validator. The bound-domain ordinary
    /// outgoing_seal_repository getter stays available; the successor
    /// serving port stays absent. Core private issuer-bound replay gate
    /// alone supplies replay scope; this raw data is never protocol
    /// authority on its own.
    #[doc(hidden)]
    pub fn new_bound_from_import_batches(
        binding: &ImportBinding,
        active_writer_fence: WriterFenceGeneration,
        batches: &[ImportBatch],
    ) -> Result<Self, DurableCommitRejection> {
        encode_import_binding(binding)
            .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
        let chain: &ChainId = &binding.context.chain_id;
        let mut previous_next: Option<ImportProgress> = None;
        let mut last_locator: Option<Vec<u8>> = None;
        let mut counted_rows: u64 = 0;
        for batch in batches {
            if batch.binding() != binding {
                return Err(DurableCommitRejection::ImportBindingMismatch);
            }
            match &previous_next {
                // The first batch's accumulator is the core-supplied genesis
                // value; runtime never invents or authenticates that hash,
                // so only the structural ordinal/digest fields are checked.
                None => {
                    if batch.expected().next_ordinal != 0
                        || batch.expected().last_batch_digest.is_some()
                    {
                        return Err(DurableCommitRejection::ImportConflict);
                    }
                }
                // Every later batch's expected progress, including the
                // accumulator, must equal the previous batch's actual next()
                // byte for byte; a substituted accumulator refuses.
                Some(previous) => {
                    if batch.expected() != previous {
                        return Err(DurableCommitRejection::ImportConflict);
                    }
                }
            }
            for row in batch.rows() {
                let locator: Vec<u8> = row.locator();
                if last_locator
                    .as_ref()
                    .is_some_and(|before| *before >= locator)
                {
                    return Err(DurableCommitRejection::ImportConflict);
                }
                last_locator = Some(locator);
            }
            let batch_rows: u64 = u64::try_from(batch.rows().len())
                .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
            counted_rows = counted_rows
                .checked_add(batch_rows)
                .ok_or(DurableCommitRejection::InvalidPersistedState)?;
            previous_next = Some(batch.next().clone());
        }
        let final_ordinal: u64 = previous_next.as_ref().map_or(0, |next| next.next_ordinal);
        if final_ordinal != binding.row_count || counted_rows != binding.row_count {
            return Err(DurableCommitRejection::ImportConflict);
        }
        let store: Self = Self::new_bound(binding.domain, active_writer_fence);
        {
            let mut data = store
                .inner
                .write()
                .map_err(|_| DurableCommitRejection::UnavailableBeforeCommit)?;
            for batch in batches {
                validate_rows(&data, binding.domain, chain, batch.rows(), false)?;
                install_rows(&mut data, binding.domain, batch.rows())?;
            }
        }
        Ok(store)
    }
}

fn authority(
    data: &MemoryDurableStoreData,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> Result<(), DurableCommitRejection> {
    validate_memory_durable_commit_domain(data, domain)?;
    validate_memory_durable_commit_authority(data, context)
}
fn outcome(result: Result<(), DurableCommitRejection>) -> DurableCommitOutcome {
    match result {
        Ok(()) => DurableCommitOutcome::Committed,
        Err(reason) => DurableCommitOutcome::Rejected(reason),
    }
}
fn sequence(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
) -> Result<u64, DurableCommitRejection> {
    memory_next_mutation_sequence(data, domain)
        .ok_or(DurableCommitRejection::CommitSequenceOverflow)
}

fn expected_head(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
    object_id: ObjectId,
    head: &ImportObjectHead,
    rows: &[ImportRow],
) -> Result<MemoryStoredObjectHead, DurableCommitRejection> {
    let latest = data
        .object_versions
        .range(
            (*domain.as_bytes(), object_id, DurableObjectVersion::FIRST)
                ..=(*domain.as_bytes(), object_id, DurableObjectVersion::MAX),
        )
        .next_back()
        .map(|(_, version)| version);
    let latest: Option<&DurableObjectVersionRecord> = rows
        .iter()
        .filter_map(|row| {
            if let ImportRow::ObjectVersion(version) = row {
                (version.object_id() == object_id).then_some(version)
            } else {
                None
            }
        })
        .chain(latest)
        .max_by_key(|version| version.object_version());
    let latest: &DurableObjectVersionRecord =
        latest.ok_or(DurableCommitRejection::ImportConflict)?;
    match head {
        ImportObjectHead::Tombstoned {
            last_object_version,
        } if *last_object_version == latest.object_version() => {
            Ok(MemoryStoredObjectHead::Tombstoned {
                head_revision: ObjectHeadRevision::FIRST,
            })
        }
        ImportObjectHead::Current {
            object_version,
            digest,
            owner_projection,
            routing_projection,
        } if *object_version == latest.object_version() && *digest == latest.digest() => {
            if let DurableObjectPayload::Inline(inline) = latest.payload()
                && owner_projection.owner() != Some(&inline.object().owner)
            {
                return Err(DurableCommitRejection::ImportConflict);
            }
            Ok(MemoryStoredObjectHead::Current {
                head_revision: ObjectHeadRevision::FIRST,
                object_version: *object_version,
                digest: *digest,
                owner_projection: owner_projection.clone(),
                routing_projection: routing_projection.clone(),
            })
        }
        _ => Err(DurableCommitRejection::ImportConflict),
    }
}

fn validate_rows(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
    chain: &ChainId,
    rows: &[ImportRow],
    retry: bool,
) -> Result<(), DurableCommitRejection> {
    let domain_bytes: [u8; 32] = *domain.as_bytes();
    for row in rows {
        let identical: Option<bool> = match row {
            ImportRow::State { key, value } => data
                .state_domains
                .get(&domain_bytes)
                .and_then(|entries| entries.get(key))
                .map(|stored| stored.value == *value),
            ImportRow::Receipt(receipt) => data
                .receipts
                .get(&(domain_bytes, *receipt.request_id().as_bytes()))
                .map(|stored| stored == receipt),
            ImportRow::ObjectVersion(version) => {
                if version.provenance().chain_id() != chain {
                    return Err(DurableCommitRejection::ImportBindingMismatch);
                }
                data.object_versions
                    .get(&(domain_bytes, version.object_id(), version.object_version()))
                    .map(|stored| stored == version)
            }
            ImportRow::ObjectHead { object_id, head } => {
                let expected: MemoryStoredObjectHead =
                    expected_head(data, domain, *object_id, head, rows)?;
                data.object_heads
                    .get(&(domain_bytes, *object_id))
                    .map(|stored| *stored == expected)
            }
        };
        if identical == Some(false) || (retry && identical != Some(true)) {
            return Err(DurableCommitRejection::ImportConflict);
        }
    }
    Ok(())
}

fn install_rows(
    data: &mut MemoryDurableStoreData,
    domain: AtomicityDomainId,
    rows: &[ImportRow],
) -> Result<(), DurableCommitRejection> {
    // All fallible checks precede the first insertion, including heads whose
    // immutable versions are contained in this same bounded batch.
    let mut heads: BTreeMap<ObjectId, MemoryStoredObjectHead> = BTreeMap::new();
    for row in rows {
        if let ImportRow::ObjectHead { object_id, head } = row {
            heads.insert(
                *object_id,
                expected_head(data, domain, *object_id, head, rows)?,
            );
        }
    }
    let domain_bytes: [u8; 32] = *domain.as_bytes();
    let revision: StateRevision = StateRevision::INITIAL
        .checked_next()
        .map_err(|_| DurableCommitRejection::StateRevisionOverflow)?;
    for row in rows {
        match row {
            ImportRow::State { key, value } => {
                data.state_domains
                    .entry(domain_bytes)
                    .or_default()
                    .entry(key.clone())
                    .or_insert_with(|| StoredStateValue {
                        revision,
                        value: value.clone(),
                    });
            }
            ImportRow::Receipt(receipt) => {
                data.receipts
                    .entry((domain_bytes, *receipt.request_id().as_bytes()))
                    .or_insert_with(|| receipt.clone());
            }
            ImportRow::ObjectVersion(version) => {
                data.object_versions
                    .entry((domain_bytes, version.object_id(), version.object_version()))
                    .or_insert_with(|| version.clone());
            }
            ImportRow::ObjectHead { .. } => {}
        }
    }
    for (id, head) in heads {
        data.object_heads.entry((domain_bytes, id)).or_insert(head);
    }
    Ok(())
}

impl InactiveImportRepository for MemoryDurableStateStore {
    fn begin_import(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        initial_accumulator: Digest32,
    ) -> DurableCommitOutcome {
        let Ok(mut data) = self.inner.write() else {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit);
        };
        outcome((|| {
            authority(&data, context, domain)?;
            if binding.domain != domain || data.lifecycle.binding() != Some(binding) {
                return Err(DurableCommitRejection::ImportBindingMismatch);
            }
            let initial: ImportProgress = ImportProgress {
                next_ordinal: 0,
                last_batch_digest: None,
                accumulator: initial_accumulator,
            };
            match &data.lifecycle {
                NamespaceLifecycle::FreshImport(_) => {}
                NamespaceLifecycle::Importing { progress, .. } if *progress == initial => {
                    return Ok(());
                }
                _ => return Err(DurableCommitRejection::ImportConflict),
            }
            let next: u64 = sequence(&data, domain)?;
            data.lifecycle = NamespaceLifecycle::Importing {
                binding: binding.clone(),
                progress: initial,
            };
            data.mutation_sequences.insert(*domain.as_bytes(), next);
            Ok(())
        })())
    }
    fn read_import_progress(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<Option<ImportProgress>, DurableReadError> {
        let lifecycle: NamespaceLifecycle = self.get_namespace_lifecycle(context, domain)?;
        if lifecycle.is_ordinary() {
            return Err(DurableReadError::InvalidPersistedState);
        }
        Ok(lifecycle.progress().cloned())
    }
    fn commit_import_batch(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        batch: &ImportBatch,
    ) -> DurableCommitOutcome {
        let Ok(mut data) = self.inner.write() else {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit);
        };
        outcome((|| {
            authority(&data, context, domain)?;
            if batch.binding().domain != domain || data.lifecycle.binding() != Some(batch.binding())
            {
                return Err(DurableCommitRejection::ImportBindingMismatch);
            }
            let NamespaceLifecycle::Importing { progress, .. } = &data.lifecycle else {
                return Err(DurableCommitRejection::ImportConflict);
            };
            if progress == batch.next() {
                return validate_rows(
                    &data,
                    domain,
                    &batch.binding().context.chain_id,
                    batch.rows(),
                    true,
                );
            }
            if progress != batch.expected() {
                return Err(DurableCommitRejection::ImportConflict);
            }
            validate_rows(
                &data,
                domain,
                &batch.binding().context.chain_id,
                batch.rows(),
                false,
            )?;
            let next: u64 = sequence(&data, domain)?;
            install_rows(&mut data, domain, batch.rows())?;
            data.lifecycle = NamespaceLifecycle::Importing {
                binding: batch.binding().clone(),
                progress: batch.next().clone(),
            };
            data.mutation_sequences.insert(*domain.as_bytes(), next);
            Ok(())
        })())
    }
    fn finish_import(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        expected: &ImportProgress,
        verified_target: &portable::PortableSnapshotToken,
    ) -> DurableCommitOutcome {
        let Ok(mut data) = self.inner.write() else {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit);
        };
        outcome((|| {
            authority(&data, context, domain)?;
            if binding.domain != domain || data.lifecycle.binding() != Some(binding) {
                return Err(DurableCommitRejection::ImportBindingMismatch);
            }
            if expected.next_ordinal != binding.row_count
                || data.lifecycle.progress() != Some(expected)
            {
                return Err(DurableCommitRejection::ImportConflict);
            }
            let current: u64 = data
                .mutation_sequences
                .get(domain.as_bytes())
                .copied()
                .unwrap_or(0);
            verified_target
                .check(
                    &data.portable_namespace,
                    domain,
                    data.active_writer_fence,
                    current,
                )
                .map_err(|_| DurableCommitRejection::ImportConflict)?;
            if matches!(data.lifecycle, NamespaceLifecycle::CompleteInactive { .. }) {
                return Ok(());
            }
            if !matches!(data.lifecycle, NamespaceLifecycle::Importing { .. }) {
                return Err(DurableCommitRejection::ImportConflict);
            }
            let next: u64 = sequence(&data, domain)?;
            data.lifecycle = NamespaceLifecycle::CompleteInactive {
                binding: binding.clone(),
                progress: expected.clone(),
            };
            data.mutation_sequences.insert(*domain.as_bytes(), next);
            Ok(())
        })())
    }
}
