//! Closed storage-only installation, with every row/progress decision in one
//! fenced SQL transaction. Hosts must opt in through a dedicated import facade.
mod conditional_readiness;
use super::*;
use runtime::inactive_import::encode_import_progress;
use runtime::portable::PortableSnapshotToken;
use runtime::{
    ImportBatch, ImportBinding, ImportObjectHead, ImportProgress, ImportRow, NamespaceLifecycle,
};

fn reject(error: PreCommitFailure) -> DurableCommitRejection {
    error.into_commit_rejection()
}
fn conflict() -> DurableCommitRejection {
    DurableCommitRejection::ImportConflict
}

fn binding_matches(
    metadata: &NamespaceMetadata,
    binding: &ImportBinding,
    domain: AtomicityDomainId,
) -> Result<(), DurableCommitRejection> {
    if binding.domain != domain || metadata.lifecycle().binding() != Some(binding) {
        return Err(DurableCommitRejection::ImportBindingMismatch);
    }
    Ok(())
}

fn write_progress(
    session: &mut dyn SqlSession,
    phase: i64,
    progress: &ImportProgress,
) -> Result<(), DurableCommitRejection> {
    let bytes: Vec<u8> = encode_import_progress(progress).map_err(|_| conflict())?;
    let changed = session
        .exec(
            "UPDATE durable_import_progress SET phase = ?1, progress = ?2 WHERE id = 1",
            &[SqlValue::Integer(phase), SqlValue::Blob(bytes)],
        )
        .map_err(|error| reject(error.into()))?;
    if changed.rows_affected() != 1 {
        return Err(conflict());
    }
    Ok(())
}

fn expected_head(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    id: ObjectId,
    head: &ImportObjectHead,
) -> Result<DurableObjectHead, DurableCommitRejection> {
    let latest: DurableObjectVersion = max_object_version(session, id)
        .map_err(reject)?
        .ok_or_else(conflict)?;
    let version: DurableObjectVersionRecord = load_object_version(session, namespace, id, latest)
        .map_err(reject)?
        .ok_or_else(conflict)?;
    match head {
        ImportObjectHead::Tombstoned {
            last_object_version,
        } if *last_object_version == latest => Ok(DurableObjectHead::Tombstoned {
            head_revision: ObjectHeadRevision::FIRST,
            last_object_version: latest,
        }),
        ImportObjectHead::Current {
            object_version,
            digest,
            owner_projection,
            routing_projection,
        } if *object_version == latest && *digest == version.digest() => {
            if let DurableObjectPayload::Inline(inline) = version.payload()
                && owner_projection.owner() != Some(&inline.object().owner)
            {
                return Err(conflict());
            }
            Ok(DurableObjectHead::Current {
                head_revision: ObjectHeadRevision::FIRST,
                object_version: latest,
                digest: *digest,
                owner_projection: owner_projection.clone(),
                routing_projection: routing_projection.clone(),
            })
        }
        _ => Err(conflict()),
    }
}

fn install_head(
    session: &mut dyn SqlSession,
    id: ObjectId,
    head: &ImportObjectHead,
) -> Result<(), DurableCommitRejection> {
    let (status, version, algorithm, digest, owner, routing): (
        i64,
        SqlValue,
        SqlValue,
        SqlValue,
        SqlValue,
        SqlValue,
    ) = match head {
        ImportObjectHead::Current {
            object_version,
            digest,
            owner_projection,
            routing_projection,
        } => (
            OBJECT_HEAD_STATUS_CURRENT,
            SqlValue::Blob(encode_u64(object_version.get()).to_vec()),
            SqlValue::Integer(i64::from(digest.algorithm().as_u16())),
            SqlValue::Blob(digest.bytes().to_vec()),
            owner_projection.bytes().map(<[u8]>::to_vec).into(),
            routing_projection.bytes().map(<[u8]>::to_vec).into(),
        ),
        ImportObjectHead::Tombstoned { .. } => (
            OBJECT_HEAD_STATUS_TOMBSTONED,
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Null,
        ),
    };
    session.exec("INSERT INTO durable_object_heads (object_id, status, head_revision, object_version,
        digest_algorithm, digest_bytes, owner_projection, routing_projection) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        &[SqlValue::Blob(id.as_bytes().to_vec()), SqlValue::Integer(status),
          SqlValue::Blob(encode_u64(ObjectHeadRevision::FIRST.get()).to_vec()), version, algorithm, digest, owner, routing])
        .map_err(|error| reject(error.into()))?;
    Ok(())
}

fn install_rows(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    batch: &ImportBatch,
    retry: bool,
) -> Result<(), DurableCommitRejection> {
    // The batch's closed locator order puts immutable versions before heads.
    // Any late failure rolls back earlier rows and progress in the same write.
    for row in batch.rows() {
        match row {
            ImportRow::State { key, value } => {
                let stored: VersionedStateValue = load_state_value(session, key).map_err(reject)?;
                if stored.revision() != StateRevision::INITIAL {
                    if stored.value() != value.as_deref() {
                        return Err(conflict());
                    }
                } else {
                    if retry {
                        return Err(conflict());
                    }
                    let revision: StateRevision = StateRevision::INITIAL
                        .checked_next()
                        .map_err(|_| DurableCommitRejection::StateRevisionOverflow)?;
                    session
                        .exec(
                            "INSERT INTO durable_state (key, revision, value) VALUES (?1, ?2, ?3)",
                            &[
                                SqlValue::Blob(key.clone()),
                                SqlValue::Blob(encode_u64(revision.get()).to_vec()),
                                value.clone().into(),
                            ],
                        )
                        .map_err(|error| reject(error.into()))?;
                }
            }
            ImportRow::ObjectVersion(version) => {
                if version.provenance().chain_id() != &batch.binding().context.chain_id {
                    return Err(DurableCommitRejection::ImportBindingMismatch);
                }
                match load_object_version(
                    session,
                    namespace,
                    version.object_id(),
                    version.object_version(),
                )
                .map_err(reject)?
                {
                    Some(stored) if &stored == version => {}
                    Some(_) => return Err(conflict()),
                    None if retry => return Err(conflict()),
                    None => insert_object_version(session, namespace, version)?,
                }
            }
            ImportRow::ObjectHead { object_id, head } => {
                let expected: DurableObjectHead =
                    expected_head(session, namespace, *object_id, head)?;
                let exists = session
                    .exec(
                        "SELECT object_id FROM durable_object_heads WHERE object_id = ?1",
                        &[SqlValue::Blob(object_id.as_bytes().to_vec())],
                    )
                    .map_err(|error| reject(error.into()))?;
                if exists
                    .one()
                    .map_err(|error| reject(error.into()))?
                    .is_some()
                {
                    if load_object_head(session, namespace, *object_id).map_err(reject)? != expected
                    {
                        return Err(conflict());
                    }
                } else {
                    if retry {
                        return Err(conflict());
                    }
                    install_head(session, *object_id, head)?;
                }
            }
            ImportRow::Receipt(receipt) => {
                match load_receipt(session, receipt.request_id()).map_err(reject)? {
                    Some(stored) if &stored == receipt => {}
                    Some(_) => return Err(conflict()),
                    None if retry => return Err(conflict()),
                    None => {
                        let digest: Digest32 = receipt.event_digest();
                        session
                            .exec(
                                "INSERT INTO durable_receipts (request_id, event_digest_algorithm,
                            event_digest_bytes, canonical_bytes) VALUES (?1, ?2, ?3, ?4)",
                                &[
                                    SqlValue::Blob(receipt.request_id().as_bytes().to_vec()),
                                    SqlValue::Integer(i64::from(digest.algorithm().as_u16())),
                                    SqlValue::Blob(digest.bytes().to_vec()),
                                    SqlValue::Blob(receipt.canonical_bytes().to_vec()),
                                ],
                            )
                            .map_err(|error| reject(error.into()))?;
                    }
                }
            }
        }
    }
    Ok(())
}

impl<B: SqlBackend> SqlDurableEngine<B> {
    fn import_write(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        step: impl FnOnce(&mut dyn SqlSession, &NamespaceMetadata) -> Result<(), DurableCommitRejection>,
    ) -> DurableCommitOutcome {
        if !self.domain_is_bound(domain) {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch);
        }
        run_write(
            &self.backend,
            Self::budget(context),
            |session, now| {
                let result: Result<(), DurableCommitRejection> = (|| {
                    let metadata: NamespaceMetadata =
                        schema::verify_namespace(session, &self.namespace)
                            .map_err(|error| reject(error.into()))?;
                    validate_authority(&metadata, context, now).map_err(reject)?;
                    step(session, &metadata)?;
                    check_deadline_before_commit(session, context).map_err(reject)
                })();
                Ok(match result {
                    Ok(()) => TransactionDecision::Commit(DurableCommitOutcome::Committed),
                    Err(reason) => {
                        TransactionDecision::Rollback(DurableCommitOutcome::Rejected(reason))
                    }
                })
            },
            Self::unavailable_commit_outcome,
        )
    }

    /// Storage-only begin; only the immutable FreshImport binding may advance.
    pub fn begin_import(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        initial_accumulator: Digest32,
    ) -> DurableCommitOutcome {
        self.import_write(context, domain, |session, metadata| {
            binding_matches(metadata, binding, domain)?;
            let initial: ImportProgress = ImportProgress { next_ordinal: 0, last_batch_digest: None, accumulator: initial_accumulator };
            match metadata.lifecycle() {
                NamespaceLifecycle::FreshImport(_) => {}
                NamespaceLifecycle::Importing { progress, .. } if progress == &initial => return Ok(()),
                _ => return Err(conflict()),
            }
            let inventory = session.exec("SELECT EXISTS(SELECT 1 FROM durable_state UNION ALL SELECT 1 FROM durable_receipts
                UNION ALL SELECT 1 FROM durable_object_heads UNION ALL SELECT 1 FROM durable_object_versions
                UNION ALL SELECT 1 FROM durable_outbox_messages UNION ALL SELECT 1 FROM durable_outbox_delivery
                UNION ALL SELECT 1 FROM durable_outbox_attempts)", &[]).map_err(|error| reject(error.into()))?;
            if inventory.one().map_err(|error| reject(error.into()))?.ok_or_else(conflict)?
                .integer(0).map_err(|error| reject(SqlSessionError::from(error).into()))? != 0 { return Err(conflict()); }
            write_progress(session, 1, &initial)?;
            schema::advance_mutation_sequence(session, metadata.mutation_sequence()).map_err(|error| reject(error.into()))?;
            Ok(())
        })
    }

    /// Reads validated local progress; missing required origin/progress refuses.
    pub fn read_import_progress(
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

    /// Atomic bounded installation with exact retry, never overwrite/repair.
    pub fn commit_import_batch(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        batch: &ImportBatch,
    ) -> DurableCommitOutcome {
        self.import_write(context, domain, |session, metadata| {
            binding_matches(metadata, batch.binding(), domain)?;
            let NamespaceLifecycle::Importing { progress, .. } = metadata.lifecycle() else {
                return Err(conflict());
            };
            if progress == batch.next() {
                return install_rows(session, &self.namespace, batch, true);
            }
            if progress != batch.expected() {
                return Err(conflict());
            }
            install_rows(session, &self.namespace, batch, false)?;
            write_progress(session, 1, batch.next())?;
            schema::advance_mutation_sequence(session, metadata.mutation_sequence())
                .map_err(|error| reject(error.into()))?;
            Ok(())
        })
    }

    /// Finishes only against the caller's exact current destination observation.
    /// This flag is durable installation completeness, not readiness or serving.
    pub fn finish_import(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        expected: &ImportProgress,
        verified_target: &PortableSnapshotToken,
    ) -> DurableCommitOutcome {
        self.import_write(context, domain, |session, metadata| {
            binding_matches(metadata, binding, domain)?;
            if expected.next_ordinal != binding.row_count
                || metadata.lifecycle().progress() != Some(expected)
            {
                return Err(conflict());
            }
            let namespace: Vec<u8> =
                portable::portable_namespace_bytes(&self.namespace, &metadata.source_instance_id())
                    .map_err(|_| conflict())?;
            verified_target
                .check(
                    &namespace,
                    domain,
                    metadata.writer_fence(),
                    metadata.mutation_sequence(),
                )
                .map_err(|_| conflict())?;
            match metadata.lifecycle() {
                NamespaceLifecycle::CompleteInactive { .. } => return Ok(()),
                NamespaceLifecycle::Importing { .. } => {}
                _ => return Err(conflict()),
            }
            write_progress(session, 2, expected)?;
            schema::advance_mutation_sequence(session, metadata.mutation_sequence())
                .map_err(|error| reject(error.into()))?;
            Ok(())
        })
    }
}
