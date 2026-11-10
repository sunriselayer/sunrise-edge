//! Read-only original-bond source observation against the live host store.
//! The optional local listener exposes observations, never approval or signing.

#[cfg(target_os = "linux")]
pub(super) mod listener;

use crate::sqlite_genesis_checks::{
    OriginalHostPins, read_original_host_state, read_stable_advisory_with_token,
    verify_original_signer,
};
use execution::{LocalWasmExecutionEngine, local_execution::LocalExecutionPolicy};
use node_core::genesis::VerifiedGenesisRoot;
use node_core::{
    ObjectQueryResult,
    ordered_economics::{
        OrderedEconomicsEnvironment, OrderedEconomicsPolicy, OrderedHistoryIdentity,
        query_ordered_history_summary,
    },
    query_committed_epoch_state, query_object,
};
use objects::{Object, ObjectRef, decode_object, encode_object};
use protocol_types::{AtomicityDomainId, Digest32, Epoch, ValidatorId};
use runtime::portable::PortableSnapshotToken;
use runtime::{
    Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore};
use std::{
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

/// A local observation at one stable SQLite token. It is neither a chain
/// proof nor a mutation fence, and can become stale immediately after return.
pub(super) struct OriginalBondCurrentnessObservation {
    pub(super) token: PortableSnapshotToken,
    pub(super) epoch: Epoch,
    pub(super) validator_set_digest: Digest32,
    pub(super) ordered_tip: OrderedHistoryIdentity,
    pub(super) coin: ObjectRef,
}

/// Pinned, read-only reader for one original host's already-claimed writer
/// fence and *same* store Arc. Construction neither opens nor advances state.
/// Only the original host can construct this reader after its fence claim.
/// Its local listener grants no signing authority.
pub(super) struct OriginalBondCurrentnessReader {
    store: Arc<SqliteDurableStore>,
    blobs: Arc<SqliteBlobStore>,
    root: VerifiedGenesisRoot,
    policy: OrderedEconomicsPolicy,
    leg_policy: LocalExecutionPolicy,
    engine: LocalWasmExecutionEngine,
    domain: AtomicityDomainId,
    validator: ValidatorId,
    validator_public_key: [u8; 32],
    fence: WriterFenceGeneration,
    timeout_millis: u64,
    next_correlation: AtomicU64,
}

impl OriginalBondCurrentnessReader {
    /// Binds the reader to an original host's preexisting, claimed store.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        store: Arc<SqliteDurableStore>,
        blobs: Arc<SqliteBlobStore>,
        root: VerifiedGenesisRoot,
        domain: AtomicityDomainId,
        validator: ValidatorId,
        validator_public_key: [u8; 32],
        fence: WriterFenceGeneration,
        timeout: Duration,
    ) -> Result<Self, Box<dyn Error>> {
        let timeout_millis: u64 = u64::try_from(timeout.as_millis())?;
        if timeout_millis == 0
            || timeout_millis > super::MAX_HOST_TIMEOUT_SECONDS * 1000
            || root.genesis_context().epoch() != Epoch::new(0)
            || store.writer_fence()? != fence
        {
            return Err("original bond currentness reader pins are invalid".into());
        }
        let policy: OrderedEconomicsPolicy =
            OrderedEconomicsPolicy::from_genesis_root(&root, domain)?;
        let leg_policy: LocalExecutionPolicy =
            LocalExecutionPolicy::generic_object_results(root.genesis_context().clone());
        Ok(Self {
            store,
            blobs,
            root,
            policy,
            leg_policy,
            engine: LocalWasmExecutionEngine::new(),
            domain,
            validator,
            validator_public_key,
            fence,
            timeout_millis,
            next_correlation: AtomicU64::new(1),
        })
    }

    /// Rechecks one independently prepared original-bond Coin preimage. The
    /// caller must already have validated its operation-specific Coin meaning;
    /// this method requires the exact canonical body and reference to be the
    /// current inline object under a stable local token.
    pub(super) fn observe(
        &self,
        reviewed: &ObjectRef,
        reviewed_bytes: &[u8],
    ) -> Result<OriginalBondCurrentnessObservation, Box<dyn Error>> {
        if reviewed_bytes.is_empty()
            || reviewed_bytes.len() > node_core::MAX_AUTHENTICATED_OBJECT_BODY_BYTES
        {
            return Err("original bond reviewed Coin size refused".into());
        }
        let decoded: Object = decode_object(reviewed_bytes)?;
        if encode_object(&decoded)? != reviewed_bytes
            || decoded.id != reviewed.id
            || decoded.version != reviewed.version
        {
            return Err("original bond reviewed Coin preimage mismatch".into());
        }
        let sequence: u64 = self
            .next_correlation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| "original bond observation identity exhausted")?;
        let now: u64 = SystemClock.now_unix_millis()?;
        let deadline: u64 = now
            .checked_add(self.timeout_millis)
            .ok_or("original bond observation deadline overflow")?;
        let mut correlation: [u8; 16] = [0; 16];
        correlation[..8].copy_from_slice(&self.fence.get().to_be_bytes());
        correlation[8..].copy_from_slice(&sequence.to_be_bytes());
        let context: DurableOperationContext = DurableOperationContext::new(
            self.fence,
            StorageDeadline::new(deadline).ok_or("invalid observation deadline")?,
            StorageCorrelationId::new(correlation).ok_or("invalid observation identity")?,
        );
        let pins: OriginalHostPins<'_> = OriginalHostPins {
            domain: self.domain,
            expected_context: self.root.genesis_context(),
            root: &self.root,
            resolver: self.root.genesis_resolver(),
        };
        let environment: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
            policy: &self.policy,
            history: &[],
            leg_policy: &self.leg_policy,
            engine: &self.engine,
            blobs: self.blobs.as_ref(),
            seal: None,
        };
        let ((epoch, validator_set_digest, ordered_tip), token) =
            read_stable_advisory_with_token(self.store.as_ref(), &context, self.domain, || {
                let (_fee, record) =
                    read_original_host_state(self.store.as_ref(), &context, &pins)?;
                verify_original_signer(
                    &record,
                    &self.root,
                    self.validator,
                    &self.validator_public_key,
                )?;
                let live = query_committed_epoch_state(
                    self.store.as_ref(),
                    &context,
                    self.domain,
                    self.root.genesis_context().chain_id(),
                )?;
                let trusted_digest: Digest32 = self
                    .root
                    .genesis_committee()
                    .digest(self.root.genesis_resolver())?;
                if live.current_epoch != Epoch::new(0)
                    || live.current_validator_set_digest != trusted_digest
                {
                    return Err("original bond committed epoch/set changed".into());
                }
                let summary =
                    query_ordered_history_summary(self.store.as_ref(), &context, &environment)?;
                let query = query_object(
                    self.store.as_ref(),
                    &context,
                    self.domain,
                    self.root.genesis_context().chain_id(),
                    reviewed.id,
                )?;
                require_exact_inline(
                    query,
                    reviewed,
                    reviewed_bytes,
                    self.root.genesis_context().chain_id(),
                    self.root.genesis_context().protocol_version(),
                )?;
                Ok((
                    live.current_epoch,
                    live.current_validator_set_digest,
                    summary.identity,
                ))
            })?;
        if token.writer_fence() != self.fence {
            return Err("original bond observed writer fence changed".into());
        }
        Ok(OriginalBondCurrentnessObservation {
            token,
            epoch,
            validator_set_digest,
            ordered_tip,
            coin: reviewed.clone(),
        })
    }
}

fn require_exact_inline(
    query: ObjectQueryResult,
    reviewed: &ObjectRef,
    reviewed_bytes: &[u8],
    chain: &protocol_types::ChainId,
    protocol_version: protocol_types::ProtocolVersion,
) -> Result<(), Box<dyn Error>> {
    match query {
        ObjectQueryResult::CurrentInline {
            object_id,
            object_version,
            digest,
            creating_chain_id,
            protocol_version: created_version,
            canonical_object_bytes,
            ..
        } if object_id == reviewed.id
            && object_version.get() == reviewed.version
            && digest == reviewed.digest
            && &creating_chain_id == chain
            && created_version == protocol_version
            && canonical_object_bytes == reviewed_bytes =>
        {
            Ok(())
        }
        _ => Err("original bond Coin is absent, not inline, or differs from review".into()),
    }
}

#[cfg(test)]
#[path = "../../tests/support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[cfg(test)]
#[path = "../../tests/support/genesis_fixture.rs"]
mod genesis_fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::original_genesis_install::{OriginalGenesisInstallation, install_original_genesis};
    use ed25519_zebra::VerificationKey;
    use protocol_types::{ChainId, HashAlgorithmId, ProtocolVersion};
    use runtime::{DurableObjectVersion, ObjectHeadRevision};
    use runtime_sqlite::SqliteNamespace;
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "bond-currentness-unit-{}-{nonce}",
                std::process::id(),
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    pub(super) struct Installed {
        _directory: Directory,
        pub(super) store: Arc<SqliteDurableStore>,
        pub(super) blobs: Arc<SqliteBlobStore>,
        pub(super) root: VerifiedGenesisRoot,
        pub(super) network: super::genesis_fixture::FastVoteGenesisFixture,
        pub(super) claimed: WriterFenceGeneration,
        pub(super) public_key: [u8; 32],
        pub(super) reviewed: ObjectRef,
        pub(super) body: Vec<u8>,
    }

    impl Installed {
        pub(super) fn new() -> Self {
            let directory = Directory::new();
            let fixture = super::causal_genesis_fixture::build("bond-currentness-unit");
            let network = fixture.network;
            let root = VerifiedGenesisRoot::verify_bytes(
                &network.resolver,
                &network.manifest_bytes,
                network.manifest_digest,
                &network.context,
            )
            .unwrap();
            let initial = WriterFenceGeneration::new(1).unwrap();
            let namespace = SqliteNamespace::new(
                network.chain_id.clone(),
                network.validators[0].validator_id,
                network.domain,
            );
            let store = Arc::new(
                SqliteDurableStore::create_new(
                    directory.0.join("state.sqlite"),
                    namespace,
                    initial,
                )
                .unwrap(),
            );
            let blobs = Arc::new(
                SqliteBlobStore::create_new_fresh(directory.0.join("blobs.sqlite")).unwrap(),
            );
            let deadline = SystemClock
                .now_unix_millis()
                .unwrap()
                .checked_add(60_000)
                .unwrap();
            let context = DurableOperationContext::new(
                initial,
                StorageDeadline::new(deadline).unwrap(),
                StorageCorrelationId::new([0x71; 16]).unwrap(),
            );
            let policy = OrderedEconomicsPolicy::from_genesis_root(&root, network.domain).unwrap();
            install_original_genesis(
                store.as_ref(),
                blobs.as_ref(),
                &OriginalGenesisInstallation {
                    context: &context,
                    domain: network.domain,
                    resolver: &network.resolver,
                    root: &root,
                    policy: &policy,
                    checkpoint: 10,
                },
            )
            .unwrap();
            let claimed = initial.checked_next().unwrap();
            store.advance_writer_fence(initial, claimed).unwrap();
            let public_key: [u8; 32] =
                VerificationKey::from(&network.validators[0].signing_key).into();
            let coin = root
                .manifest()
                .objects
                .iter()
                .find(|entry| entry.object.id == network.fee_coin)
                .unwrap();
            let body = encode_object(&coin.object).unwrap();
            let reviewed = ObjectRef {
                id: coin.object.id,
                version: coin.object.version,
                digest: network
                    .resolver
                    .hash_for_purpose(network.epoch, protocol_types::HashPurpose::Object, &body)
                    .unwrap(),
            };
            Self {
                _directory: directory,
                store,
                blobs,
                root,
                network,
                claimed,
                public_key,
                reviewed,
                body,
            }
        }

        pub(super) fn reader(&self) -> OriginalBondCurrentnessReader {
            OriginalBondCurrentnessReader::new(
                Arc::clone(&self.store),
                Arc::clone(&self.blobs),
                self.root.clone(),
                self.network.domain,
                self.network.validators[0].validator_id,
                self.public_key,
                self.claimed,
                Duration::from_secs(30),
            )
            .unwrap()
        }

        pub(super) fn path(&self) -> &Path {
            &self._directory.0
        }
    }

    #[test]
    fn claimed_original_sqlite_coin_refuses_wrong_validator_and_stale_fence() {
        let installed = Installed::new();
        let reader = installed.reader();
        let observation = reader
            .observe(&installed.reviewed, &installed.body)
            .unwrap();
        assert_eq!(observation.token.writer_fence(), installed.claimed);
        assert_eq!(observation.epoch, installed.network.epoch);
        assert_eq!(observation.coin, installed.reviewed);
        assert_eq!(observation.ordered_tip.through_height, 0);

        let wrong_validator = OriginalBondCurrentnessReader::new(
            Arc::clone(&installed.store),
            Arc::clone(&installed.blobs),
            installed.root.clone(),
            installed.network.domain,
            installed.network.validators[1].validator_id,
            installed.public_key,
            installed.claimed,
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(
            wrong_validator
                .observe(&installed.reviewed, &installed.body)
                .is_err()
        );
        let changed_reference = ObjectRef {
            version: installed.reviewed.version + 1,
            ..installed.reviewed.clone()
        };
        assert!(reader.observe(&changed_reference, &installed.body).is_err());
        let stale = installed.claimed.checked_next().unwrap();
        installed
            .store
            .advance_writer_fence(installed.claimed, stale)
            .unwrap();
        assert!(
            reader
                .observe(&installed.reviewed, &installed.body)
                .is_err()
        );
    }

    #[test]
    fn local_coin_result_refuses_noncurrent_and_changed_preimages() {
        let chain = ChainId::new("bond-observation").unwrap();
        let version = ProtocolVersion::new(1);
        let id = objects::ObjectId::new([7; 32]);
        let digest = Digest32::new(HashAlgorithmId::Sha2_256, [8; 32]);
        let reviewed = ObjectRef {
            id,
            version: 1,
            digest,
        };
        let body = b"reviewed-coin";
        let current = || ObjectQueryResult::CurrentInline {
            object_id: id,
            head_revision: ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            creating_chain_id: chain.clone(),
            protocol_version: version,
            canonical_object_bytes: body.to_vec(),
        };
        assert!(require_exact_inline(current(), &reviewed, body, &chain, version).is_ok());
        for result in [
            ObjectQueryResult::Absent { object_id: id },
            ObjectQueryResult::Tombstoned {
                object_id: id,
                head_revision: ObjectHeadRevision::FIRST,
                last_object_version: DurableObjectVersion::FIRST,
            },
            ObjectQueryResult::CurrentBlobReference {
                object_id: id,
                head_revision: ObjectHeadRevision::FIRST,
                object_version: DurableObjectVersion::FIRST,
                digest,
                blob_digest: digest,
            },
        ] {
            assert!(require_exact_inline(result, &reviewed, body, &chain, version).is_err());
        }
        assert!(require_exact_inline(current(), &reviewed, b"changed", &chain, version).is_err());
        let wrong_version = ObjectRef {
            version: 2,
            ..reviewed.clone()
        };
        assert!(require_exact_inline(current(), &wrong_version, body, &chain, version).is_err());
        let wrong_digest = ObjectRef {
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [9; 32]),
            ..reviewed.clone()
        };
        assert!(require_exact_inline(current(), &wrong_digest, body, &chain, version).is_err());
        let foreign = ChainId::new("foreign").unwrap();
        assert!(require_exact_inline(current(), &reviewed, body, &foreign, version).is_err());
        assert!(
            require_exact_inline(current(), &reviewed, body, &chain, ProtocolVersion::new(2))
                .is_err()
        );
    }
}
