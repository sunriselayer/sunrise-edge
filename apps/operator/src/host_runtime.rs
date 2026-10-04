//! Shared, provider-neutral pieces reused verbatim by the original SQLite
//! source host, the PostgreSQL FastVote host and the first-successor
//! host: the real Ed25519 ConsensusSigner, a Transport that accepts
//! nothing to send, the already-committed-genesis/fee-policy read
//! (generic over any DurableDomainStateStore), and the pure committed-
//! validator-set key/member and committee-equality checks. Each caller
//! keeps its own distinct refusal diagnostics and decision ordering; this
//! module holds no decision ordering, writer-fence or dispatcher logic.
#![forbid(unsafe_code)]

use consensus::ConsensusSigner;
use ed25519_zebra::SigningKey;
use execution::paid_execution::{PaidFeePolicy, decode_paid_fee_policy};
use execution::publication::PublicationContext;
use native_http::{
    IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySource, IndexedOutboxIdentitySourceError,
};
use node_core::fast_path::FastPathValidatorSetRecord;
use node_core::fast_path::records::FastPathValidatorEntry;
use node_core::genesis::{GenesisInstallMarker, VerifiedGenesisRoot};
use protocol_types::{AtomicityDomainId, SignatureSchemeId, ValidatorId};
use runtime::{
    DurableDomainStateStore, DurableOperationContext, DurableOutboxLeaseId, RuntimeError,
    StorageCorrelationId, Transport, VersionedStateValue, WriterFenceGeneration,
};
use std::{
    error::Error,
    sync::atomic::{AtomicU64, Ordering},
};

/// A real (non-mocked) `ConsensusSigner` backed by a locally loaded
/// Ed25519 signing key. Never logs or exposes the key material.
#[derive(Clone)]
pub struct FileEd25519Signer {
    validator_id: ValidatorId,
    signing_key: SigningKey,
}

impl FileEd25519Signer {
    /// Takes ownership of an already-loaded key; never reads a file or
    /// holds any other authority itself.
    pub fn new(validator_id: ValidatorId, signing_key: SigningKey) -> Self {
        Self {
            validator_id,
            signing_key,
        }
    }
}

impl ConsensusSigner for FileEd25519Signer {
    fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        let signature: [u8; 64] = self.signing_key.sign(framed).into();
        Ok(signature.to_vec())
    }
}

/// A `Transport` that accepts nothing to send and never claims to have
/// delivered anything. Correct for every certified-only/original-source
/// router that never mounts a route calling `Transport::send`.
pub struct NoOutboundTransport;
impl Transport for NoOutboundTransport {
    fn send(&self, _message: Vec<u8>) -> Result<(), RuntimeError> {
        Err(RuntimeError::TransportUnavailable)
    }
    fn drain_outbound(&self) -> Result<Vec<Vec<u8>>, RuntimeError> {
        Ok(Vec::new())
    }
}

/// Attempt identities unique within one claimed writer generation. A
/// restarted host must claim a different generation. Sequence `0` is a permanent
/// exhaustion sentinel (never reused), so overflow wraps to `0` instead
/// of silently restarting at `1`.
///
/// Distinct from first-successor's own `GenerationIdentities`, which has
/// no sentinel and instead exhausts only at the natural `u64::MAX`
/// overflow boundary; that is a real behavioral difference, not
/// incidental duplication, so it is intentionally left unshared.
pub struct SequentialIdentitySource {
    generation: WriterFenceGeneration,
    sequence: AtomicU64,
}

impl SequentialIdentitySource {
    /// Starts fresh attempt identities for one already-claimed writer generation.
    pub const fn new(generation: WriterFenceGeneration) -> Self {
        Self::with_initial_sequence(generation, 1)
    }

    const fn with_initial_sequence(
        generation: WriterFenceGeneration,
        initial_sequence: u64,
    ) -> Self {
        Self {
            generation,
            sequence: AtomicU64::new(initial_sequence),
        }
    }
}

impl IndexedOutboxIdentitySource for SequentialIdentitySource {
    fn next_attempt_identity(
        &self,
    ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
        let sequence: u64 = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current: u64| {
                if current == 0 {
                    None
                } else {
                    Some(current.checked_add(1).unwrap_or(0))
                }
            })
            .map_err(|_| IndexedOutboxIdentitySourceError::Exhausted)?;
        let mut lease_bytes: [u8; 32] = [0; 32];
        lease_bytes[..8].copy_from_slice(&self.generation.get().to_be_bytes());
        lease_bytes[8..16].copy_from_slice(&sequence.to_be_bytes());
        let mut correlation: [u8; 16] = [0; 16];
        correlation[..8].copy_from_slice(&self.generation.get().to_be_bytes());
        correlation[8..].copy_from_slice(&sequence.to_be_bytes());
        Ok(IndexedOutboxAttemptIdentity::new(
            DurableOutboxLeaseId::new(lease_bytes)
                .map_err(|_| IndexedOutboxIdentitySourceError::Unavailable)?,
            StorageCorrelationId::new(correlation)
                .ok_or(IndexedOutboxIdentitySourceError::Unavailable)?,
        ))
    }
}

/// Reads the already-committed genesis marker and fee policy and requires
/// them to match the trusted verified root exactly. Never installs
/// anything. Generic over any `DurableDomainStateStore` so the SQLite
/// source host and the PostgreSQL FastVote host share one body instead of
/// two copies differing only in store type.
pub fn require_committed_genesis_fee_policy<S: DurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected_context: &PublicationContext,
    root: &VerifiedGenesisRoot,
) -> Result<PaidFeePolicy, Box<dyn Error>> {
    let marker_key: Vec<u8> = node_core::genesis_marker_key(expected_context)?;
    let marker_value: VersionedStateValue = store
        .get_versioned_durable(context, domain, &marker_key)
        .map_err(|error| format!("failed to read committed genesis marker: {error:?}"))?;
    let marker_bytes: &[u8] = marker_value.value().ok_or(
        "no committed genesis install marker for expected context; this namespace was never bootstrapped",
    )?;
    let marker: GenesisInstallMarker = node_core::decode_genesis_install_marker(marker_bytes)?;
    if marker.context != *expected_context
        || marker.manifest_digest != root.digest()
        || marker.genesis_authority != root.manifest().genesis_authority
    {
        return Err("committed genesis marker differs from the trusted verified root".into());
    }
    let policy_key: Vec<u8> =
        node_core::local_instance_state::paid_fee_policy_key(expected_context)?;
    let policy_value: VersionedStateValue = store
        .get_versioned_durable(context, domain, &policy_key)
        .map_err(|error| format!("failed to read committed fee policy: {error:?}"))?;
    let policy_bytes: &[u8] = policy_value
        .value()
        .ok_or("no committed paid fee policy for expected context")?;
    let policy: PaidFeePolicy = decode_paid_fee_policy(policy_bytes)?;
    if policy != root.manifest().fee_policy {
        return Err("committed fee policy differs from the trusted verified root".into());
    }
    Ok(policy)
}

/// Pure key/member check: the configured validator must be a committed
/// member whose registered public key matches the locally loaded signing
/// key. No store access; callers already hold the record they decided to
/// trust.
pub fn require_registered_signer<'a>(
    record: &'a FastPathValidatorSetRecord,
    validator_id: ValidatorId,
    public_key: &[u8; 32],
) -> Result<&'a FastPathValidatorEntry, String> {
    let entry: &FastPathValidatorEntry = record
        .validators
        .iter()
        .find(|candidate| candidate.id == validator_id)
        .ok_or(
            "configured --validator-id is not a member of the committed current validator set",
        )?;
    if entry.signature_scheme != SignatureSchemeId::Ed25519 || entry.public_key != public_key {
        return Err(
            "local signing key does not match the committed validator's registered public key"
                .into(),
        );
    }
    Ok(entry)
}

/// Pure equality: whether `record` is exactly the trusted root's own
/// signed committee/context. Callers keep their own distinct refusal
/// diagnostic text; this only decides the comparison.
pub fn fast_path_committee_matches(
    record: &FastPathValidatorSetRecord,
    root_committee: &FastPathValidatorSetRecord,
) -> bool {
    record == root_committee
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, Epoch, ProtocolVersion};

    fn test_context() -> PublicationContext {
        PublicationContext::new(
            ChainId::new("host-runtime-test").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(0),
        )
        .unwrap()
    }

    fn entry(seed: u8) -> FastPathValidatorEntry {
        FastPathValidatorEntry {
            id: ValidatorId::new([seed; 32]),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: vec![seed; 32],
        }
    }

    #[test]
    fn registered_signer_rejects_mismatched_public_key() {
        let record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: test_context(),
            validators: vec![entry(7)],
        };
        let mismatched_key: [u8; 32] = [1; 32];
        assert!(
            require_registered_signer(&record, ValidatorId::new([7; 32]), &mismatched_key).is_err()
        );
    }

    #[test]
    fn registered_signer_rejects_an_unknown_validator() {
        let record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: test_context(),
            validators: vec![entry(7)],
        };
        let key: [u8; 32] = [7; 32];
        assert!(require_registered_signer(&record, ValidatorId::new([9; 32]), &key).is_err());
    }

    #[test]
    fn registered_signer_accepts_the_matching_member() {
        let record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: test_context(),
            validators: vec![entry(7)],
        };
        let key: [u8; 32] = [7; 32];
        assert!(require_registered_signer(&record, ValidatorId::new([7; 32]), &key).is_ok());
    }

    #[test]
    fn committee_equality_accepts_the_identical_committee() {
        let record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: test_context(),
            validators: vec![entry(1), entry(2)],
        };
        let root_committee: FastPathValidatorSetRecord = record.clone();
        assert!(fast_path_committee_matches(&record, &root_committee));
    }

    #[test]
    fn committee_equality_rejects_a_foreign_committee() {
        let root_committee: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: test_context(),
            validators: vec![entry(1), entry(2)],
        };
        let foreign: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: test_context(),
            validators: vec![entry(1), entry(99)],
        };
        assert!(!fast_path_committee_matches(&foreign, &root_committee));
    }

    #[test]
    fn sequential_identity_source_exhaustion_is_sticky_near_u64_max() {
        let generation: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        let source: SequentialIdentitySource =
            SequentialIdentitySource::with_initial_sequence(generation, u64::MAX - 1);
        let first: IndexedOutboxAttemptIdentity = source
            .next_attempt_identity()
            .expect("sequence u64::MAX - 1 should succeed");
        let second: IndexedOutboxAttemptIdentity = source
            .next_attempt_identity()
            .expect("sequence u64::MAX should succeed");
        assert_ne!(first, second, "consecutive identities must not repeat");
        for _ in 0..10 {
            assert!(
                matches!(
                    source.next_attempt_identity(),
                    Err(IndexedOutboxIdentitySourceError::Exhausted)
                ),
                "identity source must remain exhausted"
            );
        }
    }

    #[test]
    fn sequential_identity_source_zero_sequence_is_immediately_exhausted() {
        let generation: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        let source: SequentialIdentitySource =
            SequentialIdentitySource::with_initial_sequence(generation, 0);
        assert!(matches!(
            source.next_attempt_identity(),
            Err(IndexedOutboxIdentitySourceError::Exhausted)
        ));
    }
}
