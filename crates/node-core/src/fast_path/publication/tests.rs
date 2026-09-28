//! DR-0154 publication-retention regressions over real handoff-capable
//! (`0x6424/v2`) commitment witnesses, real quorum `FastCertificate`s and a
//! real durable store -- reusing the same paid-execution fixtures the
//! fast-path prepare/apply regressions use, so every bundle here carries an
//! actually certified paid `Call`, not a synthetic envelope.

use super::*;
use crate::fast_path::tests::{
    IndeterminateCommitStore, RetentionReplica, TestSigner, logical_replica, physical_replica,
    physical_transfer_bundle_bytes, rebundle_with_other_subset, transfer_bundle_bytes,
    transfer_bytes,
};
use crate::paid_execution::tests::{
    FIRST_PAID_NONCE, context, domain, next_nonce, protocol, resolver,
};
use consensus::bundle::{
    ArtifactEntry, ArtifactManifest, PublicationBundle, encode_publication_bundle,
};
use protocol_types::HashPurpose;

const REQUEST: u8 = 0xE4;

fn retain(
    replica: &RetentionReplica,
    bundle: &PublicationBundle,
    signer: &TestSigner,
) -> RetentionResult<AvailabilityVote> {
    retain_publication(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &encode_publication_bundle(bundle).unwrap(),
        signer,
    )
}

fn retained_publication(replica: &RetentionReplica, request: u8) -> FastPathPublicationRecord {
    let key: Vec<u8> = fastpath_publication_key(protocol().chain_id(), &[request; 32]).unwrap();
    decode_fastpath_publication_record(&replica.row(&key).expect("publication retained")).unwrap()
}

fn retained_ack(replica: &RetentionReplica, request: u8) -> Option<FastPathAvailabilityAckRecord> {
    let key: Vec<u8> =
        fastpath_availability_ack_key(protocol().chain_id(), &[request; 32]).unwrap();
    replica
        .row(&key)
        .map(|bytes| decode_fastpath_availability_ack_record(&bytes).unwrap())
}

#[test]
fn retention_verifies_the_complete_closure_and_durably_retains_before_exposing_an_ack() {
    let replica: RetentionReplica = logical_replica();
    let (bundle, certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    assert!(
        !bundle.manifest.entries.is_empty(),
        "a real certified paid Call must require replay artifacts"
    );

    let vote: AvailabilityVote = retain(&replica, &bundle, &replica.signer).unwrap();
    assert_eq!(vote.identity.request_id, [REQUEST; 32]);
    assert_eq!(vote.identity.signed_intent_digest, certificate.tx_hash);
    assert_eq!(
        vote.identity.execution_commitment,
        certificate.execution_effects_hash
    );

    let ack: FastPathAvailabilityAckRecord =
        retained_ack(&replica, REQUEST).expect("acknowledgement retained");
    assert_eq!(ack.vote, encode_availability_vote(&vote).unwrap());
    assert_eq!(
        ack.identity,
        encode_availability_identity(&vote.identity).unwrap()
    );

    // Every artifact's exact bytes are durably retained, not just its hash.
    let record: FastPathPublicationRecord = retained_publication(&replica, REQUEST);
    assert_eq!(record.request_id, [REQUEST; 32]);
    assert_eq!(record.witness, bundle.witness);
    assert_eq!(record.signed_intent, bundle.signed_intent);
    for (entry, content) in bundle.manifest.entries.iter().zip(bundle.contents.iter()) {
        let key: Vec<u8> = artifact_key(protocol().chain_id(), &[REQUEST; 32], entry).unwrap();
        assert_eq!(replica.row(&key).as_deref(), Some(content.as_slice()));
    }
}

#[test]
fn retention_changes_no_lock_head_nonce_or_receipt() {
    let replica: RetentionReplica = logical_replica();
    let locks_before: Vec<Option<Vec<u8>>> = replica.lock_rows();
    let head_before = replica.coin_head();
    let nonce_before: u64 = next_nonce(&replica.store);
    let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);

    retain(&replica, &bundle, &replica.signer).unwrap();

    assert_eq!(replica.lock_rows(), locks_before);
    assert_eq!(replica.coin_head(), head_before);
    assert_eq!(next_nonce(&replica.store), nonce_before);
    assert!(
        replica.request_receipt([REQUEST; 32]).is_none(),
        "retention must never create an original user receipt"
    );
}

#[test]
fn retention_accepts_a_full_certificate_despite_a_conflicting_partial_local_prepare() {
    // DR-0154's surviving-observation case: this replica locally prepared a
    // conflicting request Y over the same object and sender nonce; the quorum
    // certified X. Retaining X's full certificate must neither refuse nor
    // disturb Y's reservations.
    let replica: RetentionReplica = logical_replica();
    let conflicting: FastVote = replica.prepare_transfer(0xD3, FIRST_PAID_NONCE).unwrap();
    let locks_before: Vec<Option<Vec<u8>>> = replica.lock_rows();
    assert!(
        locks_before.iter().all(Option::is_some),
        "the conflicting prepare must really hold both locks"
    );

    let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let vote: AvailabilityVote = retain(&replica, &bundle, &replica.signer).unwrap();
    assert_eq!(vote.identity.request_id, [REQUEST; 32]);

    assert_eq!(
        replica.lock_rows(),
        locks_before,
        "retention must not release or overwrite a conflicting local lock"
    );
    assert_eq!(
        replica.prepare_transfer(0xD3, FIRST_PAID_NONCE).unwrap(),
        conflicting,
        "the conflicting prepared record must still replay byte-identically"
    );
}

#[test]
fn an_equivalent_valid_signer_subset_returns_the_same_retained_acknowledgement() {
    let replica: RetentionReplica = logical_replica();
    let (first, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let second: PublicationBundle = rebundle_with_other_subset(REQUEST, FIRST_PAID_NONCE);
    assert_ne!(
        encode_publication_bundle(&first).unwrap(),
        encode_publication_bundle(&second).unwrap(),
        "the fixture must really carry two different valid proofs"
    );

    let original: AvailabilityVote = retain(&replica, &first, &replica.signer).unwrap();
    let retained_certificate: Vec<u8> = retained_publication(&replica, REQUEST).certificate;
    let repeated: AvailabilityVote = retain(&replica, &second, &replica.signer).unwrap();

    assert_eq!(original, repeated, "one operation, one acknowledgement");
    assert_eq!(
        retained_publication(&replica, REQUEST).certificate,
        retained_certificate,
        "the first accepted proof's exact audit bytes are not replaced"
    );
}

#[test]
fn exact_retention_replay_returns_the_retained_acknowledgement() {
    let replica: RetentionReplica = logical_replica();
    let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let first: AvailabilityVote = retain(&replica, &bundle, &replica.signer).unwrap();
    assert_eq!(retain(&replica, &bundle, &replica.signer).unwrap(), first);
}

#[test]
fn freeze_blocks_new_retention_ack_but_preserves_exact_ack_replay() {
    let replica: RetentionReplica = logical_replica();
    let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let first: AvailabilityVote = retain(&replica, &bundle, &replica.signer).unwrap();
    let closure: crate::ordered_economics::AdmissionClosureRecord =
        crate::ordered_economics::AdmissionClosureRecord {
            closed_epoch: protocol().epoch(),
            request_id: [0x55; 32],
            closed_at_block_height: 3,
        };
    let key: Vec<u8> = crate::ordered_economics::engine::admission_closure_key_for_tests(
        protocol().chain_id(),
        protocol().epoch(),
    );
    replica.put_row(
        key,
        crate::ordered_economics::encode_admission_closure_record(&closure).unwrap(),
    );
    assert_eq!(retain(&replica, &bundle, &replica.signer).unwrap(), first);

    let fresh_request: u8 = REQUEST + 1;
    let (fresh, _certificate) = transfer_bundle_bytes(fresh_request, FIRST_PAID_NONCE);
    assert!(matches!(
        retain(&replica, &fresh, &replica.signer),
        Err(PublicationRetentionError::Node(
            NodeCoreError::PersistenceInvariant(
                "admission closed by a committed ordered-economics epoch freeze"
            )
        ))
    ));
    assert!(retained_ack(&replica, fresh_request).is_none());
}

#[test]
fn retention_replay_refuses_corrupt_stored_operands_and_certificate() {
    for corruption in 0..3 {
        let replica: RetentionReplica = logical_replica();
        let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
        let first: AvailabilityVote = retain(&replica, &bundle, &replica.signer).unwrap();
        let mut record: FastPathPublicationRecord = retained_publication(&replica, REQUEST);
        match corruption {
            0 => record.request_id = [0xAB; 32],
            1 => record.signed_intent.push(0xAB),
            _ => record.certificate.push(0xAB),
        }
        replica.put_row(
            fastpath_publication_key(protocol().chain_id(), &[REQUEST; 32]).unwrap(),
            encode_fastpath_publication_record(&record).unwrap(),
        );
        assert!(matches!(
            retain(&replica, &bundle, &replica.signer),
            Err(PublicationRetentionError::InconsistentRetainedRecord(_))
        ));
        assert_eq!(
            retained_ack(&replica, REQUEST).unwrap().vote,
            encode_availability_vote(&first).unwrap()
        );
    }
}

#[test]
fn retention_replay_refuses_corrupt_stored_artifact() {
    let replica: RetentionReplica = logical_replica();
    let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let first: AvailabilityVote = retain(&replica, &bundle, &replica.signer).unwrap();
    let entry: &ArtifactEntry = bundle.manifest.entries.first().unwrap();
    let key: Vec<u8> = artifact_key(protocol().chain_id(), &[REQUEST; 32], entry).unwrap();
    replica.put_row(key, b"corrupted artifact bytes".to_vec());
    assert!(matches!(
        retain(&replica, &bundle, &replica.signer),
        Err(PublicationRetentionError::InconsistentRetainedRecord(
            "retained publication artifact"
        ))
    ));
    assert_eq!(
        retained_ack(&replica, REQUEST).unwrap().vote,
        encode_availability_vote(&first).unwrap()
    );
}

#[test]
fn retention_refuses_a_bundle_whose_identity_differs_from_the_retained_one() {
    // A retained publication pins one logical identity per request id. A
    // fully valid bundle that derives a *different* identity for that same
    // request id must fail closed and sign nothing, rather than replace the
    // retained record or expose a second acknowledgement.
    let replica: RetentionReplica = logical_replica();
    let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let vote: AvailabilityVote = retain(&replica, &bundle, &replica.signer).unwrap();

    let mut other: AvailabilityIdentity = vote.identity.clone();
    other.signed_intent_digest = Digest32::new(other.signed_intent_digest.algorithm(), [0x77; 32]);
    let mut record: FastPathPublicationRecord = retained_publication(&replica, REQUEST);
    record.identity = encode_availability_identity(&other).unwrap();
    replica.put_row(
        fastpath_publication_key(protocol().chain_id(), &[REQUEST; 32]).unwrap(),
        encode_fastpath_publication_record(&record).unwrap(),
    );

    assert!(matches!(
        retain(&replica, &bundle, &replica.signer),
        Err(PublicationRetentionError::ConflictingRetainedIdentity)
    ));
    assert_eq!(
        retained_ack(&replica, REQUEST)
            .expect("the original acknowledgement is untouched")
            .vote,
        encode_availability_vote(&vote).unwrap()
    );
}

#[test]
fn retention_refuses_a_manifest_missing_a_required_artifact() {
    let replica: RetentionReplica = logical_replica();
    let (mut bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    bundle.manifest.entries.pop();
    bundle.contents.pop();
    assert!(matches!(
        retain(&replica, &bundle, &replica.signer),
        Err(PublicationRetentionError::MissingRequiredArtifact { .. })
    ));
    assert!(retained_ack(&replica, REQUEST).is_none());
}

#[test]
fn retention_refuses_a_manifest_declaring_an_unrequired_artifact() {
    let replica: RetentionReplica = logical_replica();
    let (mut bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let content: Vec<u8> = b"unrequired artifact bytes".to_vec();
    // `ObjectBody` is the highest kind and an all-0xFF identity sorts after
    // every real object identity here, so the manifest stays canonically
    // ordered and the refusal is really about closure, not about ordering.
    bundle.manifest.entries.push(ArtifactEntry {
        kind: ArtifactKind::ObjectBody,
        identity: vec![0xFF; 40],
        content_digest: resolver()
            .hash_for_purpose(protocol().epoch(), HashPurpose::Object, &content)
            .unwrap(),
        content_length: u32::try_from(content.len()).unwrap(),
    });
    bundle.contents.push(content);
    assert!(matches!(
        retain(&replica, &bundle, &replica.signer),
        Err(PublicationRetentionError::UnrequiredArtifact { .. })
    ));
    assert!(retained_ack(&replica, REQUEST).is_none());
}

#[test]
fn retention_refuses_substituted_artifact_content() {
    let replica: RetentionReplica = logical_replica();
    let (mut bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let last: usize = bundle.contents.len() - 1;
    let length: usize = bundle.contents[last].len();
    bundle.contents[last] = vec![0x5A; length];
    assert!(matches!(
        retain(&replica, &bundle, &replica.signer),
        Err(PublicationRetentionError::Bundle(
            consensus::bundle::PublicationBundleError::ArtifactContentDigestMismatch { .. }
        ))
    ));
    assert!(retained_ack(&replica, REQUEST).is_none());
}

#[test]
fn retention_refuses_a_signed_intent_that_is_not_the_certified_transaction() {
    let replica: RetentionReplica = logical_replica();
    let (mut bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    bundle.signed_intent = transfer_bytes(&replica.fixture, 0xD3, FIRST_PAID_NONCE);
    assert!(matches!(
        retain(&replica, &bundle, &replica.signer),
        Err(PublicationRetentionError::SignedIntentDigestMismatch)
    ));
    assert!(retained_ack(&replica, REQUEST).is_none());
}

#[test]
fn retention_refuses_a_foreign_atomicity_domain() {
    let replica: RetentionReplica = logical_replica();
    let (mut bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    bundle.domain = AtomicityDomainId::new([0x9A; 32]).unwrap();
    assert!(matches!(
        retain(&replica, &bundle, &replica.signer),
        Err(PublicationRetentionError::ForeignDomain)
    ));
}

#[test]
fn retention_refuses_a_historical_v1_commitment_witness() {
    // A physical-profile store produces a `0x6424/v1` witness. Its bytes stay
    // verifiable under their own original rules, but they can never back a
    // publication bundle.
    let physical: RetentionReplica = physical_replica();
    let (bundle, _certificate) = physical_transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let error = retain(&physical, &bundle, &physical.signer)
        .expect_err("a v1 witness must never be retained as a publication bundle");
    assert!(
        matches!(
            error,
            PublicationRetentionError::Node(NodeCoreError::PersistenceInvariant(
                "fast-path commitment witness is not the handoff-capable v2 profile"
            ))
        ),
        "unexpected error {error}"
    );
    assert!(retained_ack(&physical, REQUEST).is_none());
}

#[test]
fn an_indeterminate_commit_exposes_no_acknowledgement() {
    let replica: RetentionReplica = logical_replica();
    let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let store: IndeterminateCommitStore = IndeterminateCommitStore::new(replica.store.clone());
    let error = retain_publication(
        &store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &encode_publication_bundle(&bundle).unwrap(),
        &replica.signer,
    )
    .expect_err("an ambiguous commit must never expose a signature");
    assert!(
        matches!(
            error,
            PublicationRetentionError::Node(NodeCoreError::DurableCommitIndeterminate(_))
        ),
        "unexpected error {error}"
    );
    assert!(retained_ack(&replica, REQUEST).is_none());
}

#[test]
fn retained_records_round_trip_and_reject_noncanonical_bytes() {
    let replica: RetentionReplica = logical_replica();
    let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let vote: AvailabilityVote = retain(&replica, &bundle, &replica.signer).unwrap();

    let record: FastPathPublicationRecord = retained_publication(&replica, REQUEST);
    let bytes: Vec<u8> = encode_fastpath_publication_record(&record).unwrap();
    assert_eq!(decode_fastpath_publication_record(&bytes).unwrap(), record);
    let mut padded: Vec<u8> = bytes;
    padded.push(0);
    assert!(decode_fastpath_publication_record(&padded).is_err());

    let ack: FastPathAvailabilityAckRecord = FastPathAvailabilityAckRecord {
        identity: encode_availability_identity(&vote.identity).unwrap(),
        vote: encode_availability_vote(&vote).unwrap(),
    };
    let ack_bytes: Vec<u8> = encode_fastpath_availability_ack_record(&ack).unwrap();
    assert_eq!(
        decode_fastpath_availability_ack_record(&ack_bytes).unwrap(),
        ack
    );
    let mut truncated: Vec<u8> = ack_bytes;
    truncated.pop();
    assert!(decode_fastpath_availability_ack_record(&truncated).is_err());
}

/// A synthetic `ArtifactEntry` for exercising [`stage_publication_artifacts`]
/// in isolation, with no certified bundle required: staging only ever reads
/// `entry.kind` and `entry.content_digest.bytes()` (via [`artifact_key`]), so
/// the algorithm and identity here are arbitrary but fixed.
fn staging_entry(
    kind: ArtifactKind,
    identity: u8,
    digest_byte: u8,
    content: &[u8],
) -> ArtifactEntry {
    ArtifactEntry {
        kind,
        identity: vec![identity; 4],
        content_digest: Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [digest_byte; 32]),
        content_length: u32::try_from(content.len()).unwrap(),
    }
}

#[test]
fn stage_publication_artifacts_dedupes_identical_content_under_different_identities() {
    // Two distinct required identities of the same kind that happen to hold
    // byte-identical content are content-addressed to the exact same storage
    // key; staging must write that key once, not refuse the manifest as a
    // duplicate write.
    let chain: ChainId = protocol().chain_id().clone();
    let request: [u8; 32] = [0xE5; 32];
    let content: Vec<u8> = b"shared artifact bytes".to_vec();
    let manifest: ArtifactManifest = ArtifactManifest {
        entries: vec![
            staging_entry(ArtifactKind::StateValue, 0x01, 0x99, &content),
            staging_entry(ArtifactKind::StateValue, 0x02, 0x99, &content),
        ],
    };
    let staged =
        stage_publication_artifacts(&chain, &request, &manifest, &[content.clone(), content])
            .expect("identical content under different identities must dedupe, not conflict");
    assert_eq!(staged.len(), 1, "one distinct storage key expected");
}

#[test]
fn stage_publication_artifacts_refuses_a_genuine_content_disagreement_under_one_key() {
    // Two entries that collide on the exact same content-addressed storage
    // key (same kind, same declared digest) but disagree on their actual
    // bytes must be refused, never silently resolved by picking one.
    let chain: ChainId = protocol().chain_id().clone();
    let request: [u8; 32] = [0xE6; 32];
    let manifest: ArtifactManifest = ArtifactManifest {
        entries: vec![
            staging_entry(ArtifactKind::StateValue, 0x01, 0x99, b"one"),
            staging_entry(ArtifactKind::StateValue, 0x02, 0x99, b"other"),
        ],
    };
    let error = stage_publication_artifacts(
        &chain,
        &request,
        &manifest,
        &[b"one".to_vec(), b"other".to_vec()],
    )
    .expect_err("a genuine content disagreement under one key must refuse");
    assert!(
        matches!(
            error,
            PublicationRetentionError::Node(NodeCoreError::PersistenceInvariant(
                "publication artifact content disagrees under one content-addressed key"
            ))
        ),
        "unexpected error {error}"
    );
}

#[test]
fn a_real_v2_witness_round_trips_through_the_mirrored_operand_decoders() {
    // Pins `witness::required_artifacts` to `commitment`'s own encoders: the
    // decoder consumes every operand list exactly, with no trailing byte, and
    // derives precisely the closure the fixture's manifest declares.
    let (bundle, certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let (event_digest, required) = witness::required_artifacts(&bundle.witness).unwrap();
    assert_eq!(event_digest, certificate.tx_hash);
    assert_eq!(required.len(), bundle.manifest.entries.len());
    required.require_closed(&bundle.manifest).unwrap();
}

#[test]
fn a_truncated_or_padded_witness_is_refused() {
    let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let mut padded: Vec<u8> = bundle.witness.clone();
    padded.push(0);
    assert!(witness::required_artifacts(&padded).is_err());
    let mut truncated: Vec<u8> = bundle.witness;
    truncated.pop();
    assert!(witness::required_artifacts(&truncated).is_err());
}
