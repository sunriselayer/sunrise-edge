//! Single typed, closed family API for exact durable key construction shared
//! by every ordered-economics storage key rooted under
//! [`crate::ordered_economics::engine::ORDERED_ECONOMICS_STATE_PREFIX`].
//!
//! Historically `engine` and `identity` each hand-built
//! `<prefix><infix><chain id>[<suffix>]` bytes with their own ad hoc infix
//! concatenation, appending any suffix separately at the call site.
//! [`OrderedKeyFamily`] is a closed enum that carries each family's exact
//! required suffix as typed variant data, so [`key`] always builds one
//! complete, correctly suffixed address: no caller can omit a required
//! suffix, attach the wrong one, or mix up which family a view, epoch,
//! height, digest or request id belongs to.
use super::*;
use canonical_encoding::encode_chain_id;

/// One ordered-economics durable key family, carrying the exact payload its
/// historical builder appended after `<prefix><infix><chain id>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OrderedKeyFamily {
    /// `state/`: the durable `ConsensusState` row.
    State,
    /// `applied-height/`: the durable applied-height marker.
    AppliedHeight,
    /// `vote-high/`: the durable highest-voted-view watermark.
    VoteHigh,
    /// `leader-proposal/<view>`: the durable per-view signed leader proposal.
    LeaderProposal { view: u64 },
    /// `vote/<view>`: the durable per-view signed local vote.
    Vote { view: u64 },
    /// `committed-proof/<epoch><height>`: the immutable per-height committed
    /// proof archive.
    CommittedProof { epoch: Epoch, height: u64 },
    /// `candidate/<digest>`: the immutable per-digest candidate record.
    Candidate { digest: Digest32 },
    /// `header/<request id>`: the immutable per-request-id header record.
    Header { request_id: [u8; 32] },
    /// `outcome/<request id>`: the immutable per-request-id retained outcome
    /// record.
    Outcome { request_id: [u8; 32] },
}

impl OrderedKeyFamily {
    const fn infix(&self) -> &'static [u8] {
        match self {
            Self::State => b"state/",
            Self::AppliedHeight => b"applied-height/",
            Self::VoteHigh => b"vote-high/",
            Self::LeaderProposal { .. } => b"leader-proposal/",
            Self::Vote { .. } => b"vote/",
            Self::CommittedProof { .. } => b"committed-proof/",
            Self::Candidate { .. } => b"candidate/",
            Self::Header { .. } => b"header/",
            Self::Outcome { .. } => b"outcome/",
        }
    }
}

/// `<prefix><infix><chain id>`, unvalidated.
fn base_bytes(family: &OrderedKeyFamily, chain: &ChainId) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = super::engine::ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    key.extend_from_slice(family.infix());
    key.extend(encode_chain_id(chain)?);
    Ok(key)
}

/// Builds the one exact, complete, validated durable key for `family` on
/// `chain`. [`OrderedKeyFamily::State`], [`OrderedKeyFamily::AppliedHeight`],
/// [`OrderedKeyFamily::VoteHigh`], [`OrderedKeyFamily::LeaderProposal`] and
/// [`OrderedKeyFamily::Vote`] validate once over the complete key, exactly as
/// their historical direct-key/identity builders did.
/// [`OrderedKeyFamily::CommittedProof`], [`OrderedKeyFamily::Candidate`],
/// [`OrderedKeyFamily::Header`] and [`OrderedKeyFamily::Outcome`] validate the
/// `<prefix><infix><chain id>` prefix first and then revalidate the complete
/// key, exactly as their historical double-validation builders did.
pub(crate) fn key(chain: &ChainId, family: OrderedKeyFamily) -> Result<Vec<u8>, NodeCoreError> {
    let mut bytes: Vec<u8> = base_bytes(&family, chain)?;
    match family {
        OrderedKeyFamily::State | OrderedKeyFamily::AppliedHeight | OrderedKeyFamily::VoteHigh => {
            validate_transactional_state_key(&bytes)?;
        }
        OrderedKeyFamily::LeaderProposal { view } | OrderedKeyFamily::Vote { view } => {
            bytes.extend_from_slice(&view.to_be_bytes());
            validate_transactional_state_key(&bytes)?;
        }
        OrderedKeyFamily::CommittedProof { epoch, height } => {
            validate_transactional_state_key(&bytes)?;
            bytes.extend_from_slice(&epoch.get().to_be_bytes());
            bytes.extend_from_slice(&height.to_be_bytes());
            validate_transactional_state_key(&bytes)?;
        }
        OrderedKeyFamily::Candidate { digest } => {
            validate_transactional_state_key(&bytes)?;
            bytes.extend_from_slice(&digest.bytes());
            validate_transactional_state_key(&bytes)?;
        }
        OrderedKeyFamily::Header { request_id } | OrderedKeyFamily::Outcome { request_id } => {
            validate_transactional_state_key(&bytes)?;
            bytes.extend_from_slice(&request_id);
            validate_transactional_state_key(&bytes)?;
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LITERAL_PREFIX: &[u8] = b"se/instances/v1/ordered-economics/";

    fn test_chain() -> ChainId {
        ChainId::new("durable-keys-tests").unwrap()
    }

    fn literal_prefix(infix: &[u8], chain: &ChainId) -> Vec<u8> {
        let mut key: Vec<u8> = LITERAL_PREFIX.to_vec();
        key.extend_from_slice(infix);
        key.extend(encode_chain_id(chain).unwrap());
        key
    }

    #[test]
    fn state_key_matches_literal_bytes() {
        let chain: ChainId = test_chain();
        let expected: Vec<u8> = literal_prefix(b"state/", &chain);
        assert_eq!(super::super::engine::ordered_state_key_for_tests(&chain), expected);
    }

    #[test]
    fn applied_height_key_matches_literal_bytes() {
        let chain: ChainId = test_chain();
        let expected: Vec<u8> = literal_prefix(b"applied-height/", &chain);
        assert_eq!(
            super::super::engine::ordered_applied_height_key(&chain).unwrap(),
            expected
        );
    }

    #[test]
    fn vote_high_key_matches_literal_bytes() {
        let chain: ChainId = test_chain();
        let expected: Vec<u8> = literal_prefix(b"vote-high/", &chain);
        assert_eq!(
            super::super::identity::ordered_vote_high_key(&chain).unwrap(),
            expected
        );
    }

    #[test]
    fn leader_proposal_key_view_layout_zero_and_max() {
        let chain: ChainId = test_chain();
        for view in [0u64, u64::MAX] {
            let mut expected: Vec<u8> = literal_prefix(b"leader-proposal/", &chain);
            expected.extend_from_slice(&view.to_be_bytes());
            assert_eq!(
                super::super::identity::ordered_leader_record_key(&chain, view).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn vote_key_view_layout_zero_and_max() {
        let chain: ChainId = test_chain();
        for view in [0u64, u64::MAX] {
            let mut expected: Vec<u8> = literal_prefix(b"vote/", &chain);
            expected.extend_from_slice(&view.to_be_bytes());
            assert_eq!(
                super::super::identity::ordered_vote_record_key(&chain, view).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn committed_proof_key_epoch_and_height_layout_zero_and_max() {
        let chain: ChainId = test_chain();
        for epoch_value in [0u64, u64::MAX] {
            for height in [0u64, u64::MAX] {
                let mut expected: Vec<u8> = literal_prefix(b"committed-proof/", &chain);
                expected.extend_from_slice(&epoch_value.to_be_bytes());
                expected.extend_from_slice(&height.to_be_bytes());
                assert_eq!(
                    super::super::engine::ordered_committed_proof_key(
                        &chain,
                        Epoch::new(epoch_value),
                        height
                    )
                    .unwrap(),
                    expected
                );
            }
        }
    }

    #[test]
    fn candidate_key_digest_layout() {
        let chain: ChainId = test_chain();
        for fill in [0x00u8, 0xFF] {
            let digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [fill; 32]);
            let mut expected: Vec<u8> = literal_prefix(b"candidate/", &chain);
            expected.extend_from_slice(&digest.bytes());
            assert_eq!(
                super::super::engine::ordered_candidate_record_key(&chain, digest).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn header_key_request_id_layout() {
        let chain: ChainId = test_chain();
        for fill in [0x00u8, 0xFF] {
            let request_id: [u8; 32] = [fill; 32];
            let mut expected: Vec<u8> = literal_prefix(b"header/", &chain);
            expected.extend_from_slice(&request_id);
            assert_eq!(
                super::super::engine::ordered_request_header_key(&chain, &request_id).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn outcome_key_request_id_layout() {
        let chain: ChainId = test_chain();
        for fill in [0x00u8, 0xFF] {
            let request_id: [u8; 32] = [fill; 32];
            let mut expected: Vec<u8> = literal_prefix(b"outcome/", &chain);
            expected.extend_from_slice(&request_id);
            assert_eq!(
                super::super::engine::ordered_outcome_key(&chain, &request_id).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn required_families_do_not_collide_with_each_other_or_history() {
        let chain: ChainId = test_chain();
        let view: u64 = 7;
        let request_id: [u8; 32] = [0x11u8; 32];
        let digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]);
        let keys: Vec<Vec<u8>> = vec![
            super::super::engine::ordered_state_key_for_tests(&chain),
            super::super::engine::ordered_applied_height_key(&chain).unwrap(),
            super::super::identity::ordered_vote_high_key(&chain).unwrap(),
            super::super::identity::ordered_leader_record_key(&chain, view).unwrap(),
            super::super::identity::ordered_vote_record_key(&chain, view).unwrap(),
            super::super::engine::ordered_committed_proof_key(&chain, Epoch::new(view), view)
                .unwrap(),
            super::super::engine::ordered_candidate_record_key(&chain, digest).unwrap(),
            super::super::engine::ordered_request_header_key(&chain, &request_id).unwrap(),
            super::super::engine::ordered_outcome_key(&chain, &request_id).unwrap(),
        ];
        let unique: std::collections::BTreeSet<Vec<u8>> = keys.iter().cloned().collect();
        assert_eq!(unique.len(), keys.len());
    }

    #[test]
    fn required_families_do_not_alias_historical_candidate_header_outcome_proof_prefixes() {
        let chain: ChainId = test_chain();
        let view: u64 = 11;
        let historical_prefixes: Vec<Vec<u8>> = vec![
            literal_prefix(b"committed-proof/", &chain),
            literal_prefix(b"candidate/", &chain),
            literal_prefix(b"header/", &chain),
            literal_prefix(b"outcome/", &chain),
        ];
        let required_keys: Vec<Vec<u8>> = vec![
            super::super::engine::ordered_state_key_for_tests(&chain),
            super::super::engine::ordered_applied_height_key(&chain).unwrap(),
            super::super::identity::ordered_vote_high_key(&chain).unwrap(),
            super::super::identity::ordered_leader_record_key(&chain, view).unwrap(),
            super::super::identity::ordered_vote_record_key(&chain, view).unwrap(),
        ];
        for required in &required_keys {
            for historical in &historical_prefixes {
                assert_ne!(required, historical);
                assert!(!required.starts_with(historical.as_slice()));
                assert!(!historical.starts_with(required.as_slice()));
            }
        }
    }
}
