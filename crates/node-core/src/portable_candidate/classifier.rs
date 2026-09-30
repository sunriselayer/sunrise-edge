//! Closed transfer policy. Inclusion preserves bytes, not proof of legitimacy.
use super::*;
use crate::logical_generation::{
    FastpathRowClass, OrderedRowClass, classify_fastpath_row, classify_ordered_row,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortableStateKeyClass {
    Included,
    ExcludedLocal,
}

/// Existing explicit classifiers own fast-path and ordered family names.
/// Retained candidate bodies are history, not local cache. Unknown reserved
/// protocol families fail closed, while ordinary application keys transfer.
pub fn classify_state_key(
    key: &[u8],
    chain: &ChainId,
    protocol: ProtocolVersion,
) -> Result<PortableStateKeyClass, PortableCandidateError> {
    use PortableStateKeyClass::{ExcludedLocal, Included};
    if key.starts_with(PORTABLE_CANDIDATE_STATE_PREFIX) {
        return Ok(ExcludedLocal);
    }
    // Local anti-equivocation reservations are not transferable consensus
    // history; the exact signed candidate and committed proof are retained
    // separately. These families are not part of the logical-row classifier.
    if [
        b"se/instances/v1/ordered-economics/leader-proposal/".as_slice(),
        b"se/instances/v1/ordered-economics/vote-high/",
        b"se/instances/v1/ordered-economics/vote/",
        b"se/instances/v1/ordered-economics/reservation/",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix))
    {
        return Ok(ExcludedLocal);
    }
    if let Some(class) = classify_fastpath_row(key) {
        return Ok(match class {
            FastpathRowClass::LocalReservation | FastpathRowClass::LocalSigningSafety => {
                ExcludedLocal
            }
            FastpathRowClass::AuthenticatedHistory => Included,
        });
    }
    if let Some(class) = classify_ordered_row(key) {
        return Ok(match class {
            OrderedRowClass::LocalProgress => ExcludedLocal,
            OrderedRowClass::ConsensusControl
                if key.starts_with(b"se/instances/v1/ordered-economics/state/")
                    || key.starts_with(b"se/instances/v1/ordered-economics/applied-height/") =>
            {
                ExcludedLocal
            }
            _ => Included,
        });
    }
    if let Some(suffix) = key.strip_prefix(crate::logical_generation::LOGICAL_STATE_PREFIX) {
        if [
            b"profile/".as_slice(),
            b"state/",
            b"state-digest/",
            b"object/",
            b"nonce/",
        ]
        .iter()
        .any(|prefix| suffix.starts_with(prefix))
        {
            return Ok(Included);
        }
        return Err(PortableCandidateError::Invalid(
            "unknown logical provenance family",
        ));
    }
    const INSTANCE_HISTORY: &[&[u8]] = &[
        b"se/instances/v1/records/",
        b"se/publications/v1/records/",
        b"se/publications/v1/policies/",
        b"se/publications/v2/policies/",
        b"se/publications/v3/policies/",
        b"se/publications/v4/policies/",
        b"se/instances/v1/policies/",
        b"se/instances/v2/policies/",
        b"se/instances/v3/policies/",
        b"se/instances/v1/fee-policy/",
        b"se/instances/v1/genesis-manifest/",
        b"se/instances/v1/genesis-marker/",
        b"se/object-authority/v1/",
    ];
    if INSTANCE_HISTORY
        .iter()
        .any(|prefix| key.starts_with(prefix))
    {
        return Ok(Included);
    }
    let layout_prefix: Vec<u8> = format!("se/{chain}/v{}/", protocol.get()).into_bytes();
    if let Some(suffix) = key.strip_prefix(layout_prefix.as_slice()) {
        // Conservatively refuse even tombstoned legacy outbox entries.
        if suffix.starts_with(b"outbox/") {
            return Err(PortableCandidateError::Invalid(
                "legacy outbox requires separate closure",
            ));
        }
        const KNOWN: &[&[u8]] = &[
            b"epoch/",
            b"validators/",
            b"objects/",
            b"effects/",
            b"requests/",
            b"system-modules/",
            b"sender-nonces/",
            b"protocol/migrations/",
        ];
        if suffix == b"protocol/config"
            || suffix == b"protocol/upgrades"
            || KNOWN.iter().any(|prefix| suffix.starts_with(prefix))
        {
            return Ok(Included);
        }
        return Err(PortableCandidateError::Invalid(
            "unknown persistence-layout family",
        ));
    }
    if key.starts_with(b"se/") {
        return Err(PortableCandidateError::Invalid(
            "unknown reserved protocol state family",
        ));
    }
    Ok(Included)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_history_and_provenance_but_not_local_reservations() {
        let chain: ChainId = ChainId::new("candidate-test").unwrap();
        let version: ProtocolVersion = ProtocolVersion::new(1);
        for key in [
            b"se/instances/v1/ordered-economics/candidate/x".as_slice(),
            b"se/instances/v1/ordered-economics/freeze/x",
            b"se/instances/v1/ordered-economics/drain-set/x",
            b"se/instances/v1/fastpath/bond/x",
            b"se/instances/v1/fastpath/publication/x",
            b"se/instances/v1/logical/state/x",
            b"se/publications/v1/records/x",
            b"se/publications/v4/policies/x",
            b"application-state",
        ] {
            assert_eq!(
                classify_state_key(key, &chain, version).unwrap(),
                PortableStateKeyClass::Included
            );
        }
        for key in [
            PORTABLE_CANDIDATE_STATE_PREFIX,
            b"se/instances/v1/ordered-economics/state/x",
            b"se/instances/v1/ordered-economics/drain-completion/x",
            b"se/instances/v1/ordered-economics/leader-proposal/x",
            b"se/instances/v1/ordered-economics/vote-high/x",
            b"se/instances/v1/ordered-economics/vote/x",
            b"se/instances/v1/ordered-economics/reservation/x",
            b"se/instances/v1/fastpath/availability-ack/x",
            b"se/instances/v1/fastpath/lock/x",
        ] {
            assert_eq!(
                classify_state_key(key, &chain, version).unwrap(),
                PortableStateKeyClass::ExcludedLocal
            );
        }
        for key in [
            b"se/instances/v1/fastpath/future/x".as_slice(),
            b"se/instances/v1/logical/future/x",
            b"se/future/x",
            b"se/candidate-test/v1/outbox/x",
        ] {
            assert!(classify_state_key(key, &chain, version).is_err());
        }
    }
}
