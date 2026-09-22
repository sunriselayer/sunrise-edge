//! FastVote Phase 2 authorization-class declaration.
//!
//! The declaration deliberately keeps three independent questions separate:
//! who may invoke an in-process operation, which cryptographic authority must
//! validate its protocol action, and whether native external ingress exists.
//! All seven current operations remain local-operator-invoked and externally
//! closed. Their existing entrypoints continue to enforce the cryptographic
//! authority named here; this module does not introduce a forgeable marker
//! token or a new transport capability.

/// Every state-changing or signing FastVote Phase 2 operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FastVotePhase2Operation {
    /// Stage one exact sender-authenticated paid intent and cast a FastVote.
    Prepare,
    /// Verify and atomically apply one FastCertificate.
    ApplyCertificate,
    /// Derive a successor set and cast one outgoing-set transition vote.
    ProposeEpochTransition,
    /// Verify and atomically activate one outgoing-set transition certificate.
    ActivateEpochTransition,
    /// Record same-transaction, conflicting-outcome FastVote evidence.
    RecordFastVoteEquivocation,
    /// Record cross-transaction, same-object-version FastVote evidence.
    RecordFastVoteObjectConflict,
    /// Record conflicting-target epoch-transition evidence.
    RecordEpochTransitionEquivocation,
}

/// In-process caller authority for a Phase 2 operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationAuthority {
    /// The embedding node's trusted local operator invokes the Rust entrypoint.
    LocalOperator,
}

/// Exact cryptographic authority enforced by a Phase 2 operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptographicAuthority {
    /// The exact sender-signed intent and one committed active-set signer.
    SenderAndActiveValidator,
    /// The exact sender-signed intent and an active-set quorum certificate.
    SenderAndActiveValidatorQuorum,
    /// One signer in the committed outgoing validator set.
    OutgoingValidator,
    /// A quorum certificate from the committed outgoing validator set.
    OutgoingValidatorQuorum,
    /// Two conflicting FastVotes verified against their historical active set.
    FastVoteEquivocationEvidence,
    /// Conflicting object-version FastVotes verified against their historical active set.
    FastVoteObjectConflictEvidence,
    /// Conflicting transition votes verified against their historical outgoing set.
    EpochTransitionEquivocationEvidence,
}

/// External ingress availability for a Phase 2 operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalIngress {
    /// No HTTP, CLI or `NodeEventKind` ingress is implemented.
    Closed,
}

/// Orthogonal authorization policy for one Phase 2 operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Phase2AuthorizationPolicy {
    /// Trusted in-process invocation authority.
    pub invocation: InvocationAuthority,
    /// Protocol-level cryptographic authority.
    pub cryptographic: CryptographicAuthority,
    /// External transport exposure.
    pub external_ingress: ExternalIngress,
}

/// Returns the closed, exhaustive authorization policy for one operation.
#[must_use]
pub const fn policy(operation: FastVotePhase2Operation) -> Phase2AuthorizationPolicy {
    let cryptographic: CryptographicAuthority = match operation {
        FastVotePhase2Operation::Prepare => CryptographicAuthority::SenderAndActiveValidator,
        FastVotePhase2Operation::ApplyCertificate => {
            CryptographicAuthority::SenderAndActiveValidatorQuorum
        }
        FastVotePhase2Operation::ProposeEpochTransition => {
            CryptographicAuthority::OutgoingValidator
        }
        FastVotePhase2Operation::ActivateEpochTransition => {
            CryptographicAuthority::OutgoingValidatorQuorum
        }
        FastVotePhase2Operation::RecordFastVoteEquivocation => {
            CryptographicAuthority::FastVoteEquivocationEvidence
        }
        FastVotePhase2Operation::RecordFastVoteObjectConflict => {
            CryptographicAuthority::FastVoteObjectConflictEvidence
        }
        FastVotePhase2Operation::RecordEpochTransitionEquivocation => {
            CryptographicAuthority::EpochTransitionEquivocationEvidence
        }
    };
    Phase2AuthorizationPolicy {
        invocation: InvocationAuthority::LocalOperator,
        cryptographic,
        external_ingress: ExternalIngress::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_phase2_authorization_matrix_is_closed_and_exhaustive() {
        let cases: [(FastVotePhase2Operation, CryptographicAuthority); 7] = [
            (
                FastVotePhase2Operation::Prepare,
                CryptographicAuthority::SenderAndActiveValidator,
            ),
            (
                FastVotePhase2Operation::ApplyCertificate,
                CryptographicAuthority::SenderAndActiveValidatorQuorum,
            ),
            (
                FastVotePhase2Operation::ProposeEpochTransition,
                CryptographicAuthority::OutgoingValidator,
            ),
            (
                FastVotePhase2Operation::ActivateEpochTransition,
                CryptographicAuthority::OutgoingValidatorQuorum,
            ),
            (
                FastVotePhase2Operation::RecordFastVoteEquivocation,
                CryptographicAuthority::FastVoteEquivocationEvidence,
            ),
            (
                FastVotePhase2Operation::RecordFastVoteObjectConflict,
                CryptographicAuthority::FastVoteObjectConflictEvidence,
            ),
            (
                FastVotePhase2Operation::RecordEpochTransitionEquivocation,
                CryptographicAuthority::EpochTransitionEquivocationEvidence,
            ),
        ];

        for (operation, expected_cryptographic) in cases {
            let actual: Phase2AuthorizationPolicy = policy(operation);
            assert_eq!(actual.invocation, InvocationAuthority::LocalOperator);
            assert_eq!(actual.cryptographic, expected_cryptographic);
            assert_eq!(actual.external_ingress, ExternalIngress::Closed);
        }
    }
}
