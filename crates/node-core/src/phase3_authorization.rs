//! FastVote Phase 3, DR-0137 implementation unit 2 authorization-class
//! declaration.
//!
//! Mirrors [`crate::phase2_authorization`]'s three orthogonal questions --
//! who may invoke the in-process operation, which cryptographic authority
//! must validate its protocol action, and whether native external ingress
//! exists -- for the closed bond-lifecycle operations
//! ([`crate::bond_lifecycle`]). Every operation remains local-operator
//! invoked and externally closed: this module adds no HTTP route, CLI
//! command or [`crate::NodeEventKind`].

/// Every closed DR-0137 bond-lifecycle operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondLifecycleOperation {
    /// `Exited -> Active`.
    Deposit,
    /// `Active -> Active`, atomic two-leg swap.
    Replace,
    /// `Active -> Unbonding`.
    Unbond,
    /// `Unbonding -> Exited`.
    Withdraw,
}

/// In-process caller authority for a bond-lifecycle operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationAuthority {
    /// The embedding node's trusted local operator invokes the Rust entrypoint.
    LocalOperator,
}

/// Exact cryptographic authority enforced by a bond-lifecycle operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptographicAuthority {
    /// The committed validator's own bond-row authorization signature, plus
    /// the exact source-owner's `ExecuteLocalContract` signature over the
    /// one embedded deposit leg.
    ValidatorAndSourceOwner,
    /// The committed validator's own bond-row authorization signature, plus
    /// the exact same-sender owner signatures over both embedded legs.
    ValidatorAndTwoLegOwner,
    /// The committed validator's own bond-row authorization signature alone;
    /// no contract execution and no owner signature.
    ValidatorOnly,
    /// The committed validator's own bond-row authorization signature, plus
    /// an exact `ExecuteLocalContract` signature from whichever account
    /// submits/invokes the one embedded release leg. That submitter signs
    /// only to spend its own nonce and relay the call; it proves no
    /// ownership or source authority over the released custody object (the
    /// custody object is never sender-owned) and the recipient was already
    /// fixed by the committed validator at the prior `Unbond`.
    ValidatorAndReleaseSubmitter,
}

/// External ingress availability for a bond-lifecycle operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalIngress {
    /// No HTTP, CLI or [`crate::NodeEventKind`] ingress is implemented.
    Closed,
}

/// Orthogonal authorization policy for one bond-lifecycle operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Phase3AuthorizationPolicy {
    /// Trusted in-process invocation authority.
    pub invocation: InvocationAuthority,
    /// Protocol-level cryptographic authority.
    pub cryptographic: CryptographicAuthority,
    /// External transport exposure.
    pub external_ingress: ExternalIngress,
}

/// Returns the closed, exhaustive authorization policy for one operation.
#[must_use]
pub const fn policy(operation: BondLifecycleOperation) -> Phase3AuthorizationPolicy {
    let cryptographic: CryptographicAuthority = match operation {
        BondLifecycleOperation::Deposit => CryptographicAuthority::ValidatorAndSourceOwner,
        BondLifecycleOperation::Replace => CryptographicAuthority::ValidatorAndTwoLegOwner,
        BondLifecycleOperation::Unbond => CryptographicAuthority::ValidatorOnly,
        BondLifecycleOperation::Withdraw => CryptographicAuthority::ValidatorAndReleaseSubmitter,
    };
    Phase3AuthorizationPolicy {
        invocation: InvocationAuthority::LocalOperator,
        cryptographic,
        external_ingress: ExternalIngress::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_phase3_authorization_matrix_is_closed_and_exhaustive() {
        let cases: [(BondLifecycleOperation, CryptographicAuthority); 4] = [
            (
                BondLifecycleOperation::Deposit,
                CryptographicAuthority::ValidatorAndSourceOwner,
            ),
            (
                BondLifecycleOperation::Replace,
                CryptographicAuthority::ValidatorAndTwoLegOwner,
            ),
            (
                BondLifecycleOperation::Unbond,
                CryptographicAuthority::ValidatorOnly,
            ),
            (
                BondLifecycleOperation::Withdraw,
                CryptographicAuthority::ValidatorAndReleaseSubmitter,
            ),
        ];
        for (operation, expected_cryptographic) in cases {
            let actual: Phase3AuthorizationPolicy = policy(operation);
            assert_eq!(actual.invocation, InvocationAuthority::LocalOperator);
            assert_eq!(actual.cryptographic, expected_cryptographic);
            assert_eq!(actual.external_ingress, ExternalIngress::Closed);
        }
    }
}
