//! Restricted owning-module assertions for the actual private dispatch.
//! Callers supply a genuine engine-produced proof and the actual source store.
//! This exposes no constructor or verified-proof capability outside tests.
use super::*;

pub(in crate::ordered_economics) fn assert_execute_seal_stops(
    repository: &dyn OutgoingSealRepository,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    proof: &consensus::CommittedBlockProof,
    expected: &'static str,
) {
    env.policy.authenticate_candidate(candidate).unwrap();
    let block: CommittedBlock =
        super::super::ordered_history::verified_committed_block(env.policy, proof).unwrap();
    let candidate_digest: Digest32 = env.policy.candidate_digest(candidate).unwrap();
    assert_eq!(block.transactions.as_slice(), &[candidate_digest]);
    let outcome: LegOutcome = execute_seal_candidate(
        context,
        env,
        candidate,
        block.height,
        block.digest,
        Some(repository),
    );
    match outcome {
        LegOutcome::Stop(OrderedEconomicsError::Prerequisite(actual)) => {
            assert_eq!(actual, expected)
        }
        LegOutcome::Stop(other) => panic!("unexpected dispatch Stop: {other:?}"),
        _ => panic!("the challenged Seal dispatch must Stop without an accepted or refusal output"),
    }
}
