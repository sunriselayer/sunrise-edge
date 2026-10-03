# DR-0188: bounded ordered-client empty alignment

Date: 2026-10-03

Status: Accepted implementation boundary; validation evidence belongs in TODO.

## Context

The closed ordered profile permits a candidate only at height `h % 3 == 1`.
A legitimate saved pre-Seal cut can leave the outgoing high QC at another
height. Repeated Tick changes views, not certified heights, so retrying that
candidate forever cannot reach an economic-bearing height.

## Decision

The ordinary network client may finish at most two genuine empty rounds before
placing any candidate. This is generic delivery, not a Seal exception or a
change to canonical consensus, scheduling, admission or signing authority.

Before the first proposal POST, reserve artifact handles for the maximum five
rounds: up to two alignment rounds, the candidate and its two empty descendants.
Persist each proposal and certificate before its POST; retain alignment rounds
in chronological replay manifests and results. Candidate bytes remain bound to
their exact request and authenticated candidate-carrying proposal. An empty
alignment acknowledgement cannot supply a committed candidate outcome.

Routing status remains an unsigned hint. Count only configured distinct
validators and independently verified high QCs. Never infer finality, applied
business state, readiness or a signing permission from reported height or view.
Every generated round is authenticated and its parent is the previous actual
round's certified digest, height and view. Different genuine quorum voter
subsets may certify that same parent; verify every complete certificate, but
do not require identical vote-vector bytes for parent continuity. An
inconsistent placement fails rather than relaxing the
closed profile. Deadline and alignment bounds apply even under stale hints.

An explicitly retained candidate proposal is re-verified and resumed exactly;
do not insert new alignment work ahead of that proposal. Original completed
requests retain receipt-first reconciliation and require signerless replay.

At the node boundary, original-result reconciliation is a separate read-only
phase, not fresh admission with signing disabled. It checks only the immutable
request binding and the retained outcome/header/receipt relationship. A missing
outcome grants no admission or signing authority and must reach the ordinary
namespace guard before installed-profile, candidate-carrier or business reads.
Actual admission consumes the same binding observations in its atomic commit;
it alone prepares carrier writes and, when authorized, reservations. This keeps
completed originals readable on inactive imports without letting partial import
metadata participate in fresh signing.

## Verification

Use real signed consensus proposal/vote/QC fixtures for both non-economic
starting heights, exact artifact/replay continuity and retained-proposal resume.
Reject invalid-QC or single-peer invented routing hints and artifact failures
before corresponding network mutation. The existing aligned three-round flow
and canonical vectors remain unchanged. First-epoch Seal acceptance must start
from the genuine unmodified post-Drain source and traverse the real HTTP/CLI
path; do not pre-advance its fixture to hide this client defect.
