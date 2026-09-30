# DR-0163: committed DrainSet closes candidate voting before the cut

Date: 2026-09-30

## Status

Accepted handoff safety direction. Current implementation and validation
evidence belong in [`TODO.md`](../../../TODO.md). This decision does not
approve a portable cut, Seal, activation or a network launch.

## Problem

The local barrier in [DR-0162](0162-business-free-cut-barrier.md) is not a
network decision. With four validators, one replica can install it while the
other three have not. If those three can still sign a second `Freeze` or
`DrainSet`, they can certify a later control candidate. The barriered replica
then refuses to apply that committed candidate, cannot advance its prefix and
cannot reach Seal. This can happen with an honest quorum; a local CAS fence
alone is not a network-level business-free guarantee.

## Decision

1. An **accepted and committed** `DrainSet` is the ordered close-all-candidate
   decision for its outgoing epoch. Its durable `DrainSetRecord`, not a local
   union-ready marker or a merely proposed or refused `DrainSet`, closes fresh
   leader proposals and votes for every candidate kind, including `Freeze`
   and another `DrainSet`. Empty consensus proposals and signerless certified
   catch-up remain legal. The later Seal requires an explicit, narrow,
   independently reviewed exception; it is not authorized by this decision.
2. A signer reads the exact chain/epoch record and asserts its observed
   revision in the same durable proposal or vote-identity commit. A concurrent
   accepted `DrainSet` makes that commit lose by CAS before any signature is
   exposed. A present malformed or tombstoned record stops rather than being
   treated as absence. A previously completed candidate still reconciles to
   its exact retained outcome, and conflicting request-id reuse remains a
   conflict; neither path is a fresh vote.
3. A proposal can first commit `DrainSet` through its justification. Before
   exposing a vote for any candidate-bearing payload, the signer previews the
   authenticated, bounded signerless transition. If that transition commits
   `Freeze` or `DrainSet`, it persists the observation without a vote. A
   refused `DrainSet` writes no close-all record. Previously signed candidate
   chains still undergo normal signerless processing and deterministic
   outcomes; the new gate does not erase them.
4. A local business-free barrier still waits for completed drain, an applied
   committed prefix and candidate-free authenticated high/locked suffixes.
   Closing new votes is not proof that an unknown older certificate or branch
   has already been resolved. Before a portable cut, retain an independently
   verifiable committed proposal/QC history and establish a post-DrainSet
   empty control anchor. The importer verifies these from outgoing-set
   signatures, not from a source replica's local marker or Boolean claim.

## Safety argument and remaining proof

The closed ordered profile admits candidates only at heights congruent to 1
modulo 3. A `DrainSet` at height `d` can commit when the certificate for its
height `d+2` descendant is processed; the next candidate slot is `d+3`.
Processing that justification must apply or already know the committed
`DrainSet` before an honest vote at `d+3`. This relies on the shared-engine
three-chain rules, mandatory known-ancestor vote readiness, complete candidate
bytes, the one-candidate-per-event bound and the same-event preview. HotStuff
locking must also prevent a conflicting branch from committing around the
accepted `DrainSet`. These are coupled protocol obligations, not a property of
the local record lookup alone.

The four-validator asymmetric-barrier test checks the direct control-candidate
counterexample. Additional adversarial schedules and durable proposal/QC
proofs are still required before this becomes portable cut authority. The
local barrier must not be operator-exposed as a complete handoff mechanism
before that work and Seal/activation are implemented.
