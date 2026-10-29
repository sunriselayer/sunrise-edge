# DR-0281: Live application Coins with the recovered same-identity key

Date: 2026-10-29 (Asia/Singapore)

Status: Accepted source contract. Actual qualification belongs in TODO.md.

## Context

The own-created application mint/burn fixture already creates a distinct
`own-recovered.seed.restored` after its original live operations and
historical same-frame signing reference. Its recovered signer and revoked
restart then stop before the following six-stage application Coin sequence.
That sequence previously selected the original disposable seed for every
live signer group and revoked restart.

## Decision

Select the existing recovered application key for all six live stages:
mint-one, split, merge, burn, mint-two and transfer. Require all prior tracked
custody signers to have completed communicate/reap and removed their sockets.
Check the recovered path is a custody-owned regular mode-0600 file, with a
path and device/inode distinct from the original seed. Record the actual
selected child-argv path for each of the five live signer groups and its
revoked restart, and validate every selection in Python and Node.

Retain the original 47 application setup predicates, operation and request
order, public application/genesis pins, approvals, frames, signature byte
comparisons, business submissions, independent stage/result/receipt/replay
oracles, nonces, owners, supply and exact group counters. Preserve the initial
own-created mint/burn and all historical signing-only recovery controls.
Add no operation, key copy, identity, authority, profile, child or ownership
policy, and retain every existing allocation, resource, capture, PTY and time
limit. This is a consumer selection within the existing trust contracts.

## Limits

The initial own-created mint/burn executes before this recovered path exists;
its live key selection is unchanged. Historical recovery requests remain
signing-only. This slice establishes no new key rotation, creator/TreasuryCap
migration, automatic signing, real-key ceremony, complete M2 acceptance or
public readiness. Source checks do not establish actual fixture execution or
capture headroom.
