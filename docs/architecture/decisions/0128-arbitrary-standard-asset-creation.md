# DR-0128: arbitrary Standard Asset creation

Accepted design, 2026-09-21 (Asia/Singapore).

## Decision

Create a new Standard Asset by instantiating the already published public
Standard Asset code through the ordinary signed paid `Instantiate` path. A
creation transaction selects a fresh creator-scoped instance seed. The package
initializer creates exactly one creator-address-owned `Definition` and one
creator-address-owned `TreasuryCap<A>` at zero supply, where `A` is the
host-derived ObjectId of that `Definition`.

The fee policy continues to pin the separate genesis Standard Asset instance
used to reserve and settle fees. It grants no creation or application
authority. The new instance uses the same authenticated code revision but has
its own exact instance target and object-authority scope. Node core receives no
Standard Asset entrypoint, constructor, body, asset-ID, or supply special case.

This repository is unreleased. The CLI may change directly to require an exact
application asset selection for non-genesis assets; no legacy module, native
creation transaction, compatibility selector, or alternate asset identifier is
retained.

## CLI contract

`create-asset` is a human-facing builder for one ordinary paid
`PaidApplication::Instantiate`. It:

1. rejects Ledger selection before device, file, or network access;
2. validates TLS configuration separately from the locally configured expected
   protocol context;
3. fetches and validates the installed paid fee policy;
4. selects that policy's exact authenticated public Standard Asset code, but a
   caller-supplied fresh instance seed;
5. signs the instance target, empty initializer arguments, fee consent, request
   ID, nonce, and gas limit;
6. submits through the existing paid endpoint and independently verifies the
   result;
7. validates the successful application effects as exactly one `Definition`
   and one `TreasuryCap<A>` owned by the creator, excluding ordinary fee and
   refund outputs; and
8. reserves caller-selected recovery paths before submission, then preserves
   the signed submission and independently verified result plus canonical
   instance reference before printing the asset, definition, treasury-cap, and
   instance identities.

The existing `transfer`, `split`, `merge`, `mint`, and `burn` commands accept an
application selection consisting of both `--asset` and `--instance-ref`. The
pair is all-or-none. When present, the CLI decodes the canonical instance pin,
requires its context and code to equal the expected active context and the
policy-pinned Standard Asset code, verifies the remote instance record exactly,
and signs calls against that instance with `A = --asset`. When absent, the five
commands retain the explicit local-devnet default of the policy-pinned genesis
asset. This default is CLI product behavior only; admission always validates an
exact signed instance target and typed object authority.

Display metadata such as name, symbol, decimals, URI, or mutable presentation
fields is not asset identity and is not added to the initializer in this slice.
It belongs in separately specified ordinary objects with explicit update
authority. A zero-supply asset plus its non-transferable TreasuryCap is the
complete initial capability lifecycle for this gate; mint creates the first
Coin and burn reduces the same instance-scoped supply.

## Verification gate

One real file-backed SQLite, native-HTTP, and CLI test must create a second
asset, mint and transfer its Coin through the specialized commands, and prove:

- the fee instance and application instance are distinct while using the same
  authenticated Standard Asset code;
- the created Definition ObjectId is the only asset identity and matches the
  TreasuryCap and Coin nominal type argument;
- genesis fee-asset objects cannot be substituted as the new asset's cap or
  Coin before signing;
- exact replay before and after close/reopen returns the original creation
  result without recreating Definition, TreasuryCap, fees, or nonce effects;
- reusing the request ID with different signed creation bytes leaves both asset
  instances, receipts, fee objects, and sender nonce unchanged; and
- a stale writer generation cannot commit after restart.

Targeted unit tests pin all-or-none application selection, canonical instance
decoding, context/code/remote-record equality, effect classification, and
Ledger rejection before I/O. The complete repository gate and a focused fresh
security/tech-lead review of the delta are required before merge.

## Consequences

- Standard Asset creation demonstrates generic paid instantiation rather than
  introducing another protocol-embedded transaction family.
- Asset identity, instance authority, fee asset, and individual Coin ObjectIds
  remain separate concepts.
- An asset creator can immediately mint, transfer, split, merge, burn, and pay
  fees without the application asset becoming an admitted fee asset.
- Mutable metadata, TreasuryCap delegation or destruction, partial burn,
  freezing, allowances, Unique Asset, and governed fee-asset admission remain
  separate later features.
