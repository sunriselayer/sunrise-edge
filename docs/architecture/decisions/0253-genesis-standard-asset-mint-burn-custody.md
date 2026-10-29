# DR-0253: Genesis Standard Asset mint/burn custody

Date: 2026-10-16

Status: Accepted design. Qualification is tracked in TODO.md.

## Decision

Extend the trusted-local-OS custody boundary (DR-0238, DR-0246, DR-0249) to
the genesis Standard Asset `TreasuryCap`-owner operations `mint` and `burn`.
These are the next bounded family: unlike `transfer`/`split`/`merge`, their
authority precondition is `TreasuryCap` ownership, not `Coin` ownership, and
they change total supply rather than only moving value between coins.

The genesis/code/instance/fee-policy pin is not reverified or
re-implemented: this family wraps the same private `PinnedAssetTrust`
(DR-0246/DR-0249) as every other Standard Asset custody family. The only
addition to shared trust is `PinnedAssetTrust::cap_tag` (the genesis
`TreasuryCap` nominal type, derived from the same verified origin/asset as
`coin_tag`) and `validate_owned_cap`, the `TreasuryCap` analogue of
`validate_owned_coin`. A new private `asset_mint_burn` module wraps
`PinnedAssetTrust` and adds only `mint`/`burn`'s own entrypoint, argument
shape, and supply-arithmetic checks.

The published WASM remains the sole execution oracle: custody adds no new
protocol math and never changes what the contract itself enforces on-chain.
What custody adds is an *independent* pre-approval review of the exact same
checked arithmetic the contract performs — computed from the caller-supplied
canonical preimages under custody's own pinned trust, never from the
caller's claimed amount or claimed outcome:

- `mint` decodes the `TreasuryCap`'s current supply from its own verified
  preimage, rejects a zero amount, and rejects a checked-addition overflow,
  before any approval or signing step.
- `burn` decodes the `TreasuryCap`'s current supply and the whole `Coin`'s
  exact amount from their own verified preimages, rejects a zero-amount
  coin, and rejects a checked-subtraction underflow, before any approval or
  signing step.

Both independently rebuilt outcomes (the exact before/after supply) are
displayed in the bounded review a human must approve, never only the
caller's claimed amount.

`mint` takes one owned `TreasuryCap` Write, a positive amount, and a
recipient; it creates a fresh `Coin` for the reviewed amount and recipient,
exactly as the published contract does. `burn` takes one owned `TreasuryCap`
Write and a distinct owned whole `Coin` Consume — never a partial amount —
and the exact consumed `Coin` amount reduces supply. Both require a fee
source that is owned and distinct from every application input, with a
positive maximum fee strictly below the fee source's balance and the refund
returned to the sender, matching every other family.

A new adapter-local message kind 4 carries both operations (a closed
`mint`/`burn` operation tag selects the trailing fixed-field shape), under
the same `CUSTODY_WIRE_VERSION`. Kind 1 (publication), kind 2 (transfer) and
kind 3 (split/merge) keep their existing decoders and `serve`/
`serve-transfer`/`serve-split-merge` policies unchanged; a kind-4 frame is
refused by all three, and kind 1/2/3 frames are refused by the new
`serve-mint-burn`. `custody prepare-mint`/`approve-mint`/`sign-mint` and the
`-burn` equivalents mirror the existing offline split/merge commands, with
their own distinct `APPROVE-MINT`/`APPROVE-BURN` typed confirmation lines
(never split/merge's confirmation strings).

The ordinary paid `standard_asset mint`/`burn` CLI accepts the same three
custody signer flags `transfer`/`split`/`merge` already do; custody's own
fee/asset/refund pin checks apply identically. Every application input's
canonical preimage (the `TreasuryCap`, then the `Coin` for `burn`) is
captured in `operation.inputs` order and carried to custody, which never
trusts that order or any caller-claimed amount or supply outcome: it
decodes, validates ownership/schema/nominal type and recomputes every
reference, amount and the exact before/after supply itself before rendering
the review it requires a human to approve. `create-asset` stays unsupported
and fails before any I/O, exactly as before.

No genesis change is required to exercise this family: the existing
one-owner Docker fixture's single development owner is both the sole
genesis owner and `mint_authority` (DR-0196/`apps/devnet`), so it already
owns the installed `TreasuryCap<A>` — not necessarily the same key as the
separate genesis authority, which owns no `Coin` or `TreasuryCap`.

## Compatibility and lifecycle

No protocol encodings, cryptographic domains, execution effects, fee quote
ordering or historical vectors change. The kind-4 message is outside the
protocol namespace, by the same reasoning as kind 1/2/3. Approval and
expiry reuse the existing whole-frame store exactly; revocation is tested
directly for this family (tamper, expire, revoke, and refuse-to-restore-a-
revoked-record cases in `asset_mint_burn_tests.rs`). Key recovery and
rotation are architecturally shared code paths with every other family and
are not expected to differ, but — unlike revocation — neither is exercised
by a mint/burn-specific test; this decision record does not itself
constitute acceptance evidence for recovery/rotation under this family.

## Limits

Same trusted OS/root, separate-UID model and limits as DR-0238/DR-0246/
DR-0249. `create-asset`, other packages/instances/epochs and automatic
protocol signing stay outside this profile. No real keys, host users, public
services, network activation, asset owner/key migration, or security audit
are claimed. No new cryptographic primitive, canonical encoding, or protocol
arithmetic is introduced; custody's independent supply checks are a
pre-approval review of the same contract-enforced arithmetic, not a second
source of protocol authority.
