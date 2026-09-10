# Public Standard Asset and settlement replacement

Date: 2026-09-07 (Asia/Singapore).

This is a design proposal and implementation map, not an activation decision or
completion claim. The current roadmap remains in `TODO.md`. It follows the
unified contract-call model in DR-0123 and the normative `docs/design.md`.

## Observed implementation

- `apps/devnet/modules/standard_asset_v1.wat` uses the legacy `env` host and
  lacks the public profile's declared memory maximum. Its transfer export
  validates input shape, while node-core synthesizes the owner transition.
- `apps/devnet/src/catalog.rs` supplies trusted owner-transition and creation
  policies. Public defining-code authority must replace those grants.
- `apps/devnet/src/fee.rs::StandardAssetCoinFeeComposer` decodes and rewrites
  payer/treasury Coin amounts in native Rust. `node-core` orchestrates its
  privileged access to the treasury, which is hidden from application WASM.
- The public host admits sender-owned original inputs. Its signed call table
  cannot authorize mutation of a treasury Coin owned by another address.
- Existing public failure results forbid application effects. Fee-bearing
  failures therefore need an explicit result contract; they must not silently
  reinterpret the zero-fee result format.

## Proposed replacement

Publish and instantiate Standard Asset through the same authenticated records,
typed ABI, scoped handles and fenced persistence as user contracts. Transfer,
split, merge, mint and burn execute their actual object operations in WASM.
Supply arithmetic stays in the contract. Initialization establishes supply and
capabilities atomically; no native object seeding followed by attached sidecars.

Fee policy pins the exact settlement target/revision, entrypoint, accepted asset,
recipient and resource bound. Signed fee consent binds that policy and a maximum
amount. Neither a caller-selected target nor an unsigned policy change can
redirect payment. Settlement invokes ordinary defining-code operations; there
is no Standard Asset-specific owner exception or native Coin-body callback.

Prefer creating an ordinary Coin owned by the configured fee recipient over
mutating one shared treasury Coin. Only the payer's existing Coin is spent.
The recipient can later merge its own Coins using the same public contract.
This avoids both foreign-owner write authority and a shared treasury write in
every payment. It is not a claim that all other fast-path prerequisites are met.

## Revised funding proposal after Sui research

The initial mandatory separate-Coin proposal is withdrawn. Sui demonstrates
that one Coin can fund both execution and application work by withdrawing the
maximum budget before application execution. Its GasCoin has special consumption
rules and its runtime performs SUI-specific charging; this is evidence for
reservation, not evidence that its implementation meets our generic-host goal.
Sources inspected at Sui commit `0804d277859dfe2a2ab3fdbf23b75870d8f0ce6f`:

- [PTB execution and GasCoin rules](https://docs.sui.io/develop/transactions/ptbs/prog-txn-blocks).
- [Gas smashing and failure effects](https://docs.sui.io/develop/transaction-payment/gas-smashing).
- [Budget reservation/refund implementation](https://github.com/MystenLabs/sui/blob/0804d277859dfe2a2ab3fdbf23b75870d8f0ce6f/sui-execution/latest/sui-adapter/src/static_programmable_transactions/execution/context.rs#L413).
- [Native gas charging](https://github.com/MystenLabs/sui/blob/0804d277859dfe2a2ab3fdbf23b75870d8f0ce6f/sui-execution/latest/sui-adapter/src/gas_charger.rs#L452).

The replacement should separate reserved funds from spendable funds inside one
invocation, not require users to prepare separate Coins. The concrete proposal
is recorded in DR-0124. Opus approved the revised design after requiring
independent phase resource budgets, typed returns and explicit phase-failure
receipts. This is design approval, not implementation approval or activation.

## Atomic lifecycle to implement after that choice

1. Authenticate and reconcile exact replay before policy/code/object reads.
2. Verify signed consent, exact locally committed policy and all immutable
   code/instance pins, ownership, references and deterministic resource bounds.
3. Reserve bounded settlement resources before application execution. Define
   worst-case admission and actual-gas pricing without recursive fee charging.
4. Run application and settlement inside one invocation. A normalized
   application trap discards application state/events but may retain authorized
   settlement effects and a rejected receipt. An admitted reserve/settlement
   failure restores pre-reservation object state and commits a zero-charge
   rejected receipt plus consumed nonce; it must not permit exact free replay.
   Fresh-request resource abuse remains a separate public-admission gate.
5. Commit all read assertions, final objects/authority, nonce and complete
   receipt once. Replay never executes or charges either phase again.

Fee-only effects must be explicit in versioned canonical results. Creation
ordinals, gas bounds and object versions must remain unambiguous across both
phases. Exact-full-balance payment must have an explicit consume rule rather
than constructing an invalid zero-amount Coin.

## Delivery and removal boundary

Keep one coherent implementation PR covering the five existing asset operations,
the signed settlement flow, CLI/devnet activation and real SQLite restart E2E.
Do not ship a helper-only completion or keep parallel privileged/public asset
implementations merely for unreleased history. Remove discarded fixture/catalog
activation branches when the replacement is usable. Existing development
directories need an explicit fresh-state boundary, not an implicit migration.

Acceptance includes wrong asset/capability/instance/defining-code rejection,
checked supply arithmetic, fee caps, application and settlement traps, unchanged
pre-admission/conflict state, same-boot/restart replay, generation fencing, an
independently published caller, the full repository gate and fresh Opus review.
Publication/initialization fee policy and bootstrap admission must also be
specified; ordinary users must not inherit a privileged genesis exemption.
