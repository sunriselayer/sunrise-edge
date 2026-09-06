# Architecture decision DR-0108

Add the first partial-value operations to the local Standard Asset v1 devnet
as a separate additive activation. Protocol v4 and module version 1 remain the
historical whole-coin transfer behavior. Protocol v5 activates module version 2
with `split` and `merge`; it does not rewrite v4 canonical bytes or semantics.
This is a bounded developer-network slice, not a production or public-testnet
readiness claim.

- **Partial split.** `split` has two ordered, sender-owned `Write Coin<A>`
  inputs: source at index 0 and a distinct fee coin at index 1. Canonical
  `StandardAssetSplitArgsV1` contains a nonzero amount and recipient. The
  module checks that the amount is strictly below the source amount, writes
  the nonzero remainder to the source, and creates exactly one recipient-owned
  coin of the same nominal type and schema. The recipient signs no access and
  is not read or written as an existing object.
- **Two-coin merge.** `merge` has a primary sender-owned `Write Coin<A>` at
  index 0, a secondary sender-owned `Consume Coin<A>` at index 1, and a
  distinct sender-owned fee `Write Coin<A>` at index 2. The module checked-adds
  the two amounts into the primary and consumes the secondary. It creates no
  coin, and both inputs must carry the same `AssetId` through the shared typed
  ABI variable.
- **Generic but closed creation authorization.** The committed
  `PreinstalledObjectCreationPolicy` authorizes exactly one `Create`, only for
  `split`, and only at creation ordinal zero. It projects the recipient from
  the committed argument type/version/field, derives the created `ObjectId`
  from the signed transaction and ordinal, and copies the nominal type hash
  and schema from the already typed-ABI-verified source input. After exact
  replay, nonce, and module-policy reconciliation, node-core reads that id's
  head before signed-input object I/O and requires it to be exactly `Absent`;
  current or tombstoned state, duplicate effects, wrong owner/type/schema/
  version, extra creates, or caller-selected ids fail closed. The generic
  translation boundary also projects the created body's nominal type through
  the committed ABI constructor and requires it to match the copied type hash.
  Node-core does not decode balances or independently repeat the module's
  arithmetic conservation rule.
- **Atomicity and replay.** A successful split atomically commits the source
  mutation, one created object, fee payer/treasury mutations, nonce, receipt,
  and outbox. A merge atomically commits its primary mutation, secondary
  consume, fee mutations, nonce, receipt, and outbox. Exact replay reconciliation
  occurs before module/policy resolution and object I/O, so neither operation
  reapplies effects. Request-id reuse with different bytes leaves both object
  query results, receipts, and nonce unchanged.
- **Fail-closed boundary.** Wrong protocol/module version, module or
  entrypoint, access index or mode, object count, type/schema or asset
  unification, malformed or out-of-range arguments, shared/system/immutable or
  non-sender ownership, duplicate object ids, and generic contract `Create`
  are rejected. Mint, burn, arbitrary coin discovery/selection and dust
  consolidation, Unique Asset v1, multisig, Ledger, TypeScript/client/UI,
  and production fee aggregation remain deferred.

The active catalog commits the module code, manifest, semantics envelope, typed
entrypoint policies, creation policy, and protocol-v5 configuration together.
The local devnet remains a test fixture; this decision does not claim
production, mainnet, or public-testnet readiness.
