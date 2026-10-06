# DR-0196: Offline operator-layer Standard Asset genesis authoring

Date: 2026-10-06 (Asia/Singapore)

Status: Accepted design. Claude Opus returned DESIGN APPROVE on 2026-10-06
after checking the defining phase limits and ephemeral validation environment. This record does not approve custody, a key ceremony, audit or
real-network activation. Current implementation and release status belong only
in TODO.md.

## Context

DR-0195 deliberately consumes an already signed original genesis. The existing
devnet builder uses a checked-in public seed, local identities and fixed
allocation/economics values. It is a development fixture, not a real-network
authoring tool. Existing runtime publication/instantiation commands need a live
endpoint; genesis authoring cannot depend on an already running genesis.

The defining installer requires the publication publisher, initializer sender
and instance creator to equal the manifest's single genesis authority. Its
generic code/object/resource validation must not become a Standard Asset-only
node-core path.

## Decision

### One named operator preset, existing protocol

Add `apps/operator/src/standard_asset_genesis.rs` and a thin executable with
closed `author` dispatch. This is explicitly a Standard Asset preset built with
the public template's ordinary package, layouts and entrypoints. It is not an
arbitrary-package compiler or a native balance implementation.

The operator takes a normal dependency on `public-standard-asset`. Protocol
crates receive no template dependency, privileged branch, schema change, new
message type or protocol/module version. Do not import or modify the devnet
builder, identities, seed, derivation labels or default economic values.
Historical fixtures remain separate from real operator inputs.

In scope is a narrow public read-only re-export from
`execution::paid_execution` of its defining `PHASE_CALLS`, `PHASE_HANDLES`,
`PHASE_CREATIONS`, `PHASE_EVENTS`, `PHASE_MEMORY_BYTES` and
`PHASE_OUTPUT_BYTES`. Their values and wire/coordinator consumers are unchanged;
the private VM module does not become public. The preset consumes this single
source, not copied devnet literals or caller-configurable phase caps.

### Closed inputs

- Explicit chain, protocol, original epoch and complete hash schedule, using
  existing local parsers. The profile is the existing CausalAdmission profile
  with an explicit positive minimum Freeze block height.
- Explicit expected genesis-authority public key and protected
  `--genesis-key-file`. Use the existing bounded signing-key loader. Derive and
  compare the key before signing anything; never accept a seed in argv, stdin
  logs or a default configuration.
- Explicit package origin seed, instance seed, publication and initialization
  request IDs, definition ObjectId and TreasuryCap ObjectId. Do not invent a
  new derivation domain. Use the existing genesis nonce-zero convention for
  each separately signed publication and initializer, not a runtime nonce
  query or a sequence of live transactions.
- A bounded closed validator table: validator ID, registered Ed25519 public
  key, positive voting power, positive bond amount and collateral ObjectId.
  Require unique validator IDs and registered keys (a preset-local constraint,
  not a new core-wide rule), and exactly one initial
  collateral object for every committee member. Apply the existing committee,
  bond minimum and exposure bounds.
- A bounded closed allocation table: Address owner, positive amount and Coin
  ObjectId. One owner may legitimately have multiple different Coin objects;
  do not collapse those allocations into an account balance or reject repeated
  owners. Every ObjectId across both tables and the definition/cap is unique.
- Explicit mint authority and fee recipient, plus the configurable gas prices,
  conversion divisor, reserve/settle allowances, Publish prices and bond
  minimum/unbonding/exposure settings. Existing fixed phase caps, Standard Asset
  ABI/schema and hook names remain their defining constants, not configurable
  protocol semantics. No copied devnet economic defaults.
- An independently supplied local validation domain, checkpoint and bounded
  timeout. The domain is used only for ephemeral installer validation; it is
  neither authenticated by the manifest nor derived from storage/provider data.
- Exactly one fresh manifest output path. Reject unknown/duplicate fields,
  excess records, malformed canonical values, unsupported context/profile,
  path aliases with the key, both tables and configuration inputs, and existing
  outputs. This action starts no listener and calls
  no provider, deployment API or live store.

All input files are bounded before decoding. Check `2 + allocations + validators
<= MAX_GENESIS_OBJECTS` and all sums with checked arithmetic. Treasury supply
equals the exact sum of normal allocations and collateral Coins, validated
with the public template's body codecs. The preset obeys existing role/address
rules; it adds no blanket rule that the same principal cannot hold several
explicitly selected roles.

### Signing, verification and persistence

1. Parse public inputs and output constraints before loading the key. Build
   the ordinary package/code artifact and authenticate the independently
   expected authority against the protected key.
2. Compute and sign the exact existing publication frame; construct its code
   reference and instance, then compute and sign the exact Instantiate frame.
3. Assemble the ordinary definition, TreasuryCap, allocation and BondCollateral
   objects and their complete authorities, plus the fee/economics policies and
   committed committee. Sign the existing manifest frame **last**, because it
   embeds the exact nested signed frames.
4. Encode the canonical manifest, compute its commitment and verify through
   `VerifiedGenesisRoot::verify_bytes`. This is self-consistency, not independent
   human approval, complete installability or proof that validators hold keys.
5. Run the existing defining `install_genesis` and `install_ordered_genesis`
   owners in a fresh private `MemoryDurableStateStore::new_bound` at fence 1,
   with the explicit local validation domain and existing generic execution
   policy/engine. Use the trusted local SystemClock only for the discarded
   in-memory pacemaker, and derive the operation deadline from that clock plus
   the bounded timeout with checked arithmetic. The environment uses an empty
   `MemoryBlobStore`, `LocalWasmExecutionEngine`, generic leg policy and
   `seal: None`. Share the original installation composition with DR-0195
   wherever genuinely identical, rather than a parallel installer recipe.
   No clock value or validation checkpoint enters the manifest bytes or successful
   stdout; the checkpoint belongs only to the discarded in-memory installation.
   `new_bound` starts Ordinary/Unsealed and grants no successor
   serving capability. Root signature verification alone is insufficient for
   fee, ABI, object, collateral and installer correctness.
6. Only then reserve the one manifest file with create-new. Retain attached
   file and existing regular ancestor/parent handles, write the exact bytes,
   synchronize file and parent, and read/compare through the held file before
   one closed success line with the manifest commitment and authority key.
   The output and stdout assert no domain binding, live readiness or custody.

Validation refusals before reservation produce no new output and leave inputs
and existing destinations unchanged. Post-reservation I/O failures preserve
partial artifacts for explicit inspection and advertise no success; do not
claim that every possible failure leaves no file, or auto-delete/repair it.
Reuse existing artifact primitives only where those guarantees actually hold;
any missing primitive belongs to a narrow local file owner, not a generic
maintenance framework or a serialized trusted flag.

## Required local evidence

This slice depends on the accepted DR-0195 prepare/preflight implementation;
merge that owning slice first and consume its actual executable in this
acceptance, never a weaker raw-fixture substitute.

- Run the actual author executable with temporary protected fake keys and a
  genuine four-validator configuration. Feed its exact output directly into
  DR-0195 prepare for independent SQLite pairs, then actual preflight and
  original host query/restart. No raw fixture insertion into prepared stores.
- Produce identical manifest bytes/digest from the same inputs into distinct
  fresh outputs at different actual clock observations. Inspect the chosen
  authority, code/instance, all owners, sum
  of allocation/collateral supply, fee policy and exact complete committee.
- Refuse wrong expected authority, bad key permissions/shape/symlink, zero
  Freeze height, duplicate IDs/keys, missing bond, invalid prices/allowances,
  overflow, excess objects, malformed/oversized tables, input/output aliases
  and existing outputs without mutation or successful stdout.
- Retain tampered-root and installability negatives separately: a valid outer
  signature must not make invalid nested signatures, object bodies or policies
  acceptable. Preserve partial-output failure semantics.
- Require focused and complete storage-neutral validation, fresh independent
  exact-head complete review and passing CI before normal merge. No PostgreSQL
  service or real provider is selected.

## Separate real-network decisions

Actual validator/key custody, proof-of-possession or multi-party ceremony
requirements, allocation and economics choices, independent economics/ingress
audits, chain/hash/freeze selection, TLS and the activation profile remain
separate. A local operator tool must neither select them silently nor certify
release readiness. Multi-party signatures, HSM integration, load/HA and other
deferred product work are not introduced by this preset.
