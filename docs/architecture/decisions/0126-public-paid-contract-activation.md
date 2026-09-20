# DR-0126: public paid contract activation

Accepted design, 2026-09-20 (Asia/Singapore).

## Decision

Activate paid Call, Instantiate and Publish as one externally usable devnet
slice. A booted node must expose the same authenticated paid intent through the
Rust client, CLI, native HTTP admission, fenced durable handler and pinned
Standard Asset reserve/settle contract. Installing an internal policy without a
reachable paid route, or exposing a route before its policy is durably closed,
is not an acceptable intermediate activation state.

The implementation is ordered but lands as one reviewed pull request:

1. calibrate the existing shared reserve/settle phase caps and define the
   minimum R/S allowances and gas-schedule floor in one public paid profile;
2. validate the installed fee contract's complete ABI and role shape before
   installation and again before paid admission;
3. close historical object framing, Consume fee-source deletion, transitive
   paid-publication dependency and paid-publication query evidence;
4. atomically install and close a genesis manifest containing the public
   Standard Asset package, instance, initialized objects, profile-four
   policies and paid fee policy;
5. expose the paid submission and installed-policy query through native HTTP,
   the Rust client and software-signer CLI; and
6. retain the zero-fee profile-four rejection and independently reconstruct the
   paid result vector.

Removal of the legacy native Coin composer and migration of the five historical
asset CLI commands is the immediately following activation slice. It must not be
performed before the replacement paid route is usable, and it must not be kept
as an indefinite compatibility branch after that migration. PostgreSQL fault
operations, public multi-validator launch, Ledger clear signing and production
HA remain separate gates.

## Genesis authority and installer boundary

Bootstrap is not an incoming transaction kind and does not create an unsigned
execution exception. The manifest fixes one genesis authority and carries the
exact pre-signed publication and initialization frames that existing audited
handlers authenticate. The resulting publisher and instance identities are
therefore ordinary immutable public-contract identities.

The installer is fenced and atomic. It commits the manifest, package and
instance records, initialized objects and authority, profile-four publication
and execution policies, paid fee policy, and a closed marker in one durable
transaction. A present marker permits verification only: restart must compare
the complete manifest commitment and installed records and must never replay
initialization, overwrite balances or reissue supply. Partial prior state,
different bytes, a tombstoned marker or missing installed records fail closed.
No HTTP route invokes the installer.

Allocate canonical frame `0x6416/v1` to the genesis manifest and
`0x6417/v1` to its closed install marker. Their exact fields, bounds and stable
vectors are implementation evidence of this decision. State keys remain under
the reserved `se/instances/` namespace and are bound to the publication
context.

Node core stays asset-agnostic. It validates and installs bounded canonical
manifest entries; only the devnet composition builds those entries from the
public Standard Asset package. No Standard Asset amount or supply field is
decoded by node core.

## Paid profile and policy admission

The existing phase-limit module is already the single definition used by the
policy wire and coordinator. Activation adds measured minimum reserve and
settle allowances plus a minimum base/execution-only price schedule; test
fixture literals are removed. Measurements use the pinned Standard Asset WASM,
`wasmi` and `wat` toolchain with conservative headroom. Values are committed
policy bytes and require an explicit reviewed policy/version change to retune.

Intrinsic `PaidFeePolicy` decoding is not installed-contract authority.
Admission resolves the installed fee interface and proves the exact
`reserve`, `reserve_all` and `settle` argument, input and ordered result roles;
the bound asset and reservation types and schema; non-transferability of the
reservation; and absence of any other reservation-consuming export. A mismatch
rejects installation and a new paid request before execution or nonce use.

Historical object references are verified under their recorded provenance and
trusted historical resolver. Missing historical context fails closed; the
current resolver is never substituted merely because it can decode the bytes.
Consume remains an ordinary durable Delete with retained provenance, not a
paid-path exception.

## External surface

Native HTTP exposes a bounded paid-execution submission and a read-only query
for the exact installed fee-policy bytes. The zero-fee local-execution router
continues to reject profile four so installation cannot create a free-execution
bypass.

The Rust client and CLI query the policy, verify the independently configured
expected protocol context, resolve and verify the fee source and owner, compute
the policy digest and quote, and only then sign. Software signing is the first
surface. Ledger fails closed before device or submission work until its separate
clear-signing contract is implemented.

Publication queries return authenticated provenance rather than synthesizing a
legacy signed submission for a paid record. Legacy and paid records remain
distinguishable while sharing the same immutable interface and dependency
verification rules.

## Required evidence

- measured reserve, reserve-all and settle fuel with headroom, below-floor
  rejection and rounding-bound `actual <= reserved` properties;
- ABI/role mismatch matrices at install and admission;
- historical-resolver acceptance and missing-history rejection;
- file-backed SQLite Consume deletion, exact replay, request conflict and
  writer fencing with unchanged receipt/nonce/object evidence;
- depth-two paid publication dependency and legacy/paid publication queries;
- fresh install, verify-only restart and partial/tampered/supply-reissue
  installer rejection;
- paid Publish, Instantiate and Call through native HTTP and the CLI, plus
  zero-fee profile-four and Ledger fail-closed regressions;
- stable Rust vectors and an independent JavaScript reconstruction of
  `0x6415/v1`; and
- the complete repository gate and a fresh independent review.

This decision activates a local devnet paid surface. It is not a claim that the
public multi-validator network, production operations or mainnet gates are
complete.
