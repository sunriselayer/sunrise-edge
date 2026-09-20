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
execution exception. The manifest fixes one genesis authority, carries the
exact pre-signed publication and initialization frames that existing audited
handlers authenticate, and adds a signature by that same authority over the
complete canonical manifest payload. That outer signature binds every initial
object and object-authority entry; none of the declared initial state is an
unsigned installer input. The resulting publisher and instance identities are
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
vectors are implementation evidence of this decision. `0x6419/v1` encodes one
bounded object/authority entry and `0x641a/v1` encodes their bounded ordered
list. Field 6 of `0x6416/v1` is the Ed25519 signature over canonical fields
1–5 under the `genesis-manifest-v1` message domain. State keys remain under the
reserved `se/instances/` namespace and are bound to the publication context.

The atomic install commits the ordinary accepted publication receipt for the
manifest's signed `PublicationSubmission`, rather than a special bootstrap
receipt. The normal durable publication loader can consequently verify and use
the package with no genesis-only bypass. Verify-only restart checks that exact
receipt together with the manifest, publication, instance, policies, marker,
object authorities and version-one object provenance.

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

Allocate canonical frame `0x6418/v1` to `PublicationQueryResult`, distinct
from `0x6416`/`0x6417` above. Field 1 is a `u16` provenance discriminant
(Legacy=1, Paid=2). A Legacy result's field 2 is the complete encoded
`PublicationSubmission` (frame `0x6308`); a Paid result's field 3 is the
complete encoded `SignedPaidIntent` (frame `0x6413`), never a bare request
identity, so a caller can independently re-authenticate it end to end. Each
provenance uses exactly its own field; decoding rejects any other field
present. `MAX_PUBLICATION_QUERY_RESULT_BYTES` bounds the encoded frame before
any allocation driven by caller-supplied bytes and is re-checked after
encoding. A caller that decodes a Paid result must re-authenticate its
`SignedPaidIntent` under its own explicitly supplied original resolver and
context, require a `PaidApplication::Publish` application, require the
artifact's origin to equal the queried origin, and check the artifact's
semantics against its own independently configured expectation; it must
never treat server-returned bytes as trusted before that check completes.

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

## Implementation status (2026-09-20)

Items 1–6 are implemented and locally validated as one activation slice.
This remains local-devnet evidence; the production and public-network gates in
the decision above remain open.

- **Calibrated paid profile.** `execution::paid_execution::{MIN_RESERVE_ALLOWANCE,
  MIN_SETTLE_ALLOWANCE, MIN_EXECUTION_PRICE}` are the committed protocol-critical
  floors. They are calibrated against real measured fuel for the pinned public
  Standard Asset `reserve`/`reserve_all`/`settle` exports, run under `wasmi`
  through the existing phase coordinator
  (`local_wasm::coordinator::tests::calibrated_allowances_retain_headroom_over_measured_reserve_and_settle_fuel`
  is the reproducible measurement: on this date, measured `reserve_gas` was
  13025/12667 and `settle_gas` was 8741/8881 for Write/Consume access,
  respectively), with roughly 2x conservative headroom. `validate_paid_fee_policy`
  rejects a policy below these floors or with a zero execution price.
  Duplicated `200_000` test literals were removed in favor of these constants;
  the stable Rust/JS `0x6414`/`0x6412`/`0x6413` vectors were regenerated together
  and both still round-trip and match. Canonical field IDs/versions are
  unchanged.
- **Installed fee ABI/role admission.**
  `execution::paid_execution::validate_fee_interface_admission` is a reusable
  validator over one `VerifiedPublicationInterface` and `PaidFeePolicy`. It
  proves the exact `reserve` (Write Coin<A> → one required Consume
  Reservation<A>), `reserve_all` (Consume Coin<A> → the same required result),
  and `settle` (Consume Reservation<A> → required Read fee slot 0, optional
  Read refund slot 1) roles, their fixed DR-0124 argument layouts, that the
  reservation type is absent from `transferable_constructors`, and that no
  other export of the fee package interface selected by `policy.code.origin()`
  accepts it. This is not a claim about every export in the transitive
  dependency closure. Node-core's durable admission
  (`handle_paid_execution`) invokes it immediately after the pinned fee scope
  loads and before the immutable quote is derived or the nonce is committed.
  A dedicated fail-closed matrix (`crates/execution/tests/paid_fee_interface_admission.rs`,
  18 cases) and a node-core regression proving pre-quote/pre-nonce rejection
  back this. Node-core stays asset-agnostic; no amount is decoded.
- **Historical object framing.** `ObjectSnapshot` retains the object version
  record's own creating `(chain_id, protocol_version)` provenance, and a new
  `historical_resolver_for_provenance` helper selects the trusted resolver
  matching that provenance from `[current] ++ history` before nominal-type
  verification, mirroring the existing `original_resolver` pattern for
  code/instance contexts. Missing history fails closed
  (`NodeCoreError::ObjectHistoricalResolverUnavailable`); the current resolver
  is never substituted. `execution::publication::{match_object_input_metadata,
  validate_object_input_bodies}` take the caller's current/execution resolver
  (checked unconditionally, including for a zero-object entrypoint) plus one
  additional resolver per positional input for DR-0126 historical selection.
  Old-protocol acceptance, missing-history rejection, unchanged same-version
  behavior and the zero-object wrong-chain invariant are covered in
  `node-core::tests::bound_snapshots` and
  `execution::tests::publication_interface::binding`. The production native
  HTTP router (`preinstalled_wasm_structured_durable_router[_with_executor]`)
  now takes an explicit `history: Vec<HashSuiteResolver>` parameter, shared by
  its local-execution and publication routes instead of a hardcoded empty
  slice; `native_http::tests::local_execution_http` proves both old-protocol
  acceptance and missing-history rejection through the real HTTP router.
- **Durable Consume evidence.** Real durable
  `ReservationAccessKind::Consume` coverage proves source Delete/tombstone,
  retained provenance (the immutable version-one record still reads back),
  exact replay without re-delete, request-conflict invariance, and file-backed
  SQLite writer fencing across a close/reopen
  (`node_core::paid_execution::tests::{consume_reservation_deletes_the_source_with_retained_provenance_replay_and_conflict_invariance,
  consume_reservation_sqlite_reopen_replays_exactly_and_a_stale_writer_generation_is_fenced}`).
- **Depth-two paid-Publish dependency and publication query provenance.**
  `node_core::paid_execution::tests::depth_two_paid_publish_dependency_resolves_under_one_shared_load_budget`
  proves a paid root declaring one edge to an already-published middle
  package (itself declaring one edge to a leaf) resolves the full three-node
  closure under one shared `PublicationLoadBudget`, with the deterministic
  metered units counting all three nodes. Separately, `node_core::publication::query_publication`
  no longer rejects a stored paid record: it returns the new
  `PublicationQueryResult::{Legacy(PublicationSubmission), Paid(SignedPaidIntent)}`
  (canonical frame `0x6418/v1`, normatively allocated above), never
  synthesizing a legacy signature for a paid record and bounding the encoded
  frame with `MAX_PUBLICATION_QUERY_RESULT_BYTES` before decode and after
  encode. The Rust client independently re-authenticates a Paid result's
  embedded `SignedPaidIntent` under its own explicitly supplied original
  resolver/context, requires a `PaidApplication::Publish` application, checks
  the artifact's origin against the queried origin, and checks its semantics
  against the caller's own expectation before ever returning it; adversarial
  coverage in `clients/rust/tests/publication.rs` exercises wrong origin,
  tampered signature, mismatched context, a non-Publish application kind,
  wrong semantics, and malformed/oversized/trailing query frames. Native
  HTTP's publication query route, the Rust client's `query_publication*`
  methods and the `sunrise-edge-cli` publication query command are all
  updated to this provenance-aware result; the CLI prints
  `published=true`/`provenance=paid` only after that independent
  re-authentication succeeds. Zero-fee dependency resolution
  (`local_execution_client`) explicitly rejects a paid dependency rather than
  misusing it, since it has no legacy submission to authenticate.
- **Closed signed genesis.** `node_core::genesis` validates a bounded canonical
  manifest, the outer genesis-authority signature, ordinary signed publication
  and initialization frames, exact profile-four policies, fee ABI roles,
  object nominal bodies and authority/type fingerprints before any write. One
  writer-fenced durable invocation installs all records, initial objects and
  the normal publication receipt. Restart is verify-only and rejects a changed
  manifest, partial/tombstoned state, missing or changed records and stale
  writer generation. `apps/devnet::paid_contracts` is the only layer that knows
  the installed package is Standard Asset; node core never decodes an amount or
  supply field.
- **Paid HTTP, Rust client and CLI activation.** The explicit
  `--enable-paid-contracts` devnet flag installs the manifest before routing and
  composes only the paid profile-four surface. Native HTTP exposes bounded paid
  submission, the exact installed fee-policy query, authenticated publication
  query and instance query required for subsequent calls. The Rust client and
  software-signer CLI independently validate expected protocol context,
  publication provenance, instance pins, fee source and policy before signing.
  `paid-publish`, `paid-instantiate` and `paid-call` reserve every requested
  output before network submission and write derived references only after a
  successful result. Ledger remains fail-closed.
- **Activation integration and independent bytes.** The real file-backed
  SQLite integration `apps/cli/tests/devnet_paid_contract_e2e.rs` crosses the
  production router and Rust HTTP transport with three real CLI invocations:
  paid Publish writes a dependency reference, paid Instantiate writes an
  instance reference, and paid Call consumes that pin; all three commit charged
  successful results. The zero-fee registry still rejects profile four. The
  JavaScript vector script independently reconstructs complete `0x6415/v1`
  bytes without importing the Rust codec and matches the Rust length and digest.
