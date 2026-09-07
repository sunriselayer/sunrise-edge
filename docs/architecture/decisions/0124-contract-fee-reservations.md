# DR-0124: contract-defined fee reservation and settlement

Accepted design, 2026-09-07 (Asia/Singapore). This refines `docs/design.md`
before implementation; activation and completion evidence belong in `TODO.md`.

## Chosen boundary

One sender-owned Coin may fund both fees and application work. A signed paid
invocation authorizes reservation before its application reads the spendable
remainder. No pre-split transaction or separate fee Coin is mandatory. Sui's
reservation model motivates this boundary, but SUI-specific runtime accounting
and GasCoin privileges are not imported.

The protocol controls admission, metering, ordering, exact settlement policy
and access to a reserved resource. The committed defining contract controls
asset representation, debit, split, refund and supply conservation. The host
must not decode Coin amounts or bypass owner/type/instance authority.

## Signed consent and exact policy

Paid consent binds the original fee source ObjectRef, original owner, maximum
asset charge, refund recipient, policy digest, application gas limit and the
existing chain/protocol/epoch/request/nonce/call target and capabilities. If the
source also occurs in application access, its original reference must match
exactly; the paid signature explicitly authorizes the application to observe
the post-reservation body. Each original object is loaded and committed once.
Consent separately declares the reservation access mode (Write or Consume).
Durable access/conflict accounting uses the stronger of the two modes, while
application grants retain exactly their signed application modes. Reservation
rights never strengthen the application's declared access mode.

Committed policy binds an exact defining-code/instance revision, reserve and
settle exports, accepted asset/type parameters, reservation result type, fixed
fee recipient, gas schedule and phase resource caps. Requests cannot nominate
another implementation or treasury. Current policy and all original publication
contexts are verified before execution. Policy updates require governance;
the first local activation may use an explicitly installed immutable policy,
but must not claim an implemented governance update mechanism.

## Three phases, one invocation

1. **Reserve.** Invoke the committed contract with the source, computed
   worst-case charge, and pinned recipients. It debits the source and returns
   one fresh, own-defined reservation resource. Its amount is the computed
   worst-case charge, not automatically the whole user-signed maximum.
2. **Application.** Expose only the spendable source and other signed inputs.
   Keep the reservation handle private to the coordinator. The application may
   transfer or consume the remainder under ordinary authority rules; it cannot
   acquire the reservation through an alias, nested call or fabricated selector.
3. **Settle.** Invoke the committed contract with only the reserved handle and
   the protocol-computed actual charge. Consume the reservation, create a normal
   fee Coin for the policy recipient and, if nonzero, a fresh refund Coin for the
   signed refund recipient. No reservation survives a successful commit.

Fresh refund outputs deliberately differ from Sui's refund-to-GasCoin behavior.
They avoid writing a transferred/consumed Coin or restoring attenuated rights.
The CLI must show both fee and refund outputs. Coin fragmentation is a tradeoff,
not hidden automatic merging or a requirement for an extra preparatory payment.

For the initial positive-amount Coin contract, exact-full reservation can consume
the source only when it is not an application input. If the root ABI still
requires that source, reject before application entry; do not fabricate a
zero-valued Coin or weaken its type invariant. A separate fee Coin remains an
option, not a requirement.

The asset contract enforces `source_before = remainder + reserved` and
`reserved = fee + refund` with checked arithmetic and exact asset identity.
Reservation is a temporary representation of existing supply; it does not alter
TreasuryCap supply. The resource binds invocation/policy identity and recipients.
No foreign-owner treasury input or native fallback debit exists.

## Generic frame results, not asset discovery

Reserve must return its resource through a bounded, explicit typed frame-result
mechanism. Validate current handle rights, type, defining code, instance,
freshness, ownership, uniqueness and result cardinality. A raw arena index,
creation-order guess or native Coin parser is not a return channel. The same
mechanism must be usable by ordinary contract composition, without adding a
Standard Asset-only host primitive. The coordinator delegates the protected
result only to settlement using the same frame validator.

## Failure, resource and accounting semantics

Retain a post-reservation object/event savepoint. Application failure restores
that savepoint, discarding every application's scope effects and events. It does
not restore gas or cumulative resource consumption. Settlement then runs and the
rejected application status plus reservation/settlement effects commit together.
After authenticated admission and input integrity checks, a reserve or settlement
execution failure restores the pre-reservation application/object state and
commits only an explicit zero-charge rejected receipt and the consumed nonce.
It does not leave application changes, partial fees or escrow, and never invokes
a native fallback. Exact replay returns that receipt without re-executing the
expensive application. Malformed signatures, wrong context/policy, stale inputs,
invalid nonce and request conflicts still reject without writes. These are
different outcomes; "nothing commits" is not used for every failure category.
Zero-charge phase failure is not a complete economic DoS solution: fresh valid
requests can still cost resources. Pinned settlement code and calibration need
review, and public admission remains gated on that cost/abuse analysis.

Protect settlement headroom before application entry: fuel, retained memory,
handles, calls, creations, events and encoded result bytes. An application must
not prevent charging by consuming those reserved capacities. Failures of one
phase must not poison the following phase's reserved limiter state. Keep one
global monotonic creation ordinal, including gaps for rolled-back creations;
never reuse an ID because application state rolled back.

The initial deterministic pricing charges fixed bounded reserve and
settle allowances R and S, plus actual metered application gas A. Admission uses
application limit L. Convert `base + price * (L + R + S)` once to worst-case asset
units, check it against signed max_fee, and reserve that amount. Actual charge
converts `base + price * (A + R + S)` with the same committed checked rounding.
Refund equals reserved asset units minus actual asset units. Never compute it by
separately converting unused gas. Actual phase work is bounded by R and S;
settlement is not recursively charged for calculating its own fee. Fixed charged
allowances must be disclosed, not described as exact phase gas usage. The paid
schedule admits only base and execution-gas prices; read/write/storage/system
prices must be zero until corresponding signed resource maxima are implemented.
Require L + R + S <= 1,000,000 and checked arithmetic throughout. A property
test must prove actual charge <= reserved charge under the chosen ceiling
conversion, including rounding boundaries.

For the first profile, reserve and settle each receive at most 8 calls, 16
handles, 4 creations, 16 events, 8 MiB cumulative linear-memory allocation and
1 MiB encoded-effect allowance. Application receives the remaining global
64-call/256-handle/128-creation/1024-event/64-MiB-memory/16-MiB-result capacities,
with encoding-envelope overhead accounted explicitly. These are logical budgets,
not a promise to allocate memory upfront. Enforce phase caps during operations,
including output byte accounting, before mutating the arena. Set independent
phase fuel and failure flags, retain cumulative resource and ordinal counters,
and keep settlement's unused capacity inaccessible to the application.

R and S are positive committed fuel caps, calibrated against canonical tests
for the exact pinned exports with conservative headroom. Tests are evidence,
not a proof of all WASM semantics; deterministic runtime caps remain mandatory.
Activation rejects schedules below the measured calibration requirements.

## Durable boundary and activation

Authenticate and reconcile exact replay before policy/code/object reads. Verify
every source, scope, policy and publication read in the same final fenced CAS.
One commit writes final objects and authority, original versions advanced at
most once, nonce and a complete receipt. Replay performs none of the phases.
Pre-admission rejection and request-ID conflict leave all state unchanged.

Use explicitly versioned paid signing/policy/result frames. A zero-fee signature
never opts into charging. Results distinguish application status, actual charge,
refund and complete committed effects; old failure results remain unchanged.
Transient consumed reservations must not leave durable orphan authority rows.
Reject surviving output objects of the policy's exact reservation type as a
host-validated postcondition, not merely a contract promise. The host validates
fee/refund output identity, type, owner and provenance; amount correctness
depends on the pinned contract and its audited supply arithmetic, not a claimed
host inspection of opaque bodies. Include actual output references in receipts.

The savepoint covers the complete arena (object value and consumed/transferred/
dirty flags), events and phase-local result slots. Rollback truncates subsequent
arena entries and events and restores prior entries; it never rewinds the
creation ordinal, calls, handles, consumed fuel or cumulative memory allocations.

## Concrete integration interfaces

Extend the signed executable ABI with bounded typed object results (initially
at most four per entrypoint), and bind them in `BoundObjectSignature`. A generic
`return_object` operation supplies handles checked against those declarations.
The call boundary delivers returned handles into the caller's handle namespace,
not raw arena indices. Reject duplicate results, consumed handles and aliases
already granted to the receiving frame; rights cannot exceed those returned by
the callee. Each delivered handle also increments the permanent cumulative
handle counter, even after its receiving frame exits or rolls back.
The coordinator uses that exact validation for the fresh sender-owned
reservation result and never exposes it to the application frame.

Result positions are signed and ordered. A slot may explicitly permit absence;
an absent value occupies its slot but grants no handle. Required slots cannot
be omitted. Settlement returns the fee and refund in distinct declared slots,
so a zero refund is represented as absence, not a zero-valued Coin or an output
guessed by recipient (the two recipients may coincide). Reserve has one required
slot. Optionality is generic ABI metadata, not a settlement-only convention.
`return_object(slot, handle)` names the declared slot, each set at most once;
delivery contains one entry per slot with an explicit absence sentinel. Required
slots must be filled on normal frame exit. Ordinary root-call results are
validated and then dropped as handles; their object effects still persist.
Coordinator roots retain the validated slots. The paid policy requires positive
base/execution pricing sufficient for a nonzero actual fee, and requires its fee
slot present. It requires the refund slot present exactly when the independently
computed refund is nonzero. Both may be optional in generic metadata, but paid
policy postconditions enforce those stronger runtime requirements.

### Typed-result wire and authority boundary

Result metadata uses executable ABI `0x5406/v2`, with field 4 holding the
ordered entrypoint result lists (`0x540A/v1`). Each result declaration is
`0x5309/v1`: mode, schema, nominal type pattern and a closed optional flag.
All-empty result declarations use the existing executable ABI version 1;
version 2 with all-empty declarations is noncanonical and rejected. The
aggregate result type-node budget spans all entrypoints, not each list alone.

The imports `return_object`, `get_object_id`, `get_object_type`,
`call_dependency_with_results` and `call_contract_with_results` require WASM
profile 4 in both the executing artifact and the selected policy. Profile 4
uses host ABI 3, execution rules 3, semantics `0x630B/v4` and policy
`0x6409/v3`. Older policies never admit profile-4 code. The result buffer holds
one little-endian u32 per declared slot; `u32::MAX` denotes absence. Validate
the whole receiving buffer and result batch before extending caller grants.

Returning a handle is not a write: a foreign-owned Read handle or a
dependency-defined handle may be relayed. Actual writes and consumes still
require the sender owner, exact defining code and exact instance/context.
Revalidate returned slots against final live state at frame exit, including
consumption and transfer attenuation. The receiving frame cannot acquire a
duplicate alias, and delivered handles permanently count toward the global
handle limit even after frames exit.

General-call authorizations still select original signed input ObjectIds;
typed results do not add a fresh-object selector to that authorization format.
A returned fresh object is therefore not automatically eligible as a later
general-call input. Dependency calls retain their existing handle-based path.
No implicit result-to-authorization conversion or asset-specific exemption is
permitted.

## Public asset identity

The public Standard Asset initializer creates one own-defined Definition object.
Its host-derived ObjectId becomes the asset's opaque type argument A. Coin<A>
and TreasuryCap<A> therefore share an asset identity, while every individual
Coin retains its independent ObjectId. Host creation already binds context,
instance, defining code, invocation digest and a monotonic ordinal; the contract
must not accept caller-chosen A in initialization or fabricate an arbitrary
TreasuryCap. A generic read-only object-ID accessor exposes the identity of a
handle the frame already possesses. A bounded canonical type accessor exposes
its validated nominal tag for ordinary type-preserving operations.

Package-local constructors are Definition (1, no type argument), Coin (2),
TreasuryCap (3) and Reservation (4); the latter three use one package-local opaque
argument domain 1. Coin amounts and TreasuryCap supply fields use checked u64
arithmetic. Asset identity lives in the nominal type, not a duplicated body field.
Only Coin is transferable; other constructor operations remain restricted to
their defining contract. Definition creation is not an authority exemption.
Two independent instances cannot mint mutually substitutable assets by reusing
a seed. No new asset-specific native hash operation or uniqueness registry is
introduced. This is a fresh public package, not reinterpretation of old fixture
body bytes or the old seed-based AssetId derivation.
Nominal tags alone do not prove instance authority: all Coin/TreasuryCap writes
and consumes must pass the existing defining-code and exact-instance checks.
A future read-only proof API must validate provenance rather than assume equal
tags imply equal instance authority. The guest obtains its own origin from the
existing canonical instance record, whose framing must be decoded with bounds;
no additional origin or asset-specific hash import is necessary. Reading an
ObjectId does not authorize an ID-to-handle lookup; that operation remains absent.

Represent the middle phase as Call, Instantiate or Publish under one paid
envelope and one reserve/settle coordinator. Instantiate forbids application
object inputs but permits the separately declared fee source. Publish charges
deterministically for bounded artifact bytes and closure nodes in execution
units; it does not run a different fee mechanism. Paid result status distinguishes
reservation failure, application failure with settled fee, settlement failure,
and success. Old zero-fee bytes are neither reinterpreted nor silently charged.

Bootstrap is an installer, never an incoming request mode. An exact genesis
manifest pins artifact, instance/initializer, initial distribution, TreasuryCap
recipient and fee policy. Its fenced installation must atomically commit the
manifest, code/instance/host-produced objects, policy and closed-install marker.
At least one authorized owner receives an initial fee Coin. Restart verifies
the installed commitment and historical provenance; it never overwrites current
balances or reissues supply. External requests cannot invoke bootstrap, and a
fresh development-state activation boundary replaces incompatible fixtures.

The integrated replacement must include the five asset CLI operations, public
publication/initialization, actual WASM authority, native HTTP/devnet activation,
canonical vectors, adversarial tests and real file-backed SQLite replay/fencing.
Publication/initialization charging and bootstrap policy installation need exact
admission rules before activation; users must not inherit a genesis exemption.
Remove the old asset-specific catalog grants/native composer with the usable
replacement, not maintain them to preserve discarded development fixtures.

## Review gate

Before code, resolve concrete phase/return APIs, bootstrap and publication fee
scope, and testable caps. Before merge, prove same-source success, consumed and
transferred remainder, exact-full boundary, wrong policy/asset/type/instance,
escrow isolation, app exhaustion with successful settlement, app and settlement
traps, no orphan reservation, fee rounding, output bounds, replay/conflict and
writer fencing. Full repository validation and fresh Opus approval are required.
