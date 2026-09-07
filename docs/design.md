# Generic contracts: target design

This is the normative **To-Be** design for generic contracts and Standard
Asset integration. It describes required behavior, not implementation status.
Current status, sequencing, and completion gates belong only in
[`TODO.md`](../TODO.md). The [architecture index](architecture/README.md)
describes the existing architecture. The
[2026-09-07 decision and gap record](meeting-notes/2026-09-07-generic-contract-design.md)
records why this design was selected and the implementation it replaces.

## One execution and authorization model

Standard Asset and user-published contracts must use the same validated
publication records, typed ABI, object operations, execution, fees, and atomic
persistence boundaries. Installing code at genesis does not grant blanket
permission to create objects, change owners, or modify another type's state.
Protocol-governed operations must have explicit, narrowly scoped authority;
neither an asset name/ID nor membership in a node-local catalog grants it.

Do not expose trusted preinstalled policy constructors to arbitrary publishers
and treat their declarations as authorization. A commitment authenticates the
declared bytes; it does not prove entitlement to the requested authority.

During replacement, remove Standard Asset-only execution paths and discarded
unreleased fixture compatibility branches. Do not maintain parallel privileged
and public implementations to preserve development history. Historical decision
records may remain as evidence. This cleanup is distinct from the deliberate
contract upgrade and signed-revision rules below.

## Code, types, instances, and objects

| Concept | Meaning and required separation |
| --- | --- |
| Code identity | An immutable commitment to executable WASM, typed ABI, manifest, exact dependencies, and execution/validation semantics. The same WASM with different authority declarations is not the same executable artifact. |
| Package lineage | An authenticated namespace linking authorized code revisions and their type declarations. Copying code or claiming the same name cannot join another lineage. |
| Type identity | A nominal declaration within its defining lineage, including type arguments. It must not change merely because an implementation revision changes. Incompatible type changes require an explicit new type/schema and migration contract. |
| Instance identity | An independent deployment/configuration and authority scope using published code. Reusing code never shares another instance's state, capabilities, or administration. |
| Object identity | The identity of an individual owned/shared/immutable state value. Its concurrency version, schema version, and authorized execution revision are distinct concepts. |

These are semantic distinctions, not a requirement for five mutable registries.
Use explicit typed references rather than overloading an object reference as an
unrelated catalog lookup. Assign concrete wire types, IDs, and encodings only
with the corresponding implementation and collision/vector checks.

The nominal reference format in [DR-0113](architecture/decisions/0113-package-scoped-type-identity.md)
uses a structured origin (chain, publisher scheme/key reference, creation seed),
a package-local constructor, and ordered arguments. Hash commitments are not
logical lineage identity: rotating the hash algorithm must not create a second
lineage. An unverified origin is a reference, never evidence of publication or
authority. Authenticate the full publication request and enforce origin
absence atomically before using it to establish defining-code authority.

Instances organize independent application configuration and authority. State
remains in individually declared objects; do not put every coin behind one
mutable contract storage root. An instance must not become a second, competing
type authority. Any instance-scoped capability must bind the target instance,
and object access must enforce that scope in addition to type and owner rules.

## Publication, instantiation, and calls

Publication authenticates the publisher and commits bounded, validated code
and metadata. Revisions are immutable. Preserve the hash/encoding/validation
context needed to verify published commitments across protocol upgrades.
Dependencies bind both the exact code revision and its authenticated lineage;
structural similarity or a copied ABI does not establish type provenance.

The signed candidate boundary in
[DR-0114](architecture/decisions/0114-authenticated-publication-candidate.md)
binds exact artifact data without granting publication or execution authority.
Opaque ABI declarations and dependency claims must be verified before durable
admission, not trusted merely because the publisher signed their bytes.

The object-signature checks in
[DR-0115](architecture/decisions/0115-public-object-signature-abi.md) bind
package-local generic constructor signatures to an exact signed candidate
closure. Value layouts, runtime substitution, object authority and durable
dependency publication remain separate obligations; a well-formed interface
is not a published or executable contract.

Concrete substitution and metadata matching in
[DR-0116](architecture/decisions/0116-bound-object-signatures.md) preserve those
boundaries. Matching a type fingerprint and schema must not substitute for
canonical body, signed-reference, persisted-state, owner or instance validation.

Instantiation uses published code to establish an independent instance and its
initial objects/authority. Initialization effects and the instance record
commit atomically. Initializers must not re-run as an accidental side effect of
publishing an upgrade. Deterministic identity derivation and absence checks
must reject collisions and repeated initialization.

Calls bind the exact code and applicable instance/revision authorization in
signed bytes, together with chain, protocol, epoch, arguments, and declared
access. Never resolve an unqualified `latest` after signing. Reject stale or
unauthorized references rather than silently selecting another revision.

Cross-contract calls use declared typed interfaces and bounded call frames.
The host tracks the executing code, caller, object handles, and delegated
authority, preserving access and gas bounds without allowing callee privilege
escalation. A dependency cannot write another module's objects merely because
it can read their bytes. Nested calls share the transaction's atomic outcome.

## Ownership and type authority

An owner's signature permits the requested use of an object; it does not let
arbitrary code rewrite that object's internal representation. For example, a
Coin owner cannot publish a module that increases that Coin's amount.

The host must enforce the following for every contract, including Standard
Asset:

- Creation is limited to types the executing code is authorized to construct.
  IDs are host-derived, fresh, and resource-bounded. A supplied type hash or a
  same-typed input is not construction authority.
- Internal mutation/destruction requires defining-code authority or an
  explicitly authorized interface/capability, as well as declared access and
  applicable ownership authorization.
- Transfers obey the type's verified transfer permissions and ownership rules.
  Do not infer permission to change an owner from an arbitrary args field or
  from preinstalled catalog membership.
- Opaque typed handles cannot be forged, duplicated into conflicting mutable
  borrows, reused after consumption, or used outside their authorized call and
  instance scope. Validate effects before persistence as well as host access.

Use publication-time ABI/verifier checks together with runtime enforcement.
ABI declarations alone do not provide Move-equivalent static guarantees.
Specify exactly which invariants are statically checked and which the host
checks; do not claim proof of arbitrary WASM business semantics.

## Revision authority and state migration

Extending a lineage requires an explicit upgrade capability scoped to that
lineage. Define its custody, transfer, and irreversible relinquishment through
the ordinary authority model. Authority to publish a revision does not by
itself authorize changing every user's object or every independent instance.

Keep code revision, ABI compatibility, and object schema version separate.
Mechanical ABI/layout compatibility does not prove semantic compatibility.
Upgrade policy must specify which revisions may operate on existing state,
which changes require migration, and whose authority authorizes that migration.

Migration is a bounded atomic transition over declared objects. It updates
state and the host-enforced execution/schema authorization together. Old code
must not be able to mutate a migrated object by omitting an application-level
version check. Merely proving that old code belongs to the same lineage is
insufficient authorization. Reject unsupported mixtures of revisions/schemas
in multi-object operations; cross-object invariants must hold during mixed
revision operation, not just after migration is finished.

Preserve the owned-object fast-path opportunity using immutable code and
object-scoped revision authorization. Reading immutable code does not alone
make a transaction fast-path eligible: all state, authority, and dependency
accesses matter. A shared instance-wide upgrade switch or mutable revision
registry requires ordering/fencing against affected calls. Do not hide such a
dependency from conflict detection or claim it is consensus-free. No automatic
whole-state scan or background migration is a protocol requirement.

## Standard Asset and fees

Standard Asset defines its asset identity, Coin, TreasuryCap, and mint, burn,
split, merge, and transfer behavior using the public contract facilities.
Amount arithmetic, supply accounting, and asset-specific state encoding stay
in that contract. The host protects generic type authority, ownership,
consumption, deterministic execution, and atomicity; it does not implement
Coin-specific conservation arithmetic or privileged mint operations.

Fee admission, accepted fee assets, gas pricing, and settlement authorization
remain explicit protocol policy. Actual asset-state settlement uses a pinned,
committed contract revision with a bounded interface, rather than an arbitrary
node-local Rust callback that rewrites Coin bodies. The request cannot choose
an unapproved fee implementation or redirect the treasury. The protocol must
specify settlement resources and failure behavior without recursive fee
charging, and govern changes to the pinned settlement revision.

Application effects and settlement commit atomically. A normalized execution
trap may discard application effects while committing only authorized fees and
the rejected receipt under the defined fee policy. Pre-execution rejection and
request-ID conflicts must not be confused with such fee-bearing failures.
Exact replay returns the original outcome without executing application or
settlement code again.

## Durability and verification obligations

Reconcile receipt/nonce replay before resolving code/policies or doing
application object I/O. Commit publication/instance/migration state, affected
objects, nonce, receipt, and outbox in the same fenced atomicity domain. Failed
publication cannot leave partially usable code or authority. Transport,
schedulers, caches, and process lifetime confer no correctness or authority.

The acceptance gate must demonstrate equivalence of Standard Asset and a
separately published contract under the same public facilities. Include
adversarial type/instance forgery, unauthorized revision extension, old-code
access after migration, mixed-revision operations, dependency substitution,
capability misuse, replay, and rollback cases. A working upload endpoint alone
does not establish a safe generic contract platform. Detailed implementation
sequence and required test evidence remain in TODO.
