# Contract publication, instances, and calls

This is the normative **To-Be** contract lifecycle. It shares the authority and
durability model in [`../architecture/generic-contracts.md`](../architecture/generic-contracts.md).
Current implementation status and sequencing belong only in
[`TODO.md`](../../TODO.md).

Publication authenticates the publisher and commits bounded, validated code
and metadata. Revisions are immutable. Preserve the hash/encoding/validation
context needed to verify published commitments across protocol upgrades.
Dependencies bind both the exact code revision and its authenticated lineage;
structural similarity or a copied ABI does not establish type provenance.

Publication ingress must bind its replay request ID in the publisher signature
and atomically reserve the origin together with the shared sender nonce and
receipt. Storage admission alone never grants execution or defining-type
authority. The explicit local development composition is specified in
[DR-0121](../architecture/decisions/0121-durable-local-code-publication.md); its
fee-free, non-executing policy is not public-network admission or VM semantics.

[DR-0122](../architecture/decisions/0122-local-instance-execution.md) specifies a
distinct opt-in executable policy, immutable independently created instances and
the typed `sunrise` host. Host-stamped object authority binds the exact instance,
defining code and nominal type; neither legacy catalog execution nor an owner's
signature may bypass it. Same-instance dependency-library calls share one
bounded invocation and roll back together. DR-0123 extends this same frame model
with explicitly signed target/revision and delegated authority for general calls;
instance equality never selects a different permission system.
Standard Asset and native fee settlement are not grandfathered into this path.

The signed candidate boundary in
[DR-0114](../architecture/decisions/0114-authenticated-publication-candidate.md)
binds exact artifact data without granting publication or execution authority.
Opaque ABI declarations and dependency claims must be verified before durable
admission, not trusted merely because the publisher signed their bytes.

The object-signature checks in
[DR-0115](../architecture/decisions/0115-public-object-signature-abi.md) bind
package-local generic constructor signatures to an exact signed candidate
closure. Value layouts, runtime substitution, object authority and durable
dependency publication remain separate obligations; a well-formed interface
is not a published or executable contract.

Concrete substitution and metadata matching in
[DR-0116](../architecture/decisions/0116-bound-object-signatures.md) preserve those
boundaries. Matching a type fingerprint and schema must not substitute for
canonical body, signed-reference, persisted-state, owner or instance validation.

[DR-0117](../architecture/decisions/0117-canonical-call-values.md) binds explicit
canonical argument layouts into the signed code artifact. Callers cannot
substitute the layout during validation; representational validity still does
not establish authenticated execution, object body invariants or ownership.

[DR-0118](../architecture/decisions/0118-signed-object-body-layouts.md) selects
constructor body layouts from the exact signed defining ABI. Canonical body
representation checking must remain separate from object-reference digest,
trusted state, owner and execution-authority validation. Fixed representation
does not establish a contract's arithmetic or application invariants.

[DR-0119](../architecture/decisions/0119-bound-durable-object-snapshots.md) reuses
durable head/record/blob integrity verification for ABI-bound reads. Returned
head observations must be revalidated by the eventual atomic commit; they do
not reserve state or authenticate a call, owner, instance or code authority.

Instantiation uses published code to establish an independent instance and its
initial objects/authority. Initialization effects and the instance record
commit atomically. Initializers must not re-run as an accidental side effect of
publishing an upgrade. Deterministic identity derivation and absence checks
must reject collisions and repeated initialization.

Calls bind the exact code and applicable instance/revision authorization in
signed bytes, together with chain, protocol, epoch, arguments, and declared
access. Never resolve an unqualified `latest` after signing. Reject stale or
unauthorized references rather than silently selecting another revision.

[DR-0120](../architecture/decisions/0120-authenticated-call-intent.md) fixes these
targets in a capability-free signed intent and binds its arguments/access to
the exact candidate ABI. Instance identity is `(chain, creator, creation seed)`;
its pinned authorization revision is separate from code and object versions.
This signed claim must be resolved against authenticated durable records, not
used as authority in its own right. The fee-free intent profile is not an
admissible transaction; fee consent must be explicitly signed before execution.

Cross-contract calls use declared typed interfaces and bounded call frames.
The host tracks the executing code, caller, object handles, and delegated
authority, preserving access and gas bounds without allowing callee privilege
escalation. A dependency cannot write another module's objects merely because
it can read their bytes. Nested calls share the transaction's atomic outcome.

Use one call and authorization model, whether the caller and callee share an
instance or not. Each frame carries an exact execution target (code revision
plus instance/revision), typed object handles and attenuated rights. Instance
identity is a checked value in this model, not a reason to introduce a separate
dispatcher, permission system or child transaction. Defining-code authority
and instance isolation remain independent predicates in the same check.

A library invocation selects another code revision in the current instance;
an invocation into another deployment selects that instance explicitly. Both
use the same frame-entry and object-operation rules. Publication dependencies
prove code/type provenance, never the authority to enter an arbitrary instance.
The signed invocation authorizes exact caller/callee targets, entrypoints,
type arguments and object-right ceilings. At runtime a callee receives only
unique handles actually delegated by its caller, with rights no stronger than
both that signed ceiling and the caller's current rights. Consumption or transfer
cannot be undone by entering a fresh frame.

Call arguments may be computed by the signed caller code and are checked
against the callee's committed argument layout and byte/gas bounds. Do not
replace contract composition with an externally supplied fixed-argument batch
interpreter. There is one shared fuel/resource budget and atomic outcome.
[DR-0123](../architecture/decisions/0123-unified-contract-calls.md) fixes this model
and its initial bounded implementation; DR-0122's dependency selector is an
adapter into the same checks, not a second authority framework.

The executable host profile must be explicit and committed separately from
non-executing publication admission. Do not activate a raw legacy host merely
because its artifact passed structural validation. Any local zero-fee execution
profile needs a new signed execution domain and an exact committed resource
and fee policy; an older nonadmissible call-intent signature must stay
nonadmissible. Zero fees are not unsigned consent to future settlement.
