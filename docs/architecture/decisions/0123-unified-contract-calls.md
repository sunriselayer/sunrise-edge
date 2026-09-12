# DR-0123: one contract-call authorization model

Decision: 2026-09-07 (Asia/Singapore).

This decision precedes implementation. Concise current status and remaining
work belong in [`TODO.md`](../../../TODO.md); durable verification evidence
belongs in the applicable decision record. It refines DR-0122 without granting
production/network authority.

## Decision and rejected alternative

All contract calls use one execution target, frame-entry validator, object
authority model, resource budget and atomic persistence boundary. An execution
target contains exact published code plus an immutable instance target/revision.
Whether two target instances compare equal does not choose another security
system. A library call is code execution in its selected instance, not an
exception to type authority. A call to another deployment changes that selected
instance, not the meaning of ownership or delegation.

Reject a separate cross-instance permission plane, a child transaction handler,
and a fixed batch of externally supplied calls masquerading as WASM composition.
Do not add an instance-creator signature requirement merely because a target is
different. Owners authorize object use; the target's code controls its interface
and type-specific operations. Multi-owner spending still requires explicit owner
authorization and is not inferred from an instance's administrator.

## Signed authority and runtime dispatch

The authenticated root invocation binds the existing chain/protocol/epoch,
sender, nonce, request ID, root code/instance, root arguments and gas, and a
bounded ordered table of call authorizations. Each authorization fixes:

- the exact caller code and caller instance target/revision;
- the exact callee code and callee instance target/revision;
- the callee entrypoint and ordered type arguments;
- the ordered original input ObjectIds and maximum Read/Write/Consume modes.

ObjectIds resolve to the root's signed exact access references. Authorization
cannot add undeclared objects or replace a stale reference. The root ABI includes
all initial handles it can forward, including foreign-instance handles. Such a
handle is transportable authority, not permission for the root to mutate another
instance's state or another code's representation.

The guest selects an authorization index, an ordered list of its current opaque
handles and argument bytes. It cannot override targets, entrypoint, type arguments
or rights. The host checks the current frame against the authorization's caller,
then checks unique handles against the signed object selectors, the caller's
current modes and the callee ABI. All three bounds must hold; rights never grow
by unioning them. The callee receives only those handles, not the entire pool.

Arguments are computed by the signed caller code, bounded and canonically checked
against the committed callee layout before entry. This intentionally authorizes
the specified code to compute arguments within its explicitly signed call
capabilities; it is not a promise that the owner separately signed every resulting
argument byte. Business constraints stay in the caller/callee programs.

An authorization is a reusable bounded capability, not a required batch step.
The shared call/fuel budget limits repetitions. Skipped authorizations do not
cause fake execution, and the host never automatically runs table entries.
Initially, authorized call selectors refer to original signed input objects;
newly created handles may follow the existing library delegation rules but do
not silently acquire a capability for an unrelated target. Extending that input
selection policy requires an explicit contract, not an unchecked wildcard.

## Common frame and authority checks

Each frame carries its own verified instance record/target, exact executing code,
verified ABI view, arguments and handle table. The shared arena owns each object
once, with its original authority, current value and consumed/transferred state.
Frame-local aliases never duplicate the underlying ownership resource.

Before entering any frame, verify exact published code/dependency provenance,
target scope, entrypoint/type binding, allowed input selectors and modes, argument
layout, and global limits. Initializers remain root-only and never execute through
ordinary nested dispatch. The first implementation rejects re-entry of an active
exact (instance, code) target for both same- and different-instance calls; this
is one conservative reentrancy rule, not an instance-special-case rule.

Selected code must be the selected instance's root code or belong to that root's
verified exact dependency closure. A signature cannot pair arbitrary code with an
instance to obtain its scope. Conflicting exact code references for one lineage
inside an invocation are rejected; code revision activation is not inferred.

Before internal mutation, destruction or transfer, require current frame instance
to match object authority, current defining code to match its exact authorized
code, appropriate current handle rights and sender ownership. Transfer also
requires the defining ABI's transferable declaration. Consumption invalidates all
aliases; transfer permanently reduces all aliases to Read, including self-transfer
and subsequent calls using the same authorization. Merely returning from a frame
does not restore rights. Sender-owned Address inputs remain the only admitted
owner kind; Shared/System/Immutable and implicit multi-owner authority stay closed.

Creation stamps the current frame's actual instance/context and defining code,
using the existing centralized creation derivation with one global ordinal.
It must not accidentally stamp root authority on a callee's new object.
`get_instance` returns the current frame record; `get_caller` retains its documented
transaction-sender meaning and is not proof of the immediate calling package.
Existing event bytes carry a scoped type, not an instance provenance proof.

The existing dependency-call ABI is a narrow selector adapter into the same
frame-entry implementation: its target instance is the current frame's instance,
its code is an exact declared dependency, and its handles come from its caller.
It grants no authority absent from the common validation. Do not retain two
independent implementations of mutation checks or nested execution.

## Admission, persistence and bounds

Authenticate and reconcile the exact receipt before any code, policy, instance
or object I/O. For fresh admission, resolve a bounded table of verified scopes
and code closures, and deduplicate original objects into one arena. Every repeated
ObjectId must refer to identical original reference and authority; a conflicting
reference is an error, not an opportunity to pick the latest or widen a mode.

All instance, code, policy, authority and object-head reads participate in the
same fenced atomic read set. Immutable instance records are reads, not a shared
mutable storage root. Child execution never calls the top-level transaction
handler, reserves a second nonce or commits independently. Final effect validation
selects authority/layout from the object's actual admitted scope, not root scope.

Success commits all application effects, nonce and receipt together. Any nested
trap discards every frame's changes and events, committing only the existing
explicit zero-fee rejected receipt/nonce. Request-ID conflict changes nothing;
same-boot and reopened-store replay reapplies nothing. The local outbox remains
absent. All scopes belong to the same trusted atomicity domain and active protocol
version; no distributed transaction or implicit migration is added.

Bounds apply globally, not once per target: at most 8 distinct instances,
33 unique code nodes and 16 MiB of code across all closures, 32 unique initial
objects with the existing aggregate body-read limit, 16 signed call authorizations
within a 64 KiB authorization-table limit. Existing depth 8, calls 64, fuel ceiling
1,000,000, retained memory 64 MiB, cumulative handles 256, creations 128, events
1024 and result 16 MiB remain invocation-wide. Code/layout storage is shared.
Checked arithmetic and charging-before-copying apply to new host inputs too.

## Encoding and activation

Existing accepted canonical bytes and vectors retain their meaning. Additional
signed authorizations require explicit versioned framing and a committed
authorization-enabled host/semantics policy; old signatures cannot authorize new
calls by an omitted-field default. The new host import is general contract
dispatch, not `call_other_instance`. Encoding/host versioning is a capability
activation boundary, not a permanent second execution or authority implementation.

The explicit frames are `0x640B/v1` (instance target, exact code reference),
`0x640C/v1` (original ObjectId, existing canonical access mode), `0x640D/v1`
(ordered object selector list), `0x640E/v1` (caller, callee, entrypoint, type
arguments, selector list), and `0x640F/v1` (ordered authorization table). The two
lists use a u32 count in field 1 and consecutive item fields starting at 2.
Nonempty authorizations add field 4 to `0x6405/v2`, wrapped by `0x6406/v2`;
an empty table retains v1 framing. The signed policy digest still distinguishes
the activated execution policy even when the table is empty. Versions and
unknown fields fail closed; removing or replacing a table invalidates a signature.

Host profile 3 admits the existing typed imports plus the exact five-i32-to-i32
`call_contract` import. Its `0x630B/v3` semantics pins host ABI 2 and execution
rules 2; `0x6409/v2` adds invocation-wide authorization, scope, input and unique
code limits. `0x630A/v3` activates publication separately. Old policy encodings
and keys remain unchanged; the new policy keys are explicitly distinct. A
profile-3 closure may contain exact profile-2/3 code, never nonexecuting profile 1.
Canonical request bytes plus the fixed 54-byte submission framing overhead count
toward the global code-byte bound; shared code is counted and retained once.

Reuse existing instance targets, object authority sidecars, creation derivation,
nonce and receipt structures where their meaning already fits. Allocate new wire
identifiers only after namespace searches and add independent encoding vectors.
Default routes remain closed. The Rust CLI signs and exports the exact bounded
authorization table alongside its invocation, verifies all referenced scopes
against locally expected context, and preserves create-new output and exact-replay
semantics. Do not infer authorization from an HTTP response.

## Required evidence and remaining scope

Use the same generic host and persistence path for calls in one instance and
between independent instances. Demonstrate a real inventory caller consulting
an independently initialized policy contract, passing typed handles with narrowed
rights, creating outputs in their actual scopes, and rolling back both scopes
when the nested program rejects. Include unauthorized caller/target/revision,
wrong scope/code/type, absent or stale object, rights escalation, reuse after
consume/transfer, initializer re-entry, active-target reentrancy and global bounds.
Verify real SQLite close/reopen, fencing, exact success/trap replay, conflict
invariance, CLI/HTTP use, independent vectors and the full repository gate.

Standard Asset and native fee-path replacement follow this generalized model;
no privileged asset exception is added here. Dynamic code upgrades/migrations,
multi-signer authority, arbitrary-created-handle call selectors, return values,
public network admission, UI and production readiness are not claimed here.
