# Verified inactive business import

[DR-0176](decisions/0176-verified-inactive-business-import.md) defines the
storage and authority boundary after the [pre-Seal cut](first-epoch-business-cut.md).
Work status belongs only in [TODO.md](../../TODO.md). Operator steps are in
the [local import guide](../guides/business-import.md).

## Authority and identities

The input is a complete saved cut, not an advertised snapshot root. Core
authenticates the original genesis/history/publication/control material and
privately executes it again under the operator's independent local pins.
`VerifiedImportPlan` is opaque: decoded rows, a cursor, an equality report or
a supplied completion flag cannot construct it.

The binding keeps four different identities separate:

- The semantic cut is independent of source-local physical revisions.
- The exact package fixes the original verifying carriers and saved components.
- The raw plan fixes the privately derived installation inventory.
- The destination has its own namespace, source-instance identity and writer
  fence. Neither the source's token nor its writer is destination authority.

The destination validator identifier is a local namespace selector, not
membership, readiness or activation proof. Import preserves the outgoing
context and authenticated generation floor; it does not admit a successor
generation or silently switch the defining-code/economics epoch.

## Permanent storage origin

| Lifecycle | Durable meaning | Fresh execution and protocol signing |
| --- | --- | --- |
| Ordinary | Explicit normal storage origin, not proof of active membership | Still subject to all existing authority gates |
| FreshImport | Dedicated fresh target bound to exactly one raw plan | Refused |
| Importing | Exact bound inventory with atomic bounded progress | Refused |
| CompleteInactive | Independently compared complete inventory | Refused |

The import origin and binding live in protected durable metadata, not generic
State keys. Mutable progress is subordinate to that origin: deleting a cursor,
phase or completion marker is corruption, never a transition to Ordinary.
There is no import-to-Ordinary or activation transition in this capability.

The common state-store lifecycle read has no default Ordinary implementation.
Concrete stores and forwarding views explicitly implement it with current
domain, fence and deadline validation. A captured read-only source view cannot
invent live admission authority. Normal bootstrap/open and ordinary commits
refuse an import origin; the commit recheck is atomic with the mutation.

Native durable SQLite uses schema version 2 and shared SQL metadata identity
v3. Older initialized durable files are explicitly unsupported, not silently
migrated, repaired or reset. PostgreSQL implements verified Ordinary origin
without import bootstrap. Shared SQL enforcement does not establish a deployed
Durable Objects import host; D1 remains a separately designed adapter.

## Raw installation, not semantic decoding

Comparison subjects are not restoration codecs. Core retains the raw facts
from its independent private reconstruction and validates every owning
key/schema. It restores actual verified Fast/availability carriers through
their owning codecs, not normalized certificate subjects or invented AV rows.

The closed inventory contains State values/tombstones, immutable object
versions, live/deleted heads and exact original receipts, plus their referenced
immutable bodies. It preserves code and instances, nonces/economics, logical
provenance and original ordered/control history. Only exact validated local
signing/reservation/progress/live-consensus-safety facts are excluded. There is
no Standard Asset exception, broad namespace drop or synthetic live ordering tip.

Physical State/head revisions are allocated locally. Object-version physical
creation coordinates are rebased to zero only for this independently verified
first CausalAdmission epoch/inactive profile; logical generations, immutable
contents/versions and signed/hash-linked checkpoint operands stay intact.

## Atomic bounded progress

Verified bodies are installed before references, immutable versions before
heads and original receipts after their material. `InactiveImportRepository`
is a separate storage-only seam, not an ordinary transaction bypass or proof
of cryptographic business validity.

One transaction admits at most 128 rows and 64 MiB represented bytes, retaining
the legal 32 MiB body bound. The invocation limit counts new batches, not total
history or reverification cost. Binding, current fence/deadline and expected
progress are checked together; absent rows are inserted and exact retries are
compared without overwriting conflicts. The same transaction advances progress.

An indeterminate acknowledgement requires fresh fenced reconciliation of exact
batch identity and contents. A claimed cursor or successful blind retry cannot
advance authority. Before completion, core fully enumerates destination rows
and referenced bodies and compares them with the private plan. Finish checks
the verified snapshot token and exact complete progress atomically.

## Replay and live guards

Exact original business replay reconciles its receipt first under the current
destination fence, returning the original response without execution or outbox
work. Fresh business paths then check lifecycle before engines or reservations.
Protocol signing and cached votes/ACKs are not this replay exemption.

Fast prepare/retain/apply, frontier/drain streams, epoch votes, ordered proposal/
tick/recovery, genesis initialization and activation must refuse import-origin
authority before exposing signatures or doing live work. Historical read-only
inspection remains separate. Storage-level refusal is an atomic backstop,
not a replacement for the entry-specific pre-signature guards.

Completion is therefore safe installation evidence only. Readiness, Seal,
activation, next-set serving and independent security audit remain different
authorities and acceptance gates.
