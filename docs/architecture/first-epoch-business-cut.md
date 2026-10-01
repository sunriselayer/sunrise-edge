# First-epoch pre-Seal business cut

[DR-0175](decisions/0175-first-epoch-preseal-business-cut.md) defines this
bounded export and independent saved-verification capability. It depends on
[causal reconstruction](business-reconstruction.md), including the legitimate
frozen member completion in
[DR-0174](decisions/0174-frozen-member-business-reconstruction.md).
The wider [epoch handoff](epoch-handoff.md) retains separate persistent import,
readiness, Seal and activation authority. Current status belongs only in
[TODO.md](../../TODO.md); executable local steps are in the
[operator guide](../guides/business-cut.md).

## What a verified candidate means

An opaque `VerifiedBusinessCut` can be constructed only by private execution
under the caller's locally verified signed genesis, hash schedule, context,
committee and atomicity domain. Decoded identities, public application hints,
progress files and an equality-report boolean cannot construct it.

The predecessor is the pinned genesis of the first outgoing CausalAdmission
epoch. Advanced epochs and other profiles are refused: they require a separately
verified predecessor/activation chain, not a caller-supplied prior root.

Private reconstruction repeats the authenticated contiguous ordered prefix
and actual Owned executions. Freeze and DrainSet must be genuinely accepted by
their owning executor. Every selected signed frontier is verified from its
seed to its terminal count/digest, with full publication artifact closure.
The deduplicated committed union must agree exactly. Every union member must
have its independently executed complete original outcome, and every applied
Owned original must belong to that union. Retention, readiness, an aggregate
count or an empty history tip is not business completion.

The fixed target requires an authenticated candidate-free terminal three-chain:
the target, its child and its grandchild each carry no candidate digest. This
is not the complete live high/locked suffix predicate required by Seal. New
justified progress may require a corrected pre-Seal candidate. Export neither
installs a first-writer-wins target nor proves latest network state.

For a real source, all four collections and referenced bodies are captured
under one backend-enforced token. Independent expected-state equality and a
final token/outbox check are mandatory. File export rechecks the same token
before publishing completion. No source fence is claimed or advanced.

## Semantic identity and exact package are different

The semantic identity binds the verified genesis predecessor, outgoing context,
committee/domain, committed DrainSet, fixed ordered target, four business
collection counts/roots, semantic artifact closure and execution-generation
floor. It does not bind a source namespace, local sequence, writer fence or
arbitrary equivalent certificate signer subset.

The exact package binds the semantic identity and every immutable component's
closed descriptor, length and digest. Its terminal accumulator is not its own
component. A different valid proof subset may produce a different exact package
without changing the independently derived semantic business identity.
Saved continuation pins both identities and additionally the source-local
token for a source export. No token is cross-validator consensus authority.

Use the committed HashSuite and canonical NodeEvent-purpose frames. Collection
seeds bind explicit genesis/context/domain and collection, never the final
cut digest. Neither Seal nor future activation is included in its own cut.

## Closed transfer streams

| Stream | Meaning |
| --- | --- |
| State | Application/code/instance/object authority, nonces, economics and non-control logical provenance |
| Receipts | Exact original Owned and Ordered business receipts |
| ObjectHeads | Current live or tombstoned heads, without physical CAS revisions |
| ObjectVersions | Every immutable version/deletion with authenticated provenance and exact payload |
| AuthorityCompanions | Exact ordered candidate/header/outcome/archive/applied-height facts, current Freeze/DrainSet and their subject-specific provenance/original control receipts |
| Artifacts | Exact referenced semantic body closure, separate from small descriptors |
| Proofs | Original verifying publication, availability, ordered and selected-frontier material needed to repeat independent execution |

The final three streams are not ordinary rows that an importer may blindly
restore. Comparison-normalized Fast/availability certificate subjects are not
restorable certificates. Keep the original verified proof carriers separately.
Original Freeze/DrainSet receipts are not synthetic bookkeeping; companion
placement preserves exact verification and existing audit equality.

Partition only after the existing field-aware projection has validated each
owner/key/schema. Derive companion keys from the independently verified
history/control identities and their owning key builders. Never discard an
entire familiar namespace or accept an unknown key as a companion by prefix.

Only explicitly recognized local reservation/signing/progress/physical facts
retain the existing audit exclusions. Normalize the initial genesis
installation coordinate through the existing pin-verified rule, not later
signed or hash-linked checkpoints. Tombstones are not absence. All logical
provenance stays verified even when its exact control subject belongs in
companions rather than State.

The floor is the maximum of the verified genesis floor, every independently
applied Owned witness generation and every independently produced provenance
generation, including deleted subjects and control/history companions.
Unapplied prepares, unselected retention and source-advertised maxima contribute
no authority. The floor is not its later checked successor or a backend counter;
export does not authorize admission using it.

## Bounded transport and independent verification

A descriptor is at most 16 KiB. A canonical page contains at most 128 descriptors
and 4 MiB. Payload chunks contain at most 1 MiB; their encoded frames also carry
bounded descriptor/header overhead. Large legal bodies are never nested in a
descriptor or whole-history superframe. Original bodies retain their owning
legal size bounds; there is no arbitrary total-history ceiling.

Pages pin the semantic cut and exact package, collection, previous accumulator,
ordered key range and terminal status. Chunks pin the same identities, exact
descriptor, offset and total length. Every stream, including an empty one,
needs its verified terminal. Omission, surplus, reordering, duplication,
substitution, foreign identities and incomplete/truncated bodies refuse.

Operator work limits bound newly saved chunks/components per invocation to
one through 4,096. Already saved files are immutable and reverified; resumption
does not trust a saved cursor or completion marker. Changed source observation
requires a new archive, not deletion of pins or forced continuation.

Offline saved verification needs the original local pins but no source DB or
signing key. It authenticates all original proof material, privately repeats
reconstruction and complete drain, rederives the candidate and compares every
complete semantic and exact package stream. File hashes and a supplied root
alone never establish execution correctness.

## Authority and provider limits

There is no incoming-state installation, inactive-validator mutation permit,
readiness signature, transition vote, Seal-ready permit, force unlock or active
serving capability here. A source restart/fence change invalidates that saved
observation; genuine restart/replay tests do not grant epoch activation.

Persistence is the runtime capability contract. SQLite source composition and
PostgreSQL operational acceptance are distinct; neither requires the other to
derive or verify a cut. No D1 implementation or deployed provider qualification
is implied. Standard Asset uses ordinary generic contract execution, without
an asset-specific admission or projection exception.
