# DR-0119: ABI-bound durable object snapshots

Accepted: 2026-09-07 (Asia/Singapore).

## Reuse the existing integrity boundary

The durable object loader's storage-integrity portion is shared between the
existing authenticated submission path and generic ABI-bound input reads.
It is extracted, not reimplemented with a second hash/provenance policy.
No canonical bytes, signature frames, hash domains or persisted layouts change.

For each declared reference the shared loader checks, in order:

- A current head exists and matches the declared version and full digest.
- Its immutable version record matches ID, version and digest.
- Stored provenance names the trusted chain, before any blob fetch.
- Blob bytes are bounded, independently verified by their content digest,
  then strictly decoded. Inline canonical bytes use the same integrity path.
- Decoded ID/version/schema agree with the record and reference.
- The record digest verifies over exact canonical bytes using the record's
  original chain/protocol version and its self-described hash algorithm.
- The current head's owner projection agrees with the decoded owner.

The reader's active epoch hash suite is not used to rehash historical records.
Unsupported digest algorithms fail closed. Existing canonical-body bounds
(1 MiB per object, 8 MiB aggregate) still precede hashing/decode; each payload
is counted once. Blob stores may allocate during fetch, so these are node-side
post-fetch work limits, not a promise of bounded allocation inside an adapter.

## ABI-bound read composition

`load_bound_object_snapshots` accepts an already-bound interface signature and
an ordered access manifest. Before storage I/O it checks the exact count,
32-object limit, duplicate IDs and chain agreement with the trusted resolver.
It loads through the shared integrity boundary, then applies the DR-0118
metadata and signed constructor-body checks. The value-data bounds (64 KiB
per object, 256 KiB aggregate) additionally constrain the accepted result;
the larger existing canonical-record bounds constrain earlier loading work.

The returned objects and exact `DurableObjectHeadRead` observations preserve
manifest order. Reading is not reserving: heads may change immediately after
observation, and a multi-object read is not an atomic snapshot. The eventual
fenced transaction must include every returned head assertion and atomically
reject a stale observation. This read helper neither commits nor certifies
that a future commit will succeed.

## Authorization stays separate

Integrity is not permission. The generic read helper does not authenticate the
manifest/call signature, nonce, durable publication, revision or instance,
authorize an owner, grant defining-code mutation rights or prove application
invariants. It may read a System/Shared/Immutable object whose representation
is valid; this never authorizes a Write or execution over that object.
Its output is not accepted as an executable or host capability.

The existing submission path retains its owner checks and narrow trusted
preinstalled policies after the common loader. Those exceptions are not
available to the generic helper and are not promoted to public authority.
No public request route or new transaction executor is activated here.

The domain, operation context and resolver are trusted composition inputs,
not placement authority supplied by a request. A future generic submission
composition must reconcile exact receipt/nonce replay **before** invoking this
loader, authenticate the call and publication/instance authority, then commit
all head assertions, effects, receipt and nonce atomically. Existing submission
replay-before-object-I/O ordering is unchanged. Remaining gates live in TODO.
