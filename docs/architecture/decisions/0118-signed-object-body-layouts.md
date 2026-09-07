# DR-0118: Signed constructor body layouts

Accepted: 2026-09-07 (Asia/Singapore).

## Decision

Every constructor declares a canonical body layout in its signed code artifact.
The layout is selected by exact defining package origin and constructor, not
by the caller or by a global asset/type table. The constructor declaration
remains the sole source of its schema version. Dependency-defined object bodies
use the exact dependency ABI retained by interface verification.

The bounded DR-0117 value grammar is reused for object data, without new body
codecs or asset-specific projections. Generic type arguments distinguish nominal
identity but do not alter the constructor's body representation in this profile.
There is no type-variable-dependent inline body substitution: typed objects
remain separate handles, not arbitrary inline values embedded through a generic
parameter. A Coin-like constructor may carry an opaque asset type argument and
an ordinary U64 value; arithmetic and conservation remain contract semantics.

## Wire profile

`CallAbi` frame `0x5405` version **2** has exactly three required fields:

1. Unchanged `PackageAbi` bytes, including ordered constructors and entrypoints.
2. `0x5402` version-1 list of argument layouts, paired with entrypoints.
3. `0x5402` version-1 list of body layouts, paired with constructors.

Both list lengths must match exactly. Constructor order is the existing strict
ascending local ID order. The 256-layout-node budget is shared across both
lists, including unused constructor declarations. The entire envelope, not
each half separately, must fit 65536 bytes. Existing layout/value frame IDs,
versions and bytes are unchanged.

Only version 2 is accepted by active candidate interface verification. The
unreleased version-1 envelope is rejected, with no synthesized body layout or
legacy execution fallback. Historical version-1 vector evidence is preserved;
the active version-2 envelope gets an independent fixed vector. There is still
no durable public registry requiring migration. Standalone PackageAbi and
Transaction/Object/receipt bytes are unchanged.

## Representation validation boundary

`validate_object_input_bodies` first bounds the supplied input count and total
body bytes, then performs all existing metadata checks (ordered access, unique
object IDs, ID/version, type and schema), then decodes each body against the
layout retained in the verified defining ABI. It accepts no replacement schema.

Each object retains the value codec's 65536-byte, depth-8 and 1024-node limits;
the invocation accepts at most 32 objects and 256 KiB of aggregate body bytes.
This bounds work across inputs as well as inside each object. Validation returns
unit and grants no executable capability. The metadata-only helper remains
explicitly metadata-only.

This is representation checking, not verification of ObjectRef digest, trusted
storage provenance, current state, ownership, call signature, instance/revision
authority or application invariants. Valid body bytes can still represent an
unauthorized state. No engine or persistence path treats this result as
admission. Those obligations remain explicit in [TODO](../../../TODO.md).
