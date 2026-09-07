# DR-0117: Signed argument layouts and canonical call values

Accepted: 2026-09-07 (Asia/Singapore).

The version-1 envelope below is historical. [DR-0118](0118-signed-object-body-layouts.md)
supersedes its active admission profile with mandatory constructor bodies in
version 2; the value/layout encodings specified here remain unchanged.

## Explicit call ABI, no object-only fallback

Public candidate interface verification now requires a `CallAbi` envelope:
the unchanged DR-0115 object-signature ABI and exactly one argument layout
for every entrypoint, in the same order. The object ABI remains the sole
declaration of entrypoint names/order; the envelope does not duplicate names.
Both the root and every dependency must supply a valid envelope. There is no
implicit empty-argument layout or fallback to the former object-only format.

This intentionally changes the **unreleased candidate admission profile**.
Previously signed object-only candidates can still authenticate their exact
opaque artifact bytes, but cannot pass interface verification. No durable
published registry or public publication route exists to migrate. Standalone
`PackageAbi` codecs and their stable vectors remain unchanged; this is not a
claim that old candidates remain interface-compatible. A separate envelope
uses new frame IDs without changing historical bytes or adding an active
legacy public execution path.

The entire envelope is inside `CodeArtifact.unverified_abi`, covered by the
existing full-artifact commitment and publisher signature. Interface
verification retains the checked layouts from those exact bytes. A bound
signature borrows its selected entrypoint's layout from the verified interface.
`validate_call_arguments` takes the bound signature and bytes, **not a schema
chosen by the caller**, and returns `Result<()>`. Rust callers can encode
values using `encode_call_value` and the read-only bound layout.

## Value grammar

The layouts are Bool, unsigned 64/128-bit integers, bounded bytes, bounded
UTF-8 strings, ordered heterogeneous tuples, and bounded homogeneous lists.
Tuple positions are stable field identities; names are SDK/UI concerns.
Bytes declare a minimum and maximum length, allowing an exact-size byte field
without introducing an address or object-reference authority type. UTF-8
limits count bytes, not characters. No normalization is performed.

There are no floats, coercions, maps with unspecified ordering, object handles,
ownership/reference variants, arbitrary custom validators, or asset-specific
projections in the grammar. A byte array resembling an address confers no
authority. A function with no arguments declares `Tuple([])` explicitly and
requires its canonical value encoding; zero bytes are not that encoding.
One root layout describes the argument value; ordinary positional arguments
use a tuple of at most 32 fields.

All scalars use exact fixed widths: Bool is a `u16` equal to 0 or 1, U64 is
8 bytes, U128 is 16 bytes, and integers are little-endian. Bytes have no text
interpretation. Strings must be well-formed UTF-8 with no normalization;
canonically encoded distinct strings remain distinct. Tuples have exact field
count/order and lists validate every element against their one element layout.

## Bounds and canonical frames

Every layout/value/envelope is at most 65536 encoded bytes, including framing.
Layout depth is at most 8 and at most 256 layout nodes are accepted. In a
`CallAbi`, that node budget is shared across **all** entrypoint layouts.
Tuples have at most 32 fields; list maxima are at most 256. Byte limits and
UTF-8 limits cannot exceed 65536; byte minimum cannot exceed maximum.

Value depth is at most 8 with at most 1024 value nodes across all siblings.
Aggregate byte/string payload copying and the outer encoded value each have a
65536-byte cap. A layout permitting a 65536-byte leaf does not waive the outer
framing budget. Limits are checked before corresponding allocation/recursion;
an invalid layout is rejected even when its list value would be empty.

All frames use `CanonicalStruct` version 1. Repository search found these IDs
unused. Unknown fields, variants, versions, wrong widths, duplicate/out-of-order
fields, count/field disagreement, malformed UTF-8 and trailing bytes fail
closed. All fields listed for a selected shape are required.

| ID | Fields |
| --- | --- |
| `0x5401` Layout | 1 kind `u16` (Bool1, U642, U1283, Bytes4, Utf85, Tuple6, List7); primitives: no more fields; Bytes: 2 min `u32`, 3 max `u32`; Utf8: 2 max bytes `u32`; Tuple: 2 layout list; List: 2 max count `u16`, 3 element layout |
| `0x5402` Layout list | 1 count `u16`; fields 2 through count+1 layout frames |
| `0x5403` Value | 1 same kind `u16`; 2 scalar payload or tuple/list value-list frame |
| `0x5404` Value list | 1 count `u16`; fields 2 through count+1 value frames |
| `0x5405` Call ABI | 1 unchanged `PackageAbi` frame; 2 positional argument-layout list |

The outer envelope retains the existing 64 KiB artifact ABI budget. The
candidate graph retains its existing node/path/aggregate-ABI bounds. No new
hash domain, signature message family, Transaction/Object/receipt encoding,
or protocol cryptographic primitive is introduced.

## Non-claims and remaining admission boundary

Canonical argument validation checks only declared representation and resource
bounds. It does not authenticate a call transaction or persisted object, verify
an object-reference digest or body layout, authorize ownership/instances/host
effects, reserve a package, execute WASM, or prove application business logic.
No engine, route or store accepts this result as admission authority. Standard
Asset receives no special treatment. Object body layouts and authenticated
call/admission/persistence remain separate gates in [TODO](../../../TODO.md).
