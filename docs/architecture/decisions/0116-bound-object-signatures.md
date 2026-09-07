# DR-0116: Bound object signatures and input metadata matching

Accepted: 2026-09-07 (Asia/Singapore).

## Boundary

`bind_object_signature` specializes a DR-0115 verified interface with concrete
DR-0113 type arguments. The resulting private `BoundObjectSignature` borrows
that exact interface and contains concrete ordered object type/schema/access
expectations. It is not an executable capability. No engine, durable registry,
or public route accepts it as admission authority.

`match_object_input_metadata` compares those expectations with a supplied
access manifest and resolved object slice. Its return value is only `Result<()>`.
It does **not** authenticate the transaction, manifest or state snapshot;
verify `ObjectRef.digest`; validate owner, instance, revision authority or
object body layout; or authorize host operations. An unchanged type/schema
with a different owner/body may still match, as the tests explicitly show.
The caller must separately verify canonical object bytes against the signed
reference and trusted persisted state, then enforce owner/instance/defining-code
authority before executing anything. Metadata matching must never replace that
admission sequence.

## Binding

Entrypoint lookup is exact and bounded. Every supplied type argument, including
an unused argument, must match its declared nominal/opaque kind and opaque
domain. Concrete nominal arguments resolve every nested constructor against
the retained verified ABIs. Only self and signed **direct** root dependencies
are visible, including inside supplied generic arguments; the transitive
closure is not ambient type authority. Unknown constructors, wrong arity and
wrong domains fail closed. This restricted generic argument scope can be
expanded only alongside an explicit verified call-dependency design.

Substitution uses one flat entrypoint parameter list at every nesting level.
Repeated parameters retain identical values and argument/input order is
preserved. Expanded tags must satisfy DR-0113 bounds, not merely the bounds of
each argument before substitution: nominal depth 4, total tag/argument nodes
64 per output tag, at most 8 arguments per tag and at most 32768 encoded bytes.
A substituted subtree is charged at its new depth before cloning. The total
encoded output tag budget is 256 KiB; at most 32 object parameters are produced.
No scalar argument or canonical value-layout ABI is introduced in this slice.

The interface retains already verified dependency declarations; binding does
not accept a caller-supplied declaration registry, re-decode unsigned ABI, or
clone stored WASM. The bound signature's lifetime keeps the verified interface
alive, and the entrypoint name is borrowed from that interface, not the request.

## Metadata matching

Counts must match exactly before iteration. Each ordered manifest entry must
match the corresponding resolved object's ID/version and requested mode, and
the mode must equal the bound ABI mode. Duplicate IDs are rejected even for
multiple reads; there is no sorting, deduplication or implicit mutable alias.
Schema comparison is exact equality.

The object type commitment is verified against the expanded logical tag using
`verify_scoped_type_id` and a separately trusted resolver/current epoch. The
resolver chain must equal the interface chain. Publication protocol/epoch is
not substituted for current execution context, nor does an upgrade redefine
nominal identity. A historical digest algorithm is accepted only if trusted
for ObjectType by the supplied epoch; future or unsupported algorithms fail.
This comparison neither authenticates package publication nor proves that a
stored body actually satisfies that type's representation.

No new canonical frame, ID, hash domain, signature payload, transaction format,
or object encoding is added. No Standard Asset-specific policy, old global
constructor bridge, or native balance logic is introduced. Rust client users
can access both `public_abi` and `package_types` to construct these values.
Status and remaining execution/admission gates are in [TODO](../../../TODO.md).
