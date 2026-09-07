# DR-0113: Package-scoped nominal type identity

Accepted: 2026-09-07 (Asia/Singapore).

## Boundary

The generic contract design requires independently published code to be unable
to acquire another package's type authority by copying a constructor number.
The `abi` crate defines the public identity representation separately from its
existing trusted constructor registry. This is a value/codec/commitment layer,
not signature verification, publication, a type registry, or host authority.

`PackageOrigin::unverified` creates a reference consisting of chain ID, an
Ed25519 publisher reference, and a 32-byte creation seed. A zero seed is valid;
the seed is not an execution nonce or proof of freshness. The explicit scheme
field is Ed25519 only. The publisher bytes are not validated as an owning key
by this layer. Publication must validate the key under the committed owner
policy, authenticate the signer and full publication request, and atomically
enforce origin absence before granting authority. Copying another origin's
bytes proves none of those conditions.

Origin equality compares those structured fields, not a hash of them. No
unused standalone lineage digest or hash domain is introduced. Authorized
revisions retain their origin; code revision, instance, schema version,
protocol version, and execution epoch do not redefine a nominal type.

## Type algebra and bounds

`ScopedTypeTag` combines an origin, a nonzero package-local `u16` constructor,
and an ordered list of arguments. Constructor numbers are not globally
allocated object-body identifiers. An argument is either a nested nominal
type or a 32-byte opaque identity with a nonzero `u16` argument-class label.
Opaque labels are interpreted by the consuming type, not global protocol
permissions. Opaque values have no built-in AssetId or Coin interpretation.
Repeated arguments are valid; their order must not be sorted away.

Every nested origin must name the same chain. Bounds apply to constructors,
encoders, and decoders: chain IDs at most 128 UTF-8 bytes, at most 8 arguments
per tag, nominal depth at most 4 (root at depth 1), at most 64 total tag and
argument nodes, and at most 32768 encoded bytes. The nominal argument wrapper
and its nested tag each count as one node. Origin frames are at most 256 bytes.
Decoding checks byte/count/depth/node bounds before corresponding allocations
or recursion, carrying one shared node budget through the whole tree.

## Canonical encoding and hashing

Repository-wide identifier search found these exact canonical IDs unused:

| ID (version 1) | Fields |
| --- | --- |
| `0x5201` PackageOrigin | 1 chain string; 2 scheme `u16 = 1`; 3 publisher bytes (32); 4 creation seed (32) |
| `0x5202` ScopedTypeArg | 1 variant `u16`; nominal (1): 2 nested tag; opaque (2): 2 nonzero domain `u16`, 3 value (32) |
| `0x5203` ScopedTypeTag | 1 origin frame; 2 nonzero constructor `u16`; 3 count `u16`; 4 through 3+count argument frames |

Integers use the shared little-endian canonical field encoding. All fields
are required for the selected shape. Unknown fields, versions, schemes,
variants, malformed lengths, and trailing bytes fail closed.

The whole encoded tag is passed to the existing `hash_type_identity` frame.
Derivation and verification reject a mismatch with the trusted resolver's
chain, including nested origins. They never fold nested digest values into
the logical tag. Historical verification uses the recorded digest algorithm
only if trusted for ObjectType at or before the supplied execution epoch.
Thus two digest values across a permitted hash rotation may verify against
one logical type. The epoch must come from trusted execution context.

## Integration constraints

There is no conversion from the legacy unscoped `TypeTag` or trusted
`ConstructorRegistry` to this public namespace. Neither decoding nor deriving
a digest grants construction, mutation, consumption, transfer, dependency,
instance, or upgrade authority. Future publication and host execution must
bind authenticated lineage and exact authorized revisions to these values.

Existing trusted ABI bytes and execution remain unchanged by this isolated
foundation. Their public-path replacement must remove superseded Standard
Asset-only authority and fee callbacks, not keep a privileged compatibility
bridge. Current completion and integration work belong in [TODO](../../../TODO.md).
