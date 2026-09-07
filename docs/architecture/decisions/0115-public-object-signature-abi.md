# DR-0115: Public object-signature ABI and candidate dependency closure

Accepted: 2026-09-07 (Asia/Singapore).

## Boundary

The public ABI describes package-local constructors and generic object input
signatures without the legacy global constructor registry, AssetId projection,
or publisher-declared host privileges. `abi::public_abi` is unverified data.
`execution::publication::verify_publication_interface` checks those declarations
against an exact graph of DR-0114 authenticated candidates and returns a private
`VerifiedPublicationInterface`. Neither decoding nor this witness grants
construction, mutation, consumption, transfer, instance, or execution authority.

This is an **object-signature ABI**, not a complete value-layout or call ABI.
Schema numbers are equality tokens, not proofs of body encoding compatibility.
WASM business logic, canonical argument/value layouts, runtime generic
substitution, object/owner/instance enforcement, typed cross-contract calls,
fee authorization and durable publication require separate implementation.
Do not claim Move-equivalent static guarantees or expose legacy trusted host
policies based on these declarations.

## Generic signatures and type provenance

An ABI names its defining package origin and strictly ordered package-local
constructor declarations. Each constructor declares a nonzero `u16` local ID,
a nonzero `u32` schema, and an ordered list of argument kinds: nominal type or
opaque identity with a nonzero `u16` domain. Opaque domains have no built-in
asset meaning. A constructor cannot claim another origin: the one ABI origin
scopes all its declarations and must equal the signed artifact origin.

Entrypoints have strictly ordered unique names, an ordered list of generic
argument kinds and ordered object parameters. An object parameter declares
Read, Write or Consume, an exact schema, and a nominal type pattern. These modes
describe requested access only, never entitlement to access an object.

A pattern contains an exact structured origin, constructor and ordered
arguments. Arguments are nested nominal patterns, concrete opaque identities,
or zero-based references to the enclosing entrypoint's generic parameters.
Nesting creates no binder. Parameters cannot appear in constructor declarations;
every reference must fit the entrypoint arity. Repeated parameters are allowed
and preserve equality constraints; neither object parameters nor arguments
are sorted or deduplicated. Runtime substitution must preserve those constraints
and reapply concrete type depth/node bounds before execution.

The verifier resolves every referenced constructor and checks arity, nominal
versus opaque argument kind, opaque domain and root object schema equality.
References may name only self or an explicitly signed direct dependency, not
any package that happens to occur transitively. Nested references obey the same
rule. Copying a constructor number, ABI, or package name cannot establish
another origin's declaration.

## Exact candidate closure, not a published registry

Every input is an unforgeable authenticated candidate, previously checked
against its own trusted original context. Every signed edge must match the
supplied origin, revision, original verification context and full artifact
digest. No latest lookup, current-context rehashing, or caller-provided unsigned
ABI is accepted. Exactly one candidate per origin is permitted across the
entire closure, including the root; multiple revisions of one origin are not
supported. Input order does not affect acceptance.

The supplied set must be exactly the transitive closure reachable from the
root, with no missing or extra candidates, cycles, conflicting references or
cross-chain nodes. Every node's ABI is decoded and verified once; every node's
ABI entrypoint names must exactly match its validated WASM export names.
Diamond dependencies share one checked node. Cached subtree heights still
enforce the longest path bound, not just the first traversal's depth.

Without durable verified publication records, a direct-dependency signature
alone cannot discharge that dependency's own interface obligations. Therefore
this slice checks the bounded closure. A future registry may replace closure
inputs with trusted verified records, while preserving exact historical
commitments and signed direct edges. This witness proves only candidate-graph
consistency: origin absence/reservation, durable existence, freshness, revision
authorization and dependency publication are **not** established here.

## Canonical frames and bounds

All new frames use `CanonicalStruct` version 1; repository search found
`0x5301` through `0x5308` unused in the canonical namespace. Existing wire
encodings are unchanged. Integers are little-endian. Unknown tags, versions,
fields, duplicate/out-of-order fields, noncanonical list ordering, trailing
bytes and malformed fixed lengths are rejected, never normalized.

| ID | Fields |
| --- | --- |
| `0x5301` Package ABI | 1 origin; 2 constructor list; 3 entrypoint list |
| `0x5302` Constructor | 1 local ID `u16`; 2 schema `u32`; 3 kind list |
| `0x5303` Kind | 1 tag `u16`; nominal (1): no more fields; opaque (2): 2 domain `u16` |
| `0x5304` Entrypoint | 1 name; 2 generic kind list; 3 object parameter list |
| `0x5305` Object parameter | 1 Read/Write/Consume tag `u16` (1/2/3); 2 schema `u32`; 3 pattern |
| `0x5306` Pattern | 1 origin; 2 constructor `u16`; 3 argument list |
| `0x5307` Argument | 1 tag `u16`; nominal (1): 2 pattern; opaque (2): 2 domain `u16`, 3 value (32 bytes); parameter (3): 2 index `u16` |
| `0x5308` Ordered list | 1 count `u16`; fields 2 through count+1 items, interpreted by the enclosing field |

Per ABI: 64 KiB, 0–64 constructors, 1–64 entrypoints, 1–256 UTF-8 bytes per
name (reserved `memory` rejected), 0–8 constructor/entrypoint generic arguments,
0–32 object inputs per entrypoint, nominal pattern depth at most 4, and at most
1024 total pattern/argument nodes across the ABI. Shared node budgets apply
before recursion; byte/count limits apply before corresponding decoding and
allocation. Ordered object inputs and generic arguments may repeat.

Per candidate graph: at most 33 nodes including root, path length at most 8
including root and leaf, and at most 256 KiB aggregate ABI bytes checked before
ABI decoding. DR-0114 already bounds each owned artifact to 5 MiB; this verifier
does not copy or rehash its WASM. It retains exact owned candidates and never
loads arbitrary external state. These local checks are not a committed network
admission resource/fee policy, which must precede a public ingress route.

No Standard Asset-only privilege or alternative execution path is added.
`node scripts/public-abi-vector.mjs` independently reconstructs minimal and
generic wire vectors using Node's Buffer framing and SHA-256, without calling
the Rust encoder. The generic vector covers every new frame and variant.
Current completion gates remain in [TODO](../../../TODO.md).
