# DR-0114: Authenticated publication candidates

Accepted: 2026-09-07 (Asia/Singapore).

## Authentication is not admission

`execution::publication` binds immutable artifact data and verifies the initial
publisher's signature. Its terminal result is an
`AuthenticatedPublicationCandidate`, not a published package or permission to
execute. No node route, registry, dependency resolver, durable store, or engine
entrypoint accepts that witness. It has no public constructor or decoder.

The candidate establishes exactly that the canonical, non-identity,
prime-order Ed25519 publisher key signed the exact artifact and nonce in the
trusted expected context, and that the WASM matches structural admission
profile 1. It establishes neither freshness nor ownership of a reserved
package origin. Signature verification precedes WASM translation.

ABI declarations are opaque, nonempty byte strings named `unverified_abi`.
They are bound exactly, not parsed or validated as a typed ABI. Exact
dependency claims are named `UnverifiedDependencyRef`: their existence,
historical commitments, lineage provenance, and authorized revisions are not
resolved here. This avoids embedding the legacy global-constructor and
AssetId-specific ABI into the public contract format merely to obtain a
signature container. Those obligations must be discharged before any record
becomes published or executable. Even a well-signed invalid ABI remains only
an authenticated candidate, never an admitted contract.

## Immutable data and exact context

`CodeArtifact` contains original chain/protocol/epoch context, structured
package origin, revision (initial creation only: exactly 1), WASM admission
profile (exactly 1), expected execution-semantics commitment, exact WASM and
ABI bytes, export names, and exact dependency references. Export names are
strictly sorted and unique. Dependencies are strictly sorted by structured
origin, with one reference per origin; self-dependencies are rejected. All
referenced chains must match. Revision zero is invalid for a dependency;
other revision numbers remain unverified claims, not upgrade support.

Each dependency retains its exact origin, revision, artifact digest, and
original verification context. Neither `latest` nor current-context rehashing
can replace a signed reference. Artifact equality and references do not
implicitly compare only WASM bytes.

The resolver and expected chain/protocol/epoch are trusted caller inputs,
never reconstructed from the request. Authentication requires an exact match,
then recomputes the artifact digest with the resolver's active `ContractCode`
algorithm for that epoch. Comparing the full self-describing digest prevents
per-request algorithm selection. The semantics digest must equal a separately
supplied trusted expectation; that equality alone does not implement or
authorize those semantics.

Historical verification must supply the trusted original context and its
resolver/history. A record cannot select its own verification epoch to make
a future algorithm appear active, nor may an old artifact be reinterpreted
under a current protocol version. The original context is part of the
artifact bytes as well as the central hash/signature frames.

## Canonical frames and signature

All frames use `CanonicalStruct` version 1 and reject unknown fields,
versions, malformed fixed lengths, duplicate/out-of-order fields, and
trailing bytes. Repository search found these exact IDs unused:

| ID | Fields |
| --- | --- |
| `0x6301` Context | 1 chain string; 2 protocol `u32`; 3 epoch `u64` |
| `0x6302` UnverifiedDependencyRef | 1 origin; 2 revision `u64`; 3 context; 4 digest |
| `0x6303` CodeArtifact | 1 context; 2 origin; 3 revision `u64`; 4 WASM profile `u32`; 5 semantics digest; 6 WASM; 7 unverified ABI bytes; 8 export list; 9 dependency list |
| `0x6304` Export list | 1 count `u16`; 2 through count+1 names |
| `0x6305` Dependency list | 1 count `u16`; 2 through count+1 references |
| `0x6306` Unverified request | 1 artifact; 2 nonce `u64`; 3 artifact digest; 4 signature (64 bytes) |
| `0x6307` Signing payload | 1 context; 2 origin; 3 revision `u64`; 4 nonce `u64`; 5 recomputed artifact digest; 6 scheme `u16 = 1` |

Nested digests and origins use the shared existing encoders. Integers are
little-endian. The entire artifact, not just its WASM, is hashed under
`HashPurpose::ContractCode`. The signing payload uses central signature
framing with message family `CreatePackage`, Ed25519, and exact expected
chain/protocol/epoch. No new cryptographic primitive or hash domain is added.
Nonce and package creation seed are distinct. Authentication does not consume
the nonce or prove the origin absent; duplicate requests can authenticate
again, but must never execute twice once durable admission is implemented.

## Bounds and integration obligations

Bounds are 5 MiB per artifact/request, 4 MiB WASM, 64 KiB opaque ABI bytes,
1–64 export names of 1–256 UTF-8 bytes, and 0–32 dependency references. Context
frames are at most 256 bytes, chain IDs at most 128 bytes, and dependency
frames at most 1024 bytes. List counts and byte budgets are checked before
corresponding copying or allocation. The outer byte budget is a defensive
decode limit; field bounds constrain valid encodings more tightly.

Before wiring any network publication path, commit the allowed semantics,
typed ABI/host authority rules, dependency verification policy, deterministic
admission resource budget/charging, and ingress workload limits. Atomically
enforce origin absence, nonce/receipt replay and request-ID conflicts, code
and authority publication, and outbox persistence in the same fenced domain.
Authentication or structural WASM validation alone cannot bypass that gate.

No Standard Asset exception, legacy ABI bridge, or replacement execution path
is introduced here. Existing Transaction/Object/receipt bytes are unchanged.
Status and remaining work live in [TODO](../../../TODO.md).
