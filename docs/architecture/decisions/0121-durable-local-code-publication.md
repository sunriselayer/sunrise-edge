# DR-0121: durable local code publication

Accepted: 2026-09-07 (Asia/Singapore).

## One usable operation, not another candidate witness

The local devnet can explicitly enable authenticated, immutable code
publication and verified readback. This composes the existing WASM and signed
ABI verifier with durable admission, native HTTP, the Rust client and CLI.
It does not instantiate or execute the published code, authorize object
operations, install it in the trusted Standard Asset catalog, or claim
network-wide agreement. Publication is fee-free local storage admission;
operators must not expose this development endpoint publicly.

## Authentication and wire boundaries

One Ed25519 signature binds the request ID, trusted chain/protocol/epoch,
publisher origin, revision, nonce and artifact commitment. The latter binds
WASM, ABI, manifest, exact dependencies and validation semantics. The central
signature domain is `CreatePackageSubmission`. A signature over the older
bare `CreatePackage` candidate cannot authorize this ingress. The old encoder
is not a live fallback. Successful authentication performs no storage I/O
and grants neither freshness nor execution authority.

New CanonicalStruct frames use version 1, exact required fields,
little-endian integers, bounded input and rejection of unknown/trailing data:

| Frame | Ordered fields |
| --- | --- |
| `0x6308` submission | 1: nonzero request ID bytes32; 2: existing publication request, whose signature uses the new submission domain |
| `0x6309` signing payload | 1: request ID bytes32; 2: publication context; 3: package origin; 4: revision u64; 5: nonce u64; 6: artifact Digest32; 7: Ed25519 scheme u16 |
| `0x630A` committed local policy | 1: context; 2: semantics Digest32; 3: local mode u16=1; 4: maximum closure nodes u32; 5: maximum closure bytes u64 |
| `0x630B` local profile descriptor | 1: `local-devnet-publication-only`; 2: WASM admission profile u32; 3: local admission rules u32=1; 4: maximum closure nodes u32; 5: maximum closure bytes u64 |

The profile descriptor is hashed with `ContractCode` under trusted context.
Its rules version is not an ABI encoding version. It describes non-executing
publication admission, not a promise of executable VM semantics. Execution
admission must separately establish the supported semantics and authority.

Submission bytes are capped at 5 MiB + 128 bytes; existing inner artifact,
WASM, ABI and manifest limits still apply. The full dependency closure is
capped at 33 nodes including the root and 16 MiB of stored submissions.
Explicit trusted resolver history is capped at 16 entries. No history or
hash schedule is synthesized from an untrusted artifact or HTTP response.

## Atomic admission and provenance

After authentication, reconcile the typed durable request receipt before
reading publication policy, code dependencies, objects or sender nonce.
Exact replay returns the original response without reapplication. A different
authenticated submission using the same request ID fails as request-ID reuse.
The receipt digest uses the existing `NodeEvent` hash purpose over the unique
canonical submission frame; no synthetic `SubmitTransaction` is constructed.

Fresh admission uses the same sender/epoch nonce namespace as transactions.
It requires the locally expected policy to equal the committed policy, and
requires a never-used origin (absent value and initial storage revision).
A tombstone is not origin absence. The origin record key is independent of
protocol version and code revision, preventing a new protocol from creating
the same lineage again. This profile admits initial revision 1 only.

Each dependency must resolve to its exact committed origin, revision,
original context and artifact digest. Authenticate its stored signature,
matching successful durable receipt and original committed policy, then
verify the complete signed ABI closure. A copied ABI or unsigned local
catalog entry cannot establish defining-code provenance. Older contexts
require explicitly supplied trusted resolver history; unavailable history
fails closed.

One existing fenced invocation commit asserts every policy, dependency,
origin-absence and nonce read and atomically writes the immutable submission,
next shared nonce and typed request receipt. The response is exactly one
`Accepted` containing the canonical exact code reference. Object changes are
empty. The outbox is explicitly `None`: there is no invented peer publication
event, and no claim of certificate or distributed publication atomicity.
Definite rejection and indeterminate commit outcomes remain distinct; after
uncertainty, replay the same signed bytes and request ID.

Records live under reserved `se/publications/v1/` generic durable-state keys,
not a second database or SQLite schema. Generic state-machine plans cannot
write this namespace. Context-keyed policy records retain original validation
policy. Bootstrapping is trusted composition, rejects tombstones and changed
policy bytes, and uses the existing fenced atomic state store.

## Product boundary

Only `--enable-local-publication` installs the local policy and enables
`POST /v1/contracts/publications` and
`GET /v1/contracts/publications/{publisher}/{origin_seed}`. Default routes and
non-submit event-family authorization remain unchanged. The publication body
limit is path-specific; existing event limits are not raised. Native ingress
retains bounded admission, deadlines and writer fencing.

The CLI uses software development keys; Ledger publication signing is rejected
before device or network work. It verifies endpoint TLS independently from
the locally configured expected protocol context before signing. Explicit
`--nonce` reconstructs exact replay; omitting it queries the shared nonce.
Query authenticates publisher bytes and the exact selected origin. This is
not a cryptographic proof of inclusion or absence. Historical client readback
accepts a separately trusted original context; the local CLI uses its current
fixed profile and does not guess historical configuration.

See the [devnet guide](../../guides/devnet.md) for operator commands and
[`TODO.md`](../../../TODO.md) for remaining functional gates. No code
publication grants instance, type, owner, fee or execution privileges.

## Verification evidence

Rust tests cover strict submission/signature binding, missing and copied
dependencies, origin/policy tombstones, policy CAS races, receipt provenance,
historical context, shared nonce and indeterminate-result reconciliation.
The real SQLite test compares both complete code submissions, both canonical
receipts and the nonce record before and after same-boot/restart replay and
signed request-ID conflicts. Persisted writer generation advancement rejects
old reads, writes and publication after reopening. The HTTP/CLI E2E publishes
a dependency and dependent artifact, closes/reopens the file-backed database,
replays them, and verifies that a subsequent boot without opt-in closes ingress.
Client tests reject false acknowledgements and changed selected code/context.

`scripts/publication-submission-vectors.mjs` independently reconstructs all four
new frames and the exact Ed25519 signature without a Rust encoder. Rust pins
matching lengths and hashes, and the script is part of `check-all.sh`.
