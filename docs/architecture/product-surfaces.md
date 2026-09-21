# Developer product surfaces

This document defines the local devnet, query API, Rust client, CLI, and
hardware-signing host boundaries.

The opt-in public-code product boundaries are defined separately in
[DR-0121](decisions/0121-durable-local-code-publication.md) (non-executing
publication) and [DR-0122](decisions/0122-local-instance-execution.md) (typed
local instances and execution). `--enable-local-execution` installs the exact
executable publication/execution policy pair and enables matching router and
pre-parser capabilities. Defaults stay closed; the shared sender nonce and
fenced SQLite transaction are unchanged. The [devnet guide](../guides/devnet.md#optional-generic-contract-surfaces)
lists the current opt-in flag surface; the execution and security model for
these generic-contract capabilities is defined in
[`docs/smartcontract/`](../smartcontract/).

[DR-0123](decisions/0123-unified-contract-calls.md) adds the explicit
`--enable-general-calls` opt-in. Boot installs its publication/execution pair in
one additional fenced operation with a reserved correlation sequence; historical
policy rows are not replaced. The same HTTP execution route selects only an exact
digest in its locally configured, at-most-two-profile registry. Untrusted request
claims never construct a policy. CLI `--general-calls` selects this explicit
zero-fee policy, with an optional canonical `--authorizations` file binding
caller/callee targets and object ceilings. A shared bounded code cache enforces
the invocation-wide limit before another code fetch and reuses overlapping
closures. All queried instance revisions/digests must match the signed pins
before signing; TLS and protocol-context verification remain separate checks.

[DR-0126](decisions/0126-public-paid-contract-activation.md) and
[DR-0127](decisions/0127-public-standard-asset-cli-migration.md) activate the
mandatory paid contract path on the local devnet, installing the public
Standard Asset package and paid fee policy at genesis and routing the five
asset CLI verbs through ordinary signed paid calls.

## 42. Local devnet architecture

[DR-0081](decisions/0081-0087-cli-first-roadmap.md) fixed the local devnet's architecture ahead of its implementation so
the client/app work that depends on it can target a stable contract. The
devnet composes the existing `preinstalled_wasm_structured_durable_router`
around a dedicated startup binary in `apps/devnet` rather than introducing new
protocol behavior:

- **Strict loopback startup.** The devnet binds only a loopback address
  (`127.0.0.1`/`::1`); it never binds a non-loopback interface, and
  bundles no TLS termination, authentication, or public-exposure hardening.
  This is a local developer fixture, not a hosted network.
- **Persisted fence/boot generation.** After `SqliteDurableStore::open`
  completes its existing schema/namespace bootstrap and verification, startup
  reads the persisted writer fence through a new additive operator-only
  accessor, advances that exact value with checked arithmetic, and uses the
  result as that process's boot generation and `created_checkpoint`. It never
  invents an in-memory substitute for missing or invalid durable metadata.
  The implemented accessor and startup flow make boot generations
  non-decreasing across restarts
  and fences stale request contexts from a prior process.
- **SQLite structured store.** State, object, receipt, and outbox data use the
  additive, local-only, non-production `SqliteDurableStore`
  ([DR-0079](decisions/0076-0080-developer-mvp-foundation.md)), never
  the opaque legacy `SqliteStateStore`; the two require separate files because
  `PRAGMA application_id` is a whole-file SQLite property.
- **Empty preinstalled module catalog and no native fee composer (DR-0127).**
  The active devnet composes an empty `PreinstalledModuleCatalog` and no
  native Standard Asset fee composer (`FeeEffectComposer`). The legacy devnet
  catalog, preinstalled WASM modules, and native fee composer are deleted from
  the active devnet fixture. Generic preinstalled transaction machinery is
  retained only as inactive protocol infrastructure where unit tests exercise
  it, not as an active devnet surface.
- **Protocol version 7 and fee policy (DR-0127).** Devnet protocol version 7
  removes the legacy fee asset registry (`fee_assets` is empty) and legacy
  transaction gas schedule (`gas_schedule` base fee and execution price are
  zero). Paid pricing is carried solely by the installed `PaidFeePolicy`
  ([DR-0127](decisions/0127-public-standard-asset-cli-migration.md)).
- **Mandatory closed signed genesis (DR-0125, DR-0126, DR-0127).** Paid
  contract genesis is mandatory on every boot; the historical
  `--enable-paid-contracts` opt-in flag is removed. Startup installs or
  verifies the public Standard Asset package, an independent Standard Asset
  instance, its `Definition`, and one `TreasuryCap<A>` through a closed
  signed genesis manifest (`node_core::genesis::install_genesis`). The
  genesis authority address owns the `Definition`; the first configured
  development owner owns the `TreasuryCap<A>` as the fixed local-devnet mint
  authority — neither object uses the object model's `Immutable` ownership
  kind.
- **Genesis dev-owner coins and mint authority.** Genesis seeds two initial
  `Coin<A>` objects per configured development owner (`--dev-owner`): one
  initial fee-source coin (`DEVNET_PAID_FEE_COIN_BALANCE` = 10,000,000) and one
  initial spend-source coin (`DEVNET_PAID_SPEND_COIN_BALANCE` = 10,000,000). The
  first configured development owner owns the installed `TreasuryCap<A>`,
  making it the devnet mint authority so `mint` and `burn` CLI workflows are
  immediately usable without the public genesis signing key. Total supply is
  derived from both initial coin sets and asserted against the TreasuryCap body
  during manifest construction.
- **Fee recipient address.** Devnet requires `--fee-recipient` specifying an
  admissible `Address`. There is no seeded native treasury object, and the
  recipient need not be distinct from a development owner.
- **Historical preinstalled module and seeding fixtures (DR-0106–DR-0110).**
  Prior devnet iterations relied on privileged preinstalled modules, native fee
  composition, and seed-time coin generation:
  - Protocol 4 / [DR-0106](decisions/0106-typed-entrypoint-owner-transition.md)
    and [DR-0107](decisions/0107-standard-asset-v1-devnet-activation.md)
    introduced preinstalled typed entrypoint/owner-transition policies, seeded
    one transferable coin and one fee-payer coin per owner plus an ordinary
    treasury coin for a distinct fee-treasury owner, and used
    `StandardAssetCoinFeeComposer` for post-execution debit/credit.
  - Protocol 5 / [DR-0108](decisions/0108-standard-asset-v1-split-and-merge.md)
    added split and merge entrypoints; [DR-0109](decisions/0109-standard-asset-v1-mint.md)
    added an unbounded mint capability fixture.
  - Protocol 6 / [DR-0110](decisions/0110-standard-asset-supply-control.md)
    introduced supply-controlled mint and whole-coin burn using `TreasuryCap<A>`
    under canonical `sunrise.standard_asset.v1`.
  Under [DR-0127](decisions/0127-public-standard-asset-cli-migration.md), these
  preinstalled fixtures and native composers are superseded and removed from the
  active devnet. Existing development databases seeded under earlier versions
  are incompatible and not migrated; startup fails closed on their committed
  protocol context, and operators must use a fresh data directory.
- **Dev-profile identities are not protocol claims.** The public Standard
  Asset package and instance IDs vouch only for this committed local-devnet
  composition; no general on-chain asset registry or authenticated metadata
  surface exists. Wallet and explorer must render the ID as opaque bytes plus an
  explicitly local label, never as production asset metadata.
- **No background sweeper.** The devnet runs no resident outbox-recovery loop,
  timer, or scheduler; unattended recovery, when needed, is invoked the same
  way the native binary already exposes it (see
  [runtime-and-ingress.md §28](runtime-and-ingress.md#28-serverless-runtime-constraints) and the
  scheduler-callable recovery API in
  [persistence.md §41](persistence.md#41-production-persistence-architecture)), consistent with
  treating process lifetime as a non-requirement.
  The current generic machine and contract transitions produce responses but no
  outbound messages, so the local transport queue does not grow on this route;
  its fixed capacity remains a fail-closed bound for a future message-producing
  transition.

The devnet profile is deliberately loopback-only, single-validator and
non-production. It uses local SQLite, one shared bounded query/submission
executor, an unauthenticated public-read query API, and paid pricing carried
only by `PaidFeePolicy`; it does not define validator/certificate fee
distribution, production economics, HA, or public-network admission. The
address in `/v1/senders/{sender}/next-nonce` is a lookup selector, not
authorization. Roadmap status, readiness gates, and deferred product surfaces
belong only in [`TODO.md`](../../TODO.md).

## 43. Bounded Developer MVP query API

The Developer MVP exposes four additive `GET` routes from both normalized
structured routers. They share the event route's blocking-admission limit and
trusted storage authority, but accept no request body, writer fence, deadline,
domain, chain context, or protocol selector from HTTP:

- `/v1/context` returns the trusted `chain_id`, current `epoch`, exact canonical
  `ProtocolConfig`, and the single committed logical atomicity domain.
- `/v1/objects/{object_id}` returns true absence, a retained tombstone, a
  verified current inline object, or an explicit current blob reference.
- `/v1/receipts/{request_id}` returns typed absence or the exact canonical
  `NodeDedupRecord` after checking it against the outer durable receipt.
- `/v1/senders/{sender}/next-nonce` returns the next nonce for the current
  trusted epoch. The address in this URL is only an untrusted public lookup
  selector. It grants no authority and cannot substitute for transaction
  authentication; the returned value is usable only by a transaction whose
  signature authenticates that same sender under the committed auth profile.

Every path identifier is exactly 64 lowercase ASCII hexadecimal characters.
Malformed identifiers fail before identity allocation, clock access, or
storage I/O. Successful results use
`application/vnd.sunrise-edge.query-result`, `Cache-Control: no-store`, and
four independent canonical version-1 frames: context `0xE102`, object
`0xE103`, receipt `0xE104`, and next-nonce `0xE105`. Object status identifiers
are `1 = absent`, `2 = tombstoned`, `3 = current inline`, and `4 = current blob
reference`; receipt status identifiers are `1 = absent` and `2 = present`.
These identifiers and exact frames are stable client contracts and require
literal test vectors.

Absence is a normal `200` typed result so receipt polling needs no
transport-specific interpretation. A current inline object includes its head
revision, immutable version, self-describing digest, and exact canonical
`objects::Object` bytes. Node-core, not the HTTP adapter or storage adapter,
cross-checks head/version/digest/schema/provenance/owner projection and
recomputes the inline body digest from the version's stored chain and protocol
provenance before returning it. A blob-backed version returns only explicit
metadata and its blob digest; this MVP does not fetch or claim to verify an
unavailable blob body. A tombstone retains the ABA-safe head revision and last
immutable version. Receipt presence includes the outer event digest and exact
canonical dedup bytes only after strict decode, identity/digest agreement, and
canonical re-encoding checks. A deleted nonce record for an epoch that may be
accepted remains corruption and fails closed; true absence at initial revision
returns zero.

Every query route, including `/v1/context`, resolves the domain from the
committed manifest through the same activation-epoch-checked
`DomainPlacementManifest::resolve_domain` path the authenticated write path
uses (at the trusted current epoch, with one bounded access rather than a real
application plan) — never `placement.domain()` read unconditionally — through
one shared helper both `/v1/context` and the three storage-backed routes
call. All storage-backed queries additionally allocate a restart-safe
correlation identity and a bounded deadline from the embedding host, and run
through the same bounded blocking executor as submission. An inactive
placement therefore rejects before identity allocation, clock access, or
storage I/O for the three storage-backed routes, and before any response is
constructed for `/v1/context`; it remains an opaque `503` for every route,
while a malformed selector is a `400` rejected at the HTTP boundary.
Capacity exhaustion is `429`; malformed paths are `400`; a transient host or
storage-availability condition (identity-source unavailability, clock/runtime
failure, a durable read that proves writer fencing/deadline exhaustion/
backend unavailability/unsupported schema generation
(`DurableReadError::SchemaMismatch`, treated as an operator/deployment
condition rather than proof of corrupted persisted bytes), or committed
`ProtocolConfig` inactivity/misconfiguration) is an opaque `503`; corrupt or
unverifiable persisted content, result-encoding failure, and identity-source
exhaustion are an opaque `500`. Query responses are bounded by the existing
maximum canonical
object/receipt sizes; there is no scan, list, prefix, pagination, proof,
historical-version selector, or arbitrary state-key endpoint in this MVP
slice.

Every one of the four result types except `/v1/context` (which has no request
selector) carries the exact selector it answers — `object_id`, `request_id`,
or `sender` — in every status, including absence and tombstone. Node-core's
`ObjectQueryResult` and `ReceiptQueryResult` bind this selector at the type
level so the HTTP layer cannot construct a canonical result for one selector
from a lookup keyed by another; `native-http`'s wire codecs re-assert the same
binding as an always-present field, and the adapter independently re-checks
the selector on the result node-core returns before encoding it, as defense
in depth against a future regression.

Current vs. planned: this slice is implemented As-Is. `node-core` adds public
`query_sender_next_nonce`, `query_object`, and `query_request_receipt`
functions — implemented in a private internal module but re-exported from the
crate root, so `node_core::query_object` etc. are the stable public paths, not
a public `query` module — as the only entrypoints that can observe a
next-nonce value, an object, or a receipt outside node-core; the private
`SenderNonceRecord` framing never crosses that boundary, and the object/receipt
checks reuse the same cross-check/re-encoding rules as the authenticated write
and replay paths. `query_object` checks the immutable version's creating-chain
provenance against the trusted chain before branching on inline versus blob
payload, so a cross-chain blob record fails closed exactly like a cross-chain
inline record; a `CurrentBlobReference` result's `digest` and `blob_digest`
are the values recorded on the immutable version and cross-checked against the
head, never verified against fetched body bytes, since this MVP never fetches
a blob body. `native-http` adds the four canonical
`application/vnd.sunrise-edge.query-result` codecs (`0xE102`-`0xE105`) —
including strict decode validation of the nested canonical `objects::Object`
(id/version match, `MAX_AUTHENTICATED_OBJECT_BODY_BYTES`) and nested
`NodeDedupRecord` (request-id/event-digest match, exact re-encoding) carried
inside a `CurrentInline`/`Present` result. Object-query encoding v2 additionally
carries the immutable version's creating chain id and protocol version; the
Rust client recomputes the inline body digest before exposing it. Historical
object-query v1 remains decodable, but its inline form is rejected by the
generic client as unverifiable. The codecs also reject a zero protocol
version/hash-suite/profile/scheme/binding id, an over-length chain id, or
empty canonical `ProtocolConfig` bytes in the context result — and wires
`GET /v1/context`, `/v1/objects/{object_id}`, `/v1/receipts/{request_id}`,
and `/v1/senders/{sender}/next-nonce` into both `structured_durable_router` and
`preinstalled_wasm_structured_durable_router`, sharing their
`NativeBlockingExecutor`, admission, and pre-storage cancellation semantics.
Every path selector is validated as exactly 64 lowercase ASCII hex characters
(and, for receipts, non-zero) before any identity allocation, clock access, or
storage I/O. Stable vectors, round-trip/unknown-tag/mismatched-selector decode
tests, both-router parity across all four routes (including a populated
current-inline object and a present receipt, not only absence), malformed-
path-before-side-effects, object absent/tombstone/current-inline/current-blob/
tamper/wrong-chain, receipt absent/present/corrupt, nonce
zero/advanced/deleted-corrupt, inactive-placement-before-side-effects cases
for `/v1/context` and a representative storage-backed object route, and the
`503`/`500` operational classification — a direct case table plus the
`SchemaMismatch` decision above — are covered in both crates' test suites.

## 44. Rust client library

The Developer MVP Rust client is a runtime-neutral library at `clients/rust`.
It exposes seed-based Ed25519 key/address handling, canonical transaction
construction and signing, submission, bounded receipt waiting, and the four
query operations from section 43. It stays application-agnostic: preinstalled
or published package entrypoint names/argument frames, native-coin conventions,
fee selection, and other contract semantics belong to later consumers such as
`apps/cli`, never to the base client.

Canonical HTTP result frames and route/media-type constants are shared through
a dependency-light `node-wire` crate. `native-http` re-exports that contract so
existing server callers retain the same public names, while `clients/rust`
depends on `node-core` and `node-wire`, not on Axum or `native-http`. The shared
crate owns encoding and strict decoding only; routing, admission, clocks,
storage authority, and HTTP status classification remain server concerns.
Execution-effect decoders enforce the same collection and byte-size bounds as
their encoders and reject unknown identifiers, malformed nesting, trailing
bytes, and non-canonical representations. The transaction signature message
type is exported from node-core rather than duplicated by a client.

The initial transport is synchronous and deliberately local-development-only.
A small transport trait permits deterministic tests; the provided HTTP/1.1
implementation (`LoopbackHttpTransport`) connects only to an explicit loopback
address, opens one bounded `TcpStream` per request, applies connect/read/write
timeouts and header/body limits, requires an exact `Content-Length`, and
rejects transfer encoding, ambiguous lengths, truncated or trailing bodies,
unexpected content types, and non-loopback targets. It provides no TLS,
authentication, proxy, redirect, persistent connection, async runtime, or
production remote-node claim. (A separate, later-added `RemoteTlsHttpTransport`
lifts the loopback-only and no-TLS restrictions within S1's documented
bounds — see [DR-0085](decisions/0081-0087-cli-first-roadmap.md) — without changing this transport's own scope.)

`/v1/context` remains authoritative for chain, epoch, protocol-version, hash-
suite, authentication-profile, signature-scheme, binding, and atomicity-domain
identifiers. The canonical `ProtocolConfig` bytes are preserved as opaque bytes
in this slice rather than partially decoded. A caller supplies the exact trusted
preinstalled module reference and object references used by its transaction;
the client does not invent module discovery or object scans. Submission uses an
explicit non-zero request ID supplied by the caller, checks that the response is
bound to it, and never derives a protocol identity with an ad hoc hash.
Receipt absence is normal while waiting; polling always has explicit attempt,
elapsed-time, and backoff bounds and creates no background worker. Capacity and
temporary unavailability may be retried only within those caller-visible
bounds.

Stable literal vectors cover the shared query/response frames and signed
transaction bytes accepted by node-core. The client does not claim to recompute
transaction/effect hashes from the context's hash-suite identifier, fetch blob
bodies, verify certificates, or decode the full protocol configuration. Those
capabilities, production transports, key generation/keystores, CLI policy, and
application-specific helpers remain deferred until the MVP consumers require
them.

Current vs. planned: this slice is implemented As-Is. `node-wire` owns the
previously server-local codecs without changing their stable vectors, and
`native-http` re-exports the same public names. `execution` now strictly
decodes event records, object effects, and complete execution effects;
`clients/rust` re-exports those decoders for response consumers. The client
checks every returned object/request/sender selector against the exact query,
and the loopback transport rejects request framing injection, over-bound
headers/bodies, transfer encoding, ambiguous lengths, malformed status/header
syntax, truncation, trailing bytes, and failure to close a `Connection: close`
response within its timeout. Per-stage socket timeouts are also capped by one
monotonic complete-request deadline, and receipt polling passes its overall
elapsed deadline into every transport call, so a slow-drip peer cannot reset
the bound byte by byte. Nested effect-list decoders compare the declared count
with the frame's exact field count before allocating or iterating. Tests pin
the existing signed transaction vector, authenticate freshly client-signed
bytes through node-core, exercise fake submission/receipt behavior, exercise
adversarial raw TCP responses (including slow-drip and close timeout), and
query all four routes through a real composed devnet router over TCP. A live
signed asset transfer, duplicate replay, and restart sequence remains Developer
MVP criterion 10 work; this client slice does not claim that later E2E.

## 45. Rust client external-signer boundary and Developer MVP CLI

`clients/rust` gains a safe, additive two-stage transaction-construction API
(`transaction::PreparedTransaction`) alongside the existing single-call
`build_signed_transaction`, which is now implemented through the same path so
its stable output bytes are unchanged. `PreparedTransaction::prepare` takes an
explicit sender `Address`, the active `SignatureSchemeId` from a trusted
`/v1/context` result, and a `TransactionRequest`, and returns an immutable
value with the canonical Transaction v1 fields already fixed; it rejects any
scheme other than `Ed25519` before any framing happens, returning a
dedicated `ClientError::UnsupportedSignatureScheme(SignatureSchemeId)`.
Before this two-stage API existed, `build_signed_transaction` rejected the
same unsupported-scheme case later and less specifically: it always called
`SignatureSigner::sign_canonical`, whose own scheme-match guard returned a
wrapped `ClientError::Crypto(CryptoError::SignatureSchemeMismatch)` instead.
`build_signed_transaction`'s caller-visible error type for this case is
therefore different from before — this is a strictly additive, easier-to-
match error-type change, not a protocol change: the exact same case is still
rejected before any framing or signing, and every stable output byte for
every case that still succeeds is unchanged. `signable_frame`
exposes the exact centralized-domain-framed bytes
([`crypto::frame_signature_message`]) an external signer must produce a raw
signature over — the same bytes any in-process `SignatureSigner` ultimately
signs. `finalize` accepts that raw signature and only produces output after
independently constructing an `Ed25519Verifier` from the sender's 32 bytes,
re-deriving the same
framed bytes, and confirming the signature both has the scheme's exact
supported length and cryptographically verifies; a well-formed but invalid,
wrong-signer, or tampered (signature or transaction field) signature is
rejected with a typed `ClientError` and produces no output.
`sign_and_finalize_with` is a convenience composition of `finalize` for any
in-process `SignatureSigner` (for example `LocalSigner`), reusing
`sign_canonical`'s own scheme-match guard. This boundary exists so a future
external signer — including but not limited to a dedicated hardware wallet —
can be integrated without changing `PreparedTransaction`'s public shape or
this crate's stable transaction bytes: only a new caller supplying bytes to
`finalize` would be added.

**Ledger boundary is not implemented in this slice.** No USB/HID/Ledger
dependency exists anywhere in this workspace, and none belongs in a protocol
or client crate. `PreparedTransaction` is Ledger-*ready* only in the narrow
sense that it already exposes the exact bytes an external signer would need
and already independently verifies whatever signature comes back; it is not
a Ledger integration. A real integration additionally requires, at minimum: a
dedicated Sunrise Edge Ledger device application (existing Solana or Ethereum
Ledger apps must not be reused for Sunrise transaction signing — they know
nothing about this protocol's canonical framing and would either reject the
payload or, worse, sign it under the wrong domain); an APDU protocol and host
transport to that device application; on-device parsing and clear signing of
the exact Sunrise signature frame (chain/protocol-version/epoch/message-type/
scheme plus the canonical transaction payload) so a user approves what they
are actually signing, not opaque bytes; public-key/address verification
against the device; an explicit derivation-path policy; device/application/
firmware-version checks; explicit on-device user confirmation before signing;
host-side signature verification (which `PreparedTransaction::finalize`
already provides); and hardware-in-the-loop tests. None of this is
implemented or claimed here.

`apps/cli` is a Rust-only Developer MVP CLI. Its runtime dependencies are the
Rust client, Ledger host library, and public Standard Asset package used to
construct exact public ABI calls. Additional dev-dependencies compose real
local-devnet, persistence, canonical-fixture, and TLS end-to-end tests; none
are reachable from a non-test build. It has no
Node/browser runtime, no argument-parsing crate (flags are
parsed by a small hand-written, strict `--flag value` parser that rejects
duplicates, unknown flags, and any non-flag/extra positional token), no
`unsafe` (`#![forbid(unsafe_code)]`), and no independent canonical
encode/decode, signing, or RPC path — every protocol interaction goes
through `sunrise-edge-client`. It provides network subcommands: `address`
(derives and prints the `AddressIsPublicKey` address bound to an explicitly
named development seed file — never a keystore, never a home-directory default,
and the seed is never accepted on argv or printed); `context`, `object`,
`receipt`, and `next-nonce` (thin wrappers over the matching
`sunrise-edge-client` query methods); `contract` (structural validation, local
or paid publication, instantiation, call, and query); and the five human-facing
Standard Asset operations: `transfer`, `split`, `merge`, `mint`, and `burn`.
Every network subcommand targets an explicit `--endpoint`; with neither TLS
flag supplied, `--endpoint` must be loopback and this binary talks the legacy
plaintext `LoopbackHttpTransport` (a non-loopback address is rejected before any
connection is attempted). With both paired
`--tls-server-name`/`--tls-ca-cert-der-file` flags supplied, `--endpoint` is
instead treated as an already-resolved `SocketAddr` with no loopback restriction,
and this binary dials `RemoteTlsHttpTransport`; this binary performs no DNS
resolution of its own, so `--endpoint` remains a literal address either way.
Output is deterministic, line-oriented `key=value` text; every error is a typed,
actionable `CliError`, and every error exits the process non-zero. A successful
node response payload is decoded through `sunrise-edge-client`'s already-generic
`execution::ExecutionEffects` decoder when possible; receipts, object bodies,
and any payload that does not decode as effects are printed as bounded lowercase
hex instead of inventing a claim about their meaning.

Under [DR-0127](decisions/0127-public-standard-asset-cli-migration.md), the five
top-level CLI verbs (`transfer`, `split`, `merge`, `mint`, and `burn`) remain as
the human-facing interface, but they are thin builders for an ordinary
`PaidApplication::Call` to the policy-pinned public Standard Asset package. They
receive no native entrypoint, type, ownership, amount, fee, or settlement
privilege.

The CLI fetches and validates the installed `PaidFeePolicy` after validating the
separately configured expected protocol context (`--expected-chain-id`,
`--expected-protocol-version`, `--expected-epoch`, `--expected-hash-suite-id`,
`--expected-domain`). For this devnet profile, that policy pins the public
Standard Asset code, instance, `Coin<A>` type, schema, fee recipient, and the
single type argument `A`. The five asset commands target that exact code and
instance and reuse that exact type argument. They do not accept a
caller-selected module ID, module version, module digest, fee asset ID, fee
treasury object, code reference, instance reference, or type argument.

Every command:
1. rejects Ledger selection before device or network access until paid-intent
   clear signing is separately specified;
2. validates TLS endpoint configuration separately from the expected protocol
   context;
3. fetches the installed fee policy and current object snapshots before
   signing;
4. requires every application input to be a current inline object owned by the
   signer and to match the exact published nominal type and schema;
5. signs one paid envelope (`encode_signed_paid_intent`) containing the
   application call, fee consent, request ID, nonce, gas limit, maximum fee,
   and optional refund recipient;
6. submits through the existing paid HTTP route (`/v1/contracts/paid-executions`) and
   independently verifies the returned paid result; and
7. writes requested recovery artifacts (`--submission-out`, `--result-out`)
   before reporting success.

The application access and argument shapes are:

| Command | Entrypoint | Application access, in order | Arguments |
| --- | --- | --- | --- |
| `transfer` | `transfer` | source `Coin<A>` Write | recipient |
| `split` | `split` | source `Coin<A>` Write | positive amount, recipient |
| `merge` | `merge` | primary `Coin<A>` Write, secondary `Coin<A>` Consume | empty tuple |
| `mint` | `mint` | `TreasuryCap<A>` Write | positive amount, recipient |
| `burn` | `burn` | `TreasuryCap<A>` Write, `Coin<A>` Consume | empty tuple |

Fee consent is separate from application access and is fixed to Write
reservation for these five commands. The fee source (`--fee-source`) may be the
same object as any application input, including an application Consume input;
the signed reference must then be identical and the application sees only the
post-reservation remainder. Only a fee consent using `reserve_all`/Consume is
forbidden from overlapping application access. `mint` necessarily uses a Coin
separate from its TreasuryCap input; the other four operations may use one of
their Coin inputs for both roles.

The CLI derives arguments with the public package helpers and uses the
policy-pinned type argument. It does not decode or predict application balance
transitions as authority. Local decoding is limited to presenting and
pre-validating host-authenticated current object bodies; the WASM package
performs the state transition.

Historical preinstalled transfer fixtures ([DR-0106](decisions/0106-typed-entrypoint-owner-transition.md),
[DR-0107](decisions/0107-standard-asset-v1-devnet-activation.md)) previously
constructed a three-entry `AccessManifest` (source Write, fee Write, treasury
Write) evaluated by a validation-only preinstalled WASM module with node-core
synthesizing owner transition and `StandardAssetCoinFeeComposer` debiting
payer and crediting treasury. That preinstalled path has been deleted from the
active devnet in favor of the unified paid contract call path.

The live Standard Asset entrypoints have no Ledger clear-signing policy yet.
Selecting Ledger for `transfer`, `split`, `merge`, `mint`, or `burn` therefore
returns a typed local error after argument validation and before any device
connection or network dispatch; only the explicitly development-only
`--seed-file` path can submit these commands in the current profile. The
`address` command and reusable Ledger host libraries remain available, but
their historical protocol-3 transfer fixture is not accepted as authority for
these transactions.

The development seed file loaded by `address` and Standard Asset commands must
be an explicit path (there is no default or home-directory location), must not be
a symlink, must be a regular file, must on Unix grant no permission bit to
group or other, and must contain exactly 64 hexadecimal digits plus at most
one trailing `\n` — anything else is a typed, actionable rejection before any
key material is derived. This is a development convenience, explicitly not a
keystore.

Current vs. planned: this slice is implemented As-Is except where marked.
`clients/rust`'s two-stage signer API, its small generic re-export surface,
and `apps/cli`'s six commands are implemented and tested, including
adversarial coverage of a mismatched, malformed-length, wrong-signer, and
tampered signature; parser rejection of duplicate/unknown/malformed/
extra-positional arguments; development seed file symlink/permission/length
rejection (Unix); a fake-`Transport` unit test per query command plus
`transfer`'s full success and epoch-mismatch/unsupported-scheme/
non-current-inline-object adversarial paths; and two real loopback-TCP tests
against a composed local devnet router — one exercising `context`/
`next-nonce`/`object`, and one exercising a complete signed `transfer`
against freshly seeded accounts through to a waited, present receipt.
[DR-0088](decisions/0088-0093-hardware-signing.md) subsequently implements S4a's strict host-side profile, exact
signed-byte clear-signing fixture, and external-signer preflight.
[DR-0091](decisions/0088-0093-hardware-signing.md)
records the separate repository's S4b Ledger SDK application and Nano S+
Speculos evidence As-Is. [DR-0092](decisions/0088-0093-hardware-signing.md) subsequently implements S4c Phase 1's host
APDU/USB/HID transport and CLI signer selection in this repository's own
`clients/ledger` crate — the profile/address checks and USB-descriptor-level
device recognition only, not the active-app/firmware checks — and
[DR-0093](decisions/0088-0093-hardware-signing.md)
implements S4c Phase 2a's strict Ledger OS identity/dashboard parsing and
staged dashboard/firmware/open-app/reconnect/active-app sequence, closing
that gap strictly in software. S4c itself, physical-device HIL, and release
evidence remain unimplemented and are not claimed by any of these four
boundaries.

**Development-only residual: no memory zeroization.** `load_dev_seed`'s read
buffer and decoded `[u8; 32]` seed, and `LocalSigner`'s in-memory signing
key, are ordinary Rust values with no `zeroize`-on-drop behavior anywhere in
this slice; a process-memory disclosure (a core dump, swap, or a debugger
attached to the process) can recover them for as long as they, or a copy the
allocator has not yet overwritten, remain resident. This is consistent with
`load_dev_seed`'s and `LocalSigner`'s existing documented status as
explicit, non-keystore, development-only conveniences — not production key
handling — and is called out here rather than silently assumed.
The devnet start/split/merge/mint/burn/transfer, restart, and duplicate-replay
E2E is implemented As-Is (see `apps/cli/tests/devnet_standard_asset_e2e.rs`,
[DR-0127](decisions/0127-public-standard-asset-cli-migration.md), and "Local
devnet architecture" above). Current readiness and product-surface sequencing
belong only in [TODO.md](../../TODO.md).

## 46. Hardware Signing Profile v1 and external-signer preflight

S4 is split into four ordered boundaries so a host library cannot become a
surrogate for device-side authorization. S4a is implemented As-Is in this
repository; S4b's separate dedicated Ledger application and Nano S+ Speculos
evidence are implemented As-Is in `sunriselayer/sunrise-edge-ledger-app` by
[DR-0091](decisions/0088-0093-hardware-signing.md). S4c Phase 1's host APDU/USB and CLI signer selection (profile/address checks
and USB-descriptor-level device recognition) are implemented As-Is in this
repository by [DR-0092](decisions/0088-0093-hardware-signing.md), and S4c Phase 2a's active-app/firmware identity check
is implemented As-Is by [DR-0093](decisions/0088-0093-hardware-signing.md) — strictly in software, against
`FakeTransport` only. S4c itself is still not complete: it still needs
Phase 2b's real hardware validation. S4d
completes the remaining physical-device, reproducibility, and
release-evidence gate. S4 is not complete
until S4d passes and the CLI has an actual production signing path replacing
its development-only seed flow. DR-0107 also removed the only live transfer
shape recognized by the current Ledger policy: `address` still exercises the
host/device identity path, while the five asset commands (`transfer`, `split`,
`merge`, `mint`, `burn`) reject Ledger selection before device or network
dispatch until a paid-intent clear-signing policy is separately specified and
reviewed.

`crypto::decode_signature_frame` is the strict counterpart to the established
`frame_signature_message` encoder. It accepts only canonical type `0x2001`,
encoding version 1, and exact fields 1-6, and changes no existing bytes.
The new dependency-light `signing-view` crate independently decodes the
signable Transaction v1 shape without depending on `execution`/`wasmi`, applies
Hardware Signing Profile v1's fixed 4 KiB frame and tighter nested bounds, and
re-encodes every accepted value to require byte identity. A dev-only
differential test proves this independent encoder agrees with `execution`.

Clear signing is exact-policy-only. The first (and, as of DR-0107, now
historical — see below) policy recognized only the reference
`sunrise-local-devnet`, protocol 3, epoch 0 asset-account transfer's exact
module id/version/SHA-256 code digest, `transfer` entrypoint, non-zero
`0xF002` v1 amount, three distinct ordered `Write` references, and fee object
equal to source index 0. Unknown module, digest algorithm or bytes, version,
entrypoint, argument schema, access shape, or fee shape is a typed rejection.
DR-0107 replaced the live devnet's protocol-3 `asset_account` module with a
protocol-4 Standard Asset v1 whole-coin transfer module; the historical
policy constant (renamed `HISTORICAL_ASSET_ACCOUNT_TRANSFER_POLICY_V3`) no
longer matches any live devnet build and is kept only as a fixed-shape
historical vector. No new clear-signing policy for the Standard Asset v1
entrypoint exists yet (Ledger updates remain deferred); this device-view
crate's own behavior, profile, and APDU contract are otherwise unchanged.
There is no raw-argument, blind-signing, or expert-mode fallback. Every
rendered line comes only from the signed frame: `request_id`, destination
owner, transferred-asset symbol/id, module display name, and other queried
metadata are excluded because Transaction v1 does not bind them. Fee asset id
is signed and is displayed.

`PreparedTransaction::clear_signing_view` derives the view only from
`signable_frame`. The additive `ExternalSigner` boundary and
`sign_and_finalize_external` compare the signer's reported scheme and address
to the prepared transaction before invocation, validate the exact frame under
the fixed profile/policy, then pass that same frame to the signer. Existing
`finalize` still independently checks length and Ed25519 validity against the
sender. The host view is only preflight/conformance evidence: the eventual
device app must independently parse and display the received frame.

[`docs/signing/hardware-signing.md`](../signing/hardware-signing.md) is normative for the fixed profile bounds, stable display fixture,
provisional explicitly unregistered development derivation path, and bounded
APDU state machine/status words. The dedicated device app lives in the separate
`sunrise-edge-ledger-app` repository because its custom targets, Rust SDK/C
bindings, Speculos workflow, device matrix, and Ledger release lifecycle cannot
pass or be hidden from this workspace's host-target gate.
[DR-0091](decisions/0088-0093-hardware-signing.md) records that
device-side S4b boundary. [DR-0092](decisions/0088-0093-hardware-signing.md) places every vendor host dependency in the
new `clients/ledger` crate, never a protocol crate or `clients/rust`, and
explicitly amends the CLI's original one-runtime-dependency invariant
([DR-0084](decisions/0081-0087-cli-first-roadmap.md)) to two: `sunrise-edge-client` and `sunrise-edge-ledger`. No
physical-device evidence, registered SLIP-0044 allocation, or release
artifact exists yet; `clients/ledger`'s real USB/HID transport is itself
unvalidated against physical hardware (see [DR-0092](decisions/0088-0093-hardware-signing.md)).
