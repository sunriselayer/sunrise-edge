# Architecture decisions DR-0081–DR-0087

Local devnet, client/CLI, CLI-first sequencing, transfer policy, and uniform
fee decisions.

- DR-0081: Define the Developer MVP product-surface monorepo layout and ratify
  a uniform fungible asset model ahead of implementation.

  **Monorepo layout.** The repository gains six product paths under `apps/`
  and `clients/` as each is implemented: `clients/rust` and `clients/typescript`
  (protocol client libraries with no UI of their own), `apps/devnet` (the
  local devnet binary/startup composition; see
  [product-surfaces.md §42](../product-surfaces.md#42-local-devnet-architecture)), `apps/cli` (a Rust-only developer CLI), and `apps/explorer`/
  `apps/wallet` (browser applications). `apps/cli` depends only on
  `clients/rust`: it is never a Node/JS/browser runtime and never talks to the
  protocol through anything but `clients/rust`'s own encode/decode/signing/RPC
  surface. `apps/explorer` and `apps/wallet` are separate SvelteKit
  applications using shadcn-svelte (Luma) as their component layer, each built
  and deployed as a static/CSR app only: no request-time server-side
  rendering, no SvelteKit server adapter, no `+page.server`/`+layout.server`/
  `+server` route files, and no server actions, remote functions, or
  server-held sessions or keys in either app.
  Build-time prerendering is allowed only for a fixed static shell; no dynamic
  chain data may be embedded by that build.
  `apps/wallet` generates, holds,
  and uses signing keys only in the browser; no wallet key or signature is
  ever generated on, or transits through, a server this project controls.
  Both apps fetch dynamic chain data (objects, balances, receipts, chain/
  context info) directly in the browser runtime through
  `clients/typescript`, never through a bundler-time or server-side data
  load. No shared UI package is introduced across `apps/explorer` and
  `apps/wallet` until real duplication between the two actually exists.

  **Developer MVP order.** Developer MVP completion order (see
  [CLI Developer MVP Gate](../../development/history/roadmap-through-2026-10-06.md#cli-developer-mvp-gate)) is: local devnet, bounded query API, Rust
  client, Rust CLI, TypeScript client, explorer, wallet, restart/duplicate
  E2E, and explicit documented development-only limitations. This replaces
  [DR-0080](0076-0080-developer-mvp-foundation.md)'s earlier "TypeScript client + counter demo UI" pairing; no
  `demo/counter` directory is created.

  **Amendment: gate renamed and resequenced by DR-0085.** DR-0085 renames
  this gate `CLI Developer MVP Gate`: its local devnet, bounded query API,
  Rust client/CLI, and restart/duplicate E2E prefix is implemented As-Is.
  `clients/typescript`, `apps/explorer`, and `apps/wallet` remain required but
  start only after the `CLI-First Node Production Gate` passes. This changes
  neither the monorepo layout nor the asset model, devnet module, or deferred
  scope.

  **Uniform fungible asset model.** Every asset, including any future fee
  asset, uses exactly one `AssetId`/account/transfer implementation path.
  There is no privileged native coin, no second balance representation, and
  no separate transfer or fee-debit code path for a "special" asset. Which
  asset(s) may pay fees, and at what rate, is protocol policy layered over
  ordinary asset accounts, not a second implementation of balances or
  transfer (see [core-protocol.md §18](../core-protocol.md#18-stablecoin-fee-lifecycle)). A future fee-debit effect
  must reuse the same declared object access, the same exact-head assertions,
  and the same atomic object-effect commit as every other asset transfer; it
  may not bypass them with bespoke fee-only state.

  **Local devnet module.** The local devnet's stateful preinstalled module is
  `sunrise.devnet.asset_account.v1`, exposing one `transfer` entrypoint over
  two ordinary owned asset-account objects that both belong to the same
  sender. Both accounts carry the same configured 32-byte `fees::AssetId`
  (never a placeholder or all-zero value), while their object identities are
  distinct. The transition enforces
  balance conservation (the debited and credited amounts are identical and
  the combined balance across the two accounts is unchanged), and fails
  closed on zero amount, amount underflow, amount overflow, and any asset-ID
  mismatch between the two accounts. Because destination-owner
  authorization for a transfer into an account owned by someone else, and any
  change of an object's owner, remain fail-closed on the existing owned-
  effects path (see [runtime-and-ingress.md §30](../runtime-and-ingress.md#30-node-core-invocation-boundary) and
  [DR-0077](0076-0080-developer-mvp-foundation.md)), this
  module demonstrates only same-sender balance movement between two of the
  sender's own asset accounts. It does not implement, and must not be
  described as, user-to-user transfer. The devnet's fee registry stays empty
  and every devnet transaction commits with `fee_payment: None`; this module
  charges, computes, or debits no fee. Its body, arguments, and event use the
  devnet-local canonical type IDs `0xF001`, `0xF002`, and `0xF003`; no raw
  hand-framed event or object bytes are accepted. The current host ABI does
  not expose object metadata to WASM, so this MVP verifies the complete
  canonical body structure while node-core separately verifies sender
  ownership and frozen metadata. A metadata-readable ABI or trusted catalog
  type constraint remains deferred until cross-owner transfer or another
  devnet application object type makes structural checking insufficient.

  **Deferred beyond this MVP surface.** Cross-owner transfer authorization and
  any change of object ownership; `Create` and any notion of "associated" or
  auto-derived accounts; mint, burn, supply tracking, and asset metadata/
  registry management; fee charging, gas accounting, and any fee-debit
  effect; freeze, close, delegate, and allowance/approval semantics; Shared/
  System object ownership; blob-backed object bodies and arbitrary module
  upload; and all other production-hardening work already frozen by
  [DR-0076](0076-0080-developer-mvp-foundation.md).

  **DR-0086 amendment (current status).** The preceding same-sender boundary
  is historical. S2 permits DR-0086's exact policy-bounded existing
  Address-owned destination while preserving both owners; reassignment/
  gifting still fails closed. This dev profile installs module v2 with
  `0xF011` semantics v2; historical v1 bytes remain pinned but uninstalled.
  The `0xF001` body, `0xF002` arguments, `0xF003` event (all schema v1), and
  WASM bytes are unchanged. S2 is As-Is, not general upgrade activation or
  production/mainnet readiness.

  **DR-0087 amendment (current status).** The preceding fee-free boundary is
  historical. S3 uses ordinary asset accounts for payer and distinct treasury,
  settles actual gas after execution, and commits trap fee-only effects. The
  active module/semantics declaration is v3; historical v1/v2 declarations,
  the `0xF001`/`0xF002`/`0xF003` schemas, and WAT/WASM/code hash stay pinned.
  [DR-0088](0088-0093-hardware-signing.md) implements S4a profile/preflight;
  [DR-0091](0088-0093-hardware-signing.md) records S4b app and Nano S+
  Speculos evidence; [DR-0092](0088-0093-hardware-signing.md) implements S4c
  Phase 1 host APDU/USB/HID and CLI selection; [DR-0093](0088-0093-hardware-signing.md)
  implements Phase 2a software app/firmware identity checks. S4c still awaits
  Phase 2b physical validation; none of this establishes production readiness.
- DR-0082: Add the bounded canonical Developer MVP query surface described in
  [product-surfaces.md §43](../product-surfaces.md#43-bounded-developer-mvp-query-api). Keep query selectors non-authoritative,
  resolve all chain/domain/epoch/storage authority from trusted composition,
  independently verify durable object and receipt content before returning it,
  encode absence and blob-unavailable state explicitly, and exclude scans and
  arbitrary state access. This is a stable client wire contract, not a public
  RPC security or production indexing architecture.
- DR-0083: Define the Developer MVP Rust client boundary described in
  [product-surfaces.md §44](../product-surfaces.md#44-rust-client-library). Share canonical result codecs through `node-wire`, keep the
  client independent of `native-http`/Axum and application semantics, provide
  only a bounded loopback HTTP transport initially, require caller-supplied
  request/module/object identities, and defer production networking and full
  protocol-config/hash verification rather than approximating them.
- DR-0084: Define the Rust-only `apps/cli` Developer MVP boundary and the
  Ledger-ready external signing boundary described in
  [product-surfaces.md §45](../product-surfaces.md#45-rust-client-external-signer-boundary-and-developer-mvp-cli). `apps/cli` has exactly one
  non-development/runtime dependency, `sunrise-edge-client` (test-only
  `[dev-dependencies]` exist to compose a real devnet and build fixtures for
  this crate's own tests, and are unreachable from any non-test build),
  parses arguments with a strict hand-written parser
  (no clap, no other argument crate), never accepts a seed directly on argv,
  and treats every development seed file as explicitly named, non-default,
  non-keystore input with symlink/permission/length checks. `clients/rust`'s
  new two-stage `PreparedTransaction` external-signer API is additive and
  keeps `build_signed_transaction`'s stable output bytes unchanged; it fails
  closed on any signature scheme other than the one implemented `Ed25519`/
  `AddressIsPublicKey` binding and independently verifies a returned
  signature's exact length and cryptographic validity before producing
  output. Real Ledger (or other external/hardware) signing is explicitly not
  implemented by this decision: it requires a dedicated Sunrise Edge Ledger
  device application, an APDU/host transport, on-device parsing and clear
  signing of the exact canonical signature frame, public-key/address
  verification, an explicit derivation-path policy, device/application/
  version checks, explicit user confirmation, host-side signature
  verification, and hardware-in-the-loop tests — none of which exist yet, and
  existing Solana/Ethereum Ledger apps must never be reused for Sunrise
  transaction signing. No USB/HID/Ledger dependency exists in any protocol or
  client crate. Devnet asset-transfer semantics (the module's entrypoint name
  and argument frame) live only in `apps/cli`'s `transfer` command; the small
  generic re-exports `clients/rust` adds to support it add no application
  semantics of their own.
- DR-0085: Adopt a CLI-first production strategy and add the CLI-First Node
  Production Gate. This is a sequencing decision, not a scope change: it
  reorders when work starts, and it does not complete, delete, weaken, or
  reinterpret any existing production criterion anywhere in
  [`TODO.md`](../../../TODO.md), [`docs/operations/persistence.md`](../../operations/persistence.md), or
  [`docs/operations/postgres.md`](../../operations/postgres.md).

  **Rationale.** The Developer MVP Gate ([DR-0076](0076-0080-developer-mvp-foundation.md), resequenced by DR-0081) put
  a browser-facing product surface (TypeScript client, explorer, wallet) in
  the same near-term gate as the node's own core capabilities (local devnet,
  owned-object execution, bounded query API, Rust client, Rust CLI,
  restart/duplicate E2E). That framing under-weighted the fact that the node
  itself — persistence, operations, and release evidence — is far short of
  the production posture `TODO.md`'s Phase 15 To-Be exit criteria already
  require, while a browser UI cannot usefully exercise a node that is not
  itself production-oriented. This decision narrows the near-term gate to the
  node/client/CLI capabilities that are implementable and independently
  verifiable today, renames it to make that narrowing explicit, and inserts
  an explicit node-production gate between it and the deferred browser
  surface.

  **Gate rename and resequencing.** The gate defined in `TODO.md` is renamed
  `CLI Developer MVP Gate`. Its criteria 1-6, 10, and 11 (local devnet,
  authenticated owned-object Read/Write/Consume, preinstalled deterministic
  WASM execution, bounded query API, Rust client library, Rust-only CLI,
  restart/duplicate E2E, and explicit non-production limitations) remain the
  near-term gate. Its criteria 7-9 (TypeScript client, explorer, wallet) are
  kept verbatim — not completed, not deleted, not weakened — and are
  explicitly deferred/resequenced to start only after the new CLI-First Node
  Production Gate below passes (see the "Amendment: gate renamed and
  resequenced by DR-0085" note on DR-0081's "Developer MVP order" above).

  **Current implementation status (2026-09-04).** CLI Developer MVP criteria
  1-6, 10, and 11 and S0-S3 are implemented and validated As-Is (S2 by DR-0086,
  S3 by DR-0087), without production-readiness authority. S4a is As-Is by
  [DR-0088](0088-0093-hardware-signing.md). [DR-0089](0088-0093-hardware-signing.md)
  clarifies eight S4b device-contract points in
  [`docs/signing/hardware-signing.md`](../../signing/hardware-signing.md) and corrects
  FIRST data 230→255 bytes/first chunk 205→230, leaving CONTINUE/LAST at 230.
  [DR-0090](0088-0093-hardware-signing.md) records the separate
  `sunriselayer/sunrise-edge-ledger-app` host-validated `no_std` core;
  [DR-0091](0088-0093-hardware-signing.md) records merged PR #2, five-target
  builds, and fixed-seed Nano S+ Speculos evidence, completing S4b As-Is.
  [DR-0092](0088-0093-hardware-signing.md) implements S4c Phase 1 host
  APDU/USB/HID, CLI selection, profile/address checks, and USB-descriptor
  recognition. [DR-0093](0088-0093-hardware-signing.md) implements Phase 2a
  software-only (`FakeTransport`) app/firmware identity, bounded Ledger OS/
  dashboard parsing, staged dashboard/firmware/open-app/reconnect/active-app,
  and required `--ledger-expected-firmware-version`. S4c awaits Phase 2b
  physical validation. [DR-0095](0094-0098-blobs-audit-and-documentation.md)
  defers S4c Phase 2b/S4d HIL/release evidence and makes S5 a parallel
  software-production track. TypeScript client, explorer, and wallet wait for
  the Software Production Gate (S0-S3 + S5), not deferred S4 hardware work.

  **S1 implementation status (2026-09-01): both remote TLS transport and
  expected-protocol-context verification are implemented and tested As-Is;
  S1 as a whole is complete.** `clients/rust::context::ExpectedProtocolContext`
  takes caller-trusted `chain_id`, `protocol_version`, exact `epoch`,
  `hash_suite_id`, `transaction_auth_profile_id`, `signature_scheme_id`,
  `address_binding_id`, and logical `AtomicityDomainId`. The caller must
  deliberately update the epoch on rollover; no floor, range, or automatic
  widening exists. Construction rejects zero for the version and four IDs;
  `ChainId`/`AtomicityDomainId` reject empty/all-zero values themselves, while
  genesis epoch zero is valid. This slice does not pin or decode
  `protocol_config_bytes` or approximate full `ProtocolConfig` verification.
  `verify` compares all eight fields with untrusted `/v1/context` in a fixed
  order, returning the first typed `ProtocolContextMismatch`;
  `Client::query_verified_context` returns nothing on mismatch. The logical
  domain is a routing/placement expectation, not an added
  `crypto::SignatureDomain` input; its existing bindings remain as in
  [core-protocol.md §8](../core-protocol.md#8-signature-domain-separation).
  Failures are typed `ExpectedProtocolContextError` or
  `ClientError::ProtocolContextMismatch`, without library panics.

  `apps/cli transfer` requires `--expected-chain-id`,
  `--expected-protocol-version`, `--expected-epoch`,
  `--expected-hash-suite-id`, and `--expected-domain` before network dispatch.
  Missing, zero/invalid, and malformed-hex inputs return `ArgsError::MissingFlag`,
  `ExpectedProtocolContextError`/`TypeError`, and `HexError` respectively.
  The one implemented auth/scheme/binding combination
  (`ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID`, `Ed25519`,
  `AddressIsPublicKey`) is supplied explicitly rather than exposed as flags.
  `transfer` uses only `Client::query_verified_context` and its verified
  result for nonce/object queries, transaction context, signing, and submit.
  Adversarial tests cover all eight mismatch variants and require exactly
  one context request before rejection, with no nonce/object/sign/submit.
  Stable wire bytes and existing parser, seed-file, two-stage signer, and
  owner checks remain unchanged; the prior three ad hoc CLI comparisons moved
  to the reusable client boundary, which adds the five S1a comparisons.

  **S1's remote TLS transport slice.** `clients/rust` adds
  `transport::RemoteTlsHttpTransport` beside the unchanged loopback-only
  plaintext transport. Both use private `BoundedTransportIo` for identical
  HTTP/1.1 framing, header/body bounds, and per-stage monotonic deadlines.
  The TLS path drives a real `rustls::ClientConnection` with deadline-checked
  `read_tls`/`write_tls`/`process_new_packets`, never unbounded `complete_io`.
  Its constructor requires an already-resolved `SocketAddr`, a nonempty DNS
  server name (SNI and hostname validation; IP literals rejected), and one
  valid X.509 DER trust anchor of 1–16 KiB
  (`transport::MAX_CA_CERTIFICATE_DER_BYTES`). It accepts no system roots,
  PEM/bundle, or client certificate. Nonzero connect/handshake/post-handshake
  timeouts form one checked hard request budget; `WireRequest::deadline` can
  tighten but never extend it. Real loopback TCP/`rustls` tests in
  `clients/rust/tests/remote_tls_transport.rs` use an ephemeral `rcgen` CA/
  leaf: valid name/CA and DNS `Host` succeed; wrong name/CA, stalled or
  prematurely closed handshake, short caller deadline, bad DNS/IP name,
  empty/oversized/invalid DER, and zero timeout fail as specified. A separate
  regression test pins plaintext framing byte for byte.

  All five CLI network commands (`context`, `object`, `receipt`, `next-nonce`,
  `transfer`) parse paired optional `--tls-server-name` and
  `--tls-ca-cert-der-file` flags centrally in `apps/cli/src/net.rs`, selecting
  `CliTransport::{Loopback,RemoteTls}` without changing their generic
  `execute<T: Transport>` bodies. Neither flag keeps loopback-only plaintext
  and `CliError::NonLoopbackEndpoint`; both permit an already-resolved remote
  `SocketAddr` without DNS lookup; one flag yields
  `CliError::PartialTlsConfiguration` before dispatch. The CA file uses a
  bounded `Read::take` (limit plus one byte); empty/oversized/read failures
  have typed path-naming errors that never expose contents. Real local TLS
  tests in `apps/cli/tests/tls_cli_e2e.rs` verify `context` and exact DNS
  `Host`, plus a mismatched-chain `transfer`: the server's connection counter
  sees only `/v1/context`, and the CLI returns `ProtocolContextMismatch`
  before nonce/object/sign/submit. TLS identity thus does not replace the
  independent expected-context check.

  **Explicit limits (not silently assumed).** The transport requires an
  already-resolved `SocketAddr` and one caller-supplied DER CA; it does no DNS,
  system-root, PEM/bundle, or mTLS handling. CRL/OCSP, CA rotation/lifecycle,
  and operator delivery of the CA file remain S5/operations work. TLS server
  identity and `ExpectedProtocolContext` are independent checks: neither
  substitutes for the other. S1 evidence is not production/mainnet
  certification; Phase 16/17 and independent audit still apply. At this
  decision point S2 cross-owner transfer was next.

  **DR-0086 amendment (current status).** The preceding "S2 is next" sentence
  records DR-0085's S1 completion point. S2 is now implemented and validated
  As-Is through the exact committed destination policy, with literal owner
  reassignment still deferred; S3 is now implemented by DR-0087. S4/S5, Phase
  16/17 exit criteria, and an independent security audit remain outstanding,
  so no production/mainnet readiness is claimed.

  **CLI-First Node Production Gate.** This new gate sits between the CLI
  Developer MVP Gate and the deferred browser surface. It is a real
  node/persistence/operations gate, not client-library work, and it is
  defined entirely by reference to existing, unchanged criteria:
  `TODO.md`'s Phase 15 To-Be production exit criteria (1-10); the Post-MVP
  Production Hardening Phase 15 persistence implementation order (steps
  1-6, covering the durable domain adapter boundary, the indexed due-outbox
  repository, the normalized PostgreSQL structured-durable schema and its
  shared conformance suite, real host/power-fault and capacity/backup
  rehearsal evidence, and real Cloudflare Durable Object/AWS provider
  certification); the cross-phase production release gate; the existing hard
  activation constraint that protocol version 3's live activation stays
  prohibited until shared-object ordering, FastVote/`FastCertificate`,
  certificate publication, and every externally accepted event family's
  authorization are implemented and atomically composed where protocol
  semantics require it, and, independently, until S4/S5 and the independent
  security/release gates are completed — the bounded S3 uniform ordinary-asset
  fee composition (DR-0087) and additive owned-effects/preinstalled-WASM
  module-object effects entrypoints are implemented As-Is, but on their own do
  not satisfy this constraint; and the existing hard activation constraint that
  every externally accepted node-event family other than `SubmitTransaction`
  (especially certificate, protocol-upgrade, and validator-set-change events)
  needs its own authenticated/authorized ingress boundary before live
  activation. Passing this gate is explicitly **not** mainnet readiness:
  Phase 16 (Cloudflare) and Phase 17 (Deno/Vercel/Supabase/AWS) To-Be
  production exit criteria and an independent security audit remain required
  afterward, unchanged.

  **Ordered slices, amended by
  [DR-0095](0094-0098-blobs-audit-and-documentation.md).** This decision originally sequenced
  the CLI-First Node Production Gate as S0-S5 (see
  [CLI-First Node Production Gate](../../development/history/roadmap-through-2026-10-06.md#cli-first-node-production-gate)).
  [DR-0095](0094-0098-blobs-audit-and-documentation.md) preserves S0-S3 as the
  common baseline but supersedes the strict S4-before-S5 ordering: S4 and S5
  are independent parallel tracks.

  - S0: an automated restart/duplicate E2E, plus a separate documented
    command sequence that reproduces the local devnet/CLI experience (start,
    transfer, receipt, orderly restart, persisted state) by hand — not the
    raw byte-identical duplicate replay itself, which only the automated E2E
    proves (implemented As-Is by this decision; see criterion 10,
    `apps/cli/tests/devnet_restart_duplicate_e2e.rs`, and `docs/guides/devnet.md`).
  - S1 (implemented As-Is; see "S1 implementation status" above): remote TLS
    transport and mandatory trusted protocol-context validation before
    signing, as two separate concerns. The transport performs normal TLS
    server-identity and hostname validation under an explicit trust policy
    (this slice's `RemoteTlsHttpTransport` uses one explicitly configured
    CA/anchor and DNS name, never a system CA store); this does not require
    brittle leaf-certificate pinning as the only valid TLS trust design.
    Separately, because a successful TLS handshake authenticates the
    transport endpoint, not the protocol context, a valid TLS connection
    alone does not prove the remote server speaks the client's intended
    chain/protocol and does not by itself prevent cross-chain signing. The
    client/CLI therefore also requires a locally configured expected chain
    identity and protocol policy, and compares the remote `/v1/context`
    result's chain id, protocol version, epoch policy, signature scheme,
    address binding, and transaction auth profile against that expectation
    before any signing occurs.
  - S2 (implemented As-Is by DR-0086): cross-owner transfer through an exact
    committed destination-owner policy on the trusted preinstalled-module
    path. The roadmap phrase "object owner changes" means correct handling of
    differing source/destination owner projections; it does not authorize
    literal owner reassignment, which remains fail-closed.
  - S3 (implemented As-Is by DR-0087): uniform ordinary-asset fees and actual-
    gas metering on the local preinstalled-WASM devnet path, including
    deterministic trap fee-only settlement and restart/replay evidence.
  - S4: a secure signer replacing today's development-only `LocalSigner`, and
    a real dedicated Sunrise Edge Ledger integration (see
    [product-surfaces.md §45](../product-surfaces.md#45-rust-client-external-signer-boundary-and-developer-mvp-cli) and DR-0084; existing
    Solana/Ethereum Ledger apps are never reused).
  - S5: production persistence, outbox operation, provider deployment
    (Cloudflare Durable Object/AWS), operations (observability, runbooks),
    security (independent audit), and release evidence (migration/backup/
    disaster-recovery rehearsal, reproducible build) — i.e., the Post-MVP
    Production Hardening persistence implementation order above.

  Capacity/load/soak, PITR, and HA/failover evidence stay frozen exactly as
  the existing freeze already states, until S5's own certification or an SLO
  actually requires one of them; this decision does not add or relax that
  freeze.

  **Production target.** The conservative production target this gate and
  the existing validator-set/consensus criteria are sequenced toward is a
  multi-validator L1, not a permanently single-operator service. Nothing in
  this decision narrows validator-set, bond, or consensus criteria to a
  single-validator design; the devnet's current single-validator posture
  remains an explicit MVP-only limitation (see
  [product-surfaces.md §42](../product-surfaces.md#42-local-devnet-architecture)), not the production target.
- DR-0086: Implement S2 as a bounded committed cross-owner destination policy,
  without introducing literal object-owner reassignment.

  **Roadmap interpretation.** DR-0085's S2 phrase "destination-owner
  authorization and object owner changes" means correctly loading,
  authorizing, preserving, and committing different source/destination owner
  projections. It does not mean gifting or reassignment of an object's owner.
  Existing effect translation still requires an updated object's owner to
  equal its authenticated pre-state owner, so literal reassignment remains
  fail-closed and deferred.

  **Generic committed envelope.** A trusted `PreinstalledModuleCatalogEntry`
  now carries a bounded `PreinstalledModuleSemanticsEnvelope`: opaque
  application-semantics bytes (at most 64 KiB) plus at most 16 sorted,
  unique-index `PreinstalledObjectAccessPolicy` records. The policy and
  envelope use stable canonical type IDs `0xE007` and `0xE008`, encoding
  version 1, with stable encoding vectors. `SystemModule.semantics_hash`
  commits the exact full envelope bytes, not only the opaque application
  declaration. Both startup registry/catalog reconciliation and request-time
  module resolution independently encode and verify the actual trusted
  envelope bytes. No request field, storage projection, or caller-supplied
  digest can create or widen a policy.

  **Authorization and ordering.** The sender still owns signed access index 0,
  and the general owned-effects entrypoint remains sender-only. On the trusted
  preinstalled-WASM path only, a policy may authorize a non-sender existing
  `Owner::Address` object at one exact nonzero signed access index, exact
  entrypoint, `AccessMode::Write`, exact type hash, and exact schema version.
  Policy resolution occurs exactly once per non-replay execution, after receipt
  and nonce reconciliation but before object I/O; the resolved module is reused
  for authorization and execution. Therefore an exact replay still reconciles
  before policy/module/object work and never reapplies effects. Source-index
  policy, `Read`/`Consume`, wrong index/mode/type/schema/entrypoint/module,
  missing policy, and Shared/System/Immutable ownership all fail closed.

  **Devnet policy and startup.** The devnet catalog declares exactly one policy:
  signed destination index 1, `transfer`, `Write`, the exact asset-account type
  hash, and schema version 1. The opaque devnet semantics states that source
  index 0 is sender-owned, the existing destination may have another Address
  owner, and both owners remain unchanged. Startup seed reconciliation no
  longer assumes per-owner source/destination balance totals or paired
  sequences, because legitimate cross-owner movement invalidates both
  assumptions. It still verifies exact current owner/id/type/schema/canonical
  body/digest/provenance, immutable version-one history, and the seed receipt
  for every account, then performs one checked global fixed-supply invariant
  over the bounded configured-owner set before serving.

  **CLI and evidence.** `apps/cli transfer` requires an explicit
  `--destination-owner <32-byte-hex-address>`. Before signing it requires the
  queried source owner to equal the local signer and the queried destination
  owner to equal that explicit expected address. The real file-backed SQLite
  E2E seeds separate sender and recipient owners, transfers into the recipient
  destination, proves both balances change and the recipient owner remains
  unchanged, closes every store/router reference, reopens under writer
  generation N+1, and proves exact same-boot and post-restart request replay
  returns byte-identical submit/receipt results without reapplication. Reusing
  a committed request ID with different signed bytes returns HTTP 409 while
  both canonical object query results, both relevant receipts, and the sender
  nonce remain unchanged; the old writer generation remains fenced.

  This implementation preserves established canonical transaction,
  `ObjectEffect`, `Object`, receipt, nonce, and submit-result bytes. S2 is
  implemented and validated As-Is only. DR-0087 subsequently replaces the
  fee-free devnet posture while preserving S2's exact policy and historical
  vectors. The TypeScript client, explorer, wallet,
  S4 secure signer/Ledger work, and S5 persistence/provider/operations/release
  evidence remain deferred, and Phase 16/17 exit criteria plus an independent
  security audit remain mandatory.
- DR-0087: Implement S3 as uniform ordinary-asset fee composition on the
  trusted preinstalled-WASM devnet path, without changing historical wire,
  WAT/WASM, or storage bytes.

  **Admission and settlement.** The committed protocol configuration uses
  non-zero base/execution prices and enables exactly `DEVNET_ASSET_ID` at a
  1:1 quote. A due fee requires signed `FeePayment`; its `max_fee` must cover
  the worst case at `gas_limit` before engine work begins. The final charge is
  computed only after execution from canonical `ExecutionEffects.gas_used`.
  Successful application effects are merged with the fee debit/credit and
  committed atomically with state, nonce, receipt, and outbox. A deterministic
  trap is normalized first, discards every application effect/event, charges
  its normalized full gas through a restricted fee-only mutation, and commits
  a Rejected receipt. An insufficient payer balance after successful execution
  rejects the whole transaction, so execution work may be spent without a
  commit; this bounded devnet limitation is not production admission policy.

  **Schedule-shape invariant.** S3 only ever measures `execution_units`:
  every `fees::FeeUsage` the preinstalled-WASM machine builds leaves
  `state_read_units`, `state_write_units`, `storage_units`, and
  `system_module_units` at their default zero. Before fee admission or the
  engine ever runs, it independently validates the committed `GasSchedule`'s
  shape (`fee_effects::validate_gas_schedule_shape`): a non-zero
  `read_price`/`write_price`/`storage_price`/`system_module_price` is
  rejected as `NodeCoreError::UnsupportedGasScheduleShape` rather than
  silently multiplied by zero usage and dropped from the total by
  `fees::calculate_fee`, and a non-zero `execution_price` paired with a zero
  `base_fee` is rejected the same way, because a legitimate zero-`gas_used`
  success could otherwise settle a zero fee even though worst-case admission
  at `gas_limit` already required a treasury `Write`. The genesis all-zero
  schedule and the current devnet `base_fee`/`execution_price`-only schedule
  both pass unchanged. This is a trusted committed-configuration fault, never
  a caller-supplied one; native HTTP maps it to an opaque `500
  fee-schedule-unsupported`, distinct from every caller-facing 4xx fee code.

  **Ordinary accounts and trusted boundary.** The payer is one sender-owned
  declared `Write` object and the trusted fee sink is the distinct configured
  treasury owner's ordinary seeded destination account. The signed manifest
  names that treasury exactly once as its final `Write`, but node-core removes
  it before invoking WASM. The module therefore still observes exactly the two
  source/destination objects and cannot redirect, inspect, or authorize the
  fee sink. The pure `AssetAccountFeeComposer` receives only opaque effective
  payer/treasury bodies and a settled amount, uses the existing strict
  `0xF001` codec, checks matching asset IDs and checked balance/sequence
  arithmetic, and returns two bodies. Node-core independently freezes identity,
  owner, type/schema, provenance, and object version; a no-op or malformed
  trusted composition fails closed. One successful transaction advances each
  touched durable object version once, while the payer body sequence advances
  once for the application transfer and once for the fee mutation.

  **Catalog compatibility.** The active module and semantics declaration move
  to version 3 solely to commit the new host-side fee/treasury/event facts.
  Historical v1 same-sender and v2 cross-owner declarations remain exact
  pinned vectors and are not installed. The asset body/args/event encoding
  remains v1, the WAT/WASM bytes are unchanged, and a fixed-context canonical
  code-hash test pins the same artifact. The transfer event is deliberately
  pre-fee module output: `source_balance` is the balance after transfer but
  before settlement; the durable source object is lower by `base_fee +
  gas_used * execution_price` under this profile.

  **CLI, startup, and evidence.** Devnet configuration requires a treasury
  owner distinct from all transfer owners and reserves one of the 64 seed
  slots for it. Startup seeds/verifies all owners, selects the treasury
  destination, and wires it with the composer into the native router. CLI
  `transfer` accepts the all-or-none `--fee-asset-id`/`--max-fee`/
  `--fee-treasury-object` trio, fixes source as fee object, queries treasury
  last, and appends its final `Write`; partial input, zero max fee, or treasury
  collision fails locally. Native HTTP assigns explicit 4xx classifications
  to caller fee faults and 5xx classifications to trusted policy/composition
  invariant failures. The real file-backed SQLite E2E proves a successful
  actual-gas charge, event pre-fee semantics, and a trapped fee-only charge,
  then replays both the successful and the trapped request once in the same
  boot and once after an orderly close/reopen: every replay returns
  byte-identical canonical submit-result bytes and mutates neither the
  canonical source/destination/treasury query bytes, the second-transfer or
  trapped receipt, nor the sender's next nonce. It also proves
  writer-generation advancement/fencing and request-ID reuse conflict with
  the same canonical source/destination/treasury query bytes, all three
  receipts, and nonce unchanged.

  **Limits and next step.** This is single-validator, one fixed fee asset, one
  serializing treasury, and local SQLite only. It does not implement fee
  distribution through `FastCertificate`, multiple governed fee assets,
  production gas calibration, sufficient-balance preflight, treasury sharding,
  Shared/System/blob objects, or crash/power-loss durability. TypeScript,
  explorer, and wallet stay deferred. [DR-0088](0088-0093-hardware-signing.md) implements S4a's hardware
  profile/host preflight, [DR-0091](0088-0093-hardware-signing.md) records S4b's dedicated device application
  and Nano S+ Speculos evidence As-Is, [DR-0092](0088-0093-hardware-signing.md) implements S4c Phase 1's
  host/CLI integration As-Is, and [DR-0093](0088-0093-hardware-signing.md) implements S4c Phase 2a's
  active-app/firmware identity check As-Is, strictly in software (S4c itself
  remains incomplete). S4c Phase 2b's physical-device evidence and S4d are
  next. S5, Phase 16/17 exit criteria, and independent audit remain
  mandatory.
