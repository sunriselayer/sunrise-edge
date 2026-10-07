# DR-0209: One consensus-owned Ed25519 verifier adapter

Date: 2026-10-07 (Asia/Singapore)

Status: Accepted design. Fresh independent read-only Codex fallback returned
DESIGN APPROVE on 2026-10-07 after actual source inspection; Opus/Sonnet were
weekly-limited. This is not source, security-audit or release approval. Progress
and acceptance belong in [TODO.md](../../../TODO.md).

## Context

`ConsensusVerifier` is defined in consensus. Three production adapters in
node-core independently construct the same `crypto::Ed25519Verifier` and verify
the same supplied frame. SDK, native ingress and operator consumers import a
core implementation for this public consensus contract. Consensus already
depends on crypto, so moving its adapter there needs no new crate or Cargo edge.

These adapters intentionally differ for an unsupported scheme: FastPath returns
an authenticator error with `fast-path phase 1 supports only Ed25519`; ordered
economics and reconstruction return `Ok(false)`. This changes observable
classification, so neither behavior may silently become the other.

## Decision

Define one public `Ed25519ConsensusVerifier` alongside `ConsensusVerifier`, with
an explicit closed choice of unsupported-scheme response. Require construction
to name that choice; no implicit default, arbitrary error string, new signature
algorithm or generic verifier framework is needed. Preserve both original
responses and the existing malformed-key/signature errors. Share only the
crypto adaptation, not caller authority or registration checks.

Migrate every production consumer: FastPath and its certificate/publication/
drain users; ordered policy/history/frontier/engine; reconstruction/control/cut;
genesis, evidence, epoch and economic verification; SDK FastVote/publication/
frontier/drain/ordered clients; native ordered/successor hosts and operator/CLI
consumers. Each retains its original unsupported-scheme choice. Delete all
three old production implementations and their imports; do not leave obsolete
core wrappers or compatibility aliases in this unreleased API. The SDK's public
verifier export comes directly from consensus, with all repository consumers
migrated together.

Registered keys, validator identity, signature scheme, context, membership,
quorum and historical/live provenance remain with the owning consensus/core
verifier and caller. The adapter only verifies the supplied key/frame/signature;
it must not select keys from a peer, mint authority, access runtime/storage or
normalize message framing. Keep signature domains and every canonical byte,
vector and error precedence unchanged. Independent test verifier implementations
remain useful separate oracles rather than production duplication to erase.

## Acceptance and limits

Capture and preserve the prior outcome matrix: authentic Ed25519 signature,
wrong key/frame, malformed key/signature and both unsupported-scheme responses.
Run new adapter tests and existing consensus, SDK, core, native and operator
positive/adversarial controls. Source inventory must show one production
adapter and actual migrated callers, not an unused type. Full required local
acceptance and fresh complete exact-head source approval plus CI precede merge.

This removes three defining production implementations and the public SDK
verifier's reverse coupling. Other genesis, successor, publication and query
contracts still depend on node-core: do not remove a required Cargo dependency,
claim a standalone SDK or assert a compilation speedup without evidence.
That wider ownership design remains separate. No protocol, signing backend,
provider qualification, new authority or mainnet gate completion is introduced.
