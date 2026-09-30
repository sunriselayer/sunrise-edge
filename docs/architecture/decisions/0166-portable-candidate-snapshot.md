# DR-0166: Consistent portable candidate enumeration

Date: 2026-09-30

Status: Accepted direction; implementation and evidence are tracked in TODO.

## Context

DR-0165 verifies a local candidate-free terminal and receipt-backed ordered
history. Existing portable storage reads fence each record, but do not pin a
multi-page source. A barrier or a source-declared digest cannot supply either
snapshot consistency or authority for all business state.

## Decision

Add a stronger optional runtime contract. A local token binds the exact
namespace/domain, writer generation and a checked monotonic mutation sequence.
Independently bootstrapped SQL stores also persist a random 16-byte source
instance identity. Same logical namespace, writer and sequence must not accept
another database's token. A cloned backup still needs operator refencing; the
instance ID alone does not distinguish a byte-identical restore. The provider
advances that sequence in the same transaction as every write to
the covered state/object/receipt/outbox collections. Old/legacy entry points
must participate or the provider must refuse this contract. Guarded page,
descriptor, chunk and outbox reads compare the token inside their own read
snapshot, never in a separate advisory check. Unsupported schemas fail closed.
Use PostgreSQL's existing namespace commit sequence rather than introducing a
second protocol counter; complete its outbox coverage. Memory and shared SQL
use the same checked contract. Rolled-back writes cannot advance the sequence.

Build a bounded **candidate** enumeration, with exact keys, explicit deletion
tags, original receipt bytes, canonical record/chunk identities and resumable
running commitments. Preserve physical descriptors only as source-local
fences, separate from content commitments. Closed reserved-family classifiers
refuse unknown protocol keys. Retain authenticated history; do not treat the
entire fastpath namespace as a cache. Blob content is outside the structured
token: retrieve immutable references in bounded ranges and independently check
content before a later authenticated import.

Progress must not mutate its own source. Keep it under a separate local
namespace/domain and its own CAS/writer fence. This means progress publication
cannot atomically fold U14's source CAS read set across domains. A locally
certified terminal attached to this candidate is **not atomically fenced cut
authority**. Seal must rederive and bind the real terminal and full replay
closure; a progress row or candidate root is never a substitute.

Transport verification against an externally pinned candidate root proves only
that those source records arrived intact. It does not prove that the source's
business state is legitimate, that dependencies are complete, or that all
replicas have the same semantic state. No target eligibility marker, signature,
readiness, Seal or activation may follow from this phase. Exact history bytes
may include legacy signed checkpoint operands or equivalent QC subsets; a
candidate transfer root is not the final normalized logical-state root.

## Consequences and remaining gate

Conservative invalidation includes local/control writes and therefore requires
a quiet source to complete a candidate. This is safe refusal, not guaranteed
handoff liveness. PostgreSQL already serializes ordinary namespace commits on
its metadata row; including outbox writes extends that boundary. Do not claim
unmeasured throughput or load/soak readiness.

Complete authenticated handoff still requires independent signed-genesis and
causal fastpath/economics replay, full artifact/dependency closure, logical
normalization, a signed cut decision, conditional next-set readiness, Seal,
activation, fresh-genesis gating and independent PostgreSQL network E2E.
Draft PR #235 remains incomplete Delivery 3 and is not merge-ready.

Required negative evidence includes a legacy-path mutation, mid-page/chunk
change, changed writer/domain/namespace, unsupported schema, duplicate,
reordered or foreign continuation, tombstone versus absence, legal large
payload continuation, restart and atomic overflow refusal.
