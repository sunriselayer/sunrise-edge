# DR-0268: Certified FastVote protocol custody worker

Date: 2026-10-17, Asia/Singapore

Status: Implementation design. Execution qualification belongs in TODO.

Use a distinct, closed Linux deployment profile for the current certified
FastVote Native router: all 21 contract routes plus liveness. Reuse the original
SQLite startup, live committee/key checks, mandatory enrolled independent anchor,
lease, single writer-fence claim and actual certified router factory. Keep the
validator key, invocation context, signing and confirmed retention with that
worker. The frontend owns public genesis/context pins and HTTP/TLS delivery,
with no validator key, database, anchor handle or signing-frame interface.

The existing ordered modes and IPC version 2 remain unchanged. New modes use a
separate private framing identity and version; neither profile accepts the
other's requests or responses. Only bounded, enumerated existing HTTP operations
cross IPC. Preserve every original handler's extraction, media/header precedence,
selector errors, ignored GET bodies, status and response bytes. Preserve original
per-route limits, including 32 MiB complete publication inputs. No generic proxy,
raw signing endpoint, automatic transport retry or fallback is introduced.

The worker's new configuration explicitly supplies the trusted local
`created-checkpoint`, including an explicitly chosen zero. Neither HTTP, clock
nor frontend supplies it. Real core owners still decide authority, state,
Freeze, replay, execution and commit status. Exact historical receipt replay is
not rejected by an extra frontend current-epoch gate. The frontend independently
verifies returned FastVote, availability and original frozen-frontier signatures
and their request/endpoint bindings with existing certifiers and pure codecs.
Unsigned results retain canonical request/target binding without implying an
independent durability proof. Only the worker's confirmed whole results return;
uncertain commit or lost delivery provides no successful fresh signature.

The entire current factory includes FastVote prepare, availability ACK and
original frozen-frontier signing, plus unsigned state-owning drain routes.
Successor, fee-claim, admin and generic signing are excluded. Ordinary combined
hosting and the executable inventory remain unchanged. This profile is a
mutually exclusive deployment owner, never a concurrent writer beside another
host. Both sides authenticate exact peer UIDs before IPC bytes, use finite
bounds/deadlines and drain started work before releasing source/lease ownership.

Trusted local OS/root and worker code remain inside the selected boundary.
This design makes no hardware, compromised-worker, public-service or all-M2
qualification claim. No stopped task is continued by this slice.
