# DR-0296: Certified preinstalled SubmitTransaction admission

Date: 2026-11-25 (Asia/Singapore)

Status: Proposed. Pure candidate validation is implemented; certification,
application, reconstruction and activation are not.

## Scope and existing owner

The first additional causal family is only an authenticated
`NodeEventKind::SubmitTransaction` executed by the existing preinstalled-WASM
owner. Its inner `Transaction` has a verified sender signature and access
manifest, the outer event binds the original request ID and context, and the
machine declares no opaque application state keys. It requires at least one
authenticated object access and produces no outbound message. Other NodeEvent
kinds, arbitrary `TransactionalNodeStateMachine` callbacks, and direct
publication/local/paid endpoints gain no authority from this decision.

The new pure candidate check accepts only a locally verified, signed
`CausalAdmission` genesis profile for the same chain and protocol version,
the existing Owned request-ID lane, and a nonempty manifest accepted by the
owned-object dispatch validator. It performs no store I/O, vote or mutation.
Current `require_historical_direct_writer` refusal remains unchanged.

## Certified input, conflict and effect boundary

The future preparation owner must authenticate the exact canonical outer
event and signed inner transaction under the committed `ProtocolConfig`,
including the committed system-module record (or its absence), installed
catalog entry and semantics envelope, fee schedule/assets and trusted fee
composer configuration. Neither an HTTP route nor request bytes may select
those capabilities. The certificate subject must bind both the outer
`HashPurpose::NodeEvent` digest and inner `HashPurpose::Transaction` digest,
the original request ID, chain, protocol version, epoch, sender and nonce.

Preparation must CAS-reserve the same sender/epoch nonce and every exact
`(ObjectId, version, digest)` declared `Write`/`Consume` input, including a
fee payer and trusted treasury when charged. Read-only inputs need full
head/version/content assertions; a derived created-object ID needs an absence
assertion. The owned path's existing owner/type/ABI/fee checks still govern;
shared or system-owned mutation is not inferred from this event. Use the
current FastVote object/nonce lock keys so a paid or event prepare cannot
silently race a direct writer. The prepared original-request slot and receipt
namespace must be shared across paid and event families: a collision of the
same request ID must leave at most one certified interpretation, regardless
of which family prepares first. A different record type in that slot must
fail closed, not become a matching lock owner merely because its raw request
ID matches.

The versioned prepared-effect witness must cover the exact deterministic
result of the existing preinstalled-WASM transition: canonical accepted or
rejected `NodeOutput`, charged fee and payer/treasury effects, all validated
object head assertions and mutations (including synthesized owner transfer
or creation and authority), the sender next-nonce write, exact original
receipt bytes, any internal logical provenance, and the complete verified
semantic dependency observations/generation. Its outbox field is explicitly
empty for this owner. It must exclude per-store physical CAS revisions and
installation coordinates while retaining their commit assertions. Prepare
signs only a hash derived from this locally computed witness; apply re-runs
the owning transition and compares its full witness, lock set and prepared
record to the certificate before one atomic commit. An unsigned caller-supplied
effect digest cannot substitute for that derivation.

Use a distinct canonical witness type/version and a distinct vote/certificate
signature family from paid FastVote and ordered economics; do not extend
`0x6424/v2`, `FastVote` v1, or `OrderedCandidate` v1 in place. Allocate IDs and
hash/signature domains only with the owning prepare/apply implementation and
stable Rust plus independent vectors. Exact replay remains receipt-first and
preserves old bytes. This decision fixes the fields and authority boundaries,
not a premature wire layout.

## Reconstruction and activation

Before a new certificate can be admitted on a handoff-capable chain, the
verified owned-publication and private reconstruction owners must recognize
this distinct producer, authenticate its exact event/transaction and quorum,
reexecute the same preinstalled module and fee effects, place it by verified
dependencies relative to ordered events, and compare the full receipt and
semantic state against the source. Unknown producer schemas continue to
refuse. Old paid and ordered history remains readable and verifiable.

Activation requires a separately selected protocol version bound by signed
genesis and a matching installed profile; no existing causal genesis becomes
permissive merely by upgrading software or mounting a route. The concrete
version and identifiers belong to the coherent certification implementation.
Until prepare/apply, reconstruction, fault/replay tests and host composition
exist, the pure candidate check is neither a mutation capability nor a beta
qualification. Required negative tests include wrong lane/context/profile,
cross-family request-ID reuse, foreign and stale locks, stale nonce, effect
or certificate substitution, replay after epoch change, and ambiguous commit
recovery; positive tests must cover multiple validators and independent
source reconstruction.
