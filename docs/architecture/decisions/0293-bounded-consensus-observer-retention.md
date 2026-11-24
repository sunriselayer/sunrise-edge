# DR-0293: Bounded consensus observer retention and certified-body recovery

Date: 2026-11-14 (Asia/Singapore)

Status: Selected defensive cache policy; codec compatibility retained.

## Context

`process_observed_proposal` admitted every distinct valid signed
leader/view/height digest. Height-only `ChainedHotStuff::prune_state`
then kept all same-height speculation. One enrolled Byzantine leader,
without a quorum, could fill the existing 4096-proposal / 16 MiB
`0xD010` encode cap. The next authorized persist then failed, and an
authentic certified body could no longer progress.

The `0xD010`/`0xD011`–`0xD016` v1 layouts, type IDs, version, and
stable vectors are unchanged. Saturated historical v1 bytes must still
decode and re-encode identically; compaction happens on the next
authorized event. Safety, signed domains, proof semantics, signing
gates, and public two-phase replay result structs stay as they were.

## Decision

Shared `prune_state` (both `on_event` and `on_observer_event`) becomes
the single bounded cache owner and may fail closed.

Certificate age, observed/pending vote equivocation age, local identity
watermarks, and proof-before-prune order are preserved. Protected
proposal bodies are those named by retained certificates, `high_qc`,
`locked_qc`, `last_voted_digest`, and committed digests inside the
existing two-height window, plus the available parent walk that connects
those roots through the committed boundary. The walk does not continue
to genesis and does not use a 64-step ancestor cap. A missing referenced
root is protected when its body later arrives. Partial pending votes do
not pin speculative bodies.

Unprotected speculation keeps the canonical minimum digest per
`(view, leader)`, independent of arrival order. Remaining candidates
are admitted newest-view-first with canonical leader/digest ties, inside
the existing 64-view horizon, an explicit finite speculative count, and
the shared encoded-state byte budget. Protected cost is derived once
with the existing codec helpers; optional entries are charged
incrementally. Protected material that already exceeds the codec caps
fails closed. Proof, lock, and vote material is never dropped to make
room.

After an observer body is validated, inserted, and justified, if no QC
is stored for that digest the engine retries `try_form_certificate` and
emits only `Certificate`, never a local `Vote`.

Signerless ordered-economics replay keeps whole-prefix authentication
and zero POST on an invalid artifact. After observe then certificate, if
the QC acknowledgement is `Applied` with an empty committed list, it
sends at most one extra observe of the exact preverified proposal bytes.
A nonempty certificate commit skips that step. Extra-observe failure is
attributed separately and does not relabel the QC acknowledgement.
`ReplayRoundOutcome` / `PeerResult` stay two-phase; detailed replay
exposes `NotRequired` / `Skipped` / failure. `record_peer_result` is
not called a third time. CLI `network-replay` writes the extra
attribution to a reserved `.rehydration` sidecar and leaves `.results`
as the closed five-field, two-record-per-peer format.

## Consequences

Honest certified progress can recover a previously evicted competing
body. Byzantine same-view equivocation can no longer fill the persist
cap. Cache contents after an authorized event may differ from a
saturated historical v1 snapshot; the snapshot itself remains a valid
v1 frame. This is not a protocol-upgrade, a new wire type, or a TODO
completion.
