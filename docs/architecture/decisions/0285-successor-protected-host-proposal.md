# DR-0285: Successor protected host proposal

Date: 2026-11-03, Asia/Singapore

Status: The human selected the trusted local OS and distinct-process/UID
boundary for successor signing on 2026-11-03. The role-specific transport and frontend verification have a development
implementation. This record selects no release profile or provider. The original recurring selector later passed with two distinct-UID markers,
seven epoch ends and e8 terminal unlock on exact source `049dcd59` (external
receipt `n2-049d-retry1-terminal-1104/root-verification.md`). That bounded
result remains separate from later-source complete required, CI and release
qualification in TODO. Existing original ordered and certified
FastVote worker approvals do not extend to a serving successor.

## Actual consumer and authority

[`successor_host serve`](../../../apps/operator/src/successor_host.rs) currently
loads a software Ed25519 key and composes the signer, verified chain artifacts,
SQLite writer, blob store and Native HTTP listener in one process. Its
`HostAuthority` resolves the live successor warrant against the current store
and held artifacts for each storage-touching request. The
[`successor_router`](../../../crates/native-http/src/successor.rs) then enters
the existing core owner under that fresh warrant. It refuses an original
genesis namespace and direct mutation routes; no cached warrant or caller
assertion can authorize a later request.

Actual successor signing consumers are ordered proposal, vote and Tick, FastVote
prepare, availability ACK and a finalized frozen-frontier vote. The router also
contains query, apply, history and drain controls that do not invoke the signer.
Their state and fence ownership cannot be split from a new signer by assuming that a signature
frame alone proves live authority. `serve-history` is a separate keyless
historical-read mode; it must not gain a signing route.

[DR-0264](0264-original-ordered-protocol-custody-worker.md) protects only the
original ordered host. [DR-0268](0268-certified-fastvote-protocol-custody-worker.md)
protects the current original certified host. Their private protocol and
runtime evidence do not establish protection for this successor host.

## Selected boundary and proposed composition

Under a trusted local OS, run the whole existing successor composition in a
distinct-UID worker: signer key, verified chain artifacts, startup resolution,
SQLite writer, blob store, current writer fence and per-request fresh warrant
stay together. A keyless TLS/HTTP frontend may admit only the existing bounded
successor route set through authenticated local IPC. It owns no key, artifact
directory, database, independent anchor or `ConsensusSigner` port. The worker
keeps the current trusted local genesis/context/hash schedule, domain,
validator ID and `created-checkpoint` pins. HTTP bodies and peer claims may
declare an epoch where the existing route permits it, but neither they nor the
frontend can authoritatively select a key, epoch, domain, checkpoint, signing
frame or authority role.

The worker reuses `successor_router`'s route-specific decoding and the core's
fresh serving, committee/key, possession/eligibility and confirmed-retention
checks. The frontend does not reimplement those decisions or accept a raw
`sign_framed(bytes)` endpoint. Where an existing route commits, successful
output follows its confirmed commit or exact reconciliation; query and
liveness routes keep their existing separate response rules. Where a successful
result includes a signature, frontend verification must bind independently
trusted successor public context and committee, endpoint and request to the
existing pure certifier or codec. The original certified frontend's genesis
committee is not the successor committee and cannot be reused unchanged.
The worker's reply or query is not a trust root for this public context;
the frontend needs independently pinned public successor evidence or another
separately reviewed derivation before implementation. Signature validity
alone does not grant a fresh serving warrant.

This proposal is one mutually exclusive successor-host mode, not another
writer beside the ordinary combined host. It does not enlarge original worker
routes or let the frontend use the keyless `serve-history` route to reach
signed output. Preserve existing HTTP extraction, media/header precedence,
status and replay bytes, including refusal and old-epoch behavior. Private
IPC framing must identify this role distinctly, bound request and response
bytes, authenticate exact peer UIDs before dispatch, and impose finite
admission/deadlines. A lost reply is not a safe automatic retry; a started
operation must drain before key/store/fence ownership is released. A failed,
timed-out or abandoned delivery refuses only its own connection. The serial
worker waits for its owning blocking executor to drain before accepting another
request under the same fence; a lost reply never yields a successful result.
The frontend's startup preflight spends one worker connection and one internal
worker request, but does not spend the configured public request budget. The
worker reserves that request and requires `--max-connections` to exceed
`--max-requests`, so a one-public-request configuration can still serve after
preflight. Uncertain commits use the owning exact reconciliation path, with no
successful output unless it confirms the retained result.

Same-identity key recovery requires old writer exclusion and the existing
retained safety history. A different identity needs the existing authorized
membership/epoch path; changing a key file is not rotation of validator
authority. This profile claims neither independent rollback detection nor
protection from a compromised worker or root. No real keys, host users,
security policy or deployment are authorized here.

## Original implementation checklist and remaining verification

The prospective wording below is the original design checklist, not a live
implementation status. The exact-`049dcd59` distinct-UID original recurring selector has bounded
success evidence; later-source complete required, CI and release evidence
remain separate. Consult [TODO.md](../../../TODO.md) for current status.

Inventory the exact existing successor route/method/body limits and settle the
frontend's independent public successor context before adding the private
transport. Reuse the current host factory, core and bounded IPC/UID/socket
primitives rather than copying the original/certified route table or adding a
second consensus implementation. Preserve `serve-history` as a separate
keyless constructor. Keep the original seven-epoch and withdrawal checks in
the existing ignored owner
`compiled_registered_replacement_and_recurring_successor_hosts` in
[`conditional_readiness_sqlite.rs`](../../../apps/operator/tests/conditional_readiness_sqlite.rs).
Extend that owner for selected worker/frontend behavior, wrong-key and UID
refusals, response loss, restart and unchanged replay only where its current
assertions do not already cover them. No short duplicate recurrence test can
replace that run. An implementation change then needs the existing exact-source
required gate, hosted CI and relevant RELEASE/UID evidence.

Detailed role permissions, local pin ownership and recovery authority require
review before release qualification. This document does not close M2-N2, M2 or any
independent security/release gate. Progress remains in [`TODO.md`](../../../TODO.md).
