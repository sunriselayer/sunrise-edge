# DR-0214: Protected custody and trustworthy review boundary

Date: 2026-10-07, Asia/Singapore

Status: Proposed contract and threat-model comparison. No replacement custody
backend, trusted review surface or production qualification is selected.

## Context and scope

[DR-0208](0208-native-sqlite-first-and-protected-signing.md) selects Native plus
SQLite first and DO later, and removes mandatory Ledger mainnet completion.
Key protection, authority separation, exact content review, refusal/failure,
recovery, rotation and revocation remain required. These are distinct from
SQLite durability and the choice of a vendor or deployment profile.

[DR-0211](0211-external-signing-preparation.md) and
[signing preparation](../signing-preparation.md) supply immutable operation
owners and mechanical signature checks. `PreparedSigningFrame` checks the
configured account/scheme and finalization independently verifies the returned
signature against the retained frame. This proves signature validity; it
neither protects the provider's key nor establishes trustworthy human review.

## Separate authority owners

| Signing role | Defining owner and retained boundary |
| --- | --- |
| Interactive client operations | Existing SDK prepared owners and `ExternalSigner`; human intent review must cover their retained operation-specific content before signing |
| Automatic validator protocol messages | `ConsensusSigner` plus the real core admission, live serving, committee, locks and durable identity owners; no per-vote human confirmation |
| Conditional readiness | `node_core::conditional_readiness` owns actual-key matching, eligible successor checks, complete inactive-target verification and exact retained-slot reconciliation; readiness confers no serving authority |
| Genesis and administrative approval | Genesis authoring and each actual administrative operation retain their own locally pinned authority and ceremony; validator membership does not confer these powers |

Current [native custody](../../../apps/operator/src/host_runtime.rs) holds a
raw `SigningKey`; the SQLite host loads a seed and checks its public key against
the committed original authority before composing it. Readiness currently owns
its software key directly. [Genesis authoring](../../../apps/operator/src/standard_asset_genesis.rs)
also loads a raw key and signs publication, initialization and the manifest.
SDK preparation migrates none of these custodians. An administrative provider
integration must first identify the actual signing consumer; this record
creates no new admin route, privilege or general-purpose signing endpoint.

## Proposed provider-independent contract

1. Local trusted configuration fixes the role, expected public key, supported
   scheme, chain/context, permitted signature domains and exact provider account
   or key version before requests arrive. Authenticate configuration provenance
   and changes. A peer identity, provider default or caller-supplied role is not
   authority. Provider key selection must remain fixed through each operation.
2. Reuse existing canonical frames and raw Ed25519 signatures through existing
   client/validator ports. Retain the expected frame/key and independently verify
   every new returned signature before signed output or retained state is exposed.
   The current `ConsensusSigner` declaration alone does not prove its actual key.
   Keep readiness under its narrow owner; do not export it as a general signer.
3. A custody adapter enforces the selected key-use scope and refuses unknown
   domains, unsupported schemes, mismatched accounts and malformed or over-bound
   requests before key use. Domain permission is necessary but does not replace
   operation authentication or live protocol admission. Provider-specific code
   belongs outside protocol crates; no new crypto, canonical tag, wire protocol,
   broker controller or public `trusted=true` flag follows from this contract.
4. Refusal, timeout, disconnect, restart, malformed output or wrong key/frame
   produces no successful signed result and no development-key fallback. Keep
   SDK provider failures opaque through Display, Debug and source chains; apply
   equivalent secret/credential redaction at actual host/provider boundaries.
   Do not conflate refusal with a successfully reconciled retained signature.
5. Specify exposure for encrypted storage, unlock material, process memory,
   backups, logs, crash dumps, IPC and administrative access under the chosen
   threat model. Restrict invocation and key administration separately. An
   encrypted file or socket permission alone is not custody qualification.

### Automatic signing and durable authority

Automatic signing must remain inside actual existing live handlers. Preserve
fresh original/successor serving admission, committed context/set and local-key
matching, writer fencing, operation-specific possession/eligibility checks and
atomic safety retention. `ConsensusSigner::sign_framed` is not a live warrant;
passing valid bytes directly to a protected key grants none of those powers.
Current byte-only ports convey neither digest preimages nor independent review
or live authority. A separated signer needs a separately reviewed authenticated
content/authority arrangement; this proposal selects no such protocol.

Preserve [ordered identity retention](../../../crates/node-core/src/ordered_economics/identity.rs):
immutable proposal/vote bindings and the durable vote watermark, alongside
consensus lock safety. Preserve FastVote's retained commitment/material and
object/nonce locks. Output waits for the owning confirmed commit; uncertainty
requires exact fresh reconciliation, not a second conflicting signature or
exposure of an unretained result. Restart must preserve these contracts.

Readiness remains nonexclusive before Seal and freshly verifies every new or
retained return. Preserve its complete-target comparison, actual eligible key,
protected slot and ambiguity rules; do not impose an invented global sign-once
policy. Ordinary fencing does not detect a mutually consistent database rollback.
Recovery of unique votes must account for that threat, including a signer that
observes frames before a node commit. Key isolation alone supplies no independent
rollback anchor or external signing-history guarantee.

## Trustworthy interactive review

The review surface must authenticate its policy and trust inputs independently
of untrusted node/relay responses and host-supplied labels. Whether the review
surface shares a trusted OS or needs a separate device/host is a human choice.
An agent confirmation prompt, hash display or successful SDK finalization cannot
stand in for this boundary. Reuse `signing-view` only for its recognized historical
transaction profile; its existing policy grants no generic-contract authority.

Review and signing must consume the same immutable prepared content. Decode
bounded canonical preimages, reject unknown/trailing fields and recompute all
relevant commitments and the exact frame under retained trusted configuration.
Bound total bytes, collections, nesting, work and displayed fields before use;
do not silently truncate approval-critical values or fetch mutable replacement
preimages at finalization. Preserve each operation's authentication/error order
and paid execution's original post-sign quote.

| Operation family | Required review inputs in addition to context, key and exact frame |
| --- | --- |
| Local/paid Call or Instantiate | Exact authenticated code/instance revision and dependency closure, entrypoint, ABI/type arguments, argument bytes, declared access/authorizations, nonce/request, gas and fee consent/policy; recognized semantic effects and limits |
| Publication, including paid Publish | Publisher/origin, revision, code, ABI/exports, dependency provenance, semantics and artifact commitment, request/nonce and any paid consent; code approval provenance separate from hash consistency |
| Original/successor registration | Core-derived validator identity, bond resource/amount, predicted initial row, exact signed custody leg and outer envelope, original root or verified successor scope |
| Fee claim | Exact intent/request, claimant from the certificate's historical committee, certificate/workflow provenance, claim recipient/resource/amount and relevant epochs; current membership cannot replace historical identity |
| Genesis/admin operation | Every actual nested signed object and its authority, approved code/policies, committee/economic configuration and operation-specific replay boundaries; display the manifest's full approved commitments and preimages |

Authenticating generic code/ABI proves identity and structure, not understood
business semantics. A review policy must bind exact code/revision/dependencies
to independently approved operation meaning and display every material authority
or economic consequence. Unknown code, semantics, arguments or effects refuse
approval. Raw arguments, a familiar contract name or an asset-shaped ABI are
not a blind-signing escape hatch. Unsupported families remain unavailable for
protected human approval until their own policy and trusted surface exist.

## Custody threat models to choose between

These are threat models, not assertions about any product's capabilities.

| Candidate | Trusted boundary and intended protection | Residual assumptions and required evidence |
| --- | --- | --- |
| Dedicated encrypted local custody | Trust local OS/root and the custody process; protect stored keys and restrict ordinary callers, separately from the node process | Unlock/process memory remains inside that trust boundary. Prove IPC access, role/domain policy, review integrity, encrypted backup/recovery and refusal/restart behavior; OS/root compromise is not claimed to be resisted |
| Signer on a separated host | Trust signer host/admin, authenticated channel and its key-use policy; seek isolation from a compromised node host | A separated key can still sign malicious authorized-looking requests. Decide how signer policy authenticates intent/live authority without duplicating consensus or weakening core owners; prove credential/replay bounds, outage/ambiguity and both-host recovery |
| Hardware-backed signer | Trust the selected device, firmware, provisioning/admin and any review path; seek a defined key-extraction barrier | Non-exportability, raw-frame support, policy enforcement, review display and recovery are requirements to investigate, not assumed features. Hardware alone does not validate arbitrary semantics, live state or node rollback |

No candidate becomes an initial-profile prerequisite or default through this
comparison. Native/SQLite and later DO retain the same protocol contracts;
providers need their own actual exposure, failure and recovery evidence.

## Recovery, rotation and revocation

Choose separate operator, custody-administrator, genesis/admin approver and
recovery-holder roles, permitted overlap and emergency authority explicitly.
Define backup custody, recovery quorum/access, unlock and stop/revoke procedures
before real keys. Rehearse restore with old writers fenced and safety history
preserved or independently reconciled; ambiguous or rolled-back history must
not be treated as a virgin signing identity. Restore availability is not proof
against equivocation. A provider outage must fail closed.

Provider revocation prevents future authorized provider use only within its
enforcement boundary; it cannot invalidate copied keys or erase valid historical
signatures. Under `AddressIsPublicKey`, a different public key means a different
address. Plan asset/authority migration and validator membership/key changes
through existing authorized operation/epoch mechanisms, with explicit overlap,
cutover and historical verification. Do not invent an address alias, rewrite
genesis or assume a protocol-wide revocation registry exists.

## Safe next slice and outstanding choices

`PreparedPublication` already exposes retained inputs, builds commitment/frame and
authenticates/verifies final output. Bounded closed `CodeArtifact` decoding and
independent original-encoder/changed-preimage controls also exist. New work needs a
concrete trusted review consumer: bounded, non-authorizing presentation/preimage-to-frame
correspondence using existing encoders, explicit display/work limits, and refusal
of incomplete, missing, mismatched or undisplayable fields. Without that consumer,
defer; add no second authentication, signer call or semantic/code-safety approval.

Before custody wiring, the human must choose the threat boundary and trusted
review surface, actual independent operators/key roles and recovery holders,
accepted semantic policies, recovery/rotation/revocation authority and the first
qualified provider topology. Provider selection and protocol/controller design
are separate reviewed work, not deductions from this comparison.

Qualification then needs the actual consumers, exact-byte/refusal/adversarial
controls, secret-exposure and restart/ambiguity evidence, trusted review coverage,
recovery/rotation/revocation rehearsal and independent final-source/release
review. Local fakes prove composition only. This proposal closes no M2/release
gate and authorizes no keys, deployment or public network. Progress remains in [TODO.md](../../../TODO.md).
