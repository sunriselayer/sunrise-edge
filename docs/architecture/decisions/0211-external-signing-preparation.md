# DR-0211: Immutable live-operation preparation before custody selection

Date: 2026-10-07 (Asia/Singapore)

Status: Accepted design after fresh independent read-only Codex fallback
DESIGN APPROVE on 2026-10-07. This is not source approval or M2 qualification.
The human-approved DR-0208 removes mandatory Ledger product completion, not key
protection, content review or recovery/rotation/revocation. No custody backend or
mainnet signing qualification is selected by this decision.

## Context

The live Rust SDK still requires `LocalSigner` for generic local/paid execution,
publication and bond registration, and a seed for successor fee claims. Those
restrictions propagate to the actual CLI. The existing `PreparedTransaction`
and `ExternalSigner` already provide immutable exact-frame preparation and
independent returned-signature verification for historical transaction profiles.
That pattern can serve the live operations without adding another provider trait.

The historical signing-view understands only its exact `transaction-v1` policy;
it cannot authorize generic contracts, paid publication, claims or registration.
Native validator `FileEd25519Signer` and genesis authoring still hold raw keys.
Automatic protocol signing and human operation approval have different authority
owners; removing SDK seed ownership does not migrate those other custodians.

## Decision

Use one client-private `PreparedSigningFrame` for an explicitly configured public
identity, supported scheme and immutable canonical frame. Reuse the existing
`ExternalSigner` contract, preserving its exported paths. Check its declared
scheme/account before signing, then independently verify the returned signature
against the retained expected public key and exact frame with the existing
crypto implementation. Do not select a key from a peer's response, a provider's
mutable default, or a supplied validator-id/key assertion. No new crypto,
signature scheme, canonical frame, broker protocol or authority flag follows.

Each typed operation owns preparation, immutable content access and consuming
`finalize(signature)`. Retain the trusted resolver/context/policy and canonical
preimages needed for existing authentication; a caller cannot mutate the intent
between review and finalization. Expose exact bytes/typed content, not a promise
that a host-rendered string establishes independent approval. Shared frame code
does not select business policy, verify code provenance or approve funds.
Unsupported schemes, malformed signature lengths, altered frames and signatures
from another key produce no signed output. Provider refusal/failure produces no
output or silent LocalSigner fallback; provider errors must not disclose secrets.

Migrate the following real families in one coherent SDK/CLI slice:

- Generic local execution: `PreparedLocalExecution`, including the one-instance
  convenience path, retains explicit sender, trusted context/policy digest,
  authorizations, resolved scopes and original final authentication.
- Paid Call/Instantiate/Publish: `PreparedPaidExecution` retains fee-policy pins,
  exact consent/application/request/nonce/gas, final intent authentication and
  original post-sign fee quote. Fee-source validation needs expected owner
  `Address`, not a secret-bearing signer. Preserve existing validation/error
  order; do not invent a second quote evaluator or drop the post-sign quote.
- Publication: `PreparedPublication` retains publisher binding, complete artifact,
  semantics/commitment, nonce/request identity and submission authentication.
- Original/successor bond registration: extend the existing prepared owners with
  public-key-only preparation, frame access and finalization. Derive validator
  identity through the existing core owner; retain custody-leg, predicted row,
  original/successor scope and current-context checks. An already-signed inner
  leg does not authorize a substituted outer envelope or key.
- Successor fee claims: `PreparedFeeClaim` retains the exact verified workflow,
  request, intent and claimant key from the historical certificate committee.
  Independently verify the returned signature, absent in the seed-only helper.
  Historical claimant identity must not silently become the current committee.
- Existing `PreparedTransaction`: consume the same private frame/identity owner
  while retaining both profile byte vectors and the separate Ledger clear-policy
  convenience path. It does not acquire generic-operation review authority.

The LocalSigner/seed development conveniences delegate to these preparations;
they remain explicitly development-only. Migrate actual CLI local/paid execution,
publication, Standard Asset paid operations, bond registration and successor
claim callers. Do not leave the new interfaces unused or introduce production
provider flags before a driver and its trust boundary are selected.

## Content review and automatic signing

The human command/review owner must review the same immutable prepared content
whose frame is signed. Digest-bearing frames need bounded canonical preimages,
independent commitment recomputation and operation/authority/economic fields.
Retain owned immutable snapshots or immutable borrows of every required trust
input and preimage through finalization, including the predicted bond row and
signed custody leg; do not accept replacement trust inputs when finalizing.
Unknown semantic review fails closed; an agent confirmation prompt or opaque
digest is not adequate transaction review. The first preparation refactor does
not implement or attest that independent review boundary.

Automatic validator signing stays behind `ConsensusSigner`, committed public
identity, permitted domains and actual live protocol authority. Readiness stays
inside its narrower eligible-key/retention owner, never a general signer.
Neither needs human confirmation for every protocol vote. Their protected key
providers, actual host wiring and fresh returned-signature checks remain M2 work.

## Custody alternatives, not selected providers

- A dedicated local OpenSSH Ed25519 agent can be investigated as an exact-data
  signing boundary. Use standard agent signing, not the incompatible `sshsig`
  envelope; isolation, content review and recovery are separate requirements.
  A general login agent/socket must not become protocol custody.
- systemd encrypted credentials can protect stored credentials but deliver key
  material to the service; they are not a non-exporting signing provider.
- Vault Transit can be investigated with exact-data Ed25519, fixed key/version,
  independent verification and explicit TLS/ACL/availability operations. It is
  not a default infrastructure dependency or authorization for paid/live use.

Primary references inspected on 2026-10-07:
[agent protocol](https://datatracker.ietf.org/doc/html/rfc9987),
[systemd credentials](https://github.com/systemd/systemd/blob/main/docs/CREDENTIALS.md),
[Transit signing API](https://developer.hashicorp.com/vault/api-docs/secret/transit#sign-data).
These alternatives are not qualified or deployed.

Before custody implementation, settle the accepted threat boundary, trusted
human review surface, independent operator/key roles, recovery holders and
rotation/revocation procedure. Provider revocation prevents future use; it does
not erase valid historical signatures or silently rotate an AddressIsPublicKey
identity. Do not custom-build cryptography to evade this choice.

## Acceptance

Pin unchanged deterministic signed bytes for every migrated family and both
transaction profiles. Prove zero signer calls on each existing pre-sign identity,
context and policy refusal, plus wrong key/frame, short/long signatures and
changed-preimage refusal. Preserve current validation order, original/successor
registration, certificate-scoped historical claims and final paid quoting.
Preserve existing operation-specific error mapping and the ordinary
`PreparedTransaction::sign_and_finalize_with<S: SignatureSigner>` crypto path;
sharing mechanical checks does not authorize a new uniform business error.
Exercise external signer fakes for refusals, not as custody evidence; exercise
actual development CLI callers through the new owners. Complete required local
acceptance, fresh full exact-source review and CI still precede merge.

Custody qualification separately needs the actual provider's refusal/failure,
restart, exposure controls, recovery, rotation and revocation evidence, and
trusted content review for every human signing family. This refactor, a fake
signer or a locked file alone cannot close M2 or authorize network launch.
