# Immutable operation signing preparation

[DR-0211](decisions/0211-external-signing-preparation.md) defines the shared
mechanical boundary. [DR-0208](decisions/0208-native-sqlite-first-and-protected-signing.md)
removes mandatory Ledger product completion, not protected keys, trustworthy
content review, recovery, rotation or revocation. Release status belongs in
[`TODO.md`](../../TODO.md).

## Defining owners

The client-private [`PreparedSigningFrame`](../../clients/rust/src/signing_frame.rs)
owns the explicitly configured expected public identity, supported signature
scheme and immutable exact frame. It reuses the existing
[`ExternalSigner`](../../clients/rust/src/transaction.rs) and crypto verifier;
there is no additional provider trait, signature scheme or signing wire format.
Provider-declared scheme and identity are checked before `sign_frame`. Returned
signatures are independently verified against the original expected key and
frame before signed output is returned. Generated provider failures expose no
provider diagnostics through Display, Debug or the error-source chain.

Operation-specific prepared owners retain the trust inputs and preimages, and
own their original authentication and error order:

| Prepared owner | Immutable content and final authentication |
| --- | --- |
| [`PreparedTransaction`](../../clients/rust/src/transaction.rs) | Original transaction, domain and signable payload for both transaction profiles; its ordinary `SignatureSigner` convenience retains the crypto error contract and its separate historical clear-policy path remains bounded |
| [`PreparedLocalExecution`](../../clients/rust/src/local_execution_client.rs) | Explicit sender, intent, resolver, local/general policy and resolved execution scopes; original scope/ABI checks precede signing and local authentication remains in finalization |
| [`PreparedPaidExecution`](../../clients/rust/src/paid_execution_client.rs) | Exact application, consent, policy pins, nonce, request, gas and authorizations; original encode/authenticate and post-sign fee quote remain, rather than claiming every business check is pre-sign |
| [`PreparedPublication`](../../clients/rust/src/publication_client.rs) | Complete artifact and dependency preimages, publisher, commitment, semantics, nonce, request, resolver and context; original publication authentication remains |
| [`PreparedLocalBondRegistration` / `PreparedSuccessorBondRegistration`](../../clients/rust/src/bond_registration.rs) | Core-derived validator identity, signed custody leg, predicted row and original root or immutable successor workflow; original registration-scope and outer/inner authentication remain |
| [`PreparedFeeClaim`](../../clients/rust/src/fee_claim_client.rs) | Exact request, intent and immutable verified workflow; claimant identity comes from `certificate_set(intent.certificate_epoch)`, never the current committee or an untrusted response |

Content accessors are immutable. Consuming `finalize(signature)` accepts no
replacement context, policy, scopes, artifact, predicted row or custody leg.
Unsupported schemes, identity mismatch, wrong key/frame, malformed signature
length and provider refusal produce no signed output. No failed external call
falls back to a development key. Existing operation-specific errors remain
distinct rather than being replaced by a uniform business validation layer.

## Actual consumers and evidence boundaries

Development `LocalSigner`/seed conveniences delegate to these prepared owners.
Actual CLI local/general execution, paid Call/Instantiate/Publish, publication,
Standard Asset paid operations, original/successor bond registration and
successor fee claims use the same preparation and finalization. Their concrete
signer selections differ: generic local/paid commands reject custody, ordinary
bond and generic fee-claim commands use development signing, while the scoped
original-genesis bond and publication/recognized Standard Asset/positive Split
have dedicated protected routes. The
[dated route and test-owner map](signing-route-test-map.md) preserves the 8a5
source snapshot; use the current family contracts and TODO for live scope and
qualification.
Fee-source ownership checks take the expected public `Address`, not
secret-bearing keys.
CLI development seed flags are still development flags; no production provider
driver or custody flag follows from this refactor.

Tests compare independent original raw frame/sign/encode sequences with the new
owners and development wrappers. External fakes exercise refusal and zero-call
pre-sign boundaries, not key protection. Genuine registration and historical
fee-claim controls remain inside the original owning operator recurrence; merely
compiling those controls does not prove that expensive workflow passed.

## Fee-claim review consumer

[Saved successor fee-claim review](fee-claim-review.md) consumes the retained
`PreparedFeeClaim` through `FeeClaimReview`. Seed-free prepare exports and offline
review/development-sign commands use the same canonical inputs and independently
verified workflow. Displayed host-proposed economics and generic leg arguments
are not semantic approval or current-row proof. This adds no protected fee-claim
backend or publication-custody permission; [DR-0245](decisions/0245-saved-successor-fee-claim-review.md)
records the exact boundary.

## Separate M2 requirements

Mechanical signature validity is not independent human content review. When a
trusted review surface is selected, it must use the same retained content,
recompute commitments from bounded preimages and fail closed on unknown
semantics. The historical
Ledger transaction policy is not generic-contract review authority.

Automatic validator signing stays with `ConsensusSigner`, committed public
identity and actual live protocol authority. Readiness has its own narrower
eligible-key and retention boundary. SDK operation preparation alone does not
migrate native operator/genesis custody or these automatic signers. Their
separate bounded development implementations are tracked by their own
decisions and [TODO.md](../../TODO.md), not inferred from these SDK owners.

For each family, a protected provider, operator/key-role separation, exposure
controls, refusal/restart behavior, trusted content review and
recovery/rotation/revocation require their own design and qualification. The
selected routes below and in the correspondence map supply bounded components;
their existence does not establish complete coverage of M2. Provider revocation
does not erase historical signatures or silently rotate an AddressIsPublicKey
identity. SDK preparation selects no additional backend or public network launch.

[DR-0214](decisions/0214-protected-custody-and-review-boundary.md) preserves the
earlier threat-model comparison, not a current family selection. The selected
boundaries below retain separate review, automatic-signing and genesis/admin
authority.

[DR-0238](decisions/0238-publication-only-local-os-custody.md) selects the
trusted local OS with a separate process and UID for `PreparedPublication`
only. Its `serve` process never
receives a caller-supplied frame: it rebuilds `PreparedPublication` from its
own pinned config and the caller's bounded artifact/nonce/request-id, and
`custody approve` is the human-review consumer of `PublicationReview` this
document's "Separate M2 requirements" section above anticipates. It does not
migrate any other prepared owner, `ConsensusSigner`, readiness, or genesis/
admin signing, and it is not an at-rest-encryption or compromised-root claim.
Readiness, successor and offline genesis later received separate selected local-OS
boundaries in [DR-0284](decisions/0284-conditional-readiness-protected-worker-proposal.md),
[DR-0285](decisions/0285-successor-protected-host-proposal.md) and
[DR-0286](decisions/0286-standard-asset-genesis-protected-review-worker.md).
Their development evidence does not extend DR-0238 or qualify the release.

[DR-0246](decisions/0246-genesis-standard-asset-transfer-custody.md) adds a
separate [genesis Standard Asset transfer](standard-asset-transfer-custody.md)
consumer of `PreparedPaidExecution`. Its custody process pins genesis and the
in-tree code/fee semantics, reconstructs signed object references from canonical
preimages and renders their amounts before exact-frame approval. The original
publication server remains closed to this family. This does not migrate other
paid operations, fee claims, automatic consensus/readiness or genesis/admin keys.
Subsequent DR-0249/0253/0255/0258/0261 add the separate recognized split/merge,
mint/burn, create and own-created application consumers. DR-0269 separately
selects the strict partial positive fee Split Leg/Claim consumer. See the map
for their actual CLI/backend/test owners; none enables generic paid execution.
DR-0264/0268 select automatic ordered/certified workers under their existing
live-authority owners, independently of these SDK preparations.

[DR-0287](decisions/0287-bond-registration-structural-preview.md) and
[DR-0288](decisions/0288-successor-bond-registration-structural-preview.md)
provide seed-free, nonauthorizing bond previews. For the original-genesis
profile, [DR-0289](decisions/0289-bond-outer-key-custody-and-split-approval.md)
and [DR-0291](decisions/0291-original-bond-inner-standard-asset-profile.md)
select separate content approvers and key workers, and the manifest-fixed
whole-Coin Standard Asset transfer. [DR-0292](decisions/0292-original-bond-trusted-local-currentness.md)
selects the designated local node for source-Coin currentness and a pre-sign
recheck. The [development fixture](original-bond-protected-signing.md) connects
this limited path; it does not authorize generic bond operations or qualify real
approvers, keys or release. Successor live-epoch collateral and other family
choices remain open in TODO M2-N3.

## Selected-family lifecycle correspondence

The existing contracts distinguish same-key restoration, a new signing
identity, and an authorized object or membership transition. Replacing a key
file does not transfer an old identity's ownership, historical entitlement or
approval. Cancellation affects later authorization checks; it cannot recall
an already released signature. Automatic protocol workers retain their own
live-authority and fencing rules rather than human approval tombstones.

The publication and asset rows below use existing phases of the
[bounded custody controller](../../scripts/check-docker-custody-fixture-1013.mjs).
The [lifecycle contract](publication-custody-lifecycle.md) distinguishes
historical signing-only recovery from the separately implemented live consumers.

| Family | Implemented lifecycle boundary | Existing defining controls and limits |
| --- | --- | --- |
| Publication / kind 1 | Stop-first same-key recovery retains the complete revocation set. A new publisher needs its own matching key/config, request and exact approval. | `phase_recovery_verification`, `phase_retain_revocation_through_recovery`, `phase_new_identity`. A new publisher does not migrate the old account. |
| Genesis Coin transfer / kind 2 | Historical same-key signing recovery and the separate recovered-A live A-to-B-to-A Coin handoff retain cancellation and restarted refusal. | `phase_transfer_recovery`, `phase_genesis_coin_identity_handoff`; [transfer probes](../../apps/cli/src/custody/asset_fixture.rs). The handoff moves that Coin, not every object or fee source. |
| Genesis Coin split/merge / kind 3 | Same-key historical recovery, recovered-key self operations and the separate recovered-A foreign split/B return use their existing object-owner transitions. | `phase_split_merge_recovery`, `phase_split_merge`, `phase_genesis_split_identity_handoff`; [split/merge probes](../../apps/cli/src/custody/asset_split_merge_fixture.rs) and [handoff probe](../../apps/cli/src/custody/asset_fixture.rs). No account-wide identity alias is introduced. |
| Genesis mint/burn / kind 4 | Same-key historical recovery and the separate live recovered-key mint/burn consumer preserve old/new revocations after restart. | `phase_genesis_mint_burn_recovery`, `phase_mint_burn`; [mint/burn probe](../../apps/cli/src/custody/asset_mint_burn_fixture.rs). This does not rotate TreasuryCap authority. |
| Create-asset and own-created application asset/Coin | Recovered-key first create, mint/burn and six live Coin stages coexist with the independent historical application transfer and split/merge recovery profiles. | `phase_create_recovery`, `phase_initial_application_recovery`, `phase_own_asset_mint_burn`, `phase_own_asset_coin_operations`; [create probe](../../apps/cli/src/custody/asset_create_fixture.rs), [application Coin probe](../../apps/cli/src/custody/asset_application_coin_fixture.rs). Creator/publisher and separate genesis-fee pins remain fixed; creator migration is not supplied. |
| Positive strict-partial fee Split Leg/Claim | Stop-first same-key recovery retains both phase approvals and permanent cancellation. Restored approvals, expired phases and a different historical claimant key refuse. | [Existing two-phase controller](../../scripts/check-docker-positive-fee-split-fixture-1017.mjs), `distinct_uid_positive_fee_split_probe` in the [owning probe](../../apps/cli/src/custody/positive_fee_split_fixture.rs). A different key does not inherit the old certificate's entitlement. |
| Original ordered / certified FastVote workers | Stop/drain, downtime refusal, saved-signature replay, fencing and same-identity key-path recovery retain the existing protocol safety state. | `recover_stopped_keys` in the [ordered owner](../../scripts/fixtures/original-ordered-custody-1017.py), `recover_stopped_worker_keys` in the [certified owner](../../scripts/fixtures/certified-fastvote-custody-1017.py). A membership/key replacement needs its existing protocol authorization. |
| Readiness / successor workers | Reaped workers resume through the original same-key-path recovery controls. Eligible keys, retained slots, fresh serving warrants and committee/fence checks remain authoritative. | The original [readiness/recurring owners](../../apps/operator/tests/conditional_readiness_sqlite.rs) and [successor protected helper](../../apps/operator/tests/support/successor_host_acceptance/protected.rs). This is not an arbitrary new-key substitution route. |
| Offline genesis author | A new manifest worker resumes retained nested approval only for the same pinned draft/config/reviewer, unexpired state and no tombstone. The test restores the original key-file bytes after intentional wrong-key substitution and refusal; outer-review disconnect retains the approval for another worker. | `protected_author_reviews_three_exact_frames_and_installs_four_validator_pairs` in the [genesis owner](../../apps/operator/tests/standard_asset_genesis.rs), backed by [protected processing](../../apps/operator/src/standard_asset_genesis/protected.rs). Authenticated revoke survives restart. This is bounded resume/restoration, not lost-key backup recovery or in-place authority rotation. |
| Original-genesis bond inner/outer | Broker restart retains exact approval records under its exclusive store lock. Workers require their separately pinned keys. Permanent tombstones invalidate the shared request ID, and release/revoke ordering is serialized. | `protected_original_bond_uses_two_distinct_approvers_and_workers` in the [bond owner](../../apps/cli/tests/bond_registration.rs), plus `exact_record_uid_expiry_restart_and_revoke` in [approval storage](../../apps/cli/src/custody/bond_approvals.rs). Source-host restart invalidates old currentness; refreshed requests need both approvals. No new-key or live-successor bond migration follows. |
| Fee-claim preview/export | Inspection and development signing supply no protected-provider lifecycle. | The [review contract](fee-claim-review.md) remains separate from positive Split; a display is not protected approval. |

These are source-to-owner correspondences, not new executions. Existing
shared key/config startup checks need not be duplicated for every asset
family. The historical [route/test map](signing-route-test-map.md) retains its
own pinned snapshot; it is not rewritten by this table. Each executed result
keeps its own source/profile in [TODO.md](../../TODO.md). An ignored fixture's
existence, ordinary CI success or this correspondence does not establish fresh
same-source UID/RELEASE qualification, actual enrollment, production backup
recovery or complete M2 acceptance. Unselected families and stopped work do
not acquire implementation or qualification through this table.
