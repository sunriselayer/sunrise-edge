# Signing routes and their existing test owners

This is a source correspondence map for the signing boundaries implemented at
`8a5cc30a1d4a6166c6a69e720713252112817833`. It records existing consumers and
tests, not a new provider selection, security assessment or release gate.
Current completion and remaining decisions belong only in
[`TODO.md`](../../TODO.md). The implementation rationale remains in the linked
decision records; [DR-0214](decisions/0214-protected-custody-and-review-boundary.md)
remains Proposed.

## How to read the evidence

There are three separate layers:

1. SDK preparation and finalization bind the expected identity and immutable
   signing bytes. Development signers and external test doubles exercise this
   layer without proving key protection.
2. A selected CLI/backend pair reconstructs one recognized operation under its
   own trusted inputs, obtains exact approval where required and independently
   verifies the returned signature. Generic commands do not inherit permission
   from a specialized command that shares the same SDK owner.
3. A real process/UID/business fixture tests that pair's selected deployment and
   lifecycle. A Rust function's existence, compilation or a successful ordinary
   test run does not establish that an ignored Docker fixture executed.

Same-identity key recovery, refusal of a mismatched new key, a positive signature
by a new identity and authorized migration of assets/protocol authority are
different observations. Cancellation prevents future checks within the selected
backend; it cannot recall a signature already released. Ordinary required CI
does not by itself qualify every selected RELEASE/Docker profile.

## SDK prepared owners and actual CLI consumers

The six logical entries below contain seven concrete prepared types: original
and successor bond registrations are distinct owners. Each row names existing
test functions, rather than inferring coverage from a count of tests.

| Prepared owner | Actual consumer and selected signing boundary | Existing tests and their limit |
| --- | --- | --- |
| `PreparedTransaction` | [Historical `finalize_with_ledger`](../../apps/cli/src/signer.rs) has test callers but no production CLI dispatch caller. It is not the generic-contract custody path. | [Transaction tests](../../clients/rust/src/transaction.rs): `both_profiles_preserve_independent_original_signed_bytes`, `submission_preparation_binds_the_exact_request_id`, `finalize_rejects_a_signature_from_the_wrong_signer`, `external_signer_identity_mismatch_stops_before_signing`. [CLI helper tests](../../apps/cli/src/signer.rs): `ledger_finalization_uses_the_exact_cli_profile_and_policy_and_verifies_the_signature`, `ledger_finalization_rejects_a_policy_mismatch_before_device_signing`. The latter use fake transport, not a physical device or a reachable production command. |
| `PreparedLocalExecution` | [`commands/local_execution::run`](../../apps/cli/src/commands/local_execution.rs) uses development `LocalSigner` for generic local/general Instantiate/Call and explicitly rejects custody. The recognized positive fee Split Leg below is a separate narrow consumer of this owner. | [SDK tests](../../clients/rust/tests/local_execution.rs): `prepared_local_and_general_execution_preserve_independent_signed_bytes`, `prepared_local_execution_refuses_external_failures_and_changed_preimage`, `prepared_local_execution_preserves_presign_refusals_without_external_calls`. CLI `rejects_custody_signer_selection_before_any_io` proves the generic route stays closed to custody. |
| `PreparedPaidExecution` | [`commands/paid_execution::run`](../../apps/cli/src/commands/paid_execution.rs) uses `LocalSigner` for generic paid Call/Instantiate/Publish and rejects custody. Separately, [`AssetSigner::sign`](../../apps/cli/src/commands/standard_asset.rs) dispatches Transfer/Split/Merge/Mint/Burn/Create custody requests, then independently calls `prepared.finalize`. | [SDK tests](../../clients/rust/tests/paid_execution.rs): `prepared_paid_families_preserve_independent_original_bytes`, `prepared_paid_refuses_external_failures_and_changed_preimage`, `prepared_paid_preserves_presign_refusals_and_postsign_quote_order`. CLI `rejects_custody_signer_selection_before_any_io` covers the generic refusal. A structurally valid wrong base-policy pin or insufficient maximum fee can fail after one signing call; this is not a claim that every business check precedes signing. |
| `PreparedPublication` | [`commands/publication::run`](../../apps/cli/src/commands/publication.rs) chooses development signing or publication-only custody and independently finalizes the retained preparation. `run_preview` builds `PublicationReview` without signing. | [SDK tests](../../clients/rust/tests/publication.rs): `prepared_publication_preserves_independent_bytes_and_owned_artifact`, `prepared_publication_refuses_external_failures_and_changed_preimage`, `prepared_publication_keeps_presign_publisher_and_context_refusals`. [Review tests](../../clients/rust/tests/publication_review.rs): `review_matches_independently_recomputed_fields_for_every_known_profile`, `review_refuses_semantics_that_do_not_match_the_declared_profile`. These prove byte/review correspondence, not OS isolation. |
| `PreparedLocalBondRegistration` / `PreparedSuccessorBondRegistration` | [`commands/bond_registration::run`](../../apps/cli/src/commands/bond_registration.rs), exposed by `economics bond-registration-prepare`, signs original or successor preparation with a development seed. Its output is a `structural_registration_claim` with `executed=false`; it selects no protected governance backend. | [CLI/SDK tests](../../apps/cli/tests/bond_registration.rs): `executable_prepares_exact_claim_wraps_kind7_and_preserves_inputs`, `sdk_preparation_is_immutable_and_refuses_an_independent_signer`, `public_key_registration_preserves_original_raw_and_executable_bytes`, `registration_refuses_external_failures_changed_row_and_presign_mutations`. Genuine successor registration is additionally exercised by the recurrence owner described below; structural wrapping or ingress delivery alone is not executed registration. |
| `PreparedFeeClaim` | [`run_fee_claim_prepare`](../../apps/cli/src/commands/ordered_economics_network.rs) supports development signing or seed-free export. [`fee_claim_review::run`](../../apps/cli/src/commands/fee_claim_review.rs) performs offline review/development signing. The separate positive Split route below selects a protected consumer. Historical identity comes from `certificate_set(intent.certificate_epoch)`. | [SDK selector tests](../../clients/rust/src/fee_claim_client/tests.rs): `split_leg_selectors_match_when_leg_bytes_are_identical`, `final_transfer_leg_selectors_match_when_leg_bytes_are_identical`, `intent_validator_mismatch_is_refused`. CLI `review_selection_never_falls_back_to_seed_io` and `malformed_saved_frames_refuse_before_any_signer` cover selection/decoding. These small structural controls do not substitute for a genuine historical workflow. |

The genuine workflow controls for the last two rows remain inside existing
operator tests, not new standalone replicas:

- [`recurring_lifecycle_acceptance::register`](../../apps/operator/tests/support/recurring_lifecycle_acceptance.rs)
  compares current-context successor registration against independently built
  raw bytes, checks external provider failures and refuses old-context signing.
  Its enclosing exact test is
  `compiled_registered_replacement_and_recurring_successor_hosts` in
  [`conditional_readiness_sqlite.rs`](../../apps/operator/tests/conditional_readiness_sqlite.rs).
- [`successor_host_acceptance`](../../apps/operator/tests/support/successor_host_acceptance.rs)
  constructs genuine historical fee claims, compares raw/development/external
  signing, rejects changed preimages and refuses a new committee member trying
  to use an old certificate's entitlement. Its enclosing exact test is
  `compiled_conditional_readiness_real_retention_restart_and_distinct_certificate`
  in the same test target.

[`CI_REQUIRED_EXTENDED_CASES`](../../scripts/ci-gates.sh) and the existing exact
discovery/execution helper own those ignored tests. Their selectors, timeouts,
seven epochs and withdrawal-unlock controls are retained. Running a short
selector test or merely compiling the enclosing target is not their success.

## Selected protected client routes

Every selected route uses the trusted local OS and private process/permission
boundary defined by its own decision. This does not promise encrypted backups,
resistance to a compromised root, hardware isolation or public operation.
The [server](../../apps/cli/src/custody/server.rs) loads a locally selected
family policy; sharing its transport never grants arbitrary-frame signing.

| Selected route | Concrete consumer/backend and contract | Existing test owners |
| --- | --- | --- |
| Publication / kind 1 | `publication::run` → [`request_signature`](../../apps/cli/src/custody/client.rs) → `server::sign_request`; [DR-0238](decisions/0238-publication-only-local-os-custody.md), [DR-0244](decisions/0244-publication-approval-revocation-and-key-lifecycle.md) | [`server.rs`](../../apps/cli/src/custody/server.rs): `sign_request_signs_and_independently_verifies_a_matching_approval`, `sign_request_refuses_when_the_approved_frame_changed`, `sign_request_refuses_an_expired_approval`, `serve_refuses_a_wrong_peer_uid_before_reading_a_request`. Separate ignored `client::tests::fixture_distinct_uid_round_trip`. |
| Genesis transfer / kind 2 | `AssetSigner::sign` → `request_transfer_signature` → `server::sign_transfer_request`; [`AssetTransferTrust`](../../apps/cli/src/custody/asset_transfer.rs), [DR-0246](decisions/0246-genesis-standard-asset-transfer-custody.md), [DR-0276](decisions/0276-live-recovered-genesis-transfer.md) | [`asset_transfer_tests.rs`](../../apps/cli/src/custody/asset_transfer_tests.rs): `actual_query_digest_and_paid_wasm_match_review_and_replay`, `exact_approval_refuses_tamper_wrong_key_expiry_and_restored_revocation`. Ignored [`asset_fixture.rs`](../../apps/cli/src/custody/asset_fixture.rs): `distinct_uid_transfer_probe`, `distinct_uid_genesis_coin_identity_handoff_probe`. |
| Genesis split/merge / kind 3 | `AssetSigner::sign` → Split/Merge requests → `server::sign_split_merge_request`; [`AssetSplitMergeTrust`](../../apps/cli/src/custody/asset_split_merge.rs), [DR-0249](decisions/0249-genesis-standard-asset-split-merge-custody.md), [DR-0278](decisions/0278-live-recovered-genesis-split-merge.md), [DR-0283](decisions/0283-live-recovered-genesis-foreign-split.md) | [`asset_split_merge_tests.rs`](../../apps/cli/src/custody/asset_split_merge_tests.rs): `split_amount_between_zero_and_held_renders_review_and_replays_with_self_recipient_allowed`, `merge_checked_total_renders_review_and_replays_consuming_the_source`, `exact_approval_refuses_tampered_frame_signer_binding_expiry_and_restored_revocation`. Ignored [`asset_split_merge_fixture.rs`](../../apps/cli/src/custody/asset_split_merge_fixture.rs): `distinct_uid_split_merge_probe`; [`asset_fixture.rs`](../../apps/cli/src/custody/asset_fixture.rs): `distinct_uid_genesis_split_identity_handoff_probe`. |
| Genesis mint/burn / kind 4 | `AssetSigner::sign` → Mint/Burn requests → `server::sign_mint_burn_request`; [`AssetMintBurnTrust`](../../apps/cli/src/custody/asset_mint_burn.rs), [DR-0253](decisions/0253-genesis-standard-asset-mint-burn-custody.md), [DR-0280](decisions/0280-live-recovered-genesis-mint-burn.md) | [`asset_mint_burn_tests.rs`](../../apps/cli/src/custody/asset_mint_burn_tests.rs): `mint_amount_renders_review_and_replays_increasing_supply`, `burn_amount_renders_review_and_replays_decreasing_supply_and_consumes_coin`, `exact_approval_refuses_tampered_frame_signer_binding_expiry_and_restored_revocation`. Ignored [`asset_mint_burn_fixture.rs`](../../apps/cli/src/custody/asset_mint_burn_fixture.rs): `distinct_uid_mint_burn_probe`. |
| Create-asset / kind 5 | `AssetSigner::sign` → `request_create_signature` → `server::sign_create_request`; [`AssetCreateTrust`](../../apps/cli/src/custody/asset_create.rs), [DR-0255](decisions/0255-standard-asset-create-asset-custody.md), [DR-0282](decisions/0282-initial-recovered-application-key.md) | [`asset_create_tests.rs`](../../apps/cli/src/custody/asset_create_tests.rs): `create_replays_end_to_end_creating_definition_and_treasury_cap_with_zero_supply`, `create_prepares_the_exact_independently_rebuilt_instantiate_call_and_consent`, `sign_create_request_refuses_a_request_id_reused_with_a_changed_seed_nonce_or_max_fee`. Ignored [`asset_create_fixture.rs`](../../apps/cli/src/custody/asset_create_fixture.rs): `distinct_uid_create_asset_probe`. |
| Own-created application mint/burn and Coin transfer/split/merge / kinds 2–4 | The same closed routes, each with its own immutable [`ApplicationAssetPin`](../../apps/cli/src/custody/asset_application_pin.rs); [DR-0258](decisions/0258-mint-burn-application-asset-pin.md), [DR-0261](decisions/0261-created-standard-asset-coin-custody.md), [DR-0281](decisions/0281-live-recovered-application-coins.md), DR-0282. The genesis fee authority stays separate. | [`asset_mint_burn_tests.rs`](../../apps/cli/src/custody/asset_mint_burn_tests.rs): `application_pin_targets_the_pinned_asset_instance_and_cap_type_instead_of_genesis`, `application_pin_rejects_wrong_context_code_initializer_or_creator_with_the_exact_message`. [`asset_application_coin_tests.rs`](../../apps/cli/src/custody/asset_application_coin_tests.rs): `application_transfer_split_and_merge_target_the_local_pin_and_keep_genesis_fees`, `genesis_approvals_cannot_authorize_application_transfer_split_or_merge`. Ignored [`asset_application_coin_fixture.rs`](../../apps/cli/src/custody/asset_application_coin_fixture.rs): `distinct_uid_application_coin_probe`. |
| Positive fee-claim strict partial Split / kind 6 | [`StandardAssetPositiveSplitPolicy`](../../apps/cli/src/positive_fee_claim_split.rs) recognizes a `PreparedLocalExecution` Leg and `PreparedFeeClaim` Claim. [`positive_fee_split::prepare` / `sign_approved`](../../apps/cli/src/custody/positive_fee_split.rs) reconstruct both; [DR-0267](decisions/0267-positive-standard-asset-fee-claim-policy.md), [DR-0269](decisions/0269-positive-standard-asset-fee-claim-custody.md). Leg/Claim require separate approvals and one permanent request cancellation. | `recognized_leg_retains_independent_legacy_frame_and_signature_bytes`, `exact_custody_owner_resource_type_and_scope_are_required` in the policy module; [`positive_fee_split_approvals.rs`](../../apps/cli/src/custody/positive_fee_split_approvals.rs): `phases_coexist_and_whole_content_expiry_and_permanent_cancellation_bind_both`. Ignored [`positive_fee_split_fixture.rs`](../../apps/cli/src/custody/positive_fee_split_fixture.rs): `distinct_uid_positive_fee_split_probe`, combined with the original readiness successor workflow. |

The shared [`run_with_policy`](../../apps/cli/src/custody/server.rs) checks
key/config identity for every family. Its key-mismatch startup control need not
be copied into every asset test. In-process approval tests do not establish UID
isolation; the distinct-UID controls have their separate executable owners.

The existing [`check-docker-custody-fixture-1013.mjs`](../../scripts/check-docker-custody-fixture-1013.mjs)
owns four complete profiles, not interchangeable smoke tests:

| Profile | Existing operations and lifecycle correspondence |
| --- | --- |
| `publication-genesis` | Publication approval/cancellation/restore/new-publisher signing; genesis transfer, self split/merge and mint/burn. Selected live same-identity recovery paths are described by DR-0276/0278/0280. This is the publication/genesis core70, not the application setup47. |
| `genesis-split-handoff` | A's foreign split and revoked restart use recovered A; B's return and restart use original B. DR-0283 does not recover B or migrate an account. |
| `application-transfer-recovery` | First performs early same-key recovery, initial create/mint-burn and six live application Coin stages with revoked restarts (DR-0281/0282, original setup47). Then separately checks retained-frame historical transfer signing, old/new cancellation and recovered-key restart. The historical signature comparison itself executes no new ledger effect. |
| `application-split-merge-recovery` | The same complete early recovery/create/mint-burn/six-stage live application setup and revoked restarts precede separate retained-frame historical split/merge recovery and cancellation controls. Historical signing and executed setup effects remain distinct. |

The positive fee Split profile has a separate
[`check-docker-positive-fee-split-fixture-1017.mjs`](../../scripts/check-docker-positive-fee-split-fixture-1017.mjs)
owner and [genuine workflow contract](positive-fee-split-uid-fixture.md). Its
recognized proposal does not prove a live escrow head, nonce or entitlement;
the real store-backed preparation and ordered execution retain those checks.
Generic FinalTransfer review never grants permission to this Split-only server.

## Automatic protocol signatures and other authority owners

These are not SDK prepared-owner consumers or per-vote human approvals.

| Owner | Actual signing boundary | Existing tests and limitation |
| --- | --- | --- |
| Original ordered proposal/vote | [`protocol_custody/linux.rs`](../../apps/operator/src/protocol_custody/linux.rs) worker/frontend separation and [`ordered_custody::serve_worker`](../../crates/native-http/src/ordered_custody.rs); [DR-0264](decisions/0264-original-ordered-protocol-custody-worker.md), [DR-0273](decisions/0273-original-ordered-stopped-key-recovery.md) | `frontend_authenticates_real_original_proposal_and_vote_and_refuses_changes`, `routes_cannot_select_fastvote_readiness_raw_frames_or_caller_paths`, `worker_authenticates_before_body_and_deadline_closes_admission` in `ordered_custody.rs`. Separate ignored [`fixture_original_ordered_role_probe`](../../apps/operator/tests/protocol_custody_fixture.rs) and [`Docker fixture`](../../scripts/check-docker-ordered-custody-fixture-1017.mjs) own actual UID/TLS/worker recovery. Original epoch/same-identity recovery does not establish successor identity or off-host recovery. |
| Certified FastVote, availability ACK and original frontier vote | Same process owner with certified modes and [`certified_custody::serve_worker`](../../crates/native-http/src/certified_custody.rs); [DR-0268](decisions/0268-certified-fastvote-protocol-custody-worker.md), [DR-0274](decisions/0274-certified-stopped-key-recovery.md) | `real_fastvote_output_binds_exact_authenticated_intent_and_registered_endpoint`, `real_availability_ack_binds_complete_request_identity_and_endpoint_without_claiming_storage`, `independently_signed_frontier_output_rejects_changed_signature_endpoint_context_and_route` in [`certified_custody/tests.rs`](../../crates/native-http/src/certified_custody/tests.rs). Separate ignored [`fixture_certified_fastvote_role_probe`](../../apps/operator/tests/certified_protocol_custody_fixture.rs) and [`Docker fixture`](../../scripts/check-docker-certified-custody-fixture-1017.mjs) own the 21-route UID/TLS/business lifecycle. These are not positive membership/identity rotation evidence. |
| Conditional readiness | [`conditional_readiness::ReadinessSigningKey`](../../crates/node-core/src/conditional_readiness.rs) owns the actual software key and narrow retained vote. [`operator conditional_readiness`](../../apps/operator/src/conditional_readiness.rs) loads the key file and preserves actual-key/eligibility/history checks. This is not a `ConsensusSigner` adapter or custody-worker route. | `compiled_conditional_readiness_real_retention_restart_and_distinct_certificate` and `compiled_registered_replacement_and_recurring_successor_hosts` test genuine retained readiness and changed committees. They do not establish a selected protected readiness provider or confer serving authority. |
| Offline genesis authoring | [`standard_asset_genesis::run`](../../apps/operator/src/standard_asset_genesis.rs) loads a private key, verifies its expected public authority and signs nested publication/initialization plus the outer manifest through [`build`](../../apps/operator/src/standard_asset_genesis/build.rs). It selects no protected administrative provider. | [`standard_asset_genesis.rs`](../../apps/operator/tests/standard_asset_genesis.rs): `real_author_is_deterministic_and_installs_four_independent_validator_pairs`, `real_author_refuses_bad_configuration_key_and_existing_output_without_mutation`, `valid_outer_signature_does_not_make_a_bad_nested_publication_installable`, `real_author_refuses_unsafe_output_locations_and_protected_key_defects`. Private-file checks and valid nested signatures are not an attended protected ceremony. |

DR-0214 separates genesis/administrative approval from validator membership.
This map names the concrete offline genesis consumer; it does not invent a
generic administrative signing endpoint or assume a future governance action
exists. Any selected administrative consumer needs its own exact content and
authority contract before a backend is connected.

## Links to executed evidence

The canonical status checkout retains the dated raw-validation records; these
links are pinned to its existing `395dbb1d` commit, not to this document's tree:

- [Family table and E-records](https://github.com/sunriselayer/sunrise-edge/blob/395dbb1dab2776013e6978fa25089515f1305a5f/TODO.md):
  publication E21/E22, positive Split E128, original ordered E91,
  certified E129, protocol same-key recovery E194/E198/E199, genesis
  transfer E203–E205, self split/merge E206/E208/E209 and mint/burn
  E212/E213/E218/E219/E222. Each E-record retains its own source/profile
  and limits; it is not a pass on the current documentation commit.
- [Application six-stage recovered-key record](https://github.com/sunriselayer/sunrise-edge/blob/395dbb1dab2776013e6978fa25089515f1305a5f/docs/development/validation/2026-10-29-recovered-application-coins/README.md):
  source `ef0cea4e`, CI run `40860404544`.
- [Initial create/mint-burn recovered-key record](https://github.com/sunriselayer/sunrise-edge/blob/395dbb1dab2776013e6978fa25089515f1305a5f/docs/development/validation/2026-10-30-initial-recovered-application-key/README.md):
  source `76345c53`, CI run `40926698415`.
- [Foreign-split recovered-key record](https://github.com/sunriselayer/sunrise-edge/blob/395dbb1dab2776013e6978fa25089515f1305a5f/docs/development/validation/2026-10-30-recovered-genesis-foreign-split/README.md):
  source `77f6e576`, tree `a036f4ed`, CI run `40997627497`. Merged main
  `8a5cc30a` has that same tree. This records four complete profiles,
  literal npm-ci/full-required and eight CI jobs for that source, not a fresh
  rebuild or execution of this documentation update.

No stopped audit, fixture or durability experiment was resumed to construct
this map. Absence of a selected backend is recorded as an implementation
boundary; it is not permission to reopen a stopped task or to add every
unselected prepared owner as a mandatory release family.
