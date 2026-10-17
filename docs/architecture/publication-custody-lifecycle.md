# Publication custody cancellation, recovery and rotation

This is the development-only Linux OS/UID profile from
[DR-0244](decisions/0244-publication-approval-revocation-and-key-lifecycle.md)
and the [custody guide](local-publication-custody.md). All actions run as the
custody administrator under the trusted local OS. Use disposable keys only.
Files stay custody-owned at mode 0600 under mode 0700 directories.

## Cancel an approval

For a complete local signing fence, stop every `custody serve` using the key
and approval store and wait for actual process exit. Disabling its socket alone
does not remove the key from memory. Reconcile any already delivered signature
against the account's committed nonce/receipt before deciding on another intent.

```bash
sunrise-edge-cli custody revoke \
  --approvals-dir /var/lib/custody/approvals \
  --request-id <the full 64-hex request ID>
```

Success prints `revoked=true` and the ID. Keep the `ID.revoked` record permanently
with that store. Repeating the same command is idempotent. No original approval
is deleted; it remains available for inspection. A fresh bounded signer refuses
this ID, including after its old approval file is restored. `approve` refuses
reapproval; use a new ID and independently review a new exact intent if needed.
A cancellation issued while `serve` runs affects subsequent checks, but cannot
retract signatures already produced or preempt a request past its last check.

## Recover the same disposable key

1. Stop and wait for all signers using that key/store.
2. Retain the current config and complete current revocation set separately
   from the key being recovered. Never roll the whole approval directory back
   to an older snapshot. Restore old approval files only into a store retaining
   every current revocation; if that set is unavailable, stay stopped and use
   a fresh empty store with fresh independently reviewed approvals.
3. Recover the trusted private seed to a new custody-owned 0600 file under a
   0700 directory. Do not print its bytes or put them in argv, logs or source.
   This profile does not encrypt backups or provide an off-host backup system.
4. Start bounded `serve` with the retained config and recovered key path.
   A missing/malformed/inaccessible key or a public-key mismatch fails startup.
   Keep the operator's expected public key pinned to the original identity.
5. Verify an approved disposable publication through the existing Rust client
   and SDK finalization. The same exact frame has the same verified signature;
   a revoked request stays refused. This test is not a real publication submit.

## Rotate to a new disposable key

1. Stop and wait for all old signer processes. Retain the old key/config and
   revocation records under the same permissions for deliberate recovery.
2. Run `custody keygen --key-file NEW_PATH` at a new path. It refuses overwrite.
   Capture only its public key. Create a new private config with that publisher
   and the separately trusted chain/protocol/epoch/domain/operator UID values.
3. Update the operator's public-key pin to the new identity. Rebuild the canonical
   artifact from independently trusted inputs with the new publisher, use a
   fresh request ID, and run the full attended `custody approve` review.
4. Start bounded `serve` with the new matching config/key paths. Old key/new
   config and new key/old config must fail startup. An old publisher's artifact
   is refused; a new-publisher request still requires its own exact approval.
5. Verify the new signature through the Rust client and SDK finalization.
   Account ownership/funding/governance migration is a separate protocol action;
   swapping a custody key/config does not authorize or perform it.

Changing a file or pin cannot revoke signatures already emitted. There is no
automatic rollback to an old key. If identity, revocation freshness or nonce
reconciliation is uncertain, keep signing stopped and reconcile first.

## Asset-family fixture coverage

`scripts/check-docker-custody-fixture-1013.mjs` previously proved recovery,
rotation and the key/config startup mismatch only through the publication-only
synthetic wire probe. The dispatcher-level `KeyFileAddressMismatch` check
(`run_with_policy` in the CLI) is shared by every family, so that part is
already covered once and is intentionally not duplicated per asset family.
The added controls passed on 2026-10-17: actual exit 0/EOF in 5.558s on
test source `be3b4896`, using the A/B-produced `9de634a7` RELEASE CLI and
the retained `4d2c97e0` dev/test-opt2 oracle. All compiled Rust/Cargo inputs
are identical. Original controls, source/binary hashes and metadata, and
owned container/volume cleanup were independently checked. `TODO.md` E67
owns this result and its limits; the test-only source has no new whole-M7
or complete-required/CI qualification.

The first attempt hit Linux's single-argument size limit before container
creation. The fixture now sends a bounded compressed bootstrap, verifies
the decoded length and SHA-256 before execution, and runs the identical
136,386-byte Python program. Its bootstrap argument is 31,025 bytes.
Digest mismatch and trailing compressed data are rejected before execution.
Container and fixture resource/deadline limits are unchanged.

- **Recovered-key control against the own-created mint/burn profile**
  (`phase_own_asset_mint_burn`), following the stop-all-signers-first ordering
  in `Recover the same disposable key` above: the original key's own `serve`
  first finishes its full 6/4/2 lifecycle (including revoking
  `OWN_MINT_REQUEST_ID`/`OWN_BURN_REQUEST_ID` and refusing both on that same
  still-running process), then its own revoked-restart (2/0/2) also finishes
  and the socket is confirmed gone after each. No custody signer using the
  original key file remains running. Only then is a new recovery request
  prepared and independently approved (through the real attended PTY
  `approve-burn` review) over the SAME already-captured own-burn cap/coin/
  fee preimages and the same 3600-second expiry window, under a new dedicated
  request ID. A revoked ID is not reapproved or signed.

  `request_id` is itself part of the signed `CallIntent`
  (`asset_mint_burn.rs`'s own
  `request_id: *request.request_id.as_bytes()`), so a byte-for-byte
  signature comparison is only meaningful over the identical frame, never
  across two different request IDs. For this comparison,
  **before the seed is copied anywhere**, the ORIGINAL key file signs this
  exact SAME newly approved frame once, through its own dedicated bounded
  `serve-mint-burn` on a distinct socket (1 connection/1 signed/0 refused),
  producing the expected reference signature. That reference serve is then
  waited on, reaped and its socket confirmed gone — exactly like the
  original `serve`/`restarted` above — before the disposable seed is ever
  recovered (via the existing `phase_recover_private_key` backup/restore
  helper, to a profile-local path distinct from the publication family's
  own recovery paths).

  A second, independent `serve-mint-burn` is then started with the
  recovered key path, bound to the SAME `--asset`/`--instance-ref` pins,
  and this fixture demonstrates, against it: (1) the SAME unchanged
  recovery request signs successfully through the real `sign-burn` CLI
  (never a synthetic wire probe), and its signature bytes are asserted
  equal to the reference signature captured above — offline signing only,
  so no fresh ledger execution and no nonce/supply change, keeping the
  original supply/nonce/replay/receipt assertions above meaningful and
  unmodified; (2) the pre-existing revocation of `OWN_BURN_REQUEST_ID` —
  issued before the key was ever recovered — still refuses under the
  recovered key; (3) revoking the new recovery request's own ID and showing
  the same recovered-key instance also refuses it. A fresh restart of the
  recovered-key serve then refuses both the pre-existing and the newly
  issued revocation again. The reference serve, the recovered-key serve and
  its restart each have their own exact counters (1/1/0, then 3/1/2, then
  2/0/2), separate from the original key's own 6/4/2 and 2/0/2. Cleanup uses
  the existing same-UID `stop_owned_process` signal helper only (no
  `CAP_KILL`/`FOWNER`), and every socket path is asserted gone after each
  stop, the same pattern `main()` and `phase_new_identity` already use.
- **Rotation refusal with a new publisher configuration**
  (`family_rotation_config` + `expect_prepare_rotation_refusal`, one per
  family). A freshly generated keypair and a config identical to each
  phase's own (same chain/protocol/epoch/domain/operator pin, only the
  publisher differs) is used to re-run that family's own already-exported
  owned-object preimage through its `prepare-*` command, purely locally (no
  serve, no native host, no chain mutation):
  - transfer: `transfer coin is not owned by the pinned custody publisher`
  - split/merge: `split coin is not owned by the pinned custody publisher`
  - mint/burn: `mint cap is not owned by the pinned custody publisher`
  - create-asset (fee-only, no owned Coin/Cap input):
    `fee source is not owned by the pinned custody publisher`
  - own-created mint/burn: reusing the SAME `--asset`/`--instance-ref` pins
    under the rotated config hits `AssetMintBurnTrust::new`'s
    `ApplicationAssetPin::new` creator check first (before any cap/fee
    ownership check runs), so the asserted message is instead
    `application instance record does not match the pinned custody context,
    code, revision, initializer or creator`. This is asserted explicitly,
    matching the real validation order in `asset_mint_burn_commands.rs`
    (`load_trust` runs before `prepare_mint`/`prepare_burn`).

  Each family's own `--out` path is asserted absent both before the refusal
  is attempted and after it, so a refused `prepare-*` is also checked to
  have written nothing, using its own distinct, never-otherwise-occupied
  path per family.

Both additions preserve every original fixture family/control, resource/
deadline/log/generated-byte/process/network/UID/capability bound, and the
existing `serve`/`restarted` summaries' exact expected counters; they add
their own dedicated sockets, keys, configs and counters rather than
perturbing any existing one. The host-side Node result check requires every
new field above to be present and `true` and every new serve/restart counter
to match exactly, the same way it already required the pre-existing
`serve_summary`/`restart_summary` fields.

### 2026-10-17 transfer recovery consumer extension

The separate transfer control uses the same recovery mechanism without changing
any backend, approval format or authority policy. It starts after the original
`phase_transfer` and revoked restart have both finished. A fresh request ID
(`77` repeated 32 times, distinct from the original `75` request) retains the
original context, coin, fee, recipient and nonce preimages and receives its own
attended `approve-transfer` confirmation. A reference `serve-transfer` using the
original key signs this exact fresh frame and is reaped before the custody-owned
backup/restore helper runs. No signer using the original key remains alive.

The recovered key uses the same public-key/config/genesis pins. The real
`sign-transfer` command must independently finalize the signature and export the
same complete bytes as the reference. The pre-existing `75` revocation remains
effective. A new cancellation of `77` then refuses signing in that process; both
IDs refuse again after recovered-key restart. Exact reference/recovery/restart
counters are 1/1/1/0, 3/3/1/2 and 2/2/0/2, respectively. Normal exit must already
have removed each socket; same-UID cleanup is a failure-path fallback only.

This is offline signing over retained preimages, with no endpoint submission or
business nonce/receipt change. It does not reapprove a revoked ID, compare
signatures across request IDs, move ownership or generate a new identity.
Additional output and eight generated files each have a 16 KiB local allowance
inside the unchanged fixture totals. All original families, six publication
lifecycle summaries and E67 assertions remain. This describes the new source
control; TODO owns its separately required actual qualification.

### 2026-10-17 create-asset recovery consumer extension

The contained create-asset recovery control follows the same stop-first
mechanism as transfer and genesis split/merge. It runs after the original
create signer, its revoked restart, native host and all own-created
mint/burn/E67/Coin follow-ons have finished. A fresh `9d` request keeps the
original public instance seed, genesis/config, canonical fee preimage and
nonce and receives its own attended `APPROVE-CREATE` confirmation.

An original-key reference signs `9d` and is actually waited, with its PID and
socket absent, before custody-UID private backup/restore. The recovered key
then uses the same publisher/config/genesis pins through `serve-create` and
the real `sign-create` command. Its complete signed bytes must match the SAME
`9d` reference. Old revoked `95` refuses, cancelling `9d` refuses it in that
process, and both refuse after recovered-key restart. Each refusal checks its
own absent output. Reference/recovery/restart counters are 1/1/1/0, 3/3/1/2 and
2/2/0/2. Original trust/preimage/old approval and revocation attachments, fresh
reviewed request attachments and reference bytes remain unchanged.

This control does not submit a second create-asset: the reused seed already
names an instantiated target and the retained fee/nonce need not be current.
It proves only the source control's same-key signing and refusal contract,
with actual qualification recorded separately in `TODO.md`. It introduces
no key backend, new identity, ownership migration or general signing route.

The normal addition is nine direct `run_exec` CLI children, one PTY, three
bounded signer processes and two existing custody-UID private-copy children
(15 total). Bounded direct reads compare nonsecret evidence without reader
children. Eight generated files have a combined 16 KiB allowance; captured
output has 32 KiB and the result summary 2 KiB. These are suballocations of
the unchanged global limits. All original/T/G assertions, six publication
lifecycle summaries and E67/Coin operations remain unchanged.

### 2026-10-17 genesis mint/burn recovery consumer extension

The separate genesis kind-4 recovery control uses fresh `9e` mint and `9f`
burn requests after the original mint/burn execution, receipt replay, signer
and revoked restart have finished. Mint retains the original genesis cap and
fee with nonce 0 and amount 5,000,000 to the same publisher. Burn retains the
cap, Coin and fee exported after the ORIGINAL `93` mint with nonce 1; it never
uses an output of `9e`. The original `94` burn and nonce-2 ledger assertions
remain unchanged. Neither fresh request is submitted or treated as current.

Both requests receive their own attended operation-specific PTY confirmation.
An original-key reference signer signs both SAME fresh frames, then is
actually waited with its PID and socket absent before the existing
custody-UID private copies recover the key. Complete recovered-key signatures
must match each reference independently. Pre-existing `93`/`94` revocations,
new `9e`/`9f` cancellations and all four restarted refusals are checked with
eight separate absent output paths. Exact reference/recovery/restart counts
are 2/2/2/0, 6/6/2/4 and 4/4/0/4; no original counters are changed.

The normal addition is 18 direct CLI children, two PTYs, three bounded
signers and two custody-UID private-copy children (25 total). Fourteen new
private files have a combined 32 KiB allowance, complete captured output has
48 KiB and the result summary 4 KiB, inside the unchanged global bounds.
Seventeen original trust/preimage/request/approval/revocation attachments,
six fresh reviewed attachments and both references remain byte- and
attachment-identical. Readers never inspect private seeds. Existing original,
C/T/G, E67, six publication lifecycles and application Coin assertions remain.
This is same-key historical signing and refusal source coverage, with actual
qualification recorded separately in `TODO.md`; it adds no identity,
ownership migration, backend or live business-currentness claim.

**Still open, not covered by these additions:** a true rotated-identity
*positive* business acceptance (minting/transferring against an object the
rotated identity actually owns) still requires first moving ownership
on-chain, which remains a separate protocol action and is not implied by
any refusal check above. Other asset profiles' live recovery and full key
rotation, other automatic signing families/epochs, and any other not-yet-listed
M2 lifecycle work remain open per `TODO.md`. The original own-created mint/burn
recovery result and this new transfer source control remain separate evidence.
