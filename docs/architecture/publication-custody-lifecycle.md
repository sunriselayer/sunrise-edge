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

## Test coverage added for the asset families (not yet executed)

`scripts/check-docker-custody-fixture-1013.mjs` previously proved recovery,
rotation and the key/config startup mismatch only through the publication-only
synthetic wire probe. The dispatcher-level `KeyFileAddressMismatch` check
(`run_with_policy` in the CLI) is shared by every family, so that part is
already covered once and is intentionally not duplicated per asset family.
Two family-bound gaps were added instead. Authored source-only; no passing
Docker fixture run of these controls is recorded yet.

- **Recovered-key control against the own-created mint/burn profile**
  (`phase_own_asset_mint_burn`), following the stop-all-signers-first ordering
  in `Recover the same disposable key` above: the original key's own `serve`
  first finishes its full 6/4/2 lifecycle (including revoking
  `OWN_MINT_REQUEST_ID`/`OWN_BURN_REQUEST_ID` and refusing both on that same
  still-running process), then its own revoked-restart (2/0/2) also finishes
  and the socket is confirmed gone after each — no signer using the original key file
  is left running anywhere. Only then is a genuinely new recovery request
  prepared and independently approved (through the real attended PTY
  `approve-burn` review) over the SAME already-captured own-burn cap/coin/
  fee preimages and the same 3600-second expiry window, under a new dedicated request ID — reapproving
  or resigning a revoked ID is never done.

  `request_id` is itself part of the signed `CallIntent`
  (`asset_mint_burn.rs`'s own
  `request_id: *request.request_id.as_bytes()`), so a byte-for-byte
  signature comparison is only meaningful over the identical frame, never
  across two different request IDs. The fixture proves it the correct way:
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
- **Rotation refusal using a genuinely different already-generated config**
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

**Still open, not covered by this addition:** a true rotated-identity
*positive* business acceptance (minting/transferring against an object the
rotated identity actually owns) still requires first moving ownership
on-chain, which remains a separate, costlier addition and is not implied by
any refusal check above. Automatic/unattended signing, full key rotation of
the other four families' own live `serve` processes (only the own-created
profile gets the recovered-key serve round trip above), and any other
not-yet-listed M2 lifecycle work remain open per `TODO.md`.
