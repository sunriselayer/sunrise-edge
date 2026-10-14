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
