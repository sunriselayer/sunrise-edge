# Publication-only local OS custody

See [DR-0238](decisions/0238-publication-only-local-os-custody.md) for the
accepted design and its non-claims, and
[DR-0214](decisions/0214-protected-custody-and-review-boundary.md) for the
threat-model comparison. The human selected trusted local OS with separate
processes and permissions on 2026-10-13 for the first publication slice.
This document is
the operator-facing contract and the Docker fixture recipe; it does not
repeat the full design rationale.
The separate [Standard Asset transfer profile](standard-asset-transfer-custody.md)
uses a distinct invocation and message family. Publication `serve` remains
publication-only.

> [!WARNING]
> This is a development-only fixture, not a production key-management
> profile. At-rest encryption and compromised-root resistance are not
> claimed. Do not point it at real keys, real users, or a public network.

## Roles

- **Custody UID**: runs `custody serve` and owns the config, key file, socket
  directory, and approvals directory.
- **Operator UID**: runs `publish --custody-socket ... --custody-uid ...
  --custody-expected-public-key ...`. Must be a distinct UID from custody;
  `serve` refuses at startup otherwise. The operator needs custody's socket
  group for directory traversal and connection. Group membership grants no
  signing authority; the server checks the exact pinned peer UID.
- **Custody administrator**: runs `custody approve`. May be the same UID as
  custody for this slice; a real separate approver role is D04.

## One-time setup (as the custody UID)

```bash
install -d -m 0700 /var/lib/custody/keys
install -d -m 0750 /var/lib/custody/run
install -d -m 0700 /var/lib/custody/approvals

cargo run -q -p sunrise-edge-cli -- custody keygen \
  --key-file /var/lib/custody/keys/custody.seed
# prints public_key=<64 hex chars>; paste it into publisher_public_key below

cat > /var/lib/custody/keys/custody.config <<EOF
chain_id=sunrise-local-devnet
protocol_version=3
epoch=0
hash_suite_id=1
domain=<64 hex chars, matching --expected-domain>
publisher_public_key=<printed above>
operator_uid=<the operator UID's numeric uid>
EOF
chmod 0600 /var/lib/custody/keys/custody.config
```

## Approving one publication (as the custody administrator, on a real terminal)

The administrator must independently obtain the approved canonical artifact
bytes from their own trusted build inputs — never bytes taken from a live,
untrusted request. The administrator can use `contract preview --artifact-out`
with their own approved WASM/ABI/context/publisher/origin inputs to create the
canonical file. The file must be owned by that UID at mode 0600 under a 0700
directory. Export creates no approval; see the
[preview guide](../guides/publication-preview.md).

```bash
cargo run -q -p sunrise-edge-cli -- custody approve \
  --config /var/lib/custody/keys/custody.config \
  --approvals-dir /var/lib/custody/approvals \
  --approved-artifact /path/to/approved-artifact.bin \
  --nonce 1 \
  --request-id <64 hex chars> \
  --expires-in-seconds 3600
```

This prints the complete bounded publication review and a line to type back
exactly. Only an exact match writes the approval record.

## Serving (as the custody UID)

Approval cancellation and stopped key recovery/rotation are described in the
[lifecycle guide](publication-custody-lifecycle.md). Revocations persist alongside
approval records and must be retained when recovering keys or old approvals.

```bash
cargo run -q -p sunrise-edge-cli -- custody serve \
  --config /var/lib/custody/keys/custody.config \
  --key-file /var/lib/custody/keys/custody.seed \
  --socket /var/lib/custody/run/custody.sock \
  --approvals-dir /var/lib/custody/approvals \
  --max-connections 8 \
  --max-requests 8 \
  --total-deadline-secs 300
```

## Publishing (as the operator UID)

```bash
cargo run -q -p sunrise-edge-cli -- contract publish \
  --custody-socket /var/lib/custody/run/custody.sock \
  --custody-uid <custody UID> \
  --custody-expected-public-key <the printed public_key> \
  --nonce 1 --request-id <same 64 hex chars as approved> \
  ... # the remaining flags are identical to --seed-file publish
```

## Selected Docker fixture

[`check-docker-custody-fixture-1013.mjs`](../../scripts/check-docker-custody-fixture-1013.mjs)
executes the compiled CLI and one exact ignored test-harness probe under three
numeric UIDs inside a pinned, network-free container. Its owned managed volume
is 64MiB noswap; effective kernel limits and exact resource cleanup are checked.
It creates no host users or services. The selected fixture:

1. Runs three distinct numeric UIDs (`custody`, `operator`, `intruder`).
2. As `custody`: run setup and independently prepare the canonical artifact.
3. Run `custody approve` as custody through Python `pty.fork()` before
   starting bounded `custody serve`. Confirm the typed
   confirmation line round-trips. The operator's real Rust client leg then
   requests a signature and independently verifies it with SDK finalization.
   A scripted fixture confirmation is not a real operator ceremony or a
   submitted publication.
4. As `intruder`: confirm a connected peer is refused despite sharing the
   socket group, and confirm a different-UID listener is refused by the client's own
   `peer_cred` check.
5. Restart `serve` after it self-terminates (bounded lifetime) and confirm
   the approval store is unaffected (approvals persist; a fresh `serve`
   process can still consume them) and that `serve` never created new host
   users or services, only files under the fixture's own owned paths.
6. Refuse operator cancellation; durably cancel as custody, repeat cancellation,
   refuse reapproval and verify refusal after a fresh signer restart. Recover a
   disposable private key inside the custody UID and verify the same exact
   signature while retaining cancellation through an old approval-file restore.
   Verify missing-key and mismatched-key/config startup refusals and a separately
   approved new publisher, without changing the original controls or limits.

Build the CLI and library test harness with the same explicit toolchain and
locked inputs, then supply their actual absolute executable paths:

```bash
node scripts/check-docker-custody-fixture-1013.mjs \
  --cli-binary /absolute/target/debug/sunrise-edge-cli \
  --test-binary /absolute/target/debug/deps/sunrise_edge_cli-EXACT_HASH
```

Missing probe inputs fail. A zero-match selector cannot satisfy the JSON and
test-count oracles. The fixture checks exact serve counters, signature equality
after restart, and the operator's inability to read the seed or modify approvals.
Actual results and remaining qualification belong only in [`TODO.md`](../../TODO.md).
