# Publication-only local OS custody

See [DR-0238](decisions/0238-publication-only-local-os-custody.md) for the
accepted design and its non-claims, and
[DR-0214](decisions/0214-protected-custody-and-review-boundary.md) for the
threat-model comparison this implements one candidate of. This document is
the operator-facing contract and the Docker fixture recipe; it does not
repeat the full design rationale.

> [!WARNING]
> This is a development-only fixture, not a production key-management
> profile. At-rest encryption and compromised-root resistance are not
> claimed. Do not point it at real keys, real users, or a public network.

## Roles

- **Custody UID**: runs `custody serve` and owns the config, key file, socket
  directory, and approvals directory.
- **Operator UID**: runs `publish --custody-socket ... --custody-uid ...
  --custody-expected-public-key ...`. Must be a distinct UID from custody;
  `serve` refuses at startup otherwise.
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
bytes (for example, the same bytes `contract publish`/`preview` would send,
produced by the same build the administrator trusts) — never bytes taken from
a live, untrusted request.

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

## Docker fixture recipe (not executed by this change)

A fixture modeled on `scripts/check-docker-fault-environment.mjs` should, with
every UID created only inside the image:

1. Build three users (`custody`, `operator`, `intruder`) with distinct UIDs.
2. As `custody`: run the one-time setup above, then `custody serve` with a
   short `--total-deadline-secs`.
3. As `operator`: run `custody approve` is not available (different UID);
   instead have `custody` run `approve` through a real PTY
   (`script -qc '... custody approve ...' /dev/null` or an equivalent
   pseudo-terminal wrapper) before `serve` starts, confirm the typed
   confirmation line round-trips, then confirm `operator`'s `publish` against
   the running `serve` succeeds and the signature independently verifies.
4. As `intruder`: confirm connecting to the socket is refused (wrong peer
   UID), and confirm a second listener bound to an impostor path with the
   same socket basename but a different UID is refused by the client's own
   `peer_cred` check.
5. Restart `serve` after it self-terminates (bounded lifetime) and confirm
   the approval store is unaffected (approvals persist; a fresh `serve`
   process can still consume them) and that `serve` never created new host
   users or services, only files under the fixture's own owned paths.

This slice of work did not build or run that fixture (see
[DR-0230](decisions/0230-bounded-docker-fault-environments.md) and
`scripts/check-docker-fault-environment.mjs` for this repository's existing,
separately maintained Docker fault-environment profiles); the above is the
precise recipe for a separate run, not a claim that it has passed.
