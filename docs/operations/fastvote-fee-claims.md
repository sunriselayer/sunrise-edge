# Offline PostgreSQL fee claims

This is maintenance of **one stopped validator namespace**, not an online
network reward service. Do not use real assets. Independent Phase 3 and
ingress security reviews and live activation remain separate gates in
[`TODO.md`](../../TODO.md). [DR-0149](../architecture/decisions/0149-offline-signed-fee-claims.md)
defines the authority and preparation boundary.

## Before starting

Stop the namespace's validator and exclude other writers for the entire
sequence. Every command requires `--confirm-offline-fence-advance` and
advances the persistent writer generation. Restart the stopped validator
normally afterward; its old generation is no longer valid. A fence alone
does not stop a writer deliberately bypassing this supported boot path.

Supply independently trusted chain, protocol, epoch, hash schedule, namespace,
genesis manifest and manifest commitment. Do not learn expected values from
the database being inspected. This initial operator profile requires the
installed genesis epoch/set; it does not activate a new epoch or reset genesis.
The namespace must already have been installed through
[the PostgreSQL rehearsal](fastvote-pg-rehearsal.md).

Provide `SUNRISE_EDGE_OPERATOR_POSTGRES_DSN` through a protected environment,
never arguments, shell history or captured output. The DSN must name one TCP
host. `--tls-root-der` supplies its independently trusted DER root; the server
hostname and certificate must validate. A test TLS relay authenticates only
that client leg, not the production database's PKI.

`--validator-id` identifies the **store namespace**. A separate
`--claimant-validator-id` identifies the historical fee entitlement. They do
not have to match. Current voting membership, bond or jail status does not
replace certificate-epoch claimant authorization.

Use fresh output paths for every action, including replay. Outputs are reserved
before disruptive fencing and never overwritten; exact signed claims must be
file- and directory-synchronized before application. Failed actions can leave
empty/partial reserved files: preserve them and choose new paths, not a
truncate-and-retry workaround. Signing key files are raw 32-byte development
Ed25519 seeds, regular files without group/other access on Unix. They are not
production keystores; never place seed bytes on argv or in logs.

## Inspect, prepare, apply and replay

The examples below use public placeholders. Replace them with your trusted
values. In a Bash or Zsh shell, collect the common nonsecret flags:

```sh
economics_args=(
  --tls-root-der /secure/trusted-root.der
  --chain-id YOUR_CHAIN_ID --validator-id YOUR_NAMESPACE_VALIDATOR_ID
  --domain YOUR_DOMAIN_ID --protocol-version YOUR_PROTOCOL_VERSION
  --epoch 0 --suite 0:1:1:1:1:1:1:1
  --genesis-manifest /secure/genesis.manifest
  --expected-genesis-digest YOUR_64_HEX_DIGIT_MANIFEST_DIGEST
  --timeout-seconds 60 --confirm-offline-fence-advance
)
```

Discover a bounded page of certified escrows:

```sh
cargo run --release -p sunrise-edge-operator --bin economics_pg -- escrow-list \
  "${economics_args[@]}" --page-size 16 --out /secure/escrows-page.txt
```

Follow the returned exclusive cursor explicitly for further pages. A page is
not a complete inventory. Even a quiescent full sweep proves only coverage of
present keys, not absence of deleted history or whole-store rollback; use
[the existing inventory verifier](fastvote-fee-inventory.md) for that sweep's
precise scope.

Inspect one escrow from the original certified paid request id:

```sh
cargo run --release -p sunrise-edge-operator --bin economics_pg -- escrow-inspect \
  "${economics_args[@]}" --escrow-request-id YOUR_ESCROW_REQUEST_ID \
  --out /secure/escrow-detail.txt
```

Inspection authenticates the retained certificate, commitment and claim chain,
not just a raw database row. Its text report is not itself a signed protocol
message. Check the claimant, assigned amount and claimed state before signing.

Prepare one claim using an independently selected recipient and new request id:

```sh
cargo run --release -p sunrise-edge-operator --bin economics_pg -- claim-prepare \
  "${economics_args[@]}" --escrow-request-id YOUR_ESCROW_REQUEST_ID \
  --claimant-validator-id YOUR_HISTORICAL_CLAIMANT_ID \
  --request-id YOUR_NEW_CLAIM_REQUEST_ID --recipient YOUR_RECIPIENT_ADDRESS \
  --signing-key-file /secure/claimant-seed.bin --gas-limit 1000000 \
  --checkpoint 1 --out /secure/signed-claim.bin
```

The committed entitlement determines zero-share, split or final-transfer
operation. Positive release is evaluated through the resource's defining
public WASM/ABI, not a native Coin body rewrite. The resulting exact next-row
digest and split payout reference are signed in the existing claim encoding.
Preparation changes no escrow, object, nonce, receipt or audit envelope; the
operator invocation still advances its writer fence. It does not reserve the
generation or nonce. This first operator profile uses the claimant key for
the embedded positive execution leg as well; the core supports distinct
authorities, but this command does not select a separate execution key.
Use the same trusted `--checkpoint` during apply. It is administrative
creation metadata, not evidence of a published/committed checkpoint.

Apply the saved bytes without signing again:

```sh
cargo run --release -p sunrise-edge-operator --bin economics_pg -- claim-apply \
  "${economics_args[@]}" --claim /secure/signed-claim.bin \
  --checkpoint 1 --out /secure/claim-receipt.bin
```

Apply independently repeats authorization, execution/effect checks and atomic
generation/object/nonce fencing, then verifies the retained history and payout.
The output is the exact canonical receipt, not the latest mutable settlement
row or a network-wide settlement assertion. A historical replay receipt can
legitimately describe an earlier generation after later claims have committed.

After restarting the operator connection, replay **the same signed file** to
a fresh output path and compare receipts:

```sh
cargo run --release -p sunrise-edge-operator --bin economics_pg -- claim-apply \
  "${economics_args[@]}" --claim /secure/signed-claim.bin \
  --checkpoint 1 --out /secure/claim-replay-receipt.bin
cmp /secure/claim-receipt.bin /secure/claim-replay-receipt.bin
```

Do not submit the inner execution leg separately: it shares the request-id
namespace with the outer claim. Stale preparation requires an explicit new
request and signature; replay does not rebuild with a fresh nonce. If commit
or output persistence is ambiguous, preserve the signed artifact, inspect the
receipt and replay exactly those bytes. Failure to print `complete=true` is
not proof of rollback.

## Network boundary

Distinct claims can win in different orders on different stores. Signed
generation/row digests and CAS stop local double application but do not supply
cross-validator order. Do not run these operations concurrently across live
validators or expose the closed handler as an HTTP route. This tool verifies
only the explicitly selected offline namespace. Online shared-escrow ordering,
replica catch-up and activation-bound handoff remain separate functional work.
