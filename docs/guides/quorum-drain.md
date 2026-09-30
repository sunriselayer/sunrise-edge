# Quorum-retained drain rehearsal

This controlled continuation of [Freeze/export](frozen-frontier.md) uses
[DR-0168](../architecture/decisions/0168-quorum-retained-drainset-and-member-drain.md).
It does not activate another epoch or authorize public exposure or real custody.
Freeze remains irreversible; this is not a force-unfreeze runbook.

## Inputs and local readiness

Pin the same fresh signed-v3 genesis, expected chain/protocol/epoch/domain and
actual committed Freeze request/height used for frontier export. Select a
strict weighted outgoing quorum of complete verified descriptors. A selection
manifest is UTF-8, one exact signed `frontier.vote` file path per noncomment
line, in ascending validator-ID order. Relative paths resolve against the
manifest directory; whitespace in paths is unsupported. A saved vote alone
is provisional until all its pages verify.

The ordinary FastVote network configuration supplies descriptor endpoints and
the target; TLS endpoint identity and the independently pinned protocol
context are separate checks. Optional `--drain-artifact-network` uses that
same per-peer configuration grammar but may contain another subset of
outgoing proof holders. Changing artifact locators never changes selection.

For each outgoing voter, run the bounded compiled command with locally
verified values:

```bash
cargo run -p sunrise-edge-cli -- contract fastvote-drain-local-ready \
  --target-validator "$drain_validator" \
  --fastvote-network "$drain_network" \
  --fastvote-genesis-manifest "$drain_genesis" \
  --fastvote-expected-genesis-digest "$drain_genesis_digest" \
  --expected-chain-id "$drain_chain" --expected-protocol-version 3 \
  --expected-epoch "$drain_epoch" --expected-hash-suite-id 1 \
  --expected-domain "$drain_domain" \
  --drain-selection-manifest "$drain_selection" \
  --drain-freeze-request-id "$drain_freeze_request" \
  --drain-freeze-height "$drain_freeze_height" \
  --drain-page-limit 128 --drain-max-mutation-attempts 128 \
  --drain-artifact-network "$drain_artifact_network" \
  --out-drain-union-identity "$drain_union_file" \
  --fastvote-deadline-seconds 90 --fastvote-per-request-cap-seconds 10
```

An incomplete bounded run exits nonzero and writes no final union file.
Rerun unchanged to resume durable progress, including after host restart.
Only `drain_local_ready=true` produces the exact canonical union bytes. It
is local possession, not an ordered DrainSet, a signed cut or active readiness.
Different saved bytes are never overwritten.

Completed signers and currently staged pages do not refetch their original
descriptor endpoint. Missing unstaged pages still need that authenticated
signer; supplying another artifact locator does not replace missing membership
proof. The Rust SDK's `stage_drain_signer_page` can stage independently verified
complete pages before the original signer is unavailable.

## Build, order and recover DrainSet

Use a verified local union file and the exact selected descriptor manifest:

```bash
cargo run -p sunrise-edge-cli -- economics drain-set-build \
  --drain-selection-manifest "$drain_selection" \
  --drain-union-identity "$drain_union_file" \
  --request-id "$drain_set_request" --created-checkpoint "$drain_checkpoint" \
  --expected-chain-id "$drain_chain" --expected-protocol-version 3 \
  --expected-epoch "$drain_epoch" --domain "$drain_domain" \
  --ordered-genesis-manifest "$drain_genesis" \
  --ordered-expected-genesis-digest "$drain_genesis_digest" \
  --out "$drain_candidate"
```

This offline builder signs nothing and creates no possession or commitment.
Submit its exact file with the existing
[`economics network-submit`](ordered-economics.md) command. Every voter
independently checks its complete durable material before voting. Only the
actual ordinary committed DrainSet authorizes member application.

Use the saved proposal/certificate manifest with `economics network-replay`
for a recipient that already verified its local material but missed that
ordered decision. This signerless declared-prefix recovery is not automatic
discovery or a proof that an arbitrary history is complete. Never seed an
ordered record or readiness marker directly.

## Explicit member apply and exact replay

Supply the original signed paid intent and a pinned target:

```bash
cargo run -p sunrise-edge-cli -- contract fastvote-drain-member \
  --validator-id "$drain_validator" --signed-intent "$drain_original_intent" \
  --out-result "$drain_result" \
  --fastvote-network "$drain_network" \
  --fastvote-genesis-manifest "$drain_genesis" \
  --fastvote-expected-genesis-digest "$drain_genesis_digest" \
  --expected-chain-id "$drain_chain" --expected-protocol-version 3 \
  --expected-epoch "$drain_epoch" --expected-hash-suite-id 1 \
  --expected-domain "$drain_domain" \
  --fastvote-deadline-seconds 90 --fastvote-per-request-cap-seconds 10
```

The wire request is only a member locator. The host loads committed authority,
verifies its full proof and re-derives normal paid execution. Missing causal
prerequisites refuse; union request-ID order does not prescribe execution.
Repeat the same command for exact original replay without a second fee charge.
An existing result must match exactly; it cannot be replaced by peer data.

For reproducible evidence, build the actual CLI/host and run the ignored
`contract_lifecycle_pg_drainset_member_drain_binary_cli_e2e` through
`scripts/check-fastvote-pg.sh` with a disposable PostgreSQL URL. It shares the
ordinary Publish/Instantiate/Call/asset/trap fixture, orders real controls,
restarts during recipient progress, stops the original sole proof holder,
retrieves from an imported-proof relay, applies against a conflicting partial
reservation and compares same-boot/restart replay bytes and complete
same-replica state/revisions. Namespace isolation is not independent production
operational control. Release gates and remaining work stay in `TODO.md`.
