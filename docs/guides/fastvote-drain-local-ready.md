# Prepare one validator's frozen-frontier union

`contract fastvote-drain-local-ready` drives one selected validator's local
post-Freeze import until its exact selected frontier union is durably ready.
It does not propose or commit an ordered DrainSet, apply drained operations,
prove a cut, seal an epoch or activate a new validator set. The safety design
is in [epoch handoff](../architecture/epoch-handoff.md); implementation status
and remaining gates are in [`TODO.md`](../../TODO.md).

Use only the already trusted outgoing signed-genesis manifest and expected
chain, protocol, epoch, hash suite and atomicity domain. Keep every endpoint's
TLS identity independently pinned in the network configuration described in
[the network guide](fastvote-network.md#configure-the-network-for-the-cli).
Endpoint TLS validation never supplies the expected protocol context.

Create a UTF-8 selection manifest with one existing file path per line. Each
file must contain the exact canonical bytes of one already-signed outgoing
`FrozenFrontierVote`; the selected votes must form a valid outgoing quorum.
Blank lines and full-line `#` comments are allowed. Relative paths resolve
against the manifest's own directory. Paths containing whitespace are not
supported. Include the target in the network configuration even if it is not
one of the selected frontier signers.

```sh
cargo run -p sunrise-edge-cli -- contract fastvote-drain-local-ready \
  --target-validator TARGET_VALIDATOR_ID_HEX \
  --fastvote-network /secure/outgoing-network.conf \
  --fastvote-genesis-manifest /secure/genesis.manifest \
  --fastvote-expected-genesis-digest YOUR_64_HEX_DIGIT_MANIFEST_DIGEST \
  --expected-chain-id YOUR_CHAIN_ID \
  --expected-protocol-version YOUR_PROTOCOL_VERSION \
  --expected-epoch YOUR_OUTGOING_EPOCH \
  --expected-hash-suite-id YOUR_HASH_SUITE_ID \
  --expected-domain YOUR_DOMAIN_HEX \
  --drain-selection-manifest /secure/drain/selected-votes.txt \
  --drain-freeze-request-id FREEZE_REQUEST_ID_HEX \
  --drain-freeze-height FREEZE_BLOCK_HEIGHT \
  --drain-page-limit 16 \
  --drain-max-mutation-attempts 4
```

The CLI verifies the local selection and bounds before its first request.
`drain_local_ready=true` proves only this target's local completion for the
specified selected union; `drain_local_ready=false` with
`drain_incomplete=true` is a safe-to-resume incomplete result, not rollback.
Keep the same selection and rerun after resolving the reported prerequisite.
Neither result is a quorum decision, and no command here creates signatures.
