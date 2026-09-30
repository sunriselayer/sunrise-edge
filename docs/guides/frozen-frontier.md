# Freeze and save one validator's complete frontier

This explicitly opt-in fresh signed-v3 workflow is for protocol acceptance.
**Freeze irreversibly stops fresh application and economic admission in the
current profile.** Do not enable it on a public network expecting restart,
timeout or local override to unfreeze the chain. DrainSet, drain, cut/import,
readiness, Seal and verified activation are separate continuation requirements.

Use the [ordered-economics setup](ordered-economics.md) and
[FastVote trust configuration](fastvote-network.md). Every validator must
independently install/pin the same freshly signed manifest with a positive
`minimum_freeze_block_height`. Existing v1/v2 manifests cannot be upgraded
by CLI flags. Only native hosts explicitly configured for the ordered
surface expose this workflow.

## Build and submit actual ordered Freeze

Prepare `next-set.frame` as the canonical `FastPathValidatorSetRecord` for
the immediately following epoch. It is advisory, not readiness proof or
final membership. Signers check committed bond/key/power/policy eligibility
before voting; execution checks again. The signed minimum concerns actual
ordered height, not the user-supplied `created-checkpoint`.

Replace all placeholders with locally trusted values, not untrusted endpoint
responses. The network files use the ordinary ordered/FastVote endpoint
configuration formats and name the same pinned committee.

```sh
sunrise-edge-cli economics ordered-freeze-build \
  --ordered-network ordered-network.txt \
  --ordered-genesis-manifest genesis.frame \
  --ordered-expected-genesis-digest GENESIS_DIGEST_HEX \
  --expected-chain-id CHAIN --expected-protocol-version PROTOCOL \
  --expected-epoch EPOCH --domain DOMAIN_HEX \
  --request-id FREEZE_REQUEST_HEX --created-checkpoint CHECKPOINT \
  --advisory-next-set next-set.frame --out freeze.candidate

sunrise-edge-cli economics network-submit \
  --ordered-network ordered-network.txt \
  --ordered-genesis-manifest genesis.frame \
  --ordered-expected-genesis-digest GENESIS_DIGEST_HEX \
  --expected-chain-id CHAIN --expected-protocol-version PROTOCOL \
  --expected-epoch EPOCH --domain DOMAIN_HEX \
  --candidate freeze.candidate --out freeze-network
```

Construction contacts no endpoint and closes nothing. Record actual
acknowledged `block_height` only after shared ordering commits Freeze.
Preserve the ordered proposal/certificate artifacts and per-peer results.
Recover the declared prefix on omitted replicas through ordinary ordered
recovery before trusting their frontiers. A successful proposal POST alone
is not committed closure.

## Advance and export bounded progress

Repeat for each locally configured outgoing `VALIDATOR_HEX`. Pin the actual
committed Freeze request and height, not estimates or a local counter.

```sh
sunrise-edge-cli contract fastvote-frontier-advance \
  --fastvote-network fastvote-network.txt \
  --fastvote-genesis-manifest genesis.frame \
  --fastvote-expected-genesis-digest GENESIS_DIGEST_HEX \
  --expected-chain-id CHAIN --expected-protocol-version PROTOCOL \
  --expected-epoch EPOCH --expected-domain DOMAIN_HEX \
  --freeze-request-id FREEZE_REQUEST_HEX --freeze-height ACTUAL_HEIGHT \
  --validator-id VALIDATOR_HEX --max-steps 128

sunrise-edge-cli contract fastvote-frontier-export \
  --fastvote-network fastvote-network.txt \
  --fastvote-genesis-manifest genesis.frame \
  --fastvote-expected-genesis-digest GENESIS_DIGEST_HEX \
  --expected-chain-id CHAIN --expected-protocol-version PROTOCOL \
  --expected-epoch EPOCH --expected-domain DOMAIN_HEX \
  --freeze-request-id FREEZE_REQUEST_HEX --freeze-height ACTUAL_HEIGHT \
  --validator-id VALIDATOR_HEX \
  --output-dir validator-frontier --page-limit 128 --max-pages 128
```

`frontier=partial` is confirmed bounded progress, **not completion**. Repeat
advance until `frontier=finalized`. If export exhausts its page budget,
repeat the exact command/output directory: saved bytes are re-verified before
continuation. Host restart resumes the durable cursor/final vote without
executing pending contracts or charging fees. Bound deadlines with
`--fastvote-deadline-seconds` and `--fastvote-per-request-cap-seconds`.

Keep the entire directory: `frontier.vote`, consecutively named
`page-NNNNNNNNNNNNNNNNNNNN.response` files and `complete`. The final marker
contains exact vote bytes and is written only after terminal page, ordering,
count, Freeze pins and complete accumulator verification. A vote, partial
page set or marker copied alone is not a complete frontier. Resume checks
the stream even when a marker already exists. Corrupt or mismatched saved
artifacts fail closed and are never overwritten with fresh peer bytes.

This is one replica's signed complete identity list. It does not aggregate
a quorum, retrieve/retain every bundle remotely, apply pending operations,
release conflicting reservations or authorize a new epoch. Those are the
subsequent [epoch-handoff](../architecture/epoch-handoff.md) capabilities.
