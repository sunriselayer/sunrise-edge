# Genesis Standard Asset split/merge custody

[DR-0249](decisions/0249-genesis-standard-asset-split-merge-custody.md) adds
one more coin-owner-only family to the trusted-local-OS boundary. This guide
describes the implemented contract; qualification status belongs in
[TODO.md](../../TODO.md).

## Trust and operation

Custody's genesis/code/instance/policy pin is the exact same verification as
[genesis Standard Asset transfer custody](standard-asset-transfer-custody.md),
factored into a shared private `PinnedAssetTrust` so this family never
reimplements or re-derives it; only the entrypoint and amount checks differ.

`split` owns the source `Coin` (Write) and a distinct owned fee source.
The amount must be strictly between zero and the held balance — never zero,
never the full balance. The recipient may legitimately equal the pinned
publisher: splitting one's own coin is an ordinary operation, not a transfer,
and is never refused for matching the sender. `split`'s recipient is just as
legitimately a genuinely foreign address: this family can move part of a
coin's value to anyone, exactly like `transfer` moves a whole coin, so
enabling `serve-split-merge` authorizes real transfers-by-split, not merely
self-only housekeeping.

`merge` owns a destination `Coin` (Write) and a distinct owned source `Coin`
(Consume), plus a distinct owned fee source. The source amount must be
positive, and the destination/source checked sum is refused on overflow
before any network or signing step, mirroring the published contract's own
checked-overflow guard exactly.

Both require a positive maximum fee strictly below the fee source balance,
with the refund returned to the sender — the same fee shape as `transfer`.
`mint` and `burn` both require the `TreasuryCap` and stay unsupported in
*this* split/merge profile; they are their own separate kind-4 custody
family (see [genesis Standard Asset mint/burn
custody](standard-asset-mint-burn-custody.md), DR-0253), not an extension of
this one. `create-asset` is likewise its own separate kind-5 custody family
(see [Standard Asset create-asset custody](standard-asset-create-asset-custody.md),
DR-0255). Other packages/instances/epochs and automatic protocol signing
stay out of scope here.

The complete bounded review displays the source value(s), the split amount/
recipient/remainder or the merge values and checked total, every input
reference and access mode, the fee balance/ceiling/refund/full policy,
context/nonce/request fields and the complete signed frame.

## Optional own-created application pin

[DR-0261](decisions/0261-created-standard-asset-coin-custody.md) additionally
accepts a local `--asset`/`--instance-ref` pair for every prepare, approve,
sign and serve role and the ordinary Standard Asset CLI. Application Coins
and the Call target use that publisher-created asset's verified local pin;
fees always use the genesis Coin and policy. Both identities appear in the
review. Omitting both flags preserves the genesis behavior below. See the
[application Coin guide](standard-asset-application-coin-custody.md) for the
pin, compatibility and qualification boundary.

## Independent preparation, approval and serving

```bash
sunrise-edge-cli custody prepare-split \
  --config /private/config \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --coin-file /private/coin.bin --fee-source-file /private/fee.bin \
  --amount <strictly-between-zero-and-held> --recipient <64-hex-address> \
  --nonce 0 --request-id <64-hex-request> \
  --max-fee 1000000 --gas-limit 200000 --out /private/split-request.bin

sunrise-edge-cli custody approve-split \
  --config /private/config \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --request-file /private/split-request.bin --approvals-dir /private/approvals \
  --expires-in-seconds 3600

sunrise-edge-cli custody serve-split-merge \
  --config /private/config --key-file /private/custody.seed \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --socket /custody-run/split-merge.sock --approvals-dir /private/approvals \
  --max-connections 8 --max-requests 8 --total-deadline-secs 300
```

`prepare-merge`/`approve-merge` take `--into-file`/`--from-file` in place of
`--coin-file`/`--amount`/`--recipient`; one `serve-split-merge` invocation
accepts both operations under the one closed kind-3 decoder, exactly as
`serve-transfer` is the sole kind-2 consumer. Approval requires a real
terminal, renders the full review and requires the exact typed
`APPROVE-SPLIT`/`APPROVE-MERGE` confirmation line. `custody sign-split` and
`sign-merge` are the offline alternatives, exporting the ordinary signed
paid intent after independent finalization.

## Actual CLI consumer

The existing `standard_asset split`/`merge` CLI accepts the same three
custody signer flags `transfer` already does, with its ordinary endpoint/
context, coin or into/from, fee, nonce, request and gas flags. It captures
every owned application input's exact canonical preimage (in `split`'s one-
input or `merge`'s into-then-from two-input order) and sends them to custody
alongside the fee source preimage; the protected side independently decodes,
validates ownership/schema/nominal type, and recomputes every reference and
amount before rendering its own review. `mint` and `burn` keep their
existing custody refusal in this profile (they are DR-0253's own kind-4
family); `create-asset` is now supported under its own separate kind-5
family (DR-0255); `transfer` is unaffected and stays on kind 2.

## Lifecycle and limits

`custody revoke`, recovery and rotation reuse the existing durable store and
lifecycle exactly as DR-0246 describes; nothing about expiry, revocation or
key recovery changes for this family. The separately owned Docker fixture extends the original publication, six
lifecycle and transfer controls with an actual CLI split-to-self then merge
round trip in fresh stores. It uses the same fixed container image, resource,
output and time bounds and no-network policy. It checks the exact offline/CLI
bytes, authenticated requests and result/query correspondence, funded amounts,
consumed input, nonce, nonempty matching receipts and exact replay observations,
then durable revocation in the same process and after restart. Actual source
and execution qualification belong in [TODO.md](../../TODO.md).

### Stopped disposable-key Split/Merge recovery consumer

Added 2026-10-17 under the existing DR-0244 and DR-0249 contract. The fixture
appends a signing-only recovery consumer after the original native host,
signer and revoked restart have exited and their socket is absent. Fresh
request IDs `9b` and `9c` repeated 32 times receive independent complete-frame
approvals over real PTYs; approval through a pipe must still refuse. These
requests use the retained original split preimages and the merge snapshots
captured after the actual original `91` split. The fresh `9b` signature is
never submitted, so the merge snapshots are not outputs of a new split.
No new application chain, current-state freshness or nonce advance is claimed.

The original disposable seed signs both new requests through a separate
bounded reference server. After its actual wait, PID and socket disappearance,
two custody-UID private-copy children back up and restore only that seed.
The current config, preimages and approval/revocation store are preserved.
A recovered server signs the same two request files and must return identical
nonempty signed bytes to their respective new-request reference files.
Original revoked `91`/`92` requests remain refused; after cancellation, new
`9b`/`9c` requests also refuse. All four refuse again after a recovered-key
server restart, with every refusal output absent. The three exact summaries
are `2/2/2/0`, `6/6/2/4` and `4/4/0/4` for connections, handled, signed and
refused. Original business, transfer and all family controls remain unchanged.

This addition allocates 18 CLI children, two real PTY children, three bounded
serve children and two private-copy children. Its 14 exact new regular files
share a 32 KiB allowance; captured command/PTY output shares 48 KiB, and final
JSON evidence is at most 4 KiB. Every nonsecret comparison is bounded to
64 KiB; key bytes stay inside the existing custody-UID copy primitive with
its 256-byte limit. These are suballocations within the unchanged global
230-second Python/280-second Node, 256 KiB inner output, 64 MiB volume and
512 MiB container limits. No resource or capability is increased. Source
preparation and these finite checks do not establish actual whole-fixture
headroom; owning execution and qualification remain tracked in TODO.md.


### 2026-10-18 foreign split and received-Coin return control

This separate fixture control exercises the already-accepted foreign recipient
of `split`. It uses one fresh two-owner development genesis and live store,
with the existing disposable A and B keys and separate prefunded fee Coins.
A's protected kind-3 `split` sends 5,000,000 of its 10,000,000 Coin to B.
The original source stays with A at version 2/value 5,000,000; precisely one
new Coin is version 1/owner B/value 5,000,000. After A's original signer and
revoked restart have both actually exited, been waited, and lost their socket,
B's protected kind-2 whole transfer returns that SAME new Coin to A at version
2/value 5,000,000. A's remaining source bytes stay unchanged. A and B each
advance only their own nonce from 0 to 1 and each pay from their own fee Coin.
No third identity, fee funding migration, merge, mint or application authority change
is part of this control.

Before the split, B's preparation against A's source must refuse ownership.
Afterward A's preparation against the CURRENT B-owned new Coin must refuse,
using A's current fee preimage and nonce. Each actual operation has its own
complete operation-specific PTY approval, offline/actual CLI signed-byte
comparison, matching-identity cancellation, same-process refusal and restarted
refusal. Before sending any confirmation input, the new control requires the
complete real PTY review to match every line of the bounded prepared review,
including the full signing frame, source/fee references, context and fee policy.
It separately requires exact sender/recipient/request/operation and amount
lines, the foreign split's `recipient_is_self=false`/remainder, and the exact
`APPROVE-SPLIT` or `APPROVE-TRANSFER` confirmation prefix. The common PTY
helper's new optional expectations default to empty for every old call. All six refusal output paths remain absent. Fresh requests are `c1`
(split) and `c2` (return), repeated 32 times; `c3`/`c4` are the two preparation
refusals. No old request, counter or assertion is reused or relaxed.

The NEW ignored `distinct_uid_genesis_split_identity_handoff_probe` has
`generate`, `serve`, `after-split` and `after-return` modes. Its independently
queried canonical objects must match the exact source/received identity, nominal
type, schema, amount, owner and version. It authenticates both saved complete
frames and checks exact arguments, object/fee references, paid results and
application effect sets, quoted fee settlement and output ownership, nonempty
matching receipts and every saved request replay against the same live store.
The transient reservation remains absent, with no durable effect. Replaying the
split and return must preserve complete results, receipts, all observed object
query bytes and both nonces. Existing self-split/merge and whole-Coin handoff
probes keep their own original predicates unchanged.

The normal addition is 19 `run_exec` children, two real PTYs, four bounded
signer children and one native store host (26 total), with no private-key-copy
child. Its 32 private regular evidence leaves share 2 MiB, all command and PTY
capture shares 48 KiB, and final JSON evidence has 4 KiB. The two additional
leaves relative to the whole-Coin control retain A's exact remainder and its
current fee preimage. Readers retain owned 0600/single-link/no-follow checks.
All original 117 completion flags remain covered by the publication/genesis
core (70) and the application profile's original setup (47), with common
success/cleanup counted once. The complete setup host validator is shared with
the application profile, including every stage, group, path and counter check.
The 21 foreign-split controls run independently with fresh disposable A/B keys,
setup, volume, process accounting and output accounting:

```sh
node scripts/check-docker-custody-fixture-1013.mjs \
  --cli-binary /absolute/path/to/sunrise-edge-cli \
  --test-binary /absolute/path/to/sunrise_edge_cli-HASH \
  --profile publication-genesis
node scripts/check-docker-custody-fixture-1013.mjs \
  --cli-binary /absolute/path/to/sunrise-edge-cli \
  --test-binary /absolute/path/to/sunrise_edge_cli-HASH \
  --profile application-transfer-recovery
node scripts/check-docker-custody-fixture-1013.mjs \
  --cli-binary /absolute/path/to/sunrise-edge-cli \
  --test-binary /absolute/path/to/sunrise_edge_cli-HASH \
  --profile genesis-split-handoff
```

Omitting `--profile` or explicitly selecting `default` aliases only the
clearly identified `publication-genesis` core. Its JSON does not claim the
old single-invocation 117 shape. The application command above is mandatory
for that original coverage; unknown profile names refuse.
The independent profile calls the existing setup, keygen and config helpers,
then only the foreign-split phase. It additionally uses the existing waited
operator-UID permission probes for each custody key and its matching retained
approval. Its setup has two keygen children and four waited permission-check
children, in addition to the phase's unchanged 26 children. The phase's 32
regular evidence leaves and four setup key/config leaves use the same volume.
No seed bytes are read, exported, or included in result JSON by these checks.

The original 117 predicates now map to two separate owning runs; the 21
foreign-split predicates remain a third run. Their union retains 138 existing
semantic predicates, not one whole138 invocation or a sum of every recursive
Boolean leaf from the three JSON records. Each process starts its ordinary accounting once. No accounting
is reset or discarded within either invocation. The failed combined attempts
remain evidence of the previous cumulative-output allocation failure.

These are suballocations inside the unchanged 280-second Node/230-second
Python, 256 KiB embedded program/captured-child output, 64 KiB bootstrap and
Docker wire, 64 MiB/16,384-inode volume, 512 MiB/no additional swap, CPU1/PID64
container bounds, separately for each selected profile. Each retains the
256 KiB captured-command/PTY cap, and the foreign-split phase retains its
48 KiB suballocation. Complete transport admission and actual profile results
still require owning validation recorded in `TODO.md`; static source checks
do not establish runtime success. The new probe is test-only and requires an
attributed harness containing its exact selector; a later MJS-only profile
layout change does not relabel that compiled harness's source. It does not relax `ApplicationAssetPin`'s
creator==publisher rule, establish an application-wallet handoff, key recovery,
full key/account rotation, public ceremony or all-M2 completion.
