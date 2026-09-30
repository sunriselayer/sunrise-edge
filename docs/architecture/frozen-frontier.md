# Ordered Freeze and immutable publication frontiers

[DR-0167](decisions/0167-frozen-frontier-extraction-boundary.md) extracts
this operational capability from the complete [epoch-handoff design](epoch-handoff.md).
It extends [publication-before-apply](publication-availability.md), not contract
semantics or a privileged Standard Asset path. Work status belongs in
[`TODO.md`](../../TODO.md).

## Signed authority and atomic closure

A fresh `GenesisManifest` `0x6416/v3` signs a positive minimum ordered block
height. Version 1/2 field sets, signing preimages and admission remain
unchanged and do not authorize Freeze. The installed logical profile's
`0x6480/v2` authority cache must match the exact signed manifest/minimum.
There is no mutable setting, unsigned authority or implicit store upgrade.

The existing shared HotStuff chain orders `FreezeIntent` `0x6454/v1` in the
same operation-bearing slots as economics. Before proposal or a new vote,
each signer checks actual proposed height and the advisory next epoch's
committed bond, key, power and resource-policy eligibility. Execution checks
them again. Advisory membership is not selected membership or readiness
proof; bond amount does not replace the voting-power rule.

Only actual ordered commitment installs `AdmissionClosureRecord`
`0x6457/v1` together with its outcome under atomic writer, epoch, committee
and revision fences. Proposal, elapsed time and local operator assertions
do not close admission. Closure refuses fresh application prepare/mutation,
publication ACKs and economic admission. A retention racing Freeze either
commits complete verified material before closure or exposes no new ACK.
Exact earlier ACK and completed application replay remain read-only.

An authenticated proposal whose justification itself commits Freeze cannot
expose a fresh business vote from a stale pre-event snapshot. Empty/control
consensus progress and exact historical vote replay remain available; high
and locked QCs are not reset. Fresh evidence resolves the actual serving
epoch. Unknown, corrupt or ambiguous prerequisites stop progress rather than
manufacturing deterministic no-effect refusals.

## Complete immutable local frontier

After closure, bounded invocations advance a durable cursor through the
complete existing chain-prefix publication collection. Each full certificate,
original signed intent, witness and actual artifact closure is independently
re-verified. The frontier includes certificates never applied locally and
ACKs never aggregated. Partial prepares and digest-only references are not
frontier members or completeness proof.

Publication/artifact/ACK addresses remain unchanged. Corrupt or unsupported
foreign-epoch rows cannot be skipped as absence. Chunked artifact validation
and bounded scans introduce no whole-history cap. Cursor updates bind exact
Freeze/context/committee and observed revisions. Complete enumeration
atomically fixes the immutable descriptor and local signature before
exposing the vote. Retry verifies and returns the same vote; no contract
execution or alternate signature is performed.

Frontier identity, vote, accumulator and page use `0xD036` through
`0xD039/v1`, with signature domain `epoch-frozen-frontier-v1`. Durable
progress/final frames use `0x6459`/`0x645A/v1`. Page transport request/response
uses `0xE107`/`0xE108/v1`, with 1 through 128 entries per request. Independent
JavaScript vectors pin public framing and accumulator bytes.

## Transport and saved recovery

The opt-in native certified host exposes:

- `POST /v1/fastvote/frontier/advance`: one confirmed bounded step. HTTP 204
  means progress only; final response carries the original retained vote.
- `POST /v1/fastvote/frontier/page`: a bounded consecutive range and exact
  final vote. This read never advances or applies state.

The SDK pins the outgoing committee and endpoint signer. The compiled CLI
additionally pins signed-v3 genesis, chain/protocol/epoch, atomicity domain
and actual Freeze request/height. It verifies every consecutive page, count
and complete accumulator. A successful HTTP response alone does not establish
complete enumeration. Missing, duplicated, reordered or wrong-context
material fails verification.

The CLI synchronizes `frontier.vote`, individually named canonical
`page-00000000000000000000.response` files, and a `complete` marker containing
the exact vote. Only verified terminal completion writes the marker. Saved
bytes are immutable: interrupted runs re-verify them before continuing, and
mismatches/corruption refuse overwrite. A saved vote alone is provisional.

## Remaining boundary

One complete local frontier is not the quorum-retained union. Identity pages
do not transfer full bundles or prove remote artifact retention. This
capability provides neither ordered DrainSet/drain application nor
authenticated cut/import, readiness, Seal or activation. Fresh Logical
activation remains refused. Freeze is irreversible in this profile: restart
resumes frozen protocol progress, never unfreezes admission.

This profile is for controlled acceptance, not public-network rollover until
the continuation is implemented and verified. There is no force-unfreeze or
time-based cancellation. See the [operator guide](../guides/frozen-frontier.md).
