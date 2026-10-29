# Saved successor fee-claim review

[DR-0245](decisions/0245-saved-successor-fee-claim-review.md) defines this
non-authorizing inspection and development-signing slice. Live status belongs
in [TODO](../../TODO.md).

## Exact inputs and authority

`PreparedFeeClaim` retains the exact request and peer-prepared unsigned intent.
Local genesis, digest, domain, hash schedules and every source-free successor
link independently determine the expected e+1 context and historical committee.
The claimant is selected from `certificate_set(intent.certificate_epoch)`, not
from the current committee or an endpoint's assertion. The prepared owner and
finalization keep the exact signing frame and independently verify the returned
signature. They do not certify the peer's current escrow-row state.

`FeeClaimReview::build(&prepared)` displays the operation-specific retained
content with explicit bounds and terminal-safe values. It includes every claim
field, exact signed-leg bytes and decoded local-execution fields, object refs,
code/instance references, ordered access and authorization content, full raw
arguments, signature bytes, intent digest and signing frame. Code identity and
raw generic arguments are identified as uninterpreted. Host-proposed amount,
generation, row digests and object refs are enforced by actual ordered execution;
a readable representation does not make them trusted observations.

Malformed or mismatched legs, unsafe text and excessive display sizes refuse.
No field is silently truncated or replaced by a hash. This surface does not
create an approval, verify business meaning, authorize an embedded leg, establish
ownership/nonce freshness, or protect a key. Publication custody remains closed
to fee-claim frames and its existing approval/revocation behavior is unchanged.

## CLI workflow

Use the existing `economics fee-claim-prepare` pins and network configuration.
Choose exactly one output mode:

| Mode | Required additional flags | Result |
| --- | --- | --- |
| Existing development signing | `--claimant-seed-file`, `--created-checkpoint`, `--out` | Existing signed ordered candidate |
| Seed-free inspection export | `--claimant-public-key`, `--review-request-out`, `--review-intent-out` | Exact unsigned canonical request and intent; bounded review; no seed read or signature |

A partial export or a mixture of modes refuses. Review output paths must differ;
files use the existing private writer, with an owned 0700 parent and new 0600
files. Existing destinations are never overwritten. The pair is not an atomic
filesystem transaction; an I/O failure may leave one valid export. Both complete
files must be present and independently checked before review or signing.

`economics fee-claim-review` takes `--request` and `--intent` plus the locally
trusted `--expected-chain-id`, `--expected-protocol-version`, `--expected-epoch`,
`--domain`, `--ordered-genesis-manifest`, `--ordered-expected-genesis-digest`,
optional repeated `--suite` and the complete ordered `--successor-*` link flags
(including `--successor-max-links`). It accepts no peer/network/seed flag. It
loads bounded canonical files, rebuilds the verified workflow and prepared owner,
and prints the review without network I/O or signing.

`economics fee-claim-sign` uses those same saved files and local pins, plus
`--claimant-seed-file`, `--created-checkpoint` and a fresh `--out`. It checks that
the saved operation can be fully rendered before loading the development seed,
then signs the retained frame, independently verifies the signature and
reauthenticates the wrapped candidate. The checkpoint is an explicit outer
candidate field; the saved request/intent determine the signed fee-claim bytes.
Signing is development-only and does not imply that anyone approved a previous
printout. A changed saved file is checked as a different operation under the same
pinned authority; a screen view is not an approval record.

## Validation boundary

Focused renderer/codec cases test structural content, unsafe text, bounds and
canonical refusal. The retained compiled successor-host acceptance owns the
real source-free workflow: it saves the request/intent through the seed-free
CLI, runs offline review and sign, and compares the entire candidate with the
independent legacy signature/encoding. Historical-key/current-member refusals
and every original recurrence, delay, restart and restore control are retained.
Compiling those assertions alone is not evidence that they ran.
