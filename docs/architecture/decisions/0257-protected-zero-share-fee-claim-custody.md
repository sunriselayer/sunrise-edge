# DR-0257: Protected ZeroShare fee-claim custody

Date: 2026-10-16

Status: Accepted design. Qualification is tracked in TODO.md.

## Decision

Extend the trusted-local-OS custody boundary (DR-0238/0246/0249/0253/0255)
with a fifth family that protects the historical claimant key used to sign a
`FeeClaimOperation::ZeroShare` fee claim (DR-0137/DR-0214/DR-0245). This is
the minimum protected slice: ZeroShare releases no value and carries no
embedded transaction, so there is no raw leg to approve and no payment custody
can be turned into. The codec admits `ZeroShare` only with `share_amount == 0`
and no `signed_leg`; execution independently re-derives the claim type from
the escrow row and checks the same before installing it.

Unlike DR-0246/0249/0253/0255, this family does not share `PinnedAssetTrust`.
Fee-claim trust is the existing `SuccessorWorkflowAuthority`
(`successor_pins::load_successor_pins`), the same evidence
`economics fee-claim-review`/`fee-claim-sign` already load. Custody's own
`FeeClaimZeroTrust` (`apps/cli/src/custody/fee_claim_zero.rs`) wraps one
`CustodyConfig` and one `SuccessorWorkflowAuthority`, built from
`--genesis-manifest-file`/`--genesis-digest`/`--suite`/`--successor-*` flags
through `commands::hash_suite_pins::publication_resolver` and
`commands::successor_pins::load_successor_pins` — both bumped from
`pub(super)` to `pub(crate)` for this reuse, with no behavior change. No new
trust implementation, hashing, or committee-lookup logic is added: custody
calls the existing `PreparedFeeClaim::prepare`/`FeeClaimReview::build`
exactly as `fee_claim_review.rs` already does, and nothing else.

A pure `require_zero_share_profile(request, intent, expected_claimant_public_key)`
guard runs before any workflow or socket I/O, in every caller (custody
`approve-fee-claim`, custody `serve-fee-claim`, and the new custody branch of
`economics fee-claim-sign`). It refuses `Split`/`FinalTransfer`, a nonzero
`share_amount`, a present `signed_leg`, a request/intent `request_id`
mismatch, a zero `request_id`, and a claimant key other than the one custody
is pinned to sign for — before `PreparedFeeClaim::prepare` ever touches the
verified workflow.

**No new signing command.** There is no `custody sign-fee-claim`. The sole
consumer that produces a submittable candidate is the existing
`economics fee-claim-sign`, which now accepts the three existing custody
signer flags (`crate::signer::{CUSTODY_SOCKET,CUSTODY_UID,
CUSTODY_EXPECTED_PUBLIC_KEY}`) as an exclusive alternative to
`--claimant-seed-file`. Signer selection is checked from arguments only,
before any file I/O; a partial custody trio refuses with the existing
`PartialCustodySignerConfiguration`, and seed-plus-custody refuses with the
existing `ConflictingSignerSelection`. Review mode never registers the
custody flags, so passing one there is an ordinary unknown-flag parse
failure — the same mechanism that already refuses `--claimant-seed-file` in
review mode.

To produce a raw signature, `serve-fee-claim` uses a small `CapturingSigner`
(`apps/cli/src/custody/server.rs`): an `ExternalSigner` that wraps
`&LocalSigner` and records what `sign_frame` returns, passed to
`PreparedFeeClaim::sign_and_finalize_external`. This keeps the SDK's own
scheme/identity preflight ahead of signing and `finalize`'s own signature
verification immediately after, inside one call; only then is the captured
signature trusted and returned over the wire. `economics fee-claim-sign`'s
custody branch independently calls `PreparedFeeClaim::finalize` again on the
received signature before building the candidate, exactly as the existing
seed path does.

A new adapter-local message kind 7 carries the untrusted
`FeeClaimPrepareRequest` (`0x6461/v1`) and the host-prepared `FeeClaimIntent`
(`0x6437/v1`) together, back to back, each length-framed and canonically
exact: `[1,7] | u32BE request_len | request bytes | u32BE intent_len |
intent bytes`. No protocol type ID, canonical byte layout, or hash domain
changes; kind 7 is an adapter-local framing choice only, like kinds 1–6. Kind
1 (publication), kind 2 (transfer), kind 3 (split/merge), kind 4 (mint/burn)
kind 5 (create-asset), and kind 6 (positive fee split) keep their existing decoders and `serve`/
`serve-transfer`/`serve-split-merge`/`serve-mint-burn`/`serve-create`/
`serve-fee-split` policies unchanged; a kind-7 frame is refused by all six, and kind 1–6
frames are refused by the new `serve-fee-claim`.

`custody approve-fee-claim` requires a real terminal and a typed
`APPROVE-FEE-CLAIM-ZERO` confirmation line naming the claimant, validator,
certificate epoch, context, request/escrow IDs, resource, generation,
previous/next row digests, `share_amount=0`, recipient, intent digest and
expiry — every field `FeeClaimReview` already renders for this claim, read
verbatim from one built review rather than recomputed independently.
Revocation is rechecked immediately before and after the prompt. The written
record reuses the existing whole-frame `ApprovalRecord` unchanged.

## Compatibility and lifecycle

No protocol encodings, cryptographic domains, execution effects, fee
arithmetic or historical vectors change. The kind-7 message is outside the
protocol namespace, by the same reasoning as kind 1–6. Approval, expiry and
revocation reuse the existing whole-frame store exactly, with no new record
format. `created_checkpoint` remains an outer candidate field the claimant's
signature does not cover and custody never approves; an operator can rewrap a
signed claim with a different checkpoint, and both the seed and custody
output paths say so explicitly.

## Limits

Same trusted OS/root, separate-UID model and limits as DR-0238/0246/0249/
0253/0255. A custody config is valid for exactly one `e+1` context; a new
epoch needs a new config, with no fallback. Custody never certifies the
escrow row's currentness, generation, or whether the claim is already used —
that stays exclusively with ordered execution. Split/FinalTransfer custody,
key recovery/rotation for this family, live submission of a custody-produced
candidate, automatic protocol signing, and real keys or ceremony are all
explicitly out of scope for this slice. No new cryptographic primitive,
canonical encoding, or protocol arithmetic is introduced.
