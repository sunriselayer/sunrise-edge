# Protected ZeroShare fee-claim custody

[DR-0257](decisions/0257-protected-zero-share-fee-claim-custody.md) adds this
family to the trusted-local-OS boundary. This guide describes the
implemented contract; qualification status belongs in
[TODO.md](../../TODO.md). See
[saved successor fee-claim review](fee-claim-review.md) for the shared
`economics fee-claim-prepare`/`-review`/`-sign` surface this family extends,
and [publication-only local OS custody](local-publication-custody.md) for
the base trusted-local-OS/separate-UID model every family shares.

> [!WARNING]
> This is a development-only fixture, not a production key-management
> profile. At-rest encryption and compromised-root resistance are not
> claimed. Do not point it at real keys, real users, or a public network.

## Trust and profile

Unlike the Standard Asset families (DR-0246/0249/0253/0255), this family's
trust is not `PinnedAssetTrust`: it is the existing
`SuccessorWorkflowAuthority`, the same source-free successor evidence
`economics fee-claim-review`/`fee-claim-sign` already verify. Custody's own
`FeeClaimZeroTrust` wraps one `CustodyConfig` plus one
`SuccessorWorkflowAuthority`, loaded through the existing
`commands::hash_suite_pins::publication_resolver` and
`commands::successor_pins::load_successor_pins` helpers — reused directly,
not reimplemented.

ZeroShare releases no value and carries no embedded transaction, so there is
no raw leg for a human to approve and no way to turn this family into a
payment. A pure guard, `require_zero_share_profile`, runs before any
workflow or socket I/O and refuses:

- `Split`/`FinalTransfer` (any non-`ZeroShare` operation);
- a nonzero `share_amount`;
- a request carrying a `signed_leg`;
- a request/intent `request_id` mismatch, or a zero `request_id`;
- a claimant key other than the one custody is pinned to sign for.

`PreparedFeeClaim::prepare` and `FeeClaimReview::build` then run exactly as
`fee_claim_review.rs` already uses them: the claimant is selected from
`certificate_set(intent.certificate_epoch)` — the historical committee,
never the current one — and every other field (resource, generation, row
digests, recipient) is the host's proposal, enforced only by actual ordered
execution, never by custody.

## No new signing command

There is **no** `custody sign-fee-claim`. The only consumer that produces a
submittable candidate is the existing `economics fee-claim-sign`, which now
accepts the same three custody signer flags every other family's CLI
consumer does (`--custody-socket`, `--custody-uid`,
`--custody-expected-public-key`) as an exclusive alternative to
`--claimant-seed-file`. Selection is checked from arguments only, before any
file I/O:

| Selection | Result |
| --- | --- |
| `--claimant-seed-file` alone | Existing development signing, unchanged |
| All three custody flags | Protected custody signing |
| A partial custody trio | `PartialCustodySignerConfiguration`, before any I/O |
| Seed plus any custody flag | `ConflictingSignerSelection`, before any I/O |

Review mode (`economics fee-claim-review`) never registers the custody
flags; passing one there is an ordinary unknown-flag parse failure, the same
mechanism that already refuses `--claimant-seed-file` in review mode.

In custody mode, `fee-claim-sign` decodes the saved `--request`/`--intent`
exactly as before, runs the pure profile guard, rebuilds the workflow and
`PreparedFeeClaim`, requires the resulting claimant to equal the pinned
custody key, sends the exact request/intent pair to custody over the kind-7
socket, and independently calls `PreparedFeeClaim::finalize` on the returned
signature before building the candidate — the same independent verification
the seed path already performs.

## Independent approval and serving

```bash
sunrise-edge-cli custody approve-fee-claim \
  --config /private/config \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --suite 0:1:1:1:1:1:1:1 \
  --successor-genesis-epoch 0 --successor-max-links 1 \
  --successor-plan-history-dir /private/link0/plan \
  --successor-cut-dir /private/link0/cut \
  --successor-manifest-history-dir /private/link0/manifest \
  --successor-certificate-dir /private/link0/certificate \
  --request /private/request.bin --intent /private/intent.bin \
  --approvals-dir /private/approvals --expires-in-seconds 3600

sunrise-edge-cli custody serve-fee-claim \
  --config /private/config --key-file /private/custody.seed \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --suite 0:1:1:1:1:1:1:1 \
  --successor-genesis-epoch 0 --successor-max-links 1 \
  --successor-plan-history-dir /private/link0/plan \
  --successor-cut-dir /private/link0/cut \
  --successor-manifest-history-dir /private/link0/manifest \
  --successor-certificate-dir /private/link0/certificate \
  --socket /custody-run/fee-claim.sock --approvals-dir /private/approvals \
  --max-connections 8 --max-requests 8 --total-deadline-secs 300
```

`--request`/`--intent` are the exact canonical saved bytes the seed-free
`economics fee-claim-prepare` export already produces — the same files
`economics fee-claim-review`/`fee-claim-sign` accept.

Approval requires a real terminal, renders the full bounded
`FeeClaimReview` (prefixed with a `profile=protected_zero_share_fee_claim`
line), and requires the exact typed `APPROVE-FEE-CLAIM-ZERO` confirmation
line naming the claimant, validator, certificate epoch, context, request/
escrow IDs, resource, generation, previous/next row digests,
`share_amount=0`, recipient and intent digest, plus the expiry — every field
read verbatim from the one built review. Revocation is rechecked
immediately before and after the prompt. The written record reuses the
existing whole-frame `ApprovalRecord` unchanged.

`serve-fee-claim` is a distinct kind-7 decoder and policy: a kind 1–6 frame
sent to it refuses, and a kind-7 frame sent to `serve`/`serve-transfer`/
`serve-split-merge`/`serve-mint-burn`/`serve-create`/`serve-fee-split` refuses too. To produce
the raw signature the socket returns, `serve-fee-claim` uses a small
`CapturingSigner` wrapping the local signer as an `ExternalSigner`, passed
to `PreparedFeeClaim::sign_and_finalize_external` — this keeps the SDK's own
scheme/identity check ahead of signing and `finalize`'s own verification
immediately after, in the same call, before the captured signature is ever
returned.

## Checkpoint labeling

`created_checkpoint` is an outer candidate field set after signing; the
claimant's signature does not cover it and custody never approves it. An
operator can rewrap a signed claim with any checkpoint. Both the seed and
custody output paths of `economics fee-claim-sign` state this explicitly
(`created_checkpoint_not_covered_by_claimant_signature=true`); neither
claims the printed candidate is fixed by the signature.

## Lifecycle and limits

A custody config is valid for exactly one `e+1` context; a new epoch needs a
new config, with no fallback. `custody revoke` reuses the existing durable
store exactly as every other family. Custody never certifies the escrow
row's currentness, generation, or whether the claim is already used — that
stays exclusively with ordered execution at apply time. Split/FinalTransfer
custody, key recovery/rotation for this family, live submission of a
custody-produced candidate, automatic protocol signing, and real keys or
ceremony are all out of scope for this slice.
