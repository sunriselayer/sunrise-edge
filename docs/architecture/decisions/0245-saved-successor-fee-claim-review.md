# DR-0245: Saved successor fee-claim review and development signing

Date: 2026-10-15, Asia/Tokyo

Status: Accepted for the bounded, non-authorizing local review slice.

## Decision

Extend the existing `economics fee-claim-prepare` consumer with a seed-free
mode that takes an explicit claimant public key and saves the canonical request
and unsigned intent. The existing development-seed mode keeps its behavior.
Offline `economics fee-claim-review` and `economics fee-claim-sign` independently
load the same locally pinned source-free successor evidence and reconstruct
`PreparedFeeClaim` from the saved bytes. The sign command uses the existing
local development signer and finalization; it is not protected custody.

The SDK review accepts only the immutable prepared owner. It presents the exact
request/escrow identities, historical certificate epoch and committee claimant,
resource, amount/recipient, row generation and digests, fee/payout object refs,
operation and complete decoded signed-leg content, raw leg bytes and signing
frame. The saved intent file is the exact canonical byte record. All text is bounded and terminal-safe; unsupported, malformed or
oversized presentation refuses without truncation. Generic argument bytes and
code references are identified as uninterpreted, not business approval.

Genesis, hash schedules, domain and every successor link are local trust inputs.
The prepare peer is only a source of proposals. `PreparedFeeClaim` checks its
selectors and selects the claimant from the certificate's historical committee,
not current membership or an endpoint assertion. Economics and row references
in the host-prepared intent are still proposals, enforced by actual ordered
execution. A readable review does not independently certify current row state,
code semantics, embedded-leg authorization, ownership or nonce freshness.

Review exports use the existing private filesystem writer: owned mode-0700
parent, fresh mode-0600 file, no overwrite. The two files are not an atomic
transaction; an I/O failure may leave one valid export, never a signed claim.
Review and sign require both complete canonical files and verify them again.
Changing either saved file cannot silently change a retained prepared owner.

## Compatibility and limits

Reuse existing request/intent codecs, signing domains, payload bytes,
`SuccessorWorkflowAuthority`, historical committee lookup, candidate wrapping
and final signature authentication. Add no protocol IDs, cryptography,
dependencies, generic signer endpoint, seed fallback or publication-custody
permission. Legacy prepare output remains unchanged. Offline development sign
binds the exact saved intent, with the existing separately specified candidate
checkpoint, and is not an interactive approval ceremony.

Protected fee-claim signing needs its own independently pinned custody evidence,
operation-meaning policy and key-use boundary. If the same historical key is
also held by a validator process, protecting only one copy does not isolate that
key. Automatic consensus/readiness and genesis/admin signing retain their own
authority and durable safety owners. This record neither creates those routes
nor selects real key holders or ceremonies. Public/real-key decisions remain
with their existing owners; routine implementation does not require a new
human family-sequencing approval.

## Validation

Exercise seed-free and legacy flag separation before I/O; canonical/trailing and
size failures; exact request/intent and historical-identity refusal; full positive
and zero-share presentation; malformed/mismatched embedded legs; terminal safety
and output bounds; private no-overwrite exports; and saved-byte signing parity
through an actual verified successor workflow. Pure renderer tests alone do not
prove committee authority. Retain original publication custody controls and the
complete required repository gate.
