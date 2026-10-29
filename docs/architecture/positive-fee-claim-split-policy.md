# Recognized positive Standard Asset fee-claim Split proposals

[DR-0267](decisions/0267-positive-standard-asset-fee-claim-policy.md) defines this
pure application-specific preparation boundary. Current validation status and
remaining M2 requirements belong in [TODO](../../TODO.md).

`sunrise_edge_cli::positive_fee_claim_split` recognizes one operation: a positive,
strict partial Split of the original genesis Standard Asset fee resource, executed
under an independently verified successor workflow by its original historical
claimant. This is an immutable proposal/meaning owner, not an approval or custody
backend. It has no key, signer/provider trait, process, IPC, network, storage write
or new CLI command. Both inner-leg and outer-claim signatures have separate typed
finalization. A backend must protect both uses of the same historical key.

## Independently retained inputs

The constructor retains a `SuccessorWorkflowAuthority`, its complete verified
genesis/resource policy and explicit `HistoricalClaimantPin`. This first profile
requires the pin's certificate epoch to equal that root's original epoch and
precede the successor execution epoch. The key must be the exact Ed25519 key in
`certificate_set(certificate_epoch)`. Current membership supplies no replacement
authority. No synthetic historical committee or external currentness assertion is
accepted in place of that owner.

The policy selects only the signed genesis fee resource. It reauthenticates the
complete original publication, compares its entire code artifact, WASM, ABI,
exports, empty dependency closure, profile and semantics to the in-tree
`public-standard-asset` package, and reconstructs the exact original initializer
instance. Resource type/schema and split/transfer role names must match. It does
not copy the other custody families' assumption that execution epoch equals
genesis epoch. The original resource context and exact code/instance remain
distinct from the current successor call context and historical claimant epoch.
Other resources, upgraded code/instances and additional certificate epochs need
their own explicit policy; they are not accepted through a generic argument path.

`RetainedFeeObject` supplies the full bounded canonical object bytes, exact
reference and an explicit local hash-epoch assertion in this same protocol. The
policy recomputes that digest and reference, checks nonzero/nonexhausted version,
schema and logical Coin type, and requires exact FeeEscrow custody owner scope
(chain, escrow subject and resource). These checks bind the preimage; they do not
prove its provenance assertion, current durable head, certified escrow history,
remaining entitlement, or absence of another claim. The existing real
store-backed preparation and execution still own those facts.

## Two immutable stages

`PositiveSplitTerms` fixes the selected escrow/request, positive amount, full
recipient, captured nonce and gas. Amount must be strictly below the retained
Coin balance. The recipient uses the existing canonical-prime-order address
validator. The nonce must permit advancement; reserved replay identifiers and
gas outside the existing local-execution ceiling refuse.

1. `prepare_leg` reconstructs one exact profile-four Call: the retained successor
   context, historical claimant sender, pinned Standard Asset code/instance,
   `split`, exact resource type arguments, one Write access to the retained fee
   object, canonical amount/recipient arguments, explicit nonce/gas and no nested
   authorization. The existing `PreparedLocalExecution` checks the complete
   authenticated scope. The complete recognized meaning and exact leg frame are
   retained together. Signature finalization independently authenticates that
   same immutable leg.
2. The signed leg owns the only canonical request it may submit to the existing
   seed-free host preparation. Its known package has exactly one creation in
   Split, so the existing creation-ID/type/body/hash helpers predict the payout
   from the exact signed event, original instance and ordinal zero. Prediction is
   conditional on successful execution, not an executed receipt or claimed WASM
   test. Saved request/intent files must be bounded and byte-canonical, match this
   retained request, and contain a positive Split with that exact signed leg,
   fee object, amount, original resource/certificate epoch and predicted v2 payout.
   The existing `PreparedFeeClaim` then rechecks historical identity/selectors,
   derives the original exact outer frame and verifies its returned signature.

Legacy Split without a v2 payout, FinalTransfer and other operations remain
outside this owner. Their existing codecs, non-authorizing review and development
CLI behavior are unchanged. No signature bytes, protocol ID, schema or candidate
encoding is added or changed. The ordinary candidate checkpoint stays with the
existing caller and candidate wrapper.

## Meaning and limits

`PositiveSplitMeaning` reports known code/instance, resource, original certificate
and successor execution epochs, historical claimant, escrow/request, complete fee
reference, retained balance, amount, conditional remainder, recipient, nonce,
gas and exact leg frame. It explicitly states that entitlement, escrow currentness
and nonce freshness are unproven. The final owner includes the unchanged complete
`FeeClaimReview` and labels generation/previous-next row digests as proposals.
Neither a non-authorizing renderer nor a host's proposed economics becomes a
semantic trust source. All displayed values are bounded; unsafe chain text or an
aggregate beyond 128 KiB refuses rather than truncates.

A future approval/backend integration must independently retain the pins and
preimages, approve and serve the same immutable content, protect both key uses,
and preserve explicit expiry, permanent revocation, restart, stop/reap, recovery
and historical-key rotation limits. This module makes none of those lifecycle
claims and does not select real key holders or a ceremony. Unknown or missing
trusted inputs must remain a refusal rather than a fallback to generic signing.
The leg and outer claim share one protocol request ID but have different frames;
their future approval storage must keep the two phases distinct and make the
same permanent cancellation cover both. An outer approval cannot silently
replace a leg record in a live caller's request path.

The pure leg tests use a genuine verified genesis root and an explicit successor
context solely to exercise content recognition, byte parity, signature checking
and refusal. They create no verified successor authority. Genuine successor and
historical-key parity assertions run only inside the existing positive Split
branch of the original compiled successor acceptance helper, using its real
workflow, host-prepared intent and independent existing signatures. Original
recurrence, host, replay and lifecycle assertions remain in place. Prepared or
compiled assertions are not runtime evidence.
