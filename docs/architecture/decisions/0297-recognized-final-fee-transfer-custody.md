# DR-0297: Recognized final fee-transfer custody

Date: 2026-11-25 (Asia/Singapore)

Status: Implemented as a bounded local component. Live key enrollment and release qualification remain open in TODO M2.

## Decision

Add a separate FinalTransfer selection to the existing historical claimant fee-release owner. Keep the accepted strict-partial positive Split bytes and phase meanings unchanged. The FinalTransfer leg must be the exact in-tree original-genesis Standard Asset `transfer` of the entire retained fee Coin to the selected recipient, under the independently verified successor workflow and original certificate claimant. The amount must be positive and equal to the retained Coin balance. No caller supplies a signable frame or an alternative package, instance, resource, entrypoint, type argument, object access, or signer identity.

The embedded leg and outer fee claim are two distinct approvals and signatures under the same protected historical key. The outer claim must contain the exact authenticated signed leg, matching request selectors, complete share amount, resource and object reference. The complete bounded review retains the recognized meaning plus the existing generic fee-claim review. Host-proposed generation and row digests remain untrusted until ordered execution; retained object and nonce freshness are not established by a display.

## Local custody boundary

The existing bounded kind-6 local wire gains explicit phase tags 3 (FinalLeg) and 4 (FinalClaim); tags 1 and 2 and their bytes remain unchanged. Phase-specific approval files do not inherit Split approval. Both phases share the permanent request tombstone, exact-content expiry and restored-record refusal. The existing `serve-fee-split` worker accepts only tags 1/2, and `serve-fee-final-transfer` accepts only tags 3/4. The operator still cannot read the protected key under the selected distinct-UID model. No generic signer endpoint or protocol wire type is added.

The local component requires focused canonical, refusal, approval and worker-selection checks. Actual distinct-UID/PTY lifecycle, real enrolled claimant key, current live escrow, final-source full gate and public beta approval remain separate TODO conditions. A same-key recovery cannot transfer historical entitlement to a new identity.
