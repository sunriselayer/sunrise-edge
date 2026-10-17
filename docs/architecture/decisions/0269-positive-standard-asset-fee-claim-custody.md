# DR-0269: Protected positive Standard Asset fee-claim Split

Date: 2026-10-17 (Asia/Singapore)

Status: Accepted for the implementation boundary. Actual qualification belongs in TODO.

Use the trusted local OS model selected in DR-0214. One separate custody UID
holds the original historical claimant key and serves one finite, closed local
IPC family. Both the embedded positive Split leg and its outer claim require
that key. Reuse DR-0267's immutable typed policy and genuine verified successor
workflow; a current committee member or a caller's epoch cannot replace the
original certificate authority.

Keep two create-only approval files for the same protocol request, distinguished
by Leg and Claim phase. Each retains complete canonical content, trusted
root/current context/domain/anchor/historical identity, exact meaning and frame,
with an exclusive expiry. Both unexpired approvals are required for the outer
signature. The existing permanent request tombstone cancels both phases, even
after old approvals are restored or custody restarts. Serve never writes an
approval. Already released signatures cannot be recalled.

The local kind-6 codec carries specific preimages, never an arbitrary frame,
entrypoint, trust configuration or key. Both peers reconstruct the typed owner
and independently finalize each signature. Claim preparation verifies the
existing signed leg without signing it again. Existing protocol encodings,
development commands and kinds 1 through 5 remain unchanged.

Reuse finite server, peer UID checks before body, private files, configuration,
key loading, fixed replies and socket cleanup. A new owned trust wrapper keeps
original genesis/resource context separate from successor execution context and
historical certificate epoch. Existing genesis-equals-execution asset trust is
not applicable. Load a key only after trusted workflow construction.

This boundary approves an exact conditional proposal. It does not certify a
current escrow head, entitlement, nonce freshness or host row digests. Real
store-backed preparation and ordered execution continue to enforce those facts.

See [the custody contract](../positive-standard-asset-fee-claim-custody.md).
