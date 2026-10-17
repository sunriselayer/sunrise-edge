# Positive Standard Asset fee-claim Split custody

[DR-0269](decisions/0269-positive-standard-asset-fee-claim-custody.md) connects the
[immutable proposal policy](positive-fee-claim-split-policy.md) to a finite local
custody backend. The first profile supports only positive strict partial Split
of the original genesis fee resource, its original certificate epoch and exact
known package. FinalTransfer and other families have no route through it.

Custody, approver and client independently load local original genesis and
successor artifact pins. Configuration declares the current execution context,
hash suite and domain. Its historical claimant identity is independently checked
against the original certificate committee. The original publication publisher
may differ. No wire field selects trust paths, code, instance or a signing frame.

The Leg request retains terms and the complete fee object/reference/hash-epoch
assertion. Both peers call `StandardAssetPositiveSplitPolicy::prepare_leg`.
Custody compares exact whole approval content before signing; both peers use
typed finalization. Existing seed-free host preparation consumes the signed leg.
The Claim request retains that exact Leg request, canonical signed leg and saved
canonical host request/intent. Custody reconstructs and authenticates the leg,
checks byte equality, and calls `prepare_claim`. It never signs the leg during
Claim processing. The client finalizes the outer signature and uses the existing
candidate encoder/authenticator.

One private 0700 directory holds 0600 phase files
`<request>.positive-fee-split.leg` and `<request>.positive-fee-split.claim`.
Records are create-only and bounded. They contain complete canonical preimages,
trusted binding, exact recognized meaning and signable frame, identity and
exclusive expiry. Duplicate approval writes refuse. An outer approval/signature
also requires the matching current Leg approval. The existing `<request>.revoked`
record is shared by both phases; restoration of either phase cannot resurrect
authority. Approval requires an explicit terminal confirmation. Serve only reads.

The server retains the existing exact UID check before body, finite counts and
one total deadline, bounded length decoding, fixed 64-byte response and socket
identity cleanup. The client checks custody UID before sending, performs no
automatic retry or seed fallback, and independently verifies the signature.

Codec, file and refusal tests are distinct from genuine successor signing and
from actual UID protection. The genuine existing successor acceptance helper
must retain original positive Split bytes/frame/candidate parity. A separate
selected distinct-UID/PTY fixture remains required for both phases, using real
verified first-successor artifacts exported by the existing producer, protected
historical key provisioning, revocation between phases, restart, recovery,
rotation mismatch, stop/reap/socket disappearance, and complete child/output/
resource accounting. It must not manufacture workflow authority from a manual
epoch/context or replace the original eight-link/e8/35-role required recurrence.
Current actual source, compile and runtime status belongs only in TODO.

The explicit command sequence is `custody prepare-fee-split-leg`,
`approve-fee-split-leg`, `sign-fee-split-leg`, existing seed-free host preparation,
then `custody prepare-fee-split-claim`, `approve-fee-split-claim` and
`sign-fee-split-claim`. `custody serve-fee-split` handles both phases with one
historical key; ordinary `custody revoke` cancels both. Sign commands require
the explicit custody signer selection. They do not accept a development seed.

Every command independently requires `--config`, `--genesis-manifest-file`,
`--genesis-digest`, `--certificate-epoch`, `--validator-id`, the complete explicit
`--suite` history and existing repeated `--successor-*` archive flags/budget.
The config epoch is current; `--successor-genesis-epoch` is original. Leg input
uses `--fee-object`, canonical `--fee-ref`, `--fee-object-hash-epoch`,
`--escrow-request-id`, `--request-id`, `--amount`, `--recipient`, `--nonce` and
`--gas-limit`. Claim preparation uses `--request` for the saved Leg envelope,
`--signed-leg`, `--host-request` and `--host-intent`. Output paths are explicit
and refuse overwrite. Approval uses `--request`, `--approvals-dir` and positive
`--expires-in-seconds`; Claim signing also takes `--created-checkpoint` and
exports the existing authenticated ordered candidate.

The separate UID/PTY owning profile must explicitly receive and pin the CLI
and probe binaries/Cargo provenance, original manifest/digest/context, complete
hash schedule, ordered successor archive roles and exact historical claimant,
plus full fee object/ref/epoch and terms. The existing genuine artifact producer
must export these bounded artifacts; no fixture constructor may assert that an
arbitrary current context is verified. Provision the disposable historical key
only inside the custody UID, copy public archives into independent role-owned
paths and preserve their expected digests. The operator receives no seed/key
path or environment key. The parent review must fix deadline, memory, swap, CPU,
process, volume/inode and full raw-output caps before this selected profile runs.
It must retain both phase reviews/frames, byte-parity outputs, refusal/lifecycle
records and actual wait/EOF/cleanup for every child. This pending profile grants
no source-only or ordinary test UID-protection credit.
