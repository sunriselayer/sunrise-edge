# Publication-before-apply availability

This bounded capability implements the open-epoch FastVote publication step
from [DR-0154](decisions/0154-complete-epoch-handoff.md). It composes with
[signed logical execution generations](logical-execution-generation.md),
not with an implicit upgrade of a historical store. It does not implement
epoch handoff, Freeze, DrainSet, Seal or next-set activation.

## Flow and authority

1. Logical FastVote prepare derives the staged outcome without applying it,
   and atomically retains the exact `0x6424/v2` commitment witness and its
   required artifact bytes with the prepared record and exclusive locks before
   returning its vote. A later source request reconstructs those durable
   bytes with a supplied, independently verified FastCertificate; it does not
   execute the contract again or fabricate missing prepare material.
   Aggregate transaction capacity is checked before Logical signing; a
   later signer rejection or rejected commit cannot leave a separate material
   write. Indeterminate completion exposes no new vote; exact reconciliation
   verifies the retained witness and artifact bytes before returning it.
   Conflicting or corrupt destination material is never overwritten or
   repaired from current application state.
2. Each retainer verifies the full certificate against its own committed
   committee and serving context, authenticates the original signed intent,
   checks the witness commitment and requires the manifest to equal the exact
   artifact closure derived from the witness's signed operands. Every declared
   artifact has actual bytes verified under the trusted hash-suite schedule
   or explicitly supplied bounded historical resolvers. Bundle-declared
   algorithms or epochs do not establish trust.
3. Retention atomically commits the publication record, all artifact bytes and
   this replica's signed availability vote under writer, epoch, committee and
   row-revision fences. A vote can be computed and verified locally before
   that commit, but it is never returned on a rejected or indeterminate
   outcome. Exact retention replay re-verifies the stored material and vote;
   an equivalent valid FastCertificate signer subset returns the original
   ACK without retaining another proof variant.
4. The client verifies individual ACKs under the locally pinned committee and
   forms a strict greater-than-two-thirds availability certificate for one
   exact identity: chain, protocol, epoch, logical atomicity domain, request,
   signed-intent digest and execution commitment. Its signed genesis selects
   the commitment profile; a server response cannot select or downgrade it.
5. Fresh Logical apply, including signerless missed-prepare recovery, requires
   that verified availability certificate bound to the independently
   re-derived execution. Its bytes join the effects, fee settlement, receipt,
   nonce and lock-resolution mutations in one atomic application commit.
   Charged traps require the same publication proof. Completed exact replay
   resolves its original receipt before fresh policy, module or availability
   admission and cannot charge or apply again.

Retention itself never executes WASM, moves objects, charges fees, advances
the sender nonce, creates an original application receipt, or changes another
request's reservations. A conflicting partial local prepare does not prevent
execution-free retention of a valid full certificate.

## Surfaces and bounds

The certified-only native HTTP router adds bounded POST routes for prepare
material sourcing, bundle retention and published apply. Direct/legacy
mutating routes remain unmounted. The published apply request uses
`0xE106/v1`; publication bundle/manifest/entry frames use `0xD035`/`0xD034`/
`0xD033/v1`. Publication and local ACK records use `0x6455`/`0x6456/v1`;
the committed availability-certificate record uses `0x6458/v1`. Independent
JavaScript vectors pin new public wire bytes.

The Rust SDK verifies source bundles and returned ACKs, bounds each peer and
the whole operation by checked deadlines, and preflights the availability
certificate before applying. The compiled CLI reserves distinct outputs
before prepare, synchronizes signed intent and FastCertificate, then saves
the availability certificate before the first published-apply POST. Saved
replay uses the exact three files, without signing again. Historical v1
commands retain their original path and reject Logical-only output flags.
The older multi-entry catch-up workflow is not extended to carry Logical
availability proofs by this capability; Logical recovery uses the published
apply/saved-replay path with its explicit proof.

One operation's closure must fit the existing bounded canonical bundle and
atomic-store transaction; a closure exceeding `MAX_RETAINED_ARTIFACTS` is
refused, not partially acknowledged. This is not a whole-chain size limit or
a resumable multi-commit import protocol. Prepared data is replica-local;
publication/artifact and availability-certificate rows are authenticated
history, while local ACKs remain signing-safety state, not global cut facts.

The Cloudflare embedded host retains its historical endpoint and refuses
fresh Logical apply without publication authority. This feature only keeps
its common error mapping total; it does not mount these native routes in a DO.

## Remaining boundary

There is no Freeze marker, frontier closure, drain authority, authenticated
portable cut, complete causal scheduling, target import, readiness, Seal or
next-epoch provenance in this capability. Fresh Logical epoch transition
remains explicitly unsupported. Availability retention does not prove these
properties or independently controlled production custody. Integrated
acceptance, review/CI gates and the work queue belong in `TODO.md`.
