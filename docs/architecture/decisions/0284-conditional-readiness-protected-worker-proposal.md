# DR-0284: Conditional readiness protected worker proposal

Date: 2026-11-03, Asia/Singapore

Status: The human selected the trusted local OS and distinct-process/UID
boundary for readiness on 2026-11-03. This record selects no release profile,
provider, host user or production key. Implementation and qualification are
tracked in TODO. The publication-only decision in
[DR-0238](0238-publication-only-local-os-custody.md) did not itself select
readiness.

## Existing owner and gap

The actual `vote-sqlite` consumer in
[`apps/operator/src/conditional_readiness.rs`](../../../apps/operator/src/conditional_readiness.rs)
loads the 32-byte signer key in the operator process. Its
[`ReadinessSigningKey`](../../../crates/node-core/src/conditional_readiness.rs)
holds that key in the same process that reconstructs the inactive target and
retains the vote. The core checks the protected Serving slot, complete import,
bounded next set, actual key/member match and eligibility in its existing
order; it signs only
for an absent readiness slot, verifies the vote, and releases output only after
confirmed retention or exact fresh reconciliation. A retained vote is checked
and returned without a new signature. These checks and their order are the
authority owner; a raw `conditional-readiness-v1` frame is not permission to
sign. Readiness grants no successor Serving authority.

The same key type is also passed to successor activation, although activation
does not sign. Its actual-key/member check is still part of that owner's
admission. Moving readiness signing cannot silently replace this check with a
caller-asserted public key. The existing original ordered and certified
FastVote workers in [DR-0264](0264-original-ordered-protocol-custody-worker.md)
and [DR-0268](0268-certified-fastvote-protocol-custody-worker.md) explicitly
exclude readiness and successor signing.

## Selected boundary and proposed composition

For the selected trusted local OS boundary, place the current complete
readiness operation, validator key, inactive SQLite target, blob store,
configured optional independent anchor and current writer-fence observation
in one distinct-UID worker. The current `vote-sqlite` reads the existing fence
without advancing it; this proposal does not import the original/certified
workers' mandatory anchor or offline fence-advance requirement. A keyless
frontend may
forward one bounded, enumerated `vote-sqlite` operation through authenticated
local IPC. The worker owns local configuration and source/target path admission;
the request cannot choose a key, signing domain, authority role, storage
namespace, raw signing frame or arbitrary file path. It reuses the existing
`retain_conditional_readiness` and recurring-chain owner rather than copying
eligibility or retention logic into the frontend. The existing ordinary
combined `vote-sqlite` command remains compatible and must never run as a
second concurrent writer.

The worker pins the expected validator ID, Ed25519 public key, chain/context,
hash schedule, atomicity domain, source/target identities and exact
`conditional-readiness-v1` use from trusted local inputs. It checks the actual
loaded key against the verified eligible successor-set member before signing.
The existing core constructs the subject for the signed vote from verified
source-free evidence and decides whether the retained slot is absent. IPC
conveys operation inputs and a closed result, not `sign_framed(bytes)` or a
generic consensus signer. The worker returns bounded vote bytes; the keyless
frontend writes the immutable output artifact only after the existing
independent expected-subject and signature checks. It must not require the
worker UID to write into the operator-owned output directory. The frontend
must rederive the expected subject from its own pinned and verified source/cut inputs
with the existing `readiness_subject_for_candidate` owner, then use
`ReadinessCertifier` for subject, signer and signature. Merely checking the
worker's returned subject or a transport acknowledgement proves no authority.

An IPC refusal, timeout, disconnect, worker stop, wrong key, malformed result
or unreconciled ambiguous commit yields no successful new vote and no
development-key fallback. The current core may return an exact landed vote
after fresh reconciliation. After the prior worker is stopped, a restarted
worker reopens the target and observes its current fence through the existing
operation context, then uses the exact retained-slot path to reconcile a
confirmed result. It does not advance the fence merely because of restart,
blindly retry a signing request, or invent a global sign-once rule: corrected
pre-Seal candidates remain nonexclusive under the current core contract.
Socket and work admission must be finite; started work must drain before the
worker releases its authority and file ownership. This profile makes no
compromised-root, encrypted-at-rest, hardware or rollback-anchor claim.

Successor activation uses the same actual identity but creates no readiness
signature. Its key/authority proof must stay with the activation owner; the
readiness IPC route must not become an activation or successor-host route.
Successor automatic signing is the separate M2-N2 decision. Genesis/admin and
human asset approval are also outside this worker.

## Original implementation checklist and remaining verification

The prospective wording below is the original design checklist, not a live
implementation status. Current source and exact qualification belong in
[TODO.md](../../../TODO.md).

First define the finite request, trusted configuration, output ownership and
frontend's independently pinned import binding from the existing CLI inputs,
then reuse the original core retention function inside the worker. The pure
`readiness_subject_for_candidate` check does not by itself prove import
completeness or eligibility; the worker's core keeps those authority checks.
Share bounded IPC/UID/socket primitives with the existing local workers where
they fit, without copying their role-specific route table or fence behavior.
No new canonical protocol message, signature domain, SQL schema, generic signer
or short substitute test is proposed. The existing ignored owner
`compiled_conditional_readiness_real_retention_restart_and_distinct_certificate`
in [`conditional_readiness_sqlite.rs`](../../../apps/operator/tests/conditional_readiness_sqlite.rs)
should gain the distinct-UID/key-inaccessibility, normal vote, wrong-key,
refusal, lost-response and retained-restart observations that the selected
deployment actually needs. The recurring owner in the same file must retain
its original seven epochs and withdrawal checks. Core unit controls continue
to prove absent/present slot and corrected-candidate behavior; they do not
duplicate the process fixture. Exact-source required validation and hosted CI
follow an implementation change under the existing repository gate.

The readiness worker's trusted local configuration, distinct process/UID
permissions and recovery authority still require review. No
real key, host user, security policy, deployment, or stopped audit/fixture is
authorized by this document. Current progress and remaining M2 conditions
belong in [`TODO.md`](../../../TODO.md).
