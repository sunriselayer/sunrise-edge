# DR-0167: Extract ordered Freeze and immutable frontier export

## Decision

Accepted implementation direction, 2026-09-30. Deliver the next operational
capability from [DR-0154](0154-complete-epoch-handoff.md) as authenticated
ordered Freeze followed by resumable signed frontier export. It includes core,
native HTTP, Rust SDK, compiled CLI and independent PostgreSQL replica
acceptance. It is not a marker-only library slice or permission to merge the
unfinished aggregate handoff branch. Implementation and verification status
belong only in [`TODO.md`](../../../TODO.md).

The current open-epoch [availability capability](../publication-availability.md)
retains full certificates before application. A closed frontier is the next
necessary mechanism: it enumerates full certificates held by one replica,
including operations never applied locally and ACKs never aggregated by that
replica. It does not by itself prove a quorum-complete union or authorize a
drain application.

## Signed authorization, not retroactive reinterpretation

Preserve the existing `GenesisManifest` `0x6416/v1` and `0x6416/v2` field sets,
signing preimages and admission behavior. Version 1 has fields 1 through 8;
version 2 adds only field 9, `LogicalGenerationV2`. Neither authorizes Freeze.
Do not add field 10 under version 2 or infer authority from an HTTP flag,
installed logical profile, mutable node setting or peer response.

A fresh manifest `0x6416/v3` binds the logical commitment profile and an
explicit positive `minimum_freeze_block_height` in signed field 10. Use a
distinct version-3 signature-message domain. Strict decoding rejects missing,
extra, zero, historical-profile and unknown-version combinations. Installation,
reopen and locally pinned network configuration independently verify this
exact genesis authority. This is a fresh-store profile, not a migration or
automatic upgrade of an existing signed manifest.

For bounded application admission, the installed `LogicalProfileRecord`
`0x6480/v2` carries that positive, signed-genesis-derived minimum in field 6.
Existing `0x6480/v1` profile bytes remain unchanged and cannot authorize
Freeze. Genesis installation and every reopen/profile resolution check the
exact record version, manifest authority/digest and minimum against the
signed manifest. Absence, a tombstone or a mismatched record never downgrades
the profile. New Freeze observations and their CAS assertions apply only to
this version-3-authorized profile, so older witnesses do not acquire an extra
signed read or a changed admission rule. This local authority cache is not a
new user-selected profile and cannot be rewritten to upgrade an active store.

Freeze carries a canonical advisory validator set for the immediately
following epoch. Honest proposal and vote creation check the proposal's
actual ordered height against the signed minimum and validate committed bond,
key, power and policy eligibility using the generic validator rules. Bond
amount does not become voting power. Commit-time execution repeats those
checks against CAS-fenced current prerequisites. This advisory set witnesses
a possible continuation; it does not select membership, prove next-set
availability or replace the later readiness and Seal authority.

## Closure and shared consensus

Only a committed outgoing-set Freeze in the existing shared HotStuff chain
closes admission. Proposal submission, elapsed time, a tick or a local
operator assertion does not. The closure marker commits atomically with the
ordered outcome under writer, epoch, committee and row-revision fences.
Every application, new prepare, retention ACK and economic candidate/vote
path must observe the marker with the correct commit-time CAS discipline.
A retention racing Freeze either commits its complete material before closure
or returns no new ACK. No synthetic original-user receipt is invented from
an uncertified pending prepare.

An event whose authenticated justification commits Freeze must not expose a
fresh business vote from its own payload using a stale pre-event admission
snapshot. Safely preview the verified observer's resulting control state.
Historical vote replay and justified empty/control consensus progress remain
available; do not reset inherited high/locked QCs. An inherited committed
business operation receives the specified authenticated no-effect refusal,
while corruption, missing prerequisites or an ambiguous storage outcome stop
progress rather than manufacture such a refusal. Fresh equivocation evidence
must resolve the actual serving epoch, not an obsolete genesis-only fence.

In this capability committed Freeze is irreversible. Restart resumes frozen
protocol progress, reads and exact completed replay; it never unfreezes the
epoch. Fresh Logical activation remains explicitly unsupported. A public
network must not enable this profile merely because Freeze/export pass tests:
DrainSet, drain, verified cut, readiness, Seal and activation remain necessary
for a complete live rollover. There is no force-unfreeze or cancellation flag.

## Exact immutable frontier and bounded transport

Derive the frontier from all locally retained, independently verified full
publication certificates in the closed epoch. Recheck original signed intent,
certificate, witness and complete actual artifact bytes under local trusted
context. A partial prepare, digest-only reference, empty ACK collection or
caller-supplied list is not a frontier member or proof of completeness.

Keep the already-allocated publication, artifact and ACK storage addresses
unchanged. Do not silently move chain/request rows to chain/epoch/request
under the same family and hide prior retained bytes. Enumerate the complete
bounded chain prefix and verify record context before inclusion. This
single-epoch extraction cannot reinterpret a foreign-epoch or corrupt row as
absence; unsupported history fails closed. Later multi-epoch collection
addressing requires its own explicit design and exact-history verification.

Each invocation processes a bounded number of records/bytes and persists an
exact CAS-fenced cursor. Complete scanning fixes an immutable descriptor and
the local signed vote together before exposure. Retry returns the original
verified vote and pages, not a freshly signed alternate identity. Pages bind
context, Freeze identity, ordered range, count and the complete accumulator;
omission, addition, duplicate, reorder, alternate closure, malformed cursor,
tombstone and missing artifact fail closed. Chunking must accommodate legal
large artifacts without an arbitrary whole-history limit or unbounded scan.

The extraction processes one complete publication per advance using the
existing 2,048-artifact and 32 MiB bundle bounds. It checks declared lengths
before allocating bodies and pins portable descriptors across reads of at
most 1 MiB each. Missing, tombstoned or changed descriptors are refusals,
not evidence of absence. Present declared-empty values retain their exact
terminal-empty range semantics. There is no intra-artifact durable cursor.
An identity page may re-verify up to 128 complete publications sequentially;
the page byte cap is not an artifact-I/O budget. These bounded native checks
do not establish edge-runtime CPU or production load readiness.

The native route, SDK and CLI expose Freeze candidate construction, ordinary
ordered submission and bounded frontier advance/export. Locators never confer
authority. The client pins the signed genesis/committee and verifies returned
descriptor signatures and complete page linkage before synchronizing saved
output. Output overwrite, mismatched trust context and incomplete export are
refusals. Restart resumes the same saved/export identity without executing a
contract or changing an original receipt, nonce, object or fee settlement.

## Acceptance and next boundary

Use genuine independent PostgreSQL-backed validator hosts and the separately
compiled CLI. Generate ordinary paid Publish/Instantiate/Call and a charged
trap. Retain a valid full certificate without local application and include it
in the frontier even when that holder lacks an aggregated availability proof.
Commit actual Freeze, compare verified descriptor/page membership, kill/reopen
hosts during frontier progress and prove exact export/replay. Exercise the
height and advisory eligibility refusal, Freeze/retention CAS race, same-event
business-vote closure, stale writers, malformed/corrupt/omitted/reordered
material, failed/indeterminate commits and completed application replay.
All no-mutation claims compare complete same-replica snapshots, including
replica-local signing-safety rows and revisions.

The next capability is quorum-retained frontier union, ordered DrainSet and
certificate-backed member application with narrow conflicting-reservation
resolution. No cut/import, conditional readiness, Seal, new-epoch serving,
deployment, real custody, HA, load or production-readiness claim follows from
this extraction. Re-sweep and document every new canonical type/key/domain;
preserve all historical bytes and independent vectors. Full repository
validation and exact-final-head independent review remain merge gates.
