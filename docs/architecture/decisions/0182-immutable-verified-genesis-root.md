# DR-0182: One immutable verified genesis root

Date: 2026-10-02 (Asia/Singapore)

Status: Accepted detailed design under DR-0180 after independent Opus review
at `3e5c4b7` on 2026-10-02. This is design approval, not implementation or
security-audit approval. It grants no new protocol or serving authority.

## Context

The architecture-first pass found repeated genesis authentication in SDK file
loading, operator loading, ordered policy, registration and reconstruction.
These paths also rebuild the original committee and sometimes reauthenticate
the same manifest several times. Their authority-key checks differ in strictness.

The SDK's trusted FastVote bundle exposes mutable certifier/profile/Freeze
fields. Consequently every owned operation must recheck the supposedly trusted
bundle against duplicated committee and admission values. Reconstruction takes
profile, manifest, digest and resolver independently and correctly cross-checks
them, but callers must construct and preserve the same relationship themselves.
Moving these functions into smaller files would leave the design unchanged.

## Decision

Introduce the private immutable `VerifiedGenesisRoot` defined in
[genesis trust](../genesis-trust.md). Its only public constructor authenticates
bounded canonical bytes against local pins and stores the exact resolver,
signed profile and original committee together. Share strict authority and
committee primitives with the installer and installed-profile verification.

Migrate actual core policy/registration, SDK, operator and reconstruction
consumers. Delete independently constructible bundles and duplicated checks,
not just place wrappers in front of them. Use a root-derived genesis ordered
policy and a separately named genuine historical constructor. Trusted SDK
operations use the root resolver rather than an independently selected schedule.

Keep installation, fresh installed-row fencing, historical verification and
live serving authority separate. The root authenticates original genesis, not
all bootstrap effects or any later epoch's right to sign. Preserve independent
policy/history/domain consistency checks in reconstruction and real private
genesis installation. Remove the public admission-profile authenticator and
operator raw-manifest loader rather than preserve parallel verification paths.
Ordered environment/HTTP state get the current resolver from their policy;
registered bond verification gets it from the root. Reconstruction additionally
matches the root-derived anchor/committee/full resolver schedule, rejecting an
internally consistent historical policy/archive substituted for signed Freeze.
The existing first-epoch host retains actual installed/live-pin, signer and
writer checks; root-derived configuration is not later-epoch activation.
No canonical bytes or protocol IDs change.

## Alternatives and consequences

- A shared file helper leaves mutable authority bundles and repeated policy
  reconstruction. It reduces text duplication, not invariant duplication.
- A universal trust context mixing genesis, current epoch and operation fence
  would permit one authority axis to stand in for another. Reject it.
- An immutable manifest without its resolver leaves callers free to hash later
  operations under a schedule different from the one that verified the pin.
  Bind the resolver to the root and migrate its actual consumers.
- An additional blob-reader abstraction is not part of this unit. Add it only
  when a genuine read-only consumer or fake writable adapter justifies it.

The unreleased Rust API changes intentionally remove ambiguous constructors
and public mutable trusted fields. Earlier lax verification may now reject
noninstallable manifests earlier; typed diagnostics and multidefect precedence
are tested. Historical canonical manifests, anchors and envelopes stay valid.

## Acceptance

The architecture document specifies before/after byte fixtures, classified
construction negatives, compile-fail mutability boundaries and actual CLI,
SDK, operator and SQLite workflow acceptance. Fresh independent exact-head
review and complete required gates precede normal merge. No readiness, Seal,
activation, production qualification or live deployment is implied.
