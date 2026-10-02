# DR-0179: Authenticated initial validator bond registration

Date: 2026-10-02 (Asia/Singapore)

Status: Accepted implementation boundary after independent design review and
correction of deterministic-refusal classification. The authorized Codex
substitute returned APPROVE; Opus was unavailable. This is a
functional prerequisite for [DR-0154](0154-complete-epoch-handoff.md)'s real
incoming E, not authority to change membership or activate an epoch. Current
implementation and validation status belong only in [TODO.md](../../../TODO.md).

## Missing initial transition

Genesis only installs Active bonds for its committee, while the existing
Deposit requires an existing Exited bond. An incoming non-genesis validator
therefore cannot actually post its first collateral. Creating a synthetic
Exited row, accepting an unsigned bond row or relaxing genesis custody checks
would not establish legitimate liability or replayable history.

Introduce a separate `bond_lifecycle::registration` owner. Preserve the existing
v1 lifecycle envelope, signing domain, real-predecessor Preamble and
genesis-rooted bond-chain validation. Registration is a real ordered operation
through the existing generic custody contract, not another Standard Asset path.

## Identity and authorization

For a new non-genesis registration require validator ID equal to the exact
canonical Ed25519 authorization-key bytes. Reuse CanonicalPrimeOrder admission.
Reject every ID or authorization key in the independently pinned signed genesis
registry, even when its member is no longer active. This closes arbitrary-ID
squatting and reuse of a genesis identity/key. Existing genesis identities and
their historical bytes remain unchanged.

The new validator signs the complete initial-registration payload. The exact
source owner independently signs one existing local execution leg. The leg
must name the same context/request and target exactly this validator/resource's
BondCollateral scope under the existing committed economics authority.
Collateral donation is legal with both signatures; an envelope alone cannot
spend somebody else's object. There is no current-member signature requirement
for the new key. Ordering still needs the outgoing quorum's normal consensus.

This initial capability requires the pinned causal genesis/profile and the
first outgoing epoch. Resource authority remains the signed genesis economics
context, not a candidate-selected policy. Later repeated epochs may preserve
this installed liability; arbitrary registration after rollover requires the
separately verified serving-authority capability. Same-epoch incoming E's old
Unbond/Replace/etc. paths remain explicitly unsupported because their pure
authentication still requires outgoing membership. Do not silently widen those
paths by trusting a raw bond row. Once E legitimately joins, existing lifecycle
rules operate through the later verified-serving composition.

## Closed framing

Allocate fresh version-1 frames after an owning namespace sweep:

| Frame | Fields in canonical order |
| --- | --- |
| 0x64E0 intent | 1 operation PublicationContext, 2 nonzero Ordered request ID, 3 validator ID, 4 scheme u16, 5 exact 32-byte key, 6 defining resource PublicationContext, 7 existing BondResourceId frame, 8 exact existing signed execution leg bytes, 9 expected generation-1 row Digest32, 10 independently pinned genesis Digest32 |
| 0x64E1 signed envelope | 1 exact intent frame, 2 exact 64-byte signature |
| 0x64E2 registration anchor | 1 operation PublicationContext, 2 validator ID, 3 exact signed envelope, 4 exact resulting generation-1 bond row |

Use centralized NodeEvent hashing at the operation epoch for the complete
intent and original event identity, and existing 0x2001 signature framing with
distinct `FastPathBondRegistration` message label. Preserve all older domains.
Precisely, intent_digest is NodeEvent at e over the exact canonical 64E0
bytes. Field 6 of the 0x2001 signature frame is the self-describing
`encode_digest32(intent_digest)` bytes, not a raw intent or bare digest32.
The original registration receipt/event identity is NodeEvent at e over the
exact canonical signed 64E1 envelope. The ordered candidate digest remains its
existing separate identity; it cannot substitute for that receipt identity.
The signer pins the exact resulting bond row using the existing
`bond_row_digest` (ExecutionEffects at that row's lifecycle epoch). The payload
contains the registered key and ID, so an envelope cannot be relabelled.

Bound the leg by its existing local-execution bound and the complete signed
envelope by that bound plus 4096 bytes. Bound the anchor by the signed-envelope
bound plus the existing 64 KiB bond-row limit plus 4096 bytes for framing;
the resulting row itself must obey that existing 64 KiB bound. Context chain IDs are at most
128 bytes and protocol version is nonzero, for operation and resource contexts.
Require closed fields,
exact decode/re-encode and checked arithmetic before allocating/copying.

Store the immutable anchor at the exact chain/validator owning key
`fastpath/bond-registration/`. Allocate `OrderedOperationKind::BondRegistration`
discriminant 7; existing discriminants and canonical candidate bytes stay exact.
No new public NodeEvent family or generic maintenance method is introduced.

## Admission, execution and atomic installation

Authenticate bounded canonical envelope and inner leg before receipt-first
exact/conflicting request reconciliation. On a fresh operation, validate
Ordinary origin, current causal admission/epoch, pinned genesis/configuration,
pristine bond/registration-anchor/generation-1 transition observations and
absence from the current validator set. Absent means never-written initial
revision: a tombstone or noninitial absence refuses. An existing registration
does not accept another key, resource, anchor or generation-1 root.

Reuse ordinary ordered sender/input reservations, committed resource policy,
generic capability-scoped admitted leg execution and custody-effect validation.
Require a real owned source with exact type/schema/authority, no object creation,
no trapped leg, exactly the allowed whole-object ownership mutation, and a
nominal amount within the enabled minimum/exposure policy. The resulting bond
is Active generation 1 with current lifecycle/custody epoch, the exact actual
ObjectRef/authority and signed resulting digest. Liability begins at checked
current epoch plus one, not retrospectively. Voting power is not bond amount.

One existing atomic invocation commits actual object mutation, sender nonce,
logical generation/provenance, original receipt, new bond and signed anchor.
Do not synthesize a previous bond or an old-style generation-1 transition. Its
slot must be pristine because later ordinary transitions start at generation 2.
Ambiguous outcome is handled by exact original receipt reconciliation; no
partial authority or guessed success. Duplicate healthy registered identity
is an ordered semantic refusal. Deterministic caller-invalid results against
fully healthy admitted inputs also produce typed semantic refusals: a trapped
leg, forbidden effects, invalid amount/minimum/exposure, or incorrect signed
generation-1 digest must not wedge the ordered prefix. Classify these at their
owning checks after isolated execution; do not inherit the existing lifecycle's
blanket unclassified-Invalid-to-Prerequisite mapping or use message strings.
Missing, corrupt, unavailable, fenced or ambiguous prerequisites still stop;
they are never converted to guessed business refusals. A refused registration
installs no collateral/nonce/bond/anchor or application receipt. The ordinary
ordered refused outcome/receipt is retained atomically, and a subsequent valid
candidate must make progress. Freeze's existing closed-admission rule also
covers this kind.

## History and usable surface

Pure ordered authentication checks the new key's signed registration and exact
owned leg plus its local pinned genesis/context; it never treats the candidate
as a member. Integrate causal required observations, reservations, preflight,
normal dispatch and original archived material. The registered-chain owner
verifies a retained signed root and exact generation-1 row before walking later
existing transition records. Genesis-rooted validation remains unchanged.

Structural root/chain verification does not establish independent execution.
Private reconstruction must execute the original registration from genuine
owned producer history and compare all resulting bond, anchor, object, nonce,
receipt and provenance bytes. Add exact owning projection/classification for
the new anchor, not a broad exemption for registration State prefixes.

Expose bounded offline Rust preparation/signing and the existing authenticated
ordered-network submission/catch-up route. Preserve separate local protocol/
genesis pins and TLS authority. No membership, readiness, Seal or serving
authority is created by registration success or its receipt.
The first preparation command accepts an exact predicted generation-1 row and
signed leg as bounded operator inputs. It validates their structural linkage
and signs the expected row digest; it does not turn that supplied row into
state or execution proof. Only actual ordered generic execution and exact
resulting-row equality can install it. Automatic read-only VM preview is not
a prerequisite for this command or a new authority bypass.

## Acceptance

Use genuine Ed25519 keys and generic WASM, a real non-genesis E-owned object
produced by certified paid execution, and outgoing ABCD ordering. E is
ineligible before registration and eligible afterward through actual policy/
bond predicate; outgoing membership remains ABCD. Do not force Exited or seed
a positive bond/anchor/receipt. Verify each validator's complete resulting
state, file-backed SQLite restart/replay/fencing, source-free private replay,
compiled preparation/submission and the >128-row imported history used by the
later readiness feature.

Negatives include wrong/noncanonical/identity/torsion keys, ID/key reuse, donor
or envelope signature mismatch, foreign context/genesis/resource, wrong owner/
type/schema/effects, trapped leg, minimum/exposure, nonce and stale writer,
already registered/conflicting ID, tombstones, corrupt root/result and request
reuse. Prove no partial object/nonce/bond/anchor or registration-application
receipt changes on refusal, exact retained ordered-refusal replay, and valid
ordered progress following each deterministic invalid registration.
Run the full repository gate, exact-head independent review and required CI.
This feature is neither Delivery 3 completion nor independent security audit.
