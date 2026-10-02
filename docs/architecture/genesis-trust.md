# Immutable genesis trust

This design centralizes locally pinned genesis authentication across core,
SDK and operator composition. It is distinct from installed bootstrap effects,
historical proof verification and current serving authority.
[DR-0182](decisions/0182-immutable-verified-genesis-root.md) records its rationale.
Implementation and verification status belong in [TODO](../../TODO.md).

## One verified value, one owner

`node_core::genesis::VerifiedGenesisRoot` owns these private immutable fields:

- The decoded signed `GenesisManifest` and its self-describing `Digest32`.
- The `HashSuiteResolver` under which the locally supplied pin was checked.
- The authenticated `VerifiedAdmissionProfile`.
- The validated original genesis `ValidatorSet`.

The root has no `Default`, decoding/serde implementation, unchecked constructor
or public mutable field. It can be cloned as historical evidence; cloning does
not confer writer, reservation, consensus-vote or activation authority. Its
resolver is part of the value, not a separate caller-selected dependency.

The public constructor is:

```rust,ignore
VerifiedGenesisRoot::verify_bytes(
    resolver: &HashSuiteResolver,
    bytes: &[u8],
    expected_digest: [u8; 32],
    expected_context: &PublicationContext,
) -> Result<VerifiedGenesisRoot, GenesisRootError>
```

The pin and context must be trusted local composition. Peer-supplied values do
not become trust merely by passing this function. Bounded SDK file loading
reads once, then invokes this constructor; it does not authenticate separately.

The constructor checks, in order:

1. Bounded canonical manifest decoding.
2. Manifest commitment against the raw local digest pin.
3. Manifest context against the expected context.
4. Resolver chain/protocol against that context.
5. Canonical round-trip equality.
6. Nonzero canonical prime-order Ed25519 authority and the profile-specific
   signed frame.
7. Original committee context, Ed25519 schemes, capacity and set validity.

Classified failures distinguish manifest/encoding, commitment, context,
authority/signature and committee errors. Committee reasons are typed so SDK
diagnostics can preserve their own unsupported-scheme wording without matching
strings. Multidefect tests pin public failure precedence. Strict authority and
committee checks are already required by the installer; this does not reject
an otherwise installable genesis because an SDK used to check less.

Read-only accessors expose `manifest()`, `digest()`, `genesis_context()`,
`genesis_resolver()`, `admission_profile()` and `genesis_committee()`.
There is no accessor or operation named current, live, serving or successor.

## Shared checks, distinct meanings

Genesis owns one strict manifest-authority check and one original committee
conversion. The root, installer and installed admission-profile verification
use these primitives. They retain the installer and admission owners' typed
failure mapping and existing ordering around storage/lifecycle checks.

The root authenticates the manifest and original committee; it does not prove
that publication, initialization, custody or installed objects are valid or
present. `install_genesis_with_history` still verifies all bootstrap semantics,
origin, writer fencing and atomic durable completion. Reconstruction still
performs a real private installation. Authentication is not installation.

Installed profile checks must still observe and fence actual rows. They cannot
replace fresh storage evidence with a copied root. Retained original receipts
continue to reconcile before fresh module/policy/object I/O.

`VerifiedAdmissionProfile::from_pinned_genesis` is removed as an independent
public authenticator. The root constructs its profile through a crate-private
already-verified primitive. Installed-row checks continue to invoke the shared
authority check against actual bounded row bytes; a root is not installed-row
evidence. The operator's raw-manifest loader is removed, not preserved as a
second signature verifier. Callers needing raw fields borrow `root.manifest()`.

The installer retains its existing public signatures and raw manifest input.
Its validation order stays round-trip, authority/signature, namespace read,
context checks, capacity and committee checks. Sharing primitives does not move
that namespace read or replace the remaining bootstrap validation. Tests pin
the typed error precedence when several installer defects are present.

## Actual consumers

| Owner | New input | Removed duplicate mechanism |
| --- | --- | --- |
| Ordered genesis policy | `from_genesis_root(&root, domain)` | Optional raw manifest, independent context/digest/set/resolver verification |
| Explicit historical ordered policy | `historical(...)` | Ambiguous `new(..., None, ...)` branch |
| Bond registration preparation and verification | `&VerifiedGenesisRoot` | Per-call `pinned_inputs` reauthentication and committee conversion |
| SDK file loader | Bounded bytes and trusted local pin/context | Freely constructed `PinnedGenesis`, copied signature and committee implementations |
| Trusted FastVote bundle | Private root and derived certifier | Public mutable trusted fields, duplicated pinned set, repair-by-rechecking bundle consistency |
| SDK ordered/bond contexts | Private root and root-derived policy | Separate manifest, digest and resolver copies |
| Operator business pins | One root plus operation-specific policy/history | SDK-equivalent authentication and repeated genesis committee construction |
| Reconstruction plan | `&VerifiedGenesisRoot` plus explicit resolver history | Independently supplied admission profile, raw manifest, digest and genesis resolver |

Every current non-test caller has an explicit disposition:

| Current caller | Disposition |
| --- | --- |
| `ordered_economics::policy::OrderedEconomicsPolicy::new` | Delete the optional constructor. Root-derived first-epoch policy or explicit manifest-free `historical(...)`; no independently supplied root values |
| `registration::{prepare_bond_registration, verify_signed_bond_registration, pinned_inputs}` | Root input; delete `pinned_inputs`; root resolver/profile/committee/economics determine authentication |
| `registration::handler::verify_registered_bond_chain` | Root plus explicitly local resolver history; delete separate manifest/pin/current-resolver inputs, retain exact history/provenance walking |
| `admission_profile::VerifiedAdmissionProfile::from_pinned_genesis` | Delete public entry; root-only private verified construction. Actual installed-profile checks retain shared authority verification |
| SDK `local_genesis::{load_pinned_genesis, validator_set_from_record}` | Public bounded verified-root file loader; delete independently constructible bundle and copied committee converter |
| SDK `fastvote_client` | Private `{root, certifier}`; derived read-only accessors and no duplicated committee consistency repair |
| SDK `causal_admission` | Root resolver for all owned methods; lane/context negatives retained before any I/O; low-level historical helpers stay separate |
| SDK `ordered_economics_client::load_trusted_ordered_policy` | Load root and derive policy; genuine manifest-free test/helper callers explicitly use `historical(...)` |
| SDK `bond_registration` | Hold root/policy; prepared local claim holds the immutable root, not fresh independent manifest/resolver/digest copies |
| Operator `common::load_trusted_genesis_manifest` | Delete raw public loader and copied signature check; delegate bounded file loading to SDK root loader |
| Operator `business_pins` and `bin/business_audit_pg` | Root-derived policy, history and reconstruction plan; remove repeated authentication, profile and committee builds |
| Operator `economics` and `bin/fastvote_pg` | Root loader for locally pinned genesis; raw installation remains real/fenced. Genesis committee uses root; live installed-record conversion stays separately owned |
| Operator `bin/fastvote_host_pg` | Root-derived fixed first-epoch ordered policy. Preserve actual installed-state/live-pin checks, local signer membership, writer fence and opt-in routing |
| CLI `fastvote_network` and `fastvote_frontier` | Private bundle accessors/root-derived certifier; no mutable trusted field or independent resolver for owned methods |
| Native HTTP `OrderedEconomicsState` and core `OrderedEconomicsEnvironment` | Policy owns the sole current resolver; delete separate resolver fields and migrate all environment constructions |
| Devnet/CLI fixture signing and genesis installer | Raw manifest signing is legitimate producer work, not another authenticator. Shared installer checks preserve complete bootstrap semantics |
| `logical_generation` installed manifest verification | Shared strict authority primitive against actual installed canonical row bytes; keep row/provenance fencing, no conversion of installed rows into root authority |

Remaining test constructors migrate to the same verified boundary or explicitly
named historical construction. The acceptance search enumerates every old
constructor/loader and mutable field use, not only the examples above.

Historical constructors remain only where a real manifest-free historical
consumer exists. They do not grant causal admission, Freeze or serving powers.
No compatibility wrapper preserves the old mutable trusted bundle or optional
genesis policy constructor merely because this API existed during development.

Trusted FastVote operations use the root's resolver, not an extra arbitrary
resolver argument. They still check request lane and signed intent context
before signing or network I/O. Low-level naked-certifier historical helpers
remain explicitly separate. Additional resolver history is explicit trusted
local composition, not an endpoint-selected schedule.

The ordered policy exposes its own read-only resolver, derived from the root
or owned by explicit historical construction. `OrderedEconomicsEnvironment`
and native HTTP `OrderedEconomicsState` have no separately supplied current
resolver. All evaluation, signing, recovery and registration consumers obtain
it from their policy/root. Resolver history remains a distinct explicit local
input; it cannot replace the current schedule. This makes disagreement
unrepresentable at these actual entry points, instead of adding another check
around two freely replaceable values.

Reconstruction continues to cross-check ordered policy, history identity,
domain, anchor and execution policies against the root. Existing checks among
the old independently supplied genesis values are not a missing validation
gap: they are redundant because the new value makes disagreement impossible.
Do not delete checks on the still-independent policy/history/domain inputs.
In particular the plan requires the policy's anchor to equal the canonical
anchor derived from `(root, domain)`, including the root's signed Freeze height,
and requires its complete current resolver schedule and original committee to
match that root. An internally consistent historical policy/archive pair with
Freeze height zero cannot substitute for a signed-v4 root. Add that negative
even though the old code's internal root-value cross-checks were already sound.

The existing first-epoch serving host can use a root-derived fixed-epoch policy
as its trusted configuration. That preserves its existing genesis-epoch model;
the host still checks actual installed/live state, signer membership and writer
fencing. Constructing the root does not itself pass these checks, mount routes
or authorize signatures. It cannot stand in for authenticated successor
selection/activation or choose a later serving epoch. First-epoch configuration
is not a new serving-activation capability.

An installed committee row remains an independent input. The first-epoch host's
opt-in ordered composition must still require that row to describe the root's
original committee, in addition to its ordinary installed live-epoch/digest
checks. Deriving the ordered policy from the root cannot silently remove the
old policy constructor's comparison against the host's actually loaded row.
This is a real storage/configuration boundary, not a repair check between two
values already derived from one immutable root. Reject disagreement before
exposing a listener or performing ordered initialization.

## Acceptance and boundaries

Record v1/v2/v3/v4 digest, ordered anchor, causal profile, minimum Freeze height,
registration economics and fixed-key registration-envelope bytes before the
old implementations are removed. Compare the exact results after migration;
existing envelopes must still verify. Keep canonical golden-vector tooling
independent of the implementation under test.

Add wrong-pin, wrong-context/resolver, noncanonical/truncated bytes, zero or
noncanonical authority, bad or wrong-family signature, non-Ed25519 committee,
over-capacity committee and multidefect precedence negatives. Compile-fail
tests forbid root literals and mutation/replacement of the trusted certifier.
Replace runtime tests that only corrupted mutable trusted fields with these
construction-boundary tests; retain forged-input and before-I/O negatives.
Include wrong historical policy/archive pairing and installer error-order tests.
The old public authenticators/optional constructor and separate current ordered
resolver fields must have no remaining callers or compatibility wrappers.
CLI acceptance explicitly includes `ordered_economics_network`, not just its
shared SDK loader. A schedule-extension test rebuilds the root with a trusted
later activation and verifies the unchanged original genesis pin; mismatched
full schedules still fail reconstruction composition. Rebuilding a root is
local trust verification, not protocol-upgrade or activation authority.

Run the actual SDK, compiled CLI, operator and real SQLite reconstruction/cut/
import paths, not just root unit tests. Keep all required DB-free lanes and
selected PostgreSQL acceptance distinct. No canonical type/frame ID, digest,
signing frame, receipt, generation or store contract changes are approved.

The root is original genesis historical evidence. It never satisfies a live
epoch pin, `require_live_fastvote_pin`, conditional readiness, Seal, successor
selection or serving activation. No new protocol mechanism or generic framework
is introduced to complete those still-independent responsibilities.
