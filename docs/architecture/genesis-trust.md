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

Historical constructors remain only where a real manifest-free historical
consumer exists. They do not grant causal admission, Freeze or serving powers.
No compatibility wrapper preserves the old mutable trusted bundle or optional
genesis policy constructor merely because this API existed during development.

Trusted FastVote operations use the root's resolver, not an extra arbitrary
resolver argument. They still check request lane and signed intent context
before signing or network I/O. Low-level naked-certifier historical helpers
remain explicitly separate. Additional resolver history is explicit trusted
local composition, not an endpoint-selected schedule.

Reconstruction continues to cross-check ordered policy, history identity,
domain, anchor and execution policies against the root. Existing checks among
the old independently supplied genesis values are not a missing validation
gap: they are redundant because the new value makes disagreement impossible.
Do not delete checks on the still-independent policy/history/domain inputs.

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

Run the actual SDK, compiled CLI, operator and real SQLite reconstruction/cut/
import paths, not just root unit tests. Keep all required DB-free lanes and
selected PostgreSQL acceptance distinct. No canonical type/frame ID, digest,
signing frame, receipt, generation or store contract changes are approved.

The root is original genesis historical evidence. It never satisfies a live
epoch pin, `require_live_fastvote_pin`, conditional readiness, Seal, successor
selection or serving activation. No new protocol mechanism or generic framework
is introduced to complete those still-independent responsibilities.
