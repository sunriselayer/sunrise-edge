# Bounded, non-authorizing publication review

[DR-0237](decisions/0237-bounded-publication-review-presentation.md) implements
the concrete presentation consumer [DR-0214](decisions/0214-protected-custody-and-review-boundary.md)
named as the safe next slice after [DR-0211](decisions/0211-external-signing-preparation.md)'s
[`PreparedPublication`](../../clients/rust/src/publication_client.rs). Release
status belongs in [`TODO.md`](../../TODO.md); this page is a durable contract,
not a status line.

## What this is

[`PublicationReview`](../../clients/rust/src/publication_review.rs) is an
immutable, display-safe snapshot built only from a `&PreparedPublication`.
Building one:

- Performs a defensive self-consistency recheck of the retained, already-typed
  `CodeArtifact`: re-encodes and re-decodes it through the existing canonical
  codec, and separately recomputes the artifact commitment, the profile
  semantics commitment (dispatched by `wasm_profile`) and the exact submission
  signing frame, refusing on any mismatch against the values
  `PreparedPublication` retained. This is regression insurance on an
  already-validated Rust value, not an adversarial unknown/trailing-byte
  decoder test: `CodeArtifact::new` and `decode_code_artifact` already enforce
  every structural invariant checked here, so none of these checks can
  actually fail for any value reachable through safe Rust.
- The frame recomputation is the exact bounded canonical preimage-to-frame
  correspondence: byte-for-byte identity with
  `PreparedPublication::signable_frame`, reused (not recomputed again) as
  `frame_bytes`/`frame_hex`.
- The semantics dispatch is presentation-only: for each known profile it
  calls the one existing canonical semantics function for that exact profile,
  without implementing or replacing the cross-profile policy compatibility
  `node_core::local_execution` and `execution::execution_scopes` separately
  enforce. A conformance test compares it against the existing
  `authenticate_publication_submission` verifier for every known profile.
- Copies every material field into owned, display-safe values: publisher,
  origin chain identifier and creation seed, context chain identifier,
  protocol version, epoch, expected hash-suite id, revision, numeric and
  named WASM profile, semantics digest, artifact commitment digest, exports,
  dependency references (each dependency's own chain, publisher, seed,
  revision, protocol version, epoch and artifact digest), nonce, request
  identity and the signable frame. Nothing is truncated. Two reviews differing
  only by `--origin-seed` (or only by WASM or ABI bytes) differ in these
  fields directly, not only in an opaque digest.
- Rejects any chain identifier or export name containing a non-printable or
  control byte outright, rather than truncating, stripping, or escaping it.
  Digests, addresses, the request identity and the frame are rendered only
  through this module's own hex formatting, never through caller-controlled
  text, so a reviewing terminal cannot be made to interpret injected control
  sequences.
- Does not render raw WASM or ABI declaration bytes as display text (this is
  metadata-only preview, not semantic/code-safety review); instead shows a
  resolver-computed digest of each, using the artifact commitment's own
  existing `ContractCode` hash purpose (no new hash domain or crypto
  identifier). The exact unmodified bytes remain available to SDK callers via
  `artifact_bytes()`, the same reused buffer `build` already verified
  round-trips exactly.
- Renders every field through one small internal bounded renderer that counts
  the actual label, value and separator bytes of each field as it is produced
  against an explicit aggregate field-count bound (computed from the real
  fixed field count and the artifact's own export/dependency ceilings, not a
  placeholder number) and an aggregate byte bound (deliberately smaller than
  the structural worst case, so it is an independently reachable, tested
  bound; exceeding it refuses review only — `publish` carries no such
  ceiling). `render()` returns the one complete string a caller prints or
  stores as-is.

`PublicationReviewError` is typed and fail-closed: artifact/semantics/hashing
sub-errors, round-trip mismatch, digest mismatch, frame mismatch, an
undisplayable field, an explicit limit, or an unrecognized profile. No
variant substitutes, truncates, or silently drops content; every refusal
builds no partial review. The round-trip/digest/frame/unknown-profile
variants are documented as defensive regression insurance, unreachable for any
`CodeArtifact` producible through safe Rust.

## What this is not

- Not a signer. It never calls `ExternalSigner`/`SignatureSigner` and never
  produces a signature or custody action.
- Not a general review/approval endpoint. There is no API to record an
  approval decision, and a successful `PublicationReview` is not code-safety
  or business-semantics approval.
- Not a replacement for `PreparedPublication::finalize`'s own authentication,
  which is unchanged and still independently verifies the returned signature.
- Not protected custody, operator/key-role separation, a separated review
  host/device, or recovery/rotation/revocation. DR-0214's threat-boundary
  comparison and provider selection remain entirely open.

## CLI consumer

`apps/cli`'s `contract preview` action
(`apps/cli/src/commands/publication.rs::run_preview`) builds the same
`PreparedPublication` the `publish` action signs, through the same shared
`build_artifact_from_flags`/`semantics_for_selected_profile` helpers `publish`
uses (so the two actions' artifact construction exists exactly once and
cannot drift), from the same artifact flags plus `--publisher` (as `query`
already accepts). `publish`'s original step order — key/context/origin, then
`client.query_verified_context`, then artifact construction, then nonce/sign
— and `query` are both unchanged. `preview` builds the complete bounded
`PublicationReview::render` output before printing it once. It accepts no
TLS/endpoint flags, loads no signing seed, contacts no signer or node, and
submits nothing; `--nonce` is required because no node is queried for one.
See the [publication preview guide](../guides/publication-preview.md) for
exact usage.

## Relationship to DR-0214's remaining open work

This closes DR-0214's named "safe next slice" only. It does not select a
custody threat boundary, wire any provider (local OS, separated host, or
hardware), define operator/key-role separation, or implement
recovery/rotation/revocation. A future trusted review surface may reuse
`PublicationReview` as its content source, but trusting that surface's own
policy, configuration provenance and operator boundary is separate design and
qualification work, tracked in `TODO.md`'s M2 row.
