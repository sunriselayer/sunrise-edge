# DR-0237: Bounded, non-authorizing publication review presentation

Date: 2026-10-13 (Asia/Tokyo)

Status: Accepted design and implementation of DR-0214's deferred "safe next
slice." This is a presentation/review consumer, not custody wiring, SSH agent
integration, trusted-operator approval, or M2 qualification.

## Context

[DR-0211](0211-external-signing-preparation.md) and
[signing preparation](../signing-preparation.md) define `PreparedPublication`:
an immutable owner of the complete artifact, publisher binding, commitment,
semantics and exact signable frame, with independent returned-signature
verification. [DR-0214](0214-protected-custody-and-review-boundary.md) states
that mechanical signature validity is not independent human content review,
and names a concrete, bounded, non-authorizing presentation consumer as the
safe next slice: "bounded, non-authorizing presentation/preimage-to-frame
correspondence using existing encoders, explicit display/work limits, and
refusal of incomplete, missing, mismatched or undisplayable fields." Until
that consumer exists, DR-0214 explicitly defers it; this record supplies it.

Protected custody, operator/key-role separation and trusted content review
remain undesigned and are not addressed here. This change does not wire an
SSH agent, Vault Transit, hardware signer, or any other provider; it does not
select a threat boundary; it does not grant any family approval authority.

See [the publication review contract](../publication-review.md) for the
living contract this record introduces and
[the publication preview guide](../../guides/publication-preview.md) for the
exact CLI walkthrough.

## Decision

Add `clients/rust/src/publication_review.rs`, exposing `PublicationReview`
and `DependencyReview`. `PublicationReview::build` takes only a `&PreparedPublication`
(the same immutable owner `publish` signs) and:

1. Independently re-encodes and re-decodes the retained `CodeArtifact` through
   the existing `encode_code_artifact`/`decode_code_artifact` canonical codec,
   refusing any content that does not reproduce exactly (this is how unknown
   or trailing fields, and non-canonical order, are rejected).
2. Independently recomputes the artifact commitment via the existing
   `artifact_commitment`, and refuses if it differs from the one
   `PreparedPublication` retained.
3. Independently recomputes the profile semantics commitment by dispatching
   on the artifact's declared `wasm_profile` to the one matching existing
   semantics function (`local_publication_profile_semantics`,
   `local_execution_semantics`, `general_execution_semantics`, or
   `generic_object_result_semantics`), and refuses on mismatch or an
   unrecognized profile. This is the "recompute all relevant commitments"
   requirement DR-0214 states; it fails closed on unknown semantics rather
   than guessing a mapping.
4. Independently recomputes the exact submission signing frame via the
   existing `publication_submission_signing_frame`, and refuses unless it is
   byte-for-byte identical to `PreparedPublication::signable_frame`. This is
   the exact bounded canonical preimage-to-frame correspondence DR-0214 names.
5. Copies every material field DR-0214's publication review row lists
   (publisher, context, revision, profile, semantics, exports, dependencies,
   nonce, request identity) into an immutable, display-safe snapshot. Chain
   identifiers and export names are checked byte-by-byte against a printable
   ASCII range and rejected outright (not truncated, stripped, or escaped) if
   they contain control bytes, closing the terminal-control-injection
   concern. Digests, addresses and the request identity are rendered only
   through this module's own hex formatting, never through a caller-supplied
   string. Raw WASM/ABI bytes are deliberately NOT rendered as display text;
   only their lengths are exposed, since DR-0214's required-field list does
   not include raw code bytes and binary data is not safely displayable text.
6. Enforces new explicit bounds in addition to every existing artifact bound:
   a maximum re-encode/re-decode work ceiling, a maximum aggregate field
   count, and a maximum aggregate displayed-byte budget across the whole
   snapshot, independent of any single field's own bound.

`PublicationReviewError` is a typed, fail-closed enum (artifact/semantics
sub-errors, round-trip/digest/frame mismatch, an undisplayable field, a limit,
or an unrecognized profile); no variant truncates or substitutes content.

`apps/cli` gains an explicit `contract preview` action
(`apps/cli/src/commands/publication.rs::run_preview`, dispatched from
`apps/cli/src/commands/contract.rs`). It accepts the same artifact-construction
flags as `contract publish` plus `--publisher` (as `contract query` already
does), builds the same `PreparedPublication`, and prints every
`PublicationReview` field line-oriented. It loads no signing seed, accepts no
TLS/endpoint flags, contacts no signer or node, and submits nothing; `--nonce`
is therefore required rather than queried from a node.

## Non-claims

This is not a signer: it never calls `ExternalSigner`/`SignatureSigner` and
never produces a signature. It is not a general review/approval endpoint:
`PublicationReview` has no API accepting an approval decision, and nothing
here claims code-safety or business-semantics approval. A successful build
proves bounded structural, commitment and semantics self-consistency between
the retained artifact and the exact bytes `publish` would sign; it is not
independent human judgment, and it does not replace
`PreparedPublication::finalize`'s own authentication. `--nonce`'s explicit
requirement is a consequence of never contacting a node, not a general nonce
policy change; `contract publish` keeps querying the next nonce as before.

Protected custody, authenticated review-policy configuration, a separated
review host/device, recovery/rotation/revocation and any operator/key-role
separation remain undesigned, as DR-0214 states. This record selects no
threat boundary and wires no provider.

## Compatibility

No change to `PreparedPublication`, `CodeArtifact`, canonical encoders,
commitments, frames, or the `publish`/`query` actions' existing bytes, error
priority, or authority rules. `PublicationReview` is additive: a new type
consuming existing immutable data, with its own new, independent error type.

## Consequences

- `clients/rust` gains a typed, tested, non-authorizing publication review API
  usable by any future trusted review surface without re-deriving commitment
  or frame logic.
- `apps/cli contract preview` gives an operator a concrete way to inspect an
  exact publication's material fields before ever loading a signing seed.
- M2's protected-key backend, operator/authority separation and trusted
  review-policy configuration remain open, tracked in [`TODO.md`](../../../TODO.md).
  This record closes no M2 gate and authorizes no keys, deployment, or public
  network.
