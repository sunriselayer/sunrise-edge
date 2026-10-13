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

- Independently re-encodes and re-decodes the retained `CodeArtifact` through
  the existing canonical codec, refusing anything that does not round-trip
  exactly (unknown/trailing fields and non-canonical order included).
- Independently recomputes the artifact commitment and the profile semantics
  commitment (dispatched by `wasm_profile`), refusing on any mismatch against
  the values `PreparedPublication` retained, and refusing an unrecognized
  profile rather than guessing its semantics.
- Independently recomputes the exact submission signing frame and refuses
  unless it is byte-for-byte identical to `PreparedPublication::signable_frame`.
  This is the exact bounded canonical preimage-to-frame correspondence.
- Copies every material field into owned, display-safe values: publisher,
  chain identifier, protocol version, epoch, revision, numeric and named
  WASM profile, semantics digest, artifact commitment digest, exports,
  dependency references (each dependency's own chain, publisher, seed,
  revision, protocol version, epoch and artifact digest), nonce and request
  identity. Nothing is truncated.
- Rejects any chain identifier or export name containing a non-printable or
  control byte outright, rather than truncating, stripping, or escaping it.
  Digests, addresses and the request identity are rendered only through this
  module's own hex formatting, never through caller-controlled text, so a
  reviewing terminal cannot be made to interpret injected control sequences.
- Does not render raw WASM or ABI declaration bytes as display text; only
  their lengths are exposed. Binary data is not safely displayable as text,
  and DR-0214's required review-field list does not include raw code bytes.
- Enforces explicit new bounds beyond every existing artifact bound: a
  re-encode/re-decode work ceiling, an aggregate field-count ceiling, and an
  aggregate displayed-byte ceiling, independent of any single field's bound.

`PublicationReviewError` is typed and fail-closed: artifact/semantics
sub-errors, round-trip mismatch, digest mismatch, frame mismatch, an
undisplayable field, an explicit limit, or an unrecognized profile. No
variant substitutes, truncates, or silently drops content; every refusal
builds no partial review.

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
`PreparedPublication` the `publish` action signs, from the same artifact flags
plus `--publisher` (as `query` already accepts), and prints every
`PublicationReview` field. It accepts no TLS/endpoint flags, loads no signing
seed, contacts no signer or node, and submits nothing; `--nonce` is required
because no node is queried for one. See the
[publication preview guide](../guides/publication-preview.md) for exact usage.

## Relationship to DR-0214's remaining open work

This closes DR-0214's named "safe next slice" only. It does not select a
custody threat boundary, wire any provider (local OS, separated host, or
hardware), define operator/key-role separation, or implement
recovery/rotation/revocation. A future trusted review surface may reuse
`PublicationReview` as its content source, but trusting that surface's own
policy, configuration provenance and operator boundary is separate design and
qualification work, tracked in `TODO.md`'s M2 row.
