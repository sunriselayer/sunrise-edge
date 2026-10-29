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

1. Performs a defensive self-consistency recheck: re-encodes and re-decodes
   the retained, already-typed `CodeArtifact` through the existing
   `encode_code_artifact`/`decode_code_artifact` canonical codec, and
   separately recomputes the artifact commitment, profile semantics and
   submission signing frame via the existing `artifact_commitment`,
   per-profile semantics functions and `publication_submission_signing_frame`,
   refusing on any mismatch against what `PreparedPublication` retained. This
   is a regression check on an already-validated Rust value, not an
   adversarial unknown/trailing-byte decoder test or an independent
   code-provenance proof: `CodeArtifact::new` and `decode_code_artifact`
   already enforce every structural invariant checked here, so none of these
   four checks can actually fail for any value reachable through safe Rust.
2. The frame recomputation is the exact bounded canonical preimage-to-frame
   correspondence DR-0214 names: byte-for-byte identity with
   `PreparedPublication::signable_frame`, exposed to callers as
   `PublicationReview::frame_hex`/`frame_bytes` (the exact same buffer,
   reused rather than recomputed a second time for display).
3. The semantics recomputation dispatches on the artifact's declared
   `wasm_profile` to the one existing canonical semantics function for that
   exact profile number (`local_publication_profile_semantics`,
   `local_execution_semantics`, `general_execution_semantics`, or
   `generic_object_result_semantics`). This dispatch is presentation-only: it
   mirrors, but does not replace or own, the per-profile mappings
   `node_core::local_execution`'s dependency-closure admission and
   `execution::execution_scopes`'s execution-authority checks separately
   enforce (including their cross-profile policy compatibility, which this
   module does not implement). `clients/rust/tests/publication_review.rs`
   includes a conformance test comparing this dispatch's choice against the
   existing, independent `authenticate_publication_submission` verifier for
   every known profile, rather than introducing new core API surface.
4. Copies every material field DR-0214's publication review row lists
   (publisher, origin chain id and seed, context, protocol version, epoch,
   expected hash-suite id, revision, profile, semantics, exports,
   dependencies, nonce, request identity, signable frame) into an immutable,
   display-safe snapshot. Chain identifiers and export names are checked
   byte-by-byte against a printable ASCII range and rejected outright (not
   truncated, stripped, or escaped) if they contain control bytes, closing
   the terminal-control-injection concern. Digests, addresses, the request
   identity and the frame are rendered only through this module's own hex
   formatting, never through a caller-supplied string. Raw WASM/ABI bytes
   are deliberately not rendered as display text (this is a metadata-only
   preview of them, not a semantic/code-safety review); instead, a
   explicitly diagnostic hash of each under the existing `ContractCode`
   purpose is shown. These raw-component values are not publication identity
   or commitment, verified `canonical_code_hash`/`module_ref`, code provenance
   or approval. The commitment hashes the complete encoded artifact;
   `artifact_digest` and `frame_hex` retain their original bound meaning.
   The exact unmodified bytes remain available to SDK callers via
   `PublicationReview::artifact_bytes` (the same reused, verified-round-trip
   buffer) for independent inspection or hashing with any tool.
5. Renders every one of those fields through one small internal
   `BoundedRenderer` that counts the actual label, value and line-separator
   bytes of each field as it is produced, against an explicit aggregate
   field-count bound (`MAX_REVIEW_TOTAL_FIELDS`, computed from the real fixed
   field count plus the artifact's own export/dependency ceilings, not a
   placeholder number) and an aggregate byte bound (`MAX_REVIEW_DISPLAY_BYTES`,
   deliberately smaller than the structural worst case, so it is an
   independently reachable, tested bound rather than decoration; exceeding it
   refuses review only, `publish` carries no such ceiling).
   `PublicationReview::render` returns the one complete string a caller
   prints or stores as-is.

`PublicationReviewError` is a typed, fail-closed enum (artifact/semantics/
hashing sub-errors, round-trip/digest/frame mismatch, an undisplayable field,
a limit, or an unrecognized profile); no variant truncates or substitutes
content. The round-trip/digest/frame/unknown-profile variants are documented
in code as defensive regression insurance, unreachable for any `CodeArtifact`
producible through safe Rust, rather than left to read as adversarial-input
handling.

`apps/cli` gains an explicit `contract preview` action
(`apps/cli/src/commands/publication.rs::run_preview`, dispatched from
`apps/cli/src/commands/contract.rs`). A shared `build_artifact_from_flags`
helper (file IO, entrypoint/dependency parsing, `CodeArtifact::new`) and a
shared `semantics_for_selected_profile`/`selected_wasm_profile` pair now back
both `publish` and `preview`, so the two actions' artifact-construction logic
exists exactly once; `publish`'s original step order (key/context/origin,
then `client.query_verified_context`, then this shared artifact construction,
then nonce/sign) is unchanged, and `query` is untouched. `preview` calls the
same shared steps with no client at all, builds the complete bounded
`PublicationReview::render` string, and prints it once. It loads no signing
seed, accepts no TLS/endpoint flags, contacts no signer or node, and submits
nothing; `--nonce` is therefore required rather than queried from a node.

## Non-claims

This is not a signer: it never calls `ExternalSigner`/`SignatureSigner` and
never produces a signature. It is not a general review/approval endpoint:
`PublicationReview` has no API accepting an approval decision, and nothing
here claims code-safety or business-semantics approval. A successful build
proves bounded structural, commitment and semantics self-consistency between
the retained artifact and the exact bytes `publish` would sign; it is not
independent human judgment, and it does not replace
`PreparedPublication::finalize`'s own authentication. A matching profile
semantics digest proves the artifact's declared profile and declared
semantics are mutually self-consistent, not that the code's business logic
matches that profile's name or is otherwise safe; code approval provenance
stays separate from this hash consistency check, as DR-0214 states.
`--nonce`'s explicit requirement is a consequence of never contacting a node,
not a general nonce policy change; `contract publish` keeps querying the next
nonce as before.

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

## Correction (2026-10-13, same day)

Independent review of the initial implementation found it dropped origin
seed/chain identity and the hash-suite id, exposed no canonical artifact/frame
bytes to SDK callers, duplicated `publish`'s artifact-construction code in
`preview`, mischaracterized the defensive self-consistency recheck as an
adversarial decoder test, and used an uncounted field bound and a byte bound
that did not count hex fields. This record and the implementation were
corrected as described above (origin/hash-suite fields, `artifact_bytes`/
`frame_bytes`/`frame_hex`, the shared `build_artifact_from_flags` helper, the
reworded defensive-recheck docs, and the one `BoundedRenderer`) before any
release or M2 claim was made; no prior accepted behavior changes as a result.
