# DR-0238: Publication-only local OS custody

Date: 2026-10-13 (Asia/Tokyo)

Status: Accepted design and implementation of one DR-0214 custody threat
boundary ("dedicated encrypted local custody," without the encryption),
scoped to publication only. This is not M2 qualification, not a production
key-management profile, not operator/key-role ceremony design (D04 remains
separate), and not an at-rest-encryption or compromised-root claim.

## Context

[DR-0211](0211-external-signing-preparation.md) supplies `PreparedPublication`:
immutable publisher binding, complete artifact, commitment, semantics and an
exact signable frame, with independent returned-signature verification.
[DR-0214](0214-protected-custody-and-review-boundary.md) compares three
custody threat models and selects none as a default; it also requires a
trusted review surface that consumes the same immutable content.
[DR-0237](0237-bounded-publication-review-presentation.md) supplies that
review surface (`PublicationReview`) but builds no custody consumer.

This record selects DR-0214's "dedicated encrypted local custody" candidate
for publication only, without the encryption: trust the local OS/root and a
separate custody process under a distinct UID; protect the stored key from
ordinary callers via standard Unix ownership/permission bits, not disk
encryption. It implements exactly one consumer (`PreparedPublication`); it
adds no generic `ExternalSigner` route, no second custody backend, and no
change to `ConsensusSigner`, readiness, or genesis/admin signing.

## Decision

### Process and transport

Add `sunrise-edge-cli custody {keygen,approve,serve}` (`apps/cli/src/custody/`)
rather than a new binary; the 13-target release inventory is unchanged.
`serve` and `approve` are intended to run as a distinct "custody" Linux UID,
separate from the "operator" UID that runs `publish`; the config/key
administrator may be the same UID as custody for this DEV slice (D04 covers
real ceremony/overlap separately).

Transport is `tokio::net::UnixListener`/`UnixStream`, already a normal
dependency elsewhere in the workspace; `tokio` is promoted from a CLI
dev-dependency to a normal one. Both the client and `serve` check the peer's
UID via the existing safe `UnixStream::peer_cred()` API before any request
byte is read or sent — no `rustix`, `libc`, or new `unsafe`. `serve` also
learns its own effective UID the same way, by calling `peer_cred()` on one end
of a freshly created `UnixStream::pair()` (whose peer is, by construction,
itself), so it can refuse at startup if the configured operator UID equals
its own UID, without a `geteuid()` call.

### Configuration and key storage

One fixed, line-oriented `key=value` config file and one raw 32-byte-seed hex
key file, each required to be a non-symlink regular file at exactly mode
`0600` under a parent directory at exactly mode `0700`; a wrong owner/mode or
a symlink refuses before any content is read (closing the same
validate-then-open race `apps/cli/src/seed.rs` already documents for
development seeds). The config pins `chain_id`, `protocol_version`, `epoch`,
`hash_suite_id`, `domain`, the exact `publisher_public_key` custody will ever
sign for, and the one `operator_uid` permitted to connect. None of these are
negotiable from a request or a response.

The Unix socket's parent directory must be exactly mode `0750` (owner
read/write/list, group traverse-and-connect, other none); `serve` chmods the
bound socket file to exactly `0660` after `bind`, since the mode `bind`
creates is otherwise umask-dependent. Only the exact configured operator UID
is accepted; group membership alone is not. `serve` never unlinks a stale
socket on its own.

### Request shape: inputs to `prepare`, never a caller frame

The wire request (`apps/cli/src/custody/wire.rs`) carries only the untrusted
inputs to `PreparedPublication::prepare`: canonical `CodeArtifact` bytes
(`execution::publication::encode_code_artifact`), a nonce, and a request id —
never a caller-supplied signable frame. `serve` rebuilds `PreparedPublication`
itself from its own pinned config (resolver, context, publisher), which also
re-derives the exact signable frame; it never trusts a frame the caller
claims. The response is a closed, versioned, length-bounded envelope: either
a raw 64-byte Ed25519 signature or one redacted status byte — never a
free-form message, so a caller cannot learn more than "signed" or "refused"
plus which closed category. This is one publication family only: `serve` has
no generic sign-bytes route, and automatic/consensus/readiness/genesis
signing are untouched.

### Human approval

`custody approve` requires an independently supplied, already-canonical
approved artifact file, pinned by the custody administrator out of band —
never a live caller request — plus the nonce, request id, and an explicit
`--expires-in-seconds`. It rebuilds the exact `PreparedPublication` and
`PublicationReview` under custody's own config, requires a real terminal on
both stdin and stdout, prints the *complete* bounded `PublicationReview`
rendering (every field DR-0214 lists, not a digest prefix), and requires the
operator to type back one exact line reproducing the displayed publisher,
artifact digest, nonce, request id, and expiry. A digest-prefix prompt alone
is explicitly not treated as code-provenance or semantic approval here; this
confirmation is a parameterized approval input over the fully displayed
review, not an independent code-safety proof.

The written approval record (mode `0600`) binds the *whole* exact signable
frame bytes (not merely a digest), the expected publisher, and the explicit
expiry. Re-approving the same already-approved frame is idempotent
(overwrite, not an "already exists" error); `serve` refuses a missing,
expired, or changed-frame request with the same single redacted status.
`serve` only ever reads this store; it is never a writer.

### Client

`SignerSelection::Custody` (`apps/cli/src/signer.rs`) requires
`--custody-socket`, `--custody-uid`, and `--custody-expected-public-key`
together, with no default path, environment variable, or seed fallback;
mutually exclusive with `--seed-file` and the Ledger flag trio, matching the
existing all-or-none pattern. `commands/publication.rs`'s `publish` action
builds its own local `PreparedPublication` from the same artifact/nonce/
request-id, sends them to custody, and calls the existing
`PreparedPublication::finalize` on the returned signature — the same
independent frame/key verification every other signer path already gets.
Connect, each read/write, and the overall `serve` lifetime are all bounded by
explicit deadlines/counts (`--max-connections`, `--max-requests`,
`--total-deadline-secs` for `serve`); refusal, timeout, or a malformed
response never falls back to a development seed.

## Non-claims

At-rest encryption, process-memory protection, and compromised-root
resistance are not claimed; this is the first OS-permission model DR-0214
names, not an upgrade to it. Recovery, rotation, revocation, and a real
operator/custody-administrator ceremony remain D04/D06/D07. Only the
publication family is covered; every other signing family (generic local/paid
execution, bond registration, fee claims, `ConsensusSigner`, readiness,
genesis/admin) is untouched and remains outside this custody process. No real
keys, system users, or host services are provisioned by this change; the
described UID separation is an operational deployment step, not something
this change performs.

## Acceptance

Unit/stable-vector coverage: the wire codec (stable request/response vectors,
truncated/trailing/oversized/zero-request-id rejection); config/key file
ownership-and-mode enforcement (wrong mode, wrong parent-directory mode,
symlink); the approval store (write/read round trip, idempotent re-approval,
expiry boundary, changed-frame rejection); the signing decision itself
(publisher mismatch, no/expired/changed approval, successful independently
re-verified signature); `approve`'s real-terminal requirement; the client's
impostor-peer-UID refusal; and one real-socket round trip exercising the full
request/response framing and signature finalization end to end. Genuinely
distinct-UID and PTY behavior needs a separate Docker fixture (not executed
here); see `docs/architecture/local-publication-custody.md` for the recipe.
Progress and remaining gates stay in [`TODO.md`](../../../TODO.md); this
record authorizes no keys, deployment, or public network.
