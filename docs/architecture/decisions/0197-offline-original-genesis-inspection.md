# DR-0197: Offline original-genesis inspection without signing authority

Date: 2026-10-06 (Asia/Singapore)

Status: Proposed. Independent design review is required before implementation.
This record grants no custody, ceremony, audit or network-activation approval.
Current work and verification status belong only in TODO.md.

## Context

DR-0196 produces a signed original genesis from explicit operator inputs, and
DR-0195 prepares independent local SQLite namespaces from already signed bytes.
Neither operation is independent human approval of the economic choices.
Reviewers need to examine the signed owners, policies and original committee
without a private key, a database, a provider or a serving process.

`VerifiedGenesisRoot` authenticates a bounded manifest against locally supplied
pins; it does not verify nested publication/initialization execution, installed
objects or economics. Inspection must not mislabel root verification alone as
complete defining-installer validation.

## Decision

### A generic operator command, not a Standard Asset core privilege

Add `genesis-inspect inspect` in the operator crate, with one public command
entry point and private configuration/rendering helpers. It accepts ordinary
original-genesis manifests supported by the defining installers. It does not
require the Standard Asset preset, decode an asset body as a privileged native
balance, select a production provider or make an original root into live
serving authority. No canonical frame, protocol ID, commitment, signature,
receipt or persistence contract changes.

### Explicit local pins and closed input

Require each flag exactly once, except one to 64 `--suite` entries:

- `--chain-id`, `--protocol-version`, `--epoch` and the complete local suite
  schedule, using the existing eight-column suite parser and resolver.
- `--expected-genesis-authority`, a canonical prime-order Ed25519 public key.
- `--expected-manifest-digest`, the independently obtained raw 32-byte pin.
- `--genesis-manifest`, one bounded local signed-manifest file.
- `--validation-domain`, `--validation-checkpoint` and `--timeout-seconds` for
  isolated in-memory validation. Domain is nonzero; timeout is positive and
  no greater than the defining native operation limit of 30 seconds.

Top-level numbers and suite numeric columns must be canonical unsigned decimal.
Unknown/duplicate/missing flags fail closed. There is no private-key, output,
database, namespace, URL, listener, provider or repair flag and no environment
variable supplying trust. The manifest loader reads once with the existing
`MAX_GENESIS_MANIFEST_BYTES` bound; its existing read-only symlink-following
behavior is preserved rather than described as protected-key file loading.

### One authentication and installer composition

1. Parse all explicit configuration and construct the local resolver/context.
2. Call `sunrise_edge_client::load_verified_genesis_root` once, passing the
   independently configured digest and context. Preserve its classified errors.
3. Compare the authenticated manifest authority to the independently configured
   public authority; do not replace that pin with a key found in the file.
4. Validate the complete root with the existing ordinary original-genesis and
   ordered-genesis installers in private bounded memory.
5. Construct the whole bounded summary before writing any stdout. A validation
   refusal has nonzero exit and empty stdout. A stdout I/O error may leave a
   partial stream and remains a failure; consumers require exit zero and the
   final completion line, not an earlier descriptive header.

Move the author command's existing memory-validation block into a private
`validate_original_genesis_in_memory(root, domain, checkpoint, timeout)` helper
in `original_genesis_install`. Both author and inspect call this single owner.
The helper obtains its resolver only from the immutable root, constructs its
root-derived ordered policy, private Memory durable/blob stores and fence 1,
and invokes the existing shared installer composition. `SystemClock` affects
only the local operation deadline and pacemaker liveness timer; domain,
checkpoint and clock never enter the signed bytes or inspection output.
No disk-backed writer fence is claimed or advanced.

### A descriptive bounded summary, not a new protocol artifact

Print deterministic newline-delimited key/value text; its fields are ordinary
diagnostics, not signed or canonical protocol records. No new serialization
dependency or machine authority witness is introduced. Include:

- Self-describing manifest digest, expected chain/protocol/epoch, manifest
  encoding version, signature family, commitment profile and minimum Freeze
  height, plus the authenticated public genesis authority.
- Exact published code origin/revision/artifact digest and initialization
  instance target, encoded through their existing public canonical encoders.
- The original committee's identity, public key, signature scheme and voting
  power. Keep bond/custody information in the separate economic policy and
  object entries; never derive power from amounts.
- Human-readable fee prices, divisor, reserve/settle allowances, Publish prices,
  fee recipient and fixed phase caps from `PaidFeePolicy`, plus its existing
  canonical frame hex. Economic resource/bond settings and their canonical
  frame are similarly descriptive and remain separate from membership.
- For each bounded manifest object: ObjectId, version, schema, self-describing
  type digest, exact Owner variant and its typed address/custody fields, plus
  existing `objects::encode_object` and `encode_object_authority` bytes as hex.
  Object data stays opaque; inspection introduces no native Coin/account parser.
- A final `complete=true mode=inspect evidence=none` line. This states only that
  this invocation completed pinned-root and defining-installer inspection.

Public string values are explicitly escaped before rendering; chain identifiers
and entrypoint names must not inject terminal controls or extra lines. Fixed
labels come from exhaustive enum matches, not `Debug` formatting. Hex uses
existing canonical encoders for fee/economics/committee/code/instance/object
authority records. Bound the complete diagnostic text to four times
`MAX_GENESIS_MANIFEST_BYTES` plus 32 KiB, rejecting excess before stdout.
Output is independent of the chosen validation domain/checkpoint and actual
clock, but is not a new stable wire format or independent approval certificate.

### Trust and side effects

The digest and public authority must be obtained independently of an untrusted
manifest source. On a wrong digest, do not print a computed replacement or
offer trust-on-first-use. A successful inspection still says nothing about
key custody, independently approved allocations/prices, release audits, a
current installed epoch, Seal/readiness or activation.

The command reads the one manifest file and the local clock and writes only
stdout/stderr. It does not sign, read a secret, connect to a network, start a
listener, open/initialize/repair a database, modify the input, persist a receipt,
or call a provider. Private in-memory installation is discarded after validation.

## Acceptance

- Run the real compiled author to produce disposable signed bytes, then run
  the real compiled inspector. Compare every canonical object/authority and
  policy frame with independent public encoders. Prove separate committee
  power and custody/bond descriptions.
- Compare input bytes and full directory inventory before/after. Repeat with
  different validation domain/checkpoint/clock and require identical stdout.
  No private key is needed or accepted by inspection.
- Corrupt publication and initialization signatures separately, re-sign only
  the outer manifest with disposable test material, and recompute its pin.
  Root verification alone must succeed while the real inspector refuses with
  empty stdout at the defining installer boundary. Do not fabricate DB rows.
- Refuse wrong digest/context/schedule/authority, malformed/truncated/excess
  manifest, unsupported or duplicate flags, missing/wrong subcommand,
  noncanonical numbers, zero domain and out-of-bound timeout. Keep inputs
  unchanged and stdout empty.
- Cover output escaping and bounds with direct rendering tests. Rerun the
  real author and SQLite startup/refusal suites after extracting the shared
  memory validator; preserve their canonical output and actual installer paths.
- Require fresh complete exact-head source review and all required validation
  owners. This remains local evidence, not a real-provider/network audit.
