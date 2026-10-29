# Preview an exact publication before signing

`contract preview` builds the exact same immutable `PreparedPublication` that
`contract publish` would sign, then prints its independently recomputed and
verified material fields. It never loads a signing seed, never contacts a
signer or a node, and never submits anything:

```bash
cargo run -p sunrise-edge-cli -- contract preview \
  --expected-chain-id devnet \
  --expected-protocol-version 1 \
  --expected-epoch 0 \
  --expected-hash-suite-id 1 \
  --expected-domain 4444444444444444444444444444444444444444444444444444444444444444 \
  --publisher <publisher-address-hex> \
  --origin-seed <origin-seed-hex> \
  --wasm ./contract.wasm \
  --abi ./contract.abi \
  --entrypoints initialize,execute \
  --request-id <request-id-hex> \
  --nonce 0
```

Add `--dependencies <path>[,<path>...]` for dependency reference files (the
same format `contract publish --dependencies` and `--dependency-ref-out`
produce), and `--executable` or `--general-calls` to select the typed-host or
general-calls structural profile instead of the bare publication-only
profile. `--nonce` is required: preview never queries a node for the next
nonce, unlike `publish`.

For a separately approved local-custody publication, the custody administrator
can add `--artifact-out /absolute/private-directory/artifact.bin` to save the
exact canonical preimage from their own trusted build inputs. The existing
parent must be owned by the current UID at mode 0700. The output is a new
0600 file; overwrite and symlinks are refused. Output failure prints no partial
review. This emits bytes only and creates no approval. Feed that independent
file to `custody approve`; a live caller request is never the approval input.

Success prints line-oriented fields, including every field
[DR-0214](../architecture/decisions/0214-protected-custody-and-review-boundary.md)
names as required publication review input:

```text
preview=true
published=false
publisher=<hex>
origin_chain_id=devnet
origin_seed_hex=<hex>
chain_id=devnet
protocol_version=1
epoch=0
hash_suite_id=1
revision=1
wasm_profile=1
wasm_profile_name=publication-only
wasm_bytes=<exact length>
diagnostic_wasm_contract_code_hash=<algorithm>:<hex>
abi_bytes=<exact length>
diagnostic_abi_bytes_hash=<algorithm>:<hex>
semantics=<algorithm>:<hex>
artifact_digest=<algorithm>:<hex>
export_count=<n>
export[0]=initialize
export[1]=execute
dependency_count=<n>
dependency[0].chain_id=...
dependency[0].publisher=...
dependency[0].seed=...
dependency[0].revision=...
dependency[0].protocol_version=...
dependency[0].epoch=...
dependency[0].artifact_digest=...
nonce=0
request_id=<hex>
frame_hex=<hex>
```

`diagnostic_wasm_contract_code_hash`/`diagnostic_abi_bytes_hash` are diagnostic
hashes of retained WASM/ABI bytes under `ContractCode`. They are not publication
identity or commitment, verified `canonical_code_hash`/`module_ref`, provenance
or approval. The publication commitment hashes the complete encoded artifact;
`artifact_digest` and `frame_hex` retain their original bound meaning.
The raw bytes are not printed as text, since binary
content is not safely displayable and this is a metadata-only preview of
them, not a semantic or code-safety review. An SDK caller that needs the
exact bytes themselves (not only their length and digest) reads
`PublicationReview::artifact_bytes()`. `frame_hex` is the exact bytes
`contract publish` would sign, as lowercase hex.

Two previews differing only by `--origin-seed` differ in `origin_seed_hex`
(and `artifact_digest`) directly, not only in an opaque digest; previews
differing only in the WASM or ABI file differ in `diagnostic_wasm_contract_code_hash`/`diagnostic_abi_bytes_hash`
directly.

Failure refuses outright and prints a sanitized `error=...` line on stderr; it
never prints a partial or truncated review. Refusal reasons include a chain
identifier or export name containing a non-printable or control byte, a
semantics digest that does not match the artifact's own declared profile
(checked by independently recomputing the one existing semantics function for
that exact profile), or exceeding an explicit field/byte bound.

This proves bounded structural, commitment and semantics self-consistency
between the exact artifact and the exact bytes `publish` would sign; a
matching semantics digest means the declared profile and declared semantics
are mutually self-consistent, not that the code's logic is safe or matches
that profile's name. It is not code-safety or business-semantics approval,
and it does not authorize publishing; only `contract publish` with a real
signer submits anything. See
[the publication review contract](../architecture/publication-review.md),
[DR-0237](../architecture/decisions/0237-bounded-publication-review-presentation.md),
[local contract validation](contracts.md) for structural WASM checks before
either command, and [`TODO.md`](../../TODO.md) for remaining M2 scope.
