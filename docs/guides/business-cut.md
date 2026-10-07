# Export and independently verify a pre-Seal business candidate

`business_cut` exports one completely drained CausalAdmission epoch from an
existing local SQLite source. The examples below use the original outgoing
epoch; later epochs require the separately verified predecessor chain described
below. Saved verification repeats the
original authenticated reconstruction without a source database or signing
key. See [the cut contract](../architecture/first-epoch-business-cut.md) and
[DR-0175](../architecture/decisions/0175-first-epoch-preseal-business-cut.md).
Current completion and test evidence belong in [TODO.md](../../TODO.md).

This is not state installation, readiness, a Seal-ready permit or activation.
An empty ordering tip alone is not a complete business drain or latest-state
proof. A corrected candidate needs a separate archive; there is no force-resume
or reset option.

## Required local inputs

- The original signed CausalAdmission genesis and its independently configured
  expected commitment, outgoing chain/protocol/epoch/domain and full hash-suite
  schedule. Changing the declared epoch is not successor authority; without
  verified predecessor artifacts, advanced outgoing epochs refuse. Historical
  profiles remain unsupported.
- A complete [ordered-history archive](ordered-history.md) for one fixed target.
  Its authenticated target, child and grandchild must be candidate-free. Every
  selected committed DrainSet member must have its original complete outcome.
- For source export only, existing initialized SQLite state/blob files and the
  source validator ID from the pinned genesis. The source must have an empty
  portable outbox. The executable uses `open_existing`, not bootstrap or writer
  acquisition; capture and completion enforce the existing backend token.
- An existing private regular output directory, with no symbolic-link path
  components. Files are immutable and their complete inventory is reverified.

The local source token is a continuity check, not a cross-validator identity.
Physical writer counters, CAS revisions and equivalent certificate subsets do
not become semantic business authority. Original verifying proof carriers remain
in the exact package; normalized comparison bytes are not restorable certificates.

## Build and export

```sh
cargo build --locked -p sunrise-edge-operator --bin business_cut
BUSINESS_CUT_BIN="${CARGO_TARGET_DIR:-target}/debug/business_cut"
"$BUSINESS_CUT_BIN" --help
```

Set these task-local paths and pins from the same locally reviewed network
configuration, not from an endpoint response: `CUT_CHAIN_ID`,
`CUT_PROTOCOL_VERSION`, `CUT_EPOCH`, `CUT_DOMAIN`, `CUT_SUITE`,
`CUT_GENESIS_FILE`, `CUT_GENESIS_DIGEST`, `CUT_HISTORY_DIR`, `CUT_OUTPUT_DIR`,
`CUT_STATE_DB`, `CUT_BLOB_DB` and `CUT_VALIDATOR_ID`. `CUT_SUITE` has the existing
`epoch:id:tx:object:effects:code:config:certificate` shape. Repeat `--suite` for
each required schedule entry; one through 64 entries are accepted.

```sh
"$BUSINESS_CUT_BIN" export-sqlite \
  --chain-id "$CUT_CHAIN_ID" --protocol-version "$CUT_PROTOCOL_VERSION" \
  --epoch "$CUT_EPOCH" --domain "$CUT_DOMAIN" --suite "$CUT_SUITE" \
  --genesis-manifest "$CUT_GENESIS_FILE" \
  --expected-genesis-digest "$CUT_GENESIS_DIGEST" \
  --ordered-history-dir "$CUT_HISTORY_DIR" --out-dir "$CUT_OUTPUT_DIR" \
  --state-db "$CUT_STATE_DB" --blob-db "$CUT_BLOB_DB" \
  --validator-id "$CUT_VALIDATOR_ID" \
  --page-size 128 --chunk-size 1048576 --max-new-work 4096 \
  --timeout-seconds 300
```

`business_cut=partial` means only a bounded amount of immutable work was saved.
Repeat the same invocation with unchanged pins, source, directory and transfer
sizing until `business_cut=complete`. Each invocation accepts one through 4,096
new files, counting pins, pages and completion metadata as well as chunks.
Already saved files are reverified, not charged again to that publication bound.
This does not bound the total CPU/memory cost of private reconstruction.

`cut=` is the semantic candidate identity; `package=` is the exact saved
component identity. Both must remain fixed during resumption. Complete output
contains all seven terminal streams, including empty streams, and every bounded
proof/body component. A saved cursor or `complete` file is never sufficient.

The output reserves one staging directory, `.cut-staging-v1`, for crash-safe
publication. It may contain only regular files with the closed staging-name
format; links, subdirectories and unknown names refuse. Interrupted staging
files are never adopted as completed components or deleted by resumption.
Resume allocates fresh staging files and verifies the immutable final inventory.
`verify-saved` is read-only and does not create this directory or publish files.

A changed source token, missing or surplus file, altered transfer settings,
foreign proof, corrupt/truncated chunk or inconsistent original outcome refuses.
Do not delete identity/progress files to bypass the refusal. After legitimate
source progress or a new writer generation, derive a new observation into a
different empty output directory.

## Verify without the source

Use the same original local pins and history target. Do not pass source paths,
validator IDs or signing credentials to `verify-saved`; irrelevant flags refuse.

```sh
"$BUSINESS_CUT_BIN" verify-saved \
  --chain-id "$CUT_CHAIN_ID" --protocol-version "$CUT_PROTOCOL_VERSION" \
  --epoch "$CUT_EPOCH" --domain "$CUT_DOMAIN" --suite "$CUT_SUITE" \
  --genesis-manifest "$CUT_GENESIS_FILE" \
  --expected-genesis-digest "$CUT_GENESIS_DIGEST" \
  --ordered-history-dir "$CUT_HISTORY_DIR" --out-dir "$CUT_OUTPUT_DIR"
```

Success prints `business_cut=independently-verified`, not an import or serving
permit. Verification authenticates the original proof closure, privately
reexecutes business effects, rederives the complete drain/candidate and compares
the complete semantic and exact streams. File hashes alone cannot do this.
SQLite evidence does not certify a deployed provider. PostgreSQL remains an
optional independently selected operational profile; D1 is not implemented.

## Successor source and saved verification

Later-epoch policy comes only from the full independently verified predecessor
chain. Keep the common genesis pins bound to the original signed genesis,
including its epoch. The separately supplied `--ordered-history-dir` is the
current cut's fixed-target history, not a replacement genesis or predecessor
archive. Current epoch/context is derived from the verified chain.

Both modes accept the all-or-none successor chain: `--successor-max-links` once,
and equal-count repeated `--successor-plan-history-dir`, `--successor-cut-dir`,
`--successor-manifest-history-dir` and `--successor-certificate-dir` in predecessor
order within that explicit budget. Use only existing independently configured
artifacts; see [successor serving](first-successor.md). Do not shorten or replace
the chain with a peer's current committee response.

Successor source export additionally requires `--signer-key-file` to derive and
pin the current public key, not create a signature. It resolves fresh live
authority over the installed Serving namespace, current member/key and verified
chain. This development raw-key input is not protected-custody qualification.
Saved verification reauthenticates the same chain but accepts no signer key or
source database flags and grants no live capability.

For the bounded local recovery composition, continue with the
[offline inactive import rehearsal](business-import.md#offline-business-closure-recovery-rehearsal).
