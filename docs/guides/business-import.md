# Install a verified business cut into inactive SQLite

`business_import` privately reexecutes one complete independently authenticated
saved cut and installs its verified raw inventory into a dedicated import-only
namespace.
The result cannot admit new business, sign protocol votes/ACKs or serve an
activated epoch. See [the storage/authority contract](../architecture/verified-inactive-import.md)
and [DR-0176](../architecture/decisions/0176-verified-inactive-business-import.md).

## Inputs

First produce the complete output in the [business cut guide](business-cut.md).
Reuse its independently configured `CUT_CHAIN_ID`, `CUT_PROTOCOL_VERSION`,
`CUT_EPOCH`, `CUT_DOMAIN`, `CUT_SUITE`, `CUT_GENESIS_FILE`,
`CUT_GENESIS_DIGEST`, `CUT_HISTORY_DIR` and `CUT_OUTPUT_DIR`.

Choose two distinct absent destination database paths whose parent directories
already exist and are operator-controlled. Both files must be outside the
saved-cut and ordered-history archive trees; the command checks regular
ancestor paths and held directory identities before destination effects.
Set `IMPORT_STATE_DB`,
`IMPORT_BLOB_DB` and `IMPORT_VALIDATOR_ID` yourself. The validator ID selects
the destination namespace; it does not certify eligibility in the next set.
Do not supply a private key, endpoint or source writer generation.

```sh
cargo build --locked -p sunrise-edge-operator --bin business_import
BUSINESS_IMPORT_BIN="${CARGO_TARGET_DIR:-target}/debug/business_import"

"$BUSINESS_IMPORT_BIN" create-sqlite \
  --chain-id "$CUT_CHAIN_ID" --protocol-version "$CUT_PROTOCOL_VERSION" \
  --epoch "$CUT_EPOCH" --domain "$CUT_DOMAIN" --suite "$CUT_SUITE" \
  --genesis-manifest "$CUT_GENESIS_FILE" \
  --expected-genesis-digest "$CUT_GENESIS_DIGEST" \
  --ordered-history-dir "$CUT_HISTORY_DIR" --cut-dir "$CUT_OUTPUT_DIR" \
  --state-db "$IMPORT_STATE_DB" --blob-db "$IMPORT_BLOB_DB" \
  --validator-id "$IMPORT_VALIDATOR_ID" \
  --max-new-batches 1 --timeout-seconds 300
```

Input parsing and independent plan verification precede destination creation.

To enforce an earlier independently verified ordered-history position, add all
three `--history-floor-epoch`, `--history-floor-height` and
`--history-floor-digest` arguments to both create and resume. Retain these pins
outside the history/cut being restored. The epoch must match exactly; the
verified history must include that exact ancestor block digest. A newer tip
alone does not choose between forks. This optional refusal guard does not prove
whole-state freshness or permit activation; see
[DR-0248](../architecture/decisions/0248-import-ordered-history-freshness-floor.md).

Creation reserves fresh paths and a destination-local fence; it never reuses
an ordinary namespace or copies source-local authority. Creation failure may
leave reserved files. Do not delete/repair metadata or force resumption of
missing/invalid schemas; use another genuinely fresh destination instead.

## Resume after bounded work or restart

`business_import=partial` means bounded new batches were durably installed,
not that the target may serve. Close the process and rerun with the same exact
local pins, saved cut, destination paths and namespace:

```sh
"$BUSINESS_IMPORT_BIN" resume-sqlite \
  --chain-id "$CUT_CHAIN_ID" --protocol-version "$CUT_PROTOCOL_VERSION" \
  --epoch "$CUT_EPOCH" --domain "$CUT_DOMAIN" --suite "$CUT_SUITE" \
  --genesis-manifest "$CUT_GENESIS_FILE" \
  --expected-genesis-digest "$CUT_GENESIS_DIGEST" \
  --ordered-history-dir "$CUT_HISTORY_DIR" --cut-dir "$CUT_OUTPUT_DIR" \
  --state-db "$IMPORT_STATE_DB" --blob-db "$IMPORT_BLOB_DB" \
  --validator-id "$IMPORT_VALIDATOR_ID" \
  --max-new-batches 4096 --timeout-seconds 300
```

Each invocation accepts one through 4,096 new atomic batches, each at most
128 rows and 64 MiB total new represented rows plus distinct required bodies.
The complete installed prefix is verified before any new material is written;
resumed bodies are checked using exact-length descriptors and at most 1 MiB
read ranges. This does not cap legal history or the CPU/memory cost of
independently reconstructing it. Resume uses verified
existing writable import/blob schemas without creating or repairing them.

`business_import=complete-inactive` means the complete raw inventory and
referenced immutable bodies were independently compared and the completion
was fenced atomically. The reported `cut`, `package` and `plan` identities must
remain fixed. It is not readiness, Seal, activation or a live-network release.

An ordinary target, wrong namespace/binding/pins, conflicting row, missing or
surplus material, corrupt progress or stale fence refuses. A deleted cursor
does not erase import origin. Exact original business replay remains receipt-
first and non-executing under the current fence; new execution and cached
protocol signatures/ACKs remain refused in every import phase.

The native SQLite structured-file schema is version 5. Older initialized durable files are
unsupported, not automatically migrated or reset. Preserve any needed old
data separately and request an explicitly scoped preservation workflow.
SQLite evidence does not certify PostgreSQL, D1, a deployed DO host, readiness
or production/mainnet safety.

## Offline business-closure recovery rehearsal

[DR-0212](../architecture/decisions/0212-offline-business-closure-recovery.md)
reuses the existing commands; it is not a new live-restore or promotion mode.
Start with one genuinely drained original outgoing epoch and independently
reviewed local pins. No production values or public network are created.

1. Run the compiled [cut export](business-cut.md#build-and-export) until complete.
   Retain the original signed genesis, fixed history and complete immutable cut.
2. Stop and close every source SQLite owner, including the separate blob store.
   In an operator-controlled isolated rehearsal, make both original state and
   blob paths unavailable. Merely clearing state handles is insufficient. Do
   not move or open/close independent leaf descriptors under active SQLite.
3. Run [saved verification](business-cut.md#verify-without-the-source) with no
   source or signer inputs. Keep both source paths unavailable throughout the
   subsequent `create-sqlite`, `resume-sqlite` and exact final resume commands.
4. Require `complete-inactive`, unchanged `cut`/`package`/`plan` identities and
   `new_batches=0` on final resume. Ensure neither source path was recreated;
   input archive/history inventory must remain unchanged. An ordinary store
   open must still refuse this import-origin destination.
5. Only after the offline sequence, reattach the original sources and compare
   their complete business snapshot with the pre-export observation. An
   unchanged archive hash or successful command exit alone is not that check.

Creation is not atomic across two database files: after the first import-origin
state file is initialized, body-file creation can fail. Preserve that inactive
residue for inspection. Ordinary open and resume with a missing body file must
refuse; do not repair/bootstrap the missing file, reset metadata or force resume.

Logical execution generations and their authenticated floor are preserved.
Destination-local writer-fence/source-instance identity and physical revisions
are fresh; refencing a copy cannot revoke the original inode's writer or signer.
The rehearsal ends inactive and is not physical old-writer exclusion, arbitrary
crash continuation, freshness proof, encrypted off-host backup or mainnet M4
qualification. Those requirements remain in [`TODO.md`](../../TODO.md).

For a saved successor cut, keep original-genesis pins and provide the same full
all-or-none verified predecessor chain described in the
[cut guide](business-cut.md#successor-source-and-saved-verification). Current
context is derived from that chain, not selected by changing the declared epoch.
Import/saved verification accept no signer key; their verified business closure
does not acquire serving or signing authority.

## Encrypted local relocation

[DR-0221](../architecture/decisions/0221-encrypted-recovery-closure.md) and the
[encrypted recovery contract](../architecture/encrypted-recovery-closure.md)
define authenticated encryption of the original saved bytes, including every
explicit predecessor role for later cuts. The source implements
`business_recovery pack-saved` and `business_recovery open-saved` for the selected
disposable local single-recovery-X25519 profile. This implementation candidate
is not validator signing custody, off-host retention or a qualified backup
destination.

The opener requires completed authentication, exact inventory/physical EOF and
independent original-root proof verification in private staging before accepting
its output. It never creates SQLite or grants activation. Subsequent
create/resume still uses the existing verifier and inactive boundaries above;
independent external pins are not read from the encrypted input. These are
implemented source boundaries, not completed runtime or release qualification.

The implemented exact-TOTAL-cap same-cursor probe can establish physical EOF
only from a real underlying zero; it never qualifies plaintext or replaces
final authentication, the subsequent explicit EOF/stamp checks or proofs.

Continue using the existing inactive import rehearsal until the candidate's
validation completes; runnable encrypted-recovery instructions remain deferred.
Do not treat source presence as backup qualification or create a real recovery
key. Owning/full/source-free validation, all 35 original/current/predecessor
roles from the complete eight-predecessor e8 closure, thirteen fresh Native A/B
targets, final-head hosted CI/review, dependency/PG acceptance and host-resource/
custody gates remain pending.
Current evidence and remaining M4
requirements belong in [TODO](../../TODO.md).
