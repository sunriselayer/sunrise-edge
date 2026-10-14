# Native release handoff: artifact-to-capability/runbook bindings

This is a documentation-only binding. It implements the
[R4 "audit/launch integration" contract](implementation-structure.md#maintainability-work-packages):
connect source/build/configuration manifests and the exposed route/signer/store
capability inventory in [compositions-and-capabilities.md](compositions-and-capabilities.md)
to the actual released compositions, without hand-maintaining a copy of their
operator steps. It owns the binding design only. Current completion and
remaining R4/M7 gates stay in [TODO](../../TODO.md); this document never marks
either complete.

It binds, by source, the thirteen actual artifacts that
[`scripts/check-native-release-evidence.mjs`](../../scripts/check-native-release-evidence.mjs)
(`NAMES`, [DR-0213](decisions/0213-native-release-artifact-evidence.md)) records
and full-byte-compares from two fresh sequential Native builds.

## Hash/path/provenance versus config/authority/approval

The evidence manifest (`format: "sunrise-edge-native-evidence-v1"`) records, per
saved artifact entry under `builds.a.artifacts[]`/`builds.b.artifacts[]`: `name`,
`packageId`, `path`, device/inode/owner/mode/size/mtime/ctime, `sha256` and the
matching `source` hash record taken before the copy. That is hash/path/provenance
evidence for one already-built file. It never supplies the config/authority/
approval an operator later chooses at invocation (`--chain-id`, `--domain`,
`--validator-id`, `--signer-key-file`, `--listen`, TLS material, successor-chain
pins): those stay separately reviewed per the linked guide below and are never
read from, or implied by, the evidence manifest.

## Selecting an artifact entry

An operator substituting a binary into a runbook command must read a trusted,
reviewed `manifest.json`: confirm `format`, `evidenceKind: "native-local"`
(never `"fixture"` — a fixture manifest can set `fixturePassed: true` but can
never set `complete: true`), `complete: true`, and `expectedSha` equal to the
reviewed source commit. Then select the exact saved artifact entry by its
recorded `name`/`packageId`/`path`/`sha256`/mode for the target binary, verify
that file's current bytes/mode against the recorded `sha256`/mode, and confirm
its owning package matches the table below. Do not substitute a `PATH` lookup,
a fresh `cargo build`, or an unrelated `target/release` output for that saved
entry; those are not the verified artifact the manifest describes. Treat
`manifest.limitsOfEvidence` as binding: same-host equality only, no cross-machine
hermetic or upstream-authenticity claim, and explicitly "no M7 completion,
release/process/provider/custody/PKI/advisory/public authority".

## Dev/test versus RELEASE runtime acceptance

[DR-0213](decisions/0213-native-release-artifact-evidence.md)'s closed fixed
RELEASE recipe (`--release`, no default features, pinned Rust/CC/linker, fixed
flags) is a build-and-byte-comparison contract, not a runtime-acceptance path:
it builds twice and compares thirteen saved outputs byte-for-byte; it never
executes any compared output. The hosted `recurring-sqlite` job's dev/test
optimization opt-in ([DR-0240](decisions/0240-recurring-ci-compilation-profile.md))
changes only the dev/test Cargo profile used by day-to-day required
validation; it is a development/test build and driver, never the fixed RELEASE
recipe, and never qualifies a release artifact. Which source commits have
produced a complete same-host thirteen-target A/B comparison, and their
build/comparison timings, are current status and stay only in
[TODO](../../TODO.md); a passing comparison for one source is evidence for that
exact source only and is not, by itself, evidence that any preserved/shipped
RELEASE binary was ever executed. Actually exercising a saved RELEASE binary's
runtime behavior is a separate, later rehearsal; see
["Post-comparison local runtime rehearsal" below](#post-comparison-local-runtime-rehearsal-future-separate).
PostgreSQL-backed hosts (for example `fastvote_host_pg`) are a separate,
excluded optional deployment profile and are never one of these thirteen
artifacts.

## Required stop/restart/source-free recovery responsibilities

Two live-writer host modes (`sqlite_source_host serve`, `successor_host serve`)
share the full stop/fence contract in
[native-operations.md](native-operations.md#stop-ownership): an operator must
stop every other writer of the target namespace before starting, hold the
single writer-fence claim for the process lifetime, and use the documented
quiet-stop/SIGINT sequence, never a forced kill, for an orderly handoff. A
restart reopens the same database pair under a strictly newer writer generation
with the same public pins; it never re-prepares genesis as a recovery shortcut.

`successor_host serve-history` is signerless and material-only
(`apps/operator/src/successor_host/historical.rs`): it opens the existing
historical store and reads its current writer fence, but never claims or
advances it, and loads at most a transport TLS key, never a validator signing
key. It shares only the quiet-stop signal contract above, not the live-writer
fence-claim/generation rule; a restart simply reopens the same completed,
sealed source again and requires no new generation.

`native_observations` is a bounded foreground listener, not an instant
one-shot: it blocks on its bound socket until it has received `--max-samples`
(1 to 1,024) records or `--timeout-ms` (1 to 300,000 ms) elapses, then exits
automatically. It has no external stop signal and no restart-generation rule;
["Bounded foreground collection"](native-operations.md#bounded-foreground-collection)
requires a fresh socket path for the next run rather than adopting or removing
the prior one. It asserts no writer-fence or signing authority: it only reads
its socket and decodes already-published live summaries.

Every remaining row is a true one-shot tool with no restart or daemon
lifecycle to rehearse: each invocation independently re-verifies its saved
proofs from scratch and exits; "resume" for `business_import`/`business_recovery`
means re-running the same one-shot command against the same saved/target
paths, not a resident process accepting a signal.

Rehearsing any of these procedures against an evidence-selected artifact
(above) is a semantic-behavior rehearsal of that saved binary; it is not, by
itself, an executed step of the linked runbook, the preserved release recipe,
or an M7/release acceptance claim, and no claim is made here that an
unexecuted step has passed.

## Current loopback/dev-signer scope limit

The startup/first-successor guides linked below compose a numeric-loopback
host with an explicit local key-file signer
([compositions-and-capabilities.md](compositions-and-capabilities.md#store-and-signer-capabilities)).
That composition is a local/dev-signer rehearsal only: it is not a public
validator deployment, production PKI, protected-signer custody, or a complete
M2/other-provider certification. Binding a runbook to an artifact entry here
never extends that scope.

## The thirteen artifacts

| Artifact (`NAMES`) | Cargo source owner | Actual modes (source-classified) | Accepted family/store/signer capability | Runbook (existing guide) |
| --- | --- | --- | --- | --- |
| `sqlite_genesis` | `sunrise-edge-operator`, [`apps/operator/src/sqlite_genesis.rs`](../../apps/operator/src/sqlite_genesis.rs) | `prepare` (writes a fresh causal-admission genesis preparation), `preflight` (snapshot-bound advisory check against a public key) | Offline one-shot; no mounted route; no signing key, only a public-key pin for `preflight` | [Local SQLite validator startup: Fresh preparation / Advisory preflight](../guides/sqlite-validator-startup.md#fresh-preparation) |
| `standard_asset_genesis` | `sunrise-edge-operator`, [`apps/operator/src/standard_asset_genesis.rs`](../../apps/operator/src/standard_asset_genesis.rs) | `author` only | Offline one-shot authoring; local key-file signer matching an independently expected genesis authority; no route/store | [Offline Standard Asset genesis authoring: Run the author](../guides/standard-asset-genesis.md#run-the-author) |
| `genesis_inspect` | `sunrise-edge-operator`, [`apps/operator/src/genesis_inspection.rs`](../../apps/operator/src/genesis_inspection.rs) | single mode, no subcommand token | Offline read-only diagnostics; no signer, no store, no route | [Inspect a signed original genesis: What to examine](../guides/genesis-inspection.md#what-to-examine) |
| `sqlite_source_host` | `sunrise-edge-operator`, [`apps/operator/src/sqlite_source_host.rs`](../../apps/operator/src/sqlite_source_host.rs) | single `serve` mode (flags only, no subcommand token) | Matches the [`sqlite-source-host` composition row](compositions-and-capabilities.md#concrete-composition-owners): original-genesis namespace, offline fence claim, local key-file signer, certified/ordered router with Seal composition, numeric loopback, optional Native TLS | [Local SQLite validator startup: Serving and restart](../guides/sqlite-validator-startup.md#serving-and-restart) |
| `business_cut` | `sunrise-edge-operator`, [`apps/operator/src/business_cut/command.rs`](../../apps/operator/src/business_cut/command.rs) | `export-sqlite`, `verify-saved` | One-shot; export opens an existing SQLite source read-only (never advances its fence) and may pin, never sign with, a successor public key; verify-saved opens no database and no key | [Export and independently verify a pre-Seal business candidate: Build and export / Verify without the source](../guides/business-cut.md#build-and-export) |
| `business_import` | `sunrise-edge-operator`, [`apps/operator/src/business_import.rs`](../../apps/operator/src/business_import.rs) | `create-sqlite`, `resume-sqlite` | One-shot persistent importer into a fresh/resumed CompleteInactive namespace under its own writer fence; no signing key, no route | [Install a verified business cut into inactive SQLite: Resume after bounded work or restart](../guides/business-import.md#resume-after-bounded-work-or-restart) |
| `business_recovery` | `sunrise-edge-operator`, [`apps/operator/src/business_recovery.rs`](../../apps/operator/src/business_recovery.rs) | `pack-saved`, `open-saved` | One-shot LOCAL encrypted saved-closure transport only; never import/activation; no protocol signer | [Install a verified business cut into inactive SQLite: Offline business-closure recovery rehearsal](../guides/business-import.md#offline-business-closure-recovery-rehearsal) |
| `conditional_readiness` | `sunrise-edge-operator`, [`apps/operator/src/conditional_readiness.rs`](../../apps/operator/src/conditional_readiness.rs) | `vote-sqlite`, `certificate` | One-shot; `vote-sqlite` opens the exact completed inactive import with a local vote-only signer key and never advances the writer fence; `certificate` assembles verified weighted signatures with no key/store | [Retain and verify conditional readiness: Vote and exact restart retry / Public certificate assembly](../guides/conditional-readiness.md#vote-and-exact-restart-retry) |
| `ordered_seal` | `sunrise-edge-operator`, [`apps/operator/src/ordered_seal.rs`](../../apps/operator/src/ordered_seal.rs) | `prepare-sqlite` only | One-shot, unsigned staging of a Seal candidate and certificate; a successor `--signer-key-file`, when required, only pins a public identity; no Seal completion, activation or serving; submission is the separate ordered-consensus capability in the same guide | [First-epoch ordered Seal workflow: Prepare and stage exact material / Submit through ordinary ordered consensus](../guides/ordered-seal.md#prepare-and-stage-exact-material) |
| `successor_activation` | `sunrise-edge-operator`, [`apps/operator/src/successor_activation.rs`](../../apps/operator/src/successor_activation.rs) | `activate` only | One-shot target-local atomic activation; re-verifies the full successor chain every invocation and uses a local signer key only to authorize the activation write; no listener or serving route | [Activate and serve the first verified successor: Activate and start locally](../guides/first-successor.md#activate-and-start-locally) |
| `successor_host` | `sunrise-edge-operator`, [`apps/operator/src/successor_host.rs`](../../apps/operator/src/successor_host.rs) and [`.../successor_host/historical.rs`](../../apps/operator/src/successor_host/historical.rs) | `serve` (live writer), `serve-history` (signerless, material-only, non-fence-claiming) | Matches the [`successor-host`/`successor_history_router` composition rows](compositions-and-capabilities.md#concrete-composition-owners): `serve` re-resolves fresh verified serving authority per request, mounts certified/ordered/handoff controls plus successor fee-claim preparation, and uses a local signer key under an explicit offline-fence claim it advances once; `serve-history` mounts exactly three material-only routes, reads but never claims/advances the existing writer fence, loads at most a transport TLS key, and holds no signing/serving warrant | [Activate and serve the first verified successor: Activate and start locally / Independently pinned clients and recovery](../guides/first-successor.md#activate-and-start-locally); shared stop-signal contract in [Native stop and operational observations](native-operations.md#stop-ownership) |
| `native_observations` | `sunrise-edge-operator`, [`apps/operator/src/native_observations.rs`](../../apps/operator/src/native_observations.rs) (Linux only) | `collector` only, source-confirmed: binds the configured Unix socket, blocks collecting until `--max-samples` records arrive or `--timeout-ms` elapses, decodes each `NativeHttpSnapshot` live summary and writes the complete collection to stdout, then exits. No separate persisted-read subcommand exists | Opt-in, bounded foreground listener (up to 300,000 ms), not instantaneous; no signer, no durable store, no writer-fence authority, no mounted network route | [Native stop and operational observations: Bounded foreground collection](native-operations.md#bounded-foreground-collection) |
| `sunrise-edge-cli` | `sunrise-edge-cli`, [`apps/cli/src/main.rs`](../../apps/cli/src/main.rs) | multi-subcommand compiled CLI | Accepted family: generic contract Publication/Instantiate/Call plus the Standard Asset module (no separate node-core privilege); publication-only local OS custody signer path; no production signer backend, no USB/HID (Ledger deferred) | [Smart contracts](../smartcontract/README.md), [publication-preview.md](../guides/publication-preview.md); custody responsibilities in [local-publication-custody.md](local-publication-custody.md) |

Modes above are classified from each binary's actual subcommand dispatch and
`HELP` text, not guessed from the executable name. The two live-writer host
modes (`sqlite_source_host serve`, `successor_host serve`) are foreground
servers with the full stop/restart/fence contract above, never a background
daemon or a protocol-level correctness requirement. `successor_host
serve-history` and `native_observations` are also foreground, non-instant
processes, but neither claims a writer fence; see the distinct rules for each
above. Every remaining row is a true single-invocation tool with no restart or
daemon lifecycle attached.

## Post-comparison local runtime rehearsal (future, separate)

This section records a design boundary only; the rehearsal it describes has
not been implemented or executed, and this slice adds no new executable,
parser, framework, or change to
[`scripts/check-native-release-evidence.mjs`](../../scripts/check-native-release-evidence.mjs)
or its fixture comparer/oracle. [DR-0213](decisions/0213-native-release-artifact-evidence.md)'s
rule that its build/comparison phase never executes a compared output stays
unchanged and is not reopened by this section; it governs only that phase.

A later, separately reviewed slice may add a distinct post-comparison local
runtime rehearsal, strictly after a DR-0213 run reaches verified full
thirteen-artifact comparison and completes its own owned compiler/temp
cleanup. In a separately reviewed, controlled namespace, each saved RELEASE
ELF may be read-only bound onto the exact child executable path that the
existing dev/test acceptance driver (the `recurring-sqlite` lane in
[repository-validation.md](repository-validation.md#required-storage-neutral-checks),
[DR-0240](decisions/0240-recurring-ci-compilation-profile.md)) resolves for
that same binary name, so the driver's children execute the verified RELEASE
build while the driver/test oracle itself keeps running in-process, at the
dev/test profile. The driver's existing selectors/inputs, eight-link fixture,
epoch-8 withdrawals, 35 roles, restarts, refusals, and delays stay exactly as
written; this rehearsal changes only which executable a child path resolves
to, never the driver, comparer, oracle, host debug files, or manifest/comparer
contract from the build/comparison phase, and never borrows an earlier
profile's acceptance result for a different source.

The design requires: verifying each bound RELEASE ELF's hash/mode/owner and
the driver's own source before and after the rehearsal; a read-only whole-host
filesystem with one private writable task-scoped temporary directory; a
private loopback network and PID namespace; a cgroup bounding memory to 16
GiB, swap to 0, CPU to 4, and PIDs to 512; and capturing actual process
exits/EOF plus complete resource cleanup. Only the spawned children execute
the RELEASE build; the in-process driver and oracle remain dev/test.
Qualifying this rehearsal, like the build/comparison phase itself, grants no
M2/M3/M4/M7, public, or other-provider acceptance; those stay separate and
unresolved. The current qualification result and remaining gates are recorded only in
[`TODO.md`](../../TODO.md).
