# DR-0213: Native release artifact evidence

Date: 2026-10-07 (Asia/Singapore)

Status: Accepted bounded design. Complete independent Codex fallback review
approved the original contract at
`0f8a95fd91de667466f2f04c3b07382d166c1c1c611ed3e7d98d45082cd80c48`
and the complete target/host linker clarification at
`9e7f9a87adb87e012f6a49d95965d97372f322c4f04a2cfac4b048de1e8eb25c`.
This accepts the contract, not implementation or native-build execution.
Complete independent Codex fallback design review also approved the
unpack-completion marker amendment at
`adb80555fba150940cab4dd338a9573651f64344077875c4501abc9931f37941`.
The original missing/empty-marker allowance is not sufficient for the pinned
Cargo invocation's no-extraction contract; source correction remains separate.
Current completion and remaining gates stay in [TODO](../../../TODO.md).

## Outcome and owner

One local `scripts/check-native-release-evidence.mjs` script records nonsecret
source/build provenance and compares every byte of two fresh sequential native
builds. It implements [R4](../implementation-structure.md#maintainability-work-packages),
M7 and the [audit input contract](../../security/network-code-audit-scope.md#exact-source-and-reproducible-handoff);
its manifest supplies evidence, never runtime, signing or release authority.

[DR-0208](0208-native-sqlite-first-and-protected-signing.md) selects Native plus
SQLite first. Linux `x86_64-unknown-linux-gnu` is the first local evidence
profile, not production qualification or a waiver of other platform/provider
release criteria. No runtime, crypto, canonical encoding, schema or Cargo profile
rewrite, general controller, broad SBOM inventory or new expensive required CI
owner belongs to this slice.

## Eleven actual targets

Inspected design base: `621d1a0765360754d0a7f933753108e3f8538c1f`.
Ten auto-discovered `sunrise-edge-operator` binaries exist in
`apps/operator/src/bin/<name>.rs`:

- `sqlite_genesis`, `standard_asset_genesis`, `genesis_inspect`;
- `sqlite_source_host`;
- `business_cut`, `business_import`, `conditional_readiness`, `ordered_seal`;
- `successor_activation`, `successor_host`.

The eleventh is `sunrise-edge-cli`, declared in `apps/cli/Cargo.toml`.
CLI and Ledger defaults are empty. Select no extra features and use
`--no-default-features` for both packages: no USB/HID evidence or protected
production signer follows. Locked offline metadata must confirm these real
package/target/source paths and empty defaults; build observations must confirm
the actual selected binaries and dependency/features closure.

Operator still depends on PostgreSQL libraries and `runtime-postgres` alongside
SQLite, native HTTP, SDK and protocol/execution owners. CLI reaches the SDK,
feature-independent Ledger code and public Standard Asset module; SDK still
depends on core/execution. Record that actual closure, including locked source,
versions and archive/expanded-source verification below. Do not remove
dependencies or claim a PG-free graph. Bundled SQLite and ring require native
CC inputs. PG-only binaries/services, tests/examples and provider builds are
excluded; no `--workspace`, `--bins`, `--all-targets` or `--all-features`.

## Closed recipe and inputs

Use installed Node 22.20.0, checked through `process.version`; require its
absolute executable path. The default PATH Node is not evidence of the pin.
Use only Node built-ins and child argument arrays, without shell evaluation,
installation, downloading, provider access or rustup fallback.

The closed invocation takes source path, expected 40-character source SHA,
explicit installed tool paths and an external evidence parent. No arbitrary
features, Cargo arguments or environment overrides are accepted. Hash/version
actual Node, Git, Cargo, rustc, rustdoc, CC, AR and linker executables; resolve
driver aliases and identify the actual linker. Native CC architecture/ABI must
match the Rust host/target; vendor spelling alone is not a mismatch. Invoke
installed Rust tools directly and verify `cargo -vV`/`rustc -vV` against
committed Rust 1.97.1. Record sysroot version/path evidence. Unenumerated sysroot,
runtime and system dependencies remain explicit limits: these observations do
not prove upstream authenticity, hermeticity or hostile-tool/host integrity.
Do not mandate unused C++ tooling or hash whole compiler/system-library trees.

The checked absolute Cargo executable receives this closed argv twice:

```text
build --locked --offline --release --target x86_64-unknown-linux-gnu
--no-default-features --jobs 1 --message-format=json-render-diagnostics
-p sunrise-edge-operator -p sunrise-edge-cli
--bin sqlite_genesis --bin standard_asset_genesis --bin genesis_inspect
--bin sqlite_source_host --bin business_cut --bin business_import
--bin conditional_readiness --bin ordered_seal --bin successor_activation
--bin successor_host --bin sunrise-edge-cli --target-dir <owned compiler root>
```

Only script-generated configuration sets the checked target linker and recorded
Rust path maps. Reject undeclared Cargo configuration in source/ancestors or
selected/alternate Cargo homes, symlinked config, registry/source overrides and
config includes. Reject caller build/target/profile/flag/wrapper, CC/AR flag and
loader injection by variable name; never log rejected values or credential files.

For the selected target, use the checked CC driver with fixed generated Rust
flags `-C linker-features=-lld` and `-C link-self-contained=-linker`. These
disable the target's default LLD selection and bundled-linker search override;
`target.linker=<CC>` alone does not bind the actual GNU linker. Verify the
driver's resolved default GNU `ld` against the explicit checked linker, and
record both flags without changing committed Cargo profiles. Cargo's host
build-script/proc-macro units do not receive those target flags. Require the
actual host `cc` resolution to match the checked driver and separately hash and
record the pinned sysroot's exact `gcc-ld/ld.lld` wrapper and `rust-lld`
implementation, their version observations and host-only roles. Do not call
host LLD execution target GNU-linker execution, claim path-map normalization
of every host intermediate, or extend this into whole-sysroot qualification.
The pinned local tools must support this recipe without compilation during
preflight. Failure stops; no alternate-linker retry changes the recipe.
The [Rust code-generation options](https://doc.rust-lang.org/rustc/codegen-options/index.html#linker-features)
define the selected target's LLD and self-contained-linker controls;
[Cargo target configuration](https://doc.rust-lang.org/cargo/reference/config.html#target)
separates target from host units.

Construct a closed nonsecret child environment with explicit tool PATH,
installed dependency cache as `CARGO_HOME`, pinned Rust/CC/AR tools, offline mode,
incremental disabled and owned target/temp paths. Do not spread the caller env,
repurpose HOME, supply credentials/proxies or mutate download-cache configuration.
Resolve the selected actual registry normal/build dependency closure for this
recipe before A; reconcile its package IDs with both builds' actual observations.
For each package, stream SHA-256 of its cached `<name>-<version>.crate` against
the corresponding registry source/name/version/checksum in `Cargo.lock`. Bind
that archive to its exact declared registry cache and expanded package root.
Using Node built-in streams/zlib, compare the archive's regular-file bytes/sizes
and complete path inventory with expanded source, read-only, without extraction,
cache copying or a `.cargo-checksum.json`/vendor-checksum assumption.
Support checked gzip/tar framing and USTAR/GNU regular-file/directory entries
plus bounded GNU type `L` long-name metadata used by selected `vcpkg 0.2.15`.
Accept `L` only at header name `././@LongLink`, with ≤4,097 payload bytes:
a nonempty UTF-8 name ≤4,096 bytes and exactly one terminal NUL. Consume it
for exactly the next regular-file/directory header, then clear it; reject
orphan/repeated `L`, an incompatible next type and unknown extensions/types.
Count metadata records/bytes in the existing entry/expanded-byte budgets.
Never treat `././@LongLink` as an expanded source path. Apply path/root and
duplicate checks to the effective long name. Reject links/duplicates; require one
exact `<name>-<version>/` root, canonical bounded UTF-8 paths, no absolute path,
backslash, NUL component, dot/dot-dot component or parent escape. Match all files
and declared/inferred directories, rejecting unexplained expanded entries.
Per package: ≤128 MiB compressed, ≤512 MiB expanded, ≤256 MiB per file,
≤50,000 entries and ≤4,096 bytes per path. Entire selected closure: ≤1 GiB
compressed, ≤4 GiB expanded and ≤200,000 entries. Budget overflow fails closed.
The sole extra expanded entry is regular root `.cargo-ok`: ≤128 bytes of
nonempty closed JSON `{ "v": 1 }`, recorded separately by bytes/hash/identity;
it never authenticates source. Refuse links, other metadata or marker drift.
Before any Cargo metadata/tree call, require this attached regular marker and
an expanded manifest for every existing locked cached archive. Missing, empty,
old or invalid marker content fails before Cargo; do not repair or regenerate it.
Apply this guard at every existing input boundary. It does not require missing
unrelated archives or trust a marker instead of archive/source verification.

This accepted amendment follows the pinned
[Cargo unpack owner](https://github.com/rust-lang/cargo/blob/c980f4866141969fab6254a680546a277789d6f0/src/cargo/sources/registry/mod.rs):
`RegistrySource::unpack_package` accepts completed version-1 metadata; missing
metadata causes extraction, while empty/invalid metadata can cause destination
replacement and re-extraction. Existing `Cargo.toml` alone is not a no-unpack
guard. Any explicitly authorized offline dependency-cache preparation happens
separately before evidence, never as an automatic runner fallback. Qualification
still requires exact locked archive hashes, expanded bytes/inventory and drift
checks. Add independent missing/empty/invalid-marker controls proving zero Cargo
metadata/tree calls, no A/B launch, incomplete failure evidence and unchanged
expanded files/sentinel. Valid-marker positives must retain ordinary resolution.
Recheck selected archive hashes, expanded inventories/bytes and `.cargo-ok`
before/after both builds and before final success. Missing input, unknown format,
mismatch or drift retains incomplete evidence and exits nonzero, without fetch,
whole-CARGO_HOME hashing or a general archive framework. Sharing only verified
dependency source is allowed; no compiler/cache wrapper or prior output is input.

Record exact flags: Rust source/dependency/output prefix maps to fixed
`/sunrise-edge/source`, `/sunrise-edge/dependencies` and
`/sunrise-edge/compiler-output`; equivalent supported CC file/debug maps;
`SOURCE_DATE_EPOCH` from the commit timestamp and `LC_ALL=C`, `LANG=C`, `TZ=UTC`.
Keep committed release profiles unchanged. Never strip, patch or normalize
completed executables. Different flags require reviewed recipe change and two
new builds, not automatic retry after a mismatch.

## Ownership, fresh builds and bounded cleanup

Require the exact clean committed SHA and record tree identity, script hash,
tracked path/mode/content hashes, Cargo manifests/lock/toolchain and declared
configuration. Compare tracked bytes/modes to commit blobs despite Git
assume-unchanged/skip-worktree flags; reject untracked source or external path
dependencies. Recheck source/config/tools before and after both builds and before
final success. Exclusive frozen-source ownership prevents concurrent writes or
branch switches; boundary checks alone cannot detect every change-and-revert.

Coordinate with the current full-acceptance owner before consuming its budget.
Never use/clean/reuse its shared target. One compiler job, ≥10 GiB free-disk
admission, ≥5 GiB free-disk abort floor, 4 GiB available-memory admission and a
two-hour deadline per build are the accepted conservative local policy.
They are unmeasured, limit storage/cache growth and do
not guarantee build capacity. Do not auto-lower them. Record admission readings
and observed output use; check disk during builds and between stages.

Create one mode-0700 external run root and exclusive owner record/lock. Refuse
occupied output, source/shared-target destinations, symlink/ancestor escapes or
owner conflicts. The lock prevents duplicate invocations, not unrelated writers.
Build A in new empty `compiler-a`, with no copied/hardlinked/reused intermediates.
Copy eleven regular executables into exclusive independent `artifacts-a` files;
check attachment/mode, synchronize and rehash them. Internal Cargo hardlinks are
allowed, but saved copies cannot alias another artifact or previous compiler output.

Only after verified snapshots and stopped descendants may cleanup remove exact
tool-created `compiler-a`/temp directories whose stored ownership, directory
identity and containment still match. Never follow symlinks or delete broad
roots, user targets/caches, source, HOME, evidence or unresolved paths. Record
cleanup outcome; failed identity/cleanup stops and retains output. Then create
distinct empty `compiler-b` and repeat the same recipe from fresh compiler
outputs. This caps successful storage at one compiler target plus two snapshots.

A/B build, timeout, disk-floor, copy, cleanup or comparison failure retains raw
logs, incomplete manifest, partial snapshots and the failed compiler output;
A failure never starts B. Successful B may be cleaned only after verified
snapshots/comparison under the same owner checks. No old-run/cache scavenging.
Bound JSON lines to 1 MiB and per-build combined logs to 128 MiB; exceeding limits
fails with partial evidence. Shut down owned child/descendant processes on
failure/deadline and retain actual exit/signal information.

## Evidence, comparison and validation

Start with incomplete `manifest.json`; atomically update with checked
synchronization at closed stages. Preserve recipe/source/tool/config/dependency
observations, resource/cleanup results, raw build logs, actual exits/signals and
per-artifact names/modes/sizes/SHA-256. Identify unattempted stages and failures.
Exactly eleven shipped Cargo observations must match the metadata-derived
workspace package ID, target name, `kind=bin` and owned executable path once per
build. Dependency/library/build-script observations are allowed and recorded,
but not counted as shipped artifacts. Within the owned host/release target,
reject missing/duplicate/unexpected selected executable,
nonregular/nonexecutable/symlink/escaped or changed-during-copy artifacts.

Compare complete names, modes, sizes and hashes, then independently stream every
byte pair to exact EOF. Hash equality alone cannot complete comparison. Drift,
nonzero exit, timeout, incomplete JSON/log evidence, illegal output, mismatch,
failed synchronization or cleanup means nonzero exit and `complete=false`.
Only two actual successful fresh builds and eleven full comparisons permit
`complete=true`, scoped to same-host local equality. Do not execute the outputs.

After independent design approval, validate orchestration with separate positive
controls and negative cases for dirty/changed source/tools/config; occupied,
escaped/illegal output/owner; undeclared flags/offline miss; resource/timeout;
bad archive hash/path/type/duplicate/budget/inventory/metadata or cache drift;
orphan/repeated GNU `L`, invalid effective long name/next type or metadata overflow;
missing/duplicate/changed artifacts; B failure; equal-size differing bytes,
forged digest-only equality and unsafe cleanup/synchronization failure.
Each negative preserves evidence/unrelated paths and refuses forbidden later
stages. Separately constructed equal/unequal files test the byte comparator.
Tool doubles provide only labeled fixture evidence. Actual bounded native
rebuilding on reviewed clean committed source is required before execution claims.

Same-host/shared-source-cache repetition is not cross-machine hermetic proof.
Release-profile process acceptance, canonical/effects/consensus/proof parity,
advisory review, upgrade/migration/restore, custody/signing, PKI, provider scope
and public go/no-go stay separate. Required source/repository acceptance remains;
this outcome does not complete M7 or authorize public release.
