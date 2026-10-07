# Native release artifact evidence

The bounded runner implements [DR-0213](../architecture/decisions/0213-native-release-artifact-evidence.md).
It records source, locked dependencies, tools and flags, then compares eleven
executables from two fresh sequential builds. It never executes those executables.
Linux `x86_64-unknown-linux-gnu` is a local evidence profile, not production or
provider qualification. Actual native rebuilding, required repository/process
acceptance and M7 completion need separate evidence; neither this guide nor fixture
results claims those gates.

## Prerequisites and ownership

An owner must first approve the implementation and recipe, commit all inputs
including the runner, freeze the exact source SHA and allocate resources with the
current acceptance owner. Do not run while another acceptance owner has reserved
the budget. The script cannot allocate that budget or enforce STOP-WRITES against
unrelated writers. Its exclusive source lease blocks only another invocation of
this tool for the same canonical source, independent of output directory or SHA.
The lease lives in mode-0700 `/tmp/sunrise-edge-native-evidence-<uid>`; it is removed
only by its recorded owner after descendants stop. A stale/conflicting lease fails
closed; there is no automatic scavenging or general approval-token interface.

Use installed Node exactly 22.20.0 and explicit installed Cargo/rustc/rustdoc
1.97.1 paths, not PATH defaults or rustup proxies. Supply explicit Git, GNU CC,
AR and GNU linker paths and an existing absolute Cargo cache. Driver aliases are
resolved and recorded. The source must be a clean committed repository root with
the committed script attached there; untracked inputs and external path dependencies
are refused. Git flags cannot hide changed tracked bytes/modes. The output must be
a new external directory, not an existing empty directory. Source, cache, tools,
Git metadata and the primary checkout including its shared target are prohibited
destinations. No source/cache copying or reuse of compiler output occurs.

One job, at least 10 GiB free output-filesystem disk and 4 GiB available memory
are required at admission. Free disk below 5 GiB aborts; each build has a two-hour
deadline followed by bounded process-group shutdown. These conservative,
unmeasured floors do not guarantee capacity and cannot be lowered by CLI flags.

## Closed recipe and provenance

The CLI accepts only source/SHA, eight tool paths, Cargo cache and output path.
No arbitrary features, build arguments, environment overrides or fixture mode
are available. Children receive a closed nonsecret environment with explicit
PATH, RUSTC/RUSTDOC, CC/AR, cache, locale, commit SOURCE_DATE_EPOCH, offline mode,
disabled incremental compilation and fresh target/temp paths. HOME is neither
inherited nor repurposed. Caller build/flags/wrapper/loader injections are rejected
by variable name without printing their values. Discovered Cargo configurations
at the source/ancestors and selected/alternate Cargo homes are refused, including
symlinked config directories. Credential files are never read.

Both builds use `--locked --offline --release --no-default-features --jobs 1`,
the explicit GNU target, JSON diagnostics and only these selected binaries:

- `sunrise-edge-operator`: `sqlite_genesis`, `standard_asset_genesis`,
  `genesis_inspect`, `sqlite_source_host`, `business_cut`, `business_import`,
  `conditional_readiness`, `ordered_seal`, `successor_activation`, `successor_host`.
- `sunrise-edge-cli`: `sunrise-edge-cli`, with no USB/HID feature.

The actual normal/build closure retains PostgreSQL libraries; no PG-only binary,
service, provider build, test or example is selected. Cargo tree resolves target
conditions and selected feature sets; Cargo metadata supplies package/target/source
identities, not workspace-wide selected-feature proof. Both builds must reconcile
the exact selected package set, feature unions and every distinct feature variant,
plus exactly eleven package/bin/executable observations, not just eleven names.
Actual host/target roles are recorded from owned release paths; build-script and
proc-macro outputs must be host, while shipped binaries must be target. Malformed JSON,
unfinished JSON tails, fresh/reused artifacts and unexpected outputs fail closed.
Stdout and stderr are separate raw logs; JSON lines are limited to 1 MiB and
combined raw logs to 128 MiB per build, retaining partial evidence on overflow.

Generated configuration binds the target linker to checked CC. Fixed target Rust
flags `-C linker-features=-lld -C link-self-contained=-linker` prevent rustc's
default bundled-LLD target selection; source/cache/compiler/temp prefix maps and
equivalent CC file/debug maps are recorded. The exact recipe and source require
independent approval before execution. Cargo host build-script and
proc-macro units do not receive target Rust maps; their relevant bundled `ld.lld`
wrapper and `rust-lld` implementation are separately hashed/versioned, with PATH's
host CC required to match the checked driver. GNU target ld and bundled host LLD
are distinct observations. No automatic alternative flags, profile rewrite,
stripping or post-build byte/mode normalization is permitted.

Before resolution, existing locked cached archives must have expanded manifests,
so Cargo cannot silently extract them. Missing unrelated cached archives are not
required; an actual offline miss still fails. Each selected registry dependency
is then bound to the exact metadata manifest/cache bucket and locked source,
name/version/archive SHA-256. A bounded built-in streaming gzip/tar reader matches
every archive regular-file byte and complete declared/inferred directory inventory
to expanded source, including GNU `L` metadata used by vcpkg. It refuses unknown
formats, duplicates, links, illegal paths, extra empty directories, framing errors
and over-budget bytes/entries. Only root `.cargo-ok` is additional metadata: a
regular file at most 128 bytes, empty or closed `{ "v": 1 }`, recorded separately
and never trusted as authentication. No extraction, vendor-checksum assumption or
whole-CARGO_HOME hash is used. Cargo's own cache bookkeeping/locks are not a promise
of whole-cache read-only operation; source/archive/marker drift is checked.

## Output and failure handling

The mode-0700 run root contains an exclusive owner record, an initially incomplete
atomic synchronized manifest and raw stage/build evidence. Source bytes/modes,
configuration, tools, closure, archives, expanded inventories and markers are
read again before/after both builds and before final success. Freeze ownership is
still necessary: boundary checks cannot prove that no change-and-revert occurred.

`compiler-a` and `temp-a` are new empty directories. Eleven saved `artifacts-a`
copies preserve actual modes, cannot alias compiler or other snapshot files,
and are synchronized and rehashed. Only after stopped descendants and verified
snapshots can the exact created compiler/temp directories be removed, checking
creation identity, owner, device, containment and every descendant without
following links. Then independently fresh B repeats the same recipe. B cleanup
also requires eleven comparisons: names/modes/sizes/hashes and every byte to exact
EOF with held regular-file attachments. Successful storage is bounded to one
compiler target plus two snapshot sets; this is not a disk-capacity guarantee.

Failure retains raw logs, partial snapshots, incomplete manifest and failed
compiler output. A failure does not start B. Exit/signal and unattempted stages
are recorded; interrupt/deadline/error shutdown waits and forces the owned process
group before cleanup or return. Unsafe cleanup stops, never deletes user targets,
cache, source or broad roots. If synchronization/storage itself fails, persistence
can be incomplete; nonzero status is never success and raw retained files need
inspection. Preserve failed evidence; there is no old-run/cache scavenger.

## Invocation and fixture checks

After approval, commit/freeze and budget allocation, substitute the exact reviewed
SHA and absolute paths. The installed Node must invoke the committed source script:

```sh
/absolute/installed/node-22.20.0 /absolute/clean-source/scripts/check-native-release-evidence.mjs \
  --source /absolute/clean-source --expected-sha REVIEWED_40_HEX_COMMITTED_SHA \
  --node /absolute/installed/node-22.20.0 --git /usr/bin/git \
  --cargo /absolute/toolchain-1.97.1/bin/cargo \
  --rustc /absolute/toolchain-1.97.1/bin/rustc \
  --rustdoc /absolute/toolchain-1.97.1/bin/rustdoc \
  --cc /usr/bin/cc --ar /usr/bin/ar --ld /usr/bin/ld \
  --cargo-home /absolute/existing-cargo-cache --output-dir /absolute/new-evidence-run
```

The cheap compiler/DB/network-free controls use independently constructed archives,
files and labelled tool/resource/process doubles. They exercise successful complete
orchestration and negative drift/output/failure/timeout/cleanup/synchronization
cases. Doubles cannot select a production bypass or set native `complete=true`:

```sh
/absolute/installed/node-22.20.0 scripts/test-native-release-evidence.mjs
```

Even successful native evidence is same-host/shared-cache equality, not upstream
authenticity, hostile-host/tool integrity or cross-machine hermetic proof. Sysroot,
runtime and system-library contents are not exhaustively enumerated. Advisory,
canonical/effects/consensus/proof parity, release-profile process acceptance,
upgrade/migration/restore, custody/signing, PKI, provider scope and public go/no-go
remain separate gates. See [TODO](../../TODO.md) for current status, not this guide.
