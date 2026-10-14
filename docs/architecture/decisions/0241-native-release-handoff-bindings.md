# DR-0241: Native release handoff artifact-to-capability/runbook bindings

Date: 2026-10-14 (JST)

Status: Accepted documentation-only binding. Grants no implementation,
execution, deployment, or R4/M7 completion claim.

## Decision

Add one source-based binding document,
[native-release-handoff.md](../native-release-handoff.md), connecting each of
the thirteen actual artifacts recorded by
[`scripts/check-native-release-evidence.mjs`](../../../scripts/check-native-release-evidence.mjs)
(`NAMES`, [DR-0213](0213-native-release-artifact-evidence.md)) to its exact
Cargo source owner, its source-classified actual modes, its accepted
family/store/signer capability from
[compositions-and-capabilities.md](../compositions-and-capabilities.md), and
its existing operator runbook. This implements the
[R4 "audit/launch integration" contract](../implementation-structure.md#maintainability-work-packages):
bind actual released compositions to their source/build/configuration
manifest and capability inventory, and require unsupported families to fail
closed, without a hand-maintained copy of executable operator steps.

Modes are classified by reading each binary's actual subcommand dispatch and
`HELP` text (for example `sqlite_genesis` `prepare`/`preflight`,
`successor_host` `serve`/`serve-history`, `native_observations`'s single
source-confirmed bounded `collector` mode with no separate read subcommand),
never guessed from the executable name. True one-shot tools gain no fictitious
restart or daemon lifecycle. Only `sqlite_source_host serve` and
`successor_host serve` claim and advance a writer fence and share the full
host stop/restart/fence contract in
[native-operations.md](../native-operations.md#stop-ownership).
`successor_host serve-history` (`apps/operator/src/successor_host/historical.rs`)
is signerless and material-only: it reads but never claims or advances the
existing writer fence, so it shares only the quiet-stop signal, not the
fence-claim/generation restart rule. `native_observations` is a bounded
foreground listener (blocks up to `--timeout-ms`, at most 300,000 ms, for
`--max-samples` records, then exits automatically): it is not an instant
one-shot, but it also claims no writer fence or signing authority.

The document distinguishes:

- artifact hash/path/provenance, as recorded per saved entry under
  `builds.a.artifacts[]`/`builds.b.artifacts[]` in the DR-0213 evidence
  manifest, from the config/authority/approval an operator separately supplies
  at invocation;
- the DR-0213 fixed RELEASE recipe, a build-and-byte-comparison contract that
  never executes a compared output, from the hosted `recurring-sqlite` job's
  dev/test optimization profile ([DR-0240](0240-recurring-ci-compilation-profile.md)),
  which is a development/test build and driver and never substitutes for or
  qualifies that recipe as a runtime-acceptance path. Which source commits
  have a complete same-host thirteen-target A/B comparison, and their timings,
  is current status and stays only in [TODO](../../../TODO.md); a passing
  comparison is evidence for its exact source only, never proof that a
  preserved/shipped release binary was executed under a linked runbook, and
  never cross-machine/hermetic/provider acceptance;
- the current loopback/local-key-file-signer compositions used by the linked
  guides, which remain a local/dev-signer rehearsal, not a public validator
  deployment or complete M2/other-provider certification.

An operator selecting a saved artifact for a runbook substitution must read a
trusted, reviewed manifest's `format`, `evidenceKind` (never `"fixture"`),
`complete`, and `expectedSha`, then select the exact saved entry by its
recorded `name`/`packageId`/`path`/`sha256`/mode; a `PATH` lookup or a fresh
`cargo build` is not that verified entry. PostgreSQL-backed hosts are a
separate excluded deployment profile and are never one of the thirteen.

## Post-comparison local runtime rehearsal (future, separate)

This decision also records, as a design boundary only, a distinct future
slice that a later, separately reviewed change may implement: a
post-comparison local runtime rehearsal. It does not implement or execute
that rehearsal. The DR-0213 build/comparison phase's rule that it never
executes a compared output is unchanged and is not reopened here; it governs
only that phase.

Strictly after a DR-0213 run reaches verified full thirteen-artifact
comparison and completes its own owned compiler/temp cleanup, a separately
reviewed, controlled namespace may read-only bind each saved RELEASE ELF onto
the exact child executable path that the existing dev/test acceptance driver
(the `recurring-sqlite` lane, [DR-0240](0240-recurring-ci-compilation-profile.md))
resolves for that same binary name, so its spawned children execute the
verified RELEASE build while the driver and its test oracle keep running
in-process at the dev/test profile. The driver's existing selectors, inputs,
eight-link fixture, epoch-8 withdrawals, 35 roles, restarts, refusals, and
delays stay exactly as written; only which executable a child path resolves
to changes. This never alters the existing manifest, comparer, oracle, or
host debug files, adds no new repository executable/parser/framework, and
never borrows an earlier profile's acceptance result for a different source.

The design requires verifying each bound RELEASE ELF's hash/mode/owner and
the driver's own source before and after; a read-only whole-host filesystem
with one private writable task-scoped temporary directory; a private
loopback network and PID namespace; a cgroup bounding memory to 16 GiB, swap
to 0, CPU to 4, and PIDs to 512; and capturing actual process exits/EOF plus
complete resource cleanup. Only spawned children execute the RELEASE build;
the in-process driver and oracle remain dev/test. This grants no M2/M3/M4/M7,
public, or other-provider acceptance. No rehearsal run has been performed
under this design.

## Scope and non-goals

This is a documentation-only design boundary covering [native-release-handoff.md](../native-release-handoff.md)
and this record. It binds existing, already-accepted capability and runbook
documents to the DR-0213 evidence artifacts; it defines no new release
framework, executable wrapper, or runtime parser, and changes no existing
manifest, comparer, oracle, source, test, or CI behavior. It does not mark
`TODO.md`, R4, or M7 complete; current completion and remaining gates stay
only in [TODO](../../../TODO.md). It does not alter `README.md`, `AGENTS.md`,
source, tests, CI, or dependencies. The provider-stopped M1/D02 independent
security/release review is untouched by this slice, as is every M2/M3/M4/M7
and public/provider acceptance condition.

## Verification

This change is documentation only. Cross-referenced facts (actual
subcommand/mode dispatch, `HELP` text, manifest field names, and composition
rows) are read directly from the cited source files and existing accepted
documents at `fdc816e1`, not reproduced from memory. Every relative link
added by this slice was checked, read-only, against the files and headings it
targets.
