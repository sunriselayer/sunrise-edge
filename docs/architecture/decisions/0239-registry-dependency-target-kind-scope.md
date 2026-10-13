# DR-0239: Registry dependency target-kind scope for closure target checks

Date: 2026-10-13 (Asia/Singapore)

Status: Accepted bounded source clarification. Fixes a false-positive refusal
in `scripts/check-native-release-evidence.mjs`; grants no native build
execution, M7 completion or release authority. [DR-0213](0213-native-release-artifact-evidence.md)
remains the owning contract.

## Problem

`resolveClosure` previously called `heldFile` on `target.src_path` for every
`target` of every selected package returned by `cargo metadata`, including
registry dependencies. Some published registry crates declare metadata
targets whose source the published archive never ships — for example,
`cookie-factory 0.3.3` declares `examples/` targets in its `Cargo.toml`
metadata that `cargo package` omits from the published `.crate` (its SHA-256
`9885fa...` archive expands to exactly its 15 regular non-example files).
Because the closed recipe never selects any dependency's `example`, `test`,
`bench` or `bin` target, requiring those files to exist is unrelated to this
recipe's build inputs and produces a false ENOENT refusal before either native
build starts.

## Decision

Require canonical absolute target source paths and keep the existing
`within(...)` package/source-boundary check for every
`target.src_path` of every selected package, workspace or registry, with no
change. For a selected **workspace** package (`p.source === null`), keep
requiring a held regular file for every declared target, unchanged.

For a selected **registry** package, only require a held regular file for a
target whose declared `kind` is a normal library (`lib`, `rlib`, `dylib`,
`cdylib` or `staticlib`, singly or combined), `proc-macro`, or
`custom-build` — the kinds this recipe's `cargo build` can actually select
and link. Artifact dependencies are not enabled (`-Z bindeps` is absent).
A registry target declared as `example`, `test`, `bench` or `bin`
is accepted without requiring its source file to exist, because this recipe
never selects it (no `--workspace`, `--all-targets`, `--examples`, `--tests`
or `--benches`; dependency `bin`/`example` targets are never passed to
`--bin`). Any other declared `kind` value fails closed with an explicit
"Unsupported registry target kind" error; nothing is treated as implicitly
acceptable.

Compiler artifact and diagnostic observations for these unselected registry
kinds are refused, even when they match declared metadata.

This changes no workspace target requirement, no shipped thirteen-target
binding, no full-archive/expanded byte or inventory check in
`verifyRegistryPackage`, and relaxes no source/tool/resource/output/actual-compiler
observation requirement. It adds no implicit file discovery: an accepted unselected
target still fails the unchanged boundary check if its declared source
escapes its package root, and a required (library/proc-macro/build-script)
registry target missing its source still fails closed, before any Cargo
`build` invocation.

## Added fixture controls

`scripts/test-native-release-evidence.mjs` adds, as fixture-labelled,
compiler/network-free controls:

- Declared registry `example`, `test`, `bench` and `bin` targets with no backing files is accepted as
  an unselected target; the full fixture orchestration still reports
  `fixturePassed: true`, `complete: false` and the unchanged thirteen shipped
  comparisons.
- A missing registry `lib`, `proc-macro` or `custom-build` source still refuses before any
  build (`calls.builds` stays `{ a: 0, b: 0 }`).
- Noncanonical traversal and unknown target kinds refuse before any build.
- Observed artifacts for each of the four unselected registry kinds refuse
  completion; an unselected diagnostic also refuses before the diagnostic
  early return. Declared metadata never makes them selected inputs.
- A declared unselected registry target whose source escapes its package
  root is still refused by the retained boundary check, before any build.

Status, remaining M7 gates and every other open item stay only in
[`TODO.md`](../../../TODO.md); this record marks no additional work complete.
