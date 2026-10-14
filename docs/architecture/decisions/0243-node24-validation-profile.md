# DR-0243: Node 24 validation profile

Date: 2026-10-14 (JST)

Status: Accepted.

## Context

The Node pin in [DR-0205](0205-bounded-sdk-streamed-response-framing.md),
[DR-0207](0207-local-native-sdk-relay-integration.md), and
[DR-0213](0213-native-release-artifact-evidence.md) required 22.20.0.
The user selects Node 24 for current validation, including the real SDK relay
fixtures. Local version management uses the existing nvm without changing
its global default.

## Decision

Use exact Node 24.19.0 for every Node CI lane, the Rust-owned SDK relay
process fixtures, and the Native evidence runner. The root
[.nvmrc](../../../.nvmrc) records the same version for local `nvm use`.
All process.version checks, resolved executable checks and owning-test
prerequisite failures remain mandatory. The CI contract controls reject
old or mismatched versions in ordinary, SDK and PG profiles.

This supersedes only the Node version in those three decisions. Preserve
historical source/profile evidence, Rust 1.97.1, Deno 2.9.4, immutable action
SHAs, all thirteen Native targets, fresh A/B builds, comparisons, cleanup,
resource bounds, workload and stable byte vectors. Dependencies and npm lock
files do not change. A fixture result does not qualify a real build or provider.

## Validation

Run the existing CI registry and Native evidence fixture controls under the
selected Node, then the full repository-required commands and actual Native
A/B for the selected source/profile. Real SDK relay tests must run through
Node 24.19.0 and retain all streamed-framing and local TLS checks. Record
actual results and remaining completion gates only in
[TODO.md](../../../TODO.md).
