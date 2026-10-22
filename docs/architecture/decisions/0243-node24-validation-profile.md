# DR-0243: Node 24.19.0 validation profile

Date: 2026-10-14 (JST)

Status: Accepted. Scoped to the Node version pin used by the general CI/
validation lanes and the DR-0213 native-release-evidence scripts. Grants no
other recipe, target, dependency, or dependency-update acceptance.

## Scope

This supersedes ONLY the Node.js version pin recorded in
[DR-0205](0205-bounded-sdk-streamed-response-framing.md),
[DR-0207](0207-local-native-sdk-relay-integration.md), and
[DR-0213](0213-native-release-artifact-evidence.md) for the lanes listed
below. It does not reopen, relax, or reauthor any other binding criterion in
those records, and it does not touch the historical evidence entries already
recorded in [TODO](../../../TODO.md).

Migrated to installed Node 24.19.0, checked through `process.version`:

- The `lint`, `portable-tools`, `cloudflare`, and `check` jobs in
  [`ci.yml`](../../../.github/workflows/ci.yml).
- The `postgres-check` job in [`postgres.yml`](../../../.github/workflows/postgres.yml).
- `scripts/check-native-release-evidence.mjs` and
  `scripts/test-native-release-evidence.mjs` (DR-0213 native-release
  evidence recipe and its fixture).

Unchanged, isolated at Node.js 22.20.0:

- The `rust-tests` job's "Set up Node.js for real SDK relay interoperability"
  step in `ci.yml`, and the DR-0205/0207 test-support fixtures it owns
  (`clients/rust/tests/support/certified-relay-server.mjs`,
  `clients/rust/tests/support/native-certified-relay-server.mjs`, and
  `clients/rust/tests/support/certified_relay_process.rs`). Those fixtures
  hard-assert `process.version === "v22.20.0"`; migrating their lane without
  migrating the fixtures would make the lane fail, not pass with a different
  Node. This slice intentionally leaves that separate DR-0205/0207 relay
  work untouched.

No historical evidence entry, stable encoding vector, Rust toolchain pin
(1.97.1), Deno pin (2.9.4), action SHA, dependency, or npm lock file changes.
All thirteen DR-0213/0221/0224 native targets, the A/B build recipe,
resource/timeout bounds, and archive/cargo-ok byte vectors are unchanged.

## Decision

- `scripts/check-native-release-evidence.mjs`'s `NODE_VERSION` constant and
  its accompanying error messages now require `v24.19.0`; the same recipe,
  target list, resource bounds, and cleanup/comparison rules apply unchanged.
- `scripts/test-native-release-evidence.mjs` requires the owning process to
  run under `v24.19.0`; its 151 fixture controls (archive, marker, cleanup,
  resource, and negative cases) are unchanged in count and intent.
- `ci.yml`/`postgres.yml` set `node-version: 24.19.0` in every job listed
  above; the `rust-tests` job's SDK relay step keeps `node-version: 22.20.0`.
- `scripts/test-ci-gates.mjs` asserts the ordered sequence of `node-version:`
  values in each workflow text — `24.19.0` everywhere except the single
  `22.20.0` SDK relay occurrence in the required profile — so a stray Node 22
  pin in a migrated lane is refused rather than silently accepted, and a
  migrated lane cannot silently drift back to Node 22.

No new Node version file is added at the repository root: a single
`.nvmrc`/`.node-version` cannot represent the two coexisting pins without
implying a single profile, so operators select the exact installed Node
per lane per [AGENTS.md](../../../AGENTS.md)'s local Node version policy
instead.

## Verification

Run with the installed `/home/yu/.nvm/versions/node/v24.19.0/bin/node`:

- `scripts/test-ci-gates.mjs`: passes, including the new node-version
  ordering assertion and its negative mutation controls.
- `scripts/test-native-release-evidence.mjs`: passes; 151 fixture controls,
  zero native builds.
- `git diff --check`: clean.

Full `./scripts/check-all.sh` (actual native A/B, npm/network/build/full
gate) was not run in this slice; see [TODO](../../../TODO.md) for remaining
completion gates.
