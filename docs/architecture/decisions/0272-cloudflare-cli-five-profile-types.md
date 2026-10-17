# DR-0272: Cloudflare CLI configuration and five-profile type checks

- Date: 2026-10-17
- Status: proposed implementation; source review and validation pending

## Decision

Use external `cf@1.0.0-beta.13` and Node 24 for direct repository CLI work.
Five concrete `cloudflare.config.ts` leaves share public configuration data.
The installed loader accepts plain default-export objects, so these leaves
need no unresolved `cf/config` dependency. CI declares the exact external tool.
The project lockfile removes only its redundant direct Wrangler declaration;
the existing test plugin's resolved transitive package remains unchanged.

The renderer invokes `cf workers types --include-runtime=false` on all five
actual leaves. That validates their schema and emits an import-based template.
The invariant template alone proves neither concrete resolved Env types nor
fresh configuration. The explicit finite renderer validates binding kinds and
same-Worker SQLite exports from the same data, then emits the existing Env
names and Worker binding types. A fingerprint covers config bytes, the leaf,
renderer, CLI version and Workers type version. Unknown bindings or changed
CF template fail for review. `--check` compares all five committed declarations
without overwriting them; only ignored CF scratch output can change.

## Preserved contracts

Service and DO namespace/class/Worker names, text/secrets, compatibility dates
and flags, observability, ambient asset modules and ProcessEnv types remain.
Text values widen to string as in the existing validator/certified profiles.
Every DO export selects SQLite. The original JSONC files retain migration tags
as history; no remote migration replay, reset or deployed-state claim follows.
The type renderer disables CLI telemetry with `CF_SEND_TELEMETRY=false`, which
replaces the certified legacy CLI's `send_metrics:false` intent.

Vitest 1.4.0 loads `experimental.newConfig.configPath` with remote bindings
disabled. All four groups, Miniflare mocks, request interception and timeouts
stay. The plugin still imports the transitive Wrangler SDK for Miniflare;
removing direct CLI commands does not remove this internal SDK dependency.

## Validation status

This source-only draft has not installed tools, run CF type generation,
compiled TypeScript, run Vitest, deployed or contacted a provider account.
Proposed declaration bytes are authored from the renderer contract and require
actual generation comparison. Run the existing complete adapter check and all
four groups. Verify stale config/renderer/binding refusal and that `--check`
leaves committed declarations untouched; no new release gate is introduced.

## Sources

- [Configuration](https://developers.cloudflare.com/cf/projects/cloudflare-config/)
- [Migration](https://developers.cloudflare.com/cf/wrangler/migrate/)
- [Vitest](https://developers.cloudflare.com/workers/testing/vitest-integration/configuration/)
- [CLI environment](https://developers.cloudflare.com/cf/environment-variables/)

Installed CF1.0.0-beta.13/config0.24.0 and test plugin1.4.0 source was read for
plain-object loading, schema, generator and experimental config support. Public
docs currently recommend builder imports and illustrate the older Vitest
option; this dependency-free draft uses the installed loader's actual API.
