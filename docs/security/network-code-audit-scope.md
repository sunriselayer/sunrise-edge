# Network code-audit input contract

This defines the input required for independent review of the implemented
network lifecycle. It is not a completed audit, permission to launch, or a
selection of a production provider. The initial
[code-audit scope](initial-code-audit-scope.md) remains the original narrower
engagement; its exclusions must not be reused as approval of later network code.
Readiness, exact acceptance evidence and open decisions live in
[`TODO.md`](../../TODO.md).

## Select the actual composition

Name the exact executable and router constructor from the
[composition map](../architecture/compositions-and-capabilities.md), its build
features, original versus successor versus history-only role, storage adapter,
signer, atomicity domain and exposed route families. Describe the actual
external TLS/authentication/private-transport configuration separately from
protocol authentication. Do not describe the stateless Cloudflare relay as the
embedded validator, or native SQLite validation as complete DO qualification.
For the [portable certified relay](../architecture/decisions/0204-portable-certified-relay.md),
include the trusted profile/origin/secret selection, complete route/provider
limits, no-follow redirects, full-consumption timeout/cleanup and unknown POST
outcome reconciliation. Its tests neither grant backend authority nor qualify
the current Rust SDK or a deployed provider against streamed HTTPS.

The selected configuration must account for unsupported operations explicitly.
A narrowed provider profile needs its own accepted release decision; it must not
silently drop validator changes, slashing, rewards/claims, lifecycle/handoff or
the original protocol-v3 live-activation prerequisites. No dependency name or
test count is production authority.

## Reachable security owners

The full final-network review includes the following owners in addition to the
first engagement. These are review boundaries, not a statement that a prior
audit has already accepted them:

| Behavior | Source boundary |
| --- | --- |
| Signed intent and canonical contracts | `protocol-types`, `canonical-encoding`, `hashing`, `crypto`, `commitments`, `node-wire`, `node-core::envelope`, Rust client framing/semantic checks and signing view. Include actual feature/dependency selections. |
| Arbitrary contract lifecycle and ordinary assets | ABI/objects/execution/fees, contract SDK's reached raw host-ABI boundary and packaged public modules; core publication/local/paid/fast-path owners. Publish/Instantiate/Call, deterministic execution, object authority, fees and replay must be reviewed together without Standard Asset privileges. |
| Consensus and economics | `consensus`, `validator-set`, `bonds`, core FastVote/publication, shared ordered-economics, fee/bond/registration/equivocation and epoch-transition owners. Include committee structural validation, quorum/proofs, event-specific authorization, reward/claim accounting, bond versus membership distinction and slashing. |
| Original-root handoff and recurring recovery | Immutable genesis and admission-profile verification, business reconstruction/cut, inactive import, readiness, Freeze/drain/frontier, ordered history and completion/Seal, epoch/successor activation and fresh per-request serving authority. Complete proof-chain and physical namespace/fence binding are not optional delta inputs. |
| Persistence and ambiguous completion | Reached runtime transactions/repositories, selected native SQLite/shared SQL or PG adapter and blobs; exact receipt/nonce/object/outbox/proof retention, read assertions, writer fencing, origin/barrier/progress metadata and unresolved-versus-confirmed outcomes. Include selected adapter fault evidence rather than substituting another backend. |
| Concrete ingress, command and operator composition | Actual native/embedded routes from the composition map, Rust client/CLI, compiled operator startup/inspection/import/restart/history/activation binaries and their local pins, signer/key loading, bounds and error conversion. A family is authorized by its core owner, not by endpoint spelling. |
| Provider or proxy adapter when selected | Its actual code, bindings, deployment/network/access policy, private upstream trust, timeouts, operational signer/secret lifecycle and TLS configuration. Local fixtures do not audit an unselected or undeployed public composition. |

Include reachable constructors, decoders, validators and unsafe dependency
boundaries even if their crate was excluded from the first audit. Test fixtures
help reproduce behavior but do not grant deployment or signing authority.
Governance/upgrades, checkpoint publication, Unique Asset, multisig, UI and
Ledger do not gain certification from this contract; retain their original
gates and perform focused review before they become reachable in a release.

## Exact source and reproducible handoff

Before requesting final audit acceptance, preserve:

1. Exact 40-character committed source SHA, clean checkout, intended base audit
   SHA/range if this is a delta, and all reached paths. Do not freeze an audit at
   an uncommitted or earlier functional ancestor.
2. Locked dependencies, compiler/tool versions, enabled features, concrete
   executable/build recipe and artifact digest. A changing branch or PR title
   is not source/build provenance.
3. Redacted nonsecret configuration identifying chain/protocol/genesis digest,
   committee/domain, policies, backend, signer interface and mounted families.
   Retain secret material outside audit documents/logs. This is input evidence,
   not a new manifest-based authority mechanism.
4. Complete output and exit status for `npm ci --prefix
   adapters/cloudflare-workers`, `./scripts/check-all.sh`, `git diff --check`,
   `git status --short` and `git rev-parse HEAD` from that exact source; its own
   required CI owners plus aggregate `check`. Preserve failed/interrupted runs
   and identify them separately. Selected optional backend gates add evidence;
   they do not replace required real SQLite acceptance.
5. Actual startup, TLS/context-before-signing, certified lifecycle, ordered
   economics, five-member recurrence, restart/fence/replay and withdrawal-unlock
   evidence with scoped limitations. Test-only timing is observation, not
   benchmark, source provenance or certification.
6. Independent audit report, complete findings/dispositions and independent
   fix verification bound to the actual final revision. Tech-lead source
   approval and passing CI are not substitutes for security/economic audit.

Each later change follows the initial [delta-audit rule](initial-code-audit-scope.md#delta-audit-rule).
Keep a truthful difference between audited source, built artifact, selected
configuration and deployed endpoint. Public activation still requires the
accepted release gates and explicit human decisions, regardless of this file.
