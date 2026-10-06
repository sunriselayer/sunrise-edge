# DR-0199: Actual local validator startup and certified CLI calls through TLS

Date: 2026-10-06 (Asia/Singapore)

Status: Accepted design after independent Codex fallback DESIGN APPROVE at
`b62193c` on 2026-10-06, correcting the distinction between key loading and
actual signing. Claude and Grok subscription limits supplied no approval.
This is local acceptance evidence, not a public-network activation decision or
an independent release security audit. Source review and executed acceptance
are separate; current implementation status belongs only in TODO.md.

## Context

DR-0195 and DR-0196 separate signed original-genesis authoring, fresh SQLite
preparation and advisory preflight from the existing original serving host.
DR-0197 inspects the same independently pinned public input without signing or
opening a database. Existing CLI TLS tests use real TLS but a test-produced
context response. Existing compiled SQLite host acceptance uses plaintext
loopback, and historical lifecycle tests additionally select PostgreSQL.
Neither proves an authored original genesis can serve an actual certified CLI
application across independent SQLite validators through the ordinary remote
TLS client path.

The existing network trust boundary already separates per-peer CA/DNS
validation, locally configured protocol context and a signed original-genesis
committee pin. The serving host remains loopback-only with external TLS
termination. A test relay must not become a source of protocol authority or
substitute an encoded success, context, vote, certificate or object response.

## Decision

Add a local integration test of the complete original startup composition.
Reuse the real compiled author, inspector, preparation and serving commands,
the unchanged public Standard Asset template and the ordinary certified CLI
submission/replay paths. No new core, wire, schema, storage, cryptographic or
contract-specific policy is introduced.

All authority seeds and CA material are disposable fixture data. Author one
explicitly configured original genesis, independently inspect its public
authority/digest/context, and prepare four distinct state/blob file pairs.
Each pair belongs to a different registered validator, with its own signing
key and process. They share the same explicitly configured **logical** atomicity
domain because they are replicas of one network; do not derive that domain
from file coordinates or change it merely to make physical files independent.
No live state is seeded by SQL or invented receipts/markers.

Put a bounded, transparent loopback TLS terminator in front of each actual
compiled host. Each peer has its own generated CA, leaf DNS name and explicitly
configured CLI trust file. The terminator forwards the exact HTTP request and
the actual backend response; it manufactures no protocol result. It is a
private test helper, not a shipped ingress service or a production-auth claim.
Its TLS connection count and backend-forwarded POST count are transport-only
observations. A TLS handshake alone must not count as forwarded HTTP.

Run the real separately compiled `sunrise-edge-cli` process, not an in-process
entrypoint. Use the generic top-level transfer construction with one owned
application Coin and a distinct owned fee Coin. Persist its exact signed
intent, FastCertificate, availability certificate and result through the
existing synced/create-new artifact owner. Keep the causal signed admission
profile and do not drop the publication-before-apply step. Check canonical
object, receipt and sender-nonce query bytes against all four actual hosts.
The transfer changes only the requested ownership and ordinary paid fee
effects; it does not use a native balance or a Standard Asset core exception.

Every helper is confined to numeric loopback addresses. Listeners are finite
fixtures, not protocol/background services. Bound connection count, headers,
body/response length, connect/read/write timeouts, CLI/host children and relay
lifetime. Child guards kill and reap actual owned processes on every exit;
relay shutdown joins its worker within its socket/lifetime bounds. The test
has no provider credentials, remote database prerequisite, paid API, deployed
Worker/D1 request or public bind. The existing required gate must explicitly
build the CLI before this process test; an absent binary is a failure, never
a skip. Reuse a dependency-neutral private compiled-CLI locator instead of
importing PostgreSQL fixture helpers.

## Required evidence

1. Actual author -> secret-free inspector -> four fresh preparations -> four
   preflights -> four compiled serving hosts -> four TLS terminators -> one
   compiled CLI certified transfer. The four independent trust files really
   differ and each request reaches its actual host. Verify expected object
   ownership/value, exact committed result and receipt bytes and next nonce on
   every replica. Retain protocol bytes unchanged between transport layers.
2. Exact saved-intent/certificate/availability replay in the same boot, and
   again after stopping/reopening every actual host with its own original
   files. Rebuild only endpoint coordinates/trust configuration as required,
   never re-sign or select a new nonce/request ID. Capture every durable
   business collection and referenced blob per namespace before/after replay;
   require identical rows/bytes and mutation sequence. Restart advances each
   physical writer fence exactly once and does not alter canonical business
   state. An old held reader/writer capability is refused by the new fence.
   Cross-replica equality covers canonical application outputs; per-validator
   vote records and physical snapshot tokens are not claimed equal.
3. Wrong independently configured protocol/domain pin, wrong leaf DNS name,
   wrong per-peer CA and a mixed plaintext/TLS cohort refuse before signing or
   any mutating POST. An intentionally absent seed proves only the existing
   **local** signed-genesis/context-pin and mixed-cohort refusals which precede
   signer loading. Selected-peer CA/DNS and remotely observed context/domain
   negatives instead use a valid protected disposable seed and select the
   affected peer as `--endpoint`, so an unavailable-key error cannot mask the
   actual trust refusal. The existing seed loader derives keys without signing;
   the fee-policy query verifies remote context before the actual paid signing
   call. Review that real ordering rather than claim a measured in-memory
   signature count from absent output files. Assert the precise pin/TLS/cohort
   diagnostic, no new signed/certificate/availability/result artifact, no
   forwarded POST and complete unchanged durable snapshots on every namespace.
   Read-only context queries are allowed where needed to detect the mismatch.
4. After the original commitment exists, a legitimately different signed
   transaction reusing its request ID refuses without changing the original
   receipt, objects, nonce or any durable rows/blobs. Do not treat a saved exact
   replay as this conflicting-input negative case.
5. Run the new nonignored process target, full required storage-neutral
   validation and fresh complete exact-head independent source review. Preserve
   existing unshortened recurring-epoch owners and all mandatory CI groups;
   there is no fixture shortcut, timeout skip or provider-activation claim.

## Boundaries

This closes a concrete local composition/transport evidence gap. It does not
certify internet reachability, authenticated deployment ingress, production
certificate custody/rotation, independent validator administration, database
HA/backup/restore, throughput or production/mainnet readiness. Delivery 4 still
requires a selected reviewed activation profile, independent economics/ingress
security audits and remediation, independently controlled key/store custody and
actual authorized network startup/recovery. No provider is mandatory or
activated by this test.
