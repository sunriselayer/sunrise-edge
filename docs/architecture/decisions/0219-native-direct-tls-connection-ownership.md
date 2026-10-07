# DR-0219: Direct Native TLS under one connection lifecycle

Date: 2026-10-07 (Asia/Singapore)

Status: Accepted design after independent source-bound seam inspection and
parent review against `3ec8d7bd`. This approves the optional local implementation
and acceptance below, not production PKI, protected custody, source approval,
deployment or public activation. Work status belongs only in TODO.md.

## Context

[DR-0199](0199-local-tls-validator-startup-acceptance.md) and
[DR-0216](0216-local-tls-stop-restart-rotation.md) prove actual SDK/CLI traffic
through private disposable TLS relays to compiled plaintext Native hosts.
The original host and successor live/history hosts still use the same
`native-http` plaintext connection owner. A relay fixture is not a shipped
Native TLS terminator or production certificate rotation.

The existing owner already bounds accepted connections, request collection and
blocking application work. TLS must extend that owner, not add a second accept
loop, queue, handshake task pool, proxy or host lifecycle. The output wrapper
currently delegates flush/shutdown without its write budget; encrypted records
and close-notify make that omission observable.

## Startup configuration and ownership

Keep plaintext `serve` and `serve_with_policy` behavior and signatures unchanged.
Add one immediately used stream-upgrade seam in `native-http`; the operator
supplies the Tokio/Rustls upgrade future. Its private `native_tls` module is the
single configuration and certificate/key-loading owner for original live,
successor live and successor signerless history serving.

- Optional repeatable `--tls-cert-der-file` is an ordered leaf-first chain of
  one to four nonempty regular DER files, each at most 16 KiB and together at
  most 64 KiB. Optional scalar `--tls-key-pkcs8-der-file` is one nonempty private
  PKCS8 DER file of at most 16 KiB. Both options must be present or both absent.
- Consume the actual closed flag set. Check unknown, duplicate, unused, count
  and loopback constraints before file I/O. Load and construct TLS before
  genesis/state/blob opening or writer-generation claim. History consumes the
  same TLS options without gaining a live signer, writer fence or mutation route.
- Read bounded cap-plus-one bytes from nonsymlink regular attachments. Enforce
  private Unix key permissions and check pre-open/post-read attachment identity,
  using the existing common key-file ownership pattern. Do not reopen per
  connection, follow an environment/URL source, accept PEM/password formats,
  generate credentials or fall back to plaintext after TLS refusal.
- Report coarse configuration failures without key/DER contents. Bounded private
  file loading is not zeroization, root isolation or protected custody.
- Add the already locked `tokio-rustls` 0.26.4 directly to workspace/operator,
  with default features disabled and `ring`/`tls12` selected. Retain the locked
  Rustls 0.23.43; do not reexport optional PG transport or introduce its default
  crypto backend. Use the explicit Ring provider and `with_single_cert`.
- Require key/first-leaf SPKI correspondence. Construction does not certify
  expiry, DNS, issuer policy or every intermediate. Serve HTTP/1 only over TLS
  1.2/1.3. Disable session resumption/storage, tickets, 0-RTT and key logging.

## One connection and I/O budget owner

The lifecycle remains: accept, immediately acquire the connection permit,
spawn one tracked task holding it, upgrade if configured, collect one bounded
HTTP request, call the existing router/application, finish bounded output, then
release the permit. Close excess sockets before handshake cryptography. Keep
the existing header/body/response limits and route/status/error precedence.

Use one fixed absolute 5,000 ms TLS handshake deadline, with shutdown-watch
cancellation including an already-signaled watch. Do not add a CLI timing
family or reset the deadline on peer progress. An async deadline is not
preemption of synchronous cryptography or a total RAM/traffic/real-time bound.

Extend the existing `IoIdleTimeoutStream` output idle/total budget to write,
flush and shutdown. First write, first pending flush or first shutdown starts
the output lifetime. A ready successful empty flush before any output starts
no timer: the pinned Hyper dispatcher flushes even while admitted application
work is pending, and its empty-buffer flush directly reaches the stream.
Starting a timer on that no-op would wrongly bound storage by an output budget.
Once started, progress may refresh idle but never reset total output lifetime.
First pending flush and first shutdown are still bounded. TLS can remain pending
while draining ciphertext or close-notify; those operations must not bypass the
same budget. Keep request-read completion before admitted application work,
so ingress idle timing does not time out storage execution.

Do not abort a started `spawn_blocking` store operation or classify it as a
rollback/rejection because the peer disappears. Its work permit stays held to
completion. A lost confirmation is unknown and reconciles by exact receipt and
intent, not a new nonce or blind retry. Handshake/output deadlines do not promise
globally bounded shutdown of admitted application work. Late bind/composition
failure after a fence claim does not grant rollback, repair or fence reclamation.

## Authority and explicit stopped rotation

TLS authenticates the endpoint, not chain/protocol context, caller authority or
application intent. Existing SDK CA/DNS trust and separately configured expected
protocol context stay independent. Valid TLS with the wrong protocol context
must still refuse before signing. Do not infer authority from DNS, SNI, issuer or
bearer headers; no first-slice mTLS or new external event family is introduced.

Keep numeric loopback binding and existing publish opt-in, routing, canonical
frames, schemas and economic behavior. TLS configuration is immutable for a
host lifetime. Rotation is quiet ordinary successful stop, exact child reap,
explicit file/config replacement and restart at the same endpoint. There is no
watcher, hot reload, alternate-port fallback or automatic trust re-pin. Live
reopening advances the existing fence; history reopening advances no live fence.

## Owning acceptance

Reuse existing four-independent-store original-host, activated-successor and
history fixtures rather than create a second recurring network runner. Preserve
all genuine recurrence, unlock delays and historical refusal/replay controls.

1. Refuse half-configured/unknown/duplicate options, wrong file count/size,
   symlink/nonregular files, nonprivate key permissions, malformed leaf/key and key
   mismatch before durable I/O/fence claim. Compare exact existing state and
   verify no new durable artifacts; use private permissions for the key only.
2. Exercise real TLS success, malformed/plaintext/slow-drip or pending handshake,
   ClientHello-close, excess connection refusal, permit recovery and shutdown,
   with nonvacuous route/transport counters. Separately test private controlled
   writer branches and actual encrypted output/backpressure. Attribute each
   oracle honestly; a synthetic writer is not a real peer.
3. Prove response write/flush/shutdown budgets and application work that outlasts
   ingress idle without cancellation. Preserve actual GET/POST results and
   post-disconnect receipt reconciliation.
4. Run compiled original hosts with direct TLS and four independent SQLite
   pairs. Use actual SDK/compiled CLI certified paid transfer, complete state,
   receipts, nonce, referenced blobs and mutation sequences, exact same-boot and
   restarted replay, and request-ID conflict oracles. No relay substitutes for
   the direct-host success or rotation evidence.
5. Exercise actual activated successor TLS serving and signerless history TLS
   with its three existing historical read routes. Preserve authority/refusal
   boundaries and do not introduce history mutation or a live writer claim.
6. Keep wrong CA/DNS/leaf and valid-TLS/wrong-protocol refusal with complete
   unchanged state and no new signed result. Observe actual authenticated peer
   leaf DER with fresh no-resumption clients, not configuration alone.
7. Quietly restart the original direct hosts with a fresh same-CA leaf at their
   same endpoints, preserving protocol/cohort trust and exact receipts. Verify
   received new DER/SPKI, live fence 2 -> 3 and otherwise valid stale reads/CAS
   refuse. Perform a separate unrelated-CA direct-host restart at the same
   endpoint and fence 3 -> 4; held old SDK and fresh old-trust CLI refuse exact
   `UnknownIssuer`, while explicit new trust succeeds. Use distinct issuer DNs.
   This direct CA phase differs from DR-0216's relay-only no-backend-restart phase.
8. Restart history TLS without a live fence and retain the original DR-0216
   relay controls with their narrower attribution. No safe-path substitution
   or weakening is allowed to make direct TLS acceptance pass.

Serialize actual owning builds/tests and strict Clippy under the shared compiler
budget; retain complete npm-ci/check-all, all seven required CI owners and
success-only check, plus fresh independent complete-source review. Add no heavy
CI lane or selected-PG claim. Package compilation is not process execution.

## Limits and remaining decisions

This is server-authenticated local Native transport, not production PKI,
compromise revocation, automatic renewal, remote root distribution, overlapping
trust cutover, zero-downtime/HA or an independently audited release. Production
CA/names/trust distribution, public caller authority, protected custody/admin
roles, renewal/revocation, workload/SLO/alerts, independent audit and launch
remain separate human decisions or qualification. They do not block this safe
optional local implementation and cannot be invented from disposable fixtures.

Only numeric loopback, disposable keys/certificates and privately owned local
stores are in scope. No provider write/deployment, public listener, paid service,
credential/root action or public-network/mainnet activation is authorized.
