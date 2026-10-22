# DR-0275: Durable apply with lost local TLS acknowledgements

Date: 2026-10-19 (Asia/Singapore)

Status: Accepted bounded test design. Source review, actual producing compilation,
owning execution and complete repository qualification are separate evidence.
Current status and remaining milestone gates belong only in TODO.md.

## Context and boundary

[DR-0216](0216-local-tls-stop-restart-rotation.md) already observes an actual
ClientHello close before handshake or HTTP, plus explicit stopped trust rotation.
It does not withhold a successful published-apply response after durable paid
execution. Store-wrapper reply-loss tests exercise a different boundary.

The production CLI already saves signed intent, FastCertificate and quorum
availability before published apply. With no successful endpoint acknowledgement,
it reports failure and retains those artifacts for exact replay. A closed socket
after handshake but before response headers uses the existing client
`TruncatedResponseHeaders` diagnostic. No client retry or persistence change is
needed to verify that ambiguity and its receipt-first reconciliation.

## Decision and owners

- `apps/operator/tests/support/https_relay.rs` retains byte-transparent default
  `bind`/`start`. An explicit `start_losing_apply_ack_once` mode names one nonzero
  request ID on one peer, with one observation slot. Only exact
  `POST /v1/fastvote/publications/apply HTTP/1.1` with a canonically decoded
  published-apply request and that signed request ID can match.
- The worker completes the real TLS handshake, forwards the original request to
  its actual compiled loopback backend, and reads the entire bounded original
  response through EOF. Before consuming the one-shot it requires HTTP 200,
  unambiguous complete Content-Length framing, a canonical target `HttpNodeResult`
  containing exactly one `Accepted` response, and a canonical successful paid
  payload for the same target. Handshake, connect, timeout, truncated or error
  responses cannot consume the drop or satisfy the observation.
- The relay retains bounded original request/response bytes, header boundaries,
  observed upstream status, completed-handshake state and the actual plaintext
  response-writer byte count. It drops the real socket before the first
  application write, without `close_notify` or any manufactured HTTP/TLS result.
  The one-shot is consumed only once per peer; subsequent matching requests use
  ordinary exact forwarding. The relay holds no protocol signing authority.
- The separate nonignored Linux selector
  `actual_local_tls_lost_apply_acknowledgements_replay_exact_paid_state_once`
  in `apps/operator/tests/local_tls_startup.rs` composes the existing actual
  author, inspector, preparation, four Native hosts with independent SQLite
  pairs, and separately compiled CLI. It uses the same disposable CA/DNS,
  retained listeners, backends, signing material and independent protocol pins.
  No backend restart or writer-fence advance occurs during loss or replay.

## Required coherent oracle

1. Verify genesis state and absent target receipt/nonce before the first
   ordinary CLI transfer. Arm all four relays explicitly. Ordinary authenticated
   leaf/context queries must still work without consuming the loss.
2. Require the actual compiled CLI to exit with failure after certificate and
   availability persistence, with exactly one apply attempt for every validator.
   Every apply line must report the existing `transport error: connection closed
   before response headers were complete` diagnostic, followed by the existing
   no-endpoint-acknowledged terminal error. A handshake error, timeout or
   key/configuration refusal is not this result. The reserved result file must
   remain empty: this is the existing artifact owner's behavior, not an absent
   path or an observed caller success.
3. Require all four relays to retain a genuine complete HTTP 200 target success,
   a completed handshake, forwarded POST progress and exactly zero downstream
   application-response bytes. Compare each dispatched body with the exact saved
   intent, FastCertificate and availability bytes.
4. Query every replica's receipt before replay. Decode/reencode its exact
   `NodeDedupRecord`; require target request/digest, exactly one `Accepted`
   response and identical canonical paid result bytes. Compare each captured
   upstream body with the `HttpNodeResult` derived from that replica's persisted
   receipt. Derive the in-memory reference result from receipts only.
5. Reuse current owners to authenticate the exact signed intent and both
   certificates and verify canonical result, application Coin, fee source,
   charge/refund, consumed reservation and exactly incremented nonce on every
   replica. Capture complete per-replica 12 SQL tables, both blob tables, four
   portable collections, referenced bodies and mutation sequence before replay.
6. Run the original compiled `fastvote-replay` with those same saved bytes after
   all four one-shots are consumed. Require four stored-success acknowledgements
   and exact result output. Require canonical object/receipt/nonce equality and
   complete per-replica SQL/blob/portable images and mutation sequence unchanged.
   Loss observations, saved artifact bytes, empty failed result and original
   protocol/trust inputs remain unchanged. Join relays and orderly stop/reap hosts.

Keep all existing limits: 512 relay connections, 10-minute lifetime, 30-second
connection deadline, 3-second connect cap, 10-second socket cap, 8 MiB response
cap, 90-second CLI bound and 15-second SDK client bound. Complete SQL images
retain the existing 1,024-row, 512 KiB-cell and 16 MiB bounds. No reduced cap or
unrelated timeout change is part of this test.

## Validation and limits

The new selector and the original complete DR-0216 ordinary TLS control must run
against freshly attributed actual binaries from the integrated source. Owning
formatting and strict all-target/all-feature Clippy, `remote_tls_transport`,
literal npm-ci, the unchanged complete required gate and hosted owners remain
required; static review alone cannot establish execution success.

The existing inline transfer has an explicitly empty referenced-blob closure.
The complete blob tables and closure are still compared, but this is no positive
blob-fault qualification. This slice observes network acknowledgement loss after
genuine durable success and exact replay only. It adds no protocol, trust, schema,
economic, storage or production retry behavior and does not qualify direct
production TLS termination, physical media/fsync/power faults, whole selected
profiles, all M3, independent security review or release readiness. All listeners,
keys, certificates and stores remain disposable private local fixtures.

[DR-0277](0277-historical-blob-ack-loss.md) adds a separate historical-body
preservation selector using the same complete ACK-loss exercise. The original
selector keeps its empty closure. The new selector adds one independently fixed
typed historical reference before hosts start and retains
`positive_blob_fault=false`; paid-produced blob publication is unclaimed.

[DR-0279](0279-orderly-restart-after-historical-ack-loss.md) adds another
separate selector that combines DR-0277's historical body with an orderly
all-owner restart after the original lost-ACK captures and durable receipts
have been reconciled.
