# DR-0277: Historical referenced body across lost local TLS acknowledgements

Date: 2026-10-21 (Asia/Singapore)

Status: Accepted bounded test design. Source review, producing compilation,
owning execution and complete repository qualification remain separate evidence.
Current completion status and milestone gates belong only in TODO.md.

## Context

[DR-0275](0275-local-tls-durable-ack-loss.md) loses genuine successful apply
acknowledgements before the first downstream TLS application write and then
reconciles the exact saved paid request. Its original inline Standard Asset
transfer explicitly has an empty referenced-body closure. Comparing complete
blob tables in that case does not prove preservation of a positive reference.

The selected Standard Asset bodies are fixed small canonical layouts; padding a
Coin would violate its declared body. A larger paid-produced body or a new blob
publication path is outside this fixture. Instead, reuse the existing historical
storage-fixture condition accepted by
[DR-0265](0265-stopped-native-storage-profile-upgrade.md): one independently fixed
70 KiB canonical object, published before its typed owning reference, distinct
from all paid Coin traffic.

## Decision and owners

Add the separate nonignored Linux selector
`actual_local_tls_lost_apply_acknowledgements_preserve_historical_referenced_body`
to `apps/operator/tests/local_tls_startup.rs`. It shares the existing complete
ACK-loss exercise through an explicit Empty/Historical choice. The original
`actual_local_tls_lost_apply_acknowledgements_replay_exact_paid_state_once`
selects Empty and keeps its original empty-closure assertion and diagnostic.
Every original scenario, assertion, artifact and finite limit remains in place.

The dedicated test-private `support/historical_referenced_body.rs` adapts the
literal historical object from DR-0265. `support/storage_upgrade.rs`, its
`BodyOracle` and its separate ignored upgrade selector remain unchanged. This
slice does not invoke the upgrade owner or require a prior executable.

After real author/inspect/prepare and before starting any serving host, each of
the same four original SQLite namespaces receives exactly one fixture object:

- Object ID `[61; 32]`, version1, address owner `[62; 32]`, type digest
  SHA2-256 `[63; 32]`, schema1, and exactly70KiB of byte64.
- Canonical encoding must decode to that full fixed object and be larger than
  64KiB and at most80KiB. Its object digest is derived with the authored chain,
  protocol version and epoch through the existing resolver.
- The public `BlobStore::put_blob` publishes those exact bytes first. A typed
  Create invocation then commits an absent-head assertion, the immutable
  `BlobReference` version, owner/routing projections and a canonical Accepted
  receipt for fixture request `[81; 32]`. The event digest is independently
  derived from the same fixed object bytes in the NodeEvent domain. Require
  actual `Committed`; no SQL writes or orphan-only inserts satisfy setup.
- This setup adds no application authority, nonce mutation or outbox. All setup
  storage handles leave scope before hosts start; the parent retains only the
  independent expected object, bytes, digests, typed head/version and receipt.

## Required coherent oracle

1. Before arming loss, verify every replica's exact historical head, immutable
   version and canonical receipt through fresh typed SQLite reads. Validate the
   complete portable snapshot and require its entire referenced-body map to be
   exactly the independently fixed digest/body pair. Decode and reencode the
   full captured object and independently recompute its object digest. Require
   all four portable collections. Query each actual TLS peer and require the
   exact `CurrentBlobReference` head/version/object-digest/blob-digest result.
2. Run the unchanged DR-0275 paid transfer and four one-shot relays. Require the
   real caller failure with the original truncated-headers diagnostic and empty
   result file, genuine complete upstream target successes with zero downstream
   application bytes, exact saved intent/certificates, and independent receipt
   reconciliation before replay. Preserve the existing application Coin,
   consumed reservation, charge/refund, fee source and single nonce increment
   checks. Repeat the full historical oracle after that reconciliation.
3. Capture the existing complete per-replica12 SQL tables, both blob tables,
   four portable collections, referenced bytes and mutation sequence. Require
   the exact positive historical closure in those retained snapshots.
4. Replay the same saved request through the original compiled CLI after all
   one-shots are consumed. Require four stored-success acknowledgements, exact
   result bytes, unchanged complete images/tokens and all original artifact,
   paid effect and nonce checks. Repeat the historical typed/body/TLS oracle.
   Loss observations, empty failed result, saved bytes and pinned inputs remain
   unchanged. Join relays and orderly stop/reap the same hosts.

The fixed70KiB body and at-most80KiB canonical encoding remain the existing
historical-fixture bound. Each replica adds one head, one immutable version,
one receipt and one blob through the typed invocation and blob APIs. The shared
ACK-loss exercise retains512 relay connections,10-minute relay lifetime,
30-second connection deadline,3-second connect cap,10-second socket cap,
8MiB response cap,90-second CLI bound and15-second SDK bound. Complete SQL
images retain1,024 rows,512KiB cells and16MiB total. No cap or deadline changes.

## Qualification boundary

The positive condition is preservation of an already committed historical
reference/body while a separate genuine paid transfer loses its network ACK and
replays exactly. Both selectors retain `positive_blob_fault=false`; the new
selector also reports `paid_produced_blob_publication=false`. The fixture does
not claim paid-produced blob publication, blob-write faults, physical faults,
schema/profile/trust/protocol changes, whole M3 or release readiness.

The new selector, original empty ACK-loss selector, original complete ordinary
TLS startup/restart selector and full `remote_tls_transport` target require
owning execution against attributed actual current binaries. Formatting, strict
owning Clippy, literal npm-ci, the unchanged complete required gate and hosted
owners remain required. Source-only checks do not establish those results.

[DR-0279](0279-orderly-restart-after-historical-ack-loss.md) retains this
historical-body condition and adds a distinct all-owner orderly-restart and
post-restart replay selector. The original empty and same-generation historical
selectors keep their existing behavior.
