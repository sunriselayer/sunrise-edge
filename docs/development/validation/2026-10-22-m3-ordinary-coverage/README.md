# M3 ordinary SQLite coverage record (2026-10-22)

Frozen validation accounting record. Read against source checkout `sunrise-edge-m2-m3-followup-1021` at base `b389843411a8685da29fc96173ee5597463efefb` (tree `dfdc63d5`). The live status source is `sunrise-edge-qualified-todo-status-1018/TODO.md` at `419e98f1`, M3 lines 1097-1160. The source checkout's TODO is not used. No tests were run and no product source or TODO was changed.

## Closed-image coverage

The ordinary TLS ACK-loss selector captures four actual state databases and their paired blob databases. `apps/operator/tests/support/sqlite_durable_image.rs` at blob `28b92a76634e659698f7a14a87d88d9b5b84df19` defines a closed 12-table SQL inventory (lines 15-76), two blob tables (77-88), checks the live table and exact column inventory and captures complete ordered rows (around 170-228), then compares complete images except the explicitly advanced fence (253-276). The 12 SQL tables in that inventory are:

| SQL table | Assertion/evidence in the ordinary ACK-loss/restart path |
|---|---|
| `durable_metadata` | complete row included; `assert_only_fence_changed` permits only writer_fence 2 to 3 |
| `durable_import_progress` | complete row set equality |
| `durable_outgoing_barrier` | complete row set equality |
| `durable_successor_serving` | complete row set equality |
| `durable_state` | complete row set equality |
| `durable_conditional_readiness` | complete row set equality |
| `durable_object_heads` | complete row set equality |
| `durable_object_versions` | complete row set equality |
| `durable_receipts` | complete row set equality |
| `durable_outbox_messages` | complete row set equality |
| `durable_outbox_delivery` | complete row set equality |
| `durable_outbox_attempts` | complete row set equality |

This is closed-inventory and before/after persistence coverage. It does not assert that each table is nonempty or make a physical page/WAL equality claim. In the new restart selector, `apps/operator/tests/local_tls_startup.rs` blob `a66731d18df1ea7caa52c8e4b644ca74c24642f9`, lines 2976-3025 capture the images after durable apply, require the ACK-loss captures, orderly-stop all hosts and reopen generation 3, compare logical snapshots, then require only the fence change across all 12 SQL and two blob tables. Lines 3108 onward compare the complete durable image before/after exact replay and require unchanged portable snapshots, committed result, receipt and referenced body.

## Portable collections and positive referenced-body oracle

`apps/operator/tests/support/historical_referenced_body.rs` at blob `d2abe151db3ed57769bf54f73cfabb7fc836a2e8`:

| Portable collection | Positive ordinary assertion |
|---|---|
| State | `assert_snapshot` requires this collection in the exact captured set |
| Receipts | same exact-set assertion; the fixture also retains and reads its typed receipt |
| ObjectHeads | exact-set assertion and `verify` checks the expected current head and TLS object query |
| ObjectVersions | exact-set assertion and `verify` reads the expected version/blob reference |

The collection-set oracle is lines 130-150; install creates the canonical object, digest, version, head and receipt and writes the same referenced body to each of four replica blob stores at lines 35-127. `verify` re-reads the exact typed records and TLS object reference at lines 153-240. The body is 70 KiB and decoded/re-encoded bytes and digest are exact. This proves a positive referenced closure with a pre-existing typed historical object, not a body published by the paid transfer.

The exact selectors are `actual_local_tls_lost_apply_acknowledgements_preserve_historical_referenced_body` and `actual_local_tls_lost_apply_acknowledgements_preserve_historical_body_after_orderly_restart`, in `apps/operator/tests/local_tls_startup.rs` lines 2743-2757. The shared fixture verifies genuine successful upstream apply responses withheld before downstream response bytes and receipt-first reconciliation at lines 2840-2974. It logs `referenced_blob_closure=historical_nonempty positive_blob_fault=false paid_produced_blob_publication=false` at lines 2990-2996. These two false predicates remain false: neither positive blob fault nor paid-produced publication is covered.

## Ordinary reopen, fencing, and portable snapshot predicates

- `crates/runtime-sqlite/tests/sqlite_structured.rs` blob `8d4636af872b42b2eb24a5c7438d6ef224ac382b`, test `sqlite_structured_restart_persists_state_objects_receipts_and_outbox` lines 730-914: closes/reopens one file, reads state/object/version/receipt, rejects a duplicate invocation from its persisted receipt, reconciles an outstanding outbox lease, makes ACK idempotent, and rejects a stale context after fence advance.
- Same file test `sqlite_blob_reference_and_content_survive_paired_close_and_reopen` lines 927-1031: paired structured/blob files retain a typed blob reference and exact canonical object bytes after close/reopen.
- Same file `sqlite_structured_writer_fence_survives_reopen` lines 1061-1078: persisted fence is observed after reopen.
- `crates/runtime-sqlite/tests/sqlite_structured/portable.rs` blob `c5b1c39a96bd73460213c21512154780e9e90826`, `sqlite_portable_reads_survive_close_reopen_and_fence_old_writer` lines 29-125: portable conformance reads survive reopen and stale-generation read is `WriterFenced`.
- Same file `sqlite_portable_snapshot_token_enforces_reads_across_reopen_and_change` lines 193-282: token-bound scan/descriptor/chunk survives close/reopen, then refuses after a covered mutation; a same-length rewrite is specified by its test comment. It also rejects empty-outbox status after an outbox is added, claimed, and acknowledged.

## Qualified evidence and disposition

Live Q/TODO lines 1116-1132 records: E193/E198/E199 for empty-closure durable ACK loss and replay; E203-E205 for historical referenced-body ACK loss; and E206/E208/E209 for the new historical-body ACK loss, orderly generation 2-to-3 restart, and replay. In particular E206 records the actual runtime selector and the earlier empty/same-generation/original TLS controls; E208 is all eight natural-success CI jobs on the same b389 source; E209 is the same-source local complete-required success. These are qualified evidence for the mapped ordinary slice, not parent M3 completion.

The broader ordinary SQLite conformance/TLS/required/CI lineage is explicitly attributed in live Q/TODO lines 1155-1160 to E156/E164/E167/E168; the five existing ENOSPC cases are separately recorded as E169. This map does not substitute either for a stopped boundary. Live TODO marks independent-anchor guest boundaries and selected virtual-device partial persistent write as unverified/stopped, and marks the M3 parent incomplete. Those cells remain excluded and unverified here; no stopped code or assessment was inspected.

## Finding

No additional ordinary runtime assertion is established as missing by this matrix. The exact source shows closed coverage for all 12 table images, all four portable collection kinds, the positive historical referenced-body oracle, reopen/fencing, ACK-loss reconciliation and exact replay. This is an evidence map, not a new test result, not a claim that each SQL table has rows, and not M3 completion. No new ordinary runtime rerun is justified by this matrix alone.

## Root qualification

Root verified every cited product-file blob against b389 and the unchanged M3 files at subsequent source `8da1d620`. The five ordinary SQLite test names listed above each have an actual `ok` result in the E209 closed stdout (SHA-256 `af4a4c3ad5599d9efa213e4852fb6089d9fc6e851d6776370ae05487dfc16aa2`). The 12 table names exactly match the source inventory. Root receipt: `m3-ordinary-coverage-map-1022-root-qualified.json`. This report adds no test execution or parent acceptance.
