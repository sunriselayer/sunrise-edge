# Local original ordered protocol custody

[DR-0264](decisions/0264-original-ordered-protocol-custody-worker.md) selects a
deployment-only, trusted-local-OS worker for original ordered proposals/votes.
`sqlite_source_host protocol-worker --config <private-file>` owns the existing
core operation, key, source/body and independent anchor together.
`sqlite_source_host protocol-frontend --config <private-file>` owns HTTP/TLS
delivery only. These modes add no executable or public signing route.

Configuration is a bounded UTF-8 `key=value` file, owned by that role's UID at
0600 beneath a 0700 directory. Repeated `suite` entries retain the existing
schedule syntax. Both configurations pin the original chain/protocol/epoch,
domain, complete hash schedule, genesis file/digest and validator. The worker
additionally fixes `signing-key-file`, `state-db`, `blob-db`,
`independent-anchor-db`, `frontend-uid`, `socket`, `max-connections`,
`max-requests`, `total-deadline-seconds`, `timeout-seconds` and `max-concurrent`.
The frontend fixes `worker-uid`, `socket`, `listen`, `max-requests`,
`total-deadline-seconds`, `timeout-seconds` and `max-concurrent`, plus optional
existing TLS certificate/key flags. No request chooses paths or authority.

The worker requires `confirm-offline-fence-advance=true`; every older writer
must be stopped first. Source/body/anchor/key must live under custody-owned
private directories. The explicit anchor must already be enrolled through the
existing stopped-owner procedure. It is not copied or enrolled automatically.
The socket parent is worker-owned 0750 and the new socket is 0660; an existing
attachment refuses startup. Exact mutually pinned peer UIDs, not group
membership, admit IPC. The frontend UID must differ from worker UID.

Both invocation budgets are finite: `max-requests` and worker
`max-connections` are 1..4096, `total-deadline-seconds` is 1..3600,
`timeout-seconds` is 1..30 and `max-concurrent` is 1..256. The frontend's
startup status preflight consumes one request at both ends; configure at
least two to leave capacity for business. The frontend's concurrent accepted
HTTP connection limit is its configured `max-concurrent`. Its original
Native HTTP read/write deadlines remain independently enforced.

Transport carries one closed ordered/history operation, media/encoding header
occurrences in their original order and canonical body per connection. The
private deployment frame is version 2; version 1 peers refuse rather than
collapse repeated headers. Each of the two transported header names has at
most 64 values of 256 bytes each. The total input cap is the original maximum
proposal size plus 34,306 bytes; output retains the existing event-output cap
plus 1,024 bytes. Unknown operations, extra/trailing bytes and invalid lengths
refuse. Protocol frames, domains and signed bytes are unchanged.

Every body-using operation runs its original cheap HTTP preflight locally
before any IPC connection or request-budget use. The frontend reuses the
original preflight response and original bounded body extraction order:
ordinary ordered handlers let extractor failure win; history handlers inspect
media/encoding even if their body extraction failed. The original media-type
error still wins over encoding on ordinary POST handlers. Duplicate encoding
therefore cannot reach worker admission, signing or storage. Tick retains its
empty-body 400 rather than imposing a new one-byte extractor refusal.
Status and outcome reads ignore their request bodies and unused headers without
polling, as the original handlers do. Query fields are ignored by the original
handlers and by this frontend. A bodyless 204 retains absent content type.

This opt-in frontend is a bounded closed HTTP profile, not a general HTTP
proxy. It accepts the explicitly listed methods and paths; unsupported methods
and paths return 404. In particular it does not add automatic HEAD/OPTIONS
behavior. Outcome selectors must be raw ASCII hex with 64 characters and a
nonzero decoded request ID. A malformed nonempty single segment returns the
original 400 before IPC; percent-encoded aliases are not accepted by this
profile. Other collected bodies retain the original extractor and preflight
bounds; rejected requests do not dispatch to the worker. No raw
signature, frame, currentness claim or portable warrant is accepted. Only
worker-confirmed whole operation responses are returned.

The existing ordered router supplies authentication order, fresh invocation
context, ordinary live gates, candidate reservations, consensus lock safety,
real execution, Seal retention and immutable local proposal/vote identities
with vote watermark. DR-0215 independently verifies each actual new or retained
signature. The frontend separately validates returned signed messages against
its pinned original policy before forwarding them. No per-vote human prompt is
introduced. Exact retry remains core reconciliation, never a transport retry.

Both roles close admission and drain started work on signal/deadline. A lost
connection is not rollback. A worker restart reacquires the anchor and claims
the next fence; stale workers cannot commit. Preserve source and independent
authority together for same-host recovery. Neither OS permissions nor this
profile prove encryption, compromised-worker/root resistance, off-host restore,
power-fault durability or all-M2 completion. Runtime results belong in TODO.
