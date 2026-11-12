# Original bond protected signing (development fixture)

[DR-0289](decisions/0289-bond-outer-key-custody-and-split-approval.md) and
[DR-0291](decisions/0291-original-bond-inner-standard-asset-profile.md)
select this narrow first operation. It accepts only the original signed
genesis manifest's Standard Asset Coin revision-one whole-coin `transfer` to
the derived `BondCollateral` token, followed by the corresponding initial
validator registration. The source Coin is a supplied snapshot; neither a
local file nor an endpoint-reported `CurrentInline` proves current chain
state. The selected opt-in local-node observation is described below. The
ordered handler rechecks actual source and effects. Signing itself does not
execute or register anything.

## Roles and pinned inputs

Six pairwise-distinct numeric UIDs are fixed in each role's own 0600 config
file under a 0700 directory: CLI requester, broker, inner key worker, outer
key worker, inner approver, and outer approver. The config also fixes chain,
protocol version, one complete epoch-zero hash suite, ordered domain,
original genesis digest, source and validator public keys, and bond resource.
Every role uses byte-identical config content; the broker compares it on
every approval and signing request. Each worker loads only its own key file
and checks that its derived public key is the pinned key for its phase. The
two workers have separate 0750 socket directories and accept only the pinned
broker UID. The broker accepts only the pinned CLI and approver UIDs. All
services check Unix `peer_cred` **before reading request bytes** and have
explicit connection, request, and total-time bounds. Socket group access is
only transport access; it grants no approval or signature role.
The broker holds an exclusive lock tied to the private approval directory's
and lock file's identities for its entire service lifetime. A second broker
on a different socket cannot serve the same store; the lock file remains
after exit and an OS-released lock permits a bounded restart.

The config file fields are `chain_id`, `protocol_version`, `suite`
(`0:id:transaction:object:effects:code:config:certificate`), `domain`,
`genesis_digest`, `source_key`, `validator_key`, `resource_domain`,
`resource_id`, `cli_uid`, `broker_uid`, `inner_worker_uid`,
`outer_worker_uid`, `inner_approver_uid`, and `outer_approver_uid`. No live
request can change them. The signed manifest must match the configured
digest/context and the in-tree Standard Asset artifact, revision, empty
dependency closure, instance, type, schema and transfer entrypoint.

## Sequence

1. CLI `custody prepare-bond-inner` reconstructs a typed private preimage
   from the source Coin and pinned config. It prints the complete inner
   review and writes the request without approval or signature.
2. Under the inner approver UID, `custody approve-bond-inner` independently
   reconstructs and displays the review on a terminal, requires the exact
   confirmation line, and sends the typed request, expiry and config bytes to
   `custody serve-bond-approvals`. The broker reconstructs again, observes
   the peer UID and writes a create-only private record binding the exact
   review, request, source key and unsigned frame.
3. CLI `custody sign-bond-inner` sends the typed request to the broker. The
   broker checks the approval, connects to the inner worker and verifies its
   UID. The worker reconstructs the transfer under its own trust and key,
   challenges the broker with the exact typed request and config over that
   same authenticated connection, then signs only after approval. The broker
   verifies the signature, rechecks approval and releases it to the CLI.
   The CLI independently finalizes it into the authenticated signed leg.
4. CLI `custody prepare-bond-outer` joins that signed leg, the same request
   ID, the original source request and the predicted row. It verifies the
   signed leg, whole-Coin operation, predicted custody reference and amount,
   then prepares the immutable outer frame. The outer approver separately
   reviews and approves it. The broker requires the live inner approval
   before storing or authorizing the outer approval.
5. `custody serve-bond-outer` reconstructs both phases and signs only after
   the broker rechecks both records. CLI `custody sign-bond-outer` receives
   the signature from the broker and finalizes it through
   `PreparedLocalBondRegistration`. The result is a
   structural signed claim (`executed=false`) for the existing kind-7
   wrapper/ordered route.

`custody revoke-bond-inner` and `revoke-bond-outer` create permanent broker
tombstones. An inner tombstone also prevents later outer checks. The two
phases share one request ID, so an outer tombstone also prevents later inner
signing for that request. Approval records survive a bounded broker restart;
they do not overwrite. Expired,
changed, missing, malformed or revoked records refuse. The broker handles
one request at a time, including the worker challenge, signature verification,
final approval check, and reply write/close. Both phase expiries are checked
against one wall-clock sample immediately before emission. The reply
write/close is the signature-release ordering point. A revoke queued during
signing cannot complete before that point; if revoke completes first, no
later signature release is authorized. This is an emission ordering contract,
not a guarantee about when a separate CLI process observes buffered bytes.
The worker only returns a signature to the broker, never to the CLI. A Unix
UID proves an OS
principal for this boundary, not a real person's identity or attendance.

The Linux fixture in
[`apps/cli/tests/bond_registration.rs`](../../apps/cli/tests/bond_registration.rs)
uses a disposable user namespace with five mapped subordinate UIDs and
capability-dropped role processes. It creates no host users or real keys.
Its exact protected output matches the existing signed-leg and registration
vectors, including restart, altered-content, wrong-key and revocation
refusals. A test-only handoff now gives this fixture the existing node-core
genesis/current Coin, then passes the workers' actual signed leg and claim
unchanged to that owner's ordered commit and four-replica oracle. The local
comparison leg never becomes the execution candidate. This verifies fixture
byte continuity and ordered effects; that test-only handoff does not
authenticate current local state or enroll real approvers and keys. Full
required and exact-source CI qualification remain separate in
[TODO.md](../../TODO.md).

## Selected local-node currentness

[DR-0292](decisions/0292-original-bond-trusted-local-currentness.md) selects one
designated original SQLite source host as a trusted local observer for the
initial release. Its opt-in private Unix socket is bound after the host's
writer-fence claim and authenticates the peer UID before reading a bounded
request. The observation uses the host's own store and policy at one stable
portable token; it checks committed epoch zero, the applied ordered tip and
the reviewed Coin's complete identity and canonical body. Both approvers, the
broker, worker and CLI requery that same locator at their decision points.
A changed token, tip, Coin or restarted/unavailable node refuses the request
and requires a new request ID with both approvals. An unpinned version-one
request supplies no currentness assertion.

This is a designated-node trust boundary, not a chain-state proof or atomic
currentness guarantee at delivery. The ordered handler's source and effects
checks remain separate. The multi-UID fixture retains a fixed response for
transport refusals. With pinned operator artifacts, its v2 signing path uses
the compiled `sqlite_genesis` and `sqlite_source_host` over the same manifest
and Coin as its protected CLI roles. It stops and restarts that source to
exercise the changed writer fence before refreshing the signed request. This
fixture does not enroll real approvers or keys; exact-source runtime and
release status remain in [TODO.md](../../TODO.md).
