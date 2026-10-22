# DR-0279: Orderly restart after historical-body acknowledgement loss

Date: 2026-10-22 (Asia/Singapore)

Status: Accepted source contract. Actual qualification belongs in TODO.md.

## Context

DR-0275 exercises four genuine durable FastVote apply successes whose HTTPS
acknowledgements are withheld. DR-0277 adds a fixed historical referenced body
to that flow. Both replay in the same host generation. The ordinary TLS
restart control already reopens generation 3 and preserves TLS listeners, but
does not combine that restart with the acknowledgement-loss and historical
body path.

## Decision

Add a separate test selector using the existing positive historical-body
fixture and lost-ACK exercise. After the first failed caller result, validate
all four exact one-shot captures and reconcile all four durable receipts and
the existing complete business oracle. Then stop and reap all four relays and
hosts orderly, reopen the same SQLite stores at generation 3, and restart the
relays on the same bound listeners with the same certificates, TLS config,
names and endpoints.

Require the existing complete source-business snapshots and referenced-body
map to survive reopening. Require the complete durable SQL image comparison
to identify only the existing writer-fence generation change from 2 to 3. Read
all four receipts again and compare exact encoded bytes, verify the exact
saved intent/certificate/availability bytes and the fixed 70 KiB historical
body closure, then replay the unchanged request. Replay must leave the
generation-3 SQL images and complete business snapshots unchanged. Newly
started relays begin without inherited ACK-loss captures or counters; old
captures are checked before stopping their owners.

Keep the existing empty-closure selector and same-generation historical-body
selector unchanged. This selector retains `positive_blob_fault=false` and
`paid_produced_blob_publication=false`. No fault, protocol, authority, schema,
row-inventory or storage behavior is introduced, and no cap or deadline is
raised.

## Limits

This is an orderly local process restart over the existing development stores.
It does not establish physical power-loss durability, torn writes, a new
recovery mechanism, all M3 acceptance, production deployment or release
readiness. Actual owning execution and the existing complete gates remain
necessary for qualification.
