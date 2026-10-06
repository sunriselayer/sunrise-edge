# DR-0205: Bounded SDK response framing for streamed relays

Date: 2026-10-07 (Asia/Singapore)

Status: Proposed. Independent PLAN approval precedes production migration;
source, execution, integration and release acceptance belong in TODO.

## Existing boundary

The SDK already provides synchronous loopback HTTP and CA/DNS-pinned TLS.
Both use the same private bounded I/O and HTTP/1.1 response parser. It requires
Content-Length except for bodyless 204, rejects Transfer-Encoding, applies the
original complete-request deadline and requires one-shot Connection: close.
The [certified relay](0204-portable-certified-relay.md) emits a completely
guarded stream without prematurely asserting Content-Length. The missing seam
is response framing, not TLS, signing or protocol authority.

## Proposed contract

Extend that shared parser to accept exactly one of:

- The existing unique, valid Content-Length framing with original byte,
  close/error and deadline behavior.
- One case-insensitive `Transfer-Encoding: chunked` without Content-Length.
  No coding lists, compression, transfer parameters or duplicate coding fields.

Keep the 204 rule: end at headers; reject any Content-Length, Transfer-Encoding
and already-buffered payload; drop the connection without waiting for EOF.
Ordinary responses lacking both supported framings remain refused. No
unframed EOF-delimited 200, automatic retry or redirect is added.

The basis is [RFC 9112 sections 6.3 and 7.1](https://www.rfc-editor.org/rfc/rfc9112.html#name-chunked-transfer-coding):
chunk lengths delimit data and zero plus the complete trailer terminator
delimits completion. Conflicting framing is refused. Transport metadata cannot
replace authenticated application evidence.

Use a private std-only chunk reader behind the existing bounded I/O capability,
not another transport, HTTP client framework or protocol crate:

- Require nonempty hexadecimal sizes. Checked arithmetic refuses overflow and
  the next declared chunk that exceeds the configured decoded-body bound before
  allocation or payload reads.
- Support arbitrary TCP/TLS-record fragmentation, exact data CRLF, zero chunk
  and complete trailers. EOF before any terminator is incomplete even if the
  decoded prefix is already a valid canonical frame.
- Ignore bounded opaque chunk extensions, rejecting embedded control/newline
  ambiguity; never treat them as checksums or authority. Limit each size/extension
  line to 1 KiB and aggregate framing/trailers to 512 KiB. That independent
  budget also bounds tiny-chunk work; decoded bytes stay separately bounded.
- Validate trailer syntax with existing token/safe-value rules, consume and
  discard every trailer without merging headers. Refuse framing or content-type
  trailers, malformed fields and exhausted framing budgets.
- Keep only bounded unread wire bytes and the bounded decoded body. Reject
  buffered trailing bytes, then use the same bounded Connection: close probe as
  length framing. Keep timeout/deadline distinctions and the original deadline
  at every real read; progress never resets it.

Only a complete `WireResponse` may escape. New typed local errors describe
ambiguous/duplicate coding, malformed/incomplete chunks and metadata exhaustion;
they do not add canonical statuses, bytes or receipts. Preserve existing length
refusal priority and caller status/media binding. A dispatched POST's transport
failure is not evidence of rollback; existing SDK workflows own reconciliation.
TLS identity and expected protocol-context validation before signing remain
separate. No CLI signing, provider policy or consensus path changes.

## Owning tests and fixture scope

Keep all original real TCP/TLS, CA/DNS, token secrecy, 204, length, deadline,
malformed-header and slow-drip cases. Only the blanket chunked-200 refusal
intentionally becomes bounded acceptance; forbidden 204/unknown codings stay
negative controls. Pin existing behavior before migration.

Add test-owned raw bytes/errors for ordinary/zero chunks, every split boundary,
bounded extensions/ignored benign trailers, missing zero/data/trailer
terminators, bad hex/overflow, declared and cumulative decoded excess, framing
exhaustion, conflicting/duplicate coding, forbidden trailers, trailing bytes,
held-open peers and unchanged total deadlines. Expectations never use the new
decoder as their oracle.

Share only disposable CA/leaf inputs between real rustls tests and a separate
Node HTTPS fixture. That fixture mounts the actual certified Vercel constructor
on numeric loopback, with locally issued TLS and a completely intercepted fixed
upstream. The Rust transport exercises GET, POST and genuine 204 with native
Node chunked streaming, plus a late stream failure that cannot become success.
Verify actual wire chunking and owned bounded process/file cleanup. Existing
Node 22.20.0 is the required runtime; no hosted resource or external socket.

This is local transport interoperability, not a genuine backend quorum,
deployed-provider qualification, production custody or public activation.
Provider caps and disabled ordered/successor/DO surfaces remain unchanged.

The exact R2 required run at `7853869` executed existing transport suites before
an unrelated later node-core compiler crash. Their SDK transport/test/toolchain/
manifest inputs are byte-identical to relay prerequisite `7424d72`; preserve
that scoped pre-change evidence, not a claimed full `7424d72` gate. Record exact
owning binary and relevant source hashes and directly re-execute those unchanged
transport suites before migration. Owning migrated SDK tests, the portable Node
suite, exact-source review and required CI must pass before normal merge.
