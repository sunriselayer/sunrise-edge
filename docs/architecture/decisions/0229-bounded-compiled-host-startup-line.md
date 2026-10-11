# DR-0229: Bounded compiled-host startup line

Date: 2026-10-11 (Asia/Tokyo)

Status: Accepted for ordinary test-source implementation only. R3 remains open.

## Context

The compiled-host test supervisor owns the child before reading its piped
stdout, then captures the first LF-terminated startup line. Its existing
receiver timeout does not impose a byte limit on `BufRead::read_line`.

The inspected startup producers are the SQLite source host, active successor,
historical successor and optional PostgreSQL host. Their production output
formats are not changed. `ChainId` has no protocol length maximum; a fixed
global cutoff would silently impose a new limit on configured chain strings.

## Decision

Use the test-private `compiled_host_startup_line_limit(&str)` constructor,
returning `NonZeroUsize` from checked `428 + chain_id.as_bytes().len()`.
Every existing startup caller constructs its allowance from its known fixture
chain before spawning, including successor formats that omit the chain field.

The longest inspected fixed envelope is 428 bytes, including LF: 128 literal
and framing bytes, three 64-byte hexadecimal fields, a 10-digit `u32`, two
20-digit `u64` values and a 58-byte scoped IPv6 socket address. Independent
literal-format source controls pin these inclusive maxima:

- SQLite source: `347 + chain UTF-8 bytes`.
- Active successor: `399`.
- Historical successor: `333`.
- Optional PostgreSQL host: `428 + chain UTF-8 bytes`.

Extend both startup reader and spawn interfaces with that explicit cap. The
reader checks cap-plus-one and its conversion through `u64::try_from`, then
puts `input.take(probe)` inside `BufReader`. It keeps `read_line()?` before
successful-read classification. An encountered Read or UTF-8 failure retains
priority. A successful count above the inclusive cap returns `InvalidData`
with the fixed message `compiled host first status line exceeded byte cap`;
empty or unterminated bounded reads retain the existing `UnexpectedEof` result.

Successful first-line bytes are returned unchanged, including LF, CRLF and
Unicode. Whole-stream EOF is not required. `BufReader` may prefetch through LF;
the physical probe supplies at most cap-plus-one bytes, not a guarantee of zero
post-LF I/O, a fixed number of reads, heap capacity or wall-clock completion.
Any error occurring only beyond the bounded probe is unobserved.

Child guard ownership, receiver deadlines, successful reader join and existing
failure cleanup are unchanged. This decision does not add nonblocking pipe
configuration, process-group control, cleanup hooks or production flags.

## Exact source scope

Only these eight existing test-source files and this new ADR are selected:

- `apps/operator/tests/support/compiled_source_host_process.rs`
- `apps/operator/tests/support/successor_host_acceptance.rs`
- `apps/operator/tests/support/ordered_seal_sqlite_acceptance.rs`
- `apps/operator/tests/sqlite_source_host_process.rs`
- `apps/operator/tests/local_tls_startup.rs`
- `apps/operator/tests/support/recurring_host_acceptance.rs`
- `apps/operator/tests/standard_asset_genesis.rs`
- `apps/operator/tests/sqlite_genesis.rs`
- `docs/architecture/decisions/0229-bounded-compiled-host-startup-line.md`

The seven caller files contain ten startup calls. Existing real-case test names
and assertions remain, with only the explicit allowance passed to each call.
No TODO, architecture index, observation contract, production host or other
author's source is selected by this decision.

## Source controls and limits

Pure controls cover inclusive-cap LF, one-byte-late LF, counted endless no-LF
input, real `ConnectionReset` after exactly cap bytes, empty/short EOF,
first-LF success before a later read error, UTF-8 failure and unchanged CRLF.
Literal maximum producer-format controls use a long multibyte chain and pin
the 58-byte scoped address and 428/347/399/333 arithmetic independently of the
new constructor. These controls do not spawn children or open databases.

Source-only status: UNFORMATTED / UNCOMPILED / UNEXECUTED. No formatter,
compiler, project parser, test, process helper, service, database, network or
acquisition workflow was run for this implementation. PostgreSQL formatting
arithmetic grants no live PostgreSQL authority or qualification.

There is no all-path release, process-group, kernel-syscall, scheduling,
cleanup-time or durability guarantee. A startup line still does not establish
host survival, ordered completion, custody, activation or physical durability.
Implementation and declared controls alone do not close R3 or any TODO item;
later review and any authorized execution remain separate work.
