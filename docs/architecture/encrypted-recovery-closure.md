# Encrypted saved-business-closure transport

Status: Accepted design.
[DR-0221](decisions/0221-encrypted-recovery-closure.md) records the dated decision
after parent full-text review and a different complete design approval of the
C4 correction. This contract specifies the CLI and bounded SDK entries;
implementation and qualification status belongs in [TODO](../../TODO.md).
Design acceptance is not source approval, executed recovery, an audit,
dependency clearance or completion of M4.

## Scope and unchanged authority

The only selected prospective profile is disposable, local,
single-recovery-X25519 encryption, separate from validator signing keys. It is
not real custody, off-host retention, activation or a human M2 backend choice.
Reuse the existing [cut](first-epoch-business-cut.md), original
[genesis](genesis-trust.md), [successor chain](recurring-successor-serving.md) and
[inactive import](verified-inactive-import.md) owners. Add a bounded transport
around their original saved bytes, not a backup engine, runtime trait, proof
verifier, normalized certificate format or shell-through import wrapper.

A package contains exactly `3 + 4L` logical roles: original signed genesis,
current fixed-target history and complete current cut, plus every predecessor's
plan history, cut, manifest history and readiness certificate in explicit link
order. `L=0` is original genesis; `1..16` requires an independently supplied
`SuccessorChainBudget` and the existing all-or-none predecessor inputs. Identical
bytes in different roles are not deduplicated. Do not select the last link,
skip/reorder epochs, replace original genesis or fabricate a first-epoch base.

External chain/protocol/original-epoch/domain/hash schedule, expected original
genesis digest, expected current cut digest and exact package digest remain
independently retained inputs. None is adopted from decrypted metadata or a
peer. Later policies come only from `verify_successor_chain_authority`.
Packing and opening compare `VerifiedImportPlan::binding()` with those external
cut/package pins after the existing saved-import verification. A matching
transport hash is not freshness, sender identity, checkpoint authority, a
verified import capability or latest-state/rollback protection.

Keep raw original proof carriers and the required `source-token.bin`; the token
checks source-local continuity, not cross-replica or writer/signing/serving
authority. Do not copy SQLite/WAL/SHM or transplant physical revisions/writer
identities into destination authority. Exclude live protocol namespace/safety
rows and their reservations/cursors/ACKs outside the existing raw business
projection, validator signing keys,
TLS keys, readiness signing keys or unreferenced blobs. Logical authenticated
generations and the generation floor survive through the existing raw import
projection; destination physical revisions, source-instance identity and fence
are fresh. Preserve ALL bytes that the existing business/proof owners require;
do not add a recovery key filter or strip business data. No old writer is
revoked by this transport.

## Concrete owners and opt-in bounded entries

The proposed native operator module and tiny binary `business_recovery` expose
only `pack-saved` and `open-saved`. Their callable composition has no database,
signer, endpoint, activation, reset, adoption or cleanup input. Reuse the
crate-local saved-proof composition behind `BusinessPinInputs`/`BusinessPins`
and `business_import`, with the original core factories:
`VerifiedGenesisRoot::verify_bytes`, `verify_successor_chain_authority`,
`verify_saved_business_import` and `verify_saved_business_import_chain`.
Extract that composition once if needed; do not parse a second command or
invoke an import child. Existing `create-sqlite`/`resume-sqlite` remain separate
and independently reverify every invocation.

The prospective CLI input sets are closed, not runnable examples:

| Mode | Required local inputs |
| --- | --- |
| `pack-saved` | Existing public business trust fields and expected current cut/package; original genesis file, current history/cut and equal-count four-role predecessor paths with explicit link budget; one public X25519 recipient; absent private capture root and absent ciphertext output |
| `open-saved` | Same independent public trust fields/current cut/package and public X25519 recipient pin, explicit expected link count and budget; one ciphertext file, one separate private recovery identity file, absent private output root; NO original genesis/history/cut/source-DB path flags |

The shared trust parser retains the existing chain/protocol/original epoch/domain/
suite/genesis-digest meanings. A crate-local saved-input composition supplies
captured/generated paths to the bounded `BusinessPins` load entry; it does not
manufacture argv or a new trust model. Manifest `L` must match the local expected
count before role construction; all-or-none predecessor source inputs on pack
still use the existing ordering/budget check. Only downward profile quotas are
additional options. Unknown, duplicate or mode-irrelevant flags refuse before
file access. No subprocess, runtime/provider trait or automatic retry follows.

Before any archive constructor, install one concrete invocation-owned SDK
`ArchiveReadBudget` handle in the existing `immutable_archive` owner. Its
private shared counters cannot be reset by cloning a handle or opening a role.
Proposed additive entries are `ImmutableArchiveReader::open_bounded`,
`SuccessorChainArtifactFiles::open_bounded` and bounded variants of the existing
full-history/height readers. The chain constructor must pass that SAME handle
into every root before its first staging validation. The bounded history
entries receive held roots, rather than calling the ordinary path reader after
an outer scan. `BusinessPinInputs`' bounded load path reads original genesis
through the scoped leaf below and calls the same verified-root factory.

The installed budget governs constructor-time `validate_staging`, `names`,
nested history inventory and every repeat walk during capture, verification
and attachment rechecks. Charge each root, directory and yielded entry before
UTF-8 conversion, collection insertion or descent; charge ignored valid staging
orphans too. Validate their names/type, but never read, copy, adopt or delete
their bytes. Account repeated walks again even when they see identical entries.
Exhaustion refuses before the next allocation/descent; a successful pre-scan
cannot authorize an unbounded reader later.

Bounded history/cut entries check claimed heights, page counts, descriptor/
component counts and component lengths before the corresponding loop, reserve,
vector growth or byte concatenation. Keep the existing exact codec and its
native per-file bounds. Any count-driven decode allocation also needs its
owning bounded entry before allocation, not a duplicated recovery decoder.
Generate and close the complete history/certificate inventory; surplus files
or unexpected nested directories refuse even if the ordinary reader would
ignore them. Cut inventory still uses the existing five fixed files, every
terminal stream/page and generated original chunk names. Core receives the
closed bounded bytes and performs the SAME proof verification, not a shortcut.

Add only an opt-in Unix attached-regular-file leaf in this existing SDK owner,
using safe `OpenOptions` with no-follow/nonblocking final opening and held
pre/open/post checks. Recovery capture, private staging, ciphertext and recovery
identity reads use it, with their OWN smaller byte/private-mode policies.
Its concrete held-file return exposes bounded reads and checked attachment/
metadata, not unchecked raw path reopening. Consumer-specific ownership/mode
checks run before the first byte read, not after parsing a secret.
Refuse nonregular or changed attachments before reads; retain held root and
regular-ancestor checks. Compare device/inode/type/uid/mode/link count/length/
mtime/ctime plus exact length and content digest across capture/reuse. This
declared regular-file attachment set excludes GID and atime; it is not every
Unix metadata field. Private recovery staging-root identity retains device/inode/
mode/uid, not immutable directory timestamps across child creation. Publication's
own link/unlink checks require the expected link counts and permit ctime changes
within the otherwise compared field set; they do not prove GID preservation.
These application rules are distinct from a reviewer's full UID/GID source-file
DATA stamp or a stronger independent test-fixture oracle. This is not
whole-path isolation or a wall-clock guarantee for a blocking regular
filesystem. Unsupported platforms refuse this local profile. Ordinary
`local_genesis` continues to follow genesis file symlinks; ordinary SDK
constructors and common Ed25519 seed format/error priority stay unchanged.
This leaf is not a generic file/provider facade or a seed-loader refactor.

## Quotas and resource accounting

All ceilings are local opt-in limits, not protocol/legal-history limits; only
downward configuration is allowed. Arithmetic is checked before allocation or
I/O. Each invocation carries the same counters across ALL roles and repeat work.

| Limit | Ceiling and accounting |
| --- | --- |
| Predecessors / roles | `L <= 16`; exactly `R = 3 + 4L <= 67` |
| Packaged files | `N <= 32,768`, separate from traversed entries |
| Traversal | 8,388,608 root/directory/entry observations, including ignored orphans and repeat walks; revised local profile in DR-0232, with both earlier ceilings retained as downward refusal controls |
| History / component work | 4,096 height materializations and 32,768 cut/history descriptor-component materializations, charged again on repetition before growth |
| Locator | At most 256 bytes for role + link + name-length + name; name is 1..251 bytes |
| File body | At most 32 MiB AND the smaller existing owner limit; summed original body bytes are checked too |
| Framing/control | `K = 68 + M + 17N <= 4 MiB`, including ALL non-body plaintext bytes |
| Plaintext | `P = K + B <= 256 MiB`, including header/manifest/file/footer framing |
| Ciphertext | At most 272 MiB, including age header, nonce and chunk overhead |
| age header input | At most 64 KiB actually consumed during construction, within the same cumulative ciphertext counter |
| Identity / copy buffer | At most 1 KiB identity input, cap-plus-one refusal; 64 KiB transfer buffer |
| Deadline / descriptors | Finite cooperative 300-second walk/transfer deadline; O(1) active file handles plus bounded held role roots |

`M` is manifest payload length and `B` the sum of original file body lengths;
their exact definitions are below. Separate raw-byte quotas do not replace
count/framing quotas. Core may still materialize bounded history, proofs and
reconstructed state: this is not constant total RAM, a 64 KiB heap ceiling or
preemptible verification. Check counters/deadline before and after opaque work;
a parent-approved real-child time/memory budget must own bounded test execution.
Do not introduce a daemon, supervisor framework or public fault hook.

Preflight at least 1 GiB free headroom on EACH affected filesystem before writes.
This is a check, not reservation, ENOSPC qualification or a shared-disk filler.
Pack holds at most one 256 MiB plaintext stage plus one 272 MiB ciphertext output;
open holds at most one 256 MiB private stage plus one 256 MiB final plaintext
inventory if a separate copy is required. Retained ciphertext inputs and failed
residue are not automatically reclaimed. Memory/swap/custody policy remains open.

## Local plaintext envelope v1

This is a LOCAL transport, not a protocol canonical frame. Allocate no
`CanonicalStruct`, protocol identifier or registry entry. All integers are
unsigned big-endian; there are no optional/reserved fields. The byte sequence is:

`magic[12] || version:u16 || Manifest || File[0] ... File[N-1] || Footer || EOF`.

Magic is exactly `b"SE-RECOVERY\0"` and version exactly 1. Every record is
`tag:u8 || payload_length:u32 || payload[payload_length]`, with closed tags
Manifest=1, File=2, Footer=3. Unknown version/tag, order, short/overlong record or
extra byte refuses. This local parser never changes embedded protocol bytes.

Manifest payload is exactly:
`L:u16 || R:u16 || N:u32 || B:u64 || role_descriptor[R] || file_entry[N]`.
Thus `M = 16 + 7R + sum(45 + name_length)`; decode EXACTLY `M` bytes.

A role descriptor is `role:u8 || link_index:u16 || file_count:u32`, seven bytes.
A file entry is `role:u8 || link_index:u16 || name_length:u16 || name ||
body_length:u64 || raw_sha256[32]`, 45 fixed bytes plus the UTF-8 name.
No caller path, root, URI, trusted pin, algorithm selector or secret is encoded.
Names are the exact generated safe names allowed by the existing role owner,
not arbitrary caller strings, escaping or normalized proof paths.

| Role tag | Role | Link index / cardinality |
| --- | --- | --- |
| 1 | Genesis | 65535; exactly one `genesis.bin` |
| 2 | CurrentHistory | 65535; one complete existing fixed-target history inventory |
| 3 | CurrentCut | 65535; one complete existing cut inventory |
| 4 | PredecessorPlanHistory | Each 0..`L-1`; complete fixed-target plan history |
| 5 | PredecessorCut | Each 0..`L-1`; complete saved cut |
| 6 | PredecessorManifestHistory | Each 0..`L-1`; complete history through accepted Seal |
| 7 | PredecessorCertificate | Each 0..`L-1`; exactly one `certificate.bin` |

Role descriptors sort by `(role, link_index)` and occur exactly once for each
required pair. All counts are positive, sum exactly to `N`, and agree with
entries; no other pair is legal. File entries sort strictly lexicographically
by `(role, link_index, name UTF-8 bytes)`. Non-link roles use `u16::MAX`; link
roles use ONLY 0..`L-1`. No duplicate/reordered name or role is accepted.

Safe names are original generated leaf names: cut fixed files and
`page-{collection:02}-{index:020}.bin` /
`chunk-{collection:02}-{component:020}-{offset:020}.bin`
from the existing SDK functions; history `identity.bin`, `chunk-size.bin`,
`complete`, `height-{height:020}/descriptor.bin` and
`height-{height:020}/component-{kind:02}/chunk-{offset:020}.bin`
from its existing closed kind/height/offset formatting. Numeric widths and
legal values are the defining owner's exact format, not permissive globbing.
No absolute path, empty/dot/dot-dot component, backslash, NUL, unknown prefix,
extra directory or foreign file is legal. Only required generated intermediate
directories are rebuilt. Permitted source staging orphans are excluded entirely.

File payload is exactly `manifest_index:u32 || body_length:u64 || raw_body`,
so `payload_length = 12 + body_length` and each full File record costs
`17 + body_length`. Indices MUST be 0,1,...,`N-1` in manifest order, body length
must equal that entry and bytes must match its raw SHA-256. A zero-length body
is allowed only if the defining owner permits it. Never reencode a body.

Footer payload is exactly `N:u32 || B:u64 || manifest_sha256[32]`, 44 bytes;
its full record is 49 bytes. The hash covers the EXACT full Manifest record
`tag || payload_length || payload`, not a reserialized structure. Check all
counts, body sums and this hash against observations, then require plaintext
EOF. There is exactly one Manifest and Footer, no trailing plaintext/record.
Therefore total framing is `14 + (5 + M) + 17N + 49 = 68 + M + 17N`.
Use a maintained SHA-256 implementation for local byte integrity only.
Footer/completion/hash never constructs or serializes a verified core capability.

Output role roots are generated, not supplied by records:
`genesis/`, `current/history/`, `current/cut/`, and
`predecessors/link-00000/{plan-history,cut,manifest-history,certificate}/`
with fixed five-digit indices. Only the selected role owner generates children.
Each stored file is raw original bytes, not a pathname-dependent identifier.

## age candidate and exact EOF contract

Candidate: maintained [age 0.12.1](https://docs.rs/age/0.12.1/age/), using the
[rage v0.12.1 release](https://github.com/str4d/rage/tree/v0.12.1),
commit `7a854c9c8c02dab2ebea19e02e6693a5730a8b2a`, and the maintained
[age v1 format](https://age-encryption.org/v1).
It explicitly remains pre-1.0 beta; this local test proposal does not approve
real backup custody. These are versioned primary-source observations from the
2026-10-07 design review, not a claim about a resolved graph or latest release.

Propose `age = { version = "=0.12.1", default-features = false }`, synchronous binary
X25519 only: one typed recipient supplied locally on pack and one typed recovery
identity supplied separately on open. No passphrase/scrypt/SSH/plugin/armor/
async/keyring path, handwritten encryption or plaintext fallback. Writer choice
and the opener's expected public recipient remain independent local inputs;
derive `identity.to_public()` with the maintained library and require that pin
before decryption, not a ciphertext-selected recovery account. Writer choice
does not prove ciphertext has an exclusive recipient roster or authenticates
a sender; accept legitimate library-produced GREASE without a second age parser.
Disabled features do NOT remove unconditional scrypt/P256/HPKE/ML-KEM dependency
costs from the manifest. No resolver or library was run for this proposal.

Construct `Decryptor` over `R = &mut invocation_owned_quota_reader`, which
directly wraps ONE held unbuffered ciphertext file. The caller owns phase
control: enforce 64 KiB cumulative consumed input during header construction;
after successful construction ONLY, switch to the 272 MiB total phase without
resetting cursor or counters. HEADER phase exhaustion, including a nonempty
read at its exact cap, remains an ordinary fixed opaque quota refusal with no
EOF probe. Neither phase may use `Take`'s synthetic quota EOF. The header
parser's internal allocation can precede a quota read: consumed-byte caps are
not exact header allocation/CPU caps.

In TOTAL phase, each nonempty underlying decoder read at the exact cumulative
ciphertext cap MUST perform a real one-byte probe on the SAME held unbuffered
file/cursor. Return zero ONLY if that actual underlying read returns zero;
this lets age observe physical EOF when authenticating a short final chunk
or after a full 64 KiB final chunk. If one byte is read, count it with checked
arithmetic as cap-plus-one and immediately return a fixed opaque refusal;
never deliver that byte or qualify plaintext. An underlying I/O error also
refuses opaquely. At most cap-plus-one bytes may be observed; no further read
or retry follows refusal. An empty read buffer is never EOF evidence. This
real probe is permitted BEFORE authenticated plaintext EOF, not conditioned
on reaching it; physical zero alone does not establish final authentication.

Consume Manifest/File/Footer with checked plaintext quotas into exclusive
0700/0600 incomplete staging, then request plaintext EOF with a one-byte,
NONEMPTY buffer. Any returned byte is counted and refuses, including at the
exact plaintext cap; an outer limiter must not synthesize completion.
Require successful final authenticated chunk, including the exact 64 KiB chunk
boundary. Drop the borrowed stream reader to regain the SAME quota reader and
held file, then explicitly request true physical ciphertext EOF again with a
nonempty one-byte read under the SAME phase/counter rule. Require actual zero
and matching observed counts; do not substitute a cached decoder EOF. Recheck
the same before/after held attachment/stamps. No reset, clone, reopen, seek or
buffer bypass is allowed. No cap probe or buffered final chunk can qualify
plaintext before authentication, complete inventory and independent proofs.
Cached final-chunk exhaustion is not sufficient by itself. Truncation, damaged
header/chunk/footer, appended or concatenated ciphertext, short reads, read
errors or any trailing plaintext refuse before proof qualification or SQL.

Writer `finish()`, output sync, exact output byte checks and parent-directory
sync are mandatory; a successfully flushed nonfinal chunk is not completion.

## Identity secrecy, capture and publication

Read exactly one bounded UTF-8 X25519 secret line from a caller-held private
regular identity file: effective uid owner, mode 0400 or 0600, single link,
no-follow/nonblocking open, stable stamps and no comments/lists/extra lines.
Allow only one optional terminal ASCII LF, not trimming, comments, extra lines
or local re-casing; the maintained typed parser decides the identity grammar.
Do not reuse the common Ed25519 seed parser. Hold input bytes and any owned UTF-8
storage in maintained `zeroize` buffers on every success/error path; prefer one
`Zeroizing<Vec<u8>>` with a borrowed UTF-8 slice rather than a secret String clone.
Parse by borrowing, avoid identity-line clones and never serialize or debug
the secret. Zeroization is best-effort buffer hygiene, not swap exclusion,
complete erasure or custody.

The local error type exposes fixed opaque categories through Display, Debug AND
every `Error::source` element. It retains no identity line/buffer/secret bytes
or raw age/IO/provider error that could embed them. Source is absent or another
fixed opaque category. Executable stdout/stderr report public counts/identities
only. Mapping provider errors must not format them first or retain their source.
Malformed/wrong identity and secret-like IO-error controls assert absence through
ALL output/format/source-chain channels.

Pack captures every required role into ONE exclusive private stage with the
bounded readers, preserving raw bytes and full inventory. Verify THAT stage
against external pins using the existing core factories, then encrypt those
SAME staged bytes while rechecking hashes/stamps. Source mutation or any missing,
foreign, surplus or unstable attachment refuses; no verify-source/encrypt-new-
read gap. Both private capture root and ciphertext output must be absent and
outside every held input role, with placement checked before creation; neither
may alias/contain an input or the other output. Apply the same absent/private
placement checks to open's output and its ciphertext/identity inputs.

Open stages only incomplete private plaintext until full age authentication,
exact inventory/physical EOF and independent genesis/chain/cut verification
have ALL succeeded. Compare the external current cut/package pins before a
completion diagnostic. No public promotion or SQL/import factory is called
earlier. Successful private output has generated role paths and a last-written,
synced `recovery-complete-v1.bin` outside all role inventories, containing the
EXACT 49-byte validated Footer record. No other root-level file is part of
qualified output; only generated role directories and this diagnostic occur.
That diagnostic is not proof authority; the importer independently verifies
again. Packing's private captured stage may use the same last-written
diagnostic only after independent verification; it is never a packaged role.

Pack's private concrete terminal gate reduces the actual maintained-age finish
result to a borrow-free length/hash before moving publication. It keeps the
existing finish-result refusal, staged recheck, ordinary publication, real stage
completion and original shared-budget check order. Only then does it return
public link/file counts to the unchanged print site. Those counts carry no proof,
import or custody capability; the caller's defining business verification remains
before encryption. Finish or publication refusal cannot return printable counts.
This source composition alone is not full-CLI stdout/stderr or an exact count of
completion-function entries, and it does not make later-failure residue qualified.

PrivateStage's shared `new_file` owner checks the original shared budget before
parent preparation or private file creation, returning opaque Quota for refused
or expired admission. Capture/receive/completion retain their preceding
validations; this is the first ordinary action inside `new_file`, not a guard on
every caller's earlier IO/allocation or on all filesystem owners. Refusal-first
error precedence is deliberate. Admission is cooperative, not atomic with later
deadline/clone refusal or IO, and does not roll back later unqualified residue.

Reuse the existing create-new, held-file sync, hard-link/no-clobber and directory
sync publication mechanism only, not its equal-existing-byte `Ok(false)`
resumption meaning. ANY preexisting destination, even byte-identical, refuses.
Same-filesystem hard-link/sync failure fails without overwrite; do not claim an
atomic directory transaction. Track only invocation-owned incomplete/output
attachments. Failures retain unqualified residue for explicit inspection, not
adoption, automatic retry, scavenging, broad cleanup or secure-erase claims.

Baseline lock has transitive `zeroize 1.9.0` but no direct workspace/operator
edge; age/age-core/secrecy are absent. Future direct zeroize, age, local hash and
Unix flag dependencies need exact manifest/lock review. Registry checksums,
downloaded package provenance, resolved features/graph, MSRV, licenses,
advisories and measured build/runtime/resource cost remain unverified gates.
Do not resolve by upgrading protocol crypto. Rustls and tooling advisories
remain separate open release criteria.

## Proportional acceptance and documentation

- Pure independent literal layout vectors cover L=0 and L>0, exact lengths and
  overhead boundaries, all roles, ordering/count/index/hash errors, unknown tags/
  version, unsafe names, surplus entries and trailing bytes. No duplicate proof
  verifier or implementation-derived encryption oracle.
- Real synchronous age controls MUST later accept valid ciphertext with TOTAL
  cap exactly its actual length for BOTH a short final chunk and a full 64 KiB
  final chunk. Require successful final authentication, nonempty plaintext EOF
  and a subsequent real same-file physical zero, with cumulative observations
  exactly at the cap. Empty-buffer reads or a quota-created zero cannot satisfy
  these positives. These controls are proposed, NOT executed evidence.
- For each exact-cap positive, append one byte: observe cap-plus-one at the
  real decoder probe and immediate opaque refusal, with no qualified completion
  or SQL. Retain HEADER exact-cap refusal, lower TOTAL caps, truncated final
  chunks, concatenated ciphertext and underlying I/O error at the probe.
  Also retain small/exact-64-KiB/multichunk plaintext, correct/wrong identity,
  malformed/secret-like IO errors, unsupported input, tampering, plaintext-cap
  and stable-attachment refusals. Finish/authentication/EOF are independently
  observed; no fallback, counter reset or buffered bypass is permitted.
- File-only controls retain byte-identical preexisting-output and overlap
  refusal, no-clobber and ordinary-success cases. Private writer sinks
  distinguish repeated short writes through maintained age `finish()` and
  round-trip from nonempty write-zero refusal, partial-progress-then-error and
  failure during final age emission. Independently assert exact accepted
  prefix/count/hash and opaque permanent refusal; legitimate empty writes are
  not nonempty write-zero or EOF evidence. A private invocation-local selector
  may refuse before pending creation, create-parent sync, pending-file sync,
  final hard-link, linked-parent sync, pending unlink or final-parent sync.
  Production publication always follows the no-fault path. Inspect residue
  independently against the original held pending inode, declared attachment
  fields and bytes:
  absent leaves before creation, empty pending-only after create-parent
  refusal, complete pending-only before link, both owned hardlinks after
  link/before unlink, and final-only after unlink. An unrelated sentinel must
  preserve its exact bytes and compared metadata fields through every refusal
  and success; do not expand this to an all-field Unix metadata claim.
  Constructor-time refusal checks real empty/private residue without inventing
  a pre-creation inode. Test-fixture cleanup checks retained root identity
  before deletion but is not atomic hostile-race deletion or production rollback.
  These pre-syscall refusals do not qualify actual failed file/parent sync,
  power loss, process crash, hostile mutation, ENOSPC or durability; real
  selected-profile faults remain separate requirements. Pack must still
  propagate finish/publication failure before completion diagnostics/output.
  Three added Linux source declarations compose the actual terminal gate with a
  file-backed final-age emission refusal, a natural late equal-byte foreign inode
  collision and ordinary success. Independent literal L0 framing/real body hashes/
  Footer/bytes, private fixture stamps including GID, retained staged payloads and
  sentinel, no count result or marker in those two refusal cases, and produced-file
  decryption with authenticated plaintext EOF then later same-cursor physical EOF
  are their proposed oracles. A Linux test-only same-instance counter adds
  expected real completion-function entry counts of 0/0/1 for these controls,
  separate from returned public counts or marker bytes. One further direct
  completion control first irreversibly refuses that same original budget and
  expects entry 1, opaque Quota and metadata-only NotFound for the diagnostic.
  Its post-refusal observer reads ONLY the original preheld payload/sentinel
  descriptors: saved length is bounded before allocation, positive positional
  reads have finite attempts/checked offsets, full original held/named file
  stamps bracket every read, and a nonempty saved-offset probe requires real EOF.
  The already-held outer fixture directory identity is separate from the capture
  root; no post-refusal reopen, replacement budget or live-budget helper is used.
  All assertions remain SOURCE expectations, NOT compiled or executed entry-count,
  full-CLI, real syscall fault, business proof, SQL restore or custody evidence.
  Original named controls remain, and
  genuine source-free restore is checked separately. Wrong public recipient
  and scrypt/SSH/plugin-only inputs refuse without prompting or plaintext
  fallback; legitimate library GREASE stays accepted.
- Bounded SDK tests exhaust constructor staging, names before insertion, nested
  surplus history, huge declared heights/components before growth, repeat-walk
  accounting and aggregate cross-role quotas. Ignored orphan bytes stay unread/
  unchanged. Real regular/symlink/FIFO substitution cases use a bounded child
  with kill AND reap; no host privilege, production hook or unbounded
  `Command::output`. Ordinary genesis-symlink and Ed25519/SDK compatibility
  controls remain.
- Extend the existing compiled original import fixture, not another producer:
  pack its genuinely signed/drained cut, retain only ciphertext plus disposable
  recovery identity at a different local root, close ALL source owners, hide
  ALL SQL/genesis/history/cut input paths, and keep them unavailable through
  open, real create/resume and repeated `new_batches=0`. Independently retained
  public pins remain; compare every role's original bytes/inventory and exact
  history/receipt/referenced bodies. Ordinary open still refuses inactive output.
- Extend the existing unconditional recurring-sqlite owner's genuine later cut:
  save every `Link` role plus current history/cut, hide all original artifacts/
  SQL, relocate ciphertext and restore inactive from the FULL original-root
  chain. Preserve the real signed seven-epoch withdrawal/unlock, changed
  committees, activated successor and signerless historical controls; do not
  shorten economics, simulate epochs or add another expensive runner.
  The original e0->e1 link plus seven genuine later handoffs gives eight
  predecessors at e8: all `3 + 4*8 = 35` original/current/predecessor roles.
- Retain corruption, wrong binding/pins, placement, prefix/fence/source-token,
  ambiguous progress, missing blobs, genuine second-file WAL creation failure
  and inactive admission/signing/ordinary-serving refusals. No encrypted format
  test replaces these or the full required owners.
- The implementation is source-present, not qualified. Exact dependency/source
  review, bounded owning execution and strict Clippy, literal npm-ci/full
  required acceptance, all 35 original/current/predecessor roles, twelve fresh
  Native A/B targets and final-head hosted CI/review remain gates. The optional PG
  implementation is unchanged, but the encryption dependency expands shared
  `futures-util` feature edges used by PG; the documented full-PG dependency
  acceptance hold is unwaived. No live PG, cloud/off-host resources or real
  recovery key are authorized.

The existing [cut guide](../guides/business-cut.md) and
[import guide](../guides/business-import.md) describe the existing inactive
rehearsal and the source-present encrypted-recovery candidate. Add runnable
encrypted-recovery instructions only after implementation review and real
source-free tests. Current evidence/status lives exclusively in
[TODO](../../TODO.md), not README or a competing recovery runbook.
