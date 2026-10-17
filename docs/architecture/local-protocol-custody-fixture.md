# Selected original ordered multi-UID fixture

Date: 2026-10-17, Asia/Singapore.

This is the selected component acceptance profile for
[ADR0264](decisions/0264-original-ordered-protocol-custody-worker.md). It adds an
ignored operator integration-test harness and a separate Docker controller.
Build/run qualification and all remaining M2 gates belong in TODO; source and
syntax checks do not establish runtime acceptance.

The controller starts actual `sqlite_source_host protocol-worker` and
`protocol-frontend` roles with separate Linux UIDs. The worker retains the real
original router, validator key, source/body, independent local anchor, lease and
writer fence. The frontend owns direct TLS delivery. An intruder UID can traverse
the selected socket group but cannot read key/config/source/body/anchor paths.
No host users, groups, services, keys or public endpoints change.

The complete owning command is:

```bash
node scripts/check-docker-ordered-custody-fixture-1017.mjs \
  --source-root /absolute/clean/checkout \
  --source-head <exact-40-hex-head> \
  --build-receipt /absolute/private/build-receipt.json \
  --build-receipt-sha256 <exact-64-hex-sha256> \
  --author-binary /absolute/standard_asset_genesis \
  --inspect-binary /absolute/genesis_inspect \
  --genesis-binary /absolute/sqlite_genesis \
  --host-binary /absolute/sqlite_source_host \
  --test-binary /absolute/deps/protocol_custody_fixture-<exact-hash>
```

Before runtime approval, run the same command with leading `--inventory-only`.
That mode verifies committed source, actual build receipt, the five ELFs and
merged library closure, and prints their exact input metadata without making
ANY Docker calls or creating resources. Its result is explicitly
`mode: "inventory-only", execution: false`; it is not runtime acceptance.
The parent reviews that actual inventory before the separate execution call.

Select existing nvm Node24.19.0. No default, executable discovery, build, package
installation or download happens in this controller. Every compiled input must
already be a resolved regular0755 ELF owned by the controller's current effective
UID with exactly one link; record/recheck its link count and never normalize its
permissions or ownership to pass.
The harness is a Cargo test target, not a fourteenth release executable.

| Input role | Package/target | Recorded profile |
| --- | --- | --- |
| author | sunrise-edge-operator / standard_asset_genesis | actual dev or release |
| inspect | sunrise-edge-operator / genesis_inspect | actual dev or release |
| genesis | sunrise-edge-operator / sqlite_genesis | actual dev or release |
| host | sunrise-edge-operator / sqlite_source_host | actual dev or release |
| harness | sunrise-edge-operator / protocol_custody_fixture | test |

Use an actual compiled build receipt with schema1, exact `sourceHead`,
`sourceTree`, `nodeVersion: "24.19.0"`, `sourceFiles`, `commands` and `inputs`.
`sourceFiles` is the relative-path-to-SHA256 map for the controller's explicit
source inventory. Each command records its actual `argv`, `exit: 0`,
`stdoutEof: true`, `stderrEof: true`, absolute `logPath` and `logSha256`.
Each of the five input roles records absolute `path`, `sha256`, `length`,
`mode: 493`, actual `uid`, `nlink: 1`, `package`, `target`, actual `profile` and
`commandIndex` linking it
to that complete build command. The caller independently qualifies those raw
compiler logs; a declared receipt is not a cryptographic build attestation.

After source approval and build-slot allocation, the corresponding build inputs
can be obtained with explicit Cargo commands such as:

```bash
cargo build -p sunrise-edge-operator --all-features \
  --bin standard_asset_genesis --bin genesis_inspect \
  --bin sqlite_genesis --bin sqlite_source_host
cargo test -p sunrise-edge-operator --test protocol_custody_fixture \
  --all-features --no-run
```

These are examples of producing dev/test inputs, not execution results. The
parent owns actual command/profile/log qualification and may separately build
release artifacts. Match every supplied ELF to that actual receipt.

The controller pins the existing local Python image
`python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea`
and refuses a missing image; `--pull=never`, network none, read-only rootfs and
no-new-privileges remain explicit. Only the disposable root controller receives
CHOWN/DAC_OVERRIDE/SETUID/SETGID; every actual role checks effective UID/group and
CapEff0 before execution. The child roles use worker12001, frontend12002 and
intruder12003. Frontend/intruder supplementary12001 permits socket traversal,
while0700 private custody leaves and0600 files keep authority files unreadable.

One UUID-owned64MiB noswap tmpfs volume has16384 inodes, mode0755 and
nosuid/nodev/noexec. Source/body and independent anchor are separate sibling
private trees; this does not claim independent physical failure devices.
The tmpfs root and routing directories `source`, `authority`, `worker`, `run`
and `front` are root-owned0755, permitting the native checked-file APIs to open
every ancestor read-only. Other UIDs cannot write these routing directories.
Validator `vN` leaves, `worker/setup`, `oracle` and `artifacts` stay0700 under
their assigned UIDs; `run/vN` and `run/competing` remain0750. Private payloads
remain0600, and the existing actual filesystem-refusal controls still apply.
Inspect actual cgroup512MiB/swap0/1CPU/pids64 and actual tmpfs protections before
any role launches. Readonly-bind exactly the five ELFs and their bounded merged
`ldd` closure under `/mnt/bin` and `/mnt/libs`; use the explicit loader without
replacing image Python libraries. Record and recheck source/ELF/library hashes,
lengths, UID/GID, mode, link count and device/inode/time metadata on success and
failure.
Readonly ELF input bounds are512MiB each/2GiB aggregate, with at most64 libraries
and256MiB total library bytes. Generated tmpfs data remains bounded by64MiB.

Outer280s, inner230s and positive-work175s share fixed deadlines, leaving55s for
tail/error cleanup. Individual commands, streams, EOF drains and waits use the
remaining shared allowance. Each product invocation has total200s, timeout2s,
concurrency2, requests128 and worker connections160. A read-only oracle has210s
absolute life and at most64 closed phase commands; its idle-read cap30s allows
bounded operation phases, while each control send/reply shares ONE absolute2s
phase deadline, rechecked before every receive and at completion. Cached startup
lines also require observation before their original deadline. It retains
only owned row images and closes every SQLite connection/transaction before
acknowledging a phase. It checks no source/anchor FD remains between commands.

The actual sequence uses existing fixture author material and real compiled
inspect/prepare/preflight/anchor-inspect/enroll/checkpoint commands. It then:

1. Starts four actual workers at fence2 and four direct-TLS frontends, checking
   only the authorized source fence1->2 change and actual TLS leaf/root/name.
2. Produces one actual leader proposal and repeats it before broadcast; obtains
   and independently verifies all four actual original votes, then repeats the
   saved proposal with exact retained response bytes and complete row equality.
3. Refuses intruder UID before any length/body, an impostor worker UID before
   frontend request bytes/readiness, missing-anchor startup, a competing worker
   on a different socket with the same live lease, invalid signatures and closed
   routes. An authenticated frontend-UID child stalls after one outer-length
   byte; each actual worker closes at its finite2s request deadline before key
   or storage dispatch. Complete source/body/anchor rows remain unchanged for
   these refusals.
4. Stops/reaps all four signing workers with frontends alive, requires unavailable
   responses without fallback, checkpoints released leases, restarts at exact
   fence3 and replays saved proposal/votes before applying their saved QC.
5. Applies QC1, drives one real fresh empty round through the existing SDK, and
   signerlessly replays the fully applied two-round prefix. Full12+2 source/body
   and2 anchor row images prove the appropriate quiescent equalities. Genuine
   progress and fence claims have their own expected changes.
6. Stops/reaps every role with actual exit0, wait, both pipe EOFs and exact drain
   summary, then verifies exact owned container and volume removal.

The oracle independently decodes retained leader/vote/watermark records with
existing canonical decoders and policy engine verification, bound to actual
saved wire bytes. It does not manufacture protocol keys, state or authority.
Private artifact destinations use create-new and strict count/length/total
bounds; only selected public canonical wire bytes are copied for the separate
worker-UID oracle. Keys/configs are never copied into that public artifact tree.

The Docker owner uses one `start --attach` operation so capture is established
before container execution, including early failures with logging disabled.
This supported start command uses its default signal proxy; the owner forwards
no signals and timeout abort uses uncatchable SIGKILL on the Docker client only.
Exact owned-container cleanup remains a separate qualified operation.

Every Docker client has a bounded receipt containing operation, PID, actual
exit/signal/wait and close, per-stream physical EOF, bytes and SHA256, and capture
completeness. At most96 such records reserve512 bytes EACH inside the existing
64KiB host capture budget, including its16KiB cleanup reserve. No argv,
`Config.Env` or credential values enter these records. Missing wait/EOF fails.

Creation attempts become ambiguous BEFORE either create call. Only an actual
successful response plus qualified identity/profile inspection clears the
corresponding flag. A timeout or unqualified response remains ambiguous even
if an early exact-name lookup is empty; cleanup cannot claim removed/complete
from that observation. Every receipt includes endpoint, owner label/UUID,
container name/observed ID, volume name/observed attachment, attempted/ambiguous
flags and manual-reconciliation status. Preserve the failed attempt, reconcile
those exact names later and never automatically retry an uncertain create.

All child output is captured under a cumulative256KiB inner limit and64KiB per
stream. The complete existing JSON, including retained child stdout/stderr,
actual exit/wait and EOF metadata, crosses as one `zlib-base64-json-v1` envelope.
Decoded JSON has a separate512KiB allocation bound inside the unchanged512MiB
controller memory limit. Serialization above that bound fails; the256KiB raw
capture ceiling is not a promise that every possible escaping/metadata expansion
can be transported. No child output or control is shortened to make it fit.
The Node24 decoder requires canonical base64, complete zlib EOF, exact consumed
compressed length, no trailing or concatenated stream, exact decoded length and
SHA256, lossless UTF8 and valid JSON. It retains the exact compressed wire and
the complete decoded result in the outer evidence, permitting independent
decoding and rehashing. The existing4MiB outer capture bound also remains fixed.

The host Docker owner still retains64KiB wire output plus reserved client
metadata, with16KiB cleanup reserve inside that SAME bound. Compression does
not guarantee that arbitrary bounded output fits the remaining wire allowance;
incompressible or oversized evidence fails. The Python envelope itself refuses
wire output above64KiB before writing. A cap breach
or unresolved drain/wait fails, preserving the captured prefix and incomplete
status. Cleanup never converts an earlier failure into success. Root lacks
CAP_KILL: same-UID helpers signal still-owned unreaped positive PIDs; SIGKILL is
failure cleanup only. No process-name search or host service termination occurs.

All four actual votes and four peer phase outcomes are required. The unchanged
`certificate_from_votes` engine selects the canonical minimal quorum of three
for this equal-power four-validator fixture. Its QC membership count is three;
it does not discard or reclassify the fourth actual successful response.

Retained output equality does not prove zero hidden key calls: original propose
can call its signer before retained-identity reconciliation. QC membership and
four actual peer responses are separate from three-chain business finality.
This empty-round fixture does not claim business finality, all-M2 completion,
uncertain-SQL-commit injection, encryption, root/worker-compromise resistance or
off-host restore. Preserve the original DR0215 controls, all14 TLS selectors,
old custody fixture and13 executable release inventory unchanged; targeted,
full required and exact hosted gates remain separate mandatory evidence.
