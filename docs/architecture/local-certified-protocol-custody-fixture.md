# Selected certified FastVote multi-UID fixture

Date: 2026-10-17, Asia/Singapore.

[DR-0271](decisions/0271-certified-fastvote-multiuid-fixture.md) selects a
component fixture for the complete current [certified custody
profile](certified-fastvote-protocol-custody.md). Execution and completion
status belong in TODO. Source review, compilation and a passing component are
separate evidence; this document specifies the fixture rather than a result.

The fixture adds a separate ignored operator test target and owning Node/Python
controllers. Original ordered fixture files, its selector and protocol IPCv2
remain unchanged. The new harness is not an additional release executable.
No host user, service, key or public endpoint changes.

## Actual owners and sequence

Four actual equal-power validators each have an authority-owning worker and a
keyless direct-TLS frontend. The existing offline Standard Asset author,
inspector and genesis CLI produce and validate the signed CausalAdmission root.
The four real stores have protocol7, epoch0, minimum Freeze height1, explicit
created checkpoint10 and independently enrolled local anchors. An SDK user owns
the existing disposable paid coins. No test writes protocol state, creates a
synthetic committed Freeze, substitutes quorum authority or seeds a frontier.

1. Prepare four stores at fence1 and enroll/checkpoint their independent
   anchors. Start certified workers at fence2 and their keyless frontends.
   Check filesystem refusal for frontend/intruder UIDs, peer UID before any
   request prefix, authenticated stalled-body deadline, impostor worker refusal,
   missing anchor/checkpoint, competing writer, wrong IPC profile and wrong TLS
   CA/name. Full source/body/anchor images remain equal across refusal phases.
2. Prepare A on all four workers. Verify all four actual endpoint-bound votes,
   the real minimal three-vote certificate, prepared records and owned locks.
   A separate retention phase sources a complete real bundle and obtains four
   endpoint-bound ACKs and a three-ACK availability certificate. At both stages,
   public queries prove the original user receipt is absent, its nonce is0 and
   application/fee objects have their exact original bytes. Prepare's legitimate
   internal receipt is not confused with the original application receipt.
3. Repeat the exact A prepare/retention requests; compare saved bytes and full
   images. Refuse malformed/conflicting paid inputs and closed paths. A closed
   worker-UID test peer, without a key or store handle, returns only selected
   saved real context/vote/ACK bytes or fixed malformed/profile/identity variants;
   the actual TLS frontend must refuse a foreign endpoint vote, foreign ACK,
   wrong profile, malformed output and wrong identity with503. This peer earns
   no signing, quorum or retention credit.
4. Stop and reap workers, require socket absence, checkpoint released leases and
   obtain503 with no fallback while frontend liveness stays204. Restart at
   fence3 and repeat saved A votes/ACKs. Apply A and fresh B using genuine paid
   and availability quorums; independently decode effects, fees, object IDs,
   versions/types/amounts, exact receipts and nonce progression. A and B use
   separate application and fee references. Prepare C on all four workers and
   retain its complete bundle only on worker0, leaving C unapplied and nonce2.
5. Stop/reap both roles and checkpoint them. Start the original ordered owners
   at fence4 on the same stores. The existing SDK commits Freeze through all
   four replicas and its real three-chain rounds, with outcome at height1.
   Stop/reap both roles and checkpoint them before starting certified owners
   at fence5. Obtain actual final frontier signatures, verify their full page
   streams with `FrozenFrontierPageVerifier` and compare saved replays. Worker0
   has A/B/C; the other frontiers have A/B.
6. On worker1 stage worker0's real frontier. Pre-Freeze `publication/` records
   and ACKs do not supply post-Freeze drain possession. Source and import the
   genuine full A and B bundles before their confirmations. C confirmation first
   refuses with `drain-proof-not-retained`; source and import its actual retained
   bundle, then confirm it. These operations populate the distinct
   `drain-publication/`, `drain-publication-artifact/` and `drain-possession/`
   records through their existing owners. Drive the existing SDK to local
   three-member union readiness. The oracle compares exact stored signer
   progress, confirmed entries, union progress/ready identity, selection digest
   and saved signed
   votes. C remains unapplied: a real member apply without a committed DrainSet
   returns409 `drain-member-not-ready`. There is no positive DrainSet or member
   application extension.
7. Stop/reap workers, checkpoint released leases, verify downtime, restart at
   fence6 and replay saved frontier/progress/union and historical A receipt
   results. The final nonce stays2 and C's original receipt stays absent.
   Stop/reap all roles, require exact drain summaries, checkpoint and compare
   full final row images before exact owned container/volume removal.

The real SDK and original router owners authenticate signatures, quorums,
execution, retained witness closure, Freeze and drain transitions. The separate
read-only worker-UID oracle decodes their persisted canonical records and
compares actual saved wire bytes; it never signs or mutates state. Each read
connection closes before acknowledgement. Full images cover all12 source
schema tables, both body tables and both anchor tables. Quiescent controls use
whole-image equality; intentional progress and exact writer-fence claims have
separate expected changes. SQL values are admitted before copying under the
existing1024-row,512KiB-cell and16MiB-image allocations.

## Route coverage

| Existing contract | Actual owning exercise |
| --- | --- |
| prepare, source, retain, published apply | A/B/C real votes, complete bundles, ACKs and A/B paid effects |
| historical certificates | fresh causal request refused without publication authority |
| retained source | actual C bundle fetched after Freeze for missing-proof import |
| frontier advance/page | all four final signatures, complete verified page chains, exact replay |
| signer page/member confirm/import | real staged C frontier, missing-proof refusal, exact import and confirmation |
| signer progress/union advance | existing resumable SDK, actual stored progress and three-member local readiness |
| drain apply | genuine pre-DrainSet409, C receipt absent and nonce2 |
| context/object/receipt/nonce/fee policy/publication/instance | verified genesis pins, genuine paid objects and saved receipts |
| liveness | local204 during worker downtime, including ignored nonempty GET body |

These are all21 certified contract entries plus liveness. Unsigned query and
progress transport checks do not become independent inclusion, freshness or
whole-state proofs. Local readiness is not a committed DrainSet. The fixture
makes no zero-hidden-key-call, uncertain-SQL-commit injection, compromised-root
or worker, independent-device, restore, public-service or all-M2 claim.

## Exact inputs and bounds

Use existing Node24.19.0 with the following explicit invocation. Prepend
`--inventory-only` for the separate zero-Docker input qualification.

```bash
node scripts/check-docker-certified-custody-fixture-1017.mjs \
  --source-root /absolute/clean/checkout --source-head <exact-head> \
  --build-receipt /absolute/private/actual-build-receipt.json \
  --build-receipt-sha256 <actual-sha256> \
  --author-binary /absolute/standard_asset_genesis \
  --inspect-binary /absolute/genesis_inspect \
  --genesis-binary /absolute/sqlite_genesis \
  --host-binary /absolute/sqlite_source_host \
  --test-binary /absolute/deps/certified_protocol_custody_fixture-<actual-hash>
```

All five inputs belong to `sunrise-edge-operator`; the four binaries record
actual dev/release profiles and the new target records its actual test profile.
Use the same schema1 build-receipt fields and independent complete CargoJSON/log
qualification specified by the [original fixture](local-protocol-custody-fixture.md).
Only the new exact source inventory and harness target differ. Inputs must be
normal0755/current-EUID/single-link regular ELF files with exact source/profile
provenance, retained by `cp -a --reflink=always` at separate inodes. Never chmod
an input to pass. No build, discovery fallback, download or installation occurs
in the runtime controller.

The existing pinned Python image and Docker profile are unchanged: network
none, no pull, read-only rootfs, no-new-privileges,512MiB memory/swap0,CPU1 and
pids64. Root has only CHOWN/DAC_OVERRIDE/SETUID/SETGID; actual worker12001,
frontend12002 and intruder12003 children check UID/GID/groups and CapEff0.
Supplementary group12001 permits socket traversal while0700 leaves and0600
files refuse key/source/body/anchor/config access. Root-owned routing ancestors
are0755 for checked read-only native path traversal. A single private UUID-owned
64MiB noswap/nosuid/nodev/noexec tmpfs has16384 inodes. Source/body and anchor are
separate sibling trees, not distinct physical devices.

Retain outer280s, inner230s, work175s/tail55s, role lifetime200s, operation2s,
concurrency2, requests128 and worker connections160. The successful closed
sequence has147 children,27 selected probe phases and32 oracle exchanges.
Actual runtime enforces at most160 children,32 probe records,64 oracle exchanges,
96 requests per endpoint per probe and112 accounted requests per generation,
leaving16 below the configured128. Readiness consumes one worker/frontend
request; stalled and wrong-profile IPC requests are separately counted.
Explicit A/B drain imports add four HTTP calls in the existing probe: two
bundle-source calls on worker0 and two import calls on worker1. They add no
child, probe or oracle exchange and retain every existing request/deadline cap.
The original bounded child capture, actual waits, physical stdout/stderr EOF,
same-UID signals, exact socket removal and failure cleanup remain mandatory.

Readonly ELF caps remain512MiB each/2GiB total; merged libraries stay at most64
entries/256MiB. Inner complete child raw capture remains256KiB cumulative and64KiB
per stream. Complete decoded JSON stays at most512KiB; lossless zlib/base64 wire
plus Docker-client metadata retains the same64KiB allocation and16KiB cleanup
reserve. Outer complete evidence stays4MiB. All raw child stdout/stderr and exact
compressed wire remain available for independent rehashing; no digest-only
replacement, truncation or cap increase is permitted. Oversize evidence fails.

The unchanged Docker ownership/capture machinery starts once with `start
--attach`, pins exact UUID/name/volume/ID, records actual client wait/EOF and
keeps ambiguous creates unresolved. Failure never becomes success through
cleanup. Final source/ELF/library identity rechecks and exact targeted resource
absence remain required. Component qualification is separate from the final
required/hosted/release gates and any remaining M2 criteria.
