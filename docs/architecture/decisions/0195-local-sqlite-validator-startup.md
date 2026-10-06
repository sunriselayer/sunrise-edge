# DR-0195: Explicit local SQLite validator preparation and preflight

Date: 2026-10-06 (Asia/Singapore)

Status: Accepted design. Fresh independent Claude Opus returned DESIGN APPROVE
on 2026-10-06 after the explicit boundaries below were closed. This is not
implementation, PR or security-audit approval. Current implementation and
release status belong only in [TODO.md](../../../TODO.md).

## Context

DR-0192 ships an original SQLite serving host which correctly refuses to
bootstrap, repair or reset its input namespace. The original-root preparation
sequence currently exists in genuine tests, not in a shipped SQLite operator
command. Its startup checks are also coupled to writer-fence acquisition, so an
operator cannot inspect configuration without taking over a writer generation.

Delivery 3 supplies genuine recurring membership, recovery and withdrawal
behavior. The next startup work must consume those existing engines, not add
another protocol or claim public-network activation from a local process test.
Development and verification for this slice use local SQLite only. Production
Cloudflare/D1 writes, provider deployment, paid-plan changes and public exposure
are explicitly excluded.

## Decision

### Separate preparation, inspection and serving

1. Ship `apps/operator/src/sqlite_genesis.rs` and its thin `sqlite_genesis`
   executable with closed `prepare` and `preflight` dispatch. Preparation
   consumes one validator's new ordinary state/blob files and an already signed
   genesis manifest **within the defining installer's supported profile**:
   one self-contained dependency-free publication, one Instantiate initializer,
   and fee/economics resources pinned to that code/instance. Require
   explicit local chain, protocol, original epoch, logical domain, complete hash
   schedule, manifest digest, validator identity and checkpoint. Reuse
   `load_verified_genesis_root`, the accepted causal profile and existing
   `OrderedEconomicsPolicy::from_genesis_root` before destination creation.
   Require the local validator to belong to that original committed committee.
   This command neither constructs/signs a genesis manifest nor reads a signing
   seed, starts a listener or creates current successor authority. The existing
   genesis installer takes no blob store; preparation creates an empty supported
   blob database and claims no generic paid code/body closure.
   The logical domain is independently supplied local protocol configuration,
   not a manifest-authenticated value or a database/provider-derived identity.
   Bind the new state namespace to that exact domain and require it on reopen.
2. Preparation is **fresh-only**, not an idempotent repair command. Refuse an
   existing state or blob destination, including an empty file, symlink/parent
   traversal and invalid state namespace binding before intentional creation.
   Refuse pre-existing `-wal`, `-shm` or `-journal` sidecars for either file and
   any main/sidecar alias between the two normalized destinations. Check these
   fresh-only constraints before intentionally creating either resource. Add
   `SqliteDurableStore::create_new` using the existing held-file/ancestor checks
   used by the import factory; use the existing blob `create_new`. Do not use
   auto-bootstrap `open` against arbitrary existing files. Initialize the
   ordinary schema under its own initial writer fence **1**, then call the defining
   `install_genesis` and `install_ordered_genesis` owners. No new storage schema,
   canonical frame, asset privilege or business evaluator is introduced.
   Genesis and ordered initialization use the same namespace and fence.
   Ordered initialization's `now_unix_millis` comes from the trusted local clock
   solely for the existing pacemaker. It is neither manifest nor peer authority;
   different preparation times affect liveness timers, not business results.
3. Genesis and ordered initialization are separate existing commits, and state
   and blob files are separate physical resources. Do not claim cross-file or
   whole-preparation atomicity. On failure preserve partial files for explicit
   inspection, report failure and expose no successful startup result; a new
   attempt uses new destinations. The serving host still refuses incomplete
   ordered state. Preparation never resets or resumes an existing namespace.
   Synchronize created file and parent handles with the existing `sync_created`
   discipline after installation, before exactly one closed success output line.
   The first serving claim must be strictly newer than the initial fence.
4. Add an explicit read-only preflight consumer without changing the existing
   `sqlite_source_host` flag-only serving invocation or its offline-confirmation
   requirement. A separate `sqlite_genesis preflight` mode may own dispatch.
   It uses `SqliteDurableStore::open_existing`, not the historical source open:
   only existing Ordinary/Unsealed original-epoch state is eligible. Imported,
   Sealed and recurring-successor namespaces refuse; their separately verified
   D3 serving path is not widened. Open an existing blob database read-only and
   verify its supported schema/shape only: blobs have no namespace binding and
   this mode cannot prove a state/blob ownership association. Observe
   the current writer generation and verify the locally pinned genesis,
   causal profile, committed fee policy, complete committee/live pin, local
   signer public key and existing ordered status. Take the public key from an
   explicit `--validator-public-key` pin, never from a private seed. Reuse the
   public-key-accepting registered-signer check; serving continues to derive its
   own public key from its protected seed and passes those exact bytes.
   No listener, initialization,
   fence advance, transaction signature or state mutation is permitted.
5. Share genuinely identical original-host checks under one private operator
   owner, reused by preflight and by serving **after** serving's fresh fence
   acquisition. Share ordered-state verification without moving initialization
   into serving. Preserve root/context/fee/committee checks and typed failures;
   do not promote a preflight result into a live warrant or cache it for startup.
6. Construct preflight's operation context at the observed persisted fence,
   without `checked_next` or `advance_writer_fence`. Surround all durable
   deciding reads with two `begin_portable_snapshot` observations and require
   exact token equality: namespace, domain, writer fence and mutation sequence.
   Immutable blob contents keep their own existing validation;
   that token does not authenticate blobs. A changed source is a refusal, never
   an advisory success. Preflight is a bounded local observation, not a lock,
   an activation capability or a guarantee about future startup. Nonmutation
   means unchanged logical rows, objects, receipts, fence and mutation sequence;
   it does not claim byte-identical SQLite files, because a read-write WAL
   connection may checkpoint when it closes.

### Owners and excluded authority

| Owner | Responsibility | Excluded authority |
| --- | --- | --- |
| Operator genesis command | Closed local pins, fresh preparation and advisory preflight orchestration | Manifest construction, signing, network deployment, existing-state repair |
| Original host startup checks | One definition of committed root/fee/committee/key/status agreement | Fence acquisition, genesis initialization, successor authorization |
| SQLite fresh-file factory | Exclusive held-file creation and ordinary schema/fence initialization | Protocol configuration, membership or activation decisions |
| Existing core installers | Defining signed genesis and original ordered initialization | New genesis for an already serving/imported/Sealed namespace |
| Existing serving host | Fresh offline-coordinated fence, reverified pins and loopback transport | Trusting a previous preflight or implicit bootstrap |

No generic maintenance framework, serialized trusted flag, protocol change,
PostgreSQL requirement or extra Delivery 3 completion condition follows.

## Required local evidence

- Run the real preparation executable against a genuine signed multi-validator
  fixture into independent fresh local SQLite pairs; no fixture insertion into
  the prepared stores. Verify defining markers, objects, fee/committee rows and
  genuine ordered state, including close/reopen.
- Prove invalid digest/context/profile/validator and invalid/equal/existing/
  symlink destinations, pre-existing sidecars and cross-file sidecar aliases
  refuse without changing pre-existing files or state.
  A repeated prepare refuses unchanged, rather than silently repairing state.
- Run actual preflight against prepared files; compare all durable rows, object
  and receipt bytes, blob inventory, writer fence and mutation sequence before
  and after using logical snapshots, not SQLite file hashes. Verify
  missing/deleted/malformed ordered state, wrong root/fee/
  committee/key, imported/Sealed origins and a real concurrent token change
  refuse. No success result on a changed observation.
- Start the shipped host on a genuinely prepared pair, query through loopback,
  stop/reopen and require a strictly newer writer generation on restart. Keep
  the existing missing-state/no-repair and all recurring acceptance owners.
- Require focused tests, the complete storage-neutral gate and fresh independent
  complete exact-head review plus CI before normal merge. PostgreSQL and real
  providers remain unselected; local success is not release/audit certification.

## Remaining separate work

An independently reviewed genesis construction/key ceremony, ingress/TLS and
economics security audits, a selected real-network activation profile and its
actual startup/recovery evidence remain separate. This local preparation slice
does not authorize or complete them.

The existing import factory's sidecar freshness policy is a separately scoped
follow-up, not silently changed by this original-genesis preparation command.
