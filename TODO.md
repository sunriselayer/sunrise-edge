# Current delivery roadmap

**2026-09-07: deliver usable features, not another sequence of standalone
codec/validator/witness PRs.** The CLI Developer MVP and initial scoped audit
remediation are existing baselines, not a completed generic contract platform.
The public-contract foundations (DR-0112–DR-0120) and opt-in local durable code
publication (DR-0121), opt-in independent local instance execution (DR-0122),
and unified signed contract calls (DR-0123) are implemented and locally validated.
The internal Standard Asset package, paid execution engine, signed atomic
genesis installation, public paid CLI/HTTP activation, and migration of all five
asset commands away from the deleted preinstalled/native fee path are
implemented and locally validated under DR-0127. The generic-contract gate is
closed. DR-0128 adds arbitrary Standard Asset creation as an ordinary paid
instance plus immediate mint/transfer use. Its complete repository gate,
focused Codex Security delta scan, and fresh Opus tech-lead review have passed.
DR-0129 phase 0 added the owned-object `FastVote`/`FastCertificate`
canonical types, wire codec, and signature/quorum aggregation library in
`crates/consensus`. DR-0130 phase 1 now adds the local `node-core`
certified-execution boundary: signed paid-intent preparation, durable
object/nonce locks, complete staged-commit commitment, static signed-genesis
validator-set verification, and atomic certificate apply. It deliberately
adds no HTTP/CLI or other externally reachable FastVote ingress. FastVote is
delivered across four phases (see the
[FastVote Certified Execution Gate](#fastvote-certified-execution-gate)):
phase 0 (DR-0129, done); phase 1, owned-object certified execution — signed
paid intent authentication, exact replay reconciliation, nonce/policy/
object/ABI validation, deterministic paid execution, a canonical commitment
over the complete staged commit, durable exclusive owned-object version
locks, quorum certificate verification, and atomic certificate apply
(implemented and locally validated in
[DR-0130](docs/architecture/decisions/0130-owned-object-certified-execution.md));
phase 2, validator lifecycle, implemented as four
slices (epoch/validator-set transitions, equivocation evidence,
multi-validator fault/restart tests; slice 1, general mutation
authorization/fencing, implemented in
[DR-0131](docs/architecture/decisions/0131-fastvote-validator-lifecycle.md),
which also fixes slices 2-4's safety contract, including the key
transition safety proof; slice 2, epoch transition, implemented in
[DR-0132](docs/architecture/decisions/0132-fastvote-epoch-transition.md);
slice 3, equivocation evidence, implemented and locally validated in
[DR-0133](docs/architecture/decisions/0133-fastvote-equivocation-evidence.md);
slice 4's authorization/ingress boundary is implemented in
[DR-0134](docs/architecture/decisions/0134-fastvote-authorization-boundary.md),
including its companion code and review gate); and phase 3,
economics/security completion. DR-0135 implements the non-signable protocol
custody prerequisite, DR-0136 implements typed, positive genesis bond
commitments derived through authenticated generic executable ABI metadata,
DR-0137 unit 2 implements the closed post-genesis whole-object bond
lifecycle (Deposit/Replace/Unbond/Withdraw), and DR-0137 unit 3 implements
one-time evidence-driven forfeiture, jail/reactivation and next-set
eligibility coupling. Unit 4 commits the certified fee object into
request-scoped escrow and persists deterministic active-validator entitlements.
DR-0137–DR-0140 also implement signed claim execution, distribution and
payout verification. **FastVote is complete only after phase 3.** Phase 1
permits a closed local developer rehearsal, not multi-validator protocol-v3
live activation; the hard activation constraints below still apply.

| Order | Deliverable | Completion evidence | Status |
| --- | --- | --- | --- |
| 1 | Durable local code publication | CLI publish/query; immutable code/ABI/exact dependencies; authenticated admission; origin absence; shared nonce and receipt atomicity (no outgoing message); real SQLite restart/replay/conflict/fencing | Implemented and locally validated (DR-0121); fee-free opt-in local storage only |
| 2 | Run independently instantiated user contracts | CLI instantiate/call; instance isolation; defining-code/type/owner/revision authority; bounded host object operations and typed cross-contract calls; rollback/replay E2E | Local instance execution and unified signed contract calls implemented and locally validated (DR-0122/0123); zero-fee opt-in only |
| 3 | Standard Asset and fees through the public facilities | Existing asset operations use the same contract/host path; explicitly signed fee consent and committed settlement contract; remove trusted-only policies and native Coin-body rewriting; success/trap/replay parity | Implemented and validated (DR-0126/DR-0127); complete repository gate and fresh Opus tech-lead review passed |
| 4 | Arbitrary asset creation and focused delta audit | CLI creation and supply/capability lifecycle needed for initial asset use; security review of the added generic contract surface and remediation | Implemented and validated (DR-0128); focused Codex Security scan found 0 reportable findings and fresh Opus review approved |
| 5 | FastVote and multi-validator integration (4 phases; see [gate](#fastvote-certified-execution-gate)) | Owned-object certification across independent validator invocations, certificate publication, duplicate/reordered delivery, quorum/configuration changes, restart and fault evidence | **Phases 0-2 implemented and locally validated; Phase 3 remains open.** DR-0135–DR-0140 implement custody, bonds, forfeiture, signed fee claims and payout verification. DR-0142/0143 add offline SQLite and PostgreSQL certified inventory. DR-0144/0145 exercise four CLI validators, separate test databases and bounded PostgreSQL claim/reopen regressions. DR-0148's certified-only HTTP host and Rust CLI quorum/replay flow are implemented and validated; PR #223 merged as `12a08c6` after fresh exact-head Opus approval and passing CI. Authenticated lifecycle operator surfaces, owned-state/settlement handoff and activation-bound catch-up remain separate functional work. Independent Phase 3 and new-ingress security gates remain open; no live activation or deployment is authorized. Per [DR-0147](docs/architecture/decisions/0147-function-first-network-delivery.md), representative sustained load/soak/capacity certification and adopted throughput/recovery SLOs are post-launch hardening, not a Phase 3 prerequisite. FastVote overall is incomplete. |

Deliverables 1–3 close the [Generic Contract Publication Gate](#generic-contract-publication-gate).
Asset creation was the final focused delta before FastVote/multi-validator
integration. DR-0129 phase 0 supplied its canonical-types/codec foundation;
DR-0130 phase 1 supplies local certified execution without adding external
ingress. DR-0131 fixes phase 2's architecture and implements slice 1
(general mutation authorization/fencing); DR-0132 fixes and implements
slice 2's design (epoch transition); DR-0133 implements and locally validates
slice 3 (equivocation evidence); DR-0134 implements slice 4's authorization and
closed-ingress boundary, closing Phase 2. DR-0135 implements the non-signable
protocol-custody prerequisite for Phase 3; DR-0136 binds that custody to an
authenticated executable-ABI value observation and a durable genesis bond
record without importing Standard Asset into node-core runtime code; DR-0137
unit 2 adds the closed `bond_lifecycle` execution boundary that authorizes
the first post-genesis custody mutations (whole-object deposit, replacement,
unbond and withdrawal) through the same generic contract-effect validation
discipline, also without a Standard Asset exception. Standard
Asset remains a dev fixture, and the generic fee layer retains its transitive
`AssetId` dependency. Phase 3
economics/security completion remains open.
Contract
upgrades/migrations remain a separate explicit
capability after the initial immutable-code flow, not a prerequisite for
claiming that first flow. Production recovery/HA/provider certification,
Ledger, TypeScript, explorer, wallet, Unique Asset and multisig remain
separate deferred gates below; none is deleted or silently treated as
complete by this ordering.

**Active network functional delivery, with separate release gates (DR-0147):**
The completed economics core supports implementing and testing the opt-in
network surface while independent reviews remain open; it does not authorize
live exposure before those reviews pass. Functional work to make FastVote
usable is prioritized ahead of load testing; peak TPS,
concurrent-user and recovery targets remain undecided and are deferred to
post-launch hardening. The active order is:

- [x] authenticated, request/event-driven external validator access for
  FastVote prepare/certificate/apply, plus a CLI end-to-end quorum submission
  path;
  - 2026-09-26 status: [DR-0148](docs/architecture/decisions/0148-certified-fastvote-network.md)
    implements the certified-only HTTP router (`native_http::fastvote::certified_fastvote_router`,
    structurally excludes every direct/legacy mutating route), the two
    dedicated prepare/certificate routes, a fixed fresh-vote core
    verification gap, a network client (`clients/rust::fastvote_client`)
    with local-genesis-pinned, Byzantine/unavailable-peer-tolerant quorum
    collection, a long-running PostgreSQL-backed hosting binary
    (`apps/operator/src/bin/fastvote_host_pg`, loopback-only, never installs
    genesis, claims its namespace's writer fence exactly once at startup),
    and the `contract paid-call --fastvote-network`/`contract fastvote-replay`
    CLI surface (per-peer TLS, mandatory pre-POST signed-intent/certificate
    artifact persistence, exact-bytes replay). PR #223 merged on 2026-09-26
    as `12a08c6`, after fresh Opus **APPROVE** bound to final head `1c2f31e`
    and passing required CI. Exercised by a
    real four-validator SQLite-backed HTTP E2E
    (`apps/operator/tests/fastvote_network_e2e.rs`, including both handlers'
    authentication-before-I/O counters, fixed/live-epoch refusals, genuine
    cached future-vote refusal and historical receipt-first replay)
    and a real four-process live-PostgreSQL E2E driven through the compiled
    CLI library's command entry point, not a separately executed CLI binary
    (`apps/operator/tests/fastvote_host_pg_cli_e2e.rs`, gated behind
    `SUNRISE_EDGE_TEST_POSTGRES_URL`, wired into
    `scripts/check-fastvote-pg.sh`), covering a charged trap, a successful
    transfer, exact replay of both, a rejected request-id-reuse conflict
    with independently re-verified unchanged durable state, a
    stale-writer-fence rejection, and a real close/reopen of a validator's
    host process. The earlier `00672f1` candidate passed the repository gate
    but received Opus **BLOCK**. The approved final head includes corrections:
    checked CLI preparation-through-apply budget using the selected cohort
    client's exact TLS policy; all-output reservation and retained file/
    directory synchronization; fail-closed explicit replay artifacts and
    exact success/charged-trap result output; tested shared operator input,
    key, genesis and TLS helpers; live epoch/set startup pinning and clear
    out-of-band re-pin refusal; real runtime counters and the production-path
    method matrix. SDK checked caps/deadlines and sticky identity exhaustion
    remain covered. Parent source review, SQLite HTTP/startup tests and the
    updated four-process PostgreSQL CLI-library E2E passed after integration.
    Test-only follow-up pins shared operator commands to the exact
    fixture protocol, preserving legacy v1 and explicit network v3. The parent
    passed `npm ci --prefix adapters/cloudflare-workers` and the complete
    `./scripts/check-all.sh` after these corrections, including required live
    PostgreSQL fault cases, the explicit host/CLI-library E2E, stable vectors
    and adapter checks. Main matches origin/main and the approved tree.
    Codex implementation/cross-review did not replace Opus approval. Independent
    Phase 3 and new-ingress security reviews remain open; this is not public-
    network, production, or custody authorization. Filesystem tests establish
    strict synchronization/error handling on Unix, not power-loss recovery
    or validated support for other platforms.
- [ ] expose the already-implemented bond/epoch/equivocation/reward/claim
  lifecycle through explicit authenticated operator/network surfaces where
  needed;
  - Current slice: [DR-0149](docs/architecture/decisions/0149-offline-signed-fee-claims.md)
    specifies offline single-namespace PostgreSQL escrow inspection, generic
    signed claim preparation, apply/exact replay and payout verification.
    Implementation and verification are pending. Direct network claim mutation
    is excluded: local generation CAS does not order shared-escrow claims
    across validators. Online ordering/certification and the remaining
    bond/epoch/equivocation surfaces stay open.
- [ ] owned-state and settlement handoff correctness, activation-bound state
  verification, and validator catch-up before live epoch/set changes or
  validator replacement/activation. Local epoch CAS and lock-reclamation
  tests alone do not establish cross-validator state convergence. Keep the
  initial host fixed to one configured epoch/set until this gate is reviewed
  and verified; do not expose a live activation route in DR-0148.
- [ ] bounded independent-validator functional start/restart/replay/
  authorization evidence, a documented deployment/configuration walkthrough,
  and a focused security review, before exposing this ingress.

This network functional delivery has its own separate design, authentication
and security/audit gate; it does not fold into Phase 3 completion.
Representative sustained load/soak/capacity certification and adopting
throughput/recovery SLOs remain post-launch hardening, not a prerequisite
for either. No target numbers are adopted.

**Working rule:** internal tasks may be small, but a PR should deliver a usable
operation or an independently testable safety boundary. Do not split a feature
into separate type/codec/validation/loader PRs merely to tick more boxes.
Iterate with targeted tests; run the complete gate and fresh final review on
the integrated coherent change. Do not count foundation helpers as completion
of the enclosing feature. The detailed gates and historical evidence below
remain authoritative; this table is their active delivery order.

# Protocol design brief

あなたはRust、分散システム、BFTコンセンサス、WebAssembly、暗号プロトコル、ゼロ知識証明に精通したシニアブロックチェーンエンジニアです。

以下の設計思想に基づく、新しいproduction-grade L1 blockchainを実装してください。

将来のmainnet運用、protocol upgrade、multi-cloud deployment、validator set変更、暗号アルゴリズム移行、state互換性、ZK executionを最初から前提として設計してください。


# 0. Core Philosophy

最重要原則:

"A blockchain node is a state machine, not a process."

従来型Blockchain Nodeのような、

- 常駐daemon
- while(true)
- 常時接続P2P
- persistent WebSocket
- background worker
- RAM上の巨大なmutable state

をprotocolの前提にしてはいけません。

validatorはrequest/event drivenなstate machineとして実装します。

以下のruntime上で同一Node Coreを動作可能にしてください。

- Cloudflare Workers
- Vercel Functions
- Supabase Edge Functions
- AWS Lambda
- Deno Deploy
- Node.js
- native server

Cloudflare Workers等はruntime adapterに過ぎません。
protocol/coreにvendor-specific dependencyを入れてはいけません。


# 1. Fundamental Principles

1. Node is a state machine, not a process
2. Consensus does not require persistent processes
3. Consensus does not require persistent connections
4. Relay / client / schedulerはuntrusted
5. Cloud providerはconsensus trust rootではない
6. Object-centric versioned state
7. ABI-driven concurrency
8. Deterministic WASM execution
9. Protocol upgradeabilityはfirst-class feature
10. Native tokenをprotocol securityの前提にしない
11. Validator bondとvoting powerを分離する
12. Stablecoin-denominated transaction fees
13. Validator rewardはtransaction feesを基本とする
14. Dynamic governance-installed system modules
15. Zero-knowledge proof friendly execution
16. Cryptographic agilityを最初から設計する
17. Hash algorithmはtransaction senderに選択させない
18. Domain separationを全protocol hash/signatureに適用する
19. Global mutable state/global mutexは禁止
20. Massive stateでもserverless execution可能にする


# 2. Technology Stack

Core:
- Rust

Smart Contracts:
- WebAssembly
- Rustをfirst-class smart contract languageとする

Canonical WASM Execution:
- Rust製deterministic interpreter
- wasmi等を候補とする

Optional Optimized Execution:
- Wasmtime
- native/JIT/AOT
- platform-specific accelerators

ただしoptimized engineはcanonical semanticsを変更してはいけません。


# 3. Repository Structure

workspace/
  Cargo.toml

  crates/
    protocol-types/
    protocol-config/
    canonical-encoding/
    crypto/
    hashing/
    commitments/
    objects/
    abi/
    execution/
    chain-ir/
    system-modules/
    fees/
    bonds/
    validator-set/
    consensus/
    fast-path/
    governance/
    upgrades/
    migrations/
    zk/
    node-core/
    runtime/

  adapters/
    memory/
    native-http/
    cloudflare-workers/
    vercel/
    supabase/
    aws-lambda/
    deno/

  sdk/
    rust/
    typescript/

  contracts/
    system/
    examples/

  tests/
    integration/
    adversarial/
    upgrade/
    determinism/
    cryptography/
    zk/


# 4. Canonical Encoding

Hash functionの選択以上に、
「何をhash/signするか」のbyte representationを厳密に定義してください。

protocol-criticalな型についてcanonical serializationを定義する。

要件:

- deterministic
- injective
- versioned
- platform independent
- architecture independent
- map iteration orderに依存しない
- float禁止
- ambiguous concatenation禁止
- length framing必須
- enum discriminant明示
- integer endian明示

単純な

H(a || b || c)

は禁止。

canonical framingを使用する。

例:

[protocol magic]
[type/domain id]
[encoding version]
[field count]
[field id]
[field length]
[field bytes]
...


# 5. Cryptographic Agility

Hash algorithmを一種類へハードコードしない。

ただしtransaction senderやsmart contractが
consensus-critical hash algorithmを自由に選択できる設計にはしない。

原則:

"Hash algorithms are agile, but never negotiable per transaction."

protocol/epochごとにHashSuiteを固定する。


# 6. Self-Describing Digest

裸の32-byte hashをprotocol typeとして乱用しない。

例:

#[repr(u16)]
enum HashAlgorithmId {
    Sha2_256   = 0x0001,
    Sha3_256   = 0x0002,
    Blake3_256 = 0x0003,
}

struct Digest32 {
    algorithm: HashAlgorithmId,
    bytes: [u8; 32],
}

algorithm identifierはcanonical serializationに含める。

Digestは原則としてself-describingにする。


# 7. Hash Suite

用途ごとのhash algorithmをProtocolConfigで管理する。

struct HashSuite {
    id: HashSuiteId,

    transaction_hash: HashAlgorithmId,
    object_digest: HashAlgorithmId,
    effects_hash: HashAlgorithmId,
    code_hash: HashAlgorithmId,
    config_hash: HashAlgorithmId,
    certificate_hash: HashAlgorithmId,
}

Transaction自身がHashAlgorithmIdを自由指定してはいけない。

使用するHashSuiteは:

chain_id
protocol_version
epoch

から一意に決定する。


# 8. Genesis Hash Policy

Genesisでは保守性を優先する。

第一候補:

SHA-256

用途:

- TransactionHash
- ObjectDigest
- ExecutionEffectsHash
- CodeHash
- ProtocolConfigHash
- CertificateHash

SHA3-256も最初からimplementation supportしておき、
将来のalgorithm migration先として利用可能にする。

BLAKE3は高速hashとしてsupportしてよいが、
Genesis consensus root cryptographyとして必須にはしない。

重要:

HashAlgorithm implementationはinterfaceで抽象化する。


# 9. Hash API

例:

trait HashFunction {
    fn algorithm_id(&self) -> HashAlgorithmId;

    fn hash(
        &self,
        domain: HashDomain,
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        canonical_payload: &[u8],
    ) -> Digest32;
}

Hash関数呼び出し側が勝手なprefixを作らない。

domain separation framingはhashing crateで一元管理する。


# 10. Domain Separation

すべてのprotocol hashに明示的なdomain separationを適用する。

例:

enum HashDomain {
    Transaction,
    Object,
    ExecutionEffects,
    ContractCode,
    ProtocolConfig,
    Certificate,
    ValidatorSet,
    GovernanceAction,
    SystemModule,
    Migration,
    StateNode,
}

hash inputの概念形:

Hash(
    MAGIC
    || HashAlgorithmId
    || HashDomain
    || DomainVersion
    || ChainId
    || ProtocolVersion
    || PayloadLength
    || CanonicalPayload
)

ただし実際には単純concatではなくcanonical framingを使う。


# 11. Signature Domain Separation

署名対象も同様にdomain separationする。

署名domainには最低限:

- chain_id
- protocol_version
- epoch
- message_type
- signature_scheme_id

を含める。

cross-chain replay
cross-message replay
cross-version replay

を防ぐ。


# 12. Hash Suite Upgrade

HashSuiteはfuture epochで切り替え可能にする。

GovernanceAction:

ScheduleHashSuite {
    new_suite: HashSuiteId,
    activation_epoch: Epoch,
}

即時切替は禁止。

例:

Epoch 1:
HashSuiteV1 = SHA-256

Epoch 500:
HashSuiteV2 = SHA3-256

古いDigestはalgorithm IDを保持するため、
読み取り可能でなければならない。


# 13. No Global Rehash Migration

HashSuite変更時に全historical stateを一括rehashしてはいけない。

例:

Object@41
digest = SHA2_256:abc...

Epoch transition

Object@42
digest = SHA3_256:def...

古いObjectRefは旧algorithm identifier付きで有効。

更新されたversionから新HashSuiteを使える設計にする。

100TB stateでもhash migrationのために一括scanを要求してはいけない。


# 14. Adding Consensus-Critical Hash Algorithms

System Moduleとconsensus hash algorithmを区別する。

System Module内のcrypto primitive:
- governance transactionだけで追加可能

Consensus-critical hash algorithm:
- node implementationが対応済みであること
- protocol upgradeまたはsupported algorithm activationを経ること

未知のconsensus hash algorithmを
WASM moduleとして勝手に解釈してcore trust rootへ使用してはいけない。


# 15. Commitment Schemes are Separate from General Hashes

HashAlgorithmIdとCommitmentSchemeIdを分離する。

ZK/state commitmentはgeneral-purpose transaction hashingとは別問題として扱う。

例:

enum CommitmentSchemeId {
    SparseMerkleSha256V1,
    SparseMerklePoseidon2Bn254V1,
    SparseMerklePoseidon2Bls12381V1,
}

Poseidon2の場合は単に"Poseidon2"とだけ記録しない。

最低限以下をschemeとして固定する:

- finite field
- width
- rate/capacity
- round parameters
- constants version
- tree construction
- leaf encoding
- node encoding
- domain separation


# 16. State Model

EVM型global key-value storageは禁止。

Versioned Object Modelを採用する。

struct Object {
    id: ObjectId,
    version: u64,
    owner: Owner,
    type_hash: Digest32,
    schema_version: u32,
    data: Vec<u8>,
}

enum Owner {
    Address(Address),
    Shared,
    Immutable,
    System,
}

struct ObjectRef {
    id: ObjectId,
    version: u64,
    digest: Digest32,
}

Object data:

(ObjectId, Version)
    -> immutable blob

Object head:

ObjectId
    -> latest version / latest digest

Object lock:

(ObjectId, Version)
    -> TxHash


# 17. Transactions Declare State Access

transactionはアクセスするObjectを事前宣言する。

enum AccessMode {
    Read,
    Write,
    Consume,
}

将来的に:

Create
Append
Commutative(Operation)

を追加可能にする。

例:

CommutativeAdd
AppendOnly
CRDT-like operation


# 18. ABI as Execution and Concurrency Protocol

ABIはfunction signatureだけではない。

以下を含むprotocol-level manifestとする。

- function types
- argument schema
- Object types
- Read / Write / Consume
- ownership rules
- capabilities
- execution limits
- system module usage
- expected access paths

Rust contract例:

#[entry]
pub fn transfer(
    token: Read<Token>,
    from: Write<Balance>,
    to: Write<Balance>,
    amount: u128,
)

↓

AccessManifest {
    token: Read,
    from: Write,
    to: Write,
}

contractはtransactionで宣言されていないObjectへアクセスできない。

違反時はexecution trap。

**実装状況（2026-09-06、DR-0105 / DR-0106）:** DR-0105で
`AccessManifest`（which object / which access mode）とは別に、`crates/abi`へ
boundedなtyped-ABI foundationを追加した。`TypeArg`
（AssetId-onlyの32-byte値）、`TypeTag`（constructor + optional type arg、
`0x51xx`帯の新canonical type ID `0x5101`/`0x5102`）、`ConstructorDeclaration`/
`ConstructorRegistry`（fixed-depth canonical body projection、bounded 32
constructors、zero body/type/field IDをfail closedで拒否、variable-arity
constructorのfirst projection stepはexactに自身の`body_type_id`/`body_version`
と一致必須、`body_type_id`衝突をfail closedで拒否する明示的constructor-to-body
binding）、`EntrypointSignature`/`ParamDeclaration`（bounded 8 params、exact
`AccessMode`/schema version、`MAX_ENTRYPOINT_BYTES=256`は
`execution::MAX_TRANSACTION_ENTRYPOINT_BYTES`をdependency-safeに複製した
protocol-level boundであり、より狭いsigning-viewのoptional hardware display
bound（64）とは別物）、`verify_entrypoint_inputs`（single-pass pre-execution
verification、`type_hash`をprojected `TypeTag`に対し`verify_type_id`で検証
（algorithm-tagged commitmentとして、それ自体をlogical identityとして生の
digest同士で比較しない）、shared type variableのunification）を実装した。
`hashing`に`HashDomain::ObjectType`（次のaudited free value `0x000F`）/
`HashPurpose::ObjectType`と、`protocol_version`/`schema_version`を含まない
別canonical frameのnominal object-type identity hash（`frame_type_identity_input`/
`hash_type_identity`/`verify_type_identity_digest`）を追加し、epoch-scoped
trusted historyに存在しない、または未実装のalgorithmをfail closedにした。
`crates/standard-assets`が3つのconstructor定数、schema version、deterministic
registry、tag constructor、type-id helperを公開する。`ConstructorId 0`は
reservedでありregistry validationでfail closedに拒否する。`verify_type_id`等へ
渡す`epoch`は必ずauthenticated execution epochでなければならず、
request-controlledな値であってはならない、と明記した。`HashPurpose::ObjectType`が
汎用の`frame_hash_input`/`hash_for_purpose`経路へ渡された場合は
（`protocol_version`を含む別frameとなり`TypeTag`commitmentと不整合になるため）
fail closedに拒否するnarrow rejectionを追加した。`0x5001`が既存の
`protocol-config::PROTOCOL_CONFIG_TYPE_ID`と数値衝突することは、別々の
canonical struct namespaceであり各decoderが`require_type`で自分の期待値のみを
受理するため実害はないと明記した（既存IDのrenumberは行っていない）。
`objects::apply_lazy_migration`の既存の生`Digest32`比較（`ObjectTypeMismatch`）は、
typed ABI activation前に`verify_type_id`様の検証へ和解させるべきdeferred workと
してdocumentedのみ行った（このslice自体は変更していない）。DR-0105時点のこの
slice単体はinertであり、preinstalled module、`Create`、owner change、transfer、
mint、fee integration、node-core/execution/runtime配線のいずれも行っていなかった。
DR-0106（2026-09-06、
docs/architecture/decisions/0106-typed-entrypoint-owner-transition.md）により、
`Transaction.protocol_version >= MIN_OWNER_TRANSITION_PROTOCOL_VERSION`（`4`）かつ
committed catalog policyの二重gateの下で動作する、generic typed owner-transition
core（policy検証・owner-only mutationのsynthesis・translation boundaryでの独立
再検証を含むnode-core配線）を追加した。ただし現行のいかなるpreinstalled module
catalogもこの2つのpolicyをcommitしないため、Standard Asset module本体、devnet
fixtureのreplacement、CLI/signing-view、そしてこのgeneric coreを超えた
`Create`/transfer/mint/fee integrationは引き続き未実装のまま（詳細は
“Asset Standards Gate”のcompletion criteria参照）。現在の
`PreinstalledOwnerTransitionPolicy::project_recipient`はexact recipient-onlyの
canonical argsフレーム（type id/encoding version/single field）のみを射影でき、
distinctなfee payerを扱うentrypointはそのfee payerを別途engine-visibleなWrite
typed parameterとしてsignatureへ宣言する必要がある。


# 19. Fine-Grained Parallelism

将来的にはObject単位より細かいaccess pathも表現可能にする。

例:

Write(
    object = DEX,
    path = pool[ETH_USDC]
)

Tx1:
DEX.pool[ETH_USDC]

Tx2:
DEX.pool[BTC_USDC]

なら競合しない。

AccessKey:

(ObjectId, ObjectPath)

まで拡張可能にする。


# 20. Serverless Node Architecture

validator invocation:

Request/Event
    ↓
load only required persistent state
    ↓
NodeCore.handle_event()
    ↓
deterministic state transition
    ↓
atomic persistence / CAS
    ↓
signed response / outbound messages
    ↓
return
    ↓
process disappears

process memoryはprotocol stateではない。


# 21. Node Core API

pub async fn handle_event<R: Runtime>(
    runtime: &R,
    config: &NodeConfig,
    event: NodeEvent,
) -> Result<NodeOutput>;

enum NodeEvent {
    SubmitTransaction(Transaction),
    ReceiveVote(Vote),
    ReceiveCertificate(Certificate),
    ReceiveConsensusMessage(ConsensusMessage),
    ApplyGovernanceCertificate(GovernanceCertificate),
    ApplyProtocolUpgrade(ProtocolUpgradeCertificate),
    ApplyValidatorSetChange(ValidatorSetChangeCertificate),
    Tick(Tick),
}

struct NodeOutput {
    responses: Vec<NodeResponse>,
    outbound_messages: Vec<OutboundMessage>,
}

node-core内部で禁止:

spawn()
while(true)
background jobs
persistent sockets
global mutable state


# 22. Runtime Abstraction

trait StateStore
trait BlobStore
trait Signer
trait Transport
trait Clock
trait Scheduler

等に分割する。

StateStoreには最低限:

get
put
compare_and_swap
atomic conditional update

を用意する。


# 23. Untrusted Transport

validator間常時P2Pを要求しない。

messageを運ぶ主体は:

- client
- browser
- RPC provider
- relay
- validator
- keeper

誰でもよい。

relayは:

drop
duplicate
reorder
delay
replay
mutate

できる前提。

protocol safetyはcryptographic signatureとpersistent stateに依存する。


# 24. Fast Path

Owned / non-conflicting Object transactionはglobal consensus orderingなしで処理可能にする。

validator:

1. chain_id verify
2. protocol_version verify
3. epoch verify
4. sender signature verify
5. fee payment verify
6. ObjectRef verify
7. ABI / AccessManifest verify
8. conflict check
9. deterministic execution
10. Object version lock
11. execution effects hash
12. Vote署名
13. response

validator同士の直接通信を必須にしない。


# 25. Vote

struct Vote {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,

    validator: ValidatorId,

    tx_hash: Digest32,
    execution_effects_hash: Digest32,

    signature: Signature,
}


# 26. Certificate

struct FastCertificate {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,

    tx_hash: Digest32,
    execution_effects_hash: Digest32,

    votes: Vec<Vote>,
}

quorum certificate成立後にcommit。

certificate処理は完全idempotent。


# 27. Shared Object Consensus

Shared / conflicting ObjectのみBFT orderingへ送る。

trait ConsensusEngine {
    fn protocol_id(&self) -> ConsensusProtocolId;

    fn on_event(
        ...
    ) -> Result<ConsensusOutput>;
}

候補:

- HotStuff-derived event-driven BFT
- DAG-BFT
- Mysticeti-like architecture

daemonを前提にしない。


# 28. Timeout Model

timeoutはNodeEvent::Tickとして外部入力する。

Tick senderはuntrusted。

利用可能:

Cloudflare Cron
Vercel Cron
Supabase cron
AWS EventBridge
client
random keeper

protocol自身がepoch/view/deadlineを検証する。


# 29. Validator Security Model

Native token stakingを必須としない。

以下を分離:

Validator Identity
Validator Membership
Validator Voting Power
Validator Bond
Validator Economics


# 30. Genesis Validator Model

Genesis時点ではbond tokenが存在しない可能性がある。

したがってpermissioned validator setでchainを起動可能にする。

例:

V1
V2
V3
V4

AdmissionPolicy:
GenesisPermissioned

BondAssets:
empty

BondRequirement:
None


# 31. Bond Assets After Genesis

Stablecoin contractがdeployされた後、
governance transactionでbond assetとして登録可能にする。

例:

Deploy USDC contract

↓

GovernanceTx:
AddBondAsset {
    asset_id: USDC,
    min_bond: ...,
}

↓

ScheduleValidatorPolicy {
    activation_epoch: 100,
    policy: BondAndGovernance,
}


# 32. Bond != Voting Power

bond amountはvoting powerを増やさない。

例:

100,000 USDC bond
-> voting power 1

10,000,000 USDC bond
-> voting power 1

bondの目的:

- Sybil cost
- slashable collateral
- validator eligibility

wealth-based voting powerにはしない。


# 33. Validator Admission Policies

enum ValidatorAdmissionPolicy {
    GenesisPermissioned,
    GovernancePermissioned,
    BondAndGovernance,
    BondRequired,
}

想定transition:

GenesisPermissioned
    ↓
BondAndGovernance
    ↓
必要ならBondRequired


# 34. Bond Asset Config

struct BondAssetConfig {
    asset_id: AssetId,
    min_bond: Amount,
    enabled: bool,
    unbonding_epochs: u64,
    max_validator_exposure: Option<Amount>,
}


# 35. Bond Object

struct BondObject {
    validator_id: ValidatorId,
    asset_id: AssetId,
    amount: Amount,
    bonded_epoch: Epoch,
    unlock_epoch: Option<Epoch>,
}

bond:

Stablecoin Object
    ↓
BondObject

unbond:

request_unbond
    ↓
unbonding period
    ↓
withdraw

unbonding period中はslash可能。


# 36. Slashing

cryptographically provable misconductのみslash対象。

Slash:

- same Object versionへのconflicting vote
- consensus equivocation
- conflicting finalized statements
- cryptographically provable double-signing

原則Slashしない:

- offline
- slow response
- request timeout
- provider outage
- Cloudflare outage
- Vercel outage

liveness failureとByzantine evidenceを明確に分離する。


# 37. Stablecoin Transaction Fees

native gas tokenは必須にしない。

struct FeePayment {
    asset: AssetId,
    max_fee: Amount,
    fee_object: ObjectRef,
}

approved stablecoin等で直接fee payment可能。


# 38. Fee Asset Registry

GovernanceAction:

AddFeeAsset
DisableFeeAsset
UpdateFeeAssetParameters

を実装。

canonical AssetIdを使用し、
symbol stringをidentityとして使わない。


# 39. Deterministic Fee Calculation

float禁止。

内部canonical unitを使用。

例:

1 USD = 1_000_000 fee units

Fee:

base_fee
+ execution_units * execution_price
+ state_read_units * read_price
+ state_write_units * write_price
+ storage_units * storage_price
+ system_module_units


# 40. Validator Fee Revenue

inflation rewardをprotocol前提にしない。

transaction fee:

Transaction Fee
    ↓
Committed Active Validator Set
    ↓
stablecoin distribution

certificateの有効なquorum subsetには依存せず、確定したactive validator setからdeterministically計算。


# 41. Fee Settlement Separation

Phase A:
TransactionExecutionEffects

Phase B:
Certificate

Phase C:
FeeSettlementEffects

確定したactive validator setからfee distributionを計算する。

rounding remainderのrecipientもcanonicalに決定する。


# 42. WASM Smart Contracts

禁止:

network
filesystem
wall clock
OS randomness
arbitrary external I/O
arbitrary global state lookup

許可:

declared object read
declared object write
object create
object consume
event emit
crypto functions
system module calls
deterministic protocol context


# 43. Execution Engine

trait ExecutionEngine {
    fn execute(
        &self,
        protocol_version: ProtocolVersion,
        module: &[u8],
        entrypoint: &str,
        inputs: &[ResolvedObject],
        args: &[u8],
    ) -> Result<ExecutionEffects>;
}

Canonical:
deterministic WASM interpreter

Optional:
native/JIT/AOT

output equivalence必須。


# 44. Chain IR

WASMを最終protocol semanticsへ固定しすぎず、
versioned deterministic Chain IRを導入できる設計にする。

Rust
 ↓
WASM
 ↓
Chain IR
 ↓
Execution

IR例:

LOAD_OBJECT
READ_FIELD
WRITE_FIELD
ADD_U64
CALL_SYSTEM
CREATE_OBJECT
CONSUME_OBJECT
EMIT_EVENT

Chain IR:

- deterministic
- versioned
- bounded
- statically inspectable
- ZK-friendly


# 45. ZK Architecture

                Chain IR
                   ↓
       ┌───────────┼───────────┐
       ↓           ↓           ↓
 Interpreter   Native/JIT    ZK Prover

初期は:

canonical interpreter
    ↓
RISC-V zkVM

等のbackendを許容。

将来的にChain IR専用proverへ変更可能。


# 46. Execution Proof

struct ExecutionProof {
    proof_system: ProofSystemId,

    tx_hash: Digest32,

    input_commitment: Commitment,

    output_commitment: Commitment,

    proof_bytes: Vec<u8>,
}

初期:
validator quorum

将来:
validator quorum + execution proof

さらに将来:
proof verification中心のvalidator execution

を可能にする。


# 47. ZK-Friendly State Commitment

transaction access setが事前確定していることを利用する。

StateRoot

├ proof A@12
├ proof B@44
└ proof C@8

      ↓

execution

      ↓

A@13
B@45
C@9

      ↓

NewStateRoot

state commitment schemeはCommitmentSchemeIdで明示する。


# 48. Dynamic System Modules

precompile追加のためにnode binary updateを必須にしない。

"precompile"をSystem Moduleへ一般化する。

Governance Transaction
    ↓
SystemModuleRegistry
    ↓
activation
    ↓
contractから利用


# 49. System Module

struct SystemModule {
    module_id: ModuleId,
    version: u64,

    canonical_code_hash: Digest32,
    semantics_hash: Digest32,
    manifest_hash: Digest32,

    activation_epoch: Epoch,
    status: ModuleStatus,
}

canonical implementationはportable deterministic codeを使用する。


# 50. System Module Manifest

struct SystemModuleManifest {
    module_id: ModuleId,

    input_schema: TypeSchema,
    output_schema: TypeSchema,

    max_input_size: u64,

    gas_model: GasModel,

    zk_hint: Option<ZkHint>,
}


# 51. Governance-Installed Crypto Modules

protocol upgradeなしでGovernance Transactionにより追加可能:

- Poseidon2
- SHA variants
- secp256k1 utilities
- Ed25519 utilities
- BLS utilities
- Groth16 verifier
- Plonk verifier
- future crypto primitives

ただしこれらはSystem Module level。

TxHash等のconsensus root primitiveとは明確に分ける。


# 52. Native System Module Acceleration

native optimized implementationはoptional。

CanonicalSystemModule(input)
==
NativeImplementation(input)

であること。

native implementation非対応validatorでも参加可能にする。


# 53. ZK System Module Acceleration

System Moduleにはzk_hintを設定可能。

例:

CALL_SYSTEM POSEIDON2

をZK backendで専用gadgetへ置換可能にする。

canonical semanticsとのequivalenceを保証する。


# 54. Protocol Versioning

type ProtocolVersion = u64;

protocol-critical messageには必ず:

chain_id
protocol_version
epoch

を含める。

unknown protocol version:
reject

silent fallback:
禁止


# 55. ProtocolConfig

struct ProtocolConfig {
    protocol_version: ProtocolVersion,

    hash_suite: HashSuiteId,

    commitment_scheme: CommitmentSchemeId,

    execution_rules: ExecutionRules,

    gas_schedule: GasSchedule,

    fee_assets: FeeAssetConfig,

    bond_assets: BondAssetConfig,

    validator_policy: ValidatorPolicy,

    consensus_parameters: ConsensusParameters,

    object_rules: ObjectRules,

    feature_flags: FeatureFlags,
}

ProtocolConfig自身もcanonical encodingしてhashする。


# 56. Protocol Upgrade

struct ProtocolUpgrade {
    from_version: ProtocolVersion,
    to_version: ProtocolVersion,

    activation_epoch: Epoch,

    new_config_hash: Digest32,

    migration_hash: Option<Digest32>,

    compatibility_policy: CompatibilityPolicy,
}

future epoch activationのみ。


# 57. Governance

trait GovernanceEngine {
    fn verify_action(
        action: &GovernanceAction,
        certificate: &GovernanceCertificate,
    ) -> Result<()>;
}

GovernanceAction例:

RegisterSystemModule
ActivateSystemModule
DeactivateSystemModule

AddFeeAsset
DisableFeeAsset

AddBondAsset
DisableBondAsset

ChangeValidatorAdmissionPolicy

AddValidator
RemoveValidator
ScheduleValidatorSet

ScheduleHashSuite
ScheduleCommitmentScheme

ScheduleProtocolUpgrade


# 58. State Migration

全state一括migration禁止。

Objectにschema_versionを持たせる。

lazy migration:

Old Object
    ↓
deterministic migration function
    ↓
New Object

migration functionもhash/versionで識別する。


# 59. Genesis to Bonded Network Transition

以下をprotocol-native lifecycleとして実装する。

Genesis
    ↓

permissioned validator set
bond assets = empty

    ↓

chain starts

    ↓

stablecoin contract deployed

    ↓

Governance:
AddFeeAsset(USDC)

    ↓

Governance:
AddBondAsset(USDC)

    ↓

Governance:
ScheduleValidatorPolicy(
    BondAndGovernance,
    activation_epoch = N
)

    ↓

grace period

    ↓

validators bond USDC

    ↓

Epoch N

BondAndGovernance activated


# 60. Runtime Adapters

Cloudflare:
- Workers
- Durable Objects / D1 abstraction
- R2

Vercel:
- Functions
- Postgres-compatible StateStore
- Blob/S3-compatible storage

Supabase:
- Edge Functions
- Postgres
- Storage

AWS:
- Lambda
- DynamoDB/Postgres
- S3

Deno:
- Edge/serverless adapter

Cloudflare-specific semanticsをprotocol safety requirementにしない。


# 61. Security Invariants

Invariant 1:
honest validatorは同一Object versionのconflicting transactionsへ二重voteしない。

Invariant 2:
quorum certificateなしにcommitted stateを変更できない。

Invariant 3:
同じcertificateから全validatorが同じstate transitionを導出する。

Invariant 4:
relayをtrustしない。

Invariant 5:
schedulerをtrustしない。

Invariant 6:
cloud providerをtrustしない。

Invariant 7:
process memoryをprotocol stateにしない。

Invariant 8:
protocol version mismatchはreject。

Invariant 9:
fee calculationはdeterministic。

Invariant 10:
fee settlementはdeterministic。

Invariant 11:
bond amountはvoting powerを増やさない。

Invariant 12:
slashにはcryptographic evidenceが必要。

Invariant 13:
native optimizationはcanonical semanticsを変更できない。

Invariant 14:
same transaction + same inputs + same protocol config
から全runtimeで同じeffects hashを生成する。

Invariant 15:
HashSuiteはtransaction senderがnegotiationできない。

Invariant 16:
hash domain間でcross-protocol collision semanticsを共有しない。

Invariant 17:
HashSuite変更時もhistorical digestを検証可能。

Invariant 18:
unknown hash algorithmをsilent fallbackしない。

Invariant 19:
general-purpose hashとZK commitment schemeを混同しない。

Invariant 20:
normal executionとZK executionが同じstate transition semanticsを持つ。


# 62. Required Cryptographic Tests

必須:

1. canonical encoding test vectors
2. HashDomain test vectors
3. SHA-256 hash vectors
4. SHA3-256 hash vectors
5. Digest algorithm ID serialization vectors
6. cross-domain hashが異なること
7. cross-chain hashが異なること
8. cross-protocol-version hashが異なること
9. equivalent structured payloadが同一canonical bytesになること
10. ambiguous structured payloadが同一bytesにならないこと
11. old HashSuite digest verification
12. HashSuite epoch transition
13. unknown HashAlgorithmId rejection
14. unknown CommitmentSchemeId rejection
15. no silent fallback


# 63. Required Integration Tests

Test 1:
4 validators
f=1
quorum=3

Alice -> Bob transaction

certificate成立後、
全validatorで同じdigest。


Test 2:
same Object version conflict
double vote禁止。


Test 3:
independent Objects
parallel execution可能。


Test 4:
certificate replay/idempotency。


Test 5:
requestごとにNode process完全破棄。


Test 6:
relay reorder/duplicate/delay/stale。


Test 7:
stablecoin transaction fee。


Test 8:
vote arrival orderが異なってもfee settlement一致。


Test 9:
Genesis permissioned modeでbond無しにchain起動。


Test 10:
stablecoin deployment後AddBondAsset。


Test 11:
BondAndGovernance future activation。


Test 12:
validator stablecoin bond。


Test 13:
bond額によらずequal voting power。


Test 14:
equivocation slash。


Test 15:
offlineのみではslashしない。


Test 16:
Protocol Version N -> N+1。


Test 17:
old epoch replay rejection。


Test 18:
lazy migration。


Test 19:
GovernanceのみでSystem Module追加。


Test 20:
node binary updateなしでportable System Module実行。


Test 21:
native System Module equivalence。


Test 22:
ZK gadget equivalence。


Test 23:
normal execution / ZK execution effects hash一致。


Test 24:
Cloudflare/native adapterでeffects hash一致。


Test 25:
HashSuiteV1 SHA-256でObject作成。


Test 26:
future epochでHashSuiteV2へ移行。


Test 27:
旧SHA-256 ObjectRefを新epochで正しくread。


Test 28:
Object更新後は新HashSuite digestを使用。


Test 29:
global state rehash無しにmigration可能。


Test 30:
HashAlgorithmId/domain/versionを変更するとhashが必ず変化。


# 64. Coding Requirements

production-quality Rust。

必須:

- unsafe原則禁止
- library codeのunwrap乱用禁止
- typed errors
- thiserror等
- structured logging
- metrics abstraction
- deterministic serialization
- canonical cryptographic framing
- no global mutable state
- no background tasks in node-core
- no vendor dependency in protocol core
- domain-separated hashes
- domain-separated signatures
- explicit chain_id
- explicit epoch
- explicit protocol_version
- explicit HashAlgorithmId
- explicit CommitmentSchemeId
- serialization test vectors
- cryptographic test vectors
- property-based testing
- fuzz testing
- adversarial tests
- cross-runtime determinism tests
- public API doc comments


# 65. Implementation Order

## As-Is milestones and To-Be destination

このPhase一覧はincremental deliveryの順序であり、最終品質の定義ではない。
`implemented`はそのPhaseのAs-Is milestoneが実装・検証されたことだけを意味し、
production-ready、mainnet-ready、監査済みを意味しない。

この文書のTo-Beは一貫してproduction-grade L1である。したがって:

- experimental、temporary、mock、reserved、deferred、interface-onlyな実装を
  production上の完成形として扱ってはいけない。
- 各experimental milestoneにはproduction exit criteriaを残し、criteriaを満たすまで
  TODOから削除したり「完了」と解釈したりしてはいけない。
- 後続PhaseはAs-Isの制約から逆算してTo-Beとの差分を閉じる。実験実装を別名で
  複製するだけのPRを新しいPhaseの完了としてはいけない。
- mainnet release判断はPhase番号ではなく、cross-phase production release gateと
  security reviewの充足で行う。
- TODOはcurrent implementation status・roadmap sequencing・未解決のproduction gapの
  唯一のlive情報源である。docs/architectureはimplemented As-Is behaviorとaccepted
  decision recordsを記録するが、live work queueではない。READMEはcurrent statusを
  一切含めない。
- 各PhaseのPRを完了するときは、TODOのAs-Isと残存production exit criteriaを同時に
  更新する。criteriaを満たしていない項目へ単に`implemented`だけを付けない。

## CLI Developer MVP Gate

このgateは、browser向けproduct surfaceより先にsingle-nodeのRust-only developer体験を
成立させるCLI-first pivot（DR-0085）を追跡する。対象はcriteria 1-6・10・11であり、
criteria 7-9は削除・完了扱いせず、Software Production Gate（S0-S3 + S5）通過後へ
resequenceする。詳細な設計根拠と実装履歴はDR-0081–DR-0095、現行Standard Assetへの
置換はDR-0107以降に置き、この節にはgate定義・現況・残件だけを残す。

**Current status (2026-09-13):** criteria 1-6・10・11はimplemented and validated As-Isで、
CLI Developer MVP Gateは通過済み。S0-S3はimplemented and validated As-Is、S4aは
host preflight As-Isである。S4bはSpeculos/Ragger emulator evidence、S4c Phase 1/2aは
software-only evidenceであり、いずれもphysical hardware validationではない。
S4c Phase 2b、S4d、その他のLedger実機/release workはdeferredであり、S4全体は未完了。
S5とS4はDR-0095によりparallel trackで、TypeScript client・explorer・walletは
Software Production Gate（S0-S3 + S5）までdeferredである。このstatusはcompleteな
CLI-First Node Production Gate、production、mainnet readinessを意味しない。

CLI Developer MVP completion criteria（capability criteria 2-3を満たしながら、product
surfaceはdocs/architecture/decisions/0081-0087-cli-first-roadmap.md DR-0081の順序に従う: local devnet、bounded query API、Rust
client、Rust CLI、TypeScript client、explorer、wallet、restart/duplicate E2E、
explicit dev limitations）。**pivot後のgateはcriteria 1-6・10・11だけであり、
criteria 7-9（TypeScript client、explorer、wallet）はverbatimのまま以下に残すが、
[Software Production Gate](#software-and-hardware-release-gates)（S0-S3 + S5）を通過するまで
明示的にdefer/resequenceする（削除・完了扱い・弱体化ではない）:**

1. native HTTPとlocal durable SQLiteを使い、停止・再起動できるsingle-node local devnetを
   documented commandで起動できる。
2. authenticated owned inline objectのRead/Write/Consumeを実行し、signed accessと
   deterministic `ObjectEffect`を厳密に対応付け、nonce、application state、object head/version、
   receipt、outboxを同じdurable invocationでatomic commitする。Create、Shared/System owner、
   blob-backed bodyは明示的にfail closedのままでよい。
3. governed/preinstalled moduleをexact commitmentからloadし、bounded deterministic WASMで
   少なくとも1つのstateful contractを実行できる（devnetの具体的なmoduleは
   DR-0081当時は`sunrise.devnet.asset_account.v1`の`transfer` entrypointだったが、
   DR-0107によりStandard Asset v1 whole-object `Coin<A>` transferへreplaceされた。
   DR-0081/DR-0107参照）。任意upload、JIT、production meteringはMVP範囲外とする。
4. chain/context情報、object、receipt、authenticated senderのnext nonceを取得するbounded
   query APIを提供する。
5. `clients/rust`でkey/address、canonical transaction encode/sign、submit、receipt wait、
   queryを提供するRust client libraryを実装し、serverのcanonical contractに対する
   stable vectorsを共有する。
6. `clients/rust`のみに依存するRust-only developer CLI（`apps/cli`）を実装する。
   `apps/cli`はNode/browser runtimeに依存せず、canonical encode/decode・signing・RPC呼び出しは
   すべて`clients/rust`経由とする。
7. `clients/typescript`でkey/address、canonical transaction encode/sign、submit、
   receipt wait、queryを提供するTypeScript client libraryを実装し、同じstable vectorsを共有する。
   **（pivot後: この criterion のcontentは変更しない。実装着手は
   [Software Production Gate](#software-and-hardware-release-gates)（S0-S3 + S5）通過後まで
   deferする。）**
8. `apps/explorer`として、SvelteKit + shadcn-svelte（Luma）によるstatic/CSR専用のexplorer app
   を実装する。request-time server-side rendering、SvelteKit server adapter、
   `+page.server`/`+layout.server`/`+server` route、server actions/remote functions/
   server-held sessionやkeyは一切使わない。dynamic chain dataは`clients/typescript`経由の
   client-side fetchのみとする。
   **（pivot後: この criterion のcontentは変更しない。実装着手は
   [Software Production Gate](#software-and-hardware-release-gates)（S0-S3 + S5）通過後まで
   deferする。）**
9. `apps/wallet`として、同様にSvelteKit + shadcn-svelte（Luma）によるstatic/CSR専用のwallet app
   を実装する。制約は8と同一（SSR/server adapter/server route/server actionsなし）に加え、
   signing keyはbrowser内でのみ生成・保持・使用し、server側へ渡したり生成させたりしない。
   `apps/explorer`と`apps/wallet`の間でreal duplicationが発生するまで、共有UI packageは
   導入しない。
   **（pivot後: この criterion のcontentは変更しない。実装着手は
   [Software Production Gate](#software-and-hardware-release-gates)（S0-S3 + S5）通過後まで
   deferする。）**
10. devnet再起動後もstate/object/receipt/nonceが保持され、同一request retryがeffectを
    二重適用しないことを自動E2Eで証明する（DR-0127以降`apps/cli/tests/devnet_standard_asset_e2e.rs`
    でimplemented As-Is。real file-backed `SqliteDurableStore`、composeしたdevnet router、
    real loopback TCP、`sunrise-edge-cli::run`によるuser-facing split/merge/mint/burn/transferと
    `sunrise-edge-client`による独立検証を使い、orderly stop/reopen後のobject・receipt・
    next-nonce query resultとsubmit resultのcanonical bytes一致、same-bootおよび
    restart後のbyte-identicalな成功済み`transfer`署名済みsubmissionのexact replay非再適用、
    installed `PaidFeePolicy`による actual `application_gas_units`に一致するexact fee
    reservation/settlement、already-committedな
    request idの別transaction（異なるsigned bytes）での再利用がfail closedになりobject/
    receipt/nonceを一切変更しないこと、pre-restart writer
    generationがreopen後にfencedであることを証明する。orderly stop/reopenのみの証明であり、
    `kill -9`、power loss、torn write、load、concurrency、SQLiteのproduction適性は
    証明しない。下記S0参照）。
11. single validator、owned-object only、installed `PaidFeePolicy`が指す単一のpublic
    Standard Asset `Coin<A>`をfee objectとして使う（専用のtreasury objectはなく、fee
    recipientは`--fee-recipient`で指定するaddress。validator/certificate distributionや
    production economicsなし）、local SQLite、`transfer`/`split`/`merge`/`mint`/`burn`は
    すべてpolicy-pinnedなordinary paid contract callであり（node-core固有のdestination/
    owner-transition policyは存在せず、owner変更は published WASMパッケージ自身が行う）、
    4 bounded query routeがunauthenticated public-read API（呼び出し元は誰でも
    任意のobject/receipt/next-nonce/contextを読める。`/v1/senders/{sender}/next-nonce`の
    addressはpublic lookup selectorでありauthorizationではない）であること、queryと
    submissionが単一の共有admission budget（`NativeBlockingExecutor`／
    `--max-concurrent`）を使う（片方のtrafficがもう片方をstarveしうる）こと、
    non-production security/operationsという制約をREADMEと起動時表示へ明記する。

### Implementation evidence summary

- local devnetとfile-backed SQLite lifecycleは`apps/devnet`およびDR-0081で実装済み。
- authenticated owned-object effectsとatomic durable mutationはnode-coreの
   structured durable pathおよびDR-0078で実装済み。generic pathの権限を広げない。
- exact committed preinstalled WASM executionはDR-0078/DR-0081で実装され、DR-0107で
   Standard Asset v1 whole-object semanticsへ置換された。DR-0127以降、active devnetは
   このpreinstalled/native fee composer pathを完全に削除し、public Standard Asset
   packageへのordinary policy-pinned paid contract callへ統一した。
- native HTTP compositionは`preinstalled_wasm_structured_durable_router`へ接続済み。
  public `POST /v1/events`はDR-0099により`SubmitTransaction`以外をidentity allocation、
  clock read、storage I/O、machine transition、outbox、transportより前にfail closedとし、
  family固有の認証・認可なしには再公開しない。
- bounded canonical query APIはDR-0082、Rust client boundaryはDR-0083、Rust-only CLIと
   external-signer boundaryはDR-0084で実装済み。
- cross-owner/feeの旧development fixtureはDR-0086/DR-0087のhistorical recordであり、
   現行のtyped policy、whole-coin transfer、split/merge/mintはDR-0106以降を参照する。
- TLS endpoint authenticationとsigning前のtrusted protocol-context validationは
   独立したboundaryとしてS1で実装済み。TLS成功をchain/protocol identityの証明とみなさない。
- Ledgerのdevice/host milestonesとsoftware-only evidenceはDR-0088–DR-0093、残る実機/
   release workのdeferとsoftware trackとの並行化はDR-0095を参照する。
- orderly close/reopen、writer-generation fencing、same-boot/post-restart exact replay、
   request-id conflict時のstate/receipt/nonce不変は DR-0127の
   `apps/cli/tests/devnet_standard_asset_e2e.rs`で検証済み。これは`kill -9`、power loss、
   torn write、load/concurrency、SQLiteのproduction適性を証明しない。

### Residual limitations retained by this gate

- queryとsubmissionは1つの`NativeBlockingExecutor`/`--max-concurrent` budgetを共有し、
  一方のtrafficが他方をstarveし得る。single validator、public unauthenticated bounded
  query、fixed development configurationを含め、non-production postureのままである。
- development seedの読み込みbuffer、decoded seed、`LocalSigner`のkey materialには
  zeroize-on-dropがなく、core dump・swap・debugger等から回収され得る。これはproduction
  key handlingではない。
- capacity/load/soak、PITR、HA/failover、provider certification/deployment、certificate
  publication、non-`SubmitTransaction` event-family ingressなどは本gateの完了条件へ
  遡及追加せず、後続のproduction/security gatesで追跡する。

**Repository boundary:** Rust client (`clients/rust`)、Rust CLI (`apps/cli`)と、deferredな
TypeScript client (`clients/typescript`)、explorer (`apps/explorer`)、wallet (`apps/wallet`)は、
DR-0081のextraction条件を満たすまでmonorepo内に置く。`demo/counter`は作成せず、browser appは
別々のstatic/CSR-only SvelteKit surfaceとし、real duplicationが生じるまで共有UI packageを
導入しない。

## Initial Code Security Audit Entry Gate

**目的（2026-09-05、docs/architecture/decisions/0094-0098-blobs-audit-and-documentation.md DR-0097）:** production/mainnetの全機能と
運用証跡を揃えてから初めて第三者監査を開始する旧解釈を廃止し、現在すでに動く
CLI-first nodeのsecurity-critical coreを早期にfreezeして監査へ出す。このgateは
「監査を開始できる固定scope」を定義するだけであり、Software Production Gate、
CLI-First Node Production Gate、production readiness、mainnet readinessを意味しない。
後から追加するprotocol/event/provider surfaceはfocused delta auditを受け、最終release
gateでは全auditの重大指摘解消を引き続き要求する。

**Current status:** criterion 1（外部event ingressを`SubmitTransaction`だけへ閉じるfail-closed
変更）はnative HTTPの4router family全て（`router`、`resolved_domain_router`、
`structured_durable_router`、`preinstalled_wasm_structured_durable_router`と各
`_with_executor`構成関数）でimplemented As-Isとなった
（docs/architecture/decisions/0099-submit-only-event-ingress.md DR-0099）。criteria 2-3の
audit scope、source-backed threat model、root `SECURITY.md`、private vulnerability reporting
routeもimplemented As-Isとなった。初回audit revisionはこれらの文書を導入したpull requestの
final validated head SHAとし、同一SHAに対するclean-tree complete repository gateとrequired
GitHub checksをpull-request handoffへ記録する。このevidenceをmerge条件とすることで、Initial
Code Security Audit Entry Gateは通過し、初回第三者code security auditを開始できる。これは
audit完了、Software Production Gate、CLI-First Node Production Gate、production readiness、
mainnet readinessのいずれも意味しない。

初回監査のobject-query integrity指摘（High）はDR-0101でremediation As-Isとした。
`CurrentInline` v2はimmutable versionのcreating chain/protocolを返し、Rust clientがbody digestを
再計算してから結果を公開する。v1 vectorは不変でdecode可能だが、digest contextを欠くinline
responseはgeneric clientがrejectする。profile-2署名はDR-0103のcanonical `0xE009` envelopeで
outer `request_id`とexact Transaction-v1 signable bytesを束縛し、relabelはidentity/clock/storage前に
失敗する。Transaction v1 bytes、profile 1、historical `transaction-v1` vectorは不変である。

初回監査のnon-exclusive Ed25519 value-owner指摘（Medium）はDR-0102でremediation As-Isとした。
historical profile 1のZIP-215 verificationは変更せず、active devnet profile 2ではsender、読み込んだ
address owner、cross-owner destination、fee treasury、devnet funded ownerをcanonical、non-identity、
prime-order subgroupへ制限する。profile 2からprofile 1へのdowngradeはない。

初回監査で確認されたnative HTTP slow-connection resource exhaustion（Medium）はDR-0100で
remediation As-Isとした。repository-owned `serve`はHTTP parse前のbounded connection permit、
header total timeout、socket-read idle timeout、body total timeout、response-write idle/total timeout、
one-request connectionを全router familyへ一律適用し、既存body-size boundと
`NativeBlockingExecutor`を独立して維持する。raw TCPのadversarial testはincomplete header/body、
connection overload後のrecovery、slow-drip body total timeout、stalled/slow-drip response write、legitimate
livenessを検証する。

**Initial audit remediation re-review完了（2026-09-05）。** PR #130 head
`cdf438c51b1609eb4886d8edcddc22af183f48c0`に対するfresh GPT Daybreak Blue Standard
single-pass static source audit（scan id
`034f9d08-2613-402d-868e-0fce48bb6bfc`）は、declared scope内でstatus `completed`、
coverage `complete`、reportable findings 0となり、上記High 1件・Medium 3件を全てfixedと
dispositionした。canonical evidenceは
`docs/security/audits/2026-09-05-pr-130-daybreak/`に保存する。これはsource-only auditであり、
production proxy/kernel/TLS、PostgreSQL deployment/operations、HA、backup、load/soak、physical
hardware、Software Production Gate、CLI-First Node Production Gate、production readiness、
mainnet readinessの完了またはcertificationを意味しない。初回audit後のsecurity-critical変更は
引き続き`docs/security/initial-code-audit-scope.md`のfocused delta-audit ruleへ従う。

### 最小completion criteria

1. **実装済み（implemented As-Is、DR-0099）。** public/native `POST /v1/events`のaudit対象
   surfaceを、現在唯一end-to-endで認証・認可される`SubmitTransaction`へ明示的に限定した。
   `ReceiveVote`、`ReceiveCertificate`、`ReceiveConsensusMessage`、
   `ApplyGovernanceCertificate`、`ApplyProtocolUpgrade`、`ApplyValidatorSetChange`、`Tick`の
   全non-`SubmitTransaction` kindは、native-http外部境界のtyped private errorにより、
   identity allocation・clock読み取り・storage I/O・machineのaccess_plan/transition・outbox
   処理・transport sendより前に、4router family全てで同一のopaque
   `501 event-family-requires-authenticated-route`へfail closedする。legacy `router`と
   `resolved_domain_router`はどちらも`SubmitTransaction`を認証しないため、既存の
   `submit-transaction-requires-authenticated-route`応答と合わせて全known kindを閉じている。
   node-coreのgeneric `TransactionalNodeStateMachine`経路・`validate_generic_event`・
   `NodeCoreError`の公開variantは変更していない。各family固有の認証・認可を実装するまで、
   この境界だけがscopeであり、全familyを先に実装することはこのgateの条件ではない。
2. **実装済み。** immutable audit commitとin-scope surfaceを固定する。初回監査対象はcanonical encoding/
   hashing/signature framing、`SubmitTransaction` authentication、nonce/replay/dedup、owned
   object access/effects、preinstalled deterministic WASM、ordinary-asset fee composition、
   runtime structured transaction、SQLite/PostgreSQLのatomic state/object/receipt/outbox、
   両adapterのblob-reference mapping、runtime publication contractとlocal SQLite blob store、
   native HTTP bounds/error mapping、Rust client/CLIの
   pre-signing context/TLS boundaryとする。
3. **実装済み。** `SECURITY.md`または同等のaudit packetに、trust boundary、attacker capabilities、key/
   signer assumptions、supported surface、known limitations、out-of-scope項目、完全な検証
   command、private vulnerability reporting routeを記録する。既存stable vectorsと
   `npm ci --prefix adapters/cloudflare-workers` + `./scripts/check-all.sh`が固定audit commitで
   成功し、作業treeがcleanであることを記録する。

この3 criteriaを満たしたimmutable commitを対象に、直ちに初回第三者code security auditを
開始する。current in-scope codeのCritical/High指摘をremediationし、監査開始後に追加した
protocol-critical surfaceは同じ監査のdelta reviewまたは後続focused auditへ送る。最終
production releaseにはMedium以下を含むaccepted-risk記録と、cross-phase release gateが
要求する重大指摘解消を別途必要とする。

### 初回監査を待たせない項目の分類

| 項目 | 初回code audit前 | production/live activation前 |
| --- | --- | --- |
| FastCertificate + certificate publicationのatomic composition | out-of-scopeとしてdefer | multi-validator protocol v3 activation前に実装し、delta audit必須 |
| non-`SubmitTransaction` event family | 全family実装は不要。external ingressでfail closedだけ必須 | externally受理する各familyの認証・認可を実装し、delta audit必須 |
| checkpoint/state-root publication + verified restore | defer | production state recovery/commitmentをclaimする前に実装・rehearsal・delta audit |
| PostgreSQL transactional outbox | state/receipt/outbox atomic commit、indexed claim/ack、reconciliationはimplemented As-Isで監査対象 | provider運用、retention、monitoringを選定deploymentへ接続 |
| PITR、backup、off-host restore | defer | concrete RPO/RTOとdeployment topologyが要求する範囲でrelease前にrehearsal |
| HA、writer failover、fencing orchestration | durable fence contractは監査対象、実HAはdefer | chosen topologyとsplit-brain threat modelに基づきrelease前に証明 |
| TLS certificate rotation/revocation | current TLS/context boundaryは監査対象、lifecycle運用はdefer | chosen PKI/ingressのrotationをrelease前にrehearsal |
| real fault、ENOSPC、load/soak/capacity | 既存bounded fault証跡を監査対象とし、追加網羅はdefer | concrete SLO/limitsから必要caseとbudgetを決めてcertify |

この分類は項目の削除ではなく、**初回監査の開始条件からproduction operationsを外す**
resequenceである。現時点でPostgreSQL transactional outbox contractは再実装TODOではない。
database-process SIGKILL、pre-commit data/WAL ENOSPC、connection exhaustion、snapshot restore、
TLS commit-loss、PgBouncer rehearsalも既存As-Is evidenceとして監査へ提示し、未実装の
physical media faultや長期soakを同じ項目として重複実装しない。

## Generic Contract Publication Gate

**Design baseline (DR-0111, 2026-09-07):**
[`docs/architecture/generic-contracts.md`](docs/architecture/generic-contracts.md)
and [`docs/smartcontract/`](docs/smartcontract/README.md) are the accepted To-Be;
DR-0111 preserves dated As-Is evidence and replacement rationale. That design
record alone did not implement publication, instance isolation, public type
authority, or upgrades; later records implement the first three while upgrades
remain open. Standard Asset must use the same public facilities
as user contracts; remove superseded trusted-only paths and native Coin-body
settlement callbacks rather than retaining unreleased compatibility branches.

The deliverables in the [current roadmap](#current-delivery-roadmap) are the
work queue. The foundation checklist below records existing evidence, not
the unit at which further PRs should be split.

### Existing foundation evidence

The foundations below were implemented and validated in PRs #143–#151 on
2026-09-07, including the complete repository gate and independent tech-lead
review. They are prerequisites, not completed publish/instantiate/call features.

| Foundation | Accepted decision | Boundary |
| --- | --- | --- |
| Structural WASM admission and offline CLI validation | DR-0112 | Does not publish or execute code |
| Package origins and nominal type identity | DR-0113 | A reference alone grants no lineage authority |
| Signed artifact candidates | DR-0114 | Signature and commitment are not durable admission |
| Typed ABI and exact candidate dependency closure | DR-0115 | Declaration consistency is not published dependency provenance |
| Concrete type substitution and input metadata | DR-0116 | Type matching is not ownership or body integrity |
| Signed argument and constructor-body layouts | DR-0117–DR-0118 | Canonical values do not prove application invariants |
| Durable head/record/blob integrity reads | DR-0119 | Returned head assertions require later atomic validation |
| Request-ID-bound call intent and exact ABI binding | DR-0120 | No fee consent, instance/owner authority or execution consumer |

Detailed invariants and encoding evidence remain in the
[decision index](docs/architecture/decisions/README.md) and their regression
tests. Later foundations supersede earlier implementation gaps; historical
statements such as “body validation remains open” are not the live work queue.

### Remaining feature completion

- [x] **Local code publication ([DR-0121](docs/architecture/decisions/0121-durable-local-code-publication.md)):**
  immutable code/ABI/dependency records, committed publication policy, exact
  durable dependency provenance, shared nonce/receipt atomicity, CLI query and
  restart/replay/fencing are implemented. It remains an explicit local-devnet
  opt-in and grants no fee, instance, execution, peer-publication or object
  privileges. The outbox is intentionally absent. Stable vectors and complete
  validation evidence live with the decision record.
- [x] **Independent instance execution ([DR-0122](docs/architecture/decisions/0122-local-instance-execution.md),
  [DR-0123](docs/architecture/decisions/0123-unified-contract-calls.md)):**
  authenticated create/call, immutable instance and defining-code authority,
  bounded typed host operations, explicitly authorized cross-instance calls,
  CLI integration and atomic rollback/replay/fencing are implemented under the
  zero-fee local opt-in policy. An uncommitted candidate or signed ABI declaration
  grants no execution right. This completed local flow does not itself close fee
  parity, upgrades or public-network readiness; detailed regression and validation
  evidence lives with the decision records.
- [ ] **Standard Asset/fee parity:** replace trusted-only asset and fee
  paths with the ordinary public package and explicitly signed, committed and
  bounded fee settlement defined by
  [DR-0124](docs/architecture/decisions/0124-contract-fee-reservations.md).
  The public package, paid engine and internal fenced durable admission are
  implemented and locally validated without a grandfathered admission exception.
  The same Coin may fund fees and application work; a separate Coin is optional.
  Calibrated installation and external activation remain open.
  - [x] Generic bounded typed frame returns, profile-4 object metadata and ordered
    optional result handles, independent phase budgets, monotonic counters,
    savepoints and the private three-phase coordinator are implemented. Real-WASM
    regressions cover rollback, reservation isolation, output bounds and resource
    exhaustion. Detailed semantics and validation evidence are retained in
    DR-0124. Follow-up coverage should assert that memory exhaustion leaves fuel
    remaining and derive the event-framing allowance from the canonical encoder.
  - [x] Explicit paid Call/Instantiate/Publish consent, pinned contract policy,
    base/execution-only pricing and calibrated reserve/settle allowances. The internal
    consent/policy wire, immutable quoting, all-three-kind paid engine, exact
    Publish metering and independently verified result receipts are implemented.
    The durable handler reconciles replay before policy/object I/O and atomically
    commits paid effects, authorities, instance/publication records, nonce and
    receipt with writer fencing. Call/Instantiate/Publish remain one combined
    activation gate.
    [DR-0126](docs/architecture/decisions/0126-public-paid-contract-activation.md)
    was completed as one local-devnet activation slice on 2026-09-20. Its
    pre-installer prerequisites were:
    - [x] calibrated R/S values (`MIN_RESERVE_ALLOWANCE`/`MIN_SETTLE_ALLOWANCE`)
      and a positive execution-price floor for the existing shared phase-cap
      definition, measured against the pinned public Standard Asset WASM with
      a documented and test-enforced 2x conservative headroom, wired into
      policy validation;
    - [x] installed fee ABI/role admission (`validate_fee_interface_admission`),
      invoked before the quote and nonce commit, with a fail-closed matrix
      (exact-error assertions, arity 0/2, schema mismatch and
      reservation-typed-as-reserve-object cases) and a node-core regression
      proving the exact role-validator rejection reason before quote/nonce;
    - [x] authenticated historical object framing across protocol versions
      (`ObjectSnapshot` provenance plus a fail-closed historical-resolver
      selection that preserves the unconditional wrong-chain check even for a
      zero-object entrypoint), with old-protocol, missing-history and
      same-version regressions at both the `execution`/`node-core` unit level
      and through the real production native HTTP router (which now takes an
      explicit `history: Vec<HashSuiteResolver>` instead of a hardcoded empty
      slice);
    - [x] durable Consume source-deletion, depth-two paid-Publish dependency and
      paid-aware publication-query coverage. `PublicationQueryResult`
      (canonical frame `0x6418/v1`, normatively allocated, with stable
      Legacy/Paid vectors and a documented `MAX_PUBLICATION_QUERY_RESULT_BYTES`
      bound) carries a Paid record's *exact* stored `SignedPaidIntent`, never
      only a request identity; the Rust client independently
      re-authenticates it (context/signature, `PaidApplication::Publish`,
      origin, semantics) before returning it, with adversarial coverage for
      each of those checks plus malformed/oversized/trailing frames, and the
      CLI prints `published=true` only after that verification. Propagated
      through native HTTP, the Rust client and the CLI.
    The same slice also completed the signed closed installer/bootstrap marker,
    exact ordinary publication receipt, native HTTP/Rust-client/CLI paid
    submission and installed-policy query (DR-0126 items 4–5).
  - [x] Public Standard Asset transfer/split/merge/mint/burn and reserve/settle
    package implementation and activation hardening ([DR-0125](docs/architecture/decisions/0125-public-standard-asset-activation-hardening.md)).
    The public WASM package implements all amount transitions and checked supply
    arithmetic; the host does not decode or rewrite Coin amounts. Asset identity
    is the host-created Definition ObjectId and each Coin retains its own ObjectId.
    Fee/refund addresses are validated before reservation. The WAT compiler is
    pinned exactly, package construction verifies the canonical Digest32 framing
    used by every WAT check, and a permanent unchanged-WASM digest vector plus
    foreign-recipient and all-entrypoint same-code cross-instance authority
    regressions are implemented. This closes the package-local prerequisite only;
    it does not install or activate the package or paid policy.
  - [x] Fenced atomic signed genesis manifest installer, closed bootstrap marker
    and native HTTP/Rust-client/software-signer CLI activation
    ([DR-0126](docs/architecture/decisions/0126-public-paid-contract-activation.md)).
    Real file-backed SQLite integration crosses CLI → HTTP → durable admission
    for paid Publish, Instantiate and Call, including derived dependency/instance
    pins and charged successful results. The installer commits the ordinary
    publication receipt in the same fenced transaction and verifies it on restart.
  - [x] Remove asset-only grants/native composer and migrate the five historical
    asset CLI commands to the replacement paid route
    ([DR-0127](docs/architecture/decisions/0127-public-standard-asset-cli-migration.md)).
    Protocol v7 installs the public package and paid policy on every boot,
    composes an empty preinstalled catalog with no native fee composer, deletes
    the old WASM/catalog/seeding implementation, and makes `transfer`, `split`,
    `merge`, `mint`, and `burn` ordinary policy-pinned paid calls. One real
    SQLite/HTTP/CLI E2E covers all five operations, exact metered charge,
    close/reopen persistence, exact replay non-reapplication, request-ID reuse
    conflict with object/receipt/nonce invariance, and stale writer fencing.
  - [x] Add arbitrary Standard Asset creation and initial use through the same
    paid public facilities ([DR-0128](docs/architecture/decisions/0128-arbitrary-standard-asset-creation.md)).
    `create-asset` signs an ordinary `PaidApplication::Instantiate` against the
    already published Standard Asset code and creates a fresh instance-scoped
    Definition plus zero-supply TreasuryCap. The five asset verbs accept an
    all-or-none exact asset/instance pin while fees remain on the separately
    policy-pinned genesis asset. A real SQLite/HTTP/CLI E2E proves creation,
    mint, transfer, same-boot and post-restart replay non-reapplication,
    request-ID conflict invariance and writer fencing without a node-core asset
    branch. Complete repository gate、focused Codex Security scan、fresh Opus
    tech-lead reviewまで通過済みである。
  - [ ] Complete activation evidence and fresh combined review. Existing evidence
    now covers canonical vectors, same-source/transferred-source behavior, phase
    exhaustion and traps, charged/zero-charge receipts, exact replay, request
    conflict, SQLite restart/fencing, full CLI/HTTP paid activation, and a permanent
    independent JavaScript reconstruction of `0x6415/v1`. Still required are the
    fresh combined review, service-backed PostgreSQL fault evidence and the full
    public gate.
  Public admission additionally requires analysis of fresh-request unpaid
  phase-failure abuse; this local replacement is not a readiness claim.

The numbered criteria below are the complete gate; this grouping does not
remove any of their safety, validation or migration obligations.

**Priority decision (2026-09-07):** protocol固有のpreinstalled moduleやその運用補助を
積み上げ続ける前に、permissionlessな汎用contract surfaceを実装する。DR-0110の
supply-accounted mint/burn sliceを完了した直後の順序は、(1)このgate、(2)arbitrary
Standard Asset create-asset、(3)FastVoteとする。Asset固有の新機能、Unique Asset、multisig、
追加のproduction background processingはこのgateを追い越さない。CLI Developer MVPの
historical completion criterion 3が任意uploadを当時のMVP外とした事実は変更しないが、
post-MVPの現在はこれを最優先のopen sliceへresequenceする。

Completion criteria:

1. authenticated signerがbounded canonical module publication requestを送れる。requestは
   exact chain id、protocol version、epoch、package origin/code revision、canonical WASM、manifest、
   ABI/semantics commitmentをbindし、unknown field、trailing bytes、unsupported import/export、
   duplicate/reused package origin/code revisionをfail closedする。
   初回publicationからexact dependency revisionとauthenticated lineageをbindし、
   commitment検証contextをcurrent protocol versionと独立に永続化する。
2. nodeはWASM validation、deterministic resource bounds、code/manifest/ABI/semantics hashを
   trusted protocol contextで再計算し、immutable code/ABI/dependency publication record、nonce、receipt、
   outboxを一つのfenced durable invocationへatomic commitする。失敗時は部分publicationを
   残さない。daemon、background loop、persistent connectionをcorrectness requirementにしない。
3. call transactionはcallerが実行bytesや未commit manifestを注入できず、publish済みのexact
   `(package origin, code revision, original publication context, artifact commitment)`
   (artifactはWASM、ABI/manifest、semantics、exact dependenciesをbindする) に加えてsigned target
   instance identity、authorized instance/code revision、exact dependency lineage/revisionsを
   参照する。typed ABI、declared object access、owner policy、gas/resource bound、canonical
   argumentsを実行前に検証し、preinstalled moduleと同じdeterministic execution/effect/fee/replay
   boundaryを使う。instantiationはauthenticated instance scope内でのみadmitし、deterministic
   instance idを割り当て、同じidの既存instanceのabsenceを検証してcollisionをfail closedで
   拒否する。instance record、initial state、authority、nonce、receipt、outboxを一つのfenced atomic persistenceへ
   commitし、部分的なinstance作成を残さない。initializerはcodeがupgradeされたことのみを
   理由に再実行できない。
4. Rust clientとCLIに`contract publish`、`contract instantiate`、`contract call`を追加する。各commandはTLS endpoint
   validationとは別にlocally expected protocol contextを確認し、queryしたcommitmentとsigned
   bytesを一致させてから署名する。software signerを最初のsurfaceとし、Ledgerはexact
   clear-signing policyが追加されるまでfail closedする。
5. real file-backed SQLite E2Eでpublish、instantiate、call、same-boot/post-restart exact replay、writer-generation
   fencing、request-id reuse conflict、duplicate initialization/instance collision rejectionを
   検証する。conflict/rejection時はmodule registry/catalog、application objects、fees、receipt、
   nonce、outboxが不変であることをcanonical bytesで比較する。ここでrejectionはpre-execution
   rejectionを指す。実行trapのfee-only settlementは別途検証し、application rollback、確定した
   fee/receipt、replayでの再課金なしを確認する。同じcodeから作成した複数instanceがstate、
   capability、admin権限を共有しないindependent instanceであることをtestする。
6. stable vectors、negative/adversarial tests、complete repository gate、fresh tech-lead reviewを
   通過する。ここまで完了する前にpermissionless contract platform、public testnet readiness、
   production/mainnet readinessをclaimしない。
7. publicationとinitializationを分離し、同じcodeを使うinstance間でstate、capability、
   admin権限を共有しない。型のlineage/provenance、defining-codeの作成・変更・消費権限、
   owner authorization、typed cross-contract call境界をhostで検証する。既存のtrusted
   policyをpublisherが宣言するだけの方式は不可とする。
8. Standard Assetと独立にpublishしたcontractが同じCreate/Transfer/Consume/typed-call/
   fee/persistence機構を使うことを検証する。別moduleからのCoin amount書き換え、型の
   偽造、instance/capability取り違えを拒否する。mint/burn/split/mergeの算術をnode-coreへ
   移さず、trusted-only policy経路とnative asset settlementの置換・削除を完了条件にする。
   fee settlementはgovernanceがpinした特定のcommitted contract revisionのみを使い、
   settlementをbounded resource/gasへ制限する。callerや実行requestが実装moduleや
   treasury送金先を選択・redirectすることを禁止し、fee決済処理自体がさらなるfeeを
   再帰的に課さないことを検証する。pinned revisionの変更はgovernance手続きを経た
   場合のみ許可する。

Related revision/migration slice (same accepted design, separately reviewable
after the initial immutable-code publish/instantiate/call slice):

- [ ] Implement scoped upgrade authority and irreversible relinquishment,
  separating revision publication from authority to migrate state.
- [ ] Implement bounded atomic migration and host-enforced rejection of old
  code on migrated state; test unsupported mixed revisions and dependency
  substitution. Define concrete compatibility and migration authorization rules.
- [ ] Include shared upgrade/revision state in ordering and fencing; preserve
  owned-object fast-path eligibility only when all dependencies permit it.

These revision/migration items remain open and must pass their own stable-vector,
adversarial, SQLite restart/replay, complete-gate, and review evidence before
upgrade support is claimed. They do not authorize new Asset-specific work to
bypass the generic publication gate.

## Asset Standards Gate

**目的（2026-09-06、docs/architecture/decisions/0104-asset-standards-gate.md
DR-0104）:** Initial Code Security Audit Entry Gate後に追加するasset surfaceを、
builderまたはpublic testnetへ露出する前に固定する。fungible standardは
**Standard Asset v1**、NFT-like standardは**Unique Asset v1**と呼ぶ。Standard Asset v1は
Sui-likeのowned `StandardAssetCoinV1` objectとtyped capability authorityを使い、
definition、coin、capabilityを別objectにする。各coinはexact `AssetId` + integer amountを
持ち、1 ownerが同じassetの複数coinを所有できる。object identity/versionが
anti-double-spend/version mechanismであり、coin bodyの別sequenceはv1に入れない。

**Current status:** DR-0104による名称、モデル、development fixtureのreplacement、fail-closed activation
boundaryはaccepted。認証に使ったprofileのowner policyでauthenticated executionの
Address-owned outputをcommit前に再検証するprerequisiteに加え、`AssetId`と
`StandardAssetDefinitionV1`/`StandardAssetCoinV1`/`StandardAssetMintCapabilityV1`/
`StandardAssetTreasuryCapV1`
のcanonical identity/value schema（`crates/standard-assets`）がimplemented As-Is。
`AssetId`のcanonical type ID（`0x7001`）は同じprotocol conceptへそのまま使い、`fees`から新しい
dependency-lightな`standard-assets` crateへownershipを移した。各consumerは
`standard-assets`から直接importし、未リリースAPIのcompatibility facadeは設けない。Sunrise Edgeはまだreleaseされておらず、
devnet-local `0xF001`/`0xF010`/`0xF011`はpublic compatibility obligationではない
development fixtureであり、Standard Asset v1 activationはこれをmigrateや
dual-supportではなくreplaceする前提とする。local devnetではtransfer/split/mergeが有効で、
既存derived assetに対するcapability-authorized mintはDR-0109のbounded devnet sliceとして
実装・complete repository gate検証・fresh independent tech-lead review済みである。その後の
public contract replacementはDR-0127でfive verbsをgeneric paid Callへ移し、DR-0128で同じ
published codeのordinary paid Instantiateによる任意asset作成とinitial mint/transferを
実装した。以下の残存criteriaはopenであり、metadata、capability delegation/destruction、
Unique Asset v1、builder/public-testnet asset surfaceはまだ有効ではない。

### Completion criteria

1. **実装済み（documentation only、DR-0104）。** Standard Asset v1と
   Unique Asset v1の名称、owned coin + typed capabilityの分離、object-versionによる
   double-spend防止、devnet fixtureのreplacement boundaryとfee integration boundaryをarchitecture decisionとして固定した。
2. **実装済み（prerequisite only）。** authenticated executionが返すCreated/Mutated
   objectのAddress ownerを、transactionを認証した同じprofile-versioned policyで
   object mutation構築前にfail closed再検証する。これ自体はCreateを認可しない。
3. **部分実装。** identifier namespace全体をauditし、`HashDomain::AssetId = 0x000E`/
   `HashPurpose::AssetId`と`0x70xx`/`0x71xx`帯の`StandardAssetDefinitionV1`
   (`0x7101`)/`StandardAssetCoinV1` (`0x7102`)/`StandardAssetMintCapabilityV1`
   (`0x7103`、historical frozen)/`StandardAssetTreasuryCapV1` (`0x7107`)を
   additiveにallocateした。`derive_asset_id`はchain、protocol
   version、Standard Asset v1、authenticated creation authority、canonical
   typed `AssetCreationSeed`、epoch/hash-suite scheduleをbindし、`HashSuite::algorithm_for`が
   選ぶprotocol-configuration hash algorithmのみを使う（caller-selected algorithmは
   不可）。definitionは作成時protocol versionを明示的に保持し、別versionのresolverでの
   再検証をfail closedにする。deterministic stable vectorとnegative/adversarial testをpinした。
   new coin `ObjectId`はcoin固有formulaを増やさず、既存のgeneric versioned
   created-object derivation（exact signed transaction hash context +
   creation ordinal）を共有する。DR-0108のsplitはcreation ordinal zeroを
   1個だけ許可するcommitted policyによりこの導出を実際に使う。
4. **部分実装。** `StandardAssetDefinitionV1`、`StandardAssetCoinV1`、
   `StandardAssetMintCapabilityV1`、`StandardAssetTreasuryCapV1`を別々のbounded canonical schemaとして
   `crates/standard-assets`に実装し、unknown version/field/tag、non-canonical
   bytes、unknown hash algorithm、zero coin amountをfail closedにした。
   duplicate identityはDR-0108のsplit Create pathで、exact `Absent` pre-read、
   current/tombstone collision、duplicate effect、extra Createをfail closedにする。
   DR-0105（2026-09-06、
   `docs/architecture/decisions/0105-typed-asset-abi-foundation.md`）により、
   `AssetId`をこの3つのschema全てのnominal ABI型引数とするbounded typed-ABI
   foundationを`crates/abi`（[section 18](#18-abi-as-execution-and-concurrency-protocol)参照）と
   `crates/standard-assets`（3つのconstructor定数、schema version、deterministic
   registry、tag constructor、type-id helper）に追加した。`hashing`の新しい
   `HashDomain::ObjectType`/`HashPurpose::ObjectType`はprotocol_version/
   schema_versionを含まない別frameを使い、object nominal type identityが
   protocol upgradeとschema migrationを跨いで安定することをstable vectorと
   adversarial testでpinした。DR-0106（2026-09-06、
   `docs/architecture/decisions/0106-typed-entrypoint-owner-transition.md`）により、
   `node-core`側に`PreinstalledTypedEntrypointPolicy`/`PreinstalledOwnerTransitionPolicy`の
   canonical policy codecと、`PreinstalledWasmMachine::transition`がWASM実行前に
   `abi::verify_entrypoint_inputs`を呼ぶ検証配線、成功後にnode-core自身が
   owner-only mutationをsynthesizeしtranslation boundaryで独立再検証する配線を追加した。
   DR-0107（2026-09-06、
   `docs/architecture/decisions/0107-standard-asset-v1-devnet-activation.md`）により、
   この2つのpolicyを実際にcommitする最初のpreinstalled module catalog entryを
   devnetへ配線した：`STANDARD_ASSET_TRANSFER_ARGS_V1`（`0x7104`）、devnet
   protocol version 3→4のbump、旧`sunrise.devnet.asset_account.v1`
   fixtureの削除とprotocol-v4 Standard Asset v1 `Coin<A>` whole-object transfer
   moduleへのreplacement、derivation-basedな devnet `AssetId`、
   `StandardAssetCoinFeeComposer`、CLI `transfer`サブコマンドの
   `--source-coin`/`--recipient`/`--fee-coin`ベースへの更新を含む。これにより
   `Create`パスなしで到達可能な、初のend-to-end owner change経路が生まれた。
   DR-0108のdevelopment sliceでbounded partial split/mergeを追加し、DR-0109のdevelopment
   sliceで既存devnet asset向けcapability-authorized mintを追加した。DR-0110以後、これらの
   unreleased fixtureはそれぞれ別のdisabled module IDへ隔離され、canonical moduleはversion 1から始まる。
   arbitrary asset Create、arbitrary discovery/coin selection/dust、Unique
   Asset v1、multisig、Ledgerのnew entrypoint対応、production fee aggregation、
   public-testnet readinessは引き続き未実装のまま。
5. **実装済み（DR-0108、bounded devnet slice）。** whole-coin transferはcanonical signed
   recipientへのexact owner changeとしてprotocol-v4 devnet/CLI/restart E2Eまで実装済み。
   DR-0108 development fixtureのpartial splitはsender remainderのMutate + recipient coinの
   exactly-one Create、mergeはsame-assetのsender-owned primaryをchecked sumへMutateし、
   secondaryをConsumeする。mergeでnew coinはCreateしない。recipientはsignせず、recipient
   stateもread/writeしない。exact one-create policyはsigned transaction-derived id、
   source-derived type/schema、recipient projection、Absent-only pre-readをnode-coreで
   独立検証する。owned-only operationはglobal total orderを避けるが、validator
   quorum/certificationは必須とする。任意coin discovery/selection、dust、burnと
   ergonomic client hidingは後続とする。DR-0109のmintは既存devnet assetに限定し、
   `Read MintCapability<A>` + fee `Write Coin<A>`からexact one recipient coinを作る。
6. **部分実装（split Createまで）。** exact committed preinstalled-module policy + protocol
   version 4/5の二重gateで、
   existing coinのbounded owner-only changeをdevnetに限定して有効化済み。DR-0108のprotocol-v5
   splitではadditive module version + exact governance-committed policyでCreateを有効化し、module/version/
   entrypoint、signed recipient、input/output count/aggregate bytes、exact outputs、type/schema/owner/
   id derivationとcreated-bodyのnominal typeをnode-coreが独立検証する。balance arithmeticと
   conservationはcommitted WASMがchecked演算で実施し、node-coreはasset固有balanceをdecodeせず、
   exact absent headを読んでnonce/receipt/fee/outboxとatomic commitする。current/tombstone
   collisionは拒否する。generic contract Create、任意asset作成、unsigned owner change、
   caller-selected IDはfail closedのままにする。DR-0109のmintだけは同じgeneric exact-one
   verificationをexact module version/entrypointへ別policyとしてcommitしている。
7. **部分実装。** protocol-v4 devnetはStandard Asset v1 fee coinをordinary objectとして扱い、
   same ownership/exact-version/checked-arithmetic/atomic-effect ruleを使う。native coinやprivileged
   balanceは追加していない。一方、現在のsingle treasury coinはlocal-devnet限定のhot spotであり、
   production fast pathへは持ち込まない。certified fee outputのcustody化と
   active-validator配分はDR-0137で実装済みだが、signed claim/payoutとその
   race/restart検証はPhase 3の残作業（下記参照）。
8. **whole-coin transfer activation sliceは実装・検証済み。**
   canonical/stable/adversarial/replay/fee-compositionとreal file-backed SQLite
   restart testを実装し、commit `891152fc098e080b5d61a2242bc997e861553cc6`でcomplete
   repository gateを通過した。Initial Audit後に追加したprotocol-critical surfaceとして、
   base `8c5a7548ca525f462ec805922ab596fb78b59407`との差分から抽出した26個のsource-like
   fileを対象にfocused delta security reviewも完了し、reportable findingは0件だった。
   1件のcandidate（同一local-devnet data directoryでtrusted operatorがseed owner一覧を
   変更した場合の旧coin併存）は、`--dev-owner`がseed provisioningであってruntime
   authorization/revocation listではなく、network callerから変更不能で新しい権限獲得も
   ないためnon-reportableと判定した。これはproduction security auditやpublic-testnet
   readinessの宣言ではない。DR-0108のsplit/mergeは別PRのdevelopment sliceとして
   実装し、exact-one Create、Absent-only collision check、checked split/merge arithmetic、
   real file-backed SQLiteでのsame-boot/post-restart exact replay non-reapplication、writer-generation
   fencing、request-id reuse時のsource/created/fee/treasury object・両receipt・nonce不変を
   focused E2Eとcomplete repository gateで検証した。merge前にこの新しいprotocol-critical
   deltaへのfresh independent reviewを要求する。generic Create/任意asset作成/Unique Asset/
   public surfaceは引き続き各sliceで新しいdelta reviewを要する。
9. **実装・検証済み（DR-0109、bounded devnet mint development slice）。** 既存derived
   devnet assetだけに`mint`を追加したfixtureは、DR-0110以後は別のdisabled module IDに隔離する。
   startupはimmutable `StandardAssetDefinitionV1`と、first dev ownerが所有するreusableな
   `StandardAssetMintCapabilityV1`をatomic pairとしてseed/restart-verifyする。typed ABIは
   `Read MintCapability<A>` index 0とfee `Write Coin<A>` index 1を同じ`A`へunifyし、
   committed WASMがnonzero amountのrecipient `Coin<A>`をexactly one Createする。
   node-coreはordinal-zero ID、recipient、type/schema/body projection、exact `Absent` headを
   asset-genericに独立検証する。CLIはexpected protocol context、nonce、capability/fee coinの
   sender ownershipとcanonical body、shared `AssetId`、distinct treasuryをsign前に検証し、
   Ledger selectionをnetwork/device access前にfail closedする。real file-backed SQLiteでの
   same-boot/post-restart exact replay、writer generation、request-id conflict時の全関連object/
   receipt/nonce不変とcomplete repository gateはunrestricted local runで検証済みである。
   protocol-critical deltaへのfresh independent tech-lead reviewもAPPROVEで完了した。
   capabilityはreusableで供給上限を持たないdevnet fixtureである。

10. **実装・検証済み（DR-0110、supply-accounted mint/burn slice）。** protocol-v6は
    canonical `sunrise.standard_asset.v1`をmodule version 1としてactiveにする。unreleasedな
    transfer/split-merge/unbounded-mint development fixtureは別module IDのdisabled entryへ隔離し、
    canonical moduleのversion番号を消費しない。active mintはowner-held
    `Write TreasuryCap<A>`を使う。
    `StandardAssetTreasuryCapV1` (`0x7107`)はexact `AssetId`、current
    `total_supply`、fixed nonzero `max_supply`をcanonical stateとして持つ。mintはcapを
    checked-addしてexact one recipient `Coin<A>`を作り、whole-coin burnはcapを
    checked-subしてsender-owned coinをConsumeする。両方ともdistinct fee coinとfinal hidden
    fee-treasuryを同じatomic commitへ含める。startupは全seed coinのinitial sumをcapへ入れ、
    immutable version-one cap historyと現在のadvanced headを再起動時に検証する。split/merge/
    burnでtombstoneになったseed coinはretained historyを検証し、再作成しない。CLIは
    supply bound、owner、canonical body、shared AssetIdを署名前に検証し、Ledgerをnetwork/device
    access前にfail closedする。real file-backed SQLite E2Eはmint/burnのsame-boot/post-restart
    exact replay non-reapplication、writer-generation fencing、request-id conflict時のdefinition/cap/
    tombstoned coin/fee/treasury object、全receipt、nonce不変をcanonical bytesで検証した。
    `npm ci --prefix adapters/cloudflare-workers`と`./scripts/check-all.sh`は通過し、fresh read-only
    Opus tech-lead reviewもblocking findingなしで`APPROVE`した。これはgeneric contract publication、
    DR-0110単独ではarbitrary asset creation、public-testnet、production/mainnet readinessの
    完了を意味しない。

11. **実装・ローカル検証済み（DR-0128、public arbitrary creation slice）。**
    `create-asset`はfee policyが認証したpublic Standard Asset codeを別のcreator-scoped
    instanceとしてordinary `PaidApplication::Instantiate`し、initializerがhost-derived
    Definition ObjectIdをasset identity `A`としてzero-supply `TreasuryCap<A>`を作る。
    node-coreへasset専用Create、constructor、body decoder、supply rewriteを追加しない。
    five verbsはall-or-none `--asset`/`--instance-ref`でexact application instanceを選べるが、
    fee reserve/settleは引き続き別のgenesis instance/assetへ固定される。real file-backed
    SQLite/native HTTP/CLI E2Eはcreate→mint→transfer、wrong genesis capのsign前拒否、
    same-boot/post-restart exact replay非再適用、request-ID conflict時の両instance・objects・
    receipts・nonce不変、writer-generation fencingを検証する。complete repository gate、
    focused Codex Security delta scan（reportable finding 0件、scan
    `6eb51995-7f20-4ee4-b836-31f3b1f8e03c`）、fresh read-only Opus tech-lead reviewは
    通過済みである。この項目はmetadata、public-testnet、production/mainnet readinessを完了しない。

metadata authenticity、partial burn、authority capabilityのdelegation/destruction、freeze/close/
allowance、governed fee-asset admission、Unique Asset v1の実装は後続sliceである。
これらを完了扱いにせず、このgateはそれぞれの後続実装とdelta reviewを
追跡し続ける。

## FastVote Certified Execution Gate

FastVote/multi-validator integration (roadmap item 5) is delivered across
four phases. This gate is the live status tracker for all four; it does not
replace or loosen the hard activation constraint recorded in the "Generic
Contract Publication Gate", "CLI-First Node Production Gate", and
`docs/architecture/core-protocol.md` section 8, which independently keeps
protocol version 3 live activation blocked until `FastVote`/`FastCertificate`,
certificate publication, and every other externally accepted event family's
authenticated/authorized ingress are implemented, atomically composed, and
S4/S5 plus independent security/release gates are complete.

**FastVote is complete only after phase 3.** Phase 1's static signed genesis
set permits a closed local developer rehearsal, not an externally reachable
multi-validator protocol-v3 activation. The previously broad "testnet after
phase 1" wording did not override the independent authenticated-ingress,
certificate-publication, S4/S5 and security/release hard constraints in this
document. An earlier limited multi-validator testnet would require an
explicitly reviewed non-production activation profile; none exists yet.
Validator-set changes, slashing, and fee/reward distribution are FastVote
completion criteria in this plan, not vague "production" deferrals.

- [x] **Phase 0 — canonical types/codec/signature/quorum library
  ([DR-0129](docs/architecture/decisions/0129-fastvote-fastcertificate-fast-path.md)).**
  `FastVote`/`FastCertificate` canonical types, wire codec, and a stateless,
  epoch-scoped `FastPathCertifier` signature/quorum aggregation library in
  `crates/consensus`, independent of `ChainedHotStuff`. Implemented, tested
  (32 co-located unit tests with real Ed25519 signing), and vector-checked
  (`scripts/fast-vote-vectors.mjs`). Does not lock objects, apply effects,
  publish anything durably, or reach any ingress.
- [x] **Phase 1 — owned-object certified execution
  ([DR-0130](docs/architecture/decisions/0130-owned-object-certified-execution.md)).**
  Implemented and locally validated as one coherent local `node-core` slice:
  1. signed paid intent authentication reusing the existing
     `execution::paid_execution::authenticate_paid_intent`/DR-0124 boundary, starting from
     canonical signed intent bytes on both prepare and apply (never a
     caller-supplied tx/effects hash);
  2. exact replay reconciliation before nonce/lock/execution work;
  3. nonce/policy/object/ABI validation reusing the existing paid-path
     validation layers;
  4. deterministic paid execution reusing the existing paid execution
     engine and fee composition (DR-0087, DR-0126/DR-0127);
  5. a canonical commitment over the complete staged commit — effects,
     pending post-certificate nonce advance, receipt outcome, fee settlement, and every locked
     object's `(id, version, digest)` — not merely the `ExecutionEffects`
     hash;
  6. durable exclusive sender-authorized owned-object version locks plus a
     sender/epoch nonce lock and exact current-nonce assertion,
     permanent until apply (no timeout/clock-based unlock after a vote in
     phase 1);
  7. byte-stable `FastVote` (re-preparing an already-prepared intent returns
     the identical signed vote, not a fresh signature);
  8. quorum certificate verification against a static signed genesis
     validator set for one frozen epoch;
  9. atomic certificate apply: application/fee-escrow mutations, nonce advance,
     receipt, certificate publication, settlement metadata, and lock release
     commit together or not at all, and a certificate that does not match
     the locally recomputed commitment is rejected without applying or
     releasing the lock.

  The current paid fee recipient becomes protocol escrow for this phase
  boundary; distribution to the committed active validator set is phase 3, not
  implemented here. Durable prepared/lock/certificate/settlement records use
  the reserved fast-path namespace and canonical frame IDs `0x641B`-`0x6425`.
  The gate includes 25 `node-core` fast-path tests, four independent
  file-backed SQLite validator stores with close/reopen replay, 10 signed
  genesis tests, and independent `scripts/fast-path-vectors.mjs`
  reconstruction. No new externally reachable event family goes live in
  phase 1. See DR-0130 for the exact safety invariants, evidence, and deferred
  Phase 2 recovery/lifecycle work.
- [x] **Phase 2 — validator lifecycle** (implemented and reviewed, 2026-09-22;
  [DR-0131](docs/architecture/decisions/0131-fastvote-validator-lifecycle.md)
  is the accepted Phase 2 architecture and fully specifies slice 1;
  slices 2-4's safety contract is fixed there. Slice 2's detailed wire/API
  design is accepted and now implemented per
  [DR-0132](docs/architecture/decisions/0132-fastvote-epoch-transition.md);
  Slice 3's detailed design is accepted and now implemented per
  [DR-0133](docs/architecture/decisions/0133-fastvote-equivocation-evidence.md),
  and Slice 4's authorization/ingress boundary is implemented per
  [DR-0134](docs/architecture/decisions/0134-fastvote-authorization-boundary.md),
  with its companion code, tests, complete gate, and fresh reviews landed).**
  Epoch/validator-set transitions,
  retired/wrong-epoch rejection, relay/event-family authorization, explicit
  equivocation evidence, and multi-validator fault/restart tests. Must
  guarantee that any lock-recovery procedure it introduces can never permit
  two conflicting certificates to apply for the same object version (phase 1
  defines no recovery path at all); DR-0131's key transition safety proof is
  exactly this guarantee, restated in terms of a CAS-fenced epoch record.
  "Retired validator" means only absent from the committed current epoch's
  validator set after a certified transition; no locally mutable membership
  action exists, so every node derives authority from the same committed set.
  Tracked as four completed slices:
  - [x] **Slice 1 — general mutation authorization/fencing layer
    (implemented, 2026-09-22; see DR-0131's slice completion criteria).**
    A committed `FastPathEpochRecord` (`0x6426/v1`, `crates/node-core/src/
    local_instance_state.rs`) holding only `current_epoch`,
    `current_validator_set_digest`, optional `previous_epoch`, and
    `activated_at_checkpoint` — no locally mutable retirement list and no
    invented revision field (the durable store's own CAS revision fences the
    record) — created atomically with genesis validator-set activation
    (`crates/node-core/src/genesis.rs`, extending the existing DR-0126
    install commit); an epoch-stamped `FastPathLockRecord` (`0x641B`,
    canonical v1 redefined in place, no v2 split since the repository is
    unreleased); a shared `crates/node-core/src/mutation_fence.rs` two-tier
    fencing model — every mutation path (fast-path prepare/apply, direct
    paid, local execution, local publication, and every authenticated
    `SubmitTransaction` path that advances a nonce — object-read-only,
    owned-effects, and preinstalled WASM) CAS-fences the epoch
    record and honors any held object/nonce lock, and validator-authorized
    prepare/apply additionally CAS-fences the active per-epoch
    `ValidatorSet` row and checks its digest against the epoch record —
    rejecting a non-current epoch, a signer absent from the committed active
    set (enforced for free by `consensus::FastPathCertifier`'s existing
    membership lookup once bound to the fenced set), or a lock/nonce-lock
    conflict before any mutation; duplicate validator public-key rejection
    in `validator_set::ValidatorSet::new` (enforced at genesis for free);
    the reserved synthetic request-id check
    (`local_instance_state::reject_reserved_request_id`) applied at each of
    the four current event/mutation families' own admission boundaries
    (paid intent, local-execution intent, publication submission, and the
    `SubmitTransaction` event envelope), with the distinct named
    `fastpath_synthetic_prepare_request_id` internal/system construction
    path unreachable from external input; and closed a direct object-lock
    branch gap in `local_execution::handle_local_execution`'s `Write`/
    `Consume` inputs and once at the common authenticated `SubmitTransaction`
    durable boundary for read-only nonce, owned-effects, and preinstalled-WASM,
    left uncovered by phase 1's evidence. No epoch-transition procedure and
    no lock reclamation exist yet. This repository is unreleased, so the
    canonical-layout change (the redefined `0x641B` and the new `0x6426`
    singleton) was made in place with no migration: any local database
    created before this change must be recreated, and restart-verify and
    every authenticated mutation path fail closed if the epoch record is
    absent (see DR-0131's consequences/deferred section). Evidenced by
    dedicated adversarial tests
    (dedicated wrong-epoch rejection at prepare, apply, direct paid, local
    execution, object-read-only `SubmitTransaction`, owned-effects
    `SubmitTransaction`, and preinstalled-WASM `SubmitTransaction`;
    validator-set-digest-mismatch rejection at prepare and apply; an
    unknown-signer rejection at prepare and at apply against a
    rogue quorum, an epoch-record CAS-fence conflict test, a duplicate
    validator public key rejected by `ValidatorSet` and at genesis install,
    a fast-path object lock now blocking `local_execution`'s direct `Write`
    branch from a different sender so the nonce-lock cannot be masking it,
    a fast-path object lock blocking the owned-effects `SubmitTransaction`
    path, and a nonce lock blocking the object-read-only path) plus
    independent stable Rust/JS vectors for
    `0x6426` and the redefined `0x641B`
    (`scripts/fast-path-vectors.mjs`). Does not by itself close this phase 2
    gate entry, does not implement epoch transition or lock recovery, and
    does not make retired-validator/wrong-epoch rejection end-to-end
    observable beyond genesis-set membership — see DR-0131 for the exact
    records, invariants, key transition safety proof, and completion
    criteria.
  - [x] **Slice 2 — epoch transition (implemented, 2026-09-22; safety
    contract fixed by DR-0131; detailed design accepted and implemented per
    [DR-0132](docs/architecture/decisions/0132-fastvote-epoch-transition.md)'s
    slice completion criteria).** Outgoing-set-certified strict `e -> e+1`
    transition: a distinct `EpochTransitionVote`/`EpochTransitionCertificate`
    frame family (`0xD009`-`0xD00B`, `crates/consensus/src/
    epoch_transition.rs`) under its own `"fast-path-epoch-transition-v1"`
    signature domain, structurally mirroring `FastPathCertifier`; node-core
    `propose_and_vote`/`activate` (`crates/node-core/src/
    epoch_transition.rs`) deriving and atomically installing the five-row
    activation write set (the permanent `0x6427` transition-audit record,
    plus the `e+1` validator-set/execution-policy/paid-fee-policy/
    publication-policy rows) in one `commit_durable` alongside the rewritten
    `FastPathEpochRecord`; `genesis::install_genesis_with_history`'s
    restart-verify replaced with the full per-step decode/load/verify/bind
    chain algorithm (DR-0132 §7, correction C1); lazy CAS-only
    stale-object-lock reclamation and stale-prepared-record supersession at
    every direct mutation path and `fast_path::prepare`; a read-only
    `query_committed_epoch_state`. Byte-stable transition votes and atomic
    next-set/epoch activation. Retired-validator and wrong-epoch rejection
    are now end-to-end observable. Fixed four latent bugs this slice's own
    adversarial evidence found: `propose_and_vote`'s "already exists" check,
    as first implemented, treated a transition record present at
    `current_epoch + 1` as an innocuous already-activated outcome; because
    `activate` installs the live epoch record and that row atomically in the
    same commit, a literal replay of that combination is partial or corrupt
    prior state, not `AlreadyActivated`, so `propose_and_vote` fails closed
    on it instead and returns `EpochTransitionVote` directly rather than a
    `TransitionProposalOutcome` wrapper whose second variant was never
    reachable (see DR-0132's implementation-review revision). That fix's own
    first cut then overstated its claim -- `propose_and_vote`'s epoch fence
    and its transition-record read are two separate reads, not one atomic
    operation, so a concurrent `activate` genuinely can commit between them;
    `propose_and_vote` now re-reads the live epoch record when it observes a
    transition row at `current_epoch + 1` and returns the retryable
    `StateConflict` if the live epoch has advanced beyond `current_epoch`,
    reserving `Invalid` for a live epoch record that still reads
    `current_epoch` (DR-0132 §3.B step 4, §6, concurrency/canonicalization
    revision). `derive_activation_set` also encoded `next_validators` in
    caller-supplied order rather than canonicalizing by `ValidatorId` first;
    `ValidatorSet::new` already canonicalizes its own digest, but the
    committed `FastPathValidatorSetRecord` bytes and `activation_digest`
    were not order-invariant, so independently derived permutations of the
    identical operator-authorized set could disagree on `activation_digest`
    and never quorum -- fixed by sorting before validation/encoding (DR-0132
    §3.A step 2). And `fastpath_synthetic_prepare_request_id`'s preimage did
    not mix in the epoch directly, so reusing the same original request id
    at the next epoch under an unchanged hash suite produced the identical
    synthetic receipt id as the outgoing epoch's own prepare, silently
    breaking C5's stale-prepared-record supersession; the epoch is now mixed
    directly into the preimage. Evidenced by the headline four-independent-
    SQLite test (genesis, a DR-0130 baseline cycle, independently derived
    and certified transition votes, atomic activation, restart-verify, and a
    fresh prepare/apply cycle at `e+1`), all seven restart-verify
    tamper-surface tests plus the two-step positive chain (DR-0132 §7),
    stale-object-lock reclamation with negative controls across direct paid
    commit, local execution, fast-path prepare, and the authenticated
    owned-effects `SubmitTransaction` boundary, stale-prepared-record
    supersession, an `activate`-vs-`apply` and an `activate`-vs-`activate`
    (including the outgoing fee-policy CAS fence) real-thread race, retry
    safety after an indeterminate `activate` commit, retired-validator
    rejection at `e+1`, a hash-suite switch landing exactly at the
    transition epoch, wrong-chain/protocol rejection on the
    already-activated path, `0x6427` codec adversarial tests, the benign
    concurrent-activation-vs-orphan-row distinction above, the
    `next_validators` permutation-invariance test, and a genuinely
    quorum-signed certificate bound to the wrong outgoing validator-set
    digest, plus independent stable Rust/JS vectors for `0xD009`-`0xD00B`
    and `0x6427`-`0x6428`. `next_validators` is operator-supplied but
    authorized only by the outgoing-set quorum certificate, not by
    governance. Does not by itself close this phase 2 gate entry (DR-0134's
    companion implementation owns that) and does not authorize testnet or
    production activation of any new ingress — see DR-0132 for the exact records,
    invariants, and completion criteria.
  - [x] **Slice 3 — equivocation evidence (implemented, 2026-09-22; see
    [DR-0133](docs/architecture/decisions/0133-fastvote-equivocation-evidence.md)'s
    slice completion criteria).**
    Explicit canonical equivocation evidence covering same-transaction
    conflicting-outcome (`0xD00D/v1`), cross-transaction same-object-version
    (via `0xD00E/v1` and the in-place `FastVote`/`FastCertificate`
    `locked_objects_digest` extension and `0xD00C/v1`
    `LockedObjectSetPreimage`, no v2/compat layer), and epoch-transition
    conflicting-target misconduct (`0xD00F/v1`), with durable record `0x6429/v1`
    in `crates/node-core/src/equivocation.rs`. Strict recheck of
    `locked_objects_digest` on exact prepare replay and before certificate
    apply; normalized signature-excluding evidence identity; historical
    validator resolution anchored against the restart-verified transition
    chain; transactional, tamper-detecting store/query with deterministic
    `AlreadyRecorded`; comprehensive unit/adversarial tests across `consensus`
    and `node-core`; and independent wire vectors in `scripts/fast-vote-vectors.mjs`
    and `scripts/fast-path-vectors.mjs`. Phase 3 economics/slashing remains incomplete.
  - [x] **Slice 4 — authorization-class declaration and gate closure
    ([DR-0134](docs/architecture/decisions/0134-fastvote-authorization-boundary.md)
    implemented and reviewed 2026-09-22).** Defines all seven Phase 2
    operations as local-operator-invoked, with current-set signer/current-set
    quorum/outgoing-set signer/outgoing-set quorum/historical-evidence proof as
    applicable; every external ingress remains closed. Adds no wire,
    `NodeEventKind`, route, CLI, client, relay, or operator-token fiction.
    Closes DR-0132 C7 by making existing epoch-sensitive native surfaces derive
    the live epoch from committed `FastPathEpochRecord` while retaining the
    mutation-time CAS fence. Companion code, tests, complete gate, Bugbot, and
    fresh security/tech-lead reviews landed in PR #180, closing Phase 2.
- [ ] **Phase 3 — economics/security completion.** Architecture is split into
  explicit slices. Custody, typed genesis bonds, bond lifecycle, certified
  fee claims, a certified multi-escrow SQLite restart sweep and cross-epoch
  historical claim evidence and a local-SQLite operator sweep are implemented;
  the PostgreSQL operator and its certified nonempty E2E now exist, but
  capacity certification and the review gate remain open:
  - [x] **Slice 0 — non-signable protocol custody prerequisite
    ([DR-0135](docs/architecture/decisions/0135-protocol-custody-owner.md),
    implemented and locally validated 2026-09-22).** Adds canonical owner tag
    5 and scope frame `0x4007/v1` that no ordinary sender-authorized mutation
    path can use, with signed-genesis-only
    creation and stable/adversarial/real-SQLite-restart evidence. Ordinary
    contract creation, authenticated input, owner transition, paid fee source,
    and FastVote lock acquisition fail closed. This slice is not a bond, slash,
    fee distribution, or payout implementation and does not close Phase 3.
  - [x] **Slice 1 — typed asset-aware genesis bond commitments
    ([DR-0136](docs/architecture/decisions/0136-fastvote-bond-commitment.md),
    implemented and locally validated 2026-09-22).** Adds generic value
    observation through authenticated executable-ABI metadata and atomically
    derives canonical `0x642A/v1` validator/resource/object/authority/amount
    records during signed genesis installation. Exact restart verification,
    partial/tampered-row rejection, independent JS vectors, and real SQLite
    close/reopen evidence are covered. Node-core runtime code imports no
    Standard Asset type or body codec and contains no asset-specific
    genesis-bond path; Standard Asset remains a dev fixture and the generic fee
    layer still carries its existing transitive `AssetId` dependency. Fee
    escrow and every custody mutation remain Slice 2.
  - [ ] **Slice 2 — closed release authority and economics
    ([DR-0137](docs/architecture/decisions/0137-fastvote-release-authority.md),
    accepted 2026-09-23; implementation in progress).** One closed,
    policy-pinned public-contract execution boundary covers bond lifecycle,
    evidence consumption and fee escrow without a Standard Asset node-core
    path. Delivery is dependency-ordered but remains one Phase 3 completion
    slice:
    - [x] resource-generic bond policy, signed economics policy, lifecycle
      codecs/keys, genesis commitment and exact restart verification
      (implemented and locally validated 2026-09-23). `BondResourceId`
      replaces the Standard-Asset-specific registry boundary; signed
      `0x642B/v1` resource entries and `0x642C/v1` policy bytes are committed
      inside clean `GenesisManifest 0x6416/v1`, persisted under a reserved
      context key and byte-exactly restart-verified. `0x642A/v1` is now the
      authoritative generation/lifecycle-epoch/minimum/state row with closed
      `0x642D/v1` lifecycle state; genesis derives generation 1 `Active` only
      after the policy's exact code/instance/type/schema/ABI and minimum checks pass.
      Rust plus independent JavaScript vectors cover the changed frames;
    - [x] invocation-local protocol-custody execution capability prerequisite
      (implemented and locally validated 2026-09-23). One exact
      policy-constructed capability binds context, sender,
      instance/code/type/schema/entrypoint, object, direction, custody scope and
      recipient. Deposit maps a derived non-address operand only for the pinned
      source; release admits only the pinned custody `Write` input and exact
      recipient. `Consume`, ambient token reuse, `create_object`, ordinary and
      paid execution remain closed. Effects are provisional: node-core
      lifecycle admission, generic postcondition validation and atomic durable
      commit are not implemented by this prerequisite. Rust contract-effect
      tests and an independent `0x642E/v1` JavaScript preimage vector cover it.
      The private capability is pinned to the complete signed execution-event
      digest, and bounded rejection sampling prevents an address-shaped
      counter-zero token from permanently blocking a valid source;
    - [x] generic custody-effect validation plus whole-object
      deposit/replacement, unbond and withdrawal, with a cryptographically
      non-forgeable transition chain (implemented and locally validated
      2026-09-23). `bond_lifecycle::effects::validate` is a contract-agnostic
      validator: exactly one whole-object `Mutated` effect, exact
      object/version-increment/type/schema, byte-identical body, an exact
      owner transition, and a positive conserved `u64` value observed only
      through the signed executable ABI; no event, creation, deletion or
      extra effect is admitted, and any leg the engine reports having created
      an object is independently rejected regardless of engine output. The
      closed `BondLifecycleIntent 0x642F/v1` envelope (signed as `0x6430/v1`)
      pins the exact `BondResourceId`, expected pre-transition generation,
      expected previous-row digest and expected next-row digest the signer
      committed to ahead of execution, and authorizes exactly one of Deposit
      (`Exited -> Active`), Replace (`Active -> Active`, an atomic
      same-sender two-leg swap with consecutive nonces and every leg's own
      `request_id` pinned to the outer intent; the replacement amount must be
      at least the previous live amount because reduction goes only through
      the Unbond/Withdraw delay), Unbond (`Active ->
      Unbonding`, no contract execution, recipient independently validated as
      a canonical prime-order Ed25519 address) or Withdraw (`Unbonding ->
      Exited`, requiring the unlock delay elapsed, the validator absent from
      the committed live set, and authorized by the committed validator plus
      an exact release-submitter signature rather than any source/deposit
      authority). A later policy minimum raise cannot strand an already-
      eligible Unbond or Withdraw: both preserve the current row's
      `required_minimum` exactly. First-ever post-genesis bonding with no
      committed row, and any transition out of `Jailed`, are rejected. The
      unsigned intent digest used for the validator's signature is distinct
      from the receipt/dedup digest, which hashes the exact signed envelope
      bytes, so a different signature over an identical intent conflicts
      rather than silently replaying. Authentication/replay follows the
      fixed order: bounded decode, every inner leg's own signature and
      `request_id` match, the reserved request-id guard, the receipt digest
      and exact/conflicting replay reconciliation, the committed-epoch
      fence, the committed bond row's resource/generation/previous-digest
      match, the row's own validator signature, and -- while the validator
      is still present in the committed live set -- an exact cross-check of
      its set signature scheme/key against the committed bond row's key --
      all before policy/nonce/lock/publication/object/execution work, and the
      deterministically built resulting row's digest is verified byte-exact
      against the signed `expected_next_row_digest` immediately before
      commit. `FastPathBondRecord 0x642A/v1` is extended in place with the
      committed validator authorization scheme/key (installed once from the
      matching genesis validator entry, copied unchanged by every later
      transition; Ed25519 only) and a canonical, safe `live_collateral()`
      accessor: once `Exited` or `Jailed`, it returns `None` rather than
      `custody_object`/`amount`, which are historical audit fields only --
      this is a discipline the type invites for code that sums or reports
      bonded stake, not one Rust's field visibility mechanically enforces,
      since both fields remain public and directly readable. The permanent
      `FastPathBondTransitionRecord 0x6431/v1` now retains the exact signed
      envelope and the exact resulting row bytes (not a digest/signature
      summary) for every generation, and its own redundant
      `committed_at_checkpoint` copy is cross-checked against the decoded
      resulting row's; genesis restart
      (`genesis::verify_fastpath_bond_chain`) independently re-decodes each
      stored envelope, re-derives and re-verifies the validator's signature,
      cross-checks every signed field against the running chain state, re-
      decodes and validates the stored resulting row's immutable
      identity/closed state transition and checkpoint, and recomputes both
      row digests -- so generation 1 stays byte-exact while later
      generations re-derive and re-verify through the chain instead of
      failing closed on the now-expected byte difference, and a deleted
      transition, swapped generation, lifted signature, tampered envelope,
      tampered stored row, a tampered `committed_at_checkpoint` summary, or a
      coordinated rewrite of a transition and the final row together all
      fail restart -- while the advanced singleton, or the transition chain
      leading to it, remains present under the store being verified; a full
      durable-store rollback to exactly the genesis snapshot is, by
      construction, indistinguishable from a legitimate fresh install unless
      a separately anchored checkpoint/state-root publication detects it,
      which is out of this unit's scope. A trapped leg or rejected invariant
      commits nothing (no "rejected but committed" receipt, unlike ordinary
      local execution). Every embedded leg's own `request_id` must equal the
      outer intent's exactly, checked before any execution or commit; both
      share the ordinary dedup request-id namespace with every other
      externally reachable request, so separately pre-submitting a leg on
      its own burns that request id and any later `bond_lifecycle`
      resubmission using it fails closed as a conflict, requiring a fresh
      signed envelope rather than a resubmission. Partial (non-whole-object)
      release remains deferred to unit 4. Rust plus independent JavaScript
      vectors cover the changed `0x642A` and new `0x642F`/`0x6430`/`0x6431`
      frames for every operation shape (not Deposit alone), including an
      exact stable-hex assertion for the signed `0x6430` wrapper matching the
      JS vector, not merely a round-trip; adversarial effect tests,
      state-machine/signature/replay/reserved-id/stale-generation/
      live-set-divergence/policy-raise/leg-request-id-mismatch tests,
      real-WASM Deposit and Replace success tests (Replace proving both
      owner transitions and one atomic commit, including equality at the
      non-decreasing floor), real-WASM negative tests (nonconsecutive nonce,
      below-minimum and below-previous-live amounts with exact atomic
      non-mutation, a genuine second-leg WASM trap, a leg reporting a created
      object), an exact/conflicting replay
      test with an engine call-counter proving non-reapplication, a real
      file-backed SQLite test spanning Deposit/Unbond/Withdraw across three
      independent close/reopen cycles (each reopen following an
      object-mutating lifecycle operation) plus writer-fence rejection and
      two competing writer attempts proving exactly one commit with no
      partial state,
      and the transition-chain restart tampering negatives above (deleted
      record, swapped generation, lifted signature, tampered envelope,
      tampered stored row, tampered checkpoint summary, coordinated rewrite)
      all pass;
    - [x] one-time evidence consumption, full forfeiture, jail/reactivation
      and next-set eligibility coupling (implemented and locally validated
      2026-09-23). All three DR-0133 evidence families (class a/b/c) are
      eligible for consumption only after their existing canonical
      verification against the chain-anchored historical validator set,
      re-run in full (including class (b)'s mandatory preimage-hash-to-
      signed-digest checks) rather than trusted from the stored row alone.
      New canonical frames: `EvidenceConsumptionRecord 0x6432/v1` (the
      permanent evidence-consumed-once absence-fence marker, keyed like the
      DR-0133 evidence row under a distinct `evidence-consumed/` prefix),
      the closed `BondTransitionAuthorization 0x6433/v1` union
      (`ValidatorEnvelope` retaining the exact signed `0x6430` bytes, or
      `ConsumedEvidence` retaining the exact evidence bytes, evidence
      epoch/digest and exact signed forfeiture leg), and the unsigned
      `SlashIntent 0x6434/v1` (authorized by the evidence itself, not a
      signature, since the validator being slashed cannot authorize its own
      forfeiture). `FastPathBondTransitionRecord 0x6431/v1` is revised in
      place: field 8 is now the encoded authorization union instead of raw
      signed-envelope bytes. `FastPathBondRecord 0x642A/v1` gains two new
      fields, both distinct from the pre-existing `lifecycle_epoch` (pure
      transition time, never overloaded to carry liability or object-mint
      provenance): `slashable_from_epoch` (field 15), the earliest evidence
      epoch this generation's live collateral is liable for -- `Deposit`
      from `Exited` and `Reactivate` from `Jailed` set it to the committing
      epoch plus one (fresh collateral can only ever join the *next*
      validator set and must never be liable for evidence at or before the
      epoch it was posted), every other operation (including the one
      genesis generation, liable from the genesis epoch itself) preserves it
      unchanged; and `custody_object_epoch` (field 16), the exact epoch
      `custody_object`'s own digest was actually computed at -- every
      operation that mints a fresh object ref (genesis, `Deposit`,
      `Reactivate`, `Replace`, `Withdraw`, `Slash`) sets it to that
      transition's own committing epoch, while `Unbond` (which executes no
      leg and never touches the custody object) carries it forward unchanged
      even as `lifecycle_epoch` itself advances. `FastPathBondLifecycleOperation` and the local
      `BondLifecycleOperation`/`0x642F`/`0x6430` intent gain `Reactivate`
      (tag 5, `Jailed -> Active`, reusing `Deposit`'s exact mechanics --
      current enabled/min/max policy checks and a fresh sender-owned whole
      object) and `Slash` (`(Active | Unbonding) -> Jailed`); `Deposit` and
      `Replace` now also enforce the committed policy's `enabled`/max-
      exposure fields, which unit 2 left unchecked. `handle_bond_slash`
      follows the fixed order: bounded decode; leg authentication;
      leg/outer request-id equality; reserved-id guards; the exact
      intent-bytes receipt digest (embedding the leg's own signed bytes, so
      a differently-signed leg over an identical intent conflicts rather
      than replaying) and reconciliation; the committed-epoch fence; the
      committed bond row with resource/generation cross-checked against the
      intent's pins; the named permanent evidence row, cross-checked
      against its own key selector and recomputed normalized identity;
      class (b)'s preimage checks; full evidence reverification against the
      historical validator set; live-collateral and
      `evidence_epoch >= bond.slashable_from_epoch` requirements -- gated on
      `slashable_from_epoch`, never on `lifecycle_epoch`: `Unbond` and
      `Replace` both stamp `lifecycle_epoch` to their own committing epoch
      while carrying forward the same (or, for `Replace`, freshly re-posted
      but liability-equivalent) live collateral a validator was already
      liable for, so gating on `lifecycle_epoch` instead would let a
      validator launder away old equivocation evidence for free merely by
      unbonding or replacing after misbehaving but before evidence lands;
      the evidence-consumed absence fence; the committed economics policy read
      without requiring the resource still accept new bonds; the
      forfeiture leg run through the existing local-execution admission
      under a new, narrowly scoped `ProtocolCustodyDirection::Forfeit`
      capability (custody-to-custody, `BondCollateral -> ForfeitedCollateral`,
      requiring identical chain/subject/resource and generalizing the
      pinned custody input to an exact operand/resulting-owner pair so
      `Release`'s recipient-address shape and `Forfeit`'s reused
      `0x642E` owner-token shape share one code path); and generic
      whole-object effect validation before one atomic commit of the
      forfeited object, the `Jailed` bond row (preserving the historical
      amount/minimum and immutable identity, generation+1, the current
      lifecycle epoch, the new forfeited object ref and
      `Jailed{conflict_digest}`), the permanent transition record, the
      evidence-consumed marker, the sender nonce range, stale lock cleanup
      and the one outer receipt. An exact replay returns the original
      receipt without reaching the absence fence; a different request
      against already-consumed evidence fails closed at the fence.
      `commit()` is refactored into a shared `commit_bond_transition`
      taking the tagged authorization and an `Option` expected-next-row
      digest (`Some` for every validator-signed transition including
      `Reactivate`, `None` for evidence-driven `Slash`, which has no
      signer to pin a row ahead of time). `genesis::verify_fastpath_bond_chain`
      branches per transition on the authorization tag: a validator tag
      keeps the existing signature/pin checks; an evidence tag fully
      re-decodes and re-verifies the retained evidence, checks the
      historical set and class-b preimages, the previous row's
      `slashable_from_epoch` against the evidence epoch, the exact `Jailed`
      state, and the
      matching consumption marker/generation/checkpoint, while every prior
      tamper check (deleted/swapped/lifted-signature/tampered-row) is
      preserved for both tags. Restart closure for the evidence tag goes
      further than re-verifying the evidence alone: `ConsumedEvidence`
      additionally retains the exact canonical previous/resulting whole-
      `Object` bodies (`previous_object`/`resulting_object`, `0x6433/v1`
      fields 7/8, each independently bounded), and restart independently
      re-authenticates the retained signed forfeiture leg under
      `LocalExecutionPolicy::generic_object_results(transition.context)`
      (exact context, policy-pinned code/instance/transfer entrypoint, the
      one signed `Write` access matching `previous_row.custody_object`
      exactly), decodes and re-encodes both retained objects to canonical
      bytes, recomputes each one's own `ObjectRef` digest at its recorded
      `custody_object_epoch`/transition epoch, requires the previous object to match
      `previous_row.custody_object` under exactly `BondCollateral` (hashed at
      the previous row's own recorded `custody_object_epoch`, never at the
      transitioning epoch, so an intervening `Unbond` that carried
      `custody_object_epoch` forward unchanged under a since-rotated hash
      suite still verifies) and the resulting object to be identical to it
      except version+1 and exactly `ForfeitedCollateral`, and requires the
      resulting row's own `custody_object`/`authority`/`amount`/
      `required_minimum`/`lifecycle_epoch` to equal that independently
      recomputed ref and the previous row's own copied fields, its
      `custody_object_epoch` to equal exactly this transition's own
      committing epoch (the forfeiture leg mints the resulting object here),
      and its `slashable_from_epoch` to be carried forward unchanged from
      the previous row as permanent audit data (no longer gating anything
      once the row is `Jailed`, but still tied to independently-verified
      facts like every other copied field). Unlike a validator-signed
      transition (pinned end to end by `expected_next_row_digest`), evidence-
      driven forfeiture has no signer to pin the resulting row ahead of time,
      so without this, a coordinated rewrite of `resulting_row` and its own
      `current_row_digest` together (and the final installed singleton to
      match) could substitute an arbitrary resulting row that is merely
      internally self-consistent; this closes that gap by tying the
      resulting row back to independently-verified evidence-external facts
      (the leg's own signature and the two whole-object bodies) instead.
      `handle_bond_slash` records the exact `previous_object`/
      `resulting_object` bytes at live-slash time (the read snapshot and the
      validated resulting object, respectively) and now folds the named
      evidence row's own read revision into its atomic CAS read set (it
      previously read but never tracked it), and `0x6433`'s `evidence_bytes`
      field has its own explicit per-field bound restored alongside
      `forfeiture_leg`'s (previously bounded only by the frame aggregate).
      Certificate application is deterministic and independent of slash
      timing: `epoch_transition::derive_activation_set`/`activate` never
      touch bond state at all (no `eligibility_reads`, no CAS merge with
      bond/policy rows) -- `derive_eligibility_reads` (requiring every
      candidate next-set validator's committed bond, read at its own
      genesis-pinned economics-policy context, to be `Active`/live, correct
      chain/id, `lifecycle_epoch <= current_epoch`, an exact auth scheme/key
      match, an enabled current policy resource, and amount within
      `[min_bond, max_validator_exposure]`) now runs exclusively inside
      `propose_and_vote`, strictly before a vote is cast, so an ineligible
      candidate is simply never voted on and can never enter a legitimately
      quorum-certified set in the first place. `activate` re-derives and
      installs the certified activation set purely from the certificate and
      current committed policy/validator-set state; a slash landing at any
      point relative to certificate formation or activation cannot change
      whether that exact certificate applies -- jailing only ever affects
      which candidates a *later* `propose_and_vote` round is willing to vote
      on (see ADR-0137's "This eligibility gate is checked in exactly one
      place" and DR-0132 §3.A/§3.C, corrected here). Genesis installation
      now fails closed unless every genesis validator has exactly one valid
      genesis bond (previously only rejected a *second* bond per validator,
      not a missing one); the shared `paid_contracts` devnet genesis builder
      and every affected genesis/epoch-transition/equivocation Rust fixture
      are updated to install one accordingly, with a dedicated test
      asserting the new fail-closed behavior in place of the old
      "address-only genesis creates no bond row" test it replaces. Focused
      new tests cover: frame round-trips and stable hex for `0x6432`/`0x6433`
      (both tags, including the revised evidence-tag shape with
      `previous_object`/`resulting_object` and a `Slash`-operation transition
      record) / `0x6434`; the full closed `validates_transition` state
      matrix for all six operations; a `Forfeit`-direction capability test;
      real end-to-end evidence-driven slashes for all three DR-0133 evidence
      families (class a `FastVote`, class b `FastVoteObjectConflict`, class c
      `EpochTransitionEquivocation`), each proving `Jailed` state, one-time
      full forfeiture, the forfeited object's owner projection and the
      consumption marker; a test proving current-epoch `FastCertificate`
      verification for a validator is byte-for-byte unaffected by that same
      validator's own later slash; exact-replay-without-re-execution (engine
      call-counter); the absence-fence rejecting a different request against
      already-consumed evidence; every non-`Reactivate` operation rejecting
      a `Jailed` bond; a real-WASM `Reactivate` end-to-end test; restart
      re-verification of a real slash transition plus tampered-consumed-
      marker, tampered-evidence-bytes, tampered-forfeiture-leg, tampered-
      previous-object and tampered-resulting-object restart negatives, plus
      coordinated-rewrite negatives for the resulting row's amount, custody
      object, lifecycle epoch, `custody_object_epoch` and
      `slashable_from_epoch` (each paired with a matching, self-consistent
      `current_row_digest` and installed singleton, proving the independent
      object/leg re-derivation -- not mere digest self-consistency -- is
      what catches them); `propose_and_vote` rejecting every one of the
      eight closed ineligibility reasons (jailed, unbonding, exited,
      under-min, over-max, disabled, key-mismatch, absent); a test proving a
      certificate formed before a slash still activates identically after
      that slash lands locally; a real file-backed SQLite close/reopen chain
      covering genesis install, a real slash, a restart re-verification, a
      real `Reactivate`, and one more restart re-verification; a real
      file-backed SQLite competing-writer test racing `Slash` against
      `Replace` from the identical committed row, proving exactly one
      commits and the final state restart-verifies; a second real file-backed
      SQLite test forming a valid two-validator certificate, unbonding and
      retiring one validator, then racing its independently valid `Slash`
      and `Withdraw` from the identical unlocked `Unbonding` row, proving the
      Withdraw winner leaves no slash receipt, extra nonce advance or
      consumed-evidence marker and the complete epoch/bond history
      restart-verifies; three real, multi-epoch
      end-to-end tests proving `slashable_from_epoch`/`custody_object_epoch`
      are actually load-bearing, not merely stored -- real evidence recorded
      at genesis epoch `E`, a real DR-0132 epoch bump to `E + 1`, then a real
      `Unbond` (respectively `Replace`) committing at `E + 1`, then a real
      evidence-driven `Slash` using the old evidence that still succeeds
      because gating is on `slashable_from_epoch` and not the now-advanced
      `lifecycle_epoch`, followed by full genesis restart re-verification of
      the complete chain; and a third that additionally rotates the active
      hash suite exactly at that same `E + 1` boundary, proving restart
      hashes the previous custody object at its own recorded
      `custody_object_epoch` (the pre-rotation suite) rather than uniformly
      at each transition's own committing epoch (the post-rotation suite);
      a focused negative test proving a freshly `Deposit`ed bond's
      `slashable_from_epoch == committing epoch + 1` floor actually rejects
      real evidence dated at or before the deposit itself (`Reactivate`
      shares the identical code path and floor, already covered positively
      by its own end-to-end test). Rust and independent JavaScript vectors
      cover the new/changed frames only (`0x6431` revised, `0x6432`/`0x6433`
      (now with `previous_object`/`resulting_object`)/`0x6434` new, plus the
      `Reactivate` `0x642F`/`0x6430` shape and `0x642A`'s two new fields);
      and
    - [ ] certified fee escrow and claims:
      - [x] settle-phase-only creation authority promotes only the pinned
        settlement ABI's exact returned fee slot into request-scoped
        `FeeEscrow` before the prepared commitment (the refund remains
        address-owned even for equal recipients); apply atomically stores the
        exact resource/object/epoch/total plus sorted unique active-validator shares
        using `T/N` and ascending-id remainder assignment in the bounded
        `0x641E/v1` row; Rust and independent JavaScript vectors cover
        `0x641E`, `0x6435` and `0x6436`;
      - [x] bounded `0x6437/0x6438` historical-validator-signed
        zero/partial/final claim handler through the policy-pinned public
        `split`/`transfer` ABI. The claim CAS-fences the settlement row,
        historical set, epoch, paid/economics policy and touched object/
        nonce, then atomically writes the result, receipt and immutable signed
        claim envelope. Rust/independent JavaScript codec vectors, real-WASM
        split then final transfer, zero-share no-object commit, exact/
        conflicting replay and file-backed SQLite close/reopen replay pass;
      - [x] direct adversarial split/final claim-effect validation matrix
        (trap, events, effect count/shape, owner, identity, schema, amount,
        conservation and created authority); real file-backed SQLite
        same-generation competing zero-share writers with distinct signed
        request ids commit exactly one row/audit/receipt; persisted and
        uncommitted indeterminate zero-share commits reconcile by exact
        replay without a second transition;
      - [x] real file-backed SQLite positive object-mutating split claims:
        distinct signed competing writers on the same generation commit one
        retained escrow and one claimant-owned payout object, row, audit,
        nonce and receipt, while the losing payout is absent; persisted and
        uncommitted indeterminate outcomes reconcile on close/reopen and
        exact replay without a second transition;
      - [x] certificate apply now atomically retains the exact `0x6424/v1`
        staged-commit preimage under a request-scoped reserved key. A real
        four-validator SQLite close/reopen test re-hashes the retained bytes
        to the quorum certificate and recovers the paid result, charged total
        and initial fee output without changing existing canonical frames;
      - [x] a read-only, explicit-escrow verifier reconstructs the certified
        generation-1 row from that witness and the historical validator set,
        then checks retained claim and embedded-leg signatures, pinned targets,
        exact row digests and the immutable escrow-side object/value
        transition chain. A file-backed
        SQLite reopen test covers the unclaimed initial row; focused tests
        cover split/final history and missing/tampered links. This is not a
        startup-wide scan and does not independently verify split payouts;
      - [x] independently restart-verify the retained signed-claim chain and
        **every** object transition from authenticated prior bytes, including
        each split payout, and complete a bounded all-escrow restart sweep or
        equivalent operational gate. DR-0140 now binds the exact split payout
        ObjectRef in `0x6437/0x6438/v2` (preserving historical v1 bytes),
        checks it and all other leg-derived creation candidates after restart,
        and supplies a read-only chain-scoped durable-key page scanner for
        memory/SQLite/PostgreSQL. Local v2 vectors, positive SQLite replay,
        file-backed post-restart payout/authority/instance tamper rejection
        and one certified initial-escrow inventory page pass. A live
        PostgreSQL scanner case is wired into the existing CI database
        harness. A real file-backed SQLite test now creates two distinct
        escrows through quorum-certified prepare/apply, fully claims one with
        split/final/two zero-share claims, partially claims the other with a
        split, closes/reopens, checks both signed payouts, and completes a
        quiescent two-page all-present-key sweep (2 rows, 5 claims, 2 payouts).
        It checks exact apply/claim replay without row or nonce reapplication
        and fails the whole sweep when a retained claim is tampered. This is
        fixture coverage, not measured network recovery time: pages are not a
        multi-page snapshot, and whole-store rollback still needs an external
        anchor (DR-0139/0140);
      - [x] bound admission to 256 active validators at genesis, epoch
        next-set derivation, prepare, apply and fee-share construction,
        retaining the 10,000 decode ceiling for historical bytes. At the
        12-byte `genesis-test` chain id, deterministic per-escrow byte counts
        at 256 are 19,838 B per settlement row,
        5,078,528 B in whole-row rewrites across 256 claims and 51,642,368 B
        in maximally sized retained signed envelopes (DR-0138). Row size
        depends on chain-id length; these are not universal bounds or a
        throughput/disk-life certification;
      - [x] bound all-present-key inventory's per-escrow orphan check to one
        exact chain-and-escrow claim-key scan (DR-0141), while retaining the
        plain per-escrow verifier's point-read path. A counting-store test
        observes one scan and zero absent point reads for a low-generation
        escrow versus 257 absent point reads previously; malformed, missing,
        tombstoned, extra and continued key sets fail closed. This is a local
        logical read-count result, not measured network recovery time;
      - [ ] capacity/load/soak certification for concurrent escrows, claim
        rate, retained envelopes and restart time before claiming network
        capacity. The 48-escrow/six-writer synthetic zero-share SQLite
        regression measures logical retained bytes and local reopen latency.
        A separate 12-escrow/three-writer real-WASM split/final regression
        measures local positive-claim latency, object/receipt persistence and
        SQLite/WAL file sizes. DR-0145 now runs the same escrow counts on real
        PostgreSQL, with 256 retained shares per zero-share row, caller retry
        counts for definite serialization rejection, logical payload bytes,
        whole-shared-table physical size diagnostics and reopen under a newer
        writer fence. All resulting rows, payout objects and receipts are
        checked. These directly set-up fixtures still do not certify sustained
        network throughput, disk life or recovery time (DR-0138/0145). Per
        DR-0147 this certification is post-launch hardening, not a Phase 3
        completion prerequisite; no target numbers are adopted;
      - [x] expose the bounded all-page verifier to a local SQLite operator
        ([DR-0142](docs/architecture/decisions/0142-fastvote-operator-escrow-inventory.md)).
        The command opens only existing namespace-bound files, requires
        explicit offline confirmation, claims a new persisted writer fence,
        checks it after the final page and prints totals only on complete
        success. The certified two-escrow/tamper restart fixture now calls
        that public driver; an executable file-backed empty-namespace test
        checks no bootstrap, confirmation, fence advance, stale-reader
        rejection and corrupt-row failure without a complete result. A second
        executable E2E creates two genuine quorum-certified escrows in a
        file-backed SQLite store, closes both files and uses page size 1 to
        force two verified rows over two pages plus a fence advance. Pages
        remain independent transactions, not snapshot-consistency evidence;
        neither fixture proves blob-backed reads or PostgreSQL network use;
      - [x] add a namespace-bound PostgreSQL content-addressed blob store
        (schema identity v3, pre-release bootstrap-only) and an offline,
        certificate-validating TLS operator command that checks existing
        schema/namespace, advances the PostgreSQL writer fence, scans every
        page and rechecks the fence/deadline before reporting success. The
        live blob-store conformance covers idempotence, conflicting concurrent
        insertion, namespace isolation, byte bounds and reopen when a live
        PostgreSQL is configured (as in repository CI). The operator
        has parser/TLS-host tests and a real-PostgreSQL certified escrow
        invocation (DR-0143);
      - [x] prove the actual TLS PostgreSQL operator on two nonempty,
        quorum-certified escrows with five signed claims (split, final and
        zero-share), two verified split payouts, close/reopen, two pages and
        a stale-writer-fence negative. The executable test uses the selected
        PostgreSQL structured and blob stores, advances the persisted fence
        twice, and runs in repository CI. It does not claim representative
        throughput, recovery time or production PostgreSQL-server TLS. The
        original requirement for a blob-backed *Standard Asset fee object*
        read was impossible under that coin's fixed `u64` body and the 64 KiB
        inline threshold; DR-0143's dated clarification removes it from this
        first-network fee profile without claiming the blob-read branch was
        exercised. Any future large-bodied fee resource requires its own
        certified PostgreSQL blob-history E2E before activation;
      - [x] verify certificate-epoch validator membership and historical
        hash-suite selection across a real vote/certificate/activation epoch
        transition that drops a validator and rotates SHA-2 to SHA-3. Separate
        certified SQLite fixtures submit dropped-validator zero-share and
        positive split claims at E+1 against an E escrow; the positive case
        executes a real WASM payout, retains the old escrow type hash while
        deriving the new payout type under E+1, and verifies the signed payout,
        retained chain, all-present-key sweep and exact replay after close/reopen.
        Bond eligibility rows are synthetic prerequisites in these fixtures;
        they do not prove real bond-deposit operations or network capacity;
      - [ ] future protocol-version activation gate: there is currently no
        durable version-switch operation, and the claim handler intentionally
        rejects a different version, including zero shares. Before adding a
        version switch, either preserve authenticated historical claims or
        fail activation while any claimable `FeeEscrow` remains, and prove
        that choice across restart (DR-0138). Do not represent operator
        config changes as an authorized protocol migration;
      - [ ] Phase 3 independent security review gate. The completed economics
        core on prior main `72a5f9847673dc9345d3b918ce46957d343cd520` passed a
        fresh Opus tech-lead review on 2026-09-26; that is not an independent
        security audit or approval of the added network-ingress candidate.

  **Remaining Phase 3 completion:** pass the independent Phase 3 security
  review over the completed custody/bond/forfeiture/claim/payout economics
  core above. The prior-main tech-lead review passed; changed surfaces still
  require fresh review, and the DR-0148 candidate remains blocked. Per
  [DR-0147](docs/architecture/decisions/0147-function-first-network-delivery.md),
  declaring an initial network load/recovery target and establishing
  representative sustained claim/restart-sweep capacity move to post-launch
  hardening; they are not a Phase 3 prerequisite, and no target numbers are
  adopted yet. The bounded DR-0145/0146 regressions remain fixture-level
  evidence, not that certification. DR-0148's opt-in experimental implementation
  may proceed while the independent review remains open; live exposure is
  still separately gated. Authenticated external validator request/event-driven
  ingress for prepare/certificate/
  apply, a CLI end-to-end quorum submission path, exposing the
  bond/epoch/equivocation/reward/claim lifecycle through explicit
  authenticated operator/network surfaces where needed, and bounded
  independent-validator functional start/restart/replay/authorization
  evidence with a documented deployment/configuration walkthrough become the
  next integrated network functional delivery, gated by its own separate
  design, authentication and security/audit review — not folded into this
  phase. Protocol-version activation is a separately blocked future gate;
  there is no live version-switch path to exercise in this phase. Revisit it
  before implementing that path. FastVote is not complete until this phase
  closes.

### Bounded PostgreSQL Phase 3 evidence and remaining gate

[DR-0145](docs/architecture/decisions/0145-postgres-phase3-capacity-and-validator-authority.md)
records one integrated PostgreSQL regression slice and the work still open:

- [x] Run concurrent zero-share and real-WASM positive split/final claims on
  the selected PostgreSQL store; close/reopen under a newer writer generation,
  verify exact retained rows, payouts and receipts, and report diagnostic
  elapsed time plus logical and physical storage measurements. Preserve the
  independent 256/257 validator admission boundary. Locally validated
  2026-09-26 on disposable PostgreSQL 18.6: 48 rows with 256 shares each and
  six callers (one zero-share claim per row), plus 12 real-WASM positive rows
  and three callers. The complete run retained 952,224 zero-share settlement
  bytes, 33,024 zero-claim envelope bytes, 5,952 positive settlement bytes,
  23,922 positive-claim envelope bytes, 3,576 escrow-object bytes and 1,596
  payout-object bytes. Relation-size readings are for whole shared tables,
  not isolated namespace storage; timings and caller retry counts vary by run.
- [x] Time a complete, multi-page certified escrow inventory with the actual
  PostgreSQL operator after restart, including the final fence recheck. A
  small disposable fixture is a regression, not representative recovery
  capacity or a long soak. The local 2026-09-26 run completed two pages/two
  certified escrows/five claims/two payouts twice on a disposable PostgreSQL
  18.6 container. The test emits per-run wall time; no target recovery budget
  is inferred.
- [x] Drive the four-validator CLI quorum with a distinct database and login
  per validator and prove cross-database `CONNECT` denial. One disposable
  server still does not prove independent administrators or failure domains.
  The local 2026-09-26 test passed full 3-of-4 prepare/apply, exact replay,
  cross-role denial and unchanged foreign durable state.
- [ ] Post-launch hardening (per
  [DR-0147](docs/architecture/decisions/0147-function-first-network-delivery.md)):
  declare the initial network workload, sustained claim-rate and recovery
  targets, and run representative PostgreSQL load/soak and fault/recovery
  trials. Not required for Phase 3 completion or initial network
  startup; no target numbers are adopted yet.
- [ ] Pass the separate Phase 3 independent security review gate (prior-main
  Opus tech-lead review passed as recorded above). Keep
  external FastVote ingress and protocol-version activation behind their own
  decisions.

### Certified PostgreSQL workload and recovery instrument

[DR-0146](docs/architecture/decisions/0146-postgres-certified-load-and-recovery-harness.md)
and the [measurement runbook](docs/operations/postgres-certified-load.md)
define this integrated instrument:

- [x] Build a finite explicitly sized workload that creates genuine
  quorum-certified paid escrows on a PostgreSQL primary with independent
  memory co-voters, claims each through positive split/final and zero-share
  paths, checks exact replay and retained state after a newer-fence reopen,
  and drives repeated complete inventories through the real TLS operator.
  Validate count/rate/deadline bounds and fail without a complete totals
  record on partial work. Wire only a fixed small smoke into repository CI;
  long runs require explicit configuration and disposable-test confirmation.
  The 2026-09-26 local smoke completed 8 escrows, 32 claims and 8 payouts,
  byte/revision-exact same-boot and post-reopen replay checks, and two
  complete TLS operator inventories (two pages each; final writer fence 4).
  This uncovered and fixed a production adapter lookup that sorted selected
  `object_version::TEXT` instead of the numeric base column. The real
  PostgreSQL regression updates through version 101, reopens, and proves
  both reads and locked mutation still reject head/history disagreement.
  A finite manual run on code commit `fa7517d` completed 64 escrows, 256
  claims and 64 payouts with 4 senders/4 claim writers, an offered-call cap
  of 8/s, a 600-second workload ceiling, a 900-second wall ceiling and
  three complete 16-page TLS inventories (final writer fence 5). There were
  279 claim attempts and 23 definite serialization retries of unchanged
  signed bytes. Creation took 120928 ms, claims 35018 ms, the core reopen
  verification 35940 ms, and inventories 39073/42665/42990 ms. Retained
  logical payload was 641856 bytes on the runbook's limited payload basis.
  Environment: PostgreSQL 18.6 with fsync/synchronous_commit/full_page_writes
  on; one shared Intel i7-12700F/20-logical-CPU, 31857-MiB-RAM host, NVMe
  storage with about 91 GiB free, no container CPU/RAM caps and other host
  work running. The roughly 318-second finite run is not a 600-second
  sustained soak, four PostgreSQL hosts or an adopted throughput/SLO result.
  A deliberate one-second workload ceiling failed during escrow creation,
  exited nonzero and emitted no complete totals record.
- [ ] Post-launch hardening (per
  [DR-0147](docs/architecture/decisions/0147-function-first-network-delivery.md)):
  adopt initial-network workload/recovery targets and gather representative
  sustained deployment measurements. A configurable instrument and its smoke
  do not satisfy this acceptance item or independent administration/host
  domains. This item is not a Phase 3 completion prerequisite; the
  separate Phase 3 independent security gate is tracked above; prior-main
  tech-lead review passed.

## Closed PostgreSQL multi-validator operator rehearsal

[DR-0144](docs/architecture/decisions/0144-closed-postgres-fastvote-operator.md)
defined the initial integrated implementation slice. This is a usable,
operator-invoked **genesis-epoch rehearsal**, not public validator ingress or
testnet activation. Keep it in one coherent PR rather than dividing schema,
CLI framing and vote/certificate handling into helper-only changes.

- [x] An operator can explicitly initialize each validator's own PostgreSQL
  namespace, install the **same** independently pinned, single-genesis-
  authority-signed manifest containing the complete validator set and one
  valid bond per validator, and restart-verify the exact manifest digest.
- [x] Separate CLI invocations with separately held Ed25519 validator keys
  can prepare the same sender-signed paid intent, exchange canonical votes as
  untrusted files, form a deterministic signed-genesis-set quorum certificate and
  independently apply it to each namespace. The key-derived public key's
  committed registration under the configured validator ID,
  locally expected chain/protocol/epoch/hash suite and manifest digest are
  checked before signing. PostgreSQL TLS and a new writer fence are required
  for each mutation; no fixed devnet key, public FastVote route, `NodeEventKind`
  or background relay is introduced.
- [x] A real PostgreSQL, multi-process E2E proves identical canonical
  responses and committed certificate/object/nonce results across at least
  a three-of-four quorum, process
  restart and exact replay without reapplication. It also rejects inadequate
  quorum, forged/foreign/wrong-epoch votes, mismatched genesis/context/key,
  request-id conflict without altered business state, and rejects stale
  writer-generation reads. A rejected operation may still advance its
  explicitly claimed fence; that is not application-state mutation.
  A shared disposable database in this test does not prove separate validator
  administrative control; the first network requires independent PostgreSQL
  authorities and credentials.
- [ ] Document an executable operator walkthrough and pass the full repository
  gate plus focused security and fresh tech-lead reviews. Prior-main Phase 3
  tech-lead review passed, but its independent security gate remains open; per
  [DR-0147](docs/architecture/decisions/0147-function-first-network-delivery.md),
  PostgreSQL capacity/soak/load certification is post-launch hardening, not a
  prerequisite for this gate. External authenticated validator ingress and any
  public network launch need a separate design and audit.

## CLI-First Node Production Gate

CLI Developer MVP Gate（criteria 1-6・10・11）を通過した後、本物のnode自体を
production-orientedへ近づけるgateを課す。これはUIより先に
node/persistence/operationsを固める決定であり、新しいproduction criteriaを
発明するものではない。2026-09-05のDR-0095により、S0-S3を共通baselineとし、
S4 Hardware Signing Release GateとS5 Software Production Gateを並行trackとして扱う。
Initial Code Security Audit Entry Gateと初回監査はこのproduction gateの完了を待たずに先行する。
TypeScript client・explorer・wallet（criteria 7-9）はSoftware Production Gateの後に
着手できるが、completeなCLI-First Node Production Gate、production、mainnet readiness
にはS4とS5の両方が必要である。以下はすべて既存criteriaを変更せず参照する。

**参照する既存criteria（すべてunchanged）:**

- 後述の「Phase 15 To-Be production exit criteria」1-10（NodeEvent kind別のcanonical
  仕様固定、concrete dispatch実装、read-set revision assertionを持つversioned
  transaction、request/event-digest dedup、transactional outbox/indexed due-work
  claim、HTTP contract明文化、adapter policyとしてのretry/backpressure、TLS/認証/
  rate limiting等を含むproduction deployment検証、conformance/fuzz/load/soak/
  capacity budget、migration/backup/disaster recovery rehearsalとindependent
  security review）。
- 後述の「Post-MVP Production Hardening: Phase 15 persistence implementation order」
  1-6（durable domain adapter boundary、indexed due-outbox repository、
  structured durable transaction envelope上のnormalized PostgreSQL schema、
  write skew/object ABA/lease fencing等を含むshared conformance、real host/power
  fault・ENOSPC・connection exhaustion・snapshot restore・TLS commit-loss・
  PgBouncer rehearsalを含むreal fault/capacity/backup rehearsal、Cloudflare
  Durable ObjectとAWS persistenceでの同一contract実装とreal provider
  certification）。
- 後述の「Cross-phase production release gate」（Coding Requirements/Security
  Invariants充足、experimental/deferred/mock/temporary項目のcriteria未充足ゼロ、
  protocol specification/migration/disaster recovery/monitoring/capacity
  planning/key management/validator operationsの再現可能な文書化、supported
  runtime間でのcanonical bytes/digests/execution effects/commitments/consensus
  outcomes/proof verificationの一致、fuzz/property/adversarial/long-running test
  と第三者security auditの重大指摘解消、mainnet genesis前のrelease
  artifact/dependency/compiler/build provenance固定とreproducible build/upgrade
  rehearsal）。
- protocol version 3のFastCertificate/certificate publicationのatomic
  composition、`SubmitTransaction`以外の外部event familyのauthenticated/
  authorized ingress、S4/S5、および独立したsecurity/release gateが完了する
  までlive activationを禁止する既存のhard activation constraint（後述の
  「Phase 15 As-Is scope」参照）。fee（S3のbounded uniform ordinary-asset fee
  composition、DR-0087）とmodule/object effect（additive owned-effects
  entrypointおよびpreinstalled-WASM entrypoint）はimplemented As-Isだが、
  FastCertificate、certificate publication、他event familyのauthorized
  ingress、S4/S5、独立security/release gateは引き続き未実装の前提であり、この
  gate単独でprotocol version 3を有効化してよいことにはならない。
- `SubmitTransaction`以外の外部から受理されるnode-event family（特にcertificate、
  protocol upgrade、validator-set change）について、live activation前に
  `SubmitTransaction`と同等のauthenticated/authorized ingressを要求する既存の
  hard activation constraint（後述の「Phase 15 As-Is scope」参照。generic node-core
  handlerが`SubmitTransaction`をrejectすることは、これらの他のfamilyを
  unauthenticatedのまま受理してよいことを意味しない）。

**このgateを通過してもmainnetではない。** provider Phase 16（Cloudflare）・
Phase 17（Deno/Vercel/Supabase/AWS）のTo-Be production exit criteriaと、初回監査後に
追加されたsurfaceのdelta audit、全監査の重大指摘解消は引き続き必須である。

### Software and hardware release gates

- **Common baseline:** S0-S3。すべてimplemented and validated As-Is。
- **Software Production Gate:** common baselineとS5の全criteria。これを通過した後、
  TypeScript client・explorer・walletへ着手できる。これはcompleteなnode-production、
  production、mainnet readinessの宣言ではない。
- **Hardware Signing Release Gate:** S4の全criteria。remaining physical-device/HIL/release
  workは明示的にdeferredであり、Software Production Gateやその後のbrowser surfaceを
  blockしない。
- **Complete CLI-First Node Production Gate:** Software Production GateとHardware Signing
  Release Gateの両方、および本節が参照する独立security/release criteriaを満たした状態。
  Ledgerをdeferしたままcompleteとは扱わない。

この並行化はS4/S5または既存production criteriaの削除・完了扱い・weakenではない。
protocol version 3のlive activationやproduction/mainnet readinessに対する既存の
hard constraintも変更しない。

**common baseline and parallel tracks（S0-S3, then S4/S5）:**

- **S0**: automated restart/duplicate E2Eと、それとは別の、local devnet/CLIの
  start・split/merge/mint/burn/transfer・receipt・orderly restart・persisted state
  をhandsで再現できるdocumented command列（implemented As-Is；criteria 10、DR-0127の
  `apps/cli/tests/devnet_standard_asset_e2e.rs`が
  raw byte-identical duplicate replayを証明し、`docs/guides/devnet.md`の
  local devnet/CLIコマンド列がそれとは独立にstart/split/merge/mint/burn/transfer/
  receipt/orderly restart/persisted stateをhandsで再現する。documented commandはraw
  byte-identical duplicate replay自体を再現するものではない）。
- **S1**: remote TLS transportと、signing前のmandatory trusted protocol-context
  検証を実装する。この2つは別の懸念であり、混同しない：(a) remote TLS transportは
  明示的なtrust policy（例: システムCA + hostname検証、または明示的に設定した
  CA/anchorの検証）のもとでTLS server identityとhostnameを通常どおり検証する。
  brittleなleaf-certificate pinningを唯一の有効なTLS trust設計として要求しない。
  (b) TLS handshakeが成功しても、それだけではclientが意図したchain/protocolに
  接続していることは証明されない（TLSはtransport endpointを認証するのであって、
  protocol contextを認証するのではない）。したがってclient/CLIは、locally
  configuredなexpected chain identityとprotocol policyを要求し、signingの
  前に`/v1/context`から得たremote contextのchain id、protocol version、epoch
  policy、signature scheme、address binding、transaction auth profileをその
  期待値と比較して一致を要求する、という別のmandatory trusted protocol-context
  検証を実装する。TLS証明書/公開鍵のpinningだけでcross-chain signingを防げると
  主張しない。
  **実装状況（2026-09-01）：(a)(b)ともimplemented As-Is。S1全体として完了。**
  (b)のsigning前mandatory trusted protocol-context検証：`clients/rust`は公開
  `ExpectedProtocolContext`（chain_id、protocol_version、この初期sliceの
  exact-epoch policy、hash_suite_id、transaction_auth_profile_id、
  signature_scheme_id、address_binding_id、論理`AtomicityDomainId`）と、
  `/v1/context`を問い合わせてその8フィールド全てを検証してから結果を返す
  `Client::query_verified_context`、フィールド別の型付き
  `ProtocolContextMismatch`を持つ。`apps/cli`の`transfer`は
  `--expected-chain-id`/`--expected-protocol-version`/`--expected-epoch`/
  `--expected-hash-suite-id`/`--expected-domain`の5フラグを必須とし、
  missing/zero/malformedな値をnetwork dispatch前にrejectしてから
  `ExpectedProtocolContext`を構築し、以降のnext-nonce/object query、
  transaction構築、signing、submissionをすべてこの検証済みcontextに基づいて行う
  （未検証の`query_context`は使わない）。8フィールドそれぞれのmismatchに対する
  adversarial testが、`transfer`がcontext requestの1回だけで停止し
  nonce/object queryやsigningへ進まないことを証明する。

  (a)のremote TLS transport：`clients/rust`は`transport::RemoteTlsHttpTransport`
  を追加した。`LoopbackHttpTransport`と同一のbounded HTTP/1.1
  request/response framing・header/body上限・per-stage monotonic deadlineを
  共有しつつ、caller供給の`SocketAddr`（DNS解決は一切行わない）、caller供給の
  DNS server name（TLS SNIとpost-handshake hostname検証の両方に使う。空文字列
  やIPアドレスliteralは拒否し、接続先IPへのfallback検証も行わない）、caller供給の
  CA trust-anchor DER（新設の公開定数`transport::MAX_CA_CERTIFICATE_DER_BYTES`
  （16 KiB）で上限し、空・oversized・不正なX.509はrejectする。systemのtrust
  storeは一切参照せず、mTLS client証明書も提示しない）を要求する。
  `clients/rust/tests/remote_tls_transport.rs`はephemeralな`rcgen`発行の
  CA/leaf対と実際の`rustls` `ServerConnection`serverに対してreal client codeを
  駆動し（fake `Transport`は使わない）、正しいhostname/CAでの成功と正確な
  `Host`ヘッダ、誤ったhostname/CAでのTLS protocol error、stalled handshakeと
  handshake完了前のpeer closeがdeadline内に速やかに失敗すること、caller
  deadlineがtransport budgetを短縮すること、malformedなconstructor入力が
  network I/O前にrejectされることを証明する。同ファイルの回帰testは、
  shared bounded-stream refactorが`LoopbackHttpTransport`のplaintext framingを
  一切変えていないことも証明する。

  `apps/cli`の`context`/`object`/`receipt`/`next-nonce`/`transfer`各コマンドは
  対になったoptional flag `--tls-server-name`/`--tls-ca-cert-der-file`を
  受け付ける（`address`は networkへ出ないため対象外）。両方とも未指定なら
  従来どおりloopback-onlyのplaintext `LoopbackHttpTransport`を使い（非loopbackな
  `--endpoint`は引き続きreject）、両方とも指定した場合のみ`--endpoint`を
  既に解決済みの`SocketAddr`として扱い`RemoteTlsHttpTransport`を使う。どちらか
  一方だけの指定はnetwork dispatch前に型付きerror
  `CliError::PartialTlsConfiguration`でfail closedする。CA fileはstdのみで
  読み込み、transportと同じ`MAX_CA_CERTIFICATE_DER_BYTES`に1 byteを加えた位置で
  `Read::take`により読み取りを打ち切ってoversizeを検出することで無制限のbufferingを防ぎ、
  空/oversized/読み込み失敗をそれぞれ型付きCliErrorで報告する（証明書の中身は
  一切出力しない）。`apps/cli/tests/tls_cli_e2e.rs`は実際の`rcgen`/`rustls`
  loopback TLS serverに対して`sunrise_edge_cli::run`を直接駆動する2つの
  deterministic integration testを追加した：1つは`context`が正しいTLS
  authenticationの下で成功し、`Host`ヘッダが正確なDNS名+portであることを
  証明する。もう1つは、TLS自体は正しく認証できたserverが`--expected-chain-id`
  と食い違う`/v1/context`を返した場合、`transfer`がserver側の接続カウンタで
  確認できる形で正確に1回だけ`/v1/context`を要求し、nonce/object/sign/submitに
  進む前に型付き`ProtocolContextMismatch`を返すことを証明する——TLS
  endpoint認証とexpected-protocol-context検証が独立した別のboundaryであり、
  一方が他方を代替しないことを示す評価である。

  **明示する限界（silentに前提としない）：** DNS解決は一切行わない（callerが
  常に解決済み`SocketAddr`を渡す）。信頼するCAはcaller供給のDER 1個のみ
  （systemのtrust store、PEM/bundle形式、複数anchorの合成はいずれも未対応）。
  mTLSは未対応（client証明書を提示しない）。証明書のrevocation（CRL/OCSP）・
  rotation・lifecycle管理は未実装であり、CA証明書をoperatorのfilesystemへ
  どう配布・rotateするかのdeployment/operations evidenceも本sliceの範囲外
  （S5またはPost-MVP Production Hardeningのpersistence/operations workへ
  明示的に先送り）。TLS endpoint認証とmandatory trusted protocol-context検証は
  意図的に統合しない：TLS handshakeの成功がprotocol-context検証を代替すること
  はなく、検証済みcontextがTLS層の信頼範囲を広げることもない。これは
  mainnet readinessやproduction certificationの主張ではない：Phase 16/17の
  production exit criteriaと独立したsecurity auditは引き続き必須である。
- **S2**: **implemented and validated baseline（DR-0086、DR-0106/DR-0107で現行化）。**
  DR-0086の旧asset-account destination policyはprotocol-v4移行時にmodule/WAT/WASMとともに
  削除された。現行devnetはexact committed typed-entrypoint policyで、sender-owned
  `Write Coin<A>`をindex 0 (transfer対象) とindex 1 (distinct fee coin) に要求し、
  canonical signed recipientへのowner-only mutationをindex 0だけにsynthesizeして独立再検証する。
  cross-owner destination objectは存在せず、recipient stateもread/writeしない。general
  owned-effects pathはsender-onlyのまま、wrong index/mode/type/schema/module/entrypoint、
  duplicate ID、Shared/System/Immutable owner、inadmissible recipientはfail closed。
  exact replay reconciliationはpolicy resolution/object I/Oより先に行い、Transaction/Object/
  receipt/nonce/submitのcanonical bytesは変更していない。real file-backed SQLite E2Eは
  whole-coin owner change、same-boot/post-restart exact replay non-reapplication、request-id reuse時の
  coin/receipt/nonce不変、writer-generation fencingを証明する。旧DR-0086 fixtureの詳細は
  historical decisionとしてのみ残す。
  DR-0108のdevelopment sliceは、この同じsender-owned object boundaryを
  `split`のsource Write + exact-one recipient Create、および`merge`のprimary Write +
  secondary Consumeへ拡張する。generic Createや任意のcaller-selected object idは許可しない。
  DR-0109のdevelopment fixtureはfirst dev ownerの`Read MintCapability<A>`とsender-owned fee
  `Write Coin<A>`を同じassetへunifyし、既存devnet assetのrecipient coinをexact-one
  Createする。任意asset作成とgeneric contract Createは引き続き許可しない。
  **DR-0127以降、この段落全体はhistorical recordである。** この preinstalled
  typed-entrypoint destination policyとpreinstalled module catalog自体がactive devnetから
  削除され、`transfer`/`split`/`merge`/`mint`/`burn`はすべてpolicy-pinnedなordinary paid
  contract call（`apps/cli/tests/devnet_standard_asset_e2e.rs`、[Asset Standards
  Gate](#asset-standards-gate)参照）に置き換わっている。
- **S3**: **implemented and validated baseline（DR-0087、DR-0107で現行化）。** committed
  scheduleはbase=1、execution=`gas_used`単価=1、他category=0、fee registryはderived devnet
  `AssetId`を1:1で1つだけenableする。transfer対象とはdistinctなsender-owned
  `StandardAssetCoinV1`をfee objectとし、ordinary treasury coinをtrusted compositionがfinal
  `Write`として指定する。treasuryはWASM inputから除外され、strict coin codecとchecked arithmeticで
  debit/creditし、payerをzeroにするexact-balance chargeもfail closed。successはowner effectとactual
  feeをatomic commitし、trapはowner effect/eventをdiscardしてnormalized full-gas fee-only mutationを
  Rejected receiptとcommitする。real file-backed SQLite E2Eはexact fee、same-boot/post-restart replay
  non-reapplication、request-id reuse時の全coin/receipt/nonce不変を証明する。single hot treasury、
  fee distribution/production gas calibrationはdeferred。
  **DR-0127以降、この段落全体はhistorical recordである。** この native
  `FeeEffectComposer`とordinary treasury coin構成はactive devnetから削除され、paid
  pricingはinstalled `PaidFeePolicy`（reserve/settle allowanceを使う`ReservationPricer`。
  [DR-0126](docs/architecture/decisions/0126-public-paid-contract-activation.md)/
  [DR-0127](docs/architecture/decisions/0127-public-standard-asset-cli-migration.md)参照）
  のみが担う。
- **S4**: secure signer（`LocalSigner`の development-only in-memory鍵に代わる
  production-oriented signing boundary）と、dedicated Sunrise Edge Ledger device
  applicationを使った実際のLedger統合
  （docs/architecture/decisions/0081-0087-cli-first-roadmap.md DR-0084、
  docs/architecture/decisions/0088-0093-hardware-signing.md DR-0088、
  `docs/signing/hardware-signing.md`参照。既存のSolana/Ethereum Ledger appの転用はしない）。以下を順番に
  完了する。S4cまで通ってもAs-Is host integrationに過ぎず、S4dとCLI replacement前に
  S4完了とはしない。
  - **S4a: implemented and validated As-Is（2026-09-04、DR-0088）。** existing
    `0x2001` signature frameのstrict decoder、fixed 4 KiB hardware profile、
    `execution`/`wasmi`非依存のstrict Transaction v1 decode/re-encode、exact devnet
    transfer allowlist、signed bytes onlyのbounded ASCII display fixture、
    `PreparedTransaction` external-signer preflightを実装する。unknown module/version/
    digest algorithm/digest/entrypoint/args/access/fee shapeはtyped rejectionで、raw args/
    blind-signing fallbackはない。`request_id`、destination owner、transferred asset metadata、
    module nameはsigned contentとして表示しない。
  - **S4b: implemented and validated As-Is（2026-09-04、DR-0091）。**
    `docs/signing/hardware-signing.md`のSLIP-0010 Ed25519、RFC 8032 compressed公開鍵、exact 6-byte
    configuration、E0 APDU state machine、device-side sender comparison、exact
    chain/protocol/epoch/module/entrypoint/arguments/access/fee policy、duplicate ObjectId
    rejection、FIRST 255-byte/230-byte chunk boundsを、separate
    `sunriselayer/sunrise-edge-ledger-app` repositoryで独立実装する。PR #1はallocation-free
    `no_std` host core、merge済みPR #2（`6f6f882`）はpinned `ledger_device_sdk` 1.37.0の
    `no_std`/`no_main` device appとして、raw `04||X||Y`からRFC 8032へのexact conversion、
    actual derivation/signing、NBGL review、session-captured path/exact buffered frameのみの署名、
    Nano S+/Nano X/Stax/Flex/Apex P clean buildを提供する。fixed public development seedの
    Nano S+ Speculos/Ragger suiteはexact configuration、exact public key、senderをそのkeyへ
    置換した1,221-byte canonical-shape fixtureのexact 64-byte signature、元のbyte-identical
    copied fixtureに対するpre-review sender mismatch、same-backend reset recovery、user
    rejectionを検証する。app-owned SWとSDK/OS-owned `6E03`/`5515`/`E000`/in-review
    `6901`/CLA `B0`は分離し、Python dependency closure、Docker image、GitHub Actionsをpinする。
    このrepositoryにnested appやworkspace `exclude`は作らず、canonical transaction/
    signature/object/receipt/nonce/submit bytesは変更しない。
  - **S4c: Phase 1（2026-09-04、DR-0092）とPhase 2a（2026-09-04、DR-0093）が
    implemented and validated As-Is、S4c全体は
    incomplete。** this repositoryのseparate `clients/ledger`（`sunrise-edge-ledger`）
    crateが`docs/signing/hardware-signing.md`のfrozen host APDU/USB/HID contract（FIRST/CONTINUE/LAST
    chunking、exact status word、`get configuration` profile/flags検証、provisional
    derivation path encoding、FIRST acceptance後の後続エラーに対するbest-effort
    reset signing）をinjectable `Transport` traitに対して実装し、
    `signer::LedgerExternalSigner`が`sunrise_edge_client::ExternalSigner`として
    device-reported configuration・on-device-confirmed public key/addressをconnect時と
    sign時の両方でcheckする（roadmapのprofile/address check）。real USB/HID
    `HidTransport`（`hidapi`、`linux-native-basic-udev` feature、system package不要）は
    `HidApi::device_list`経由でLedger vendor id・recognized product-model family
    （既存のS4b five-target build listと一致するNano X/Nano S Plus/Stax/Flex/Apex P。
    build targetのないplain Nano Sは除外）・exactなLedger usage page `0xFFA0`
    （interface-number fallbackなし、strict equality）を検証してからのみopenする
    （同じphysical pathに複数のHID top-level collectionがある場合は全recordを検査し、
    少なくとも1件が3条件すべてを満たす場合のみacceptする。全件invalid時のtyped errorは
    enumeration orderに依存しない。roadmapのdevice check、USB descriptor levelのみ）。full HID write検証、
    incomplete/malformedを即座に区別するread reassembly、bounded total elapsed
    read time（programmatic commandは30秒、human confirmationを待つ`verify public key`と
    signing LASTは各120秒。packet数で乗算しない）、Ledger short-APDU maximum 260 byte（response data最大258 byte +
    2-byte status word）へのresponse bound、non-self-referentialな
    hand-built packet vectorsも実装する。

    **Phase 1が未実装だったactive-app/firmware identity checkはPhase 2a
    （DR-0093）でsoftware実装済み：** 新しい`clients/ledger::identity` moduleが
    Ledger自身のOS-owned identity/dashboard commands（CLA `B0` `INS 01`
    "Get App And Version"、dashboard context限定のCLA `E0` `INS 01` "Get OS
    Version"・CLA `E0` `INS D8` "Open App"。正確なcommand/response shapeは
    Ledger公式`device-sdk-ts`のpinned commit `7f8a719`——`GetAppAndVersionCommand.ts`・
    `GetOsVersionCommand.ts`・`OpenAppCommand.ts`——を一次資料とする）に対して、
    strictなresponse parsing（format byte固定、non-empty ASCII `u8`-length-prefixed
    name/version、optional trailing flags field、余剰byteのtyped rejection、
    Ledgerのshort-APDU response data上限258 byteの事前check）を実装する。
    `verify_dashboard_and_open`はdashboardがexactly `BOLOS`と報告することを
    OS-owned CLA `E0` firmware queryへ送る前にcheckし、firmware versionを
    compareする前にtarget idのtop nibble（normal Secure Element OS）と`-osu`
    （OS Upgrade）markerをrejectし（bootloader/OSU deviceがgenericな
    version mismatchへ後退しないようにする）、その後にのみdashboard-reported
    Secure Element versionをcaller-supplied・事前validated（non-empty ASCII、
    64 byte以下）な`ExpectedFirmwareVersion`とexact一致させ、exactly
    `Sunrise Edge`で`open app`を送る。callerがexact同一のexplicit pathで
    reconnectした後、`verify_active_app`はactive applicationがexactly name
    `Sunrise Edge`・exactly version `0.1.0`を報告することをCLA `B0`でcheckする。
    既存の6-byte `get configuration`（`configuration::Configuration::require_supported`）
    もexact version `0.1.0`をpinするよう拡張された。既存のprofile/address
    preflight（`get configuration`確認とon-device-confirmed `verify public key`）は
    これらすべてのidentity checkの後に変わらず続く。**Phase 2aもPhase 1と同じく
    `FakeTransport`のみに対するsoftware-only実装であり、real physical hardwareに
    対するvalidationは一切ない：** 上記すべて（APDU protocol、identity/dashboard
    parsing、USB HID framing、device recognition）のphysical hardwareに対する
    validationはdeferredなS4c Phase 2bで実装する。caller-supplied
    `ExpectedFirmwareVersion`はper-connectionのoperator inputであり、S4dの
    pinned/workspace-committed multi-model app/firmware compatibility matrix
    ではない。off-by-default `usb-hid` feature配下以外の全moduleは`FakeTransport`
    によりnative dependencyなしでdeterministicにtestされ、`usb-hid`有効時の
    descriptor/framing/identity testsもall-feature gateで検証する。DR-0093時点のCLIは
    `address`/当時の`transfer`へ`--seed-file`または
    `--ledger-hid-path`+`--ledger-account`+`--ledger-expected-firmware-version`の
    explicit all-or-none signer selection（第3 flagはdevice dispatch前に事前
    validated）を追加し、Ledger選択時はネットワークdispatch前にdevice接続・
    dashboard identity・firmware・open app・reconnect後のactive-app identity・
    configuration・public key checkのすべてを`signer::connect_ledger_staged`で
    完了する。real `usb-hid`のreconnectは同一explicit pathへの`HidTransport::open`を
    bounded monotonic deadline（30秒）・fixed retry sleep（500ミリ秒）で再試行し、
    timeout時はtyped `CliError::LedgerReconnectTimedOut`でfail closedする。
    DR-0107でlive devnetのtransfer shapeをprotocol-v4 Standard Asset v1へreplaceしたため、
    現在のoperator flowは`address`だけがLedgerのon-device確認を行う。`transfer`のLedger選択は
    new clear-signing policyが未実装なので、device/network dispatch前にtyped errorで拒否する。
    DR-0093時点の3回確認はhistorical protocol-3 fixtureの挙動であり現在のlive pathではない。
    feature非依存の`FakeTransport` testはCLIのexact `DeviceSigningProfile::V1` +
    `HISTORICAL_ASSET_ACCOUNT_TRANSFER_POLICY_V3` helperをpolicy-conforming `PreparedTransaction`とvalid
    Ed25519 signatureで実行し、local signerと同一canonical outputおよびpolicy mismatch時の
    pre-device rejectionを証明する。vendor dependencyはprotocol crate/`clients/rust`
    には入らず`clients/ledger`に閉じ、CLIのone-runtime-dependency invariantは
    `sunrise-edge-client`と`sunrise-edge-ledger`の2つへDR-0092で明示的に改訂された。
    canonical transaction/signature bytesとlocal-signer pathは不変である。
  - **S4d:** S4bのNano S+ Speculos CIを維持した上で、golden/pixel UI evidence、claimed
    device modelごとのphysical-device HIL、broader user rejection/disconnect/device-reset/
    adversarial session/chunk evidence、pinned app/firmware compatibility matrix、two-clean-build
    reproducibility evidence、Ledger release/submission evidenceを揃え、CLIのdev-only
    `LocalSigner`をactual production pathで置き換える。Sunrise Edgeにはまだregistered
    BIP44/SLIP-0044 coin typeがなく、S4aのpathはdevnet-only provisionalである。
- **S5**: Initial Code Security Audit Entry Gateを先行させた後、production persistence
  （docs/operations/persistence.md/docs/operations/postgres.mdのTo-Be）、既に実装済みのtransactional outbox contractを
  selected providerの運用へ接続する作業、provider deployment（Cloudflare Durable
  Object/AWS）、operations（observability、runbook）、初回監査後のdelta security review、
  release evidence（migration/backup/disaster recovery rehearsal、reproducible build）を
  完成させる。transactional outboxのatomic commit/indexed claim/ack contract自体を
  未実装として作り直さない。

capacity/PITR/HAは、S5で明示的にtriggerされる（S5のcertificationやSLOが実際に
それらを要求する）までfrozenのままとする。これは既存の凍結方針
（`Post-MVP Production Hardening`冒頭の凍結宣言）を変更しない。

**production targetはconservativeにmulti-validator L1であり、single-operator
serviceではない。** このgateのS0-S3 baseline、S4/S5 parallel tracksと既存のvalidator-set/consensus
criteriaは、単一operatorが恒久的に運用する前提のserviceではなく、複数
validatorが独立に運用するL1へ向けたstepとして設計されている。

Phase 1:
- workspace
- protocol primitives
- canonical encoding
- HashAlgorithmId
- Digest types
- HashDomain
- HashSuite
- SHA-256 implementation
- SHA3-256 implementation
- crypto/signatures
- cryptographic test vectors

Phase 2:
- Object model
- ObjectRef
- access modes
- ABI

Phase 3:
- Runtime abstraction
- MemoryRuntime
- persistence layout

Phase 4:
- Validator identity
- Genesis validator set
- Epoch model

Phase 5:
- Fast Path
- Object locks
- Vote
- Certificate

Phase 6:
- Fee asset registry
- stablecoin fees
- validator fee distribution

Phase 7:
- Bond assets
- BondObject
- slashing evidence
- validator admission

Phase 8:
- Governance
- GenesisPermissioned -> BondAndGovernance

Phase 9:
- deterministic WASM ExecutionEngine
- Rust contract SDK

Phase 10:
- Chain IR

Phase 11:
- System Module Registry
- governance-installed precompiles
- native acceleration

Phase 12:
- Protocol upgrades
- HashSuite upgrades
- FeatureFlags
- lazy migrations

Phase 13:
- Shared Object consensus

Phase 14:
- CommitmentScheme abstraction (implemented)
- Poseidon2-based experimental ZK commitment suite (BN254 implemented;
  BLS12-381 identifier remains reserved and unsupported)
- execution proof interfaces (implemented; concrete proof backends deferred)

Phase 14 As-Is:

- SHA-256とexperimental Poseidon2/BN254のleaf/node commitment framingがある。
- Poseidon2/BN254はsafe Rustの監査容易性を優先した実装で、inactiveであり、
  temporary 4 KiB leaf limitがある。
- BLS12-381はidentifierのみ予約され、実装・activationされていない。
- ExecutionProofはcanonical envelopeとexact-ID verifier dispatchまでであり、
  concrete prover/verifier、verification key lifecycle、protocol activationはない。

Phase 14 To-Be production exit criteria:

1. Commitment scheme specificationを独立したprotocol specificationとして固定する。
   field modulus、S-box、width/rate/capacity、round constants、byte-to-field mapping、
   padding、endianness、tree depth、key-bit order、empty nodes、leaf/node domains、
   proof encodingを曖昧さなく記述する。
2. Poseidon2 implementationは独立レビュー済みの実装へ置換するか、現実装を
   production cryptographyとして別実装とのcross-check、property/fuzz test、
   side-channel評価、性能評価、暗号レビューまで完了させる。単一KATだけでは
   production承認としない。
3. temporary 4 KiB limitを、object size・proof cost・validator CPU budgetから導いた
   protocol上の正式な上限へ置き換える。上限内のworst-case benchmarkとDoS budgetを
   nativeおよび対象edge runtimeで満たす。
4. 完全なversioned sparse-Merkle treeを実装する。empty root、membership/non-membership
   proof、更新proof、複数objectのcanonical ordering、batch update、old/new root検証、
   malformed proof rejection、stable vectorsを含める。
5. CommitmentScheme activation/migrationをProtocolConfigとgovernance-controlled scheduleへ
   統合する。validator capability、future activation、unknown/unsupported scheme rejection、
   historical root/proof verification、rollback非依存のlazy migrationを検証する。
6. BLS12-381 identifierはproduction parameter setと実装を完成させるか、未対応のまま
   予約する理由とactivation禁止を明文化する。identifierの存在だけをsupportと数えない。
7. ProofSystemIdはproof system名だけでなく、version、curve/field、transcript、proof format、
   public statement version、verifying-key commitment、program image/circuit commitmentを
   一意に固定するregistry/specificationへ接続する。
8. 少なくとも1つのconcrete prover/verifier backendを実装し、Chain IR canonical executionと
   proven executionのeffects/output commitment一致、invalid proof rejection、resource bounds、
   deterministic cross-runtime verification、stable vectorsを検証する。
9. validator quorum onlyからquorum + proof、さらにproof-centric verificationへ移る
   activation policy、failure policy、fee/gas accounting、observability、
   consensus rollbackに依存しないsafe disable/recovery planを実装する。
10. cryptographic review、adversarial test、fuzzing、cross-implementation vectors、
    reproducible benchmark、independent security auditを完了する。これらを満たすまで
    Poseidon2とexecution proofをproduction-readyまたはmainnet-readyと表現しない。

Phase 15:
- native HTTP adapter (implemented As-Is)

Phase 15 prerequisites:

- bounded canonical frame decoder (implemented)
- deterministic node-core event boundary with one-key CAS persistence
  (implemented As-Is)
- adapter-neutral canonical request/response contract (implemented As-Is)
- bounded versioned multi-key StateStore transaction contract with an in-memory
  atomic reference implementation (implemented As-Is)
- declared-access transactional node-core invocation over versioned snapshots
  and atomic write sets (implemented As-Is)
- canonical request-id/event-digest dedup record and request-scoped outbox batch
  in the same atomic commit (implemented As-Is)
- ordered one-message outbox claim/lease/ack cursor with explicit at-least-once
  redelivery semantics (implemented As-Is)
- native HTTP default path using atomic deduplication and request-scoped
  persisted outbox lease/send/ack delivery (implemented As-Is)
- local durable SQLite TransactionalStateStore with WAL, synchronous FULL,
  BEGIN IMMEDIATE, revision tombstones, and schema identity checks (implemented As-Is)
- production persistence architecture separating validator-local atomicity
  domains, normalized logical data, indexed outbox recovery, provider mappings,
  migration, retention, and disaster recovery from the SQLite reference
  (design accepted; implementation pending)
- complete declared read-set revision assertion in transactional and
  idempotent node-core commits, including read-only and absent keys
  (implemented As-Is; domain-aware node-core migration pending)
- non-zero AtomicityDomainId、dedicated bounded/canonical read assertion set、
  put/delete mutation set、mutation-read containment、64 MiB aggregate envelope、
  domain-isolated memory conformanceを持つDomainTransactionalStateStore
  (implemented As-Is; node-core/durable provider migration pending)

Phase 15 As-Is scope:

- NodeEventはchain_id、protocol_version、epoch、non-zero request_id、closed event kind、
  bounded canonical payloadを持つ。
- node-coreはcontextをstate read前に検証し、1 event / 1 explicit state valueをpureな
  NodeStateMachineへ渡す。
- transition outputはcompare-and-swap成功まで返さない。競合時は内部retryせず、
  adapterへStateConflictを返す。
- node-core自身はsign、send、schedule、spawn、background loopを行わない。
- request_idはdeduplicationを実装するためのidentityであり、存在だけではidempotencyを
  保証しない。
- 現在のsingle-key CASはnative adapter統合用の実験的境界であり、production persistence
  architectureの完成形ではない。
- runtimeにはuniqueかつkey順へcanonicalizeされたbounded write-set、monotonic per-key
  revision、delete tombstoneによるABA防止、全revision一致時だけall-or-noneでcommitする
  TransactionalStateStoreを追加した。MemoryStateStoreはatomicity/conflict/bounds検証用の
  As-Is referenceでありdurable実装ではない。
- runtime-sqliteはexact-pinned bundled SQLiteを使い、WAL + synchronous FULL、5秒busy timeout、
  BEGIN IMMEDIATE、8-byte revision、delete tombstone、application/schema ID fail-closedを実装する。
  reopen persistence、ordered conflict、revision overflow、CASを検証する。recovery adapter向けには
  StateStore point-readと分離したStateKeyScannerを実装し、non-empty binary prefix、prefix内exclusive
  cursor、1,024以下のnon-zero limit、canonical order、1-row lookahead continuation、tombstone visibilityを
  強制する（implemented As-Is）。page間snapshotではないため各sweepをprefix先頭から再開する必要がある。
  blocking local-disk storeでありproduction-grade componentsを使うdeployment compositionは未実装である。network filesystem、
  kill -9/power-loss、backup/restore、capacity検証なしにprovider production persistence完成とはみなさない。
- `docs/operations/persistence.md`はSQLiteをlocal durable reference/conformance fixtureに限定し、production To-Beを
  `(chain_id, validator_id, atomicity_domain)`単位のsingle-writer authority、全read-set revision assertion、
  normalized object/request/outbox/checkpoint/migration schema、indexed due-outbox claim、writer fencing、
  content-addressed blob、明示的migration/backup/restoreとして固定する。PostgreSQLを最初の
  production-oriented reference targetとし、Cloudflareは1 domain = 1 SQLite-backed Durable Object、
  AWSは初期single fenced writer regionへ写像する（design accepted; implementation/certification pending）。
  D1 read replica、DynamoDB Global Tables、scheduler/queue/alarmをauthoritative atomicityやconsensus trust rootに
  してはならない。cross-domain writeは別protocol decisionなしにbest-effort dual writeで実装しない。
- atomicity domain IDはprovider/database addressではなくgenesisまたはgovernance activationでcommitされる
  logical protocol identityとする。初期DomainPlacementManifestはmonotonic rule version、exactly one non-zero
  never-reused domain、closed `AllState` rule、activation epochを持つ。node-coreはbounded access plan確定後かつ
  state read前に全application keyをresolveし、receipt/outbox/deliveryはそのinvocation domainを継承する。
  `(chain, validator, logical domain)`からPostgreSQL/DO/AWS authorityへのbindingはwriter-fenced deployment
  metadataでありprotocol identityへ混ぜない。AtomicityDomainIdはprotocol-typesへ置き、zeroをrejectする。
  DomainPlacementManifestはnon-zero rule version、domain、closed AllState tag、activation epochをcanonicalizeし、
  historical ProtocolConfig encoding v1を維持したままprotocol version 2+のfield 14/encoding v2としてcommitする。
  v1+manifest、v2+-manifest、empty access、pre-activation resolveはfail closedする（implemented As-Is;
  node-coreはevent context検証後にaccess planを1回だけderiveし、storage read前にmanifestをresolveして、
  committed outputと同じdomainを返すadditive handlerを持つ。native-httpはDomainTransactionalStateStore限定の
  additive routerでそのdomainをrequest-scoped outbox claim/ackまで引き回し、HTTPからdomainを受け取らない
  （implemented As-Is; durable domain store/indexed unattended recovery pending）。
- runtimeはnon-zero 32-byte AtomicityDomainId、unique/canonicalなAtomicStateReadSetと
  AtomicStateMutationSet、それらを1 domainへ閉じ込めるAtomicStateTransactionを持つ。
  全mutation keyはread assertionを必須とし、各set 4,096 keysおよびaggregate represented bytes 64 MiBを
  shared safety ceilingとして検証する。MemoryStateStoreは同一keyのdomain isolation、complete-read conflict時の
  all-or-noneを検証する（implemented As-Is）。legacy unscoped stateはprivate test domainへ隔離され、
  node-coreはadditiveなdomain-aware transactional/idempotent handlerでapplication state、dedup receipt、
  outbox batch、initial delivery cursorを1 domain transactionへ接続した（implemented As-Is）。同一keyの
  domain isolation、replay、dependency conflict時にresult/receipt/outboxを一切publishしないことを検証する。
  outbox lease/ackにもdomain-aware entrypointを追加し、legacy/domainでidentity、lease、cursor検証を共有しつつ、
  immutable batch assertionとdelivery mutationを1 domain transactionへ閉じ込めた（implemented As-Is）。
  resolved-domain native request compositionは接続済みだが、runtime-sqlite、legacy default router、scan-based
  unattended recovery、provider adapterはまだnew contractへ移行していない。
- production durable operation boundaryはnon-zero monotonic writer fence、absolute storage deadline、
  bounded non-zero correlation IDを1 invocation contextとして分離し、commit outcomeをCommitted、
  definite Rejected、Indeterminateへ閉じた。revision conflict、stale fence、serialization abort、
  commit dispatch前に証明されたdeadline/unavailabilityだけをdefinite abortとし、dispatch後のdeadline、
  connection loss、cancellationはbackendのauthoritative abort evidenceなしに失敗扱いしない
  （boundary/node-core/native composition/normalized PostgreSQL implemented As-Is;
  other durable provider wiring pending）。correlation ID、fence、deadlineを
  protocol canonical input、request dedup identity、HTTP caller-selected authorityにしてはならない。
- runtimeはnormalized store向け`DurableInvocationTransaction`を持つ。logical domain、read-onlyも許すoptional
  complete state section、typed canonical receipt、optional typed ordered outbox、explicit object sectionを分離し、
  aggregate bytesとstate domain、receipt/outbox request ID、event digest一致をI/O前に検証する。
  object sectionはcanonical unique/sortedなbody-free head assertion、read containment付きcreate/update/delete、
  distinct immutable versionとABA-safe head revision、inline canonical `objects::Object`またはself-describing blob参照を持つ。
  inline owner projectionはwrite時にtyped `Owner`から導出し、immutable versionはheadと別APIで読む。head readは
  inline bytesをSELECTせず、immutable row metadataとinline presence/lengthのみを検証する。headのowner/routing projectionは
  routing hintでありauthorizationではない。executionは別途exact versionを読み、head version/digestとの一致、inline Object decode、
  typed owner一致を検証しなければならない。blob-backed bodyは明示的に分離された`BlobStore`
  componentからfetchし、独立にverifyしてからdecode/authorizeする(DR-0094, implemented As-Is)。
  accepted authenticated Create/Updateがcommitするnewバージョンは、その canonical bytesが固定
  deterministic threshold（`node_core::MAX_INLINE_OBJECT_BODY_BYTES`、64 KiB）を超える場合のみ
  同じ`BlobStore`へpublishされblob referenceとなる。threshold以下（devnet asset accountを含む
  通常の小さいbodyはすべて該当）はこれまで通りinlineのままである。inline/blobの判定はpureな
  staging passでI/Oを行わず、実際の`put_blob`呼び出しはstate/object/receipt/outboxの完全な
  envelopeを構築・検証した後、structured commitの直前にのみ実行される（content-addressed
  insert-if-absent、同一object digestをkeyとして再利用、DR-0096, implemented As-Is;
  publish失敗はstate/receipt/nonce/outbox/object変更ゼロでabortし、複数put時に先行するpublishが
  既に成功していれば unreachable orphan として残る。後続のcommit rejectionも同様に
  publish済みblobをunreachableなcontent-addressed orphanとして残すのみ）。
  現在到達可能なのはUpdateのみで、Create effectは引き続きfail-closed/deferredである。ただし将来の
  Create実装が同じpersistence policyを迂回しないようstagingは両mutation variantを処理する。
  durable provider
  `BlobStore`（PostgreSQL/Cloudflare/AWS等、local file-backed SQLite blob storeを除く）と
  GC/checkpoint manifestは引き続き未実装。
  memoryとPostgreSQLはstate/object/receipt/outboxを同一atomic boundaryで実装済みである。authenticated
  structured durable pathはsigned read-only manifestをexact head/immutable inline versionからloadし、verified
  senderに対するtyped owner authorizationと完全なhead assertionを同一commitへ接続した（implemented As-Is）。
  すべてのimmutable object versionはcreating chain/protocol version provenance
  （`DurableObjectProvenance`、DR-0068、required field、schema redefinition済みなので
  legacy行は存在しない）を保持し、node-coreは`load_and_authorize_objects`内で
  inline payload/identity/schemaのcross-checkの後・owner-projection cross-checkの前に、
  stored `Digest32`のself-describing algorithmとそのprovenanceを使い
  `hashing::verify_digest`でdigestを独立に再計算・検証する
  （reader epochのhash suite resolverは使わない。使うとlegitimateなhistorical objectを
  誤ってrejectしてしまう）。record provenanceのchain_idはtrusted event chainと
  一致しなければならないが、protocol_versionには同等のcheckはない
  （olderなobjectも引き続きverifyできなければならないため）。inline bodyは
  hashing前に`MAX_AUTHENTICATED_OBJECT_BODY_BYTES`（1MiB/object）と
  `MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES`（8MiB/invocation）でbound済みである
  （pre-activation admission budgetであり測定済みcapacity limitではない）。
  PostgreSQLはgeneration oneをschema identity v2へin-place redefinitionし、
  さらにnamespace-bound blob tableを含むv3へ再定義した
  （いずれもpre-release bootstrap-only、`POSTGRES_SCHEMA_GENERATION`は1のまま）。
  v2では`object_versions`に
  `created_chain_id_bytes`/`created_protocol_version`と
  `CHECK (created_chain_id_bytes = chain_id_bytes)`を追加した。既存のv1/v2 schemaは
  bootstrap/inspection/request-path metadata readのすべてでfail closed
  （`SchemaMismatch`）する（object digest provenance/recomputation implemented As-Is;
  DR-0067の該当pending itemを解消した）。
  verified inputとdeterministic `ObjectEffect`をstrictに対応付け、owned Address objectのUpdate/Deleteを
  bounded durable mutationへ変換するadditive handlerはimplemented As-Isである。Create、owner/type/schema変更、
  version不整合、undeclared/duplicate effect、overflow、untrusted mutation contextはfail closedにする。
  verified objectはsigned manifestの宣言順でtransitionへ渡し、composition-trusted checkpointのregressionを拒否し、
  exact head assertion、Update/Delete、nonce、state、receipt、outboxを同じstructured durable invocationでcommitする。
  exact request replayはobject I/Oやtransitionより先にreceiptからreconcileするためeffectを再適用しない。
  generic handlerはresolved objectを渡さず、返されたeffectを黙って捨てずにfail closedにする。
  bounded preinstalled module loadとdeterministic WASM executionはadditive node-core entrypointへ
  接続済みで、認証時のcommitted registry、immutable catalogのcode/manifest/semantics commitment、
  manifest input boundとpre-activation gas ceilingをfail closedに照合し、code/manifest commitmentは
  digest自身のalgorithmと専用SystemModule domainで再検証し、canonical effectsをowned object atomic
  commitへ渡す。trap text/fuel accountingは固定reason/full-gas/empty-effectsへ正規化してから永続化する。
  exact replayはmodule resolve/object read/execution前にreceiptから返る。additive preinstalled-WASM native router
  （`preinstalled_wasm_structured_durable_router`/`_with_executor`）はこのentrypointへwiring済みである一方、
  generic structured durable routerはread-only entrypointのままである。Shared/System owner、
  arbitrary provider wiring、owned fast path certificateは未実装である。blob-backed bodyのfetch/
  verificationはDR-0094でimplemented As-Isであり、authenticated commitが生成するnew versionの
  固定64 KiB threshold超過時のblob publicationもDR-0096でimplemented As-Isである
  （threshold以下の通常の小さいbodyはinlineのまま）。devnet/startup composition
  （`apps/devnet`）は`boot_local_store`が同じdata dir下に別ファイル`blobs.sqlite3`（独自schema/
  application identity、WAL、synchronous FULL）として`runtime-sqlite::SqliteBlobStore`を開き
  `compose_devnet_router`へ明示的に渡すため、threshold超過のblob-backed versionはdevnet
  restartを生き残る設計だが、devnet asset accountのbodyは常にthreshold未満のため実際には
  この経路はまだ行使されていない（durable provider（PostgreSQL/Cloudflare/AWS等）`BlobStore`
  は引き続き未実装）。fee debit（S3のuniform ordinary-asset fee slice、DR-0087）はimplemented
  As-Isである。
  node-core additive handlerはmanifest domainをI/O前にresolveし、typed receipt replayをstate readより先に行い、
  read-only assertionを含むstate/receipt/outboxをこのenvelopeへ構築する。definite commitまたはexact replay以外では
  outputを返さない。single-lock memoryとnormalized PostgreSQL conformance storeでatomic publication、object lifecycle/ABA、
  conflict rollback、read-only、bound domain、fence、deadline、object read-count bound、blob round-trip、replayを検証する
  （runtime/memory/PostgreSQL、node-core authenticated owned-object atomic effects、bounded preinstalled
  module execution、additive preinstalled-WASM native router wiring implemented As-Is; generic structured
  durable routerはread-onlyのまま、devnet/startup compositionとarbitrary provider wiring/certification
  pending）。
- owned transaction fast pathの認証基盤として、`crypto`にexact-pinned
  `ed25519-zebra` 4.2.0（`[workspace.dependencies]`でdefault features無効を
  一箇所宣言。committed `Cargo.lock`はその依存`curve25519-dalek`を4.1.3で
  pinし、直接使わないunused dependencyとしては追加しない。Dependabotが
  どちらかのpinへ更新を提案してもauto-mergeせず既存policyでreview-gateする）
  によるZIP-215準拠のreal `Ed25519Verifier`を追加した（32-byte検証鍵・
  64-byte署名のみを受理し、非canonical encodingとsmall-order pointを
  受理するconsensus-deterministicな検証で、production signerは追加しない。
  `verify_framed`はlength検証済みの署名を明示的な`[u8; 64]`へcopyしてから
  infallibleなfixed-size `From`constructorで`Signature`を構築し、
  すでにlength検証済みの値に対するdead/mislabeledなlength-error mappingを
  持たない。`runtime::MemorySigner`はtest/local runtime合成用のpublicな
  in-memory wiring fixtureであり、意図的にnon-cryptographicで、protocol
  authenticationには絶対に使ってはならない。test-only compilation flagで
  gateされているわけではない）。`SignatureSigner::sign_canonical`と
  `SignatureVerifier::verify_canonical`（trait default method）は、
  caller供給の`SignatureDomain::signature_scheme_id`がsigner/verifier自身の
  `scheme_id()`と一致しない場合、framingや暗号操作を一切行う前に型付き
  `CryptoError::SignatureSchemeMismatch { expected, actual }`でrejectする
  （`frame_signature_message`自体のbyte formatは不変）。`protocol-config`には
  committed `TransactionAuthProfile`をProtocolConfig field 15・encoding v3
  として追加し、protocol version 3以降でのみ必須、v1/v2 historical bytesは
  不変である。profileのprofile idはarbitraryなnon-zero labelではなく
  committed protocol identifierであり、`TransactionAuthProfile::new`と
  新設の`TransactionAuthProfile::validate`（`new`および
  `ProtocolConfig::validate`から、zero idの再検証だけでなく呼ばれる）は
  同じrulesを適用する: zeroを`ZeroTransactionAuthProfileId`でreject、
  committed profile id 1/2以外を型付き
  `UnsupportedTransactionAuthProfileId(u16)`でrejectしてからexactな
  scheme/binding組み合わせを検証する。profile 1はhistorical
  `AddressIsPublicKey`、profile 2はcanonical-prime-order address bindingを持つ。
  `SignatureSchemeId`はEd25519のみ実装し、Secp256k1は予約でfail closedする。
  `resolve_transaction_auth_profile`はcommitment/resolution層であり、
  返す前に`ProtocolConfig::validate()`を必ず呼ぶため不正な設定は
  activation判定より先にfail closedする。`protocol-config`は`crypto`にも
  `objects`にも依存せず、署名検証は一切行わない（`crypto`/`protocol-config`
  implemented As-Is; RFC 8032 known-answer、ZIP-215 small-order/non-canonical
  point acceptance、RFC 8032 §5.1.7とZIP-215が共に要求するS<lルールに基づく
  非canonical `S` rejection、signature scheme mismatch rejection、
  premature/missing profile・unsupported profile id・unsupported scheme・
  不正configのadversarial testを含み、`ed25519-zebra` 4.2.0 /
  `curve25519-dalek` 4.1.3で再確認済み）。strict transaction authentication
  とproduction-oriented structured durable native routeの接続もimplemented
  As-Is（下記bullet）。persistent sender nonceもimplemented As-Is（下記bullet）。
  fee（S3のuniform asset fee slice、DR-0087）とmodule/object effects（additive
  owned-effects entrypointおよびpreinstalled-WASM entrypoint）は現在implemented
  As-Isだが、FastCertificateとCLI-First Node Production GateのS4/S5・independent
  security reviewは引き続き未実装であり、protocol version 3のlive activationは
  禁止したままである。
- `execution::decode_transaction`はexecution::Transaction v1の厳密な
  standalone canonical decoderを追加した：type id/encoding version 1を要求し、
  field 1-10と12を必須、field 11（`fee_payment`）のみoptionalとして
  exactに要求し、unknown/missing/duplicate/out-of-order field、trailing/
  truncated bytes、invalid UTF-8、誤ったnumeric/address/digest length、
  unknown tag/algorithmをtyped errorでrejectする。`AccessManifest`/
  `AccessEntry`（`abi`）、`ObjectRef`/`ObjectId`/`Address`/access mode
  （`objects`）、`FeePayment`/`AssetId`（`fees`）にも対応するpublic decoder
  を新設し、既存のstable type idとencoding version 1を再利用した。
  entrypoint・args・signature・manifest entry countには既存の32 MiB
  canonical frame boundより厳しいtransaction-specific boundをattacker-
  controlledなbytes/entriesをcopyする前に適用し、`AccessManifest`内の
  重複`ObjectId`とnon-canonicalなcount/field layoutをrejectし、最後に
  decode結果を再encodeしてinput bytesとbyte-for-byte一致することを要求する
  （代替表現を一切受理しない）。署名検証やSignatureDomain構築は一切行わない
  canonical-structure boundaryのみであり、上記の**hard activation
  constraint**を単独で満たすものではない：protocol version 3の活性化には、
  committed profileから`SignatureDomain`を構築し実際に署名を検証する
  authentication dispatch層が別途必要である。
- `node-core`はこのauthentication dispatch層をstandaloneなfail-closed
  boundary `node_core::transaction_auth`として追加した（`node-core`が
  workspace dependencyとして`execution`と`crypto`を新たに追加。
  `protocol-config`はこれまで通りどちらにも依存せず、署名検証も行わない）。
  公開entrypoint `authenticate_transaction_bytes(input, context)`は
  明示的な`TrustedTransactionContext`（caller供給の`ChainId`/`Epoch`と
  committed `ProtocolConfig`への参照。protocol version権限は
  `ProtocolConfig`のみが持ち、drift可能な別のcaller供給versionは受け付けない）
  を受け取り、(1) 委任profileをresolveし、premature/missing/invalidな
  configをdecode前にfail closedし、(2) `execution::decode_transaction`で
  厳密にdecodeし、(3) decode済みtransactionの`chain_id`/`protocol_version`/
  `epoch`をtrusted context/configと比較し、鍵や署名が不正な場合でも
  暗号処理より前に型付きmismatch errorでrejectし、(4) trusted contextと
  resolved profileのみから`crypto::SignatureDomain`を構築する。profile 1は
  historical `"transaction-v1"`、profile 2はouter `request_id`とexact
  Transaction-v1 signable bytesを含む`0xE009` envelopeを
  `"submit-transaction-v1"` familyで署名し、
  (5) signature fieldを除いたsignable payloadをencodeし、明示的で
  deterministicな`node_core::MAX_TRANSACTION_SIGNABLE_BYTES` boundを
  `crypto::frame_signature_message`やverifierがallocate/hashする前に適用して
  oversizedなsignable bytesを型付きerrorでrejectし、(6) 委任profileの
  closed `AddressBinding`に従い、profile 2ではtransaction senderをcanonical、
  non-identity、prime-order subgroupへ制限してからEd25519 verification keyとして
  使う（未実装のfuture binding/schemeはconfig/profile validationにより
  fail closedし、fallbackしない）、(7) committed
  `crypto::Ed25519Verifier`で検証し、malformed key/malformed signature
  lengthの型付き`CryptoError`と、well-formedだが暗号学的に不正な署名
  （型付き`InvalidTransactionSignature`）を区別し、(8) `Ok(true)`の場合のみ
  新設の`AuthenticatedTransaction`を返す。`AuthenticatedTransaction`は
  内部の`execution::Transaction`をprivate fieldとして持ち、read-only
  accessorとconsuming accessorのみを公開し、公開constructorを持たない。
  production signerは追加せず、devテストのみexact-pinned workspace
  `ed25519-zebra` `SigningKey`で決定的な署名を生成する。deterministic real
  Ed25519 happy path、wrong signatureの`InvalidTransactionSignature`、
  malformed signature length/malformed verification keyの型付き
  `CryptoError`維持、chain/protocol-version/epoch mismatchの暗号処理前
  rejection（鍵や署名が不正でも）、chain/protocol-version/epoch/message
  family across domain replayの失敗、premature/missing profile・invalid
  configのfail-closed、bound到達時のverifier work前rejectionを含む
  exact signable bound behavior、strict canonical bytesのみ受理し
  malformed/代替表現は`ExecutionError`経由で失敗すること、signature field
  自身をsignable payloadがcoverしないこと、signable fieldの変更が
  authenticationを無効化することをtestで検証済みである
  （`node-core`実装、workspace test As-Is）。production-oriented
  structured durable native routeはcommitted `ProtocolConfig`をcomposition
  authorityとして受け、outer `NodeEvent`のcontextを検証してからinner
  transactionを`AuthenticatedSubmitTransaction`へ変換する。認証はaccess
  plan、identity、storage用clock、storage read/write、transition、outbox
  claim/sendより前であり、wrapperは同じconfig由来のplacementを保持して
  normalized durable commitへ渡す。exact duplicateもreceipt照合より前に
  再認証する。generic node-core handlerおよびlegacy native routeは
  `SubmitTransaction`を型付きでrejectし、unauthenticated bypassを残さない。
  invalid signature、inner/outer chain/version/epoch mismatch、missing profile、
  trailing/non-canonical bytesはmachine/identity/clock/storage/sendのcall count
  zeroで失敗するtestを持つ。transaction wire field/encoding versionは追加して
  いない。protocol version 3のlive activationはshared-object ordering、
  FastVote/FastCertificate、certificate publication、他event familyの
  authorized ingressがprotocol semanticsの要求する箇所でauthenticated
  transactionとatomically composeされ、かつ独立してS4/S5と独立
  security/release gateが完了するまで禁止する。fee（S3のbounded uniform
  ordinary-asset fee composition、DR-0087）とmodule/object effect（additive
  owned-effects entrypointおよびpreinstalled-WASM entrypoint）はimplemented
  As-Isだが、単独ではこのconstraintを満たさない。
  **Hard activation constraint:** `SubmitTransaction`以外の
  externally acceptedなnode-event family(特にcertificate、protocol upgrade、
  validator-set change)も、live activationの前に同等のauthenticated/authorized
  ingressを持たなければならない。DR-0099のpublic native ingressは現在
  `SubmitTransaction`以外をside effect前にrejectする。profile 2ではouter
  `NodeEvent`の`request_id`もcanonical submission envelopeでexact
  Transaction-v1 signable bytesとともに署名され、relabelは認証で失敗する。
  profile 1のhistorical signed bytesは不変である。
- authenticated structured durable `SubmitTransaction` pathは、verified inner
  transactionからのみprivateな`(sender, epoch, nonce)` reservationを導出し、
  `PersistenceLayout`のchain/protocol-version/sender/epoch namespaceにcanonical
  next-nonce record type `0xE006`を保存する。record自身もsender/epochをbindし、
  key/value mismatchやcorrupt bytesはfail closedする。missingはexpected zero、
  exact equalityのみを受理し、checked incrementをapplication state/receipt/
  outboxと同じnormalized durable invocationに含める。exact receipt replayは
  nonce readより先にreconcileして二重消費しない。fresh requestはnonceを
  application stateより先に読み、stale/skipped nonceをtransition/commit前に
  型付き`SenderNonceMismatch`でrejectする。`u64::MAX`はwrapせず
  `SenderNonceOverflow`でrejectする。native HTTPはそれぞれ409
  `sender-nonce-mismatch`、422 `sender-nonce-overflow`へ分離してmappingする。
  absent/existing nonce raceはread revision assertionにより片方のみatomic commit
  できる。committed Accepted/Rejectedはnonceを消費し、authentication/
  transition/pre-commit failureは消費しない。application planは全event familyで
  nonce prefixをclaimできず、authenticated pathはatomic state write slotを1つ
  reserveする。domain placement countにnonceは含めない。client-side future nonce
  queue/pipeliningは実装せず、exact next nonceを直列送信する。epoch/protocol-
  version rolloverでnamespaceを分離し、古いepochを受理しないtrusted
  `NodeConfig.epoch`とsigned epochをreplay boundaryとする。`u64::MAX`到達senderは
  epoch rolloverまで送信不能。indeterminate commitはfresh request IDに変えず
  original request IDでreconcileする。generic normalized state tableを再利用し、
  tombstone revisionを持つabsenceはexpected zeroへresetせずpersistence invariant
  でfail closedする。DB schema generationとTransaction wire/schema versionは
  不変。epoch pruningのproduction policyはdeferredであり、fee debitとbounded
  retentionがない間はnew senderによるstate growthがeconomic meteringされない
  ——これはfee/object-effect compositionを持たないこのgeneric structured
  durable route（nonce-onlyの`SubmitTransaction` path）に限定した記述である。
  additive owned-effects entrypointとpreinstalled-WASM entrypointは別途fee
  （S3のbounded uniform ordinary-asset fee composition、DR-0087）とmodule/
  object effectsをimplemented As-Isであり、本項の対象外である。このgeneric
  As-Is routeをlive transaction ingressとして公開してはならない。
  FastCertificateおよび他event
  familyのauthenticated/authorized ingressが残るためlive activationは引き続き
  禁止する（runtime/node-core/native implemented As-Is）。
- request pathのcommit直後deliveryはdomain-wide `claim_due_outbox`を流用しない。同じdomainのolder due workを
  今回requestと誤認しないよう、trusted `(domain, request_id, now, lease, expiry)`を持つexact-request claimを使う。
  memory conformanceはolder due rowが存在しても指定requestだけをclaimし、cross-request/domain lease reuseを拒否する
  native structured request pathは同一operation contextでcommit後にexact requestを最大1 message claimし、
  Indeterminate claim/ackを同一identityで1回reconcileし、未解決claimをsendしない
  （contract/memory/native/PostgreSQL implemented As-Is; provider durable adapters pending）。
- indexed production outbox boundaryはtrusted runtime timeとbounded restart-safe leaseを受け、
  `(available_at, request_id)`のstable index順で最大1件だけclaimする。scheduler cursorやprefix scanを
  authorityにせず、同じlease IDの再claimはindeterminate claimのreconciliationとして同じworkを返し、
  別workへのlease reuseはfail closedする。ackは同じrequest/index/leaseの再試行をidempotent successとするため、
  normalized storeはleaseごとのrequest/index bindingとacknowledged statusをowning batchのretentionまで保持する。
  last acknowledged identityだけでは後続message進行後のdelayed retryを処理できない。claim/ackはどちらもdefinite pre-commit rejectionと
  Indeterminateを分離し、未reconcileのclaimをtransportしてはならない
  （contract implemented As-Is）。nativeはtrusted deployment compositionからlogical domain、writer fence、
  lease未満のbounded storage timeout、restart-safe lease/correlation identityを受けるone-shot indexed recoveryを持つ。
  claim/ackのIndeterminateは同じidentityで各1回だけreconcileし、unresolved claimはsendせず、scan cursorを返さず、
  HTTPとblocking admissionを共有する。single-lock memory repositoryはinitial delivery、stable due order、lease expiry、
  same-lease reconciliation、retained attempt history、later progress後のdelayed ackを検証する
  （native/memory/PostgreSQL implemented As-Is）。
  PostgreSQL以外のdurable adapter、transport-aware deadline/cancellation、real scheduler bindingは未実装である。
- runtimeのnon-default `durable-conformance` test supportは同じblack-box caseをmemoryとPostgreSQLで実行し、
  deadline exact boundaryのread/commit/claim/ack definite rejection、complete-read write skew、concurrent
  absent-key create、tombstone ABA、definite contention outcome、retained outbox lease、writer-fence handoffを
  検証する。PostgreSQL live testはさらにpool acquisition/metadata lock待ちdeadline、retry ceiling到達時の
  serialization rejectionとunsupported schema generationのread/commit/claim/ack fail-closedを検証する
  （implemented As-Is）。optional shared commit-loss capabilityはbounded test-only `NoTls` TCP proxyと、
  PostgreSQL `SSLRequest`を必須化してephemeral private CA・`localhost` SANをrustlsで検証する別の
  bounded TLS-terminating proxyを介し、
  plain state commitへCOMMIT dispatch直前のconnection lossを1回注入してstate ground truthが存在しないことを
  証明し、別途structured invocation commit・outbox claim・acknowledgementの3箇所へbackend COMMIT acceptance
  直後のconnection lossを注入して、いずれもIndeterminate(ConnectionLost)として分類されつつ、invocation commitでは
  exact state/receipt ground truthとRequestAlreadyCommittedを証明する。same-lease claim replayや
  same-identity ack replay単独ではpersistedとuncommittedを区別できないため、claimでは別leaseでのclaim probe
  （元leaseがまだactiveであることをNoDueWorkで証明）、ackでは元leaseでのreclaim probe（LeaseIdReuseとして
  rejectされることを証明）を先に行った上でsame-identity reconciliationを証明し、最後にconnection pool
  recoveryを検証する。TLS版はIP-host negative connection rejectionとcompleted authenticated handshakeも
  証明してexact same shared casesを実行する（implemented As-Is；docs/architecture/decisions/0058-0075-postgres-conformance.md DR-0074）。ただしTLSは
  test proxyで終端してbackend PostgreSQL legはplaintextであり、client/driver-to-test-terminatorの証跡に
  限る。backendがCOMMITへ成功応答を返したことの証跡であり、abrupt process/power lossに対するcrash
  durability、PostgreSQL-server/provider TLS、mTLS、certificate rotation/revocationの証明ではない。
  別途、serializedなlive testがcommitted structured invocation（state、exact receipt、
  1 due outbox message）の直後にintervening SQLなしでdatabase-service containerへ
  `docker kill --signal=KILL`し、`docker start`と新規connectionでexact state/receipt、
  `RequestAlreadyCommitted` replay、その1 requestへのexact claim/ack 1回に続く`NoDueWork`、
  最終unfaulted commitを検証する
  （implemented As-Is; docs/architecture/decisions/0058-0075-postgres-conformance.md DR-0069）。これはlive host上のlive page cacheでの
  database-process SIGKILLとWAL recoveryの証明であり、abrupt host/power loss、storage
  write-cache flush/torn-write/media/filesystem fault、disk full/WAL exhaustion、connection
  exhaustion、TLS-path connection loss、backup/restore、capacity/load/soak、real writer
  failover、provider certificationは未実装である。
  別のrequired live testはdigest-pinned disposable PostgreSQLでPGDATA/WALを未充填の
  512 MiB tmpfs、database default tablespaceを別の64 MiB tmpfsへ置き、後者だけを満杯にする。
  direct SQLSTATE `53100`、pre-commit `UnavailableBeforeCommit`、state/receipt/commit sequence
  非公開、space解放後のsame pool/store recoveryとexact replay/claim/ackを検証する
  （bounded data-tablespace ENOSPCのみimplemented As-Is; docs/architecture/decisions/0058-0075-postgres-conformance.md DR-0070）。
  さらに別のrequired live testはdigest-pinned disposable PostgreSQLで`pg_wal`だけを`initdb --waldir`で
  別の64 MiB tmpfsへ切り離し、未充填の512 MiB tmpfs上のPGDATA/default tablespaceとは明確に区別した上で
  WAL側だけを満杯にする。direct incompressible writeはWAL segment境界を跨ぐと引き続きSQLSTATE `53100`を
  返すが、severityはDR-0070のplain `ERROR`ではなく`PANIC`であり、直後に同じconnectionがcloseする
  （PostgreSQLがwhole postmasterをterminateしてcrash-restartするため、その後のautomatic recoveryも
  WAL不足で同様に失敗しserverが二度落ちる）。同じmount上でin-place recoveryした後、WALを独立に再充填し、
  bounded incompressible state mutationを使ってadapter自身のstructured invocation commitにWALを枯渇させ、
  serverを再度crashさせる。観測されたpublic outcomeはdefinite pre-commit
  `Rejected(UnavailableBeforeCommit)`である。adapter APIはraw database errorを公開しないため、exact
  SQLSTATE/severityを主張するのはdirectな第一cycleだけである。connectionだけでなく
  server全体が落ちるため、containerのentrypointをsupervisor scriptで上書きしてcontainer自体はcrash後も
  生存させ、`docker start`/`docker kill`を使わずWAL解放後に`pg_ctl start`で同じtmpfs mount上へin-place
  restartする。二回のrestartそれぞれでstrictly advanceした`pg_postmaster_start_time()`によりgenuineな
  crash/recoveryを証明した上で、
  同じpool/storeでstate/receipt/commit sequence非公開とrecovery後のexact replay/claim/ackを検証する
  （bounded WAL-filesystem ENOSPCのみimplemented As-Is; docs/architecture/decisions/0058-0075-postgres-conformance.md DR-0071）。literal `COMMIT`時の
  WAL/data ENOSPCは未検証であり、この境界についてENOSPC固有の分類は主張しない。real-device ENOSPCと
  他のfault/capacity certificationも未実装のままである。
  さらに別のrequired live testはdigest-pinned disposable PostgreSQLをtiny exact `max_connections`、
  zero `superuser_reserved_connections`、zero PostgreSQL 16+ `reserved_connections`（
  `pg_use_reserved_connections` role向けの別のindependent reserved pool）で起動し、どのroleにも
  capacity carve-outを与えない。autovacuumも無効化するが、これはoptional quiescenceに過ぎない
  ——autovacuum worker/launcherは自身のseparate budgetから割り当てられ、`max_connections`から
  carve-outされることはない。すでにopenなoperator connectionがnamespaceをbootstrapしたまま
  scenario全体で開き続ける。databaseを作成したshort-livedなadmin clientをdropした直後、operator
  connection自身のconnectionだけがactiveであることをboundedにpollして確認する
  ——`Client`のdropはasynchronousなteardownを要求するだけなので、このpollがなければadmin client
  のbackendがblocker接続の厳密なcount開始時にtransientにcapacityへ残ってしまう可能性がある。この
  pollがsafeなのは、この時点ではまだ`r2d2` poolが存在せず、このtestが開始した以外の何もconnection
  countを自発的に変化させ得ないためであり、この同じscenarioの後半（下記）でtransient countをpoll
  することがsafeでないのとは対照的である。小さくexactly boundedな数のdirect blocker
  connectionでserverの全connection slotを飽和させ、direct probeのSQLSTATE `53300`（`FATAL`
  severity）とexact active client-backend countでgenuineなexhaustionを証明する。capacityがまだ
  exhaustedのまま、zero physical connectionを保持すると証明したmax-size-oneのadapter poolで1回
  bounded structured invocation commitを実行する。`r2d2`のconnection-acquisition waitはbareな
  refusalでは早期returnしないため、このcrateがfailureをclassifyする時点でcaller自身のoperation
  deadlineも構造的にちょうど経過しており、pool exhaustionとdeadline exhaustionは同一のdefinite
  pre-commit `Rejected(DeadlineExceededBeforeCommit)`へcollapseする（connectionとtransactionが
  既にopenな状態でfaultが発生するDR-0070/DR-0071とは異なり、`UnavailableBeforeCommit`にはならない）。
  adapter poolはsaturated中に新規connectionを開けないため、state/receipt/outbox行とcommit
  sequenceの非公開はstoreではなくstill-openなoperator connectionを通じて証明する。rejected
  attempt自身の内部connection試行は`commit_invocation`が返った後も止まらず、`r2d2`が独立して
  短いbackoffで再試行し続けるため、blocker connectionを厳密に1つだけ解放して空いたslotはこの
  testが呼び出すどの呼び出しとも無関係にその背後のretryが任意のタイミングで奪う可能性がある。
  解放直後の一時的なcountをpollしてこの独立したretryとraceさせるのではなく、次の
  `commit_invocation`呼び出しがcapacity獲得後に必ず成功することを要求し、成功後にstill-openな
  operator connectionを通じてsteady-stateのactive client-backend countが厳密に`max_connections`
  であり、そのうちちょうど1つがadapter pool自身の`application_name`を持つことを証明することで、
  adapter pool自身が解放されたslotを奪ったことを確定的に証明する。同じinvocationのrecovery、
  exact replay/claim/ack、pool usabilityも同じpool/storeで証明できる（bounded
  connection-exhaustion evidenceのみimplemented As-Is; docs/architecture/decisions/0058-0075-postgres-conformance.md DR-0072）。real-device
  resource exhaustion、load/soak capacity、production certificationは未実装のままである
  （provider-managed poolerの挙動はDR-0075のbounded rehearsalとして下記の通り一部implemented
  As-Isだが、production certification/load/failoverは引き続き未実装）。別のrequired live testは
  digest-pinnedなsourceとtargetの2つの独立したdisposable containerを起動し、sourceで1件の
  structured invocation（state、receipt、1 pending outbox message）をcommitした後、
  `pg_dump -d <db> --no-owner --no-privileges --inserts`でsnapshotを取得する。`--inserts`は
  `COPY ... FROM stdin`の埋め込みdata block（`psql`自身が実装するclient-side convention）を
  回避し、self-containedな`INSERT`文だけのSQLをadapter自身の`postgres::Client::batch_execute`で
  直接targetへ適用できるようにする。PostgreSQL 18の`pg_dump`が付与する`psql`専用の
  `\restrict`/`\unrestrict`行（SQLではなくwireへ送ればsyntax errorになる）は事前に除去する。
  copied namespaceのfenceを進める前にexact schema identityと、restored namespace metadata・
  state・receiptをadapterのread path経由でexact ground truthとして検証し、operator-only
  `advance_writer_fence`でrestored namespaceのwriter fenceを進め、stale pre-backup context
  （旧fence）が`Rejected(WriterFenced)`でfail closedし公開なしであることを証明し、新fenceの
  fresh contextがexact restored receipt/stateをreconcileし、identical invocationで
  `RequestAlreadyCommitted`を観測してからrestored pending outbox
  payloadをclaim/ackし、新規workをcommitできることを証明する。negative pairではrequiredな
  `storage_metadata`の`CREATE TABLE`途中でcutしたdumpがsingle simple-query batchとしてatomicに
  failしschema markerを残さないことと、fixtureの`state_records` insertだけを除いたvalid dumpが
  schema・namespace metadata・receiptをrestoreしながらmissing stateによってdeeper rehearsal
  verification gateを通過しないことを証明する（bounded database-snapshot restore rehearsal evidenceのみ
  implemented As-Is; docs/architecture/decisions/0058-0075-postgres-conformance.md DR-0073）。これは1回の`pg_dump`/SQL-execute snapshot
  cycleのrehearsalに過ぎずproduction backup/restore機能ではない。point-in-time recovery、
  continuous WAL archiving、concurrent write負荷下でのhot backup、
  `pg_basebackup`/replicationベースのbackup、backup encryption/off-host storage、
  checkpoint publication（`sunrise_edge.checkpoints`は未使用）、blob-manifest/state-root/
  encryption-key verification、production certificationは未実装のままである。
  さらに別のrequired live testはdigest-pinned PostgreSQL 18.6とdigest-pinned
  `ghcr.io/icoretech/pgbouncer-docker` 1.25.2を1つのisolatedかつ生成済みDocker bridge
  networkへ起動し、PgBouncerはnetwork alias経由でのみPostgreSQLを解決する（host-published
  addressは使わない）。このtest自身のdirect verification connectionはproxyを経由せず
  PostgreSQL自身の別のpublished portへ直接張るため、proxyの単一backendが意図的にblockされて
  いる間も使い続けられる。`pgbouncer.ini`/`userlist.txt`はcontainerへ`docker exec ... dd
  of=<path> status=none`のstdin経由で書き込み、shellもhost bind mountも使わない。`tee`とは
  異なりBusyBox `dd`は`status=none`指定時にtarget file以外へ何も出力しないため、書き込んだ
  credential/configがcaptured outputへechoされることもない。credentialはgenerated passwordであり、
  `password_encryption=md5`を設定したPostgreSQL自身の`pg_authid.rolpassword`を読み戻して
  userlistのMD5 credential hashとしてそのまま使う（testが自前で計算しない）。設定は
  `pool_mode = transaction`、対象database/user poolに対して`pool_size`/`default_pool_size`/
  `max_db_connections`/`max_user_connections = 1`、nonzeroな`max_prepared_statements`、
  boundedな`query_wait_timeout`であり、いずれもPgBouncer自身のadmin console
  （`SHOW CONFIG`/`SHOW POOLS`/`SHOW DATABASES`/`SHOW SERVERS`/`SHOW CLIENTS`、
  simple query protocol経由）で直接証明し、client側の挙動から推測しない。`SHOW CONFIG`の
  `default_pool_size`/`max_db_connections`/`max_user_connections`と、対象databaseの
  `SHOW DATABASES`自身の`pool_size`もそれぞれ独立に読み戻してexactly oneであることを証明する
  （rendered `pool_size`だけから推測しない）。同時にopenな2つのdistinct client connectionが
  それぞれ1回のtransactionを順に実行し、`SHOW SERVERS`の`remote_pid`が両方で同一であることから
  transaction poolingが実際に同一のPostgreSQL backendを再利用したことを証明する。実際のadapter
  （genuineな`r2d2` poolと`PostgresDurableStore`、専用の`application_name`で識別）をproxy経由に
  向け、別のdirect proxied clientがCOMMIT/ROLLBACKを送らずtransactionを開いたままpoolの唯一の
  backendを保持している間（`SHOW SERVERS`の唯一の行がPgBouncer自身の`active` stateであることを
  証明し、単に存在するだけでないことを示す）に、PgBouncer自身の`query_wait_timeout`より十分長いcontext deadlineで
  1回のadapter structured invocationを実行する。live evidenceとして、PgBouncerのqueue
  timeoutはPostgreSQL protocol SQLSTATE `08P01`（`query_wait_timeout`）としてadapterの最初の
  文（transaction開始の`BEGIN`）に現れ、このcrateの`PreCommitFailure::from_sqlstate`には専用の
  分類がないためdefaultの`Unavailable`扱いとなり、definite pre-commit
  `Rejected(UnavailableBeforeCommit)`として観測される（`Indeterminate`ではない）。観測された
  経過時間はPgBouncer自身の`query_wait_timeout`を基準に上下からboundし、このtestの持つより大きな
  context budgetではなくproxy自身のqueue timeoutに起因することを証明する。state/receipt/outbox行の
  非公開はproxyを経由しないdirect operator connectionを通じて証明する。blocking transactionを
  解放した後、同じadapter pool/storeで同一invocationを再試行する。この再試行はexplicitに
  文書化されたひとつの既知のtransientのみを許容する ——
  `r2d2`はblocked probeのconnectionをevictする代わりrecycleすることがあり得る（local
  `is_closed()`がPgBouncerのasynchronousなsocket closeにまだ追随していない場合）ため、次の
  checkoutがすでに死んでいるそのconnectionを受け取りsub-millisecondでlocalかつunclassifiedな
  I/O errorとして失敗することがある（timingの点でgenuineなproxy rejectionとは明確に区別できる）。
  このretryはその狭い形状だけを許容し、loopの最終結果は必ず`Committed`でなければならない
  （accumulatorは`Committed`ではなくrejectionで初期化されており、将来retry回数を0へ縮める編集が
  あってもvacuousにpassせず確実にfailする）。
  recoveryは`Committed`を証明し、同じ`remote_pid`証跡を再度呼び出して、recovered commitが
  2つのsynthetic clientで観測したのと同一のsole backendによって処理されたことを証明した上で、
  `SHOW CLIENTS`をadapter poolの`application_name`で絞り込むことで
  adapter pool自身のproxy connectionが解放されたbackendを奪ったことを証明し、同一invocationの
  replayはexact `RequestAlreadyCommitted`を返し、exact outbox messageはclaim/ackを経て
  `NoDueWork`となり、poolはさらなるreadにも使い続けられる（bounded local PgBouncer
  transaction-pooling rehearsal evidenceのみimplemented As-Is; docs/architecture/decisions/0058-0075-postgres-conformance.md DR-0075）。これは
  provider-managed pooler service certification、load/soak capacity、PgBouncerのhigh
  availability/connection draining、client/backendいずれのlegのTLS、real writer failover、
  production readinessの証明ではない。
- ComposedRuntimeはStateStore、BlobStore、Signer、Transport、Clock、Schedulerをhidden defaultなしで
  明示的に所有・合成する。SQLiteへstate/dedup/outboxをcommit後にruntimeをdropし、同じDBを別compositionで
  reopenしてstateを再適用せずoutboxを送ること、send failure leaseがreopen後もexpiry前は抑止されexpiry時だけ
  attempts=2で再送されることを検証する（implemented As-Is）。これはorderly close/reopen conformanceであり、
  kill -9、torn write、filesystem failure、power lossの証明ではない。
- node-coreのtransactional pathはcontext検証後かつstate read前にevent-specific access planを
  確定し、全keyをrevision付きsnapshotとしてpure transitionへ渡す。undeclared/read-only updateを
  rejectし、更新しないread-write/read-only/absent/tombstoneを含む全観測revisionを
  `StateMutation::Assert`としてwrite-setへbindし、全commit成功までoutputを返さない
  （complete read-set assertion implemented As-Is）。
  native HTTP adapterはこのrecoverable transactional pathをdefaultにした。edge adapterの
  downstream service実装とdurable provider storeは別途必要である。
- recoverable transactional pathはcomplete canonical NodeEventをdedicated hash domain 0x000Dと
  active epoch hash suiteでdigest化する。application update、request_id/event digest/responseを持つ
  dedup record、ordered outbound messageを持つrequest-scoped outbox batchを同一commitへ含める。
  同一request/digestのretryはtransitionを再実行せずresponseだけを返し、別eventへのrequest ID
  reuseはfail closedする。native HTTPはrequest-scoped transport sendまで統合したが、providerが
  unattended outboxを発見するscheduling、retention/compaction、durable crash recoveryは未実装であり、
  request retryで回復できるだけでproduction delivery完成とはみなさない。
- outbox delivery cursorは1 messageずつnon-zero lease IDと5分以下のdeadlineでclaimし、batch
  revisionを同一transactionでassertする。matching lease/indexのackだけがcursorを進め、期限切れ
  claimは同じindexを再配信する。これはsend後ack前crashでmessageを失わないat-least-onceであり、
  exactly-onceではない。native HTTPは30秒leaseとinjected restart-safe lease ID sourceでtransportを
  driveする。nativeはStateKeyScanner pageからcompleted/tombstone/active leaseをskipし、最大1 outboxを
  同じlease/send/ack経路で処理してexclusive continuationを返すrecover_outboxes_onceを提供する。
  HTTPと同じNativeBlockingExecutorを共有し、resident loopやscheduler trustを作らない
  （implemented As-Is）。real provider trigger、trusted time policy、poison message、
  retention/compaction、durable fault testはTo-Beに残る。
- native adapterはPOST /v1/events、exact canonical binary media type、bounded body、
  deterministic HTTP status mapping、GET /health/live、graceful shutdownを提供する。
- native outbound eventはatomic commit済みoutboxからlease後にruntime transportへ渡し、send成功後
  にmatching lease/indexをackする。send failureは503とactive leaseを残し、期限切れ後のretryで
  at-least-once redeliveryする。requestなしのone-shot recovery seamは実装したが、provider scheduler
  trigger、durable SQLite runtime composition、process/power-fault conformanceは未実装である。
- TLS、authentication、rate limiting、durable StateStoreのbounded wiring、audit telemetry、reverse
  proxy hardeningは未実装であり、このAs-Is adapterをinternet-facing production serverと扱わない。
- 現在のRuntime traitは同期APIであるため、native adapterはcanonical decode、node-core、durable
  state、outbox send/ack、result encodeを1つのspawn_blocking jobへ隔離し、embedding processが
  non-zero concurrency limitを必ず指定する。permit枯渇時はadapter内でqueueせず429を返し、根拠の
  ないRetry-After値は生成しない。livenessはblocking poolから独立する（implemented As-Is）。
  開始済みspawn_blockingはTokioで
  cancelできないため、HTTP timeoutだけ先に返してcommitを裏で継続する実装は採用しない。
  structured durable pathはexplicit trusted cancellation signalをasync handler、blocking job開始、最初のstorage
  dispatch直前でのみ検査し、cancel済みなら503かつstate/receipt/outbox/send/ackなしで終了する。storage dispatch
  開始後はsignalを再検査せずcommit/send/ack reconciliationを完遂する（implemented As-Is）。client disconnect、
  started I/O cancellation、shutdown budget、load capacity、circuit breakerはTo-Beに残る。

Phase 15 To-Be production exit criteria:

1. 全NodeEvent kindについてcanonical payload schema、type/version ID、最大サイズ、
   authentication/authorization順序、state read/write set、response、outbound message、
   stable/negative vectorsをprotocol specificationとして固定する。
2. transaction、vote、certificate、consensus、governance、upgrade、validator-set、Tickの
   concrete dispatchを実装し、unknown kind/type/version/fieldと未対応機能をfail closedにする。
3. single-key state replacementを明示的atomicity domainと全read-set（read-only、absent、tombstoneを含む）
   revision assertionを持つversioned transactionへ置換する。複数object、index、consensus metadata、
   dedup record、outbox初期状態を同一commitで更新し、cross-domain writeはprotocol-level coordinationなしに
   部分成功させないproduction contractと、normalized PostgreSQL durable実装を完成させる。
4. request_idとevent digestをpersisted dedup recordへ統合し、duplicate、replay、reorder、
   timeout後retry、concurrent delivery、process crash後retryで同一effectsを二重適用しない。
5. state commitとoutbound publicationのcrash windowをtransactional outboxまたは同等の
   recovery protocolで閉じる。prefix full scanではなくbounded indexed due-work claimを実装し、
   commit済み未送信、送信済み未ack、duplicate sendを回復でき、relayをtrust rootにしない。
6. HTTP contractにmethod/path、content type、body/header limits、timeout、cancellation、
   status/error mapping、request correlation、backpressure、streaming禁止/許可範囲、
   secret-bearing response policyを明文化する。
7. CAS conflict、storage outage、signing failure、outbox failure、overloadに対するbounded retry、
   jitter、deadline、admission control、circuit breakingをadapter policyとして実装し、
   protocol transitionをretry policyから独立させる。
8. native HTTP adapterをTLS termination、authentication、rate limiting、request smuggling対策、
   decompression bomb対策、graceful shutdown、health/readiness、structured audit log、metrics、
   traces、secret/key isolationを含むproduction deploymentとして検証する。
9. supported native/edge runtime間でevent decode、context rejection、state transition、CAS conflict、
   error mapping、outbox recoveryのconformance suiteを通し、fuzz/property/adversarial/load/soak testと
   worst-case capacity budgetを固定する。
10. version upgrade、epoch rollover、schema compatibility、database migration、backup/restore、
    disaster recovery、key rotation、rollback非依存のsafe disable、operator runbook、SLO/alertを
    rehearsalし、independent security reviewを完了する。

Post-MVP Production Hardening: Phase 15 persistence implementation order（To-Beからの逆算）:

以下はCLI Developer MVP Gate通過まで凍結していた。ただし、MVPのatomic correctness、
restart safety、fail-closed behaviorを直接満たすために必要な既存contract修正は先行して
よいものとしていた。CLI Developer MVP Gateは現在通過済みであり、以下の項目は
["CLI-First Node Production Gate"](#cli-first-node-production-gate)のS5が参照する
production persistence作業そのものである。S3は実装・検証済み（DR-0087）、S4aは
hardware-signing profile/host preflightとして実装・検証済み（DR-0088）である。
DR-0089はS4b device contractをdocument上でclarifyし、DR-0088のAPDU 230-byte capを
FIRST最大255-byte・first chunk最大230-byteへ訂正しただけでdevice app・Speculos
evidenceを追加していない。DR-0090はmerge済みseparate `sunrise-edge-ledger-app`
repositoryのPR #1 host-core milestoneを記録する。DR-0091はmerge済みPR #2
（`6f6f882`）のdedicated Ledger SDK device app、five-target build、fixed-seed Nano S+
Speculos/Ragger evidenceをAs-Isとして記録する。S4bはAs-Isでcomplete、DR-0092により
S4c Phase 1 host APDU/USB/HID transportとCLI signer selection（profile/address check、
USB descriptor levelのdevice check）はAs-Isで実装・検証済みである。DR-0093により
S4c Phase 2aのactive-app/firmware identity check（strict Ledger OS
identity/dashboard parsing、dashboard `BOLOS` check、bootloader/OSU
rejection、exact caller-supplied expected firmware version、`open app`に
よるexactly `Sunrise Edge`のopen、bounded same-explicit-path reconnect、
exactly `Sunrise Edge`/`0.1.0`のactive-app check、既存6-byte configuration
への`0.1.0` pin追加）も`FakeTransport`のみに対するsoftware-only実装として
As-Isで実装・検証済みである。S4cは
physical hardware validationが
未実装のためincompleteであり、S4全体もincompleteである。2026-09-04の明示的な
roadmap reorderにより、S4c Phase 2b、S4d physical-device HIL/release evidence、
その他すべての残存Ledger作業はdeferredとし、旧順序を飛び越えてnon-Ledger S5
prerequisiteを進める。TypeScript client/explorer/walletはSoftware Production Gate
（S0-S3 + S5）までdeferredのままであり、S4の完了は待たない。S4、S5、completeな
CLI-First Node Production Gate、production、mainnet readinessはincompleteである。
capacity/PITR/HA等のS5 certification項目はS5または明示的なSLOがtriggerするまで
引き続き凍結する。

1. SQLite既存dataを暗黙migrationせず、writer fence、deadline、typed conflict/indeterminate failureを持つ
   durable domain adapter boundaryを定義する（implemented As-Is; composition/provider implementation pending）。
2. indexed due-outbox repository/claim contractを追加し、domain-aware unattended recoveryを接続して
   StateKeyScannerはmaintenance/compatibilityへ戻す（contract/native/PostgreSQL implemented As-Is;
   provider durable adapters pending）。
3. `docs/operations/postgres.md`のexact namespace、unsigned SQL representation、normalized relation、attempt history、
   transaction order、migration policyを維持する。adapterがopaque PersistenceLayout key prefixをparseせずに済むよう、
   state/object/receipt/outboxを明示的sectionとして持つstructured durable transaction envelopeを先に実装する
   （runtime/node-core/memory/native compositionとgeneration-one normalized schema migration/operator bootstrapは
   implemented As-Is; bounded pool、fenced state/body-free object head/immutable object version/receipt read、
   serializable structured state/object/receipt/outbox commit、canonical object lock order、tombstone history reconstruction、
   inline/blob lossless mapping、
   statementごとの残deadline timeout、bounded unchanged-envelope serialization retry、typed conflict/indeterminate分類も
   PostgreSQLでimplemented As-Is; indexed exact-request/due claim、same-lease reconciliation、retained attempt history、
   idempotent ack、pool/row-lock deadline exhaustionとcommit-boundary deadline classificationもPostgreSQLで
   implemented As-Is; in-flight cancellation/fault/capacity certification pending）。
   explicit migrationとshared contract evidenceはimplemented As-Is; broader fault/capacity evidenceは未実装である。
4. shared conformanceにexact deadline boundary、write skew、absent-key race、bound-domain/fence/deadline rejection、
   object read-count bound、blob-reference round-trip、object create/update/delete/recreate ABA、
   object conflict時のstate/receipt/outbox/version rollback、definite contention classification、lease fencingを追加し、
   PostgreSQL capability testにimmutable history/current/tombstone/blob mapping、head metadata corruption fail-closed、
   separate version readでのmalformed inline body fail-closed、
   pool/row-lock deadline、serialization failure、
   schema/version skewを追加する。optional shared commit-loss capabilityはbounded test-only `NoTls` TCP proxyと
   strict CA/hostname verification付きのbounded TLS-terminating proxyを介し、
   plain state commitへのCOMMIT dispatch直前connection lossとinvocation commit・outbox claim・acknowledgementへの
   backend COMMIT acceptance直後connection lossを別々に注入し、いずれもIndeterminate(ConnectionLost)として
   分類されることと、前者はstate ground truth不在、後者はexact state/receipt ground truth・RequestAlreadyCommitted
   （invocation commit）を証明する。claim/ackはsame-lease/same-identity replay単独では非committedと区別できない
   ため、別lease claim probe（NoDueWork）とoriginal lease reclaim probe（LeaseIdReuse）で先にpersistedを証明した上で
   same-identity reconciliationを証明し、pool recoveryを証明する
   TLS版ではIP-host negative rejectionとauthenticated handshake countも証明する
   （memory/PostgreSQL/commit-loss capability implemented As-Is；docs/architecture/decisions/0058-0075-postgres-conformance.md DR-0074；backendの
   成功応答とclient/driver-to-test-terminator TLS lossの証跡でありabrupt process/power lossに対する
   crash durability、PostgreSQL-server/provider TLS・mTLS・certificate lifecycleの証明ではない;
   provider adapters、other fault/capacity certification pending）。別途、serializedなlive testがcommitted structured
   invocationの直後にdatabase-service containerを`docker kill --signal=KILL`し、restart/readiness/
   fresh connection reconciliationを検証する（implemented As-Is; docs/architecture/decisions/0058-0075-postgres-conformance.md DR-0069）。これは
   database-process SIGKILLとWAL recoveryの証明のみであり、abrupt host/power loss、storage write-cache
   flush/torn-write/media/filesystem fault、PostgreSQL-server/provider TLS、capacity/load/soak、real writer
   failover、backup/restore、provider certificationは未実装である。
5. real host/power fault（storage write-cache flush、torn-write、media/filesystem fault含む）、
   commit-boundary/real storage-device ENOSPC、
   capacity/load/soak、backup/restore、writer failoverをrehearsalする。database-process
   SIGKILL/WAL recovery、bounded pre-commit data-tablespace ENOSPC（DR-0070）、bounded pre-commit
   WAL-filesystem ENOSPC（DR-0071）、bounded server connection-slot exhaustion（DR-0072）、bounded
   `pg_dump`ベースのdatabase-snapshot restore rehearsal（DR-0073）、bounded
   client/driver-to-test-terminator TLS commit-loss evidence（DR-0074）、bounded local PgBouncer
   transaction-pooling rehearsal（DR-0075）以外は
   このstep 5の全項目が未実装のまま残っている。connection exhaustionはDR-0072でserverが飽和した
   際にadapter poolがdefinite pre-commit `Rejected(DeadlineExceededBeforeCommit)`を返すことを
   bounded disposable containerで証明したが、real-device resource exhaustion、load/soak capacity、
   production certificationは未実装のままである。DR-0075は digest-pinned PostgreSQL 18.6と
   digest-pinned `ghcr.io/icoretech/pgbouncer-docker` 1.25.2をisolatedなDocker networkへ起動し、
   PgBouncer admin console evidence（`SHOW CONFIG`/`SHOW POOLS`/`SHOW DATABASES`/`SHOW SERVERS`/
   `SHOW CLIENTS`）でconfigured transaction modeと、default_pool_size/max_db_connections/
   max_user_connections/tested databaseのSHOW DATABASES pool_sizeが厳密に1であることと、
   2つのsimultaneously openなclient connectionが同一backendを
   sequential transactionで再利用することを直接証明し、real adapterをproxy経由に向けた上で、
   direct proxied clientがproxyの唯一のbackendを`active` stateのtransaction中に保持している間、adapter
   invocationがPgBouncer自身の`query_wait_timeout`満了によりdefinite pre-commit
   `Rejected(UnavailableBeforeCommit)`となることと非公開を証明し、release後は同一invocationの
   commit（recovered commitが同一sole backend PIDで処理されたことを再度証明）、
   `RequestAlreadyCommitted` replay、exact outbox claim/ack、pool usabilityを証明した
   （bounded local PgBouncer transaction-pooling rehearsal evidenceのみimplemented As-Is;
   docs/architecture/decisions/0058-0075-postgres-conformance.md DR-0075）。これはprovider-managed pooler service certification、load/soak
   capacity、PgBouncerのhigh availability、TLS、real writer failover、production readinessの
   証明ではない。DR-0073は
   digest-pinnedなsourceとtargetの2つの独立したdisposable containerで`pg_dump --inserts`
   snapshotを取得し、PostgreSQL 18の`pg_dump`が付与する`psql`専用の`\restrict`/`\unrestrict`行
   （SQLではない）を除去した上でadapter自身のdriver connection経由で別isolated targetへ
   直接restoreし、fence promotion前にexact schema identityとrestored namespace metadata・
   state・receiptをadapterのread pathで検証し、operator-only
   `advance_writer_fence`でrestored namespaceのwriter fenceを進め、stale pre-backup context
   （旧fence）が`Rejected(WriterFenced)`でfail closedし、新fenceのfresh contextがexact
   restored state/receiptをreconcileし、identical invocationで`RequestAlreadyCommitted`を
   観測してからexact pending outbox payloadのclaim/ackを完了して
   新規workをcommitできることを証明した
   （bounded database-snapshot restore rehearsal evidenceのみimplemented As-Is;
   docs/architecture/decisions/0058-0075-postgres-conformance.md
   DR-0073）。このtarget側だけのfence advanceは独立して動き続けるsource databaseを停止・
   fenceしないためsingle-writer failoverの証拠ではない。negative pairではrequiredな
   `storage_metadata`の`CREATE TABLE`途中でcutしたdumpがsingle simple-query batchとしてatomicに
   failしschema markerを残さないことと、fixtureの`state_records` insertだけを除いたvalid dumpが
   schema・namespace metadata・receiptをrestoreしながらmissing stateによってdeeper rehearsal
   verification gateを通過しないことを証明する。これは1回の`pg_dump`/SQL-execute
   snapshot cycleに対するrehearsal evidenceに過ぎず、production backup/restore機能ではない。
   point-in-time recovery、continuous WAL archiving、concurrent write負荷下でのhot backup、
   `pg_basebackup`/replicationベースのbackup、backup encryption/off-host storage、
   retention/rotation policy、restore automation、checkpoint publication（schemaには
   checkpoint publicationの実装がなく、`sunrise_edge.checkpoints`はこのcrateのどこからも
   書き込み・読み取りされていない）、blob-manifest/state-root/encryption-key verification、
   multi-database/whole-cluster backup、concurrent adapter write traffic下でのbackup、
   real storage-device/off-host transfer fault、production certificationは未実装のままであり、
   backup/restore評価基準を閉じるものではない。
6. 同じcontractをCloudflare Durable ObjectとAWS persistenceへ実装し、real providerでcertifyする。

Phase 16:
- Cloudflare Workers ingress adapter (implemented As-Is)

Phase 16 As-Is scope:

- ES module WorkerがPOST /v1/eventsとGET /health/liveをPhase 15 contractと同じpath、
  exact media type、identity-only content encoding、no-store semanticsで提供する。
- request bodyはReadableStreamから固定上限までだけ読み、unbounded arrayBuffer/text/JSON
  bufferingを行わない。
- node-core serviceはpublic URLではなくgenerated Env.NODE_CORE Service Bindingでawaitして呼ぶ。
- module-level mutable request state、floating Promise、Cloudflare REST API、hardcoded secret、
  passThroughOnExceptionを使用しない。
- downstream response headerをallow-listで再構築し、binding内部500をsanitized 502へ変換する。
- wrangler.jsoncはtested workerdがsupportする最新compatibility date、nodejs_compat、
  observabilityを固定し、binding typeはwrangler typesで生成する。
- workerd integration testはmock Service Bindingでsuccess、liveness、method/media/encoding、
  declared/streamed oversize、downstream failureを検証する。
- toolchain compatibility debtとして、project typecheckは`typescript-7` aliasのTypeScript 7.0.2を
  使用し、`typescript-eslint` 8.xのpeer rangeを満たすTypeScript 6.xはESLint parser専用に隔離している。
  `typescript-eslint`がTypeScript 7を正式supportした時点で、通常の`typescript` dependencyを
  TypeScript 7へ統一し、`typescript-7` aliasと一時的なTypeScript 6.xを削除する。その変更は
  forced peer resolutionを使わず、ESLintのtype-aware rulesとrepository全gateの通過を必須とする。
- 現実装はbounded ingress/relayだけであり、Cloudflare上でnode-core transitionやdurable stateを
  実行するproduction validatorの完成形ではない。

Phase 16 To-Be production exit criteria:

1. NODE_CORE serviceのdeployment architectureを固定し、Worker/WASM、Durable Object、
   Workflows/Queues、外部durable storeの責務とtrust boundaryをprotocol/runtime仕様へ接続する。
2. atomic multi-key state、persisted deduplication、transactional outbox、crash recoveryを
   Cloudflare binding/storage semantics上で実装し、duplicate/replay/concurrent invocationで検証する。
3. Cloudflare Access contextがService Binding先へ自動伝播しない前提で、public ingress認証、
   protocol署名検証、service capability、operator/admin routeを分離しfail closedにする。
4. WAF、API Shield、rate limiting、bot/DDoS policy、request/header limits、custom domain/TLS、
   Cache RulesをIaC化し、dashboard driftとsecretのsource管理混入を防ぐ。
5. CPU/memory/subrequest/invocation limits内のworst-case event benchmark、load/soak test、
   backpressure、bounded concurrency、deadline、cancellation、overload behaviorを固定する。
6. structured logs、traces、metrics、request correlation、sampling、PII/secret redaction、SLO、
   alert、cost guardrailをproduction observabilityとして実装する。
7. compatibility_date、Wrangler、workerd、generated types、service versionをrelease artifactへ固定し、
   staged rollout、version skew、rollback非依存safe disable、binding target切替をrehearsalする。
8. native adapterとのcanonical/status/error conformance、real binding integration、fault injection、
   fuzz/adversarial/security test、independent review、operator/disaster-recovery runbookを完了する。

Phase 17:
- Vercel / Supabase / AWS / Deno adapters

Phase 17 prerequisites:

- provider-neutral Web Fetch API ingress core (implemented As-Is)
- Cloudflare conformance consumer over the shared implementation (implemented)
- provider-specific lower request capacity policy (implemented As-Is)
- shared authenticated HTTPS node-core capability (implemented As-Is)
- Deno adapter wrapper (implemented As-Is)
- Vercel adapter wrapper (implemented As-Is)
- Supabase Edge adapter wrapper (implemented As-Is)
- AWS adapter wrapper and API Gateway HTTP API v2 mapping (implemented As-Is)
- cross-provider local ingress fixture matrix (implemented As-Is)
- repository-wide pinned local/CI validation gate (implemented As-Is)
- reviewed weekly dependency/action update proposals (implemented As-Is)

Phase 17 shared ingress As-Is scope:

- provider wrapperはNodeCoreFetcher capabilityだけを注入し、path、media type、body limit、
  stream read、status mapping、downstream validation、header sanitizationをshared moduleから使う。
- shared moduleはenvironment lookup、provider SDK、credential、retry loop、durable state、
  mutable global request stateを持たない。
- provider wrapperは認証/private transportを追加できるが、shared boundやfail-closed mappingを
  緩めたりprovider独自wire contractへforkしてはならない。
- provider platform limitがshared request boundより小さい場合だけ明示的なlower boundを設定できる。
  zero、非整数、shared上限超過はconfiguration errorとして拒否し、security boundの引上げを許さない。
- private service bindingを持たないWeb provider向けの暫定transportはexact HTTPS endpoint、
  allow-listed header、bounded ASCII Bearer secret、redirect拒否、1..30000ms timeoutを一実装にする。
  environment lookupとprovider credential lifecycleはこのmoduleへ入れない。
- 現在のAs-Is consumerはCloudflare workerd、local Deno runtime、local Vercel/Supabase wrapper、
  AWS HTTP API v2 mapper testであり、real provider deployment conformanceはまだ完了していない。
- liveness、unknown path、method、media parameter、content encoding、content-lengthの同一fixtureを
  5 provider consumerで実行する。これはlocal drift検出であり実gateway/runtime conformanceではない。
- Rust 1.97.1、Node 22.20.0、Deno 2.9.4を固定したcheck script/CIがRust全featureと全adapterを
  一括実行する。CI actionもverified upstream tagのcommit SHAへ固定するが、provenance、SBOM、
  reproducibility、real provider testは未完了である。
- DependabotはCargo、Cloudflare npm、GitHub Actionsを週次確認し上限付きPRを作るがauto-mergeしない。
  changelog/互換性/repository gateを人がreviewする運用の強制、provenance検証、緊急更新SLAは未完了である。

Phase 17 Deno As-Is scope:

- current Deno 2 / Deno Deploy向けdefault fetch exportがshared ingress handlerをそのまま使用する。
- node-core endpointはexact HTTPS /v1/eventsに限定し、userinfo、query、fragment、redirectを拒否する。
- Deno Deploy secretからbounded Bearer capabilityを注入し、source、response、structured errorへ
  secretを出さない。downstream timeoutは1..30000msの固定上限でfail closedにする。
- provider wrapperはcanonical bodyをdecodeせず、path、media type、body bound、status、response headerを
  forkしない。testはpermission-free mock fetchでshared rejectionとauthenticated forwardingを検証する。
- 現実装はpublic HTTPS endpointへのBearer-authenticated relayであり、private connectivity、mTLSまたは
  signed service request、rotation/revocation、durable deduplication/outbox、real Deno Deploy rehearsalを
  production完成とみなさずTo-Beに残す。

Phase 17 Vercel As-Is scope:

- current Vercel Node.js FunctionのWeb fetch exportを使用し、canonical 2 pathを単一handlerへrewriteする。
- documented 4.5 MB Function payload ceilingより小さい4 MiB request budgetをshared lower-bound policyへ
  渡し、declared/streamed oversizeをnode-core forwarding前に413とする。
- Sensitive Environment VariableのBearer capability、exact HTTPS endpoint、redirect拒否、bounded timeoutは
  shared authenticated transportを再利用し、provider固有のcanonical decodeやstatus mappingを作らない。
- 現実装はpermission-free local wrapper testまでで、Vercel preview/production deployment、rewrite後の
  original path保持、platform 413/504、response 4.5 MB ceiling、Fluid Compute lifecycleは未検証である。
- 4 MiBはprotocol transport上限より小さいためfull conformanceではない。全valid eventを受理できる
  ingress architecture、private/mutual authentication、rotation、durable outbox等をTo-Beに残す。

Phase 17 Supabase As-Is scope:

- `sunrise-edge` Edge Functionのdefault fetch exportを使用し、gatewayがfunctionへ見せる
  `/sunrise-edge/*` prefixをcanonical 2 pathにだけexact matchで除去してshared handlerへ渡す。
- `supabase/config.toml`で`verify_jwt = true`を明示し、eventとlivenessの両方を現在はgateway JWT必須にする。
  public healthとauthenticated submissionの分離は認証を暗黙disableせずproduction設計へ残す。
- outboundはshared exact HTTPS/Bearer/redirect/timeout capabilityを再利用し、secret名はreserved
  `SUPABASE_` prefixを使わない。canonical bodyのprovider decodeや独自status mappingを追加しない。
- hosted limitsに256 MB memory、2秒CPU/request、150秒idle timeoutはあるが、同じ公式limit pageに
  payload ceilingはないため根拠のないprovider boundを設定せずshared boundを維持する。
- 現実装はpermission-free local wrapper testまでで、Supabase CLI/local gateway/hosted deploy、JWT
  claims policy、gateway 401/413/504、isolate reuse、real capacityは未検証としてTo-Beに残す。

Phase 17 AWS As-Is scope:

- API Gateway HTTP API payload format 2.0 eventだけをtyped validationし、method、rawPath、lowercase
  headers、base64 bodyをWeb Requestへ変換してshared handlerへ渡す。1.0やmalformed eventは拒否する。
- canonical event POSTはstrict canonical base64を必須にし、encoded lengthをdecode前に検査する。
  shared contractが使うcontent-type/content-encoding/content-length以外のheaderを再構築しない。
- API Gateway 10 MBに対しsynchronous Lambda request/buffered responseはJSON envelope込み6 MBのため、
  request/responseとも保守的4 MiB budgetとし、全protocol-valid envelope対応とは主張しない。
- Lambda proxy resultはcanonical binaryを壊さないよう常にbase64 responseとし、responseもbounded read、
  header allow-list、oversize 502でfail closedにする。
- control-plane SDKやunauthenticated IaCを含めない。payloadFormatVersion 2.0、JWT scope/IAM/custom
  authorizer、VPC/private transport、Secrets Manager/KMS、reserved concurrency/throttle/WAF、real deploy、
  platform retry/durability/observabilityはTo-Beに残す。

Phase 17 To-Be production exit criteria:

1. Deno、Vercel、Supabase、AWSそれぞれでpublic ingress、private node-core transport、
   authentication、secret/key、durable state、outboxのdeployment architectureを固定する。
2. shared ingress contractの同一fixtureを全provider実runtime/emulatorで実行し、path/media type、
   bounds、stream cancellation、status/error、header sanitization、canonical bytesを一致させる。
3. 各providerのbody/header/CPU/memory/duration/concurrency/subrequest limitを取得・固定し、
   shared protocol limitより小さい場合の明示的413/429/503 behaviorとcapacity budgetを定める。
4. freeze/thaw、isolate reuse、cold start、concurrent invocation、client cancellation、timeout、
   platform retryでprocess memoryをprotocol stateにせず、duplicate effectsを発生させない。
5. public URLへの無認証node-core forwardingを禁止し、service/private network/mTLS/signed request等の
   provider別capabilityを実装する。secretをsource/config/logへ残さずrotationをrehearsalする。
6. provider固有log/trace/metricを共通correlationとSLOへ接続し、redaction、sampling、alert、
   cost/abuse guardrail、cross-provider incident responseを実装する。
7. IaC、runtime/toolchain/version lock、staging/canary、schema/version skew、safe disable、
   disaster recovery、provider outage時のrouting policyをrelease procedureとして固定する。
8. fuzz/adversarial/load/soak/fault-injection test、dependency/SBOM/reproducible build、
   independent security review、provider別operator runbookを完了する。

Cross-phase production release gate（最後まで延期する単独Phaseではなく常時適用）:

- Coding RequirementsとSecurity Invariantsを全crateで満たす。
- experimental/deferred/mock/temporary項目に未充足のproduction exit criteriaがない。
- protocol specification、migration/activation procedure、disaster recovery、monitoring、
  capacity planning、key management、validator operationsを再現可能に文書化する。
- supported runtime間でcanonical bytes、digests、execution effects、commitments、
  consensus outcomes、proof verificationが一致する。
- fuzz/property/adversarial/long-running testsと第三者security auditの重大指摘を解消する。
- mainnet genesis前にrelease artifact、dependency、compiler、build provenanceを固定し、
  reproducible buildとupgrade rehearsalを完了する。


# 66. Architecture Documentation

実装前に`docs/architecture/`内の該当architecture文書を作成・更新してください。

最低限以下を明文化する:

1. overall architecture
2. crate boundaries
3. canonical serialization rules
4. hash architecture
5. HashSuite lifecycle
6. hash domain separation
7. commitment scheme architecture
8. signature domain separation
9. Object lifecycle
10. Transaction lifecycle
11. Fast Path lifecycle
12. Certificate lifecycle
13. persistent state layout
14. validator lifecycle
15. Genesis bootstrap
16. bond lifecycle
17. slashing lifecycle
18. stablecoin fee lifecycle
19. governance lifecycle
20. epoch transition
21. protocol upgrade lifecycle
22. hash algorithm migration lifecycle
23. System Module lifecycle
24. WASM / Chain IR execution
25. ZK execution architecture
26. security invariants
27. failure scenarios
28. serverless runtime constraints


該当architecture文書の更新後は停止せず、
そのまま実装してください。

各Phaseごとに:

cargo fmt --check
cargo clippy --all-targets --all-features
cargo test --all

を通してください。

architecture上の矛盾を発見した場合は、
場当たり的なhackを入れず、
`docs/architecture/decisions/`へdecision recordを追加してから修正してください。


# 67. Highest Priority

architectureの中心に置くもの:

- Serverless-native validator
- No daemon requirement
- Object-centric state
- ABI-driven parallel execution
- Fast path for non-conflicting transactions
- Deterministic WASM
- Rust-first smart contracts
- Native-token-independent security
- Permissioned genesis bootstrap
- Stablecoin validator bonds
- Bond amount independent from voting power
- Stablecoin transaction fees
- Direct validator fee revenue
- Dynamic governance-installed system modules
- Protocol upgradeability
- Cryptographic agility
- Self-describing digests
- Strict domain separation
- SHA-256 as conservative Genesis general-purpose hash
- SHA3-256 supported as migration alternative
- No per-transaction hash negotiation
- No global rehash migrations
- Separate general-purpose hash and ZK commitment schemes
- Lazy state migration
- ZK-friendly execution
- Multi-cloud / edge portability

最重要の思想は以下です。

"A blockchain node is not a continuously running server.
It is a deterministic state-transition function over cryptographically authenticated events and persistent state."

また暗号設計については、

"Hash algorithms are agile, but never negotiable per transaction."

を原則としてください。

高速性だけを理由に暗号primitiveを選定せず、
保守性、標準化、長期互換性、algorithm migration、
domain separation、canonical encoding、ZK suitabilityを
用途ごとに評価してください。
