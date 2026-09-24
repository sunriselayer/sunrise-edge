// Independent DR-0130/DR-0131 wire-vector reconstruction for every canonical
// frame `crates/node-core/src/local_instance_state.rs`,
// `crates/node-core/src/fast_path/records.rs` and
// `crates/node-core/src/fast_path/commitment.rs` allocate: the fast-path
// object lock (0x641B, DR-0131 v1 layout with `locked_epoch`), prepared
// record (0x641C), certificate record (0x641D), settlement record (0x641E),
// validator-set record (0x641F), the nested object-ref list (0x6420),
// fee-share entry/list (0x6435/0x6436), validator-entry list (0x6422) and
// validator-entry (0x6423) frames, the staged-commit commitment envelope
// (0x6424) plus its `HashPurpose::ExecutionEffects` digest, the nonce lock
// (0x6425), the DR-0131 committed epoch record (0x6426), DR-0132's
// epoch-transition record (0x6427) and activation-set digest preimage
// (0x6428), DR-0133's fastpath equivocation evidence record (0x6429), and
// DR-0137's typed bond lifecycle record (0x642A, now extended in place with
// the committed validator authorization scheme/key), signed economics
// resource and policy (0x642B/0x642C), closed lifecycle state (0x642D),
// DR-0137's invocation-local protocol-custody owner-token preimage (0x642E),
// implementation-unit-2's closed bond-lifecycle intent (0x642F, every
// operation shape including DR-0137 implementation-unit-3's `Reactivate`
// tag 5, pinning an exact `BondResourceId` (0x8008) plus expected
// generation/previous/next row digests for a non-forgeable transition
// chain), its signed envelope (0x6430), and the permanent bond-generation
// transition record (0x6431, revised in place: field 8 is now the closed
// `BondTransitionAuthorization` union (0x6433) -- a validator-signed
// envelope or a one-time evidence-driven forfeiture -- rather than raw
// signed-envelope bytes). DR-0137 implementation unit 3 additionally adds
// the permanent evidence-consumed-once absence-fence marker
// (`EvidenceConsumptionRecord`, 0x6432) and the unsigned slash intent
// (`SlashIntent`, 0x6434). No Rust encoder is invoked; this reimplements
// the shared canonical-frame layout
// (crates/canonical-encoding), the self-describing Digest32 frame (0x0103),
// the PublicationContext frame (0x6301), the ObjectRef/ObjectId frames
// (0x4004/0x4001) and the domain-separated hash frame (0x1001) from
// scratch, and checks the result against the exact hex pinned by the
// co-located Rust vectors in crates/node-core/src/fast_path/tests.rs,
// crates/node-core/src/bond_lifecycle/tests.rs,
// crates/node-core/src/bond_lifecycle/slash.rs and
// crates/node-core/src/equivocation/tests.rs.
// Run: node scripts/fast-path-vectors.mjs
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

const BOND_RESOURCE_ID_TYPE_ID = 0x8008;

const uint = (n, width) => {
  const bytes = Buffer.alloc(width);
  let x = BigInt(n);
  for (let i = 0; i < width; i++) {
    bytes[i] = Number(x & 255n);
    x >>= 8n;
  }
  return bytes;
};
const beUint = (n, width) => {
  const bytes = Buffer.alloc(width);
  let x = BigInt(n);
  for (let i = width - 1; i >= 0; i--) {
    bytes[i] = Number(x & 255n);
    x >>= 8n;
  }
  return bytes;
};
const frame = (id, fields, version = 1) => Buffer.concat([
  Buffer.from('SNRE'), uint(id, 2), uint(version, 2), uint(fields.length, 2),
  ...fields.flatMap(([key, value]) => [uint(key, 2), uint(value.length, 4), value]),
]);
const list = (id, items, width = 4) => frame(id, [[1, uint(items.length, width)],
  ...items.map((value, index) => [index + 2, value])]);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();

const SHA2_256_ALGORITHM_ID = 1;
const DIGEST32_TYPE_ID = 0x0103;
const digest32 = (byte) => frame(DIGEST32_TYPE_ID, [
  [1, uint(SHA2_256_ALGORITHM_ID, 2)],
  [2, Buffer.alloc(32, byte)],
]);

const OBJECT_ID_TYPE_ID = 0x4001;
const OBJECT_REF_TYPE_ID = 0x4004;
const objectId = (byte) => frame(OBJECT_ID_TYPE_ID, [[1, Buffer.alloc(32, byte)]]);
const objectRef = (idByte, version, digestByte) => frame(OBJECT_REF_TYPE_ID, [
  [1, objectId(idByte)],
  [2, uint(version, 8)],
  [3, digest32(digestByte)],
]);

const CONTEXT_TYPE_ID = 0x6301;
const CHAIN_ID = 'dr0130-fastpath-vectors';
const PROTOCOL_VERSION = 3;
const EPOCH = 9;
const context = frame(CONTEXT_TYPE_ID, [
  [1, Buffer.from(CHAIN_ID)],
  [2, uint(PROTOCOL_VERSION, 4)],
  [3, uint(EPOCH, 8)],
]);

const packageOrigin = (publisherByte, seedByte) => frame(0x5201, [
  [1, Buffer.from(CHAIN_ID)],
  [2, uint(1, 2)],
  [3, Buffer.alloc(32, publisherByte)],
  [4, Buffer.alloc(32, seedByte)],
]);
const instanceTarget = (creatorByte, seedByte, revision, digestByte) => frame(0x6401, [
  [1, Buffer.alloc(32, creatorByte)],
  [2, Buffer.alloc(32, seedByte)],
  [3, uint(revision, 8)],
  [4, digest32(digestByte)],
]);
const dependencyRef = (origin, revision, digestByte) => frame(0x6302, [
  [1, origin],
  [2, uint(revision, 8)],
  [3, context],
  [4, digest32(digestByte)],
]);
const opaqueTypeArg = (domain, valueByte) => frame(0x5202, [
  [1, uint(2, 2)],
  [2, uint(domain, 2)],
  [3, Buffer.alloc(32, valueByte)],
]);
const scopedType = (origin, constructor, args) => frame(0x5203, [
  [1, origin],
  [2, uint(constructor, 2)],
  [3, uint(args.length, 2)],
  ...args.map((arg, index) => [index + 4, arg]),
]);
const objectAuthority = (idByte, origin, ty) => frame(0x6407, [
  [1, Buffer.alloc(32, idByte)],
  [2, context],
  [3, instanceTarget(0x13, 0x14, 1, 0x15)],
  [4, dependencyRef(origin, 1, 0x12)],
  [5, ty],
]);

// ---- FastPathLockRecord 0x641B/v1 (DR-0131: redefined in place to add
// field 3, `locked_epoch`) ----
const FASTPATH_LOCK_RECORD_TYPE_ID = 0x641b;
const lockRecord = frame(FASTPATH_LOCK_RECORD_TYPE_ID, [
  [1, Buffer.alloc(32, 0x11)],
  [2, objectRef(0x22, 7, 0x33)],
  [3, uint(9, 8)],
]);

// ---- FastPathEpochRecord 0x6426/v1 (DR-0131). Field 3 (`previous_epoch`)
// is present only starting at Slice 2's first transition; both presence
// states are vectored. ----
const FASTPATH_EPOCH_RECORD_TYPE_ID = 0x6426;
const epochRecordGenesis = frame(FASTPATH_EPOCH_RECORD_TYPE_ID, [
  [1, uint(9, 8)],
  [2, digest32(0x66)],
  [4, uint(0x77, 8)],
]);
const epochRecordWithPrevious = frame(FASTPATH_EPOCH_RECORD_TYPE_ID, [
  [1, uint(10, 8)],
  [2, digest32(0x88)],
  [3, uint(9, 8)],
  [4, uint(0x99, 8)],
]);

// ---- FastPathEpochTransitionRecord 0x6427/v1 and the non-stored
// FastPathEpochActivationSet digest preimage 0x6428/v1 (DR-0132). ----
const FASTPATH_EPOCH_TRANSITION_RECORD_TYPE_ID = 0x6427;
const FASTPATH_EPOCH_ACTIVATION_SET_TYPE_ID = 0x6428;
const nextContext = frame(CONTEXT_TYPE_ID, [
  [1, Buffer.from(CHAIN_ID)],
  [2, uint(PROTOCOL_VERSION, 4)],
  [3, uint(10, 8)],
]);
const epochTransitionRecord = frame(FASTPATH_EPOCH_TRANSITION_RECORD_TYPE_ID, [
  [1, uint(9, 8)],
  [2, uint(10, 8)],
  [3, digest32(0xaa)],
  [4, digest32(0xbb)],
  [5, digest32(0xcc)],
  [6, Buffer.from([0xdd, 0xee])],
  [7, uint(0x77, 8)],
]);
const epochActivationSet = frame(FASTPATH_EPOCH_ACTIVATION_SET_TYPE_ID, [
  [1, nextContext],
  [2, Buffer.from([0x11, 0x12])],
  [3, Buffer.from([0x21])],
  [4, Buffer.from([0x31, 0x32, 0x33])],
  [5, Buffer.from([0x41, 0x42])],
]);

// ---- FastPathNonceLockRecord 0x6425/v1 ----
const FASTPATH_NONCE_LOCK_RECORD_TYPE_ID = 0x6425;
const nonceLockRecord = frame(FASTPATH_NONCE_LOCK_RECORD_TYPE_ID, [
  [1, Buffer.alloc(32, 0x44)],
  [2, Buffer.alloc(32, 0x55)],
  [3, uint(9, 8)],
  [4, uint(42, 8)],
]);

// ---- FastPathPreparedRecord 0x641C/v1, nesting the 0x6420 object-ref list ----
const FASTPATH_PREPARED_RECORD_TYPE_ID = 0x641c;
const FASTPATH_OBJECT_REF_LIST_TYPE_ID = 0x6420;
const firstLockedObject = objectRef(0xaa, 1, 0xbb);
const secondLockedObject = objectRef(0xcc, 2, 0xdd);
const objectRefList = list(FASTPATH_OBJECT_REF_LIST_TYPE_ID, [firstLockedObject, secondLockedObject]);
const preparedRecord = frame(FASTPATH_PREPARED_RECORD_TYPE_ID, [
  [1, context],
  [2, Buffer.alloc(32, 0x66)],
  [3, digest32(0x77)],
  [4, digest32(0x88)],
  [5, Buffer.alloc(4, 0x99)],
  [6, objectRefList],
  [7, uint(5, 8)],
  [8, uint(6, 8)],
]);

// ---- FastPathCertificateRecord 0x641D/v1 ----
const FASTPATH_CERTIFICATE_RECORD_TYPE_ID = 0x641d;
const certificateRecord = frame(FASTPATH_CERTIFICATE_RECORD_TYPE_ID, [
  [1, Buffer.alloc(32, 0xee)],
  [2, Buffer.alloc(6, 0xff)],
]);

// ---- FastPathSettlementRecord 0x641E/v1, nesting 0x6435 shares in a
// 0x6436 bounded list ----
const FASTPATH_SETTLEMENT_RECORD_TYPE_ID = 0x641e;
const FASTPATH_FEE_SHARE_TYPE_ID = 0x6435;
const FASTPATH_FEE_SHARE_LIST_TYPE_ID = 0x6436;
const feeResourceId = frame(BOND_RESOURCE_ID_TYPE_ID, [
  [1, uint(9, 2)],
  [2, Buffer.alloc(32, 0x09)],
]);
const feeShare = (validatorByte, amount) => frame(FASTPATH_FEE_SHARE_TYPE_ID, [
  [1, Buffer.alloc(32, validatorByte)],
  [2, uint(amount, 8)],
  [3, uint(0, 2)],
]);
const chargedShareList = list(FASTPATH_FEE_SHARE_LIST_TYPE_ID, [feeShare(0x05, 1), feeShare(0x06, 0)]);
const settlementRecordCharged = frame(FASTPATH_SETTLEMENT_RECORD_TYPE_ID, [
  [1, context],
  [2, Buffer.alloc(32, 0x01)],
  [3, uint(1, 8)],
  [4, feeResourceId],
  [5, objectRef(0x02, 3, 0x04)],
  [6, uint(3, 8)],
  [7, uint(1, 8)],
  [8, chargedShareList],
]);
const settlementRecordUncharged = frame(FASTPATH_SETTLEMENT_RECORD_TYPE_ID, [
  [1, context],
  [2, Buffer.alloc(32, 0x07)],
  [3, uint(0, 8)],
]);

// ---- FastPathValidatorSetRecord 0x641F/v1, nesting the 0x6422 validator
// entry list, itself nesting two 0x6423 validator entries ----
const FASTPATH_VALIDATOR_SET_RECORD_TYPE_ID = 0x641f;
const FASTPATH_VALIDATOR_ENTRY_LIST_TYPE_ID = 0x6422;
const FASTPATH_VALIDATOR_ENTRY_TYPE_ID = 0x6423;
const ED25519_SCHEME_ID = 1;
const validatorEntry = (idByte, votingPower, publicKeyByte) => frame(FASTPATH_VALIDATOR_ENTRY_TYPE_ID, [
  [1, Buffer.alloc(32, idByte)],
  [2, uint(votingPower, 8)],
  [3, uint(ED25519_SCHEME_ID, 2)],
  [4, Buffer.alloc(3, publicKeyByte)],
]);
const firstValidatorEntry = validatorEntry(0x11, 100, 0x22);
const secondValidatorEntry = validatorEntry(0x33, 200, 0x44);
const validatorEntryList = list(FASTPATH_VALIDATOR_ENTRY_LIST_TYPE_ID, [
  firstValidatorEntry,
  secondValidatorEntry,
]);
const validatorSetRecord = frame(FASTPATH_VALIDATOR_SET_RECORD_TYPE_ID, [
  [1, context],
  [2, validatorEntryList],
]);

// ---- Commitment envelope 0x6424/v1 and its HashPurpose::ExecutionEffects
// digest. The created-authority list stays empty because its nested bytes are
// already pinned by the local-execution vectors. Head-read, object-mutation,
// state-read and state-mutation lists each carry a minimal item so the
// commitment layer's separate big-endian count/length framing is checked too.
// ----
const COMMITMENT_ENVELOPE_TYPE_ID = 0x6424;
const HASH_FRAME_TYPE_ID = 0x1001;
const EXECUTION_EFFECTS_DOMAIN_ID = 3; // HashDomain::ExecutionEffects
const HASH_DOMAIN_VERSION = 1;
const RESOLVER_CHAIN_ID = 'paid-durable';
const RESOLVER_PROTOCOL_VERSION = 3;
const commitmentList = (items) => Buffer.concat([
  beUint(items.length, 4),
  ...items.flatMap((item) => [beUint(item.length, 4), item]),
]);
const emptyCommitmentList = commitmentList([]);
const vectorObjectId = Buffer.alloc(32, 0xb0);
const headReadItem = Buffer.concat([vectorObjectId, Buffer.from([0])]);
const objectMutationItem = Buffer.concat([vectorObjectId, Buffer.from([0])]);
const stateReadKey = Buffer.alloc(3, 0xb1);
const stateReadItem = Buffer.concat([
  beUint(stateReadKey.length, 4), stateReadKey, beUint(6, 8),
]);
const stateMutationKey = Buffer.alloc(3, 0xb2);
const stateMutationValue = Buffer.alloc(2, 0xb3);
const stateMutationItem = Buffer.concat([
  beUint(stateMutationKey.length, 4), stateMutationKey,
  Buffer.from([1]),
  beUint(stateMutationValue.length, 4), stateMutationValue,
]);
const commitmentEnvelope = frame(COMMITMENT_ENVELOPE_TYPE_ID, [
  [1, digest32(0xa1)],
  [2, Buffer.alloc(4, 0xa2)],
  [3, emptyCommitmentList],
  [4, commitmentList([headReadItem])],
  [5, commitmentList([objectMutationItem])],
  [6, commitmentList([stateReadItem])],
  [7, commitmentList([stateMutationItem])],
  [8, Buffer.alloc(4, 0xa3)],
  [9, uint(5, 8)],
  [10, Buffer.alloc(4, 0xa4)],
]);
const hashForPurpose = (domainId, chainId, protocolVersion, payload) => sha256(frame(HASH_FRAME_TYPE_ID, [
  [1, uint(SHA2_256_ALGORITHM_ID, 2)],
  [2, uint(domainId, 2)],
  [3, uint(HASH_DOMAIN_VERSION, 2)],
  [4, Buffer.from(chainId)],
  [5, uint(protocolVersion, 4)],
  [6, payload],
]));
const commitmentDigest = hashForPurpose(
  EXECUTION_EFFECTS_DOMAIN_ID,
  RESOLVER_CHAIN_ID,
  RESOLVER_PROTOCOL_VERSION,
  commitmentEnvelope,
);

// ---- FastPathEquivocationEvidenceRecord 0x6429/v1 (DR-0133) ----
const FASTPATH_EQUIVOCATION_EVIDENCE_RECORD_TYPE_ID = 0x6429;
const equivocationEvidenceRecord = frame(FASTPATH_EQUIVOCATION_EVIDENCE_RECORD_TYPE_ID, [
  [1, Buffer.from([0xaa, 0xbb, 0xcc])],
  [2, uint(0x42, 8)],
]);

// ---- FastPathBondRecord 0x642A/v1 and state 0x642D/v1 (DR-0137) ----
const FASTPATH_BOND_RECORD_TYPE_ID = 0x642a;
const FASTPATH_BOND_STATE_TYPE_ID = 0x642d;
const bondOrigin = packageOrigin(0x10, 0x11);
const bondType = scopedType(bondOrigin, 2, [opaqueTypeArg(7, 0x30)]);
const bondStateActive = frame(FASTPATH_BOND_STATE_TYPE_ID, [
  [1, uint(1, 2)],
]);
// Committed validator authorization key: a genuine compressed Ed25519 point
// (Rust `VerificationKey::from(&SigningKey::from([0x23; 32]))`), not an
// arbitrary fill byte, since the Rust encoder structurally validates it.
const bondAuthorizationKey = Buffer.from(
  '74f85cda34d1c27c4621484731e91579c3d9c6cfc0d94b281aa11e9162058aa9',
  'hex',
);
const bondRecord = frame(FASTPATH_BOND_RECORD_TYPE_ID, [
  [1, context],
  [2, Buffer.alloc(32, 0x16)],
  [3, uint(7, 2)],
  [4, Buffer.alloc(32, 0x30)],
  [5, objectRef(0x20, 1, 0x21)],
  [6, objectAuthority(0x20, bondOrigin, bondType)],
  [7, uint(1000, 8)],
  [8, uint(0x22, 8)],
  [9, uint(1, 8)],
  [10, uint(EPOCH, 8)],
  [11, uint(100, 8)],
  [12, bondStateActive],
  [13, uint(ED25519_SCHEME_ID, 2)],
  [14, bondAuthorizationKey],
  [15, uint(EPOCH, 8)], // slashable_from_epoch
  [16, uint(EPOCH, 8)], // custody_object_epoch
]);

// ---- Signed economics resource/policy 0x642B/v1 and 0x642C/v1 (DR-0137) ----
const bondResourceId = frame(BOND_RESOURCE_ID_TYPE_ID, [
  [1, uint(7, 2)],
  [2, Buffer.alloc(32, 0x21)],
]);
const bondResourceConfig = frame(0x8002, [
  [1, bondResourceId],
  [2, uint(100, 8)],
  [3, uint(1, 1)],
  [4, uint(7, 8)],
]);
const economicsChainId = 'dr0137-economics';
const economicsContext = frame(CONTEXT_TYPE_ID, [
  [1, Buffer.from(economicsChainId)],
  [2, uint(PROTOCOL_VERSION, 4)],
  [3, uint(EPOCH, 8)],
]);
const economicsOrigin = frame(0x5201, [
  [1, Buffer.from(economicsChainId)],
  [2, uint(1, 2)],
  [3, Buffer.alloc(32, 0x11)],
  [4, Buffer.alloc(32, 0x12)],
]);
const economicsType = scopedType(economicsOrigin, 2, [opaqueTypeArg(7, 0x21)]);
const economicsDependencyRef = frame(0x6302, [
  [1, economicsOrigin],
  [2, uint(1, 8)],
  [3, economicsContext],
  [4, digest32(0x16)],
]);
const economicsResourcePolicy = frame(0x642b, [
  [1, bondResourceId],
  [2, economicsContext],
  [3, instanceTarget(0x13, 0x14, 1, 0x15)],
  [4, economicsDependencyRef],
  [5, economicsType],
  [6, uint(1, 4)],
  [7, Buffer.from('split')],
  [8, Buffer.from('transfer')],
  [9, uint(3, 2)],
  [10, bondResourceConfig],
]);
const economicsPolicy = frame(0x642c, [
  [1, economicsContext],
  [2, uint(1, 4)],
  [3, economicsResourcePolicy],
]);

// ---- Invocation-local protocol-custody owner-token preimage 0x642E/v1
// (DR-0137 implementation-unit-2 prerequisite). This token is not protocol
// state or an address; execution resolves it only inside one exact capability.
// ----
const custodyVectorChain = 'custody-vector';
const custodyScope = frame(0x4007, [
  [1, uint(1, 2)], // ProtocolCustodyPurpose::BondCollateral
  [2, Buffer.from(custodyVectorChain)],
  [3, Buffer.alloc(32, 0x22)],
  [4, Buffer.alloc(32, 0x33)],
]);
const custodyOwnerTokenPreimage = frame(0x642e, [
  [1, Buffer.from(custodyVectorChain)],
  [2, custodyScope],
  [3, objectId(0x44)],
  [4, uint(0, 4)], // bounded rejection-sampling counter
]);

// ---- BondLifecycleIntent 0x642F/v1, signed as 0x6430/v1, and
// FastPathBondTransitionRecord 0x6431/v1 (DR-0137 implementation unit 2,
// redesigned for a cryptographically non-forgeable transition chain: the
// signer pins the exact resource identity, expected pre-transition
// generation/row digest, and expected resulting row digest, and the
// permanent transition record retains the exact signed envelope and the
// exact resulting row bytes rather than a digest/signature summary alone --
// see `bond_lifecycle::handle_bond_lifecycle` and
// `genesis::verify_fastpath_bond_chain`). ----
const BOND_LIFECYCLE_INTENT_TYPE_ID = 0x642f;
const SIGNED_BOND_LIFECYCLE_INTENT_TYPE_ID = 0x6430;
const FASTPATH_BOND_TRANSITION_RECORD_TYPE_ID = 0x6431;
const closedBondResourceId = (domain, valueByte) => frame(BOND_RESOURCE_ID_TYPE_ID, [
  [1, uint(domain, 2)],
  [2, Buffer.alloc(32, valueByte)],
]);
// Every `BondLifecycleIntent` shares these fixed fields; only the
// operation-specific fields (5 for Deposit/Withdraw, 6/7/8 for Replace, 9
// for Unbond) vary by shape.
const bondLifecycleIntent = (operationFields) => frame(BOND_LIFECYCLE_INTENT_TYPE_ID, [
  [1, context],
  [2, Buffer.alloc(32, 0x72)],
  [3, Buffer.alloc(32, 0x72)],
  ...operationFields,
  [10, closedBondResourceId(7, 0x79)],
  [11, uint(1, 8)],
  [12, digest32(0x01)],
  [13, digest32(0x02)],
]);
const bondLifecycleDepositIntent = bondLifecycleIntent([
  [4, uint(1, 2)], // BondLifecycleOperation::Deposit
  [5, Buffer.from([0x01, 0x02, 0x03])],
]);
const bondLifecycleReplaceIntent = bondLifecycleIntent([
  [4, uint(2, 2)], // BondLifecycleOperation::Replace
  [6, Buffer.from([0x04, 0x05])],
  [7, Buffer.from([0x06, 0x07])],
  [8, Buffer.alloc(32, 0x22)],
]);
const bondLifecycleUnbondIntent = bondLifecycleIntent([
  [4, uint(3, 2)], // BondLifecycleOperation::Unbond
  [9, Buffer.alloc(32, 0x33)],
]);
const bondLifecycleWithdrawIntent = bondLifecycleIntent([
  [4, uint(4, 2)], // BondLifecycleOperation::Withdraw
  [5, Buffer.from([0x08, 0x09])],
]);
// DR-0137 implementation unit 3: `Reactivate` (tag 5) reuses `Deposit`'s
// exact field 5 leg shape.
const bondLifecycleReactivateIntent = bondLifecycleIntent([
  [4, uint(5, 2)], // BondLifecycleOperation::Reactivate
  [5, Buffer.from([0x0a, 0x0b, 0x0c])],
]);
// `SignedBondLifecycleIntent` is exercised only over the deposit-intent
// vector `bondLifecycleDepositIntent0x642f` used by the
// `bondLifecycleDepositIntent0x642f`/`signedBondLifecycleIntent0x6430`
// stability vectors above (own 0x71/0x72 bytes and Sha2-256(0x81)/(0x82)
// digests, matching the Rust stability test).
const bondLifecycleDepositIntentSigned = frame(BOND_LIFECYCLE_INTENT_TYPE_ID, [
  [1, context],
  [2, Buffer.alloc(32, 0x71)],
  [3, Buffer.alloc(32, 0x72)],
  [4, uint(1, 2)], // BondLifecycleOperation::Deposit
  [5, Buffer.from([0xaa, 0xbb, 0xcc])],
  [10, closedBondResourceId(7, 0x79)],
  [11, uint(4, 8)],
  [12, digest32(0x81)],
  [13, digest32(0x82)],
]);
const signedBondLifecycleIntent = frame(SIGNED_BOND_LIFECYCLE_INTENT_TYPE_ID, [
  [1, bondLifecycleDepositIntentSigned],
  [2, Buffer.alloc(64, 0x42)],
]);
// ---- DR-0137 implementation unit 3: `BondTransitionAuthorization` 0x6433/v1
// (the closed union `FastPathBondTransitionRecord` field 8 now carries: a
// validator-signed lifecycle envelope, or one evidence-driven forfeiture),
// `EvidenceConsumptionRecord` 0x6432/v1 (the permanent evidence-consumed-once
// absence-fence marker), and unsigned `SlashIntent` 0x6434/v1 -- see
// `bond_lifecycle::slash`. ----
const BOND_TRANSITION_AUTHORIZATION_TYPE_ID = 0x6433;
const EVIDENCE_CONSUMPTION_RECORD_TYPE_ID = 0x6432;
const SLASH_INTENT_TYPE_ID = 0x6434;
const bondTransitionAuthorizationValidatorEnvelope = (signedEnvelope) => frame(BOND_TRANSITION_AUTHORIZATION_TYPE_ID, [
  [1, uint(1, 2)], // tag: ValidatorEnvelope
  [2, signedEnvelope],
]);
const bondTransitionAuthorizationConsumedEvidence = ({ evidenceBytes, evidenceEpoch, evidenceDigest, forfeitureLeg, previousObject, resultingObject }) => frame(BOND_TRANSITION_AUTHORIZATION_TYPE_ID, [
  [1, uint(2, 2)], // tag: ConsumedEvidence
  [3, evidenceBytes],
  [4, uint(evidenceEpoch, 8)],
  [5, evidenceDigest],
  [6, forfeitureLeg],
  [7, previousObject],
  [8, resultingObject],
]);
const bondTransitionRecord = frame(FASTPATH_BOND_TRANSITION_RECORD_TYPE_ID, [
  [1, context],
  [2, Buffer.alloc(32, 0x79)],
  [3, uint(2, 8)],
  [4, digest32(0x11)],
  [5, digest32(0x12)],
  [6, uint(1, 2)], // FastPathBondLifecycleOperation::Deposit
  [7, uint(9, 8)],
  [8, bondTransitionAuthorizationValidatorEnvelope(Buffer.from([0xaa, 0xbb]))],
  [9, Buffer.from([0xcc, 0xdd, 0xee])],
]);
const validatorEnvelopeAuthorization = bondTransitionAuthorizationValidatorEnvelope(Buffer.from([0x21, 0x22, 0x23]));
const consumedEvidenceAuthorization = bondTransitionAuthorizationConsumedEvidence({
  evidenceBytes: Buffer.from([0x31, 0x32]),
  evidenceEpoch: 4,
  evidenceDigest: digest32(0x33),
  forfeitureLeg: Buffer.from([0x34, 0x35, 0x36]),
  previousObject: Buffer.from([0x37, 0x38]),
  resultingObject: Buffer.from([0x39, 0x3a]),
});
const slashTransitionRecord = frame(FASTPATH_BOND_TRANSITION_RECORD_TYPE_ID, [
  [1, context],
  [2, Buffer.alloc(32, 0x79)],
  [3, uint(2, 8)],
  [4, digest32(0x11)],
  [5, digest32(0x12)],
  [6, uint(6, 2)], // FastPathBondLifecycleOperation::Slash
  [7, uint(9, 8)],
  [8, consumedEvidenceAuthorization],
  [9, Buffer.from([0x14, 0x14])],
]);
const evidenceConsumptionRecord = frame(EVIDENCE_CONSUMPTION_RECORD_TYPE_ID, [
  [1, Buffer.alloc(32, 0x41)],
  [2, uint(3, 8)],
  [3, digest32(0x42)],
  [4, uint(5, 8)],
  [5, uint(12, 8)],
]);
const slashIntentVectorContext = frame(0x6301, [
  [1, Buffer.from('dr0137-unit3-vectors')],
  [2, uint(3, 4)],
  [3, uint(9, 8)],
]);
const slashIntent = frame(SLASH_INTENT_TYPE_ID, [
  [1, slashIntentVectorContext],
  [2, Buffer.alloc(32, 0x51)],
  [3, Buffer.alloc(32, 0x52)],
  [4, closedBondResourceId(7, 0x79)],
  [5, uint(3, 8)],
  [6, uint(2, 8)],
  [7, digest32(0x53)],
  [8, Buffer.from([0x54, 0x55, 0x56])],
]);

// ---- FeeClaimIntent 0x6437, signed as 0x6438: a validator-signed claim
// against one bounded FastPathSettlementRecord escrow row (DR-0137
// "Certified fee escrow and claims"), closed to ZeroShare (tag 1, no leg,
// always v1), Split (tag 2, one leg through the policy-pinned `split`
// entrypoint, either legacy v1 with no payout ref or v2 with an exact signed
// expected payout ObjectRef in field 15) or FinalTransfer (tag 3, through
// `transfer`, always v1). The signed envelope's own version always matches
// its embedded intent's version. No Rust encoder is invoked; this
// reimplements the shared canonical-frame layout, the PublicationContext,
// ObjectRef and BondResourceId frames from scratch and checks the result
// against the exact hex pinned by the co-located Rust vectors in
// crates/node-core/src/fee_claims/codec/tests.rs. ----
const FEE_CLAIM_INTENT_TYPE_ID = 0x6437;
const SIGNED_FEE_CLAIM_INTENT_TYPE_ID = 0x6438;
const feeClaimIntent = (f) => frame(FEE_CLAIM_INTENT_TYPE_ID, [
  [1, context],
  [2, Buffer.alloc(32, f.requestByte)],
  [3, Buffer.alloc(32, f.escrowRequestByte)],
  [4, uint(f.certificateEpoch, 8)],
  [5, Buffer.alloc(32, f.validatorByte)],
  [6, closedBondResourceId(7, 0x79)],
  [7, uint(f.expectedGeneration, 8)],
  [8, objectRef(f.feeOutputIdByte, f.feeOutputVersion, f.feeOutputDigestByte)],
  [9, digest32(f.previousDigestByte)],
  [10, digest32(f.nextDigestByte)],
  [11, uint(f.shareAmount, 8)],
  [12, Buffer.alloc(32, f.recipientByte)],
  [13, uint(f.tag, 2)],
  ...(f.leg ? [[14, f.leg]] : []),
  ...(f.payoutRef ? [[15, f.payoutRef]] : []),
], f.version ?? 1);
const feeClaimZeroShareIntent = feeClaimIntent({
  requestByte: 0x91, escrowRequestByte: 0x92, certificateEpoch: 9, validatorByte: 0x93,
  expectedGeneration: 1, feeOutputIdByte: 0xaa, feeOutputVersion: 1, feeOutputDigestByte: 0xbb,
  previousDigestByte: 0x81, nextDigestByte: 0x82, shareAmount: 0, recipientByte: 0x98, tag: 1,
});
const feeClaimSplitIntent = feeClaimIntent({
  requestByte: 0xa1, escrowRequestByte: 0xa2, certificateEpoch: 9, validatorByte: 0xa3,
  expectedGeneration: 2, feeOutputIdByte: 0xaa, feeOutputVersion: 1, feeOutputDigestByte: 0xbb,
  previousDigestByte: 0x81, nextDigestByte: 0x82, shareAmount: 42, recipientByte: 0xa8, tag: 2,
  leg: Buffer.from([0x01, 0x02, 0x03]),
});
const signedFeeClaimSplitIntent = frame(SIGNED_FEE_CLAIM_INTENT_TYPE_ID, [
  [1, feeClaimSplitIntent],
  [2, Buffer.alloc(64, 0x42)],
]);
const feeClaimSplitIntentV2 = feeClaimIntent({
  requestByte: 0xa1, escrowRequestByte: 0xa2, certificateEpoch: 9, validatorByte: 0xa3,
  expectedGeneration: 2, feeOutputIdByte: 0xaa, feeOutputVersion: 1, feeOutputDigestByte: 0xbb,
  previousDigestByte: 0x81, nextDigestByte: 0x82, shareAmount: 42, recipientByte: 0xa8, tag: 2,
  leg: Buffer.from([0x01, 0x02, 0x03]),
  payoutRef: objectRef(0xcc, 3, 0xdd),
  version: 2,
});
const signedFeeClaimSplitIntentV2 = frame(SIGNED_FEE_CLAIM_INTENT_TYPE_ID, [
  [1, feeClaimSplitIntentV2],
  [2, Buffer.alloc(64, 0x42)],
], 2);

const vectors = {
  fastpathLockRecord0x641b: lockRecord,
  fastpathNonceLockRecord0x6425: nonceLockRecord,
  fastpathEpochRecordGenesis0x6426: epochRecordGenesis,
  fastpathEpochRecordWithPrevious0x6426: epochRecordWithPrevious,
  fastpathEpochTransitionRecord0x6427: epochTransitionRecord,
  fastpathEpochActivationSet0x6428: epochActivationSet,
  fastpathPreparedRecord0x641c: preparedRecord,
  fastpathObjectRefList0x6420: objectRefList,
  fastpathObjectRefNestedIn0x6420: firstLockedObject,
  fastpathCertificateRecord0x641d: certificateRecord,
  fastpathSettlementRecordCharged0x641e: settlementRecordCharged,
  fastpathFeeShareFirst0x6435: feeShare(0x05, 1),
  fastpathFeeShareListCharged0x6436: chargedShareList,
  fastpathSettlementRecordUncharged0x641e: settlementRecordUncharged,
  fastpathValidatorSetRecord0x641f: validatorSetRecord,
  fastpathValidatorEntryList0x6422: validatorEntryList,
  fastpathValidatorEntry0x6423: firstValidatorEntry,
  fastpathCommitmentEnvelope0x6424: commitmentEnvelope,
  fastpathEquivocationEvidenceRecord0x6429: equivocationEvidenceRecord,
  fastpathBondRecord0x642a: bondRecord,
  fastpathBondStateActive0x642d: bondStateActive,
  protocolCustodyOwnerTokenPreimage0x642e: custodyOwnerTokenPreimage,
  bondLifecycleDepositIntent0x642f: bondLifecycleDepositIntent,
  bondLifecycleReplaceIntent0x642f: bondLifecycleReplaceIntent,
  bondLifecycleUnbondIntent0x642f: bondLifecycleUnbondIntent,
  bondLifecycleWithdrawIntent0x642f: bondLifecycleWithdrawIntent,
  bondLifecycleReactivateIntent0x642f: bondLifecycleReactivateIntent,
  signedBondLifecycleIntent0x6430: signedBondLifecycleIntent,
  fastpathBondTransitionRecord0x6431: bondTransitionRecord,
  fastpathSlashTransitionRecord0x6431: slashTransitionRecord,
  bondTransitionAuthorizationValidatorEnvelope0x6433: validatorEnvelopeAuthorization,
  bondTransitionAuthorizationConsumedEvidence0x6433: consumedEvidenceAuthorization,
  evidenceConsumptionRecord0x6432: evidenceConsumptionRecord,
  slashIntent0x6434: slashIntent,
  feeClaimZeroShareIntent0x6437: feeClaimZeroShareIntent,
  feeClaimSplitIntent0x6437: feeClaimSplitIntent,
  signedFeeClaimSplitIntent0x6438: signedFeeClaimSplitIntent,
  feeClaimSplitIntentV2_0x6437: feeClaimSplitIntentV2,
  signedFeeClaimSplitIntentV2_0x6438: signedFeeClaimSplitIntentV2,
};

const expected = {
  fastpathLockRecord0x641b: '534e52451b6401000300010020000000111111111111111111111111111111111111111111111111111111111111111102008c000000534e5245044001000300010030000000534e524501400100010001002000000022222222222222222222222222222222222222222222222222222222222222220200080000000700000000000000030038000000534e5245030101000200010002000000010002002000000033333333333333333333333333333333333333333333333333333333333333330300080000000900000000000000',
  fastpathNonceLockRecord0x6425: '534e52452564010004000100200000004444444444444444444444444444444444444444444444444444444444444444020020000000555555555555555555555555555555555555555555555555555555555555555503000800000009000000000000000400080000002a00000000000000',
  fastpathEpochRecordGenesis0x6426: '534e52452664010003000100080000000900000000000000020038000000534e5245030101000200010002000000010002002000000066666666666666666666666666666666666666666666666666666666666666660400080000007700000000000000',
  fastpathEpochRecordWithPrevious0x6426: '534e52452664010004000100080000000a00000000000000020038000000534e52450301010002000100020000000100020020000000888888888888888888888888888888888888888888888888888888888888888803000800000009000000000000000400080000009900000000000000',
  fastpathEpochTransitionRecord0x6427: '534e524527640100070001000800000009000000000000000200080000000a00000000000000030038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa040038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb050038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc060002000000ddee0700080000007700000000000000',
  fastpathEpochActivationSet0x6428: '534e524528640100050001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000a000000000000000200020000001112030001000000210400030000003132330500020000004142',
  fastpathPreparedRecord0x641c: '534e52451c640100080001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200200000006666666666666666666666666666666666666666666666666666666666666666030038000000534e524503010100020001000200000001000200200000007777777777777777777777777777777777777777777777777777777777777777040038000000534e52450301010002000100020000000100020020000000888888888888888888888888888888888888888888888888888888888888888805000400000099999999060038010000534e52452064010003000100040000000200000002008c000000534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb03008c000000534e5245044001000300010030000000534e5245014001000100010020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200080000000200000000000000030038000000534e52450301010002000100020000000100020020000000dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd07000800000005000000000000000800080000000600000000000000',
  fastpathObjectRefList0x6420: '534e52452064010003000100040000000200000002008c000000534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb03008c000000534e5245044001000300010030000000534e5245014001000100010020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200080000000200000000000000030038000000534e52450301010002000100020000000100020020000000dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  fastpathObjectRefNestedIn0x6420: '534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  fastpathCertificateRecord0x641d: '534e52451d6401000200010020000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee020006000000ffffffffffff',
  fastpathSettlementRecordCharged0x641e: '534e52451e640100080001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000001010101010101010101010101010101010101010101010101010101010101010300080000000100000000000000040038000000534e52450880010002000100020000000900020020000000090909090909090909090909090909090909090909090909090909090909090905008c000000534e5245044001000300010030000000534e524501400100010001002000000002020202020202020202020202020202020202020202020202020202020202020200080000000300000000000000030038000000534e524503010100020001000200000001000200200000000404040404040404040404040404040404040404040404040404040404040404060008000000030000000000000007000800000001000000000000000800ac000000534e524536640100030001000400000002000000020046000000534e5245356401000300010020000000050505050505050505050505050505050505050505050505050505050505050502000800000001000000000000000300020000000000030046000000534e5245356401000300010020000000060606060606060606060606060606060606060606060606060606060606060602000800000000000000000000000300020000000000',
  fastpathFeeShareFirst0x6435: '534e5245356401000300010020000000050505050505050505050505050505050505050505050505050505050505050502000800000001000000000000000300020000000000',
  fastpathFeeShareListCharged0x6436: '534e524536640100030001000400000002000000020046000000534e5245356401000300010020000000050505050505050505050505050505050505050505050505050505050505050502000800000001000000000000000300020000000000030046000000534e5245356401000300010020000000060606060606060606060606060606060606060606060606060606060606060602000800000000000000000000000300020000000000',
  fastpathSettlementRecordUncharged0x641e: '534e52451e640100030001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000007070707070707070707070707070707070707070707070707070707070707070300080000000000000000000000',
  fastpathValidatorSetRecord0x641f: '534e52451f640100020001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200be000000534e52452264010003000100040000000200000002004f000000534e524523640100040001002000000011111111111111111111111111111111111111111111111111111111111111110200080000006400000000000000030002000000010004000300000022222203004f000000534e52452364010004000100200000003333333333333333333333333333333333333333333333333333333333333333020008000000c8000000000000000300020000000100040003000000444444',
  fastpathValidatorEntryList0x6422: '534e52452264010003000100040000000200000002004f000000534e524523640100040001002000000011111111111111111111111111111111111111111111111111111111111111110200080000006400000000000000030002000000010004000300000022222203004f000000534e52452364010004000100200000003333333333333333333333333333333333333333333333333333333333333333020008000000c8000000000000000300020000000100040003000000444444',
  fastpathValidatorEntry0x6423: '534e5245236401000400010020000000111111111111111111111111111111111111111111111111111111111111111102000800000064000000000000000300020000000100040003000000222222',
  fastpathCommitmentEnvelope0x6424: '534e5245246401000a00010038000000534e52450301010002000100020000000100020020000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1020004000000a2a2a2a2030004000000000000000400290000000000000100000021b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000500290000000000000100000021b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000060017000000000000010000000f00000003b1b1b10000000000000006070016000000000000010000000e00000003b2b2b20100000002b3b3080004000000a3a3a3a309000800000005000000000000000a0004000000a4a4a4a4',
  fastpathEquivocationEvidenceRecord0x6429: '534e5245296401000200010003000000aabbcc0200080000004200000000000000',
  fastpathBondStateActive0x642d: '534e52452d64010001000100020000000100',
  fastpathBondRecord0x642a: '534e52452a640100100001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000016161616161616161616161616161616161616161616161616161616161616160300020000000700040020000000303030303030303030303030303030303030303030303030303030303030303005008c000000534e5245044001000300010030000000534e524501400100010001002000000020202020202020202020202020202020202020202020202020202020202020200200080000000100000000000000030038000000534e524503010100020001000200000001000200200000002121212121212121212121212121212121212121212121212121212121212121060026030000534e5245076401000500010020000000202020202020202020202020202020202020202020202020202020202020202002003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000300a2000000534e5245016401000400010020000000131313131313131313131313131313131313131313131313131313131313131302002000000014141414141414141414141414141414141414141414141414141414141414140300080000000100000000000000040038000000534e52450301010002000100020000000100020020000000151515151515151515151515151515151515151515151515151515151515151504001c010000534e524502630100040001007b000000534e52450152010004000100170000006472303133302d66617374706174682d766563746f7273020002000000010003002000000010101010101010101010101010101010101010101010101010101010101010100400200000001111111111111111111111111111111111111111111111111111111111111111020008000000010000000000000003003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000900000000000000040038000000534e5245030101000200010002000000010002002000000012121212121212121212121212121212121212121212121212121212121212120500e1000000534e524503520100040001007b000000534e52450152010004000100170000006472303133302d66617374706174682d766563746f727302000200000001000300200000001010101010101010101010101010101010101010101010101010101010101010040020000000111111111111111111111111111111111111111111111111111111111111111102000200000002000300020000000100040040000000534e5245025201000300010002000000020002000200000007000300200000003030303030303030303030303030303030303030303030303030303030303030070008000000e803000000000000080008000000220000000000000009000800000001000000000000000a000800000009000000000000000b000800000064000000000000000c0012000000534e52452d640100010001000200000001000d000200000001000e002000000074f85cda34d1c27c4621484731e91579c3d9c6cfc0d94b281aa11e9162058aa90f000800000009000000000000001000080000000900000000000000',
  protocolCustodyOwnerTokenPreimage0x642e: '534e52452e640100040001000e000000637573746f64792d766563746f72020072000000534e5245074001000400010002000000010002000e000000637573746f64792d766563746f7203002000000022222222222222222222222222222222222222222222222222222222222222220400200000003333333333333333333333333333333333333333333333333333333333333333030030000000534e5245014001000100010020000000444444444444444444444444444444444444444444444444444444444444444404000400000000000000',
  bondLifecycleDepositIntent0x642f: '534e52452f640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200200000007272727272727272727272727272727272727272727272727272727272727272030020000000727272727272727272727272727272727272727272727272727272727272727204000200000001000500030000000102030a0038000000534e5245088001000200010002000000070002002000000079797979797979797979797979797979797979797979797979797979797979790b000800000001000000000000000c0038000000534e5245030101000200010002000000010002002000000001010101010101010101010101010101010101010101010101010101010101010d0038000000534e524503010100020001000200000001000200200000000202020202020202020202020202020202020202020202020202020202020202',
  bondLifecycleReplaceIntent0x642f: '534e52452f6401000b0001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200200000007272727272727272727272727272727272727272727272727272727272727272030020000000727272727272727272727272727272727272727272727272727272727272727204000200000002000600020000000405070002000000060708002000000022222222222222222222222222222222222222222222222222222222222222220a0038000000534e5245088001000200010002000000070002002000000079797979797979797979797979797979797979797979797979797979797979790b000800000001000000000000000c0038000000534e5245030101000200010002000000010002002000000001010101010101010101010101010101010101010101010101010101010101010d0038000000534e524503010100020001000200000001000200200000000202020202020202020202020202020202020202020202020202020202020202',
  bondLifecycleUnbondIntent0x642f: '534e52452f640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000072727272727272727272727272727272727272727272727272727272727272720300200000007272727272727272727272727272727272727272727272727272727272727272040002000000030009002000000033333333333333333333333333333333333333333333333333333333333333330a0038000000534e5245088001000200010002000000070002002000000079797979797979797979797979797979797979797979797979797979797979790b000800000001000000000000000c0038000000534e5245030101000200010002000000010002002000000001010101010101010101010101010101010101010101010101010101010101010d0038000000534e524503010100020001000200000001000200200000000202020202020202020202020202020202020202020202020202020202020202',
  bondLifecycleWithdrawIntent0x642f: '534e52452f640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000072727272727272727272727272727272727272727272727272727272727272720300200000007272727272727272727272727272727272727272727272727272727272727272040002000000040005000200000008090a0038000000534e5245088001000200010002000000070002002000000079797979797979797979797979797979797979797979797979797979797979790b000800000001000000000000000c0038000000534e5245030101000200010002000000010002002000000001010101010101010101010101010101010101010101010101010101010101010d0038000000534e524503010100020001000200000001000200200000000202020202020202020202020202020202020202020202020202020202020202',
  bondLifecycleReactivateIntent0x642f: '534e52452f640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200200000007272727272727272727272727272727272727272727272727272727272727272030020000000727272727272727272727272727272727272727272727272727272727272727204000200000005000500030000000a0b0c0a0038000000534e5245088001000200010002000000070002002000000079797979797979797979797979797979797979797979797979797979797979790b000800000001000000000000000c0038000000534e5245030101000200010002000000010002002000000001010101010101010101010101010101010101010101010101010101010101010d0038000000534e524503010100020001000200000001000200200000000202020202020202020202020202020202020202020202020202020202020202',
  signedBondLifecycleIntent0x6430: '534e5245306401000200010074010000534e52452f640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000900000000000000020020000000717171717171717171717171717171717171717171717171717171717171717103002000000072727272727272727272727272727272727272727272727272727272727272720400020000000100050003000000aabbcc0a0038000000534e5245088001000200010002000000070002002000000079797979797979797979797979797979797979797979797979797979797979790b000800000004000000000000000c0038000000534e5245030101000200010002000000010002002000000081818181818181818181818181818181818181818181818181818181818181810d0038000000534e52450301010002000100020000000100020020000000828282828282828282828282828282828282828282828282828282828282828202004000000042424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242',
  fastpathBondTransitionRecord0x6431: '534e524531640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000079797979797979797979797979797979797979797979797979797979797979790300080000000200000000000000040038000000534e524503010100020001000200000001000200200000001111111111111111111111111111111111111111111111111111111111111111050038000000534e5245030101000200010002000000010002002000000012121212121212121212121212121212121212121212121212121212121212120600020000000100070008000000090000000000000008001a000000534e52453364010002000100020000000100020002000000aabb090003000000ccddee',
  fastpathSlashTransitionRecord0x6431: '534e524531640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000079797979797979797979797979797979797979797979797979797979797979790300080000000200000000000000040038000000534e524503010100020001000200000001000200200000001111111111111111111111111111111111111111111111111111111111111111050038000000534e5245030101000200010002000000010002002000000012121212121212121212121212121212121212121212121212121212121212120600020000000600070008000000090000000000000008007f000000534e5245336401000700010002000000020003000200000031320400080000000400000000000000050038000000534e5245030101000200010002000000010002002000000033333333333333333333333333333333333333333333333333333333333333330600030000003435360700020000003738080002000000393a0900020000001414',
  bondTransitionAuthorizationValidatorEnvelope0x6433: '534e52453364010002000100020000000100020003000000212223',
  bondTransitionAuthorizationConsumedEvidence0x6433: '534e5245336401000700010002000000020003000200000031320400080000000400000000000000050038000000534e5245030101000200010002000000010002002000000033333333333333333333333333333333333333333333333333333333333333330600030000003435360700020000003738080002000000393a',
  evidenceConsumptionRecord0x6432: '534e524532640100050001002000000041414141414141414141414141414141414141414141414141414141414141410200080000000300000000000000030038000000534e52450301010002000100020000000100020020000000424242424242424242424242424242424242424242424242424242424242424204000800000005000000000000000500080000000c00000000000000',
  slashIntent0x6434: '534e524534640100080001003c000000534e52450163010003000100140000006472303133372d756e6974332d766563746f727302000400000003000000030008000000090000000000000002002000000051515151515151515151515151515151515151515151515151515151515151510300200000005252525252525252525252525252525252525252525252525252525252525252040038000000534e52450880010002000100020000000700020020000000797979797979797979797979797979797979797979797979797979797979797905000800000003000000000000000600080000000200000000000000070038000000534e524503010100020001000200000001000200200000005353535353535353535353535353535353535353535353535353535353535353080003000000545556',
  feeClaimZeroShareIntent0x6437: '534e5245376401000d0001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200200000009191919191919191919191919191919191919191919191919191919191919191030020000000929292929292929292929292929292929292929292929292929292929292929204000800000009000000000000000500200000009393939393939393939393939393939393939393939393939393939393939393060038000000534e524508800100020001000200000007000200200000007979797979797979797979797979797979797979797979797979797979797979070008000000010000000000000008008c000000534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb090038000000534e5245030101000200010002000000010002002000000081818181818181818181818181818181818181818181818181818181818181810a0038000000534e5245030101000200010002000000010002002000000082828282828282828282828282828282828282828282828282828282828282820b000800000000000000000000000c002000000098989898989898989898989898989898989898989898989898989898989898980d00020000000100',
  feeClaimSplitIntent0x6437: '534e5245376401000e0001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000900000000000000020020000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1030020000000a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a20400080000000900000000000000050020000000a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3060038000000534e524508800100020001000200000007000200200000007979797979797979797979797979797979797979797979797979797979797979070008000000020000000000000008008c000000534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb090038000000534e5245030101000200010002000000010002002000000081818181818181818181818181818181818181818181818181818181818181810a0038000000534e5245030101000200010002000000010002002000000082828282828282828282828282828282828282828282828282828282828282820b00080000002a000000000000000c0020000000a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a80d000200000002000e0003000000010203',
  signedFeeClaimSplitIntent0x6438: '534e524538640100020001006e020000534e5245376401000e0001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000900000000000000020020000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1030020000000a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a20400080000000900000000000000050020000000a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3060038000000534e524508800100020001000200000007000200200000007979797979797979797979797979797979797979797979797979797979797979070008000000020000000000000008008c000000534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb090038000000534e5245030101000200010002000000010002002000000081818181818181818181818181818181818181818181818181818181818181810a0038000000534e5245030101000200010002000000010002002000000082828282828282828282828282828282828282828282828282828282828282820b00080000002a000000000000000c0020000000a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a80d000200000002000e000300000001020302004000000042424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242',
  feeClaimSplitIntentV2_0x6437: '534e5245376402000f0001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000900000000000000020020000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1030020000000a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a20400080000000900000000000000050020000000a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3060038000000534e524508800100020001000200000007000200200000007979797979797979797979797979797979797979797979797979797979797979070008000000020000000000000008008c000000534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb090038000000534e5245030101000200010002000000010002002000000081818181818181818181818181818181818181818181818181818181818181810a0038000000534e5245030101000200010002000000010002002000000082828282828282828282828282828282828282828282828282828282828282820b00080000002a000000000000000c0020000000a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a80d000200000002000e00030000000102030f008c000000534e5245044001000300010030000000534e5245014001000100010020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200080000000300000000000000030038000000534e52450301010002000100020000000100020020000000dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  signedFeeClaimSplitIntentV2_0x6438: '534e5245386402000200010000030000534e5245376402000f0001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000900000000000000020020000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1030020000000a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a20400080000000900000000000000050020000000a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3060038000000534e524508800100020001000200000007000200200000007979797979797979797979797979797979797979797979797979797979797979070008000000020000000000000008008c000000534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb090038000000534e5245030101000200010002000000010002002000000081818181818181818181818181818181818181818181818181818181818181810a0038000000534e5245030101000200010002000000010002002000000082828282828282828282828282828282828282828282828282828282828282820b00080000002a000000000000000c0020000000a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a80d000200000002000e00030000000102030f008c000000534e5245044001000300010030000000534e5245014001000100010020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200080000000300000000000000030038000000534e52450301010002000100020000000100020020000000dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd02004000000042424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242',
};

for (const [name, bytes] of Object.entries(vectors)) {
  const hex = bytes.toString('hex');
  assert.equal(hex, expected[name], `${name} hex mismatch`);
  console.log(JSON.stringify({ name, length: bytes.length, hex }));
}

for (const [name, bytes, length, digest] of [
  ['fastpathEconomicsResourcePolicy0x642b', economicsResourcePolicy, 958,
    '58298611f7b701ed6eb904aa53f17ccd791a04be7723345914013a107cc1b694'],
  ['fastpathEconomicsPolicy0x642c', economicsPolicy, 1046,
    '8307f47937bfb98a84e2fe4d48953ae716647461cb3677caeb703f45db49dbc3'],
]) {
  assert.equal(bytes.length, length, `${name} length mismatch`);
  assert.equal(sha256(bytes).toString('hex'), digest, `${name} digest mismatch`);
  console.log(JSON.stringify({ name, length, sha256: digest }));
}

const commitmentDigestHex = commitmentDigest.toString('hex');
const expectedCommitmentDigestHex = 'daf6fb51270cf45b82aac8b91b8719f50736fefc79e3bc285d149c1d0503a904';
assert.equal(commitmentDigestHex, expectedCommitmentDigestHex, 'fastpathCommitmentEnvelope0x6424 digest mismatch');
console.log(JSON.stringify({
  name: 'fastpathCommitmentEnvelope0x6424Digest',
  length: commitmentDigest.length,
  hex: commitmentDigestHex,
}));
