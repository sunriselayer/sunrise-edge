// Independent DR-0130/DR-0131 wire-vector reconstruction for every canonical
// frame `crates/node-core/src/local_instance_state.rs`,
// `crates/node-core/src/fast_path/records.rs` and
// `crates/node-core/src/fast_path/commitment.rs` allocate: the fast-path
// object lock (0x641B, DR-0131 v1 layout with `locked_epoch`), prepared
// record (0x641C), certificate record (0x641D), settlement record (0x641E),
// validator-set record (0x641F), the nested object-ref list (0x6420),
// validator-id list (0x6421), validator-entry list (0x6422) and
// validator-entry (0x6423) frames, the staged-commit commitment envelope
// (0x6424) plus its `HashPurpose::ExecutionEffects` digest, the nonce lock
// (0x6425), the DR-0131 committed epoch record (0x6426), DR-0132's
// epoch-transition record (0x6427) and activation-set digest preimage
// (0x6428), DR-0133's fastpath equivocation evidence record (0x6429), and
// DR-0137's typed bond lifecycle record (0x642A), signed economics resource
// and policy (0x642B/0x642C), and closed lifecycle state (0x642D). No Rust
// encoder is invoked;
// this reimplements the shared canonical-frame layout
// (crates/canonical-encoding), the self-describing Digest32 frame (0x0103),
// the PublicationContext frame (0x6301), the ObjectRef/ObjectId frames
// (0x4004/0x4001) and the domain-separated hash frame (0x1001) from
// scratch, and checks the result against the exact hex pinned by the
// co-located Rust vectors in crates/node-core/src/fast_path/tests.rs and
// crates/node-core/src/equivocation/tests.rs.
// Run: node scripts/fast-path-vectors.mjs
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

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

// ---- FastPathSettlementRecord 0x641E/v1, nesting the 0x6421 id list ----
const FASTPATH_SETTLEMENT_RECORD_TYPE_ID = 0x641e;
const FASTPATH_ID_LIST_TYPE_ID = 0x6421;
const chargedSignerList = list(FASTPATH_ID_LIST_TYPE_ID, [
  Buffer.alloc(32, 0x05),
  Buffer.alloc(32, 0x06),
]);
const settlementRecordCharged = frame(FASTPATH_SETTLEMENT_RECORD_TYPE_ID, [
  [1, Buffer.alloc(32, 0x01)],
  [2, objectRef(0x02, 3, 0x04)],
  [3, uint(1000, 8)],
  [4, chargedSignerList],
]);
const unchargedSignerList = list(FASTPATH_ID_LIST_TYPE_ID, [Buffer.alloc(32, 0x08)]);
const settlementRecordUncharged = frame(FASTPATH_SETTLEMENT_RECORD_TYPE_ID, [
  [1, Buffer.alloc(32, 0x07)],
  [4, unchargedSignerList],
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
]);

// ---- Signed economics resource/policy 0x642B/v1 and 0x642C/v1 (DR-0137) ----
const bondResourceId = frame(0x8008, [
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
  fastpathIdListCharged0x6421: chargedSignerList,
  fastpathSettlementRecordUncharged0x641e: settlementRecordUncharged,
  fastpathValidatorSetRecord0x641f: validatorSetRecord,
  fastpathValidatorEntryList0x6422: validatorEntryList,
  fastpathValidatorEntry0x6423: firstValidatorEntry,
  fastpathCommitmentEnvelope0x6424: commitmentEnvelope,
  fastpathEquivocationEvidenceRecord0x6429: equivocationEvidenceRecord,
  fastpathBondRecord0x642a: bondRecord,
  fastpathBondStateActive0x642d: bondStateActive,
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
  fastpathSettlementRecordCharged0x641e: '534e52451e6401000400010020000000010101010101010101010101010101010101010101010101010101010101010102008c000000534e5245044001000300010030000000534e524501400100010001002000000002020202020202020202020202020202020202020202020202020202020202020200080000000300000000000000030038000000534e524503010100020001000200000001000200200000000404040404040404040404040404040404040404040404040404040404040404030008000000e803000000000000040060000000534e52452164010003000100040000000200000002002000000005050505050505050505050505050505050505050505050505050505050505050300200000000606060606060606060606060606060606060606060606060606060606060606',
  fastpathIdListCharged0x6421: '534e52452164010003000100040000000200000002002000000005050505050505050505050505050505050505050505050505050505050505050300200000000606060606060606060606060606060606060606060606060606060606060606',
  fastpathSettlementRecordUncharged0x641e: '534e52451e6401000200010020000000070707070707070707070707070707070707070707070707070707070707070704003a000000534e5245216401000200010004000000010000000200200000000808080808080808080808080808080808080808080808080808080808080808',
  fastpathValidatorSetRecord0x641f: '534e52451f640100020001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200be000000534e52452264010003000100040000000200000002004f000000534e524523640100040001002000000011111111111111111111111111111111111111111111111111111111111111110200080000006400000000000000030002000000010004000300000022222203004f000000534e52452364010004000100200000003333333333333333333333333333333333333333333333333333333333333333020008000000c8000000000000000300020000000100040003000000444444',
  fastpathValidatorEntryList0x6422: '534e52452264010003000100040000000200000002004f000000534e524523640100040001002000000011111111111111111111111111111111111111111111111111111111111111110200080000006400000000000000030002000000010004000300000022222203004f000000534e52452364010004000100200000003333333333333333333333333333333333333333333333333333333333333333020008000000c8000000000000000300020000000100040003000000444444',
  fastpathValidatorEntry0x6423: '534e5245236401000400010020000000111111111111111111111111111111111111111111111111111111111111111102000800000064000000000000000300020000000100040003000000222222',
  fastpathCommitmentEnvelope0x6424: '534e5245246401000a00010038000000534e52450301010002000100020000000100020020000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1020004000000a2a2a2a2030004000000000000000400290000000000000100000021b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000500290000000000000100000021b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000060017000000000000010000000f00000003b1b1b10000000000000006070016000000000000010000000e00000003b2b2b20100000002b3b3080004000000a3a3a3a309000800000005000000000000000a0004000000a4a4a4a4',
  fastpathEquivocationEvidenceRecord0x6429: '534e5245296401000200010003000000aabbcc0200080000004200000000000000',
  fastpathBondStateActive0x642d: '534e52452d64010001000100020000000100',
  fastpathBondRecord0x642a: '534e52452a6401000c0001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000016161616161616161616161616161616161616161616161616161616161616160300020000000700040020000000303030303030303030303030303030303030303030303030303030303030303005008c000000534e5245044001000300010030000000534e524501400100010001002000000020202020202020202020202020202020202020202020202020202020202020200200080000000100000000000000030038000000534e524503010100020001000200000001000200200000002121212121212121212121212121212121212121212121212121212121212121060026030000534e5245076401000500010020000000202020202020202020202020202020202020202020202020202020202020202002003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000300a2000000534e5245016401000400010020000000131313131313131313131313131313131313131313131313131313131313131302002000000014141414141414141414141414141414141414141414141414141414141414140300080000000100000000000000040038000000534e52450301010002000100020000000100020020000000151515151515151515151515151515151515151515151515151515151515151504001c010000534e524502630100040001007b000000534e52450152010004000100170000006472303133302d66617374706174682d766563746f7273020002000000010003002000000010101010101010101010101010101010101010101010101010101010101010100400200000001111111111111111111111111111111111111111111111111111111111111111020008000000010000000000000003003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000900000000000000040038000000534e5245030101000200010002000000010002002000000012121212121212121212121212121212121212121212121212121212121212120500e1000000534e524503520100040001007b000000534e52450152010004000100170000006472303133302d66617374706174682d766563746f727302000200000001000300200000001010101010101010101010101010101010101010101010101010101010101010040020000000111111111111111111111111111111111111111111111111111111111111111102000200000002000300020000000100040040000000534e5245025201000300010002000000020002000200000007000300200000003030303030303030303030303030303030303030303030303030303030303030070008000000e803000000000000080008000000220000000000000009000800000001000000000000000a000800000009000000000000000b000800000064000000000000000c0012000000534e52452d64010001000100020000000100',
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
