// Independent DR-0130 phase 1 wire-vector reconstruction for every canonical
// frame `crates/node-core/src/local_instance_state.rs`,
// `crates/node-core/src/fast_path/records.rs` and
// `crates/node-core/src/fast_path/commitment.rs` allocate: the fast-path
// object lock (0x641B), prepared record (0x641C), certificate record
// (0x641D), settlement record (0x641E), validator-set record (0x641F), the
// nested object-ref list (0x6420), validator-id list (0x6421),
// validator-entry list (0x6422) and validator-entry (0x6423) frames, the
// staged-commit commitment envelope (0x6424) plus its `HashPurpose::
// ExecutionEffects` digest, and the nonce lock (0x6425). No Rust encoder is
// invoked; this reimplements the shared canonical-frame layout
// (crates/canonical-encoding), the self-describing Digest32 frame (0x0103),
// the PublicationContext frame (0x6301), the ObjectRef/ObjectId frames
// (0x4004/0x4001) and the domain-separated hash frame (0x1001) from
// scratch, and checks the result against the exact hex pinned by the
// co-located Rust vectors in crates/node-core/src/fast_path/tests.rs.
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

// ---- FastPathLockRecord 0x641B/v1 ----
const FASTPATH_LOCK_RECORD_TYPE_ID = 0x641b;
const lockRecord = frame(FASTPATH_LOCK_RECORD_TYPE_ID, [
  [1, Buffer.alloc(32, 0x11)],
  [2, objectRef(0x22, 7, 0x33)],
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
  [8, uint(10, 8)],
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

const vectors = {
  fastpathLockRecord0x641b: lockRecord,
  fastpathNonceLockRecord0x6425: nonceLockRecord,
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
};

const expected = {
  fastpathLockRecord0x641b: '534e52451b6401000200010020000000111111111111111111111111111111111111111111111111111111111111111102008c000000534e5245044001000300010030000000534e524501400100010001002000000022222222222222222222222222222222222222222222222222222222222222220200080000000700000000000000030038000000534e524503010100020001000200000001000200200000003333333333333333333333333333333333333333333333333333333333333333',
  fastpathNonceLockRecord0x6425: '534e52452564010004000100200000004444444444444444444444444444444444444444444444444444444444444444020020000000555555555555555555555555555555555555555555555555555555555555555503000800000009000000000000000400080000002a00000000000000',
  fastpathPreparedRecord0x641c: '534e52451c640100080001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200200000006666666666666666666666666666666666666666666666666666666666666666030038000000534e524503010100020001000200000001000200200000007777777777777777777777777777777777777777777777777777777777777777040038000000534e52450301010002000100020000000100020020000000888888888888888888888888888888888888888888888888888888888888888805000400000099999999060038010000534e52452064010003000100040000000200000002008c000000534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb03008c000000534e5245044001000300010030000000534e5245014001000100010020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200080000000200000000000000030038000000534e52450301010002000100020000000100020020000000dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd07000800000005000000000000000800080000000a00000000000000',
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
};

for (const [name, bytes] of Object.entries(vectors)) {
  const hex = bytes.toString('hex');
  assert.equal(hex, expected[name], `${name} hex mismatch`);
  console.log(JSON.stringify({ name, length: bytes.length, hex }));
}

const commitmentDigestHex = commitmentDigest.toString('hex');
const expectedCommitmentDigestHex = 'daf6fb51270cf45b82aac8b91b8719f50736fefc79e3bc285d149c1d0503a904';
assert.equal(commitmentDigestHex, expectedCommitmentDigestHex, 'fastpathCommitmentEnvelope0x6424 digest mismatch');
console.log(JSON.stringify({
  name: 'fastpathCommitmentEnvelope0x6424Digest',
  length: commitmentDigest.length,
  hex: commitmentDigestHex,
}));
