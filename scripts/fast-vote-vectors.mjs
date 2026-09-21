// Independent DR-0129 phase 0 wire-vector reconstruction for the FastVote
// payload (0xD006), FastVote (0xD007), and FastCertificate (0xD008)
// canonical frames. No Rust encoder is invoked; this reimplements the
// shared canonical-frame layout (crates/canonical-encoding) and the
// self-describing Digest32 frame (0x0103) from scratch and checks the
// result against the exact hex pinned by the co-located Rust vectors in
// crates/consensus/src/fast_vote.rs.
// Run: node scripts/fast-vote-vectors.mjs
import assert from 'node:assert/strict';

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const frame = (id, version, fields) => Buffer.concat([
  Buffer.from('SNRE'), u16(id), u16(version), u16(fields.length),
  ...fields.flatMap(([key, value]) => [u16(key), u32(value.length), value]),
]);

const ENCODING_VERSION = 1;
const FAST_VOTE_PAYLOAD_TYPE_ID = 0xd006;
const FAST_VOTE_TYPE_ID = 0xd007;
const FAST_CERTIFICATE_TYPE_ID = 0xd008;
const DIGEST32_TYPE_ID = 0x0103;
const SHA2_256_ALGORITHM_ID = 1;
const ED25519_SCHEME_ID = 1;

const digest32 = (byte) => frame(DIGEST32_TYPE_ID, 1, [
  [1, u16(SHA2_256_ALGORITHM_ID)],
  [2, Buffer.alloc(32, byte)],
]);

const CHAIN_ID = 'dr0129-vectors';
const PROTOCOL_VERSION = 3;
const EPOCH = 9;
const TX_HASH = digest32(0xaa);
const EFFECTS_HASH = digest32(0xbb);

const fastVotePayload = (validatorByte) => frame(FAST_VOTE_PAYLOAD_TYPE_ID, ENCODING_VERSION, [
  [1, Buffer.from(CHAIN_ID)],
  [2, u32(PROTOCOL_VERSION)],
  [3, u64(EPOCH)],
  [4, TX_HASH],
  [5, EFFECTS_HASH],
  [6, Buffer.alloc(32, validatorByte)],
  [7, u16(ED25519_SCHEME_ID)],
]);

const fastVote = (validatorByte, signatureByte) => frame(FAST_VOTE_TYPE_ID, ENCODING_VERSION, [
  [1, fastVotePayload(validatorByte)],
  [2, Buffer.alloc(64, signatureByte)],
]);

const voteA = fastVote(0x01, 0x5a);
const voteB = fastVote(0x02, 0x7c);
const fastCertificate = frame(FAST_CERTIFICATE_TYPE_ID, ENCODING_VERSION, [
  [1, Buffer.from(CHAIN_ID)],
  [2, u32(PROTOCOL_VERSION)],
  [3, u64(EPOCH)],
  [4, TX_HASH],
  [5, EFFECTS_HASH],
  [6, u32(2)],
  [7, voteA],
  [8, voteB],
]);

const vectors = {
  fastVotePayload0xd006: fastVotePayload(0x01),
  fastVote0xd007: voteA,
  fastCertificate0xd008: fastCertificate,
};

const expected = {
  fastVotePayload0xd006: '534e524506d00100070001000e0000006472303132392d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa050038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb06002000000001010101010101010101010101010101010101010101010101010101010101010700020000000100',
  fastVote0xd007: '534e524507d0010002000100e0000000534e524506d00100070001000e0000006472303132392d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa050038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb060020000000010101010101010101010101010101010101010101010101010101010101010107000200000001000200400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a',
  fastCertificate0xd008: '534e524508d00100080001000e0000006472303132392d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa050038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb06000400000002000000070036010000534e524507d0010002000100e0000000534e524506d00100070001000e0000006472303132392d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa050038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb060020000000010101010101010101010101010101010101010101010101010101010101010107000200000001000200400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a080036010000534e524507d0010002000100e0000000534e524506d00100070001000e0000006472303132392d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa050038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb060020000000020202020202020202020202020202020202020202020202020202020202020207000200000001000200400000007c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c',
};

for (const [name, bytes] of Object.entries(vectors)) {
  const hex = bytes.toString('hex');
  assert.equal(hex, expected[name], `${name} hex mismatch`);
  console.log(JSON.stringify({ name, length: bytes.length, hex }));
}
