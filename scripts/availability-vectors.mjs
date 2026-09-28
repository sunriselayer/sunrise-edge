// Independent DR-0154 wire-vector reconstruction for the AvailabilityIdentity
// (0xD030), AvailabilityVote (0xD031), and AvailabilityCertificate (0xD032)
// canonical frames. No Rust encoder is invoked; this reimplements the shared
// canonical-frame layout (crates/canonical-encoding) and the
// self-describing Digest32 frame (0x0103) from scratch, from the source
// field values in crates/consensus/src/availability.rs, and checks the
// result against the exact hex/byte vectors pinned by the co-located Rust
// tests `availability_identity_encoding_vector_0xd030_is_stable`,
// `availability_vote_encoding_vector_0xd031_is_stable`, and
// `availability_certificate_encoding_vector_0xd032_is_stable`.
// Run: node scripts/availability-vectors.mjs
import assert from 'node:assert/strict';

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const frame = (id, version, fields) => Buffer.concat([
  Buffer.from('SNRE'), u16(id), u16(version), u16(fields.length),
  ...fields.flatMap(([key, value]) => [u16(key), u32(value.length), value]),
]);

const ENCODING_VERSION = 1;
const AVAILABILITY_IDENTITY_TYPE_ID = 0xd030;
const AVAILABILITY_VOTE_TYPE_ID = 0xd031;
const AVAILABILITY_CERTIFICATE_TYPE_ID = 0xd032;
const DIGEST32_TYPE_ID = 0x0103;
const SHA2_256_ALGORITHM_ID = 1;
const ED25519_SCHEME_ID = 1;

const digest32 = (byte) => frame(DIGEST32_TYPE_ID, 1, [
  [1, u16(SHA2_256_ALGORITHM_ID)],
  [2, Buffer.alloc(32, byte)],
]);

// `vector_identity()` in crates/consensus/src/availability.rs.
const CHAIN_ID = 'dr0154-vectors';
const PROTOCOL_VERSION = 3;
const EPOCH = 9;
const DOMAIN = Buffer.alloc(32, 0x44);
const REQUEST_ID = Buffer.alloc(32, 0x55);
const SIGNED_INTENT_DIGEST = digest32(0xaa);
const EXECUTION_COMMITMENT = digest32(0xbb);
const SEMANTIC_ARTIFACTS_DIGEST = digest32(0xcc);

const availabilityIdentity = () => frame(AVAILABILITY_IDENTITY_TYPE_ID, ENCODING_VERSION, [
  [1, Buffer.from(CHAIN_ID)],
  [2, u32(PROTOCOL_VERSION)],
  [3, u64(EPOCH)],
  [4, DOMAIN],
  [5, REQUEST_ID],
  [6, SIGNED_INTENT_DIGEST],
  [7, EXECUTION_COMMITMENT],
  [8, SEMANTIC_ARTIFACTS_DIGEST],
]);

// `vector_vote()`: validator all-0x01, Ed25519 scheme, signature all-0x5A.
const availabilityVote = (validatorByte, signatureByte) => frame(AVAILABILITY_VOTE_TYPE_ID, ENCODING_VERSION, [
  [1, availabilityIdentity()],
  [2, Buffer.alloc(32, validatorByte)],
  [3, u16(ED25519_SCHEME_ID)],
  [4, Buffer.alloc(64, signatureByte)],
]);

const voteA = availabilityVote(0x01, 0x5a);
const voteB = availabilityVote(0x02, 0x7c);

// `availability_certificate_encoding_vector_0xd032_is_stable`: identity plus
// vote_a and vote_b in validator order.
const availabilityCertificate = frame(AVAILABILITY_CERTIFICATE_TYPE_ID, ENCODING_VERSION, [
  [1, availabilityIdentity()],
  [2, u32(2)],
  [3, voteA],
  [4, voteB],
]);

const vectors = {
  availabilityIdentity0xd030: availabilityIdentity(),
  availabilityVote0xd031: voteA,
  availabilityCertificate0xd032: availabilityCertificate,
};

const expected = {
  availabilityIdentity0xd030: '534e524530d00100080001000e0000006472303135342d766563746f727302000400000003000000030008000000090000000000000004002000000044444444444444444444444444444444444444444444444444444444444444440500200000005555555555555555555555555555555555555555555555555555555555555555060038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa070038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb080038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  availabilityVote0xd031: '534e524531d00100040001003c010000534e524530d00100080001000e0000006472303135342d766563746f727302000400000003000000030008000000090000000000000004002000000044444444444444444444444444444444444444444444444444444444444444440500200000005555555555555555555555555555555555555555555555555555555555555555060038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa070038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb080038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc020020000000010101010101010101010101010101010101010101010101010101010101010103000200000001000400400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a',
  availabilityCertificate0xd032: '534e524532d00100040001003c010000534e524530d00100080001000e0000006472303135342d766563746f727302000400000003000000030008000000090000000000000004002000000044444444444444444444444444444444444444444444444444444444444444440500200000005555555555555555555555555555555555555555555555555555555555555555060038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa070038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb080038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc020004000000020000000300c0010000534e524531d00100040001003c010000534e524530d00100080001000e0000006472303135342d766563746f727302000400000003000000030008000000090000000000000004002000000044444444444444444444444444444444444444444444444444444444444444440500200000005555555555555555555555555555555555555555555555555555555555555555060038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa070038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb080038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc020020000000010101010101010101010101010101010101010101010101010101010101010103000200000001000400400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0400c0010000534e524531d00100040001003c010000534e524530d00100080001000e0000006472303135342d766563746f727302000400000003000000030008000000090000000000000004002000000044444444444444444444444444444444444444444444444444444444444444440500200000005555555555555555555555555555555555555555555555555555555555555555060038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa070038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb080038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc020020000000020202020202020202020202020202020202020202020202020202020202020203000200000001000400400000007c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c',
};

for (const [name, bytes] of Object.entries(vectors)) {
  const hex = bytes.toString('hex');
  assert.equal(hex, expected[name], `${name} hex mismatch`);
  console.log(JSON.stringify({ name, length: bytes.length, hex }));
}
