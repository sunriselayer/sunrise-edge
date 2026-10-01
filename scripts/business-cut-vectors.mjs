// Independent DR-0175 canonical wire and NodeEvent digest reconstruction.
// No Rust encoder, source database, supplied completion flag or signer is used.
// These synthetic frames exercise codec claims, not a verified cut capability.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const uint = (value, length) => {
  const bytes = Buffer.alloc(length);
  if (length === 8) bytes.writeBigUInt64LE(BigInt(value));
  else if (length === 4) bytes.writeUInt32LE(value);
  else bytes.writeUInt16LE(value);
  return bytes;
};
const frame = (id, fields) => Buffer.concat([
  Buffer.from('SNRE'), uint(id, 2), uint(1, 2), uint(fields.length, 2),
  ...fields.flatMap(([field, bytes]) => [uint(field, 2), uint(bytes.length, 4), bytes]),
]);
const digest = (bytes) => frame(0x0103, [[1, uint(1, 2)], [2, bytes]]);
const D = digest(Buffer.alloc(32, 0x22));
const chain = Buffer.from('cut-vector');
const domain = Buffer.alloc(32, 0x11);
const context = frame(0x6301, [[1, chain], [2, uint(1, 4)], [3, uint(2, 8)]]);
const hash = (bytes) => createHash('sha256').update(frame(0x1001, [
  [1, uint(1, 2)], [2, uint(13, 2)], [3, uint(1, 2)],
  [4, chain], [5, uint(1, 4)], [6, bytes],
])).digest();
const history = frame(0x6490, [
  [1, context], [2, domain], [3, D], [4, D],
  [5, uint(9, 8)], [6, uint(11, 8)], [7, D],
]);
const union = frame(0xd03b, [
  [1, chain], [2, uint(1, 4)], [3, uint(2, 8)], [4, domain],
  [5, Buffer.alloc(32, 0x81)], [6, uint(1, 8)],
  [7, uint(3, 8)], [8, uint(0, 8)], [9, D],
]);
const root = (kind) => frame(0x64b1, [[1, uint(kind, 2)], [2, uint(0, 8)], [3, D]]);
const identity = frame(0x64b0, [
  [1, context], [2, domain], [3, D], [4, D], [5, history],
  [6, Buffer.alloc(32, 0x80)], [7, uint(4, 8)], [8, D], [9, union],
  [10, uint(7, 8)], ...[1, 2, 3, 4, 6].map((kind, index) => [11 + index, root(kind)]),
]);
const packageIdentity = frame(0x64b2, [
  [1, D], [2, uint(0, 8)], [3, D],
  ...[1, 2, 3, 4, 5, 6, 7].map((kind, index) => [4 + index, root(kind)]),
]);
const metadata = frame(0x64b9, [[1, uint(1, 2)], [2, uint(1, 2)]]);
const descriptor = frame(0x64b3, [
  [1, uint(1, 2)], [2, Buffer.from('k')], [3, metadata], [4, uint(3, 8)], [5, D],
]);
const page = frame(0x64b4, [
  [1, D], [2, D], [3, uint(1, 2)], [4, Buffer.alloc(0)], [5, D], [6, D],
  [7, uint(1, 2)], [8, uint(1, 2)], [9, descriptor],
]);
const chunk = frame(0x64b5, [
  [1, D], [2, D], [3, descriptor], [4, uint(0, 8)], [5, uint(3, 8)], [6, Buffer.from('abc')],
]);
const streamSeed = frame(0x64b6, [
  [1, context], [2, D], [3, domain], [4, uint(1, 2)], [5, Buffer.alloc(0)],
]);
const packageSeed = frame(0x64b6, [
  [1, context], [2, D], [3, domain], [4, uint(8, 2)], [5, D],
]);
const fold = frame(0x64b7, [[1, D], [2, descriptor]]);

// Fixed digest segmentation is NOT the caller's transfer chunk size. Every
// canonical digest frame stays bounded even for a legal 32 MiB component.
const componentDigest = (body) => {
  let accumulator = hash(frame(0x64bc, [[1, uint(body.length, 8)]]));
  for (let offset = 0; offset < body.length; offset += 1_048_576) {
    accumulator = hash(frame(0x64bb, [
      [1, digest(accumulator)], [2, uint(offset, 8)],
      [3, body.subarray(offset, Math.min(body.length, offset + 1_048_576))],
    ]));
  }
  return accumulator;
};
const vectors = {
  identity: hash(identity), package: hash(packageIdentity), descriptor: hash(descriptor),
  page: hash(page), chunk: hash(chunk), streamSeed: hash(streamSeed),
  packageSeed: hash(packageSeed), fold: hash(fold),
  emptyBody: componentDigest(Buffer.alloc(0)), abcBody: componentDigest(Buffer.from('abc')),
  twoRangeBody: componentDigest(Buffer.concat([Buffer.alloc(1_048_576, 0x31), Buffer.from('abc')])),
};
const expected = {
  identity: 'd98a4e4f181632fa7de62b12e69c20e3b2eeb3fa01bc151ed6c92dfac15f194f',
  package: '4e63e573084c1f570e75746cf8c119978c0a7c595a4d433c62b0b488c6f359f1',
  descriptor: 'a7e5613295ddbeda9d88b6993e63682162030cf070fe6c3a94722f7ad79ba197',
  page: '1ffcc4060c2ff8abc5d00890f473b4b41bd554ac6645f1dfd085f34fe97e4a77',
  chunk: 'ab2f5d750793a3f37cd4636b07a9d966dd2cae141bd2d714e66078394feca46d',
  streamSeed: '1049f70d333c8c572d8eb676100dd0f771931489ac892f1b3195b3695a2ca683',
  packageSeed: 'e7229e03a0c7e55c282aa2d0d62126a930b29f4607979915f18d5ad54721827d',
  fold: 'b5262c3e5f8050bf0b317e814a3885104b5066b70d8e55e5e5c42b057b472d22',
  emptyBody: 'e449fe52d46ba214503082ac5c92bb9d0c41b7c532172f7397a07a4080118bbb',
  abcBody: '32706e7347881d30903f439367789fe8aeec251c232585231911faa0fa8a5916',
  twoRangeBody: '459a27dadfc8151a27c4609aff40885c0d9024fa2ec1875339f078b3a586eb47',
};
assert.deepEqual(Object.keys(vectors), Object.keys(expected));
for (const [name, bytes] of Object.entries(vectors)) {
  assert.equal(bytes.toString('hex'), expected[name], `${name} NodeEvent vector differs`);
}
assert.equal(identity.subarray(4, 8).toString('hex'), 'b0640100');
assert.equal(descriptor.toString('hex'), '534e5245b3640100050001000200000001000200010000006b03001a000000534e5245b96401000200010002000000010002000200000001000400080000000300000000000000050038000000534e524503010100020001000200000001000200200000002222222222222222222222222222222222222222222222222222222222222222');
console.log('business cut independent wire and fixed-range NodeEvent vectors match');
