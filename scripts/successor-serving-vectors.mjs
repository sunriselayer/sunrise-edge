// Independent DR-0189 canonical vectors. Synthetic codec claims are NOT a
// verified predecessor, complete import, activation warrant or live authority.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const uint = (value, length) => {
  const bytes = Buffer.alloc(length);
  if (length === 8) bytes.writeBigUInt64LE(BigInt(value));
  else if (length === 4) bytes.writeUInt32LE(value);
  else bytes.writeUInt16LE(value);
  return bytes;
};
const frame = (type, fields, version = 1) => Buffer.concat([
  Buffer.from('SNRE'), uint(type, 2), uint(version, 2), uint(fields.length, 2),
  ...fields.flatMap(([id, bytes]) => [uint(id, 2), uint(bytes.length, 4), bytes]),
]);
const digest = (bytes) => frame(0x0103, [[1, uint(1, 2)], [2, bytes]]);
const chain = Buffer.from('cut-vector');
const chainId = frame(0x0105, [[1, chain]]);
const domain = Buffer.alloc(32, 0x11);
const D = digest(Buffer.alloc(32, 0x22));
const E = digest(Buffer.alloc(32, 0x33));
const context = (epoch) => frame(0x6301, [
  [1, chain], [2, uint(1, 4)], [3, uint(epoch, 8)],
]);
const hash = (purpose, bytes) => createHash('sha256').update(frame(0x1001, [
  [1, uint(1, 2)], [2, uint(purpose, 2)], [3, uint(1, 2)],
  [4, chain], [5, uint(1, 4)], [6, bytes],
])).digest();

// The Seal request's high bit is already set by its original producer.
// This encoder never normalizes a supplied request id into another value.
const request = Buffer.alloc(32, 0x80);
const subject = frame(0xd054, [
  [1, chainId], [2, uint(1, 4)], [3, uint(2, 8)], [4, D],
  [5, domain], [6, D], [7, request], [8, uint(10, 8)], [9, D],
  [10, uint(3, 8)], [11, E], [12, D], [13, D],
]);
const history = frame(0x6490, [
  [1, context(2)], [2, domain], [3, D], [4, D],
  [5, uint(10, 8)], [6, uint(12, 8)], [7, D],
]);
const manifest = frame(0xd055, [
  [1, subject], [2, D], [3, uint(19, 4)], [4, history],
  [5, E], [6, uint(37, 4)], [7, D], [8, E],
]);
const subjectDigest = digest(hash(13, subject));
const manifestDigest = digest(hash(13, manifest));
const anchorPreimage = frame(0x6441, [
  [1, Buffer.from('se/ordered-economics/anchor/v3-successor')],
  [2, context(3)], [3, domain], [4, D], [5, E],
  [6, uint(1, 2)], [7, uint(1024, 4)], [8, uint(10000, 8)],
  [9, uint(4, 8)], [10, subjectDigest],
], 3);
const anchorDigest = digest(hash(5, anchorPreimage));
const bindingAt = (floor) => frame(0x64c0, [
  [1, chainId], [2, uint(1, 4)], [3, uint(2, 8)], [4, domain],
  ...[5, 6, 7, 8, 9].map((id) => [id, D]),
  [10, uint(3, 8)], [11, uint(2, 8)], [12, uint(floor, 8)],
]);
const binding = bindingAt(7);
const genesisFloorBinding = bindingAt(2);
const progress = frame(0x64c1, [[1, uint(5, 8)], [2, E], [3, D]]);
const token = frame(0x64d2, [
  [1, Buffer.from('successor-vector-namespace')], [2, domain],
  [3, uint(17, 8)], [4, uint(41, 8)],
]);
const record = frame(0x64d5, [
  [1, subjectDigest], [2, manifestDigest], [3, binding], [4, progress],
  [5, token], [6, anchorDigest],
  [7, Buffer.alloc(32, 0x44)], [8, Buffer.alloc(32, 0x55)],
]);
const inactive = frame(0x64d6, [[1, uint(1, 2)], [2, Buffer.alloc(0)]]);
const serving = frame(0x64d6, [[1, uint(2, 2)], [2, record]]);
const nodeEventFrames = { subject, manifest, binding, genesisFloorBinding,
  progress, token, record, inactive, serving };
const values = Object.fromEntries(Object.entries(nodeEventFrames).map(([name, bytes]) => [
  name, [bytes.length, hash(13, bytes).toString('hex')],
]));
values.anchorPreimage = [anchorPreimage.length, hash(5, anchorPreimage).toString('hex')];
const expected = {
  subject: [542, 'a7b0e8c259b833400f234ca940e7d9132b3d303ca5b0970185892c369b3e0111'],
  manifest: [1150, '59eba06a21b3cf4af8f75aefe353f317af426b58408931d88d0e9b99f957b38d'],
  binding: [456, '10d26677f6bb5df07aa0f3f69982b69abfba650c1e367ce6491e6a5cae4f0039'],
  genesisFloorBinding: [456, 'a2d6004806b8b94c89e4d99b13793425b2378793906d9c5d1b61c80ee4d3a9fc'],
  progress: [148, '14043d720478cfdafb546ce8f272387d0575516cda993f15fa52db7d849e9a15'],
  token: [108, '36012406cf90974910c47aabedef363d2e46e08f4ad20c5702866b04a0c9fb44'],
  record: [1002, 'aa31fa7457bbb4719d945347f411931bc6fd544a4316b54143fc6582aac25585'],
  inactive: [24, 'aead91b30a178ecade9219318a660dd7e9bc3482ba44cd9faba8ffc8fbc8e8ed'],
  serving: [1026, '24d11cd840a5dca6021903f8c3543b9b29ec70bd3975bef68b83fa8ae2a435e1'],
  anchorPreimage: [382, '00e8bdc94fb69d8bce8af76b45e333aaeb4ab36a928207761079841007ea7b28'],
};
assert.deepEqual(values, expected, 'successor canonical fixed vectors differ');

// Independently encoded byte comparisons do not prove the cryptographic
// eligibility of these synthetic values or actual generation admission.
assert.equal(request[0] & 0x80, 0x80);
assert.notDeepEqual(hash(13, binding), hash(13, genesisFloorBinding));
assert.notDeepEqual(hash(13, anchorPreimage), hash(5, anchorPreimage));
assert.equal(anchorPreimage.subarray(4, 8).toString('hex'), '41640300');
assert.equal(subject.subarray(4, 8).toString('hex'), '54d00100');
assert.equal(manifest.subarray(4, 8).toString('hex'), '55d00100');
assert.equal(inactive.length, 24);
assert(subject.length <= 2048 && manifest.length <= 2048);
assert(record.length <= 16384 && serving.length <= 17408);
console.log('successor serving independent frames, anchor and cut-floor binding vectors match');
