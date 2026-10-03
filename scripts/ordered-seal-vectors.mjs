// Independent DR-0187 closed frame and hash-domain vectors. Synthetic
// codec claims are not a verified cut, readiness quorum or accepted Seal.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const uint = (value, length) => {
  const bytes = Buffer.alloc(length);
  if (length === 8) bytes.writeBigUInt64LE(BigInt(value));
  else if (length === 4) bytes.writeUInt32LE(value);
  else bytes.writeUInt16LE(value);
  return bytes;
};
const frame = (type, fields) => Buffer.concat([
  Buffer.from('SNRE'), uint(type, 2), uint(1, 2), uint(fields.length, 2),
  ...fields.flatMap(([id, bytes]) => [uint(id, 2), uint(bytes.length, 4), bytes]),
]);
const digest = (bytes) => frame(0x0103, [[1, uint(1, 2)], [2, bytes]]);
const D = digest(Buffer.alloc(32, 0x22));
const chain = Buffer.from('cut-vector');
const domain = Buffer.alloc(32, 0x11);
const hash = (purpose, bytes) => createHash('sha256').update(frame(0x1001, [
  [1, uint(1, 2)], [2, uint(purpose, 2)], [3, uint(1, 2)],
  [4, chain], [5, uint(1, 4)], [6, bytes],
])).digest();
const context = frame(0x6301, [[1, chain], [2, uint(1, 4)], [3, uint(2, 8)]]);
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
const cut = frame(0x64b0, [
  [1, context], [2, domain], [3, D], [4, D], [5, history],
  [6, Buffer.alloc(32, 0x80)], [7, uint(4, 8)], [8, D], [9, union],
  [10, uint(7, 8)], ...[1, 2, 3, 4, 6].map((kind, index) => [11 + index, root(kind)]),
]);
const suite = frame(0x0104, [1, 2, 3, 4, 5, 6, 7].map((id) => [id, uint(1, 2)]));
const schedule = frame(0xc003, [[1, uint(1, 2)], [2, frame(0xc002, [
  [1, frame(0x0107, [[1, uint(0, 8)]])], [2, suite],
])]]);
const subject = frame(0xd040, [
  [1, frame(0x0105, [[1, chain]])], [2, uint(1, 4)], [3, uint(2, 8)],
  [4, D], [5, domain], [6, D], [7, digest(hash(13, cut))],
  [8, uint(3, 8)], [9, D], [10, digest(hash(13, schedule))],
]);
const certificate = Buffer.from('certificate-fixture');
const certificateDigest = hash(6, certificate); // Certificate, not NodeEvent.
const targetFrame = frame(0xd051, [
  [1, digest(hash(13, subject))], [2, uint(1, 2)], [3, D],
]);
const target = hash(13, targetFrame);
const requestFrame = frame(0xd052, [[1, digest(target)], [2, digest(certificateDigest)]]);
const request = Buffer.from(hash(13, requestFrame));
request[0] |= 0x80;
const intent = frame(0xd050, [
  [1, subject], [2, cut], [3, uint(1, 2)], [4, D],
  [5, digest(certificateDigest)], [6, uint(certificate.length, 4)],
]);
const outcome = frame(0xd053, [
  [1, digest(target)], [2, request], [3, uint(10, 8)], [4, D],
]);
const sealedRecord = frame(0x64d4, [
  [1, uint(2, 8)], [2, request], [3, uint(10, 8)],
  [4, D], [5, digest(target)], [6, uint(1, 2)],
]);
const unsealed = frame(0x64d3, [[1, uint(1, 2)], [2, Buffer.alloc(0)]]);
const sealed = frame(0x64d3, [[1, uint(2, 2)], [2, sealedRecord]]);
const vectors = { intent: hash(13, intent), target, request, outcome: hash(13, outcome),
  certificateDigest, sealedRecord: hash(13, sealedRecord),
  unsealed: hash(13, unsealed), sealed: hash(13, sealed) };
const expected = {
  intent: 'e47c09063bd15e8d87e7dc4158dc5714aa915d1f9ea29b9a8688fae6509589bd',
  target: '439bdfeb68aec0fb9dd993db769dbd4b610ca46364e00472575b42a0e6250ee7',
  request: 'c9e8068fc0020717b6f3a73251a3b3f62a393f604b992dea4d5c2779f53feb04',
  outcome: '4920c814adabaa25b6e108d024241422a05690569275f6d8a347f9fc50686cad',
  certificateDigest: '1bf62e49f63071b9ebfdb8ef9f73e0d92b775c9d9a5325c8d6614fb463018631',
  sealedRecord: '9f7eeacfdf2bcc8c90c7b66e4f30fac7f59b742d27af054087ec4e78ee4e8281',
  unsealed: '307838011aaba8fd31736b15dfe0bb1e33a8f017e9cfd678273a151594d77ca7',
  sealed: '6c56af402d180bd3e6ed3313ddb10e2c705aebd128ca24e786930a76c7ed82b8',
};
assert.deepEqual(Object.keys(vectors), Object.keys(expected));
for (const [name, bytes] of Object.entries(vectors)) {
  assert.equal(bytes.toString('hex'), expected[name], `${name} Seal vector differs`);
}
assert.equal(hash(13, cut).toString('hex'), 'd98a4e4f181632fa7de62b12e69c20e3b2eeb3fa01bc151ed6c92dfac15f194f');
assert.notDeepEqual(certificateDigest, hash(13, certificate));
assert.equal(request[0] & 0x80, 0x80);
assert.deepEqual(request.subarray(1), hash(13, requestFrame).subarray(1));
const variant = hash(6, Buffer.from('certificate-variant'));
const variantRequest = hash(13, frame(0xd052, [[1, digest(target)], [2, digest(variant)]]));
variantRequest[0] |= 0x80;
assert.notDeepEqual(request, variantRequest);
console.log('ordered Seal independent frames, certificate domain and forced request bit vectors match');
