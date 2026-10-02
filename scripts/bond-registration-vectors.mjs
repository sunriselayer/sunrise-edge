// DR-0179 independent claims, not valid owned legs, executed rows or signatures.
// Every canonical frame is built here without invoking a Rust encoder.
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
const chain = Buffer.from('registration-vector');
const context = frame(0x6301, [[1, chain], [2, uint(1, 4)], [3, uint(2, 8)]]);
const digest = frame(0x0103, [[1, uint(1, 2)], [2, Buffer.alloc(32, 0x22)]]);
const hash = (bytes) => createHash('sha256').update(frame(0x1001, [
  [1, uint(1, 2)], [2, uint(13, 2)], [3, uint(1, 2)],
  [4, chain], [5, uint(1, 4)], [6, bytes],
])).digest();
const intent = frame(0x64e0, [
  [1, context], [2, Buffer.alloc(32, 0x81)], [3, Buffer.alloc(32, 0x33)],
  [4, uint(1, 2)], [5, Buffer.alloc(32, 0x33)], [6, context],
  [7, frame(0x8008, [[1, uint(7, 2)], [2, Buffer.alloc(32, 0x55)]])],
  [8, Buffer.from('leg')], [9, digest], [10, digest],
]);
const signed = frame(0x64e1, [[1, intent], [2, Buffer.alloc(64, 0x44)]]);
const anchor = frame(0x64e2, [[1, context], [2, Buffer.alloc(32, 0x33)], [3, signed], [4, Buffer.from('row')]]);
const signingFrame = frame(0x2001, [
  [1, chain], [2, uint(1, 4)], [3, uint(2, 8)],
  [4, Buffer.from('FastPathBondRegistration')], [5, uint(1, 2)], [6, digest],
]);
const vectors = { intent, signed, anchor, signingFrame };
const expected = {
  intent: [457, '7e900b72018f60f0d29ce17fe6dc672fa91db34d330212b71c0fc64fac2ad373'],
  signed: [543, '1785a078720dc876cd9ad5bae647ae9d40a49e9dfb8eb889840626f4552bf6c3'],
  anchor: [671, 'c5ba25783cb7746b524db970ad71688d688515b4861604f997fa25930e8bf72a'],
  signingFrame: [159, '9f52339bf11b7d3f3f7a0be1690c8ca1adb32600e5d52febf2dd1ade1659b7fc'],
};
assert.deepEqual(Object.keys(vectors), Object.keys(expected));
for (const [name, bytes] of Object.entries(vectors)) {
  assert.equal(bytes.length, expected[name][0], `${name} length differs`);
  assert.equal(hash(bytes).toString('hex'), expected[name][1], `${name} NodeEvent vector differs`);
}
assert.notDeepEqual(intent, signed);
assert.notDeepEqual(signed, anchor);
console.log('initial bond registration independent intent/envelope/anchor/signing-frame vectors match');
