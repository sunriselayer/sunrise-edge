// Independent DR-0178 public frames and real Ed25519 signing. These assertions
// do not construct a verified import, retained vote or activation authority.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

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
const chain = Buffer.from('readiness-test');
const hash = (purpose, payload) => createHash('sha256').update(frame(0x1001, [
  [1, uint(1, 2)], [2, uint(purpose, 2)], [3, uint(1, 2)],
  [4, chain], [5, uint(1, 4)], [6, payload],
])).digest();
const privateKeys = [1, 2, 3, 4].map((seed) => createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed)]),
  format: 'der', type: 'pkcs8',
}));
const publicKeys = privateKeys.map((key) => createPublicKey(key));
const powers = [4, 3, 2, 1];
const members = publicKeys.map((key, index) => frame(0xc001, [
  [1, Buffer.alloc(32, index + 1)], [2, uint(powers[index], 8)], [3, uint(1, 2)],
  [4, key.export({ format: 'der', type: 'spki' }).subarray(-32)],
]));
const set = frame(0xc002, [[1, uint(1, 8)], [2, uint(10, 8)], [3, uint(7, 8)], [4, uint(4, 4)],
  ...members.map((member, index) => [index + 5, member]),
]);
const suite = frame(0x0104, [1, 2, 3, 4, 5, 6, 7].map((id) => [id, uint(1, 2)]));
const schedule = frame(0xc003, [[1, uint(1, 2)], [2, frame(0xc002, [
  [1, frame(0x0107, [[1, uint(0, 8)]])], [2, suite],
])]]);
const subject = frame(0xd040, [
  [1, frame(0x0105, [[1, chain]])], [2, uint(1, 4)], [3, uint(0, 8)],
  [4, digest(Buffer.alloc(32, 1))], [5, Buffer.alloc(32, 2)],
  [6, digest(Buffer.alloc(32, 3))], [7, digest(Buffer.alloc(32, 4))], [8, uint(1, 8)],
  [9, digest(hash(7, set))], [10, digest(hash(13, schedule))],
]);
const payload = (index) => frame(0xd041, [[1, subject], [2, Buffer.alloc(32, index + 1)], [3, uint(1, 2)]]);
const signingFrame = (index) => frame(0x2001, [
  [1, chain], [2, uint(1, 4)], [3, uint(0, 8)], [4, Buffer.from('conditional-readiness-v1')],
  [5, uint(1, 2)], [6, payload(index)],
]);
const signatures = privateKeys.map((key, index) => sign(null, signingFrame(index), key));
const vote = (index) => frame(0xd042, [[1, payload(index)], [2, signatures[index]]]);
const certificate = frame(0xd043, [[1, subject], [2, set], [3, uint(2, 2)], [4, vote(0)], [5, vote(1)]]);
const values = { set, schedule, subject, payload: payload(0), signingFrame: signingFrame(0), vote: vote(0), certificate };
const expected = {
  set: [518, '0e90e92d746595038b79b9014de8003604214eb8f391bb47bb34d150ca1b3255'],
  schedule: [136, '0a1acc2fce007f2eede28425ab7cfe1814effc36c3409c51509a7460b0ead1b5'],
  subject: [432, '8982f691753399ceba797b16f5ab61cc908860288f849e4e864afaabd6c51673'],
  payload: [494, 'd273b0602f3a75d2850ca242d926d593ac1c508557224549873ffa37accb4403'],
  signingFrame: [592, 'e662a49c2442d69fe0a1f86bbbfb47fab4259493d3e2b156bbab877e1511c290'],
  vote: [580, 'd19fa1243f0c31ec85f4b7b9bec85bec6119d1db46fe8144c61632b2da3ebf96'],
  certificate: [2152, '04988eaa27cef657ccec52fdbeef8f17c5bc96c6aa6f3d33ea132ee6a53c08e8'],
};
assert.deepEqual(Object.keys(values), Object.keys(expected));
for (const [name, bytes] of Object.entries(values)) {
  assert.equal(bytes.length, expected[name][0], `${name} length differs`);
  assert.equal(hash(13, bytes).toString('hex'), expected[name][1], `${name} NodeEvent vector differs`);
}
assert.equal(signatures[0].toString('hex'), '939052d6dcc41cd4a7cb424f471ac38ce8ed54964f2bb2a4d2e18d20df5b45fa6db0388cdaad4ea67f3dd889f620abff0cc5cbda3c43fdf6c031106850821305');
assert(verify(null, signingFrame(0), publicKeys[0], signatures[0]));
assert(!verify(null, signingFrame(1), publicKeys[0], signatures[0]));
assert.equal(powers[0] + powers[1], 7);
assert.equal(powers[1] + powers[2] + powers[3], 6);
console.log('conditional readiness independent frames, schedule and real signature vectors match');
