// Independent DR-0123 wire reconstruction; no Rust encoder is called.
import { createHash, createPrivateKey, sign } from 'node:crypto';
import assert from 'node:assert/strict';

const uint = (n, width) => { const bytes = Buffer.alloc(width); let x = BigInt(n);
  for (let i = 0; i < width; i++) { bytes[i] = Number(x & 255n); x >>= 8n; } return bytes; };
const frame = (id, fields, version = 1) => Buffer.concat([
  Buffer.from('SNRE'), uint(id, 2), uint(version, 2), uint(fields.length, 2),
  ...fields.flatMap(([key, value]) => [uint(key, 2), uint(value.length, 4), value]),
]);
const list = (id, items, width = 4) => frame(id, [[1, uint(items.length, width)],
  ...items.map((value, index) => [index + 2, value])]);
const sha256 = bytes => createHash('sha256').update(bytes).digest();
const chain = Buffer.from('local-vector');
const digest = bytes => frame(0x0103, [[1, uint(1, 2)], [2, bytes]]);
const hash = (purpose, bytes) => sha256(frame(0x1001, [[1, uint(1, 2)],
  [2, uint(purpose, 2)], [3, uint(1, 2)], [4, chain], [5, uint(3, 4)], [6, bytes]]));
const sender = Buffer.from('ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c', 'hex');
const context = frame(0x6301, [[1, chain], [2, uint(3, 4)], [3, uint(0, 8)]]);
const origin = frame(0x5201, [[1, chain], [2, uint(1, 2)], [3, sender], [4, Buffer.alloc(32, 10)]]);
// Codec-only exact references; these vectors do not assert durable publication.
const code = frame(0x6302, [[1, origin], [2, uint(1, 8)], [3, context], [4, digest(Buffer.alloc(32, 0x66))]]);
const record = seed => frame(0x6404, [[1, context], [2, sender], [3, Buffer.alloc(32, seed)],
  [4, code], [5, uint(1, 8)], [6, Buffer.from('run')]]);
const target = seed => frame(0x6401, [[1, sender], [2, Buffer.alloc(32, seed)],
  [3, uint(1, 8)], [4, digest(hash(2, record(seed)))]]);
const caller = frame(0x640B, [[1, target(2)], [2, code]]);
const callee = frame(0x640B, [[1, target(9)], [2, code]]);
const mode = frame(0x4006, [[1, uint(1, 1)]]);
const object = frame(0x640C, [[1, Buffer.alloc(32, 0x44)], [2, mode]]);
const objects = list(0x640D, [object]);
const types = list(0x5204, [], 2);
const authorization = frame(0x640E, [[1, caller], [2, callee], [3, Buffer.from('run')], [4, types], [5, objects]]);
const table = list(0x640F, [authorization]);
const semantics = frame(0x630B, [[1, Buffer.from('local-devnet-general-contract-calls')],
  [2, uint(3, 4)], [3, uint(2, 4)], [4, Buffer.from('wasmi-1.1.0')], [5, uint(1, 4)],
  [6, uint(128, 4)], [7, uint(8192, 4)], [8, uint(128, 4)], [9, uint(2, 4)],
  [10, uint(67108864, 8)], [11, uint(16, 4)], [12, uint(65536, 4)], [13, uint(8, 4)], [14, uint(32, 4)]], 3);
const publicationPolicy = frame(0x630A, [[1, context], [2, digest(hash(4, semantics))],
  [3, uint(1, 2)], [4, uint(33, 4)], [5, uint(16777216, 8)], [6, uint(3, 4)]], 3);
const policy = frame(0x6409, [[1, context], [2, uint(3, 4)], [3, uint(0, 2)],
  [4, uint(1000000, 8)], [5, uint(8, 4)], [6, uint(64, 4)], [7, uint(67108864, 8)],
  [8, uint(16777216, 8)], [9, uint(128, 4)], [10, uint(256, 4)], [11, uint(10, 8)],
  [12, uint(1, 8)], [13, uint(2, 4)], [14, uint(1024, 4)], [15, semantics], [16, uint(2048, 8)],
  [17, uint(16, 4)], [18, uint(65536, 4)], [19, uint(8, 4)], [20, uint(32, 4)],
  [21, uint(33, 4)], [22, uint(16777216, 8)]], 2);
const reference = frame(0x4004, [[1, frame(0x4001, [[1, Buffer.alloc(32, 0x44)]])],
  [2, uint(1, 8)], [3, digest(Buffer.alloc(32, 0x55))]]);
const access = list(0x5002, [frame(0x5001, [[1, reference], [2, mode]])]);
const argumentsBytes = frame(0x5403, [[1, uint(6, 2)], [2, list(0x5404, [], 2)]]);
const call = frame(0x6402, [[1, context], [2, Buffer.alloc(32, 3)], [3, sender],
  [4, uint(4, 8)], [5, code], [6, target(2)], [7, Buffer.from('run')], [8, types],
  [9, access], [10, argumentsBytes], [11, uint(100000, 8)]]);
const intent = frame(0x6405, [[1, uint(2, 2)], [2, digest(hash(5, policy))], [3, call], [4, table]], 2);
const signing = frame(0x2001, [[1, chain], [2, uint(3, 4)], [3, uint(0, 8)],
  [4, Buffer.from('ExecuteLocalContract')], [5, uint(1, 2)], [6, intent]]);
const key = createPrivateKey({key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]), format: 'der', type: 'pkcs8'});
const signature = sign(null, signing, key);
const signed = frame(0x6406, [[1, intent], [2, signature]], 2);
const vectors = {caller, callee, object, objects, authorization, table, semantics, publicationPolicy, policy, intent, signing, signed};
const expected = {
  caller: [446, '9c4c450067f8f8bf1840fcd87120e8c5941b38e41823ba0fb408ed7868e591f4'],
  callee: [446, '167ad6be3ca6c37251b92eab6bc41f1dabb323bb780248d5533a46bffcd87bfb'],
  object: [71, 'c2611cc3b4bb1c5a0750d153bbfe046ba2c237742821e8ce4d301851f1185e41'],
  objects: [97, '2cd3868fcdab0efa75d2a0911c6cbb37d36d61c0a4b10b51c9219328b6a62b02'],
  authorization: [1050, 'deb2369bfc95285f6dc1ffe192c692f6020ccc6e342fd0d3a5698e84bac537fe'],
  table: [1076, '423d1d76bcaf26f048fd1b9baa54a33bd13bf3c293bedd1268df4d0998c36a39'],
  semantics: [192, '7f82b8a972a9ff4e23d5e731fc1c5b9776c77ad7a922ba6f4f7cde1b297502d4'],
  publicationPolicy: [172, '58f4003c412cfaaae09bb6aabc04a10f9fbdba56d10c5220e8e724b4b57f6a5f'],
  policy: [492, 'dba4c439e2cdcbcabd78e211680c9973b458420e69b912c2244ed2c45fc2da5f'],
  intent: [2068, 'febb4c8f79868db1cd7d52fe2f7f3bb63b131b45f8057aef9fc21a7e210f0ea5'],
  signing: [2160, '3c9bb339ab69f8297c386e7804e3290186f7ebc84813582bc6903ba19a8816ad'],
  signed: [2154, '2d0396172ebffb16c683e26e0c4c3c8dc643714cb53281dbddfebe07bfc2d86a'],
};
for (const [name, bytes] of Object.entries(vectors)) {
  const actual = [bytes.length, sha256(bytes).toString('hex')];
  assert.deepEqual(actual, expected[name]);
  console.log(JSON.stringify({name, length: actual[0], sha256: actual[1]}));
}
assert.equal(signature.toString('hex'), '538d0165cd3bea6ec97329f1eeff9196872f31a7875167ef51621d2a4c1b66aaade8f10e1a9807d1c495992673076cd2ef0972a8a2ea955cc9fea99dedd1020e');
assert.equal(hash(13, signed).toString('hex'), 'b25f2975709b03e4c57d096b48b0a7966379f21e8625ed166f74d318be80aeb9');
console.log(JSON.stringify({signature: signature.toString('hex'), eventDigest: hash(13, signed).toString('hex')}));
