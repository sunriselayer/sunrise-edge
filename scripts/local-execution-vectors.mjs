// Independent DR-0122 wire reconstruction. Never invokes a Rust encoder.
import { createHash, createPrivateKey, sign } from 'node:crypto';
import assert from 'node:assert/strict';

const uint = (n, width) => { const bytes = Buffer.alloc(width); let x = BigInt(n);
  for (let i = 0; i < width; i++) { bytes[i] = Number(x & 255n); x >>= 8n; } return bytes; };
const frame = (id, fields, version = 1) => Buffer.concat([
  Buffer.from('SNRE'), uint(id, 2), uint(version, 2), uint(fields.length, 2),
  ...fields.flatMap(([key, value]) => [uint(key, 2), uint(value.length, 4), value]),
]);
const list = (id, items) => frame(id, [[1, uint(items.length, 2)], ...items.map((value, i) => [i + 2, value])]);
const sha256 = bytes => createHash('sha256').update(bytes).digest();
const chain = Buffer.from('local-vector');
const digest = bytes => frame(0x0103, [[1, uint(1, 2)], [2, bytes]]);
const hash = (purpose, bytes) => sha256(frame(0x1001, [[1, uint(1, 2)],
  [2, uint(purpose, 2)], [3, uint(1, 2)], [4, chain], [5, uint(3, 4)], [6, bytes]]));
const publisher = Buffer.from('ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c', 'hex');
const context = frame(0x6301, [[1, chain], [2, uint(3, 4)], [3, uint(0, 8)]]);
const origin = frame(0x5201, [[1, chain], [2, uint(1, 2)], [3, publisher], [4, Buffer.alloc(32, 10)]]);
// Deliberately unverified exact reference; codec vectors do not claim publication.
const code = frame(0x6302, [[1, origin], [2, uint(1, 8)], [3, context], [4, digest(Buffer.alloc(32, 0x66))]]);
const empty = list(0x5308, []);
const constructor = frame(0x5302, [[1, uint(1, 2)], [2, uint(1, 4)], [3, empty]]);
const entry = frame(0x5304, [[1, Buffer.from('run')], [2, empty], [3, empty]]);
const objects = frame(0x5301, [[1, origin], [2, list(0x5308, [constructor])], [3, list(0x5308, [entry])]]);
const emptyTuple = frame(0x5401, [[1, uint(6, 2)], [2, list(0x5402, [])]]);
const u64Layout = frame(0x5401, [[1, uint(2, 2)]]);
const callAbi = frame(0x5405, [[1, objects], [2, list(0x5402, [emptyTuple])], [3, list(0x5402, [u64Layout])]], 2);
const executableAbi = frame(0x5406, [[1, callAbi], [2, Buffer.from('run')], [3, Buffer.concat([uint(1, 2), uint(1, 2)])]]);
const semantics = frame(0x630B, [[1, Buffer.from('local-devnet-typed-host-execution')],
  [2, uint(2, 4)], [3, uint(1, 4)], [4, Buffer.from('wasmi-1.1.0')], [5, uint(1, 4)],
  [6, uint(128, 4)], [7, uint(8192, 4)], [8, uint(128, 4)], [9, uint(1, 4)], [10, uint(67108864, 8)]], 2);
const publicationPolicy = frame(0x630A, [[1, context], [2, digest(hash(4, semantics))],
  [3, uint(1, 2)], [4, uint(33, 4)], [5, uint(16777216, 8)], [6, uint(2, 4)]], 2);
const policy = frame(0x6409, [[1, context], [2, uint(2, 4)], [3, uint(0, 2)],
  [4, uint(1000000, 8)], [5, uint(8, 4)], [6, uint(64, 4)], [7, uint(67108864, 8)],
  [8, uint(16777216, 8)], [9, uint(128, 4)], [10, uint(256, 4)], [11, uint(10, 8)],
  [12, uint(1, 8)], [13, uint(1, 4)], [14, uint(1024, 4)], [15, semantics], [16, uint(2048, 8)]]);
const record = frame(0x6404, [[1, context], [2, publisher], [3, Buffer.alloc(32, 2)],
  [4, code], [5, uint(1, 8)], [6, Buffer.from('run')]]);
const target = frame(0x6401, [[1, publisher], [2, Buffer.alloc(32, 2)], [3, uint(1, 8)], [4, digest(hash(2, record))]]);
const types = list(0x5204, []);
const args = frame(0x5403, [[1, uint(6, 2)], [2, list(0x5404, [])]]);
const access = frame(0x5002, [[1, uint(0, 4)]]);
const call = frame(0x6402, [[1, context], [2, Buffer.alloc(32, 3)], [3, publisher],
  [4, uint(4, 8)], [5, code], [6, target], [7, Buffer.from('run')], [8, types],
  [9, access], [10, args], [11, uint(100000, 8)]]);
const intent = frame(0x6405, [[1, uint(1, 2)], [2, digest(hash(5, policy))], [3, call]]);
const signing = frame(0x2001, [[1, chain], [2, uint(3, 4)], [3, uint(0, 8)],
  [4, Buffer.from('ExecuteLocalContract')], [5, uint(1, 2)], [6, intent]]);
const key = createPrivateKey({key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]), format: 'der', type: 'pkcs8'});
const signature = sign(null, signing, key);
const signed = frame(0x6406, [[1, intent], [2, signature]]);
const eventDigest = hash(13, signed);
const creation = frame(0x640A, [[1, context], [2, context], [3, target], [4, code],
  [5, digest(eventDigest)], [6, uint(0, 4)]]);
const objectId = hash(2, creation);
const tag = frame(0x5203, [[1, origin], [2, uint(1, 2)], [3, uint(0, 2)]]);
const authority = frame(0x6407, [[1, objectId], [2, context], [3, target], [4, code], [5, tag]]);
const effects = (success) => frame(0x6004, [[1, digest(eventDigest)], [2, Buffer.from([success ? 1 : 2])],
  ...success ? [] : [[3, Buffer.from('local contract trapped')]], [4, uint(42, 8)],
  [5, frame(0x6005, [[1, uint(0, 4)]])], [6, frame(0x6006, [[1, uint(0, 4)]])]]);
const result = frame(0x6408, [[1, Buffer.alloc(32, 3)], [2, record], [3, uint(1, 2)], [4, effects(true)]]);
const rejected = frame(0x6408, [[1, Buffer.alloc(32, 3)], [2, record], [3, uint(1, 2)], [4, effects(false)]]);
const vectors = {executableAbi, semantics, publicationPolicy, policy, record, target, intent, signing, signed, creation, authority, result, rejected};
const expected = {
  executableAbi: [478, 'b6e038faaae51d2e955f7c769de0124d48371e0fa3e1858b567fd0add917ae54'],
  semantics: [150, '153a5fd1ce1d960598cd98cbeb64990cc6df8d8415f6e74ae5289ce916019002'],
  publicationPolicy: [172, '54242664e8c2f12d088302dedf6ae1336fce4f1a6bd2566d13cd5666601f5ee3'],
  policy: [386, 'b644dbfe79db0cb61c9b183ab5b3ad23e72861651418c43df804a33f74e51586'],
  record: [435, '87aa76edf3ccb09490d69fcb0fddd781a67944b940f8c4b80c15b8d38e49e252'],
  target: [162, '5a9d72a4556636cfd27e21818f9f4b8fc212fbfa256f9849731c47df6ebbff8b'],
  intent: [801, 'd7e705bbbf4610fa6bd82a702555d6b856e0d120a6c3ccaa56aac0b4a1d5a5c0'],
  signing: [893, '7bc8b9511c3819631f94b8d287e7401dfcaf5e7bf330284e2f1fffcc02268723'],
  signed: [887, 'e7df11bf8073a1309b16ee152777cb3b3289f4789a54019702dfd401eafd3bd0'],
  creation: [634, 'c1fbf452fa39b8e21d7910e4cbb6af8a3b443124932a43b434f19e241a7f4f7f'],
  authority: [692, 'af7bbd49be81eb7195de8cf2b925e48f044b785004eb02505d9c3b400b1dce90'],
  result: [648, '43277aaa01fab2d97cc1ce20ea7d491d20def0516bea3c51c8cdb99a1326add6'],
  rejected: [676, '5e2664f3824ac57fbcca7368f77f1f3ad35ad48ac546fee59a7e7c3f31c30388'],
};
for (const [name, bytes] of Object.entries(vectors)) {
  assert.equal(bytes.length, expected[name][0]);
  assert.equal(sha256(bytes).toString('hex'), expected[name][1]);
  console.log(JSON.stringify({name, length: bytes.length, sha256: sha256(bytes).toString('hex')}));
}
assert.equal(signature.toString('hex'), '137d1b45ca14f261f4a19e36e480b224a6cd59898a40edb5104775557816bb68104f69caffd2cb3f2d188b99c640414436cee07f0258a051aacf84bbcdd1e603');
assert.equal(eventDigest.toString('hex'), '10306f955b32e62bcf94585df4456c67d210873436633828064f650d194e6c71');
assert.equal(objectId.toString('hex'), 'db57cdc4d9903664392b6118ae2c3f418fd239691f5286b4101950e4e622656e');
console.log(JSON.stringify({signature: signature.toString('hex'), eventDigest: eventDigest.toString('hex'), objectId: objectId.toString('hex')}));
assert.equal(hash(13, publicationPolicy).toString('hex'), '4c92b0152c43b3ee7f8269472f0c47bbfc281473198f0617f6f53937303750f1');
