// Independent DR-0124 execution-fee consent/policy wire reconstruction.
// Never invokes a Rust encoder; every field layout below is derived only
// from the accepted decision record and canonical-encoding framing rules.
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
const chain = Buffer.from('paid-vector');
const digest = bytes => frame(0x0103, [[1, uint(1, 2)], [2, bytes]]);
const hash = (purpose, bytes) => sha256(frame(0x1001, [[1, uint(1, 2)],
  [2, uint(purpose, 2)], [3, uint(1, 2)], [4, chain], [5, uint(3, 4)], [6, bytes]]));
const sender = Buffer.from('ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c', 'hex');
const context = frame(0x6301, [[1, chain], [2, uint(3, 4)], [3, uint(0, 8)]]);
const origin = seed => frame(0x5201, [[1, chain], [2, uint(1, 2)], [3, sender], [4, Buffer.alloc(32, seed)]]);
// Codec-only exact references; these vectors do not assert durable publication.
const dependency = (org, artifactByte) => frame(0x6302, [[1, org], [2, uint(1, 8)], [3, context], [4, digest(Buffer.alloc(32, artifactByte))]]);
const code = dependency(origin(10), 0x66);
const target = seed => frame(0x6401, [[1, sender], [2, Buffer.alloc(32, seed)],
  [3, uint(1, 8)], [4, digest(Buffer.alloc(32, seed))]]);
const objectRef = (idByte, version) => frame(0x4004, [[1, frame(0x4001, [[1, Buffer.alloc(32, idByte)]])],
  [2, uint(version, 8)], [3, digest(Buffer.alloc(32, idByte))]]);

// ---- FeeSourceConsent 0x6410/v1 ----
const consent = frame(0x6410, [
  [1, objectRef(0x30, 1)],
  [2, uint(1, 2)], // Write
  [3, uint(1000000, 8)],
  [4, sender],
]);

// ---- PaidApplication 0x6411/v1 (Call) ----
const types = list(0x5204, [], 2);
const access = frame(0x5002, [[1, uint(0, 4)]]);
const call = frame(0x6402, [[1, context], [2, Buffer.alloc(32, 1)], [3, sender],
  [4, uint(4, 8)], [5, code], [6, target(2)], [7, Buffer.from('run')], [8, types],
  [9, access], [10, Buffer.alloc(0)], [11, uint(100000, 8)]]);
const application = frame(0x6411, [[1, uint(2, 2)], [2, call]]);

// ---- PaidFeePolicy 0x6414/v1 ----
const policyOrigin = origin(20);
const policyCode = dependency(policyOrigin, 0x88);
const scopedTag = (org, constructor) => frame(0x5203, [[1, org], [2, uint(constructor, 2)], [3, uint(0, 2)]]);
const gasSchedule = frame(0x7005, [[1, uint(10, 8)], [2, uint(1, 8)], [3, uint(0, 8)],
  [4, uint(0, 8)], [5, uint(0, 8)], [6, uint(0, 8)]]);
const policy = frame(0x6414, [
  [1, context],
  [2, digest(Buffer.alloc(32, 0x99))],
  [3, target(9)],
  [4, policyCode],
  [5, Buffer.from('reserve')],
  [6, Buffer.from('reserve_all')],
  [7, Buffer.from('settle')],
  [8, types],
  [9, scopedTag(policyOrigin, 2)],
  [10, scopedTag(policyOrigin, 4)],
  [11, uint(1, 4)],
  [12, sender],
  [13, gasSchedule],
  [14, uint(1, 8)],
  [15, uint(2, 8)],
  [16, uint(5, 8)],
  [17, uint(8, 4)],
  [18, uint(16, 4)],
  [19, uint(4, 4)],
  [20, uint(16, 4)],
  [21, uint(8388608, 8)],
  [22, uint(1048576, 8)],
  [23, uint(1, 8)],
  [24, uint(1, 8)],
]);
const policyDigest = hash(5, policy); // HashPurpose::ProtocolConfig

// ---- PaidIntent 0x6412/v1 (no authorizations field: an empty table is noncanonical) ----
const intent = frame(0x6412, [
  [1, context],
  [2, Buffer.alloc(32, 1)],
  [3, sender],
  [4, uint(4, 8)],
  [5, digest(policyDigest)],
  [6, consent],
  [7, application],
  [8, uint(100000, 8)],
]);

// ---- ExecutePaidContract signature domain and SignedPaidIntent 0x6413/v1 ----
const signing = frame(0x2001, [[1, chain], [2, uint(3, 4)], [3, uint(0, 8)],
  [4, Buffer.from('ExecutePaidContract')], [5, uint(1, 2)], [6, intent]]);
const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]), format: 'der', type: 'pkcs8' });
const signature = sign(null, signing, key);
const signed = frame(0x6413, [[1, intent], [2, signature]]);

// ---- paid_invocation_digest: HashPurpose::NodeEvent over the complete signed frame ----
const invocationDigest = hash(13, signed); // HashPurpose::NodeEvent

const vectors = { consent, application, policy, intent, signing, signed };
const expected = {
  consent: [216, '74cbb9deb656ff15ca9b01e3a8ffef5c22bc5ae428b5d02d854ec5cc41f6cc36'],
  application: [694, '2a748a7be95ae2fc7c785a0333458dc4612988b1f866de09cec774cf32cd852d'],
  policy: [1213, 'b3151c82c41aa7d52e9247671c50908604fbb4a001986be78fb985125886e6fe'],
  intent: [1155, '1c78758ed2677619966a1f44ed29c51aacd3fc4b01f7b9d34f386bce4a3aa167'],
  signing: [1245, '797bca75fab06caddaa60dc5fa52d88a29a422f2027062d0d39310dc5292945b'],
  signed: [1241, '306aa3181233d2bf99a8164dfe85605bb5fd1e21171ca9eabd986876d605661a'],
};
for (const [name, bytes] of Object.entries(vectors)) {
  const actual = [bytes.length, sha256(bytes).toString('hex')];
  assert.deepEqual(actual, expected[name], `vector mismatch: ${name}`);
  console.log(JSON.stringify({ name, length: actual[0], sha256: actual[1] }));
}
assert.equal(policyDigest.toString('hex'), '9fe73f7b612cd628ee580ebbe4a772ac82cbe8bc0bb3d3068f6c212e63428e88'.slice(0, 64));
assert.equal(signature.toString('hex'), '20beb8360e4b54d87d9756a3b9cbf6d05b169849f24310e0f576035e3a47b29944ef7ddf5f796ef1ead202aab706361c1c905b5b281d5167cc1cd0f26d987f0e');
assert.equal(invocationDigest.toString('hex'), '424d67cdbfd6b09978c73f1377f90f632b892bbb1b9f7c2c23be2188d6a68d35');
console.log(JSON.stringify({ policyDigest: policyDigest.toString('hex'), signature: signature.toString('hex') }));
console.log(JSON.stringify({ invocationDigest: invocationDigest.toString('hex') }));
