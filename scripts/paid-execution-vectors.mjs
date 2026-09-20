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
const hashFor = (chainBytes, purpose, bytes) => sha256(frame(0x1001, [[1, uint(1, 2)],
  [2, uint(purpose, 2)], [3, uint(1, 2)], [4, chainBytes], [5, uint(3, 4)], [6, bytes]]));
const hash = (purpose, bytes) => hashFor(chain, purpose, bytes);
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
  [15, uint(30000, 8)],
  [16, uint(20000, 8)],
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
  policy: [1213, '5ada415ae7950357bbfaf603e7b45bf17179a5a8310bbb1867b19cd1db10d13d'],
  intent: [1155, 'd4a21596fbb60b11d587e8ba29e8aa3f459b4dfe51b3e79096f06e9339c7773f'],
  signing: [1245, '3fe63168640395db37e4e3f227316a0a9d9d8e0bada7bc7bf507697a6518be32'],
  signed: [1241, '4d74857078fb74d34bfdf87c3856a099a17f8f2871f4b6ce2d24983258ddcff0'],
};
for (const [name, bytes] of Object.entries(vectors)) {
  const actual = [bytes.length, sha256(bytes).toString('hex')];
  assert.deepEqual(actual, expected[name], `vector mismatch: ${name}`);
  console.log(JSON.stringify({ name, length: actual[0], sha256: actual[1] }));
}
assert.equal(policyDigest.toString('hex'), '2acddde1e103821c54753426941cd28f2900823f957a3277858d752a12bb822a'.slice(0, 64));
assert.equal(signature.toString('hex'), '03de053c27d8284359f9dfa4a7377bdeef869b154aa2250d4ef6636e26213df184fb575ae1bb5f1dcc8c9091b05b8e1f125693fbb5c9083a05fb5d1487112708');
assert.equal(invocationDigest.toString('hex'), '922b2e2fc3a335bfd065c6026cbefcb1946879fb1a5752425c3d798a68e74f73');
console.log(JSON.stringify({ policyDigest: policyDigest.toString('hex'), signature: signature.toString('hex') }));
console.log(JSON.stringify({ invocationDigest: invocationDigest.toString('hex') }));

// ---- PaidExecutionResult 0x6415/v1 ----
// Independent reconstruction of the Rust fixture in
// paid_execution_engine/codec.rs. This intentionally rebuilds every nested
// frame instead of importing or decoding the Rust vector.
const resultChain = Buffer.from('paid-execution-engine-test');
const resultContext = frame(0x6301, [[1, resultChain], [2, uint(3, 4)], [3, uint(0, 8)]]);
const resultOrigin = frame(0x5201, [[1, resultChain], [2, uint(1, 2)], [3, sender], [4, Buffer.alloc(32, 1)]]);
const resultDigest = bytes => digest(hashFor(resultChain, 2, bytes)); // HashPurpose::Object
const resultCode = frame(0x6302, [[1, resultOrigin], [2, uint(1, 8)], [3, resultContext], [4, resultDigest(Buffer.from('vector-code'))]]);
const instanceRecord = frame(0x6404, [
  [1, resultContext], [2, sender], [3, Buffer.alloc(32, 3)], [4, resultCode],
  [5, uint(1, 8)], [6, Buffer.from('init')],
]);
const resultObjectId = tag => frame(0x4001, [[1, Buffer.alloc(32, tag)]]);
const resultObjectRef = (tag, version) => frame(0x4004, [
  [1, resultObjectId(tag)], [2, uint(version, 8)], [3, resultDigest(Buffer.from([tag]))],
]);
const emptyObjectEffects = frame(0x6005, [[1, uint(0, 4)]]);
const emptyEvents = frame(0x6006, [[1, uint(0, 4)]]);
const effects = frame(0x6004, [
  [1, resultDigest(Buffer.from('vector-event'))],
  [2, Buffer.from([1])], // ExecutionStatus::Success
  [4, uint(4242, 8)],
  [5, emptyObjectEffects],
  [6, emptyEvents],
]);
const paidResult = frame(0x6415, [
  [1, Buffer.alloc(32, 4)],
  [2, uint(2, 2)], // PaidResultKind::Call
  [3, instanceRecord],
  [4, uint(1, 2)], // PaidExecutionStatus::Success
  [5, uint(500, 8)],
  [6, uint(320, 8)],
  [7, uint(180, 8)],
  [8, resultObjectRef(5, 1)],
  [9, resultObjectRef(6, 1)],
  [10, resultObjectId(7)],
  [11, effects],
  [12, uint(1000, 8)],
]);
const paidResultVector = [paidResult.length, sha256(paidResult).toString('hex')];
assert.deepEqual(paidResultVector, [1101, '88ed340f5e9ee4d79a13b42375a41c1f87f541128447170f98006879c0f851ca'], 'vector mismatch: paidResult');
console.log(JSON.stringify({ name: 'paidResult', length: paidResultVector[0], sha256: paidResultVector[1] }));
