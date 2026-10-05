// Independent DR-0191 Section 9 tag-2 (successor predecessor) SealIntent,
// 0xD051 target and 0xD052 request vectors. Same synthetic fixture as
// ordered-seal-vectors.mjs except field 3 = 2 and field 4 = a synthetic
// 0xD054 subject digest. Codec claims only, not a verified chain or Seal.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

const uint = (value, length) => {
  const bytes = Buffer.alloc(length);
  if (length === 8) bytes.writeBigUInt64LE(BigInt(value));
  else if (length === 4) bytes.writeUInt32LE(value);
  else bytes.writeUInt16LE(value);
  return bytes;
};
const frame = (type, fields) => Buffer.concat([
  Buffer.from("SNRE"), uint(type, 2), uint(1, 2), uint(fields.length, 2),
  ...fields.flatMap(([id, bytes]) => [uint(id, 2), uint(bytes.length, 4), bytes]),
]);
const digest = (bytes) => frame(0x0103, [[1, uint(1, 2)], [2, bytes]]);
const D = digest(Buffer.alloc(32, 0x22));
const SUBJECT = digest(Buffer.alloc(32, 0x54)); // synthetic 0xD054 digest
const chain = Buffer.from("cut-vector");
const domain = Buffer.alloc(32, 0x11);
const hash = (purpose, bytes) => createHash("sha256").update(frame(0x1001, [
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
const certificate = Buffer.from("certificate-fixture");
const certificateDigest = hash(6, certificate);
const targetFor = (tag, predecessor) => hash(13, frame(0xd051, [
  [1, digest(hash(13, subject))], [2, uint(tag, 2)], [3, predecessor],
]));
const target = targetFor(2, SUBJECT);
const requestFrame = frame(0xd052, [[1, digest(target)], [2, digest(certificateDigest)]]);
const request = Buffer.from(hash(13, requestFrame));
request[0] |= 0x80;
const intent = frame(0xd050, [
  [1, subject], [2, cut], [3, uint(2, 2)], [4, SUBJECT],
  [5, digest(certificateDigest)], [6, uint(certificate.length, 4)],
]);
const vectors = { intent: hash(13, intent), target, request };
const expected = {
  intent: "8607924ae2c2940610c22e6b0d527179d2950c4ac067e53f050c5f6d3df710eb",
  target: "c5260ad21b48607668afe8d1ac7b1de1575de88f72abb0d61bb3bb716b09a809",
  request: "83b1b959db205a890f26fb00f7016d946b88483fa6310c9fc8ea156192a719fb",
};
assert.deepEqual(Object.keys(vectors), Object.keys(expected));
for (const [name, bytes] of Object.entries(vectors)) {
  assert.equal(bytes.toString("hex"), expected[name], `${name} tag-2 Seal vector differs`);
}
// Tag 1 over the same predecessor bytes commits a different target, and the
// tag-1 fixture target is unchanged.
assert.notDeepEqual(targetFor(1, SUBJECT), target);
assert.equal(targetFor(1, D).toString("hex"),
  "439bdfeb68aec0fb9dd993db769dbd4b610ca46364e00472575b42a0e6250ee7");
assert.equal(request[0] & 0x80, 0x80);
assert.deepEqual(request.subarray(1), hash(13, requestFrame).subarray(1));
console.log("ordered Seal tag-2 successor predecessor independent vectors match");
