// Independent DR-0148 wire-vector reconstruction for the FastVote apply
// transport pairing `FastVoteApplyRequest` (0x6439). No Rust encoder is
// invoked; this reimplements the shared canonical-frame layout
// (crates/canonical-encoding) from scratch and checks the result against the
// exact hex pinned by the co-located Rust vector in
// crates/node-wire/src/lib.rs.
// Run: node scripts/fastvote-apply-request-vectors.mjs
import assert from 'node:assert/strict';

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const frame = (id, version, fields) => Buffer.concat([
  Buffer.from('SNRE'), u16(id), u16(version), u16(fields.length),
  ...fields.flatMap(([key, value]) => [u16(key), u32(value.length), value]),
]);

const ENCODING_VERSION = 1;
const FASTVOTE_APPLY_REQUEST_TYPE_ID = 0x6439;

const signedPaidIntent = Buffer.alloc(8, 0x11);
const certificate = Buffer.alloc(8, 0x22);

const request = frame(FASTVOTE_APPLY_REQUEST_TYPE_ID, ENCODING_VERSION, [
  [1, signedPaidIntent],
  [2, certificate],
]);

const expected =
  '534e524539640100020001000800000011111111111111110200080000002222222222222222';

const hex = request.toString('hex');
assert.equal(hex, expected, 'fastVoteApplyRequest0x6439 hex mismatch');
console.log(JSON.stringify({ name: 'fastVoteApplyRequest0x6439', length: request.length, hex }));
