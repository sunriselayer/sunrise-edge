// Independent canonical-frame reconstruction for the publication-gated
// FastVote HTTP request. No Rust encoder is invoked here.
import assert from 'node:assert/strict';

const u16 = (value) => {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16LE(value);
  return bytes;
};
const u32 = (value) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
};
const frame = (id, version, fields) => Buffer.concat([
  Buffer.from('SNRE'), u16(id), u16(version), u16(fields.length),
  ...fields.flatMap(([field, bytes]) => [u16(field), u32(bytes.length), bytes]),
]);

const request = frame(0xE106, 1, [
  [1, Buffer.alloc(3, 0x11)],
  [2, Buffer.alloc(2, 0x22)],
  [3, Buffer.alloc(4, 0x33)],
]);
const expected =
  '534e524506e101000300010003000000111111020002000000222203000400000033333333';
assert.equal(request.toString('hex'), expected);
console.log(JSON.stringify({
  name: 'fastVotePublishedApplyRequest0xE106',
  length: request.length,
  hex: expected,
}));
