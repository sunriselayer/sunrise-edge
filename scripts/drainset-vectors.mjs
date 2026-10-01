// Independent reconstruction; never calls the Rust encoders. Fixtures mirror
// consensus::availability::union's frozen vectors and public locator frames.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const frame = (id, fields) => Buffer.concat([
  Buffer.from('SNRE'), u16(id), u16(1), u16(fields.length),
  ...fields.flatMap(([field, value]) => [u16(field), u32(value.length), value]),
]);
const digest32 = (value) => frame(0x0103, [[1, u16(1)], [2, value]]);
const chain = Buffer.from('union-test');
const domain = Buffer.alloc(32, 9);
const freeze = Buffer.alloc(32, 7);
const hash = (payload) => createHash('sha256').update(frame(0x1001, [
  [1, u16(1)], [2, u16(3)], [3, u16(1)], [4, chain], [5, u32(4)], [6, payload],
])).digest();
const frontier = (byte) => frame(0xd036, [
  [1, chain], [2, u32(4)], [3, u64(8)], [4, domain], [5, freeze],
  [6, u64(11)], [7, u64(byte)], [8, digest32(Buffer.alloc(32, byte))],
]);
const selected = [1, 2, 3];
const seed = frame(0xd03a, [
  [1, u16(0)], [2, chain], [3, u32(4)], [4, u64(8)], [5, domain],
  [6, freeze], [7, u64(11)], [8, u64(3)],
  ...selected.flatMap((byte, index) => [
    [9 + 2 * index, Buffer.alloc(32, byte)], [10 + 2 * index, frontier(byte)],
  ]),
]);
const member = (byte) => frame(0xd030, [
  [1, chain], [2, u32(4)], [3, u64(8)], [4, domain],
  [5, Buffer.alloc(32, byte)], [6, digest32(Buffer.alloc(32, byte))],
  [7, digest32(Buffer.alloc(32, byte + 1))], [8, digest32(Buffer.alloc(32, byte + 2))],
]);
const step = (previous, count, byte) => frame(0xd03a, [
  [1, u16(1)], [2, digest32(previous)], [3, u64(count)], [4, member(byte)],
]);
const seedHash = hash(seed);
const firstHash = hash(step(seedHash, 1, 1));
const secondHash = hash(step(firstHash, 2, 2));
assert.equal(seedHash.toString('hex'), '6aca76c445901bd421f3729a4b9b7521a2bfeebaaf516bc39e37b0d01dc1cc74');
assert.equal(firstHash.toString('hex'), 'b9f65d85f09dac71212187851b395f33d3dc9328d7f1167bd924b561bff7b862');
assert.equal(secondHash.toString('hex'), 'f20fbe0bfee0e665a8d9ea44ac506350f1d81be7b188f3a0c5e16e0edd3d5c87');
const identity = frame(0xd03b, [
  [1, chain], [2, u32(4)], [3, u64(8)], [4, domain], [5, freeze],
  [6, u64(11)], [7, u64(3)], [8, u64(2)], [9, digest32(Buffer.alloc(32, 0xaa))],
]);
assert.equal(identity.toString('hex'), '534e52453bd00100090001000a000000756e696f6e2d74657374020004000000040000000300080000000800000000000000040020000000090909090909090909090909090909090909090909090909090909090909090905002000000007070707070707070707070707070707070707070707070707070707070707070600080000000b0000000000000007000800000003000000000000000800080000000200000000000000090038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

// Locator bytes confer no authority. Freeze remains tag5; DrainSet is tag6.
const source = frame(0xe109, [[1, u64(8)], [2, freeze]]);
const progress = frame(0xe10d, [[1, u64(8)], [2, Buffer.alloc(32, 1)]]);
const apply = frame(0xe10f, [[1, u64(8)], [2, freeze]]);
assert.equal(source.toString('hex'), '534e524509e10100020001000800000008000000000000000200200000000707070707070707070707070707070707070707070707070707070707070707');
assert.equal(progress.toString('hex'), '534e52450de10100020001000800000008000000000000000200200000000101010101010101010101010101010101010101010101010101010101010101');
assert.equal(apply.toString('hex'), '534e52450fe10100020001000800000008000000000000000200200000000707070707070707070707070707070707070707070707070707070707070707');
console.log('DrainSet union identity/accumulator and retained/progress/apply locator vectors match');
