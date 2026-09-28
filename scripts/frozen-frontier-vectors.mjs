// Independent canonical-frame reconstruction for frozen-frontier identity
// (0xD036/v1) and vote (0xD037/v1). This never invokes the Rust encoder.
// The fixture mirrors frozen_frontier_identity_and_vote_vectors_are_stable.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const frame = (id, fields) => Buffer.concat([
  Buffer.from('SNRE'), u16(id), u16(1), u16(fields.length),
  ...fields.flatMap(([field, value]) => [u16(field), u32(value.length), value]),
]);
const digest32 = (value) => frame(0x0103, [
  [1, u16(1)],
  [2, Buffer.alloc(32, value)],
]);

const identity = frame(0xd036, [
  [1, Buffer.from('frontier-test')],
  [2, u32(4)],
  [3, u64(8)],
  [4, Buffer.alloc(32, 9)],
  [5, Buffer.alloc(32, 7)],
  [6, u64(11)],
  [7, u64(2)],
  [8, digest32(0xaa)],
]);
const vote = frame(0xd037, [
  [1, identity],
  [2, Buffer.alloc(32, 1)],
  [3, u16(1)],
  [4, Buffer.alloc(64, 0x5a)],
]);

assert.equal(identity.toString('hex'), '534e524536d00100080001000d00000066726f6e746965722d74657374020004000000040000000300080000000800000000000000040020000000090909090909090909090909090909090909090909090909090909090909090905002000000007070707070707070707070707070707070707070707070707070707070707070600080000000b000000000000000700080000000200000000000000080038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
assert.equal(vote.toString('hex'), '534e524537d0010004000100db000000534e524536d00100080001000d00000066726f6e746965722d74657374020004000000040000000300080000000800000000000000040020000000090909090909090909090909090909090909090909090909090909090909090905002000000007070707070707070707070707070707070707070707070707070707070707070600080000000b000000000000000700080000000200000000000000080038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa020020000000010101010101010101010101010101010101010101010101010101010101010103000200000001000400400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a');
// Reconstruct the *hash preimage* independently too: the frontier's
// 0xD038 seed and step frames are wrapped in the common 0x1001 hash frame
// (SHA2-256 = 1, ExecutionEffects domain = 3, domain version = 1).
const chain = Buffer.from('frontier-test');
const hash = (payload) => createHash('sha256').update(frame(0x1001, [
  [1, u16(1)], [2, u16(3)], [3, u16(1)], [4, chain], [5, u32(4)], [6, payload],
])).digest();
const seed = frame(0xd038, [
  [1, u16(0)], [2, chain], [3, u32(4)], [4, u64(8)],
  [5, Buffer.alloc(32, 9)], [6, Buffer.alloc(32, 7)], [7, u64(11)],
]);
const availabilityIdentity = (byte) => frame(0xd030, [
  [1, chain], [2, u32(4)], [3, u64(8)], [4, Buffer.alloc(32, 9)],
  [5, Buffer.alloc(32, byte)], [6, digest32(byte)],
  [7, digest32(byte + 1)], [8, digest32(byte + 2)],
]);
const step = (previous, count, byte) => frame(0xd038, [
  [1, u16(1)], [2, frame(0x0103, [[1, u16(1)], [2, previous]])],
  [3, u64(count)], [4, availabilityIdentity(byte)],
]);
const seedHash = hash(seed);
const firstHash = hash(step(seedHash, 1, 1));
const secondHash = hash(step(firstHash, 2, 2));
assert.equal(seedHash.toString('hex'), '0b1c6153949437a5f2617e05a8849b8ae988778ac6e5aaf0ee17897b4212b7cc');
assert.equal(firstHash.toString('hex'), 'eb08a9f7032f18bdb7d9c8cd898b46761189faa0da5f741e13ab4cd651114897');
assert.equal(secondHash.toString('hex'), 'a7983d9b7dd79253338a97f1a629ea5795db854f6ba32f84cb9d2cff88dd3a41');
console.log('frozen frontier identity, vote and accumulator vectors match');
