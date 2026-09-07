// Independent DR-0115 wire-vector reconstruction. No Rust encoder is invoked.
// Run: node scripts/public-abi-vector.mjs
import { createHash } from 'node:crypto';

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const frame = (id, fields) => Buffer.concat([
  Buffer.from('SNRE'), u16(id), u16(1), u16(fields.length),
  ...fields.flatMap(([key, value]) => [u16(key), u32(value.length), value]),
]);
const list = (items) => frame(0x5308, [
  [1, u16(items.length)], ...items.map((item, i) => [i + 2, item]),
]);
const origin = frame(0x5201, [
  [1, Buffer.from('test')], [2, u16(1)],
  [3, Buffer.from('ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c', 'hex')],
  [4, Buffer.alloc(32, 1)],
]);
const nominal = frame(0x5303, [[1, u16(1)]]);
const opaque = frame(0x5303, [[1, u16(2)], [2, u16(9)]]);
const ctor = (id, kinds) => frame(0x5302, [[1, u16(id)], [2, u32(1)], [3, list(kinds)]]);
const pattern = (id, args) => frame(0x5306, [[1, origin], [2, u16(id)], [3, list(args)]]);
const parameter = frame(0x5307, [[1, u16(3)], [2, u16(0)]]);
const inner = pattern(2, [parameter]);
const outer = pattern(1, [
  frame(0x5307, [[1, u16(1)], [2, inner]]),
  frame(0x5307, [[1, u16(2)], [2, u16(9)], [3, Buffer.alloc(32, 7)]]),
]);
const entry = (kinds, objects) => frame(0x5304, [
  [1, Buffer.from('run')], [2, list(kinds)], [3, list(objects)],
]);
const abi = (ctors, ep) => frame(0x5301, [[1, origin], [2, list(ctors)], [3, list([ep])]]);
const minimal = abi([], entry([], []));
const generic = abi([ctor(1, [nominal, opaque]), ctor(2, [opaque])], entry([opaque],
  [1, 2, 3].map((mode) => frame(0x5305, [[1, u16(mode)], [2, u32(1)], [3, outer]]))));
for (const [name, bytes] of Object.entries({ minimal, generic })) {
  console.log(JSON.stringify({ name, length: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex') }));
}
