// Independent DR-0117 reconstruction; no Rust encoder is invoked.
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

const uint = (n, width) => { const b = Buffer.alloc(width); let x = BigInt(n);
  for (let i = 0; i < width; i++) { b[i] = Number(x & 255n); x >>= 8n; } return b; };
const frame = (id, fields) => Buffer.concat([
  Buffer.from('SNRE'), uint(id, 2), uint(1, 2), uint(fields.length, 2),
  ...fields.flatMap(([key, value]) => [uint(key, 2), uint(value.length, 4), value]),
]);
const list = (id, items) => frame(id, [[1, uint(items.length, 2)], ...items.map((x, i) => [i + 2, x])]);
const scalar = (kind) => frame(0x5401, [[1, uint(kind, 2)]]);
const bytes = (min, max) => frame(0x5401, [[1, uint(4, 2)], [2, uint(min, 4)], [3, uint(max, 4)]]);
const tuple = (items) => frame(0x5401, [[1, uint(6, 2)], [2, list(0x5402, items)]]);
const layout = tuple([scalar(1), scalar(2), scalar(3), bytes(2, 2),
  frame(0x5401, [[1, uint(5, 2)], [2, uint(8, 4)]]),
  frame(0x5401, [[1, uint(7, 2)], [2, uint(3, 2)], [3, tuple([scalar(2), bytes(0, 4)])]])]);
const valueFrame = (kind, payload) => frame(0x5403, [[1, uint(kind, 2)], [2, payload]]);
const valueTuple = (items) => valueFrame(6, list(0x5404, items));
const value = valueTuple([valueFrame(1, uint(1, 2)), valueFrame(2, uint(42, 8)),
  valueFrame(3, uint((1n << 128n) - 1n, 16)), valueFrame(4, Buffer.from([0, 255])),
  valueFrame(5, Buffer.from('é')), valueFrame(7, list(0x5404, [
    valueTuple([valueFrame(2, uint(7, 8)), valueFrame(4, Buffer.alloc(0))]),
    valueTuple([valueFrame(2, uint(9, 8)), valueFrame(4, Buffer.from([1, 2]))]),
  ]))]);
const origin = frame(0x5201, [[1, Buffer.from('test')], [2, uint(1, 2)],
  [3, Buffer.from('ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c', 'hex')],
  [4, Buffer.alloc(32, 1)]]);
const empty = list(0x5308, []);
const entry = frame(0x5304, [[1, Buffer.from('run')], [2, empty], [3, empty]]);
const objects = frame(0x5301, [[1, origin], [2, empty], [3, list(0x5308, [entry])]]);
const call = frame(0x5405, [[1, objects], [2, list(0x5402, [layout])]]);
const expected = {
  layout: '214d902457fa9cb3ad44048a2b63f9cfcf6b959941c02f2f960c6cac854e389d',
  value: '4198b85cdec540d1de9c2303f145cbd67cc83f54247a5acece025340dfa04dbe',
  call: '3c80fc2beb2a8365c789680efc3f13db610c2d3ae941bb9dddb5a866a1eae28c',
};
for (const [name, encoded] of Object.entries({ layout, value, call })) {
  const hash = createHash('sha256').update(encoded).digest('hex');
  assert.equal(hash, expected[name]);
  console.log(JSON.stringify({ name, length: encoded.length, sha256: hash }));
}
