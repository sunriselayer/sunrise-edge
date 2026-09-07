// Independent local publication wire reconstruction; no Rust encoder is invoked.
import { createHash, createPrivateKey, sign } from 'node:crypto';
import assert from 'node:assert/strict';

const uint = (n, width) => { const b = Buffer.alloc(width); let x = BigInt(n);
  for (let i = 0; i < width; i++) { b[i] = Number(x & 255n); x >>= 8n; } return b; };
const frame = (id, fields, version = 1) => Buffer.concat([
  Buffer.from('SNRE'), uint(id, 2), uint(version, 2), uint(fields.length, 2),
  ...fields.flatMap(([key, value]) => [uint(key, 2), uint(value.length, 4), value]),
]);
const list = (id, items) => frame(id, [[1, uint(items.length, 2)], ...items.map((x, i) => [i + 2, x])]);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const chain = Buffer.from('publication-tests');
const digest = (bytes) => frame(0x0103, [[1, uint(1, 2)], [2, bytes]]);
const hash = (purpose, bytes) => sha256(frame(0x1001, [[1, uint(1, 2)],
  [2, uint(purpose, 2)], [3, uint(1, 2)], [4, chain], [5, uint(3, 4)], [6, bytes]]));
const publisher = Buffer.from('ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c', 'hex');
const context = frame(0x6301, [[1, chain], [2, uint(3, 4)], [3, uint(0, 8)]]);
const origin = frame(0x5201, [[1, chain], [2, uint(1, 2)], [3, publisher], [4, Buffer.alloc(32, 10)]]);
// Field 3 is local admission rules v1; CallAbi below remains wire version 2.
const profile = frame(0x630B, [[1, Buffer.from('local-devnet-publication-only')],
  [2, uint(1, 4)], [3, uint(1, 4)], [4, uint(33, 4)], [5, uint(16 * 1024 * 1024, 8)]]);
const semantics = digest(hash(4, profile));
const policy = frame(0x630A, [[1, context], [2, semantics], [3, uint(1, 2)],
  [4, uint(33, 4)], [5, uint(16 * 1024 * 1024, 8)]]);
const empty = list(0x5308, []);
const entry = frame(0x5304, [[1, Buffer.from('run')], [2, empty], [3, empty]]);
const objects = frame(0x5301, [[1, origin], [2, empty], [3, list(0x5308, [entry])]]);
const emptyTuple = frame(0x5401, [[1, uint(6, 2)], [2, list(0x5402, [])]]);
const abi = frame(0x5405, [[1, objects], [2, list(0x5402, [emptyTuple])], [3, list(0x5402, [])]], 2);
// Standard WASM sections for (module (memory (export "memory") 1 2) (func (export "run"))).
const wasm = Buffer.from('0061736d0100000001040160000003020100050401010102071002066d656d6f727902000372756e00000a040102000b', 'hex');
const artifact = frame(0x6303, [[1, context], [2, origin], [3, uint(1, 8)], [4, uint(1, 4)],
  [5, semantics], [6, wasm], [7, abi], [8, list(0x6304, [Buffer.from('run')])], [9, list(0x6305, [])]]);
const artifactDigest = digest(hash(4, artifact));
const requestId = Buffer.alloc(32, 10);
const signingPayload = frame(0x6309, [[1, requestId], [2, context], [3, origin],
  [4, uint(1, 8)], [5, uint(0, 8)], [6, artifactDigest], [7, uint(1, 2)]]);
const signing = frame(0x2001, [[1, chain], [2, uint(3, 4)], [3, uint(0, 8)],
  [4, Buffer.from('CreatePackageSubmission')], [5, uint(1, 2)], [6, signingPayload]]);
const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]), format: 'der', type: 'pkcs8' });
const signature = sign(null, signing, key);
const request = frame(0x6306, [[1, artifact], [2, uint(0, 8)], [3, artifactDigest], [4, signature]]);
const submission = frame(0x6308, [[1, requestId], [2, request]]);
assert.equal(signature.toString('hex'), '2fa6c1b5e1d82c1df8ca8a031aefa66abd023e4c5407f8b9a077317a9983d1530ab64c60b246757e31c72d63bf51adb0632975a51ed96ba5a0544d821fd76804');
assert.equal(hash(13, submission).toString('hex'), '0f095f78bf67a2fe247016559eaa0d7ebf1b85973a337b1d01ede46aa7d6bfc3');
const expected = {
  profile: '673274a00cfee3915b836f96dd525bcb199567aa873b849c984efe9c419c60a8',
  policy: '01351c32c3e82c1beaba9bc95688b82d78309ab59e39f87f9b6a6dcf27878b26',
  signingPayload: '23c27d77dc3aea6293e165844723513ce27741915e79ba794cb478db9c060597',
  signing: '9de764b4b69e5467df7e81b404f517808cbc29215a8a4251f2cc6fb359e228d7',
  submission: '458ab82f5505445c3552069323881807fc7ca47cfc478d9d22ad76426cef2a2b',
};
const expectedNodeEvent = {
  profile: '632c3f95d19be4e74bb19842300bb4e8928a7241dfbf63c6dac061a2b94258ac',
  policy: '0c71581f72f429f4e160a21616eee076137481cd9012f72ecca7028b01b99187',
  signingPayload: 'b1b7bc73834c9b31afaf081dc65ab7f036886cdd8112acddf3ed333319dd5699',
  signing: '2fbc5353034ab85b88726ed2c9f238a909fce16c8504884ae3f4a5bcdfc62c75',
  submission: '0f095f78bf67a2fe247016559eaa0d7ebf1b85973a337b1d01ede46aa7d6bfc3',
};
for (const [name, bytes] of Object.entries({ profile, policy, signingPayload, signing, submission })) {
  assert.equal(sha256(bytes).toString('hex'), expected[name]);
  assert.equal(hash(13, bytes).toString('hex'), expectedNodeEvent[name]);
  console.log(JSON.stringify({ name, length: bytes.length, sha256: expected[name], nodeEventDigest: hash(13, bytes).toString('hex') }));
}
console.log(JSON.stringify({ signature: signature.toString('hex') }));
