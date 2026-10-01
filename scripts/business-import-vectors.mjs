// Independent DR-0176 persistence/integrity frames. These synthetic claims are
// not verified import plans, installed state, readiness or signing authority.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const uint = (value, length) => {
  const bytes = Buffer.alloc(length);
  if (length === 8) bytes.writeBigUInt64LE(BigInt(value));
  else if (length === 4) bytes.writeUInt32LE(value);
  else bytes.writeUInt16LE(value);
  return bytes;
};
const frame = (id, fields) => Buffer.concat([
  Buffer.from('SNRE'), uint(id, 2), uint(1, 2), uint(fields.length, 2),
  ...fields.flatMap(([field, bytes]) => [uint(field, 2), uint(bytes.length, 4), bytes]),
]);
const digest = (bytes) => frame(0x0103, [[1, uint(1, 2)], [2, bytes]]);
const D = digest(Buffer.alloc(32, 0x22));
const E = digest(Buffer.alloc(32, 0x33));
const chain = Buffer.from('cut-vector');
const chainId = frame(0x0105, [[1, chain]]);
const context = frame(0x6301, [[1, chain], [2, uint(1, 4)], [3, uint(2, 8)]]);
const hash = (bytes) => createHash('sha256').update(frame(0x1001, [
  [1, uint(1, 2)], [2, uint(13, 2)], [3, uint(1, 2)],
  [4, chain], [5, uint(1, 4)], [6, bytes],
])).digest();
const metadata = frame(0x64c3, [[1, uint(1, 2)], [2, uint(1, 2)]]);
const descriptor = frame(0x64c2, [
  [1, Buffer.from([1, 0x6b])], [2, metadata], [3, uint(3, 8)],
  // Fixed-range component commitment of 'abc', independently pinned in the
  // cut vectors; never hash a legal 32MiB body in one canonical frame.
  [4, digest(Buffer.from('32706e7347881d30903f439367789fe8aeec251c232585231911faa0fa8a5916', 'hex'))],
]);
const binding = frame(0x64c0, [
  [1, chainId], [2, uint(1, 4)], [3, uint(2, 8)], [4, Buffer.alloc(32, 0x11)],
  ...[5, 6, 7, 8, 9].map((id) => [id, D]),
  [10, uint(3, 8)], [11, uint(2, 8)], [12, uint(7, 8)],
]);
const progress = frame(0x64c1, [[1, uint(0, 8)], [2, Buffer.alloc(0)], [3, D]]);
const progressApplied = frame(0x64c1, [[1, uint(3, 8)], [2, E], [3, D]]);
const tombstone = frame(0x64c4, [
  [1, uint(2, 2)], [2, uint(19, 8)], [3, Buffer.alloc(0)],
  [4, uint(0, 2)], [5, Buffer.alloc(0)], [6, uint(0, 2)], [7, Buffer.alloc(0)],
]);
// The plan seed excludes plan_digest: no circular commitment.
const seed = frame(0x64c5, [
  [1, context], [2, Buffer.alloc(32, 0x11)],
  ...[3, 4, 5, 6].map((id) => [id, D]),
  [7, uint(7, 8)], [8, uint(3, 8)], [9, uint(2, 8)],
]);
const fold = frame(0x64c6, [[1, D], [2, uint(1, 2)], [3, descriptor]]);
const batch = frame(0x64c7, [[1, D], [2, progress], [3, uint(3, 8)], [4, D]]);
const progressSeed = frame(0x64c8, [[1, D], [2, Buffer.alloc(0)], [3, uint(0, 8)]]);
const progressFold = frame(0x64c8, [[1, D], [2, E], [3, uint(3, 8)]]);
const vectors = { binding, progress, progressApplied, metadata, descriptor, tombstone,
  seed, fold, batch, progressSeed, progressFold };
const expected = {
  binding: '10d26677f6bb5df07aa0f3f69982b69abfba650c1e367ce6491e6a5cae4f0039',
  progress: '24f8039cde4c8d125efc3e7e6d73fbbe56819a2c0d59a046ea8f57c8ee0767b9',
  progressApplied: 'bbd5e8e8cb58b2cd745a71beb6b353f3efe0caf20ac2dbc1619f13079dbf0ec7',
  metadata: 'f7b8e086242a0bb20b5580fc3a78e7a840c906a039ef2bad5b4a64077e0e123c',
  descriptor: 'cd725f4fe3c78459b78dcc2561a8e4f2981758943aeaff1bb50c8f2aac8d6255',
  tombstone: '7de36c0232da3fc995c7cb3e11b42568dd16c93130bf03a667a28b7e834b22e9',
  seed: '149603f218bf0835543b2e03df500066ac24b67b844bf8dcfbdeae7fed3ab246',
  fold: 'b88fa4d102cfeba1922cbf305c45aa3c5d329c89cb6ddafbca7a7a6f84b379f0',
  batch: '1183ce66efe0a25bddd578732b9ff6b6e9654cf3350c94da291f8f80daedf8df',
  progressSeed: 'e12eb0cfd2b630fd4caf6113572d9b8bb95ee59da2ac2212949e7dbe007a0d98',
  progressFold: '8a683a313e86be89789075494eca750abcfa809747af5a46876716e062166c2f',
};
assert.deepEqual(Object.keys(vectors), Object.keys(expected));
for (const [name, bytes] of Object.entries(vectors)) {
  assert.equal(hash(bytes).toString('hex'), expected[name], `${name} import NodeEvent vector differs`);
}
assert.equal(binding.subarray(4, 8).toString('hex'), 'c0640100');
assert.notDeepEqual(progress, progressApplied);
assert.notDeepEqual(progressSeed, progressFold);
console.log('business import independent persistence and NodeEvent vectors match');
