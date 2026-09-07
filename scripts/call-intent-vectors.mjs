// Independent DR-0120 framing and Ed25519 vector; never invokes a Rust encoder.
import { createHash, createPrivateKey, sign } from 'node:crypto';
import assert from 'node:assert/strict';
const uint = (n, width) => { const b = Buffer.alloc(width); let x = BigInt(n);
  for (let i = 0; i < width; i++) { b[i] = Number(x & 255n); x >>= 8n; } return b; };
const frame = (id, fields) => Buffer.concat([
  Buffer.from('SNRE'), uint(id, 2), uint(1, 2), uint(fields.length, 2),
  ...fields.flatMap(([key, value]) => [uint(key, 2), uint(value.length, 4), value]),
]);
const publisher = Buffer.from('ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c', 'hex');
const digest = (byte) => frame(0x0103, [[1,uint(1,2)],[2,Buffer.alloc(32,byte)]]);
const context = frame(0x6301, [[1,Buffer.from('test')],[2,uint(1,4)],[3,uint(0,8)]]);
const origin = frame(0x5201, [[1,Buffer.from('test')],[2,uint(1,2)],[3,publisher],[4,Buffer.alloc(32,1)]]);
const code = frame(0x6302, [[1,origin],[2,uint(1,8)],[3,context],[4,digest(0x66)]]);
const instance = frame(0x6401, [[1,publisher],[2,Buffer.alloc(32,2)],[3,uint(1,8)],[4,digest(0x77)]]);
const types = frame(0x5204, [[1,uint(0,2)]]);
const args = frame(0x5403, [[1,uint(6,2)],[2,frame(0x5404,[[1,uint(0,2)]])]]);
// AccessManifest uses existing frame 0x5002 and a u32 count.
const access = frame(0x5002, [[1,uint(0,4)]]);
const intent = frame(0x6402, [[1,context],[2,Buffer.alloc(32,3)],[3,publisher],[4,uint(4,8)],
  [5,code],[6,instance],[7,Buffer.from('run')],[8,types],[9,access],[10,args],[11,uint(100,8)]]);
const signing = frame(0x2001, [[1,Buffer.from('test')],[2,uint(1,4)],[3,uint(0,8)],
  [4,Buffer.from('CallContractIntent')],[5,uint(1,2)],[6,intent]]);
const key = createPrivateKey({ key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,7)]),format:'der',type:'pkcs8' });
const signature = sign(null, signing, key);
const signed = frame(0x6403, [[1,intent],[2,signature]]);
const expected = {
  types:'196f9a51ab53826c9f77f1e39ec008398bb91a89a671183ee9475a069020203c',
  instance:'332baa7a02cf83e548c1865f0b299a93241da627cee4172fdf54db1256fa0469',
  intent:'1cadd5da6a108e7aa5e8e1946a9935a71da214824cab3db810a72af23f1c8487',
  signing:'87044fa904b6282722a73670550544ed6c573b8ffe3261ec2f5c77e9bc4c1805',
  signed:'c64e2ecb8d1bf71ab98962a652aad01ead5fd5fea9a4c5bbc9584ae4df594257',
};
for (const [name, bytes] of Object.entries({types,instance,intent,signing,signed})) {
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  assert.equal(sha256, expected[name]);
  console.log(JSON.stringify({name,length:bytes.length,sha256}));
}
console.log(JSON.stringify({signature:signature.toString('hex')}));
