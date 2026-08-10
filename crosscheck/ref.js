// Byte-for-byte reference implementation of the AnchorChain privacy
// primitives, used to cross-check bsvz-proofs. Pure Node (crypto + BigInt), no
// @bsv/sdk dependency. It reproduces exactly:
//   - doubleSha256
//   - hashToPoint / generatorVector / CURVE_H / BP_U  (genpoints.ts, curve.ts)
//   - challenge / scalarBytes32                        (transcript.ts)
//   - commit                                          (commit.ts)
//   - proveDlog with a fixed nonce                    (sigma.ts)
//
// Run: node crosscheck/ref.js   (compare with: zig build crosscheck)
'use strict';

const crypto = require('node:crypto');

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const G = { x: GX, y: GY };

function mod(a, m) { a = a % m; return a < 0n ? a + m : a; }
function modP(a) { return mod(a, P); }
function modN(a) { return mod(a, N); }
function modPow(b, e, m) {
  b = mod(b, m); e = e < 0n ? e + m : e;
  let r = 1n;
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}
function inv(a, m) { return modPow(a, m - 2n, m); }

// ---- Xoshiro256++ (std.Random.Xoshiro256) ----
function rotl(x, k) { return ((x << k) | (x >> (64n - k))) & 0xffffffffffffffffn; }
function splitmix64(state) {
  state = (state + 0x9e3779b97f4a7c15n) & 0xffffffffffffffffn;
  let z = state;
  z = (z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n & 0xffffffffffffffffn;
  z = (z ^ (z >> 27n)) * 0x94d049bb133111ebn & 0xffffffffffffffffn;
  return [z ^ (z >> 31n), state];
}
function makeXoshiro(init_s) {
  let state = init_s & 0xffffffffffffffffn;
  const s = [];
  for (let i = 0; i < 4; i++) {
    let next;
    [next, state] = splitmix64(state);
    s.push(next);
  }
  return function next() {
    const r = (rotl((s[0] + s[3]) & 0xffffffffffffffffn, 23n) + s[0]) & 0xffffffffffffffffn;
    const t = (s[1] << 17n) & 0xffffffffffffffffn;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl(s[3], 45n);
    return r;
  };
}

function sha256(buf) {
  return Buffer.from(crypto.createHash('sha256').update(buf).digest());
}
function doubleSha256(buf) { return sha256(sha256(buf)); }

// ---- point ops ----
function pointAdd(a, b) {
  if (a === null) return b;
  if (b === null) return a;
  const [x1, y1] = [a.x, a.y];
  const [x2, y2] = [b.x, b.y];
  if (x1 === x2) {
    if (modP(y1 + y2) === 0n) return null;
    const lam = modP(3n * x1 * x1 % P * inv(2n * y1, P));
    const x3 = modP(lam * lam - 2n * x1);
    return { x: x3, y: modP(lam * (x1 - x3) - y1) };
  }
  const lam = modP((y2 - y1) * inv(x2 - x1, P));
  const x3 = modP(lam * lam - x1 - x2);
  return { x: x3, y: modP(lam * (x1 - x3) - y1) };
}
function pointMul(k, p) {
  k = modN(k);
  let r = null;
  let addend = p;
  while (k > 0n) {
    if (k & 1n) r = pointAdd(r, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return r;
}
function pointNeg(p) { return p === null ? null : { x: p.x, y: modP(-p.y) }; }
function encodePoint(p) {
  if (p === null) return Buffer.from([0x00]);
  const x = hexBytes(p.x.toString(16).padStart(64, '0'));
  const prefix = (p.y & 1n) === 0n ? 0x02 : 0x03;
  return Buffer.concat([Buffer.from([prefix]), x]);
}
function decodePoint(buf) {
  if (buf.length !== 33) return null;
  const prefix = buf[0];
  const x = BigInt('0x' + buf.subarray(1).toString('hex'));
  if (x >= P) return null;
  const y2 = modP((x * x % P * x) % P + 7n);
  const y = modPow(y2, (P + 1n) / 4n, P);
  if (modP(y * y) !== y2) return null;
  const wantEven = prefix === 0x02;
  if (((y & 1n) === 0n) === wantEven) return { x, y };
  return { x, y: modP(-y) };
}
function hexBytes(hex) { return Buffer.from(hex, 'hex'); }

// ---- genpoints.ts ----
function hashToPoint(label) {
  const enc = Buffer.from(label, 'utf8');
  for (let counter = 0; counter < 100000; counter++) {
    const x = doubleSha256(Buffer.concat([enc, Buffer.from(':' + counter, 'utf8')]));
    const c = Buffer.concat([Buffer.from([0x02]), x]);
    const d = Buffer.concat([Buffer.from([0x03]), x]);
    const p = decodePoint(c);
    if (p) return p;
    const q = decodePoint(d);
    if (q) return q;
  }
  throw new Error('hashToPoint: no valid point');
}
function generatorVector(domain, n) {
  const out = [];
  for (let i = 0; i < n; i++) out.push(hashToPoint(domain + '/' + i));
  return out;
}

// ---- transcript.ts ----
function scalarBytes32(s) {
  return hexBytes(modN(s).toString(16).padStart(64, '0'));
}
function challenge(label, points, scalars = []) {
  const parts = [Buffer.from(label, 'utf8')];
  for (const p of points) parts.push(encodePoint(p));
  for (const s of scalars) parts.push(scalarBytes32(s));
  let c = modN(BigInt('0x' + doubleSha256(Buffer.concat(parts)).toString('hex')));
  if (c === 0n) c = 1n;
  return c;
}

// ---- commit.ts ----
function commit(value, blinding) {
  const v = modN(value);
  const r = modN(blinding);
  const rH = r === 0n ? null : pointMul(r, H);
  if (v === 0n) {
    if (rH === null) throw new Error('commit(0,0)');
    return rH;
  }
  const vG = pointMul(v, G);
  return rH === null ? vG : pointAdd(vG, rH);
}

// ---- sigma.ts ----
function proveDlog(label, base, p, x, nonce) {
  const k = nonce;
  const a = pointMul(k, base);
  const e = challenge(label, [base, p, a]);
  return { a, s: modN(k + e * x) };
}

// ---- scalar random with rejection sampling over the seeded Xoshiro stream ----
function makeScalarRandom(nextU64) {
  return function randScalar() {
    for (;;) {
      // 32 bytes, little-endian u64 writes (matches std Random fill).
      const bytes = Buffer.alloc(32);
      for (let off = 0; off < 32; off += 8) {
        let n = nextU64();
        for (let j = 0; j < 8; j++) { bytes[off + j] = Number(n & 0xffn); n >>= 8n; }
      }
      const v = BigInt('0x' + bytes.toString('hex')); // big-endian read
      if (v < N) return v;
    }
  };
}

// ============================ output ============================
const H = hashToPoint('AnchorChain/pedersen/H/v1');
const U = hashToPoint('anchorchain/bp/U/v1');

console.log('G: ' + encodePoint(G).toString('hex'));
console.log('H: ' + encodePoint(H).toString('hex'));
console.log('BP_U: ' + encodePoint(U).toString('hex'));
const gv = generatorVector('anchorchain/bp/g/v1', 2);
const hv = generatorVector('anchorchain/bp/h/v1', 2);
console.log('g0: ' + encodePoint(gv[0]).toString('hex'));
console.log('g1: ' + encodePoint(gv[1]).toString('hex'));
console.log('h0: ' + encodePoint(hv[0]).toString('hex'));
console.log('h1: ' + encodePoint(hv[1]).toString('hex'));

const c = challenge('crosscheck/v1', [G, H], [42n]);
console.log('challenge: ' + c.toString(16).padStart(64, '0'));

console.log('commit(1234,5678): ' + encodePoint(commit(1234n, 5678n)).toString('hex'));

// Schnorr with the same seeded nonce stream as the Zig crosscheck tool.
const nextU64 = makeXoshiro(0xDEADBEEFCAFEBABEn);
const randScalar = makeScalarRandom(nextU64);
const x = 7n;
const Pub = pointMul(x, G);
const proof = proveDlog('crosscheck/schnorr/v1', G, Pub, x, randScalar());
console.log('schnorr.a: ' + encodePoint(proof.a).toString('hex'));
console.log('schnorr.s: ' + proof.s.toString(16).padStart(64, '0'));
