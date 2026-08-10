// Node smoke test for the wasm module (zig build wasm-test).
//
// Loads zig-out/bin/bsvz_proofs.wasm, asserts the deterministic AnchorChain
// byte-compat vectors (mirroring examples/crosscheck.zig), and round-trips
// every protocol the shim exports. Proofs are pinned to a deterministic RNG
// via zkp_set_rng_for_testing so the byte-compat assertions are stable.
//
// All pointers passed to the wasm exports are byte offsets into the module's
// exported linear memory; the host must copy inputs in (or use zkp_alloc).

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

// build.zig passes the artifact path as the last argument (addArtifactArg).
const artifact = process.argv[process.argv.length - 1];

const instance = await WebAssembly.instantiate(
  await WebAssembly.compile(readFileSync(artifact)),
  {},
);
const m = instance.exports;

const SCALAR = 32;
const POINT = 33;
const GROUP_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const INV7 = 0x49249249249249249249249249249248c79facd43214c011123c1b03a93412a5n;

// Always re-fetch the buffer: zkp_alloc can grow wasm memory, invalidating
// any previously captured view.
function memView() {
  return new Uint8Array(m.memory.buffer);
}

function assert(cond, msg) {
  if (!cond) throw new Error('assertion failed: ' + msg);
}
function hex(buf) {
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}
function rBytes(off, n) {
  return memView().slice(off, off + n);
}
function rHex(off, n) {
  return hex(rBytes(off, n));
}
function wBytes(off, arr) {
  memView().set(arr, off);
}
function wScalar(off, v) {
  const vw = memView();
  vw.fill(0, off, off + SCALAR);
  wBytes(off, Uint8Array.from(BigInt.asUintN(256, v).toString(16).padStart(64, '0').match(/../g), (s) => parseInt(s, 16)));
}
function alloc(n) {
  const p = m.zkp_alloc(n);
  assert(p !== null && p !== undefined, 'zkp_alloc(' + n + ')');
  return p;
}
function pointMul(pPtr, kPtr, out) {
  assert(m.zkp_point_mul(pPtr, kPtr, out) === 0, 'zkp_point_mul');
  return out;
}
function hashToPoint(domain, out) {
  const enc = new TextEncoder().encode(domain);
  wBytes(domBuf, enc);
  assert(m.zkp_hash_to_point(domBuf, enc.length, out) === 0, 'zkp_hash_to_point ' + domain);
  return out;
}
function tamper(ptr) {
  const vw = memView();
  vw[ptr] ^= 1;
}
// The wasm export returns u64 but JS surfaces i64 (signed); reinterpret.
function toInt(ptr) {
  return BigInt.asUintN(64, m.zkp_scalar_to_int(ptr));
}

const domBuf = alloc(256);

// --- deterministic byte-compat vectors (see examples/crosscheck.zig) -------

const G = alloc(POINT), H = alloc(POINT), U = alloc(POINT);
m.zkp_generator_G(G);
m.zkp_generator_H(H);
m.zkp_generator_BP_U(U);
assert(rHex(G, POINT) === '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'G vector');
assert(rHex(H, POINT) === '020b0769322f4716ee6b9a1360cba0751e5b23dd4caaa1beb85afe986f91788ed9', 'H vector');
assert(rHex(U, POINT) === '02625703259daa3c2fee574b5b318a9f9c0026c0ef58339903d6212e7c993a36f7', 'BP_U vector');

const g0 = alloc(POINT), g1 = alloc(POINT), h0 = alloc(POINT), h1 = alloc(POINT);
hashToPoint('anchorchain/bp/g/v1/0', g0);
hashToPoint('anchorchain/bp/g/v1/1', g1);
hashToPoint('anchorchain/bp/h/v1/0', h0);
hashToPoint('anchorchain/bp/h/v1/1', h1);
assert(rHex(g0, POINT) === '02a6c54dd6cd8137fd9859e397eae4fc0c329fdb37bff7fb9b5ce81933d647eb30', 'g0 vector');
assert(rHex(g1, POINT) === '02dcd9d5b79b8209b5412f6e3f2ebec6d1ff337586bba2348388b63ffa9081ee75', 'g1 vector');
assert(rHex(h0, POINT) === '02f8f740330c446a18daed91b956194eb28c90a90cba756c44d1422981d4f570ec', 'h0 vector');
assert(rHex(h1, POINT) === '02ac70ff860569c46ceb3f90fb9269feb607b19fa38e8ca8091a6bc8f227431822', 'h1 vector');

// generatorVector derives hashToPoint(domain ++ "/" ++ i)
const gv = alloc(2 * POINT);
wBytes(domBuf, new TextEncoder().encode('anchorchain/bp/g/v1'));
assert(m.zkp_generator_vector(domBuf, 'anchorchain/bp/g/v1'.length, 2, gv) === 0, 'zkp_generator_vector');
assert(rHex(gv, POINT) === rHex(g0, POINT) && rHex(gv + POINT, POINT) === rHex(g1, POINT), 'generator_vector vs g0,g1');

// challenge("crosscheck/v1", [G, H], [Scalar(42)])
const pts = alloc(2 * POINT);
wBytes(pts, rBytes(G, POINT));
wBytes(pts + POINT, rBytes(H, POINT));
const s42 = alloc(SCALAR);
wScalar(s42, 42n);
const ch = alloc(SCALAR);
wBytes(domBuf, new TextEncoder().encode('crosscheck/v1'));
assert(m.zkp_challenge(domBuf, 'crosscheck/v1'.length, pts, 2, s42, 1, ch) === 0, 'zkp_challenge rc');
assert(rHex(ch, SCALAR) === 'ab7a7c1710d91b83567113216c67605552e30bab7bb8a2580f743fe4e1d4eb85', 'challenge vector');

// commit(1234, 5678)
const cm = alloc(POINT);
const v1234 = alloc(SCALAR), b5678 = alloc(SCALAR);
wScalar(v1234, 1234n);
wScalar(b5678, 5678n);
m.zkp_commit(v1234, b5678, cm);
assert(rHex(cm, POINT) === '0316b94b91ddef49f168d9169b616d8f0f6e0905f5bea95876cd92f18ab5918d53', 'commit vector');
assert(m.zkp_commit_verify(cm, v1234, b5678) === 1, 'commit verify');
assert(m.zkp_commit_verify(cm, v1234, v1234) === 0, 'commit verify wrong blinding');

// Schnorr byte-compat vector (pinned RNG seed, as in crosscheck.zig)
const x7 = alloc(SCALAR);
wScalar(x7, 7n);
const P = alloc(POINT);
pointMul(G, x7, P);
const sA = alloc(POINT), sS = alloc(SCALAR);
wBytes(domBuf, new TextEncoder().encode('crosscheck/schnorr/v1'));
m.zkp_set_rng_for_testing(0xDEADBEEFCAFEBABEn);
assert(m.zkp_schnorr_prove(domBuf, 'crosscheck/schnorr/v1'.length, G, P, x7, sA, sS) === 0, 'zkp_schnorr_prove rc');
assert(rHex(sA, POINT) === '02bac33bf6ef1ac7dd67bce2c9d832c5d02ef584fd3bb2ff916e93a1934c70254a', 'schnorr.a vector');
assert(rHex(sS, SCALAR) === '6e26b215064aecee7be8f0cb98a950b0b4de189c1db9033368be88b14452077b', 'schnorr.s vector');
assert(m.zkp_schnorr_verify(domBuf, 'crosscheck/schnorr/v1'.length, G, P, sA, sS) === 1, 'schnorr verify');
m.zkp_set_rng_for_testing_off();

// --- scalar / point / transcript round-trips ---------------------------------

const a = alloc(SCALAR), b = alloc(SCALAR), t = alloc(SCALAR);
wScalar(a, 42n);
wScalar(b, 9n);
m.zkp_scalar_add(a, b, t);
assert(toInt(t) === 51n, 'scalar add 42+9');
m.zkp_scalar_sub(a, b, t);
assert(toInt(t) === 33n, 'scalar sub 42-9');
m.zkp_scalar_mul(a, b, t);
assert(toInt(t) === 378n, 'scalar mul 42*9');
m.zkp_scalar_neg(b, t);
assert(toInt(t) === ((GROUP_ORDER - 9n) & 0xFFFFFFFFFFFFFFFFn), 'scalar neg 9');
m.zkp_scalar_invert(x7, t);
assert(toInt(t) === (INV7 & 0xFFFFFFFFFFFFFFFFn), 'scalar invert 7');
assert(m.zkp_scalar_is_zero(x7) === 0, 'scalar is_zero');
assert(m.zkp_scalar_eq(a, a) === 1 && m.zkp_scalar_eq(a, b) === 0, 'scalar eq');

const psum = alloc(POINT), pdiff = alloc(POINT), pneg = alloc(POINT), p2 = alloc(POINT);
assert(m.zkp_point_add(G, H, psum) === 0 && m.zkp_point_eq(psum, H) === 0, 'point add');
assert(m.zkp_point_sub(psum, H, pdiff) === 0 && m.zkp_point_eq(pdiff, G) === 1, 'point sub');
assert(m.zkp_point_negate(G, pneg) === 0, 'point negate');
pointMul(G, x7, p2);
assert(m.zkp_point_eq(p2, P) === 1, 'point mul scalar');

// sha256 / sha256d vs node:crypto
const msg = alloc(64);
const msgEnc = new TextEncoder().encode('anchorchain/bp/U/v1');
wBytes(msg, msgEnc);
const h256 = alloc(SCALAR), h256d = alloc(SCALAR);
m.zkp_sha256(msg, msgEnc.length, h256);
m.zkp_sha256d(msg, msgEnc.length, h256d);
assert(rHex(h256, SCALAR) === createHash('sha256').update(msgEnc).digest('hex'), 'sha256 vs node');
assert(
  rHex(h256d, SCALAR) ===
    createHash('sha256').update(createHash('sha256').update(msgEnc).digest()).digest('hex'),
  'sha256d vs node',
);

// --- protocol round-trips (deterministic RNG) --------------------------------

m.zkp_set_rng_for_testing(0x2026010102030405n);
const zero32 = alloc(SCALAR);
const v7 = alloc(SCALAR), v9 = alloc(SCALAR), bl = alloc(SCALAR);
wScalar(zero32, 0n);
wScalar(v7, 7n);
wScalar(v9, 9n);
wScalar(bl, 1234n);

// CDS one-out-of-many: statements [G*7, G*9], true index 1, witness 9
const stmts = alloc(2 * POINT);
pointMul(G, v7, stmts);
pointMul(G, v9, stmts + POINT);
const nOr = 2;
const orSize = m.zkp_cds_or_size(nOr);
const orA = alloc(orSize / 3 | 0), orE = alloc(orSize / 3 | 0), orS = alloc(orSize / 3 | 0);
assert(m.zkp_cds_or_prove(domBuf, 'crosscheck/schnorr/v1'.length, G, stmts, nOr, 1, v9, orA, orE, orS) === 0, 'cds_or prove');
assert(m.zkp_cds_or_verify(domBuf, 'crosscheck/schnorr/v1'.length, G, stmts, nOr, orA, orE, orS) === 1, 'cds_or verify');
tamper(orA);
assert(m.zkp_cds_or_verify(domBuf, 'crosscheck/schnorr/v1'.length, G, stmts, nOr, orA, orE, orS) === 0, 'cds_or verify tampered');

// Linear range proof, 16 bits
const bits16 = 16;
const lrSize = m.zkp_range_size(bits16);
const lrBuf = alloc(lrSize);
const lrCm = alloc(POINT);
m.zkp_commit(v7, bl, lrCm);
assert(m.zkp_range_prove(v7, bl, bits16, lrBuf) === 0, 'range prove');
assert(m.zkp_range_verify(lrCm, lrBuf, bits16) === 1, 'range verify');
tamper(lrBuf);
assert(m.zkp_range_verify(lrCm, lrBuf, bits16) === 0, 'range verify tampered');

// Bulletproof range, 16 bits (commitment embedded in output)
const bpSize = m.zkp_range_bp_size(bits16);
const bpBuf = alloc(bpSize);
assert(m.zkp_range_bp_prove(v7, bl, bits16, bpBuf) === 0, 'bp prove');
assert(m.zkp_range_bp_verify(bpBuf, bpBuf + POINT, bits16) === 1, 'bp verify');
tamper(bpBuf + POINT);
assert(m.zkp_range_bp_verify(bpBuf, bpBuf + POINT, bits16) === 0, 'bp verify tampered');

// Membership: commitment cm7(7,5678), set [7, 42], value 7
const cm7 = alloc(POINT);
m.zkp_commit(v7, b5678, cm7);
const set = alloc(2 * SCALAR);
wScalar(set, 7n);
wScalar(set + SCALAR, 42n);
const msSize = m.zkp_membership_size(2);
const msA = alloc(msSize / 3 | 0), msE = alloc(msSize / 3 | 0), msS = alloc(msSize / 3 | 0);
assert(m.zkp_membership_prove(cm7, b5678, set, 2, v7, msA, msE, msS) === 0, 'membership prove');
assert(m.zkp_membership_verify(cm7, set, 2, msA, msE, msS) === 1, 'membership verify');
tamper(msE);
assert(m.zkp_membership_verify(cm7, set, 2, msA, msE, msS) === 0, 'membership verify tampered');

// Conservation: single input == single output, excess 0
const ins = alloc(POINT), outs = alloc(POINT);
wBytes(ins, rBytes(cm, POINT));
wBytes(outs, rBytes(cm, POINT));
const cA = alloc(POINT), cS = alloc(SCALAR);
assert(m.zkp_conservation_prove(ins, 1, outs, 1, zero32, cA, cS) === 0, 'conservation prove');
assert(m.zkp_conservation_verify(ins, 1, outs, 1, cA, cS) === 1, 'conservation verify');
tamper(cS);
assert(m.zkp_conservation_verify(ins, 1, outs, 1, cA, cS) === 0, 'conservation verify tampered');

m.zkp_set_rng_for_testing_off();

// last_error is empty after all successes
assert(m.zkp_last_error(alloc(256), 256) === 0, 'last_error empty');

console.log('wasm-test OK: vectors match and all protocols round-trip');
