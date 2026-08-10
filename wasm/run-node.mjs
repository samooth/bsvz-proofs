// Node smoke test for the bsvz-proofs wasm module (zig build wasm-test, and
// `npm test` in wasm/).
//
// Loads the module, asserts the deterministic AnchorChain byte-compat vectors
// (mirroring examples/crosscheck.zig) through the JS API, and round-trips
// every protocol, including tamper negatives. Proofs are pinned to a
// deterministic RNG via setRngForTesting so the vectors are stable.

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createProofs } from './index.js';

// build.zig / npm test pass the artifact path as the last argument.
const artifact = process.argv[process.argv.length - 1];

const p = await createProofs({ wasmBytes: readFileSync(artifact) });

const SCALAR = 32;
const POINT = 33;
const GROUP_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const INV7 = 0x49249249249249249249249249249248c79facd43214c011123c1b03a93412a5n;

function assert(cond, msg) {
  if (!cond) throw new Error('assertion failed: ' + msg);
}
function hex(buf) {
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}
function tamper(buf, idx = 0) {
  const t = new Uint8Array(buf);
  t[idx] ^= 1;
  return t;
}
function toHex(b) {
  return hex(b);
}

p.seed(); // exercises the host-entropy path
assert(p.version() === 1, 'version');

// --- deterministic byte-compat vectors (see examples/crosscheck.zig) -------

const G = p.generators.G();
const H = p.generators.H();
const U = p.generators.BP_U();
assert(toHex(G) === '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'G vector');
assert(toHex(H) === '020b0769322f4716ee6b9a1360cba0751e5b23dd4caaa1beb85afe986f91788ed9', 'H vector');
assert(toHex(U) === '02625703259daa3c2fee574b5b318a9f9c0026c0ef58339903d6212e7c993a36f7', 'BP_U vector');

const g0 = p.generators.hashToPoint('anchorchain/bp/g/v1/0');
const g1 = p.generators.hashToPoint('anchorchain/bp/g/v1/1');
const h0 = p.generators.hashToPoint('anchorchain/bp/h/v1/0');
const h1 = p.generators.hashToPoint('anchorchain/bp/h/v1/1');
assert(toHex(g0) === '02a6c54dd6cd8137fd9859e397eae4fc0c329fdb37bff7fb9b5ce81933d647eb30', 'g0 vector');
assert(toHex(g1) === '02dcd9d5b79b8209b5412f6e3f2ebec6d1ff337586bba2348388b63ffa9081ee75', 'g1 vector');
assert(toHex(h0) === '02f8f740330c446a18daed91b956194eb28c90a90cba756c44d1422981d4f570ec', 'h0 vector');
assert(toHex(h1) === '02ac70ff860569c46ceb3f90fb9269feb607b19fa38e8ca8091a6bc8f227431822', 'h1 vector');

// generatorVector derives hashToPoint(domain ++ "/" ++ i)
const gv = p.generators.vector('anchorchain/bp/g/v1', 2);
assert(hex(gv.subarray(0, POINT)) === toHex(g0) && hex(gv.subarray(POINT)) === toHex(g1), 'generator_vector vs g0,g1');

// challenge("crosscheck/v1", [G, H], [Scalar(42)])
const ch = p.transcript.challenge('crosscheck/v1', [G, H], [p.scalar.fromInt(42)]);
assert(toHex(ch) === 'ab7a7c1710d91b83567113216c67605552e30bab7bb8a2580f743fe4e1d4eb85', 'challenge vector');

// commit(1234, 5678)
const cm = p.pedersen.commit(1234, 5678);
assert(toHex(cm) === '0316b94b91ddef49f168d9169b616d8f0f6e0905f5bea95876cd92f18ab5918d53', 'commit vector');
assert(p.pedersen.verify(cm, 1234, 5678), 'commit verify');
assert(!p.pedersen.verify(cm, 1234, 1234), 'commit verify wrong blinding');

// Schnorr byte-compat vector (pinned RNG seed, as in crosscheck.zig)
const P = p.point.mul(G, 7);
p.setRngForTesting(0xDEADBEEFCAFEBABEn);
const schnorr = p.schnorr.prove('crosscheck/schnorr/v1', G, P, 7);
assert(toHex(schnorr.a) === '02bac33bf6ef1ac7dd67bce2c9d832c5d02ef584fd3bb2ff916e93a1934c70254a', 'schnorr.a vector');
assert(toHex(schnorr.s) === '6e26b215064aecee7be8f0cb98a950b0b4de189c1db9033368be88b14452077b', 'schnorr.s vector');
assert(p.schnorr.verify('crosscheck/schnorr/v1', G, P, schnorr.a, schnorr.s), 'schnorr verify');
p.setRngForTestingOff();
assert(!p.schnorr.verify('crosscheck/schnorr/v1', G, P, schnorr.a, tamper(schnorr.s, 31)), 'schnorr verify tampered');

// --- scalar / point / transcript round-trips ---------------------------------

const a = p.scalar.fromInt(42);
const b = p.scalar.fromInt(9);
assert(p.scalar.toInt(p.scalar.add(a, b)) === 51n, 'scalar add 42+9');
assert(p.scalar.toInt(p.scalar.sub(a, b)) === 33n, 'scalar sub 42-9');
assert(p.scalar.toInt(p.scalar.mul(a, b)) === 378n, 'scalar mul 42*9');
assert(p.scalar.toInt(p.scalar.neg(b)) === ((GROUP_ORDER - 9n) & 0xFFFFFFFFFFFFFFFFn), 'scalar neg 9');
assert(p.scalar.toInt(p.scalar.invert(7)) === (INV7 & 0xFFFFFFFFFFFFFFFFn), 'scalar invert 7');
assert(!p.scalar.isZero(p.scalar.fromInt(7)), 'scalar is_zero');
assert(p.scalar.eq(a, a) && !p.scalar.eq(a, b), 'scalar eq');

assert(toHex(p.point.add(G, H)) !== toHex(H), 'point add');
assert(toHex(p.point.sub(p.point.add(G, H), H)) === toHex(G), 'point sub');
assert(p.point.eq(p.point.mul(G, 7), P), 'point mul scalar');
void p.point.negate(G); // must not throw

// sha256 / sha256d vs node:crypto
const msgEnc = new TextEncoder().encode('anchorchain/bp/U/v1');
assert(toHex(p.transcript.sha256(msgEnc)) === createHash('sha256').update(msgEnc).digest('hex'), 'sha256 vs node');
assert(
  toHex(p.transcript.sha256d(msgEnc)) ===
    createHash('sha256').update(createHash('sha256').update(msgEnc).digest()).digest('hex'),
  'sha256d vs node',
);

// --- protocol round-trips (deterministic RNG) --------------------------------

p.setRngForTesting(0x2026010102030405n);
const bl = p.scalar.fromInt(1234);

// CDS one-out-of-many: statements [G*7, G*9], true index 1, witness 9
const stmts = [p.point.mul(G, 7), p.point.mul(G, 9)];
const orProof = p.cdsOr.prove('crosscheck/schnorr/v1', G, stmts, 1, 9);
assert(p.cdsOr.verify('crosscheck/schnorr/v1', G, stmts, orProof.a, orProof.e, orProof.s), 'cds_or verify');
assert(!p.cdsOr.verify('crosscheck/schnorr/v1', G, stmts, tamper(orProof.a), orProof.e, orProof.s), 'cds_or verify tampered');

// Linear range proof, 16 bits
const bits16 = 16;
const lr = p.range.prove(7, bl, bits16);
assert(p.range.verify(lr.commitment, lr.proof, bits16), 'range verify');
assert(!p.range.verify(lr.commitment, tamper(lr.proof), bits16), 'range verify tampered');

// Bulletproof range, 16 bits
const bp = p.rangeBp.prove(7, bl, bits16);
assert(p.rangeBp.verify(bp.commitment, bp.proof, bits16), 'bp verify');
assert(!p.rangeBp.verify(bp.commitment, tamper(bp.proof), bits16), 'bp verify tampered');

// Membership: commitment cm7(7,5678), set [7, 42], value 7
const cm7 = p.pedersen.commit(7, 5678);
const set = [p.scalar.fromInt(7), p.scalar.fromInt(42)];
const msProof = p.membership.prove(cm7, 5678, set, 7);
assert(p.membership.verify(cm7, set, msProof.a, msProof.e, msProof.s), 'membership verify');
assert(!p.membership.verify(cm7, set, tamper(msProof.a), msProof.e, msProof.s), 'membership verify tampered');

// Conservation: single input == single output, excess 0
const ins = [cm];
const outs = [cm];
const cons = p.conservation.prove(ins, outs, 0);
assert(p.conservation.verify(ins, outs, cons.a, cons.s), 'conservation verify');
assert(!p.conservation.verify(ins, outs, cons.a, tamper(cons.s, 31)), 'conservation verify tampered');

p.setRngForTestingOff();

// low-level memory + last_error are consistent after all successes
const buf = p.alloc(33);
assert(buf !== 0, 'raw alloc');
assert(p.memView().length > 0, 'memView');
p.free(buf, 33);
assert(p.lastError() === '', 'last_error empty');

console.log('wasm-test OK: vectors match and all protocols round-trip');
