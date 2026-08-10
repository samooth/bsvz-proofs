// bsvz-proofs — WebAssembly module loader and JS API.
//
// The Zig shim (src/wasm.zig) exposes a C-ABI over pointer/length pairs into
// the module's linear memory. This loader wraps that into a typed JS API:
// scalars and points are passed/returned as Uint8Array (32 and 33 bytes), and
// proofs as flat buffers sized by the *Size helpers. Error codes are thrown as
// ProofError. u64 results (scalarToInt) are surfaced as unsigned BigInt.
//
// Entropy: call seed() with CSPRNG bytes before the first proof that samples
// randomness, or the module traps. seed() pulls from crypto.getRandomValues by
// default. setRngForTesting(seed) pins a deterministic RNG for reproducible
// vectors.

const SCALAR_LEN = 32;
const POINT_LEN = 33;
const SCRATCH = 1 << 16;

export const ErrorCode = Object.freeze({
  OK: 0,
  INVALID_POINT: 1,
  INVALID_ARG: 2,
  OUT_OF_MEMORY: 3,
  PROTOCOL: 4,
});

export class ProofError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ProofError';
    this.code = code;
  }
}

async function defaultWasmBytes() {
  const url = new URL('./bsvz_proofs.wasm', import.meta.url);
  if (typeof process !== 'undefined' && process.versions?.node) {
    const { readFileSync } = await import('node:fs');
    return readFileSync(url);
  }
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`bsvz-proofs: failed to load wasm (${res.status} ${res.statusText})`);
  }
  return new Uint8Array(await res.arrayBuffer());
}

function randomBytes(n) {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('bsvz-proofs: global crypto.getRandomValues unavailable; pass entropy to seed()');
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

function bytesOf(v, len, what) {
  if (typeof v === 'bigint' || typeof v === 'number') {
    const hex = BigInt.asUintN(len * 8, typeof v === 'number' ? BigInt(v) : v)
      .toString(16)
      .padStart(len * 2, '0');
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  if (v instanceof Uint8Array) {
    if (v.length !== len) throw new TypeError(`bsvz-proofs: ${what} must be ${len} bytes`);
    return v;
  }
  throw new TypeError(`bsvz-proofs: ${what} must be a bigint or Uint8Array`);
}

function labelBytes(label) {
  if (typeof label === 'string') return new TextEncoder().encode(label);
  if (label instanceof Uint8Array) return label;
  throw new TypeError('bsvz-proofs: label must be a string or Uint8Array');
}

export async function createProofs({ wasmBytes } = {}) {
  const bytes = wasmBytes ?? (await defaultWasmBytes());
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const m = instance.exports;
  if (typeof m.zkp_version !== 'function') {
    throw new Error('bsvz-proofs: not a bsvz_proofs.wasm module (missing zkp_version)');
  }

  // Memory helpers: always re-fetch the view, zkp_alloc can grow the buffer.
  const memView = () => new Uint8Array(m.memory.buffer);
  const write = (off, arr) => memView().set(arr, off);
  const read = (off, len) => memView().slice(off, off + len);

  // A fixed scratch frame for ephemeral IO buffers. Calls are synchronous and
  // single-threaded, so resetting per call is safe.
  const scratch = m.zkp_alloc(SCRATCH);
  if (scratch === null || scratch === undefined) throw new Error('bsvz-proofs: scratch alloc failed');
  let cursor = 0;
  function reset() {
    cursor = 0;
  }
  function take(n) {
    cursor += n;
    if (cursor > SCRATCH) throw new Error('bsvz-proofs: scratch overflow');
    return scratch + cursor - n;
  }
  function alloc(n) {
    const p = m.zkp_alloc(n);
    if (p === null || p === undefined) throw new Error('bsvz-proofs: zkp_alloc failed');
    return p;
  }
  function free(p, n) {
    m.zkp_free(p, n);
  }

  function proofError(rc) {
    let msg = '';
    try {
      const p = m.zkp_alloc(256);
      if (p !== null && p !== undefined) {
        msg = new TextDecoder().decode(read(p, m.zkp_last_error(p, 256)));
        m.zkp_free(p, 256);
      }
    } catch {}
    return new ProofError(rc, msg || `bsvz-proofs error code ${rc}`);
  }

  // --- scalar helpers -----------------------------------------------------

  const scalar = {
    random() {
      reset();
      const pO = take(SCALAR_LEN);
      m.zkp_scalar_random(pO);
      return read(pO, SCALAR_LEN);
    },
    fromBytes(b) {
      reset();
      const pI = take(SCALAR_LEN);
      write(pI, bytesOf(b, SCALAR_LEN, 'scalar'));
      const pO = take(SCALAR_LEN);
      m.zkp_scalar_from_bytes(pI, pO);
      return read(pO, SCALAR_LEN);
    },
    fromInt(v) {
      reset();
      const pO = take(SCALAR_LEN);
      m.zkp_scalar_from_int(BigInt(v), pO);
      return read(pO, SCALAR_LEN);
    },
    toInt(s) {
      reset();
      const pI = take(SCALAR_LEN);
      write(pI, bytesOf(s, SCALAR_LEN, 'scalar'));
      return BigInt.asUintN(64, m.zkp_scalar_to_int(pI));
    },
    isZero(s) {
      reset();
      const pI = take(SCALAR_LEN);
      write(pI, bytesOf(s, SCALAR_LEN, 'scalar'));
      return m.zkp_scalar_is_zero(pI) === 1;
    },
    eq(a, b) {
      reset();
      const pA = take(SCALAR_LEN);
      write(pA, bytesOf(a, SCALAR_LEN, 'scalar'));
      const pB = take(SCALAR_LEN);
      write(pB, bytesOf(b, SCALAR_LEN, 'scalar'));
      return m.zkp_scalar_eq(pA, pB) === 1;
    },
    add(a, b) { return scalarBin(m.zkp_scalar_add, a, b); },
    sub(a, b) { return scalarBin(m.zkp_scalar_sub, a, b); },
    mul(a, b) { return scalarBin(m.zkp_scalar_mul, a, b); },
    neg(a) { return scalarUn(m.zkp_scalar_neg, a); },
    invert(a) {
      reset();
      const pA = take(SCALAR_LEN);
      write(pA, bytesOf(a, SCALAR_LEN, 'scalar'));
      const pO = take(SCALAR_LEN);
      const rc = m.zkp_scalar_invert(pA, pO);
      if (rc !== 0) throw proofError(rc);
      return read(pO, SCALAR_LEN);
    },
  };

  function scalarBin(fn, a, b) {
    reset();
    const pA = take(SCALAR_LEN);
    write(pA, bytesOf(a, SCALAR_LEN, 'scalar'));
    const pB = take(SCALAR_LEN);
    write(pB, bytesOf(b, SCALAR_LEN, 'scalar'));
    const pO = take(SCALAR_LEN);
    fn(pA, pB, pO);
    return read(pO, SCALAR_LEN);
  }

  function scalarUn(fn, a) {
    reset();
    const pA = take(SCALAR_LEN);
    write(pA, bytesOf(a, SCALAR_LEN, 'scalar'));
    const pO = take(SCALAR_LEN);
    fn(pA, pO);
    return read(pO, SCALAR_LEN);
  }

  // --- point helpers ------------------------------------------------------

  const point = {
    add(a, b) { return pointBin(m.zkp_point_add, a, b); },
    sub(a, b) { return pointBin(m.zkp_point_sub, a, b); },
    negate(a) { return pointUn(m.zkp_point_negate, a); },
    mul(p, k) {
      reset();
      const pP = take(POINT_LEN);
      write(pP, bytesOf(p, POINT_LEN, 'point'));
      const pK = take(SCALAR_LEN);
      write(pK, bytesOf(k, SCALAR_LEN, 'scalar'));
      const pO = take(POINT_LEN);
      const rc = m.zkp_point_mul(pP, pK, pO);
      if (rc !== 0) throw proofError(rc);
      return read(pO, POINT_LEN);
    },
    eq(a, b) {
      reset();
      const pA = take(POINT_LEN);
      write(pA, bytesOf(a, POINT_LEN, 'point'));
      const pB = take(POINT_LEN);
      write(pB, bytesOf(b, POINT_LEN, 'point'));
      return m.zkp_point_eq(pA, pB) === 1;
    },
  };

  function pointBin(fn, a, b) {
    reset();
    const pA = take(POINT_LEN);
    write(pA, bytesOf(a, POINT_LEN, 'point'));
    const pB = take(POINT_LEN);
    write(pB, bytesOf(b, POINT_LEN, 'point'));
    const pO = take(POINT_LEN);
    const rc = fn(pA, pB, pO);
    if (rc !== 0) throw proofError(rc);
    return read(pO, POINT_LEN);
  }

  function pointUn(fn, a) {
    reset();
    const pA = take(POINT_LEN);
    write(pA, bytesOf(a, POINT_LEN, 'point'));
    const pO = take(POINT_LEN);
    const rc = fn(pA, pO);
    if (rc !== 0) throw proofError(rc);
    return read(pO, POINT_LEN);
  }

  // --- transcript / generators -------------------------------------------

  const transcript = {
    sha256(data) {
      reset();
      const p = take(data.length);
      write(p, data);
      const o = take(SCALAR_LEN);
      m.zkp_sha256(p, data.length, o);
      return read(o, SCALAR_LEN);
    },
    sha256d(data) {
      reset();
      const p = take(data.length);
      write(p, data);
      const o = take(SCALAR_LEN);
      m.zkp_sha256d(p, data.length, o);
      return read(o, SCALAR_LEN);
    },
    challenge(label, points, scalars) {
      reset();
      const enc = labelBytes(label);
      const pL = take(enc.length);
      write(pL, enc);
      const pP = take(points.length * POINT_LEN);
      points.forEach((pt, i) => write(pP + i * POINT_LEN, bytesOf(pt, POINT_LEN, 'point')));
      const pS = take(scalars.length * SCALAR_LEN);
      scalars.forEach((s, i) => write(pS + i * SCALAR_LEN, bytesOf(s, SCALAR_LEN, 'scalar')));
      const o = take(SCALAR_LEN);
      const rc = m.zkp_challenge(pL, enc.length, pP, points.length, pS, scalars.length, o);
      if (rc !== 0) throw proofError(rc);
      return read(o, SCALAR_LEN);
    },
  };

  const generators = {
    hashToPoint(domain) {
      reset();
      const enc = typeof domain === 'string' ? new TextEncoder().encode(domain) : new Uint8Array(domain);
      const p = take(enc.length);
      write(p, enc);
      const o = take(POINT_LEN);
      const rc = m.zkp_hash_to_point(p, enc.length, o);
      if (rc !== 0) throw proofError(rc);
      return read(o, POINT_LEN);
    },
    vector(domain, n) {
      const enc = typeof domain === 'string' ? new TextEncoder().encode(domain) : new Uint8Array(domain);
      const size = n * POINT_LEN;
      const pD = take(enc.length);
      write(pD, enc);
      const pO = alloc(size);
      const rc = m.zkp_generator_vector(pD, enc.length, n, pO);
      const out = rc === 0 ? read(pO, size) : null;
      free(pO, size);
      if (out === null) throw proofError(rc);
      return out;
    },
    G() {
      reset();
      const o = take(POINT_LEN);
      m.zkp_generator_G(o);
      return read(o, POINT_LEN);
    },
    H() {
      reset();
      const o = take(POINT_LEN);
      m.zkp_generator_H(o);
      return read(o, POINT_LEN);
    },
    BP_U() {
      reset();
      const o = take(POINT_LEN);
      m.zkp_generator_BP_U(o);
      return read(o, POINT_LEN);
    },
  };

  // --- pedersen -----------------------------------------------------------

  const pedersen = {
    commit(value, blinding) {
      reset();
      const pV = take(SCALAR_LEN);
      write(pV, bytesOf(value, SCALAR_LEN, 'value'));
      const pB = take(SCALAR_LEN);
      write(pB, bytesOf(blinding, SCALAR_LEN, 'blinding'));
      const o = take(POINT_LEN);
      m.zkp_commit(pV, pB, o);
      return read(o, POINT_LEN);
    },
    commitWithGens(value, blinding, g, h) {
      reset();
      const pV = take(SCALAR_LEN);
      write(pV, bytesOf(value, SCALAR_LEN, 'value'));
      const pB = take(SCALAR_LEN);
      write(pB, bytesOf(blinding, SCALAR_LEN, 'blinding'));
      const pG = take(POINT_LEN);
      write(pG, bytesOf(g, POINT_LEN, 'g'));
      const pH = take(POINT_LEN);
      write(pH, bytesOf(h, POINT_LEN, 'h'));
      const o = take(POINT_LEN);
      const rc = m.zkp_commit_with_gens(pV, pB, pG, pH, o);
      if (rc !== 0) throw proofError(rc);
      return read(o, POINT_LEN);
    },
    verify(commitment, value, blinding) {
      const pC = take(POINT_LEN);
      write(pC, bytesOf(commitment, POINT_LEN, 'commitment'));
      const pV = take(SCALAR_LEN);
      write(pV, bytesOf(value, SCALAR_LEN, 'value'));
      const pB = take(SCALAR_LEN);
      write(pB, bytesOf(blinding, SCALAR_LEN, 'blinding'));
      return m.zkp_commit_verify(pC, pV, pB) === 1;
    },
    add(a, b) { return pointBin(m.zkp_commit_add, a, b); },
    sub(a, b) { return pointBin(m.zkp_commit_sub, a, b); },
  };

  // --- schnorr -------------------------------------------------------------

  const schnorr = {
    prove(label, base, p, x) {
      reset();
      const enc = labelBytes(label);
      const pL = take(enc.length);
      write(pL, enc);
      const pB = take(POINT_LEN);
      write(pB, bytesOf(base, POINT_LEN, 'base'));
      const pP = take(POINT_LEN);
      write(pP, bytesOf(p, POINT_LEN, 'p'));
      const pX = take(SCALAR_LEN);
      write(pX, bytesOf(x, SCALAR_LEN, 'x'));
      const pA = take(POINT_LEN);
      const pS = take(SCALAR_LEN);
      const rc = m.zkp_schnorr_prove(pL, enc.length, pB, pP, pX, pA, pS);
      if (rc !== 0) throw proofError(rc);
      return { a: read(pA, POINT_LEN), s: read(pS, SCALAR_LEN) };
    },
    verify(label, base, p, a, s) {
      reset();
      const enc = labelBytes(label);
      const pL = take(enc.length);
      write(pL, enc);
      const pB = take(POINT_LEN);
      write(pB, bytesOf(base, POINT_LEN, 'base'));
      const pP = take(POINT_LEN);
      write(pP, bytesOf(p, POINT_LEN, 'p'));
      const pA = take(POINT_LEN);
      write(pA, bytesOf(a, POINT_LEN, 'a'));
      const pS = take(SCALAR_LEN);
      write(pS, bytesOf(s, SCALAR_LEN, 's'));
      return m.zkp_schnorr_verify(pL, enc.length, pB, pP, pA, pS) === 1;
    },
  };

  // --- CDS one-out-of-many --------------------------------------------------

  function statementsOf(list, what) {
    const flat = new Uint8Array(list.length * POINT_LEN);
    list.forEach((s, i) => flat.set(bytesOf(s, POINT_LEN, what + '[' + i + ']'), i * POINT_LEN));
    return flat;
  }

  const cdsOr = {
    size(n) {
      return m.zkp_cds_or_size(n);
    },
    prove(label, base, statements, trueIndex, witness) {
      const n = statements.length;
      reset();
      const enc = labelBytes(label);
      const pL = take(enc.length);
      write(pL, enc);
      const pB = take(POINT_LEN);
      write(pB, bytesOf(base, POINT_LEN, 'base'));
      const pSt = take(n * POINT_LEN);
      write(pSt, statementsOf(statements, 'statement'));
      const pW = take(SCALAR_LEN);
      write(pW, bytesOf(witness, SCALAR_LEN, 'witness'));
      const pA = alloc(n * POINT_LEN);
      const pE = alloc(n * SCALAR_LEN);
      const pS = alloc(n * SCALAR_LEN);
      const rc = m.zkp_cds_or_prove(pL, enc.length, pB, pSt, n, trueIndex, pW, pA, pE, pS);
      const out = rc === 0
        ? { a: read(pA, n * POINT_LEN), e: read(pE, n * SCALAR_LEN), s: read(pS, n * SCALAR_LEN) }
        : null;
      free(pA, n * POINT_LEN);
      free(pE, n * SCALAR_LEN);
      free(pS, n * SCALAR_LEN);
      if (out === null) throw proofError(rc);
      return out;
    },
    verify(label, base, statements, a, e, s) {
      const n = statements.length;
      reset();
      const enc = labelBytes(label);
      const pL = take(enc.length);
      write(pL, enc);
      const pB = take(POINT_LEN);
      write(pB, bytesOf(base, POINT_LEN, 'base'));
      const pSt = take(n * POINT_LEN);
      write(pSt, statementsOf(statements, 'statement'));
      const pA = alloc(n * POINT_LEN);
      const pE = alloc(n * SCALAR_LEN);
      const pS = alloc(n * SCALAR_LEN);
      write(pA, bytesOf(a, n * POINT_LEN, 'a'));
      write(pE, bytesOf(e, n * SCALAR_LEN, 'e'));
      write(pS, bytesOf(s, n * SCALAR_LEN, 's'));
      const ok = m.zkp_cds_or_verify(pL, enc.length, pB, pSt, n, pA, pE, pS) === 1;
      free(pA, n * POINT_LEN);
      free(pE, n * SCALAR_LEN);
      free(pS, n * SCALAR_LEN);
      return ok;
    },
  };

  // --- linear range proof ---------------------------------------------------

  const range = {
    size(bits) {
      return m.zkp_range_size(bits);
    },
    prove(value, blinding, bits) {
      reset();
      const pV = take(SCALAR_LEN);
      write(pV, bytesOf(value, SCALAR_LEN, 'value'));
      const pB = take(SCALAR_LEN);
      write(pB, bytesOf(blinding, SCALAR_LEN, 'blinding'));
      const size = m.zkp_range_size(bits);
      const pOut = alloc(size);
      const rc = m.zkp_range_prove(pV, pB, bits, pOut);
      const proof = rc === 0 ? read(pOut, size) : null;
      free(pOut, size);
      if (proof === null) throw proofError(rc);
      return { commitment: pedersen.commit(value, blinding), proof };
    },
    verify(commitment, proof, bits) {
      reset();
      const pC = take(POINT_LEN);
      write(pC, bytesOf(commitment, POINT_LEN, 'commitment'));
      const pPr = alloc(proof.length);
      write(pPr, proof);
      const ok = m.zkp_range_verify(pC, pPr, bits) === 1;
      free(pPr, proof.length);
      return ok;
    },
  };

  // --- bulletproof range ----------------------------------------------------

  const rangeBp = {
    size(bits) {
      return m.zkp_range_bp_size(bits);
    },
    prove(value, blinding, bits) {
      reset();
      const pV = take(SCALAR_LEN);
      write(pV, bytesOf(value, SCALAR_LEN, 'value'));
      const pB = take(SCALAR_LEN);
      write(pB, bytesOf(blinding, SCALAR_LEN, 'blinding'));
      const size = m.zkp_range_bp_size(bits);
      const pOut = alloc(size);
      const rc = m.zkp_range_bp_prove(pV, pB, bits, pOut);
      const out = rc === 0 ? read(pOut, size) : null;
      free(pOut, size);
      if (out === null) throw proofError(rc);
      return {
        commitment: out.slice(0, POINT_LEN),
        proof: out.slice(POINT_LEN),
      };
    },
    verify(commitment, proof, bits) {
      reset();
      const pC = take(POINT_LEN);
      write(pC, bytesOf(commitment, POINT_LEN, 'commitment'));
      const pPr = alloc(proof.length);
      write(pPr, proof);
      const ok = m.zkp_range_bp_verify(pC, pPr, bits) === 1;
      free(pPr, proof.length);
      return ok;
    },
  };

  // --- membership -----------------------------------------------------------

  const membership = {
    size(n) {
      return m.zkp_membership_size(n);
    },
    prove(commitment, blinding, set, value) {
      const n = set.length;
      reset();
      const pC = take(POINT_LEN);
      write(pC, bytesOf(commitment, POINT_LEN, 'commitment'));
      const pB = take(SCALAR_LEN);
      write(pB, bytesOf(blinding, SCALAR_LEN, 'blinding'));
      const pS = take(n * SCALAR_LEN);
      const setFlat = new Uint8Array(n * SCALAR_LEN);
      set.forEach((s, i) => setFlat.set(bytesOf(s, SCALAR_LEN, 'set[' + i + ']'), i * SCALAR_LEN));
      write(pS, setFlat);
      const pV = take(SCALAR_LEN);
      write(pV, bytesOf(value, SCALAR_LEN, 'value'));
      const pA = alloc(n * POINT_LEN);
      const pE = alloc(n * SCALAR_LEN);
      const pS2 = alloc(n * SCALAR_LEN);
      const rc = m.zkp_membership_prove(pC, pB, pS, n, pV, pA, pE, pS2);
      const out = rc === 0
        ? { a: read(pA, n * POINT_LEN), e: read(pE, n * SCALAR_LEN), s: read(pS2, n * SCALAR_LEN) }
        : null;
      free(pA, n * POINT_LEN);
      free(pE, n * SCALAR_LEN);
      free(pS2, n * SCALAR_LEN);
      if (out === null) throw proofError(rc);
      return out;
    },
    verify(commitment, set, a, e, s) {
      const n = set.length;
      reset();
      const pC = take(POINT_LEN);
      write(pC, bytesOf(commitment, POINT_LEN, 'commitment'));
      const pS = take(n * SCALAR_LEN);
      const setFlat = new Uint8Array(n * SCALAR_LEN);
      set.forEach((sc, i) => setFlat.set(bytesOf(sc, SCALAR_LEN, 'set[' + i + ']'), i * SCALAR_LEN));
      write(pS, setFlat);
      const pA = alloc(n * POINT_LEN);
      const pE = alloc(n * SCALAR_LEN);
      const pS2 = alloc(n * SCALAR_LEN);
      write(pA, bytesOf(a, n * POINT_LEN, 'a'));
      write(pE, bytesOf(e, n * SCALAR_LEN, 'e'));
      write(pS2, bytesOf(s, n * SCALAR_LEN, 's'));
      const ok = m.zkp_membership_verify(pC, pS, n, pA, pE, pS2) === 1;
      free(pA, n * POINT_LEN);
      free(pE, n * SCALAR_LEN);
      free(pS2, n * SCALAR_LEN);
      return ok;
    },
  };

  // --- conservation ---------------------------------------------------------

  function pointsFlat(list) {
    return statementsOf(list, 'commitment');
  }

  const conservation = {
    prove(inputs, outputs, excess) {
      reset();
      const pI = take(inputs.length * POINT_LEN);
      write(pI, pointsFlat(inputs));
      const pO = take(outputs.length * POINT_LEN);
      write(pO, pointsFlat(outputs));
      const pE = take(SCALAR_LEN);
      write(pE, bytesOf(excess, SCALAR_LEN, 'excess'));
      const pA = take(POINT_LEN);
      const pS = take(SCALAR_LEN);
      const rc = m.zkp_conservation_prove(pI, inputs.length, pO, outputs.length, pE, pA, pS);
      if (rc !== 0) throw proofError(rc);
      return { a: read(pA, POINT_LEN), s: read(pS, SCALAR_LEN) };
    },
    verify(inputs, outputs, a, s) {
      reset();
      const pI = take(inputs.length * POINT_LEN);
      write(pI, pointsFlat(inputs));
      const pO = take(outputs.length * POINT_LEN);
      write(pO, pointsFlat(outputs));
      const pA = take(POINT_LEN);
      write(pA, bytesOf(a, POINT_LEN, 'a'));
      const pS = take(SCALAR_LEN);
      write(pS, bytesOf(s, SCALAR_LEN, 's'));
      return m.zkp_conservation_verify(pI, inputs.length, pO, outputs.length, pA, pS) === 1;
    },
  };

  // --- lifecycle ------------------------------------------------------------

  const api = {
    version: () => m.zkp_version(),
    seed(entropy) {
      const bytes = entropy ?? randomBytes(64);
      if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > 64) {
        throw new TypeError('bsvz-proofs: seed expects 1..64 bytes');
      }
      reset();
      const p = take(bytes.length);
      write(p, bytes);
      const rc = m.zkp_seed(p, bytes.length);
      if (rc !== 0) throw proofError(rc);
    },
    setRngForTesting(seed) {
      m.zkp_set_rng_for_testing(BigInt(seed));
    },
    setRngForTestingOff() {
      m.zkp_set_rng_for_testing_off();
    },
    lastError() {
      const p = alloc(256);
      const n = m.zkp_last_error(p, 256);
      const msg = new TextDecoder().decode(read(p, n));
      free(p, 256);
      return msg;
    },
    alloc,
    free,
    // low-level access to the raw shim and linear memory
    raw: m,
    memView,
    scalar,
    point,
    transcript,
    generators,
    pedersen,
    schnorr,
    cdsOr,
    range,
    rangeBp,
    membership,
    conservation,
  };

  return api;
}

export default createProofs;
