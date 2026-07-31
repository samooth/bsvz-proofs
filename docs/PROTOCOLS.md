# Protocol specification

This document specifies the cryptographic protocols implemented in `bsvz-zkp`.
All arithmetic is over the secp256k1 curve:

- group order `L` (the order of the base point `G`)
- two independent generators `G` (curve base point) and `H`
  (`H` derived from `"AnchorChain/pedersen/H/v1"`, see below)

All encodings and challenges are **byte-for-byte identical** to the AnchorChain
`privacy` TypeScript implementation, so proofs produced by either library verify
on the other (for identical witnesses/nonces).

Notation: `·` denotes scalar-point multiplication, `+` point addition,
`mod L` for scalar arithmetic. Scalars are written lowercase, points uppercase.

---

## 1. Generator derivation

`hashToPoint(domain)` is the AnchorChain try-and-increment hash-to-curve:
for `counter = 0, 1, 2, ...` hash `SHA-256d(domain + ":" + counter)` (double
SHA-256), interpret the digest as an x-coordinate, and try the compressed
encodings with the even-`y` (`0x02`) prefix first, then the odd-`y` (`0x03`)
prefix. The first encoding that decompresses to a valid curve point is
returned. No discrete-log relation between any two derived generators (or with
`G`) is known.

- `G` = secp256k1 base point.
- `H = hashToPoint("AnchorChain/pedersen/H/v1")` — the default Pedersen
  generator, matching AnchorChain's `CURVE_H`.
- `generatorVector(domain, n)` = `[hashToPoint(domain + "/" + i)]_{i<n}`.
- Bulletproofs use `g_i = hashToPoint("anchorchain/bp/g/v1/" + i)`,
  `h_i = hashToPoint("anchorchain/bp/h/v1/" + i)`, and
  `U = hashToPoint("anchorchain/bp/U/v1")`.

---

## 2. Pedersen commitment

```
commit(v, r) = v·G + r·H
```

- **Perfectly hiding:** for any `(v, r)` the commitment is a uniformly random
  group element when `r` is uniform.
- **Computationally binding:** opening to two different values would require a
  discrete-log relation between `G` and `H`.
- **Homomorphic:** `commit(v1,r1) + commit(v2,r2) = commit(v1+v2, r1+r2)` and
  `commit(v1,r1) - commit(v2,r2) = commit(v1-v2, r1-r2)`.

`commit(0, 0)` is the identity and is **not** a usable commitment (mirroring
AnchorChain's rejection). Range proofs avoid it by construction.

---

## 3. Fiat–Shamir transcript

The challenge is the double-SHA-256 of a domain label followed by the canonical
encodings of every public point and scalar in the statement and the prover's
commitments, reduced mod `L`, with a (negligible) zero challenge mapped to `1`:

```
challenge(label, points, scalars) =
    scalarMod_L( SHA-256d( label_utf8
                           || sec1(p_0) || ... || sec1(p_{k-1})
                           || s_0_be32 || ... || s_{m-1}_be32 ) )
    // 0 -> 1
```

- `sec1(p)` is the 33-byte compressed SEC1 encoding of a point.
- `s_be32` is the 32-byte big-endian encoding of a scalar reduced mod `L`.

This is byte-for-byte AnchorChain's `challenge`. The incremental `Hasher`
builder (`init(label)`, `addPoint(s)`, `addScalar(s)`, `finish`) produces the
same bytes without concatenating, so proofs can hash `[base, ...statements,
...a]` without allocation.

---

## 4. Schnorr proof of knowledge

Statement: given `P`, prove knowledge of `x` with `P = x·base`.

**Prover** (`label`, `base`, `P`, `x`):
1. `k ←_$ [1, L)`, `a = k·base`
2. `e = challenge(label, [base, P, a])`
3. `s = k + e·x  (mod L)`
4. proof = `(a, s)`

**Verifier** (`label`, `base`, `P`, `(a, s)`):
1. `e = challenge(label, [base, P, a])`
2. accept iff `s·base == a + e·P`

Soundness error `1/L`; special-sound (knowledge extractor rewinds on two
challenges); HVZK.

---

## 5. CDS-OR proof (one-of-many discrete log)

Statement: given `P_0, ..., P_{n-1}` prove knowledge of `x` such that
`P_j = x·base` for some `j`, without revealing `j`.

**Prover** (`label`, `base`, `statements`, `true_index`, `witness`):

1. `k ←_$ [1, L)`; `a_t = k·base` for the known branch `t = true_index`.
2. For each fake branch `j ≠ t`: `e_j ←_$ [1, L)`, `s_j ←_$ [1, L)`,
   `a_j = s_j·base - e_j·P_j`.
3. `e_total = challenge(label, [base, P_0, ..., P_{n-1}, a_0, ..., a_{n-1}])`.
4. `e_t = e_total - Σ_{j≠t} e_j  (mod L)`, `s_t = k + e_t·x  (mod L)`.
5. Proof = `({a_j}, {e_j}, {s_j})`.

**Verifier** (`label`, `base`, `statements`, proof):
1. `e_total = challenge(label, [base, ...statements, ...a])`.
2. Reject unless `Σ_j e_j == e_total  (mod L)`.
3. For each `j`, reject unless `s_j·base == a_j + e_j·P_j`.

Soundness: a prover that does not know any discrete log can only succeed by
guessing a challenge decomposition, probability `1/L`. HVZK via simulation.

---

## 6. Linear range proof

Statement: given a Pedersen commitment `C`, prove knowledge of `(v, r)` with
`C = v·G + r·H` and `0 <= v < 2^bits` (`1 <= bits <= 256`).

### Prover

1. Reject unless `1 <= bits <= 256` and `0 <= v < 2^bits`.
2. `C = commit(v, r)`.
3. Per-bit blindings, with `r_0` chosen last so `Σ_i 2^i·r_i == r`:
   for `i = 1..bits-1`: `r_i ←_$ [1, L)`, and
   `r_0 = r - Σ_{i>=1} 2^i·r_i  (mod L)`. If `b_0 = 0` and `r_0 = 0`
   (a `commit(0, 0)`; negligible), retry with fresh `r_i`.
4. Decompose `v = Σ_i 2^i·b_i`; `C_i = commit(b_i, r_i)`.
5. For each bit `i`, a CDS-OR proof with generator `H` over
   `statements = [C_i, C_i - G]`, proving knowledge of `r_i` such that
   `C_i = r_i·H` (`b_i = 0`) or `C_i - G = r_i·H` (`b_i = 1`). The label is
   `anchorchain/privacy/range/bit/{i}` (index inside the label separates bits).

Proof = `(bits, {C_i}, {CDS-OR_i})`, plus the commitment `C`.

### Verifier

1. Reject unless `1 <= bits <= 256` and `|{C_i}| = |{proofs}| = bits`.
2. Reject unless `Σ_i 2^i·C_i == C`.
3. For each `i`, reconstruct `statements = [C_i, C_i - G]` and verify the
   CDS-OR proof with generator `H` and label `anchorchain/privacy/range/bit/{i}`.

### Soundness / zero-knowledge

Step 2 binds `C` to the bit commitments, so `v = Σ_i 2^i·b_i`; each CDS-OR
proof forces `b_i ∈ {0,1}`; hence `0 <= v < 2^bits`. The proofs are HVZK and
the bit commitments perfectly hiding. Complexity: proof size and both
prover/verifier work are `O(bits)`.

---

## 7. Bulletproofs range proof (inner-product argument)

A logarithmic range proof of the same statement. Requires `bits` to be a power
of two in `(0, 256]` and `0 <= v < 2^bits`. Ported line-for-line from
AnchorChain's `bulletproofs.ts`.

**Setup:** `g = generatorVector("anchorchain/bp/g/v1", n)`,
`h = generatorVector("anchorchain/bp/h/v1", n)`, `U = BP_U`, `n = bits`.

**Prover:**
1. `aL_i = bit_i(v)`, `aR_i = aL_i - 1`, so `aL∘aR = 0`.
2. `alpha, rho, tau1, tau2 ←_$ [1, L)`; `sL, sR ←_$ [1, L)^n`.
3. `A = alpha·H + Σ aL_i·g_i + Σ aR_i·h_i`
4. `S = rho·H + Σ sL_i·g_i + Σ sR_i·h_i`
5. `y = challenge("anchorchain/bp/y", [A, S])`;
   `z = challenge("anchorchain/bp/z", [A, S])`.
6. `l(X) = (aL − z·1) + sL·X`;
   `r(X) = y^n∘(aR + z·1) + z²·2^n + (y^n∘sR)·X`.
7. `t1 = <l0, r1> + <l1, r0>`, `t2 = <l1, r1>`;
   `T1 = t1·G + tau1·H`, `T2 = t2·G + tau2·H`.
8. `x = challenge("anchorchain/bp/x", [T1, T2])`.
9. `tHat = <l0 + x·l1, r0 + x·r1>`,
   `taux = tau2·x² + tau1·x + z²·r`,
   `mu = alpha + rho·x`.
10. `h'_i = (y^{-i})·h_i`; inner-product argument on `(g, h', U, l, r)`.

**Verifier:**
1. Recompute `y, z, x` and `y^n, 2^n, z², z³, x²`.
2. `delta(y,z) = (z − z²)·<1, y^n> − z³·<1, 2^n>`.
3. Check `tHat·G + taux·H == z²·C + delta·G + x·T1 + x²·T2`.
4. `P = A + x·S − z·Σg_i + Σ(z·y^i + z²·2^i)·h'_i`;
   `P_IP = P − mu·H + tHat·U`.
5. Verify the inner-product argument against `P_IP`.

**Inner-product argument:** folds the `2n`-length witness in `log2(n)` rounds.
Round `j`:
- `cL = <aLo, bHi>`, `cR = <aHi, bLo>`;
  `L_j = Σ aLo_i·gHi_i + Σ bHi_i·hLo_i + cL·U`,
  `R_j = Σ aHi_i·gLo_i + Σ bLo_i·hHi_i + cR·U`.
- `u = challenge("anchorchain/bp/ip/" + j, [L_j, R_j])`.
- fold: `g' = u^{-1}·gLo + u·gHi`, `h' = u·hLo + u^{-1}·hHi`,
  `a' = aLo·u + aHi·u^{-1}`, `b' = bLo·u^{-1} + bHi·u`.

Verification folds `g, h` the same way, updates `P ← u²·L_j + P + u^{-2}·R_j`,
and finally checks `P == a·g_0 + b·h_0 + (a·b)·U`.

Sound and zero-knowledge under discrete log in the random-oracle model; no
trusted setup; no post-quantum claim. Proof size is `O(log n)`.

---

## 8. Membership proof

Statement: a commitment `C = v·G + r·H` hides a value `v` in a **public** set
`{s_0, ..., s_{m-1}}`, without revealing which.

For each `s_k`, `P_k = C − s_k·G`; if `v = s_k` then `P_k = r·H`, so the prover
knows its discrete log w.r.t. `H`. A single CDS-OR proof with generator `H`,
statements `[P_k]`, label `anchorchain/privacy/membership/v1` proves "I know
`log_H(P_k)` for some `k`". Linear in `|set|`. Sound and zero-knowledge under
discrete log in the random-oracle model.

---

## 9. Conservation proof

Statement: given input commitments `I_j` and output commitments `O_k`, the
net commitment `D = Σ I_j − Σ O_k` has no `G` component — i.e. the books
balance.

If value is conserved, `D = r·H` with `r = Σ r_in − Σ r_out`, and a Schnorr
proof with generator `H`, statement `D`, label
`anchorchain/privacy/conservation/v1` proves knowledge of `log_H(D)`. This is
possible **iff** `D` has no `G` component (Pedersen binding). The verifier
learns only that the books balance. The empty transaction is rejected.

---

## 10. Randomness

- `Scalar.random()` returns a uniformly random scalar in `[1, L)` via rejection
  sampling over 32-byte blocks (unbiased — strictly better than AnchorChain's
  reduced-mod-`n` sampling).
- The CSPRNG is a process-wide ChaCha20 seeded once from OS entropy
  (`src/random.zig`), with a test-only injectable RNG for reproducibility.
