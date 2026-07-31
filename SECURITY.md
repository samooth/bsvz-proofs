# Security

## Status

This library implements standard, publicly-vetted cryptographic constructions,
but it is a from-scratch implementation and has **not been independently
audited**. Do not use it in production or where real funds are at stake until:

- the code has been reviewed by a qualified cryptography engineer, and
- the dependency chain (`bsvz`, the Zig standard library crypto) has been
  validated for the deployment target.

## Threat model

Assumed adversary: a computationally bounded (PPT) adversary who may

- observe transcripts and proofs,
- modify in-flight messages (including commitments and proofs),
- act as a malicious verifier or a malicious prover (trying to forge proofs),

but cannot solve the discrete-logarithm problem in the secp256k1 group, cannot
find SHA-256 collisions/preimages, and cannot predict or influence the
randomness source.

Under this model the provided schemes claim the standard properties:

| Scheme | Property |
| --- | --- |
| Pedersen commitment | Perfectly hiding, computationally binding, additively homomorphic |
| Schnorr PoK | Special-sound, honest-verifier zero-knowledge (HVZK) |
| CDS-OR | Special-sound, HVZK |
| Linear range proof | Sound, HVZK, proof of knowledge of the opening with `v ∈ [0, 2^bits)` |
| Bulletproofs range proof | Sound, HVZK, proof of knowledge of the opening with `v ∈ [0, 2^bits)` (inner-product argument, `O(log bits)` verification) |
| Membership proof | Sound, HVZK, zero-knowledge about which set element is committed |
| Conservation proof | Sound, HVZK; reveals only that the books balance |

## Known limitations
2. **No side-channel hardening.** Field and group arithmetic comes from the Zig
   standard library and `bsvz`; the scalar rejection-sampling loop
   (`src/scalar.zig`) reveals the number of rejection iterations. Verify the
   mitigation level of the underlying libraries for your deployment.
3. **Process-global CSPRNG.** `src/random.zig` uses a single seeded ChaCha20
   instance behind a spinlock. It is thread-safe but does not fork-reseed
   (duplicate the process and both children continue the same stream). Consider
   `atfork`/re-seed handling in long-running, forking services.
4. **Not constant-time by construction.** The proof code itself does not branch
   on secrets (bit decomposition is index-based), but we do not assert this
   property on all optimized backends.

## Operational guidance

- Always pass a **unique, versioned domain string** as the challenge `label`
  and/or to `generators.hashToPoint`. Reuse across protocols enables
  cross-protocol attacks.
- Prover and verifier must construct the **identical challenge** (same label,
  same points and scalars, same order). Bind all public context (public keys,
  commitments, parameters) into the challenge inputs before extracting it.
- Never reuse a commitment blinding `r` across different values or different
  protocols — this breaks the commitment's binding and can leak the value.
- Use rejection-sampled scalars (`Scalar.random()`) for blindings and nonces.
  Never reuse a Schnorr nonce `k` (it leaks the secret).
- `linearProve` and `proveRangeBP` validate that `value < 2^num_bits` and
  `num_bits ∈ [1, 256]` (Bulletproofs additionally require a power-of-two);
  treat `error.ValueOutOfRange` / `error.InvalidRangeBits` as prover-side bugs.
- Before relying on a range proof in an application, confirm that the
  commitment the verifier validates is bound to the application context through
  the challenge (the proof binds `G`, `H`, `num_bits`, and the commitment
  automatically, but you must still bind any surrounding application data).
- The recommended dependency hash in `build.zig.zon` pins `bsvz` to a specific
  revision; do not switch to floating references.

## Reporting

If you find a security issue, contact the repository owner privately. Do not
open a public issue for a vulnerability. Include a minimal reproducer and the
affected schemes.
