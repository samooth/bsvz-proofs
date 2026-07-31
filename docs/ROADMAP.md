# Roadmap

Status of `bsvz-zkp` vs the production-integration goals of an AnchorChain
privacy backend.

## Done

- [x] Pedersen commitments (default + explicit generators, homomorphic ops)
- [x] Schnorr PoK and CDS-OR one-of-many proofs (label-bound, AnchorChain bytes)
- [x] Linear range proofs, `1 ≤ bits ≤ 256`, AnchorChain blinding scheme
- [x] Bulletproofs (inner-product argument), power-of-two bits ≤ 256
- [x] Membership proof (CDS-OR over `C − s_k·G`)
- [x] Conservation proof (Schnorr PoK of `log_H(net)`), empty tx rejected
- [x] AnchorChain byte-compatibility verified via `crosscheck/run.sh`
- [x] Test suites for all six primitives (53 tests), Debug + ReleaseSafe
- [x] Unbiased rejection-sampled scalars; test-only injectable RNG

## Next (Phase 2 — integration hardening)

- [ ] Versioned binary serialization of every proof type
      (`LinearRangeProof`, `RangeProofBP`, `MembershipProof`, CDS-OR, Schnorr)
      with size prefixes and tag bytes, mirroring AnchorChain's serializers.
- [ ] Persistent golden test vectors (JSON fixture of the `crosscheck` output)
      so regressions are caught without a Node toolchain.
- [ ] Fork-safe CSPRNG: re-seed the process-wide ChaCha20 on `fork` (or expose a
      per-thread/per-session RNG) to avoid stream duplication in daemons.
- [ ] Benchmarks (`zig build bench`): prove/verify times and proof sizes for the
      linear proof at 64/128/256 bits and Bulletproofs at 64/256 bits.

## Later (Phase 3 — scaling & audits)

- [ ] Aggregation/range batching: prove many commitments in one transcript.
- [ ] Batch verification for many CDS-OR / Schnorr proofs (multi-scalar tricks).
- [ ] Public-API review and semver stabilization (`0.1.0`).
- [ ] Third-party security audit of the whole crate + dependency chain.
