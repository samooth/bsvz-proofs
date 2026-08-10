# Comparison: `bsvz-proofs` (Zig) vs AnchorChain `privacy` (TypeScript)

Reference clone: https://github.com/prof-faustus/anchorchain (the `privacy`
package, plus its `bsv` curve wrapper). `bsvz-proofs` is now a **byte-for-byte
port** of the AnchorChain privacy primitives: every public encoding, generator,
and Fiat–Shamir challenge is identical, so proofs produced by either library
verify on the other (see `crosscheck/`).

| primitive | bsvz-proofs (Zig) | AnchorChain privacy (TS) |
| --- | --- | --- |
| Pedersen commitments `C(v,r)=v·G+r·H` | `pedersen.zig` | `commit.ts` |
| Fiat–Shamir transcript | `transcript.zig` (`challenge()`/`Hasher`, SHA-256d) | `transcript.ts` (one-shot `challenge()`, SHA-256d) |
| Schnorr PoK of dlog | `sigma.zig` | `sigma.ts` (`proveDlog`) |
| CDS-OR one-of-many | `sigma.zig` | `sigma.ts` (`proveOneOfMany`) |
| Linear range proof `[0,2^bits)`, bits ≤ 256 | `rangeproof.zig` | `range.ts` |
| Bulletproofs (inner-product argument) | `bulletproofs.zig` | `bulletproofs.ts` |
| NUMS generators | `generators.zig` (`G`/`H`/`BP_U`/`g`/`h` vectors) | `genpoints.ts` + `CURVE_H` |
| Membership proof (value in public set) | `membership.zig` | `membership.ts` |
| Homomorphic conservation proof | `conservation.zig` | `conservation.ts` |

## Parity

- **Transcript.** Both use `SHA-256d(label ‖ sec1(points) ‖ scalars32)` with a
  zero challenge mapped to `1`. Identical bytes.
- **Generators.** Same try-and-increment `hashToPoint` (try `0x02` then `0x03`,
  counter suffix `:<i>`), same domains:
  `AnchorChain/pedersen/H/v1`, `anchorchain/bp/g/v1`, `anchorchain/bp/h/v1`,
  `anchorchain/bp/U/v1`. `G`, `H`, `BP_U` verified equal to the TS values.
- **Blinding scheme.** Both derive the *first* bit's blinding last:
  `r_0 = r − Σ_{i≥1} 2^i·r_i` (no scalar inverse), retrying when `commit(0,0)`
  would result. Same bit labels `anchorchain/privacy/range/bit/{i}`.
- **Range width.** Both support `1 ≤ bits ≤ 256` (256-bit via BigInt in TS, via
  u256 helpers in Zig).
- **Bulletproofs.** Full port of `bulletproofs.ts` including the inner-product
  argument, `delta(y,z)` check, `P' = u²L + P + u⁻²R` folding, and
  `h'_i = y⁻ⁱ·h_i` weighting. Same labels `anchorchain/bp/{y,z,x}` and
  `anchorchain/bp/ip/{round}`.
- **Membership / conservation.** Same constructions and labels
  (`anchorchain/privacy/membership/v1`, `anchorchain/privacy/conservation/v1`).

## Remaining deltas (documented differences)

| aspect | bsvz-proofs | AnchorChain |
| --- | --- | --- |
| Random scalar | **rejection sampling** over `u256 < L` (unbiased, `[1,L)`) | 32 random bytes reduced mod `n` (biased, zero rejected) |
| `commit(0,0)` | returns identity (documented as unusable) | throws |
| Hash-to-curve failure | panics after 100k counters | retries until success (also bound in practice) |
| Transcript API | incremental `Hasher` *and* one-shot `challenge()` | one-shot `challenge()` only |
| Range verify signature | `linearVerify(commitment, proof)` (default `G`/`H` bound internally) | explicit generators passed in |

None of these affect the emitted bytes; they are API/style differences.

## Notes for maintainers

- `bsvz-proofs`'s `Scalar.random()` is strictly better than AnchorChain's
  `randScalar` (unbiased rejection sampling vs biased reduction).
- AnchorChain's `H` is a module constant derived once; ours is a comptime const
  over the same domain — same value, no way to accidentally use a different
  `H`.
- Both are non-constant-time by construction at the proof level (Zig std field
  arithmetic is constant-time; the proof logic branches only on public data).
  AnchorChain uses JS BigInt arithmetic (no constant-time claim at all).
