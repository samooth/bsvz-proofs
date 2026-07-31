# bsvz-zkp

Zero-knowledge proof primitives in Zig, built on top of the
[`bsvz`](https://github.com/b-open-io/bsvz) secp256k1 implementation. These are
the privacy building blocks of an AnchorChain port: every proof is
**byte-for-byte compatible** with the AnchorChain `privacy` TypeScript package
(see `crosscheck/`), so proofs cross-verify between the two implementations.

The library provides:

- **Pedersen commitments** over secp256k1: `C(v, r) = v·G + r·H`
- **Schnorr proofs** of knowledge of a discrete logarithm
- **CDS-OR proofs** of knowledge of one-of-many discrete logs (without revealing which)
- **Linear range proofs** that a commitment opens to a value in
  `[0, 2^bits)` with `bits <= 256`
- **Bulletproofs** (inner-product argument) range proofs, logarithmic in `bits`
- **Zero-knowledge membership proofs** that a committed value is in a public set
- **Homomorphic conservation proofs** that input/output commitments balance

All proofs are non-interactive via a Fiat–Shamir challenge that is byte-for-byte
AnchorChain's (`SHA-256d(label || sec1(points) || scalars32)`, zero mapped to
one).

> **Security status:** the construction is a from-scratch implementation of
> standard, well-known schemes (Pedersen, Schnorr, CDS/OR, bit-decomposition
> and Bulletproofs range proofs, OR-based membership, conservation). It is
> **not yet independently audited**. See [`SECURITY.md`](SECURITY.md) for the
> threat model, known limitations, and operational guidance before using this
> in production.

## Requirements

- Zig `0.16.0` or newer (uses the current std crypto APIs)
- Network access on first build to fetch the `bsvz` dependency

## Build and test

```sh
zig build            # compile the module
zig build test       # run the unit test suites (Debug)
zig build test -Doptimize=ReleaseSafe   # optimized tests
./crosscheck/run.sh  # byte-compatibility cross-check against AnchorChain (needs node)
```

Six test suites (Pedersen, Sigma, range, Bulletproofs, membership,
conservation) exercise real prove + verify round trips, including negative
cases.

## Quick start

```zig
const std = @import("std");
const bsvz = @import("bsvz");
const zkp = @import("bsvz-zkp");

// Commit to a value (default generators G and H match AnchorChain).
const value = zkp.Scalar.fromInt(42);
const blinding = zkp.Scalar.random();
const commitment = zkp.pedersen.commit(value, blinding);
```

### Prove a value is in range

```zig
const value = zkp.Scalar.fromInt(42);
const blinding = zkp.Scalar.random();
const bits = 8; // value must satisfy 0 <= value < 2^bits

// Linear (O(bits)) proof.
const linear = try zkp.rangeproof.linearProve(std.heap.page_allocator, value, blinding, bits);
defer zkp.rangeproof.linearProofDeinit(linear.proof, std.heap.page_allocator);
if (!zkp.rangeproof.linearVerify(linear.commitment, linear.proof)) { /* rejected */ }

// Logarithmic (Bulletproofs) proof; bits must be a power of two.
const bp = try zkp.bulletproofs.proveRangeBP(std.heap.page_allocator, value, blinding, 8);
defer zkp.bulletproofs.bulletproofDeinit(bp.proof, std.heap.page_allocator);
if (!zkp.bulletproofs.verifyRangeBP(std.heap.page_allocator, bp.commitment, bp.proof)) { /* rejected */ }
```

### Membership and conservation

```zig
// Prove commitment hides one of {1, 42, 999} without revealing which.
const set = [_]zkp.Scalar{ zkp.Scalar.fromInt(1), zkp.Scalar.fromInt(42), zkp.Scalar.fromInt(999) };
const proof = try zkp.membership.proveMembership(std.heap.page_allocator, commitment, blinding, &set, value);
defer zkp.membership.membershipProofDeinit(proof, std.heap.page_allocator);
if (!zkp.membership.verifyMembership(std.heap.page_allocator, commitment, &set, proof)) { /* rejected */ }

// Prove two input commitments balance one output commitment.
const inputs = [_]zkp.Commitment{ commit_1, commit_2 };
const outputs = [_]zkp.Commitment{ commit_3 };
const excess = r_1.add(r_2).sub(r_3); // sum(blinding_in) - sum(blinding_out)
const cproof = zkp.conservation.proveConservation(&inputs, &outputs, excess).?;
if (!zkp.conservation.verifyConservation(&inputs, &outputs, cproof)) { /* rejected */ }
```

### Schnorr proof of knowledge

```zig
const x = zkp.Scalar.random();
const P = zkp.generators.G.mul(x.toBytes()) catch unreachable;

const proof = zkp.sigma.schnorrProve("my-app/auth/v1", zkp.generators.G, P, x);
if (zkp.sigma.schnorrVerify("my-app/auth/v1", zkp.generators.G, P, proof)) { /* valid */ }
```

## Module layout

| Module | Purpose |
| --- | --- |
| `src/scalar.zig` | Canonical secp256k1 scalar (random, arithmetic, 256-bit helpers) |
| `src/random.zig` | Thread-safe ChaCha20 CSPRNG seeded from OS entropy (+ test hook) |
| `src/transcript.zig` | AnchorChain-compatible Fiat–Shamir `challenge`/`Hasher` (SHA-256d) |
| `src/generators.zig` | `hashToPoint`/`generatorVector`, default `G`/`H`/`BP_U` |
| `src/pedersen.zig` | Pedersen commitments, homomorphic add/sub, point equality |
| `src/sigma.zig` | Schnorr PoK and CDS-OR one-of-many proofs |
| `src/rangeproof.zig` | Linear (bit-decomposition) range proofs, O(bits), bits <= 256 |
| `src/bulletproofs.zig` | Bulletproofs (inner-product argument) range proofs, O(log bits) |
| `src/membership.zig` | Zero-knowledge membership in a public set |
| `src/conservation.zig` | Homomorphic conservation proof |

## Design notes

- **AnchorChain compatibility is a hard requirement.** Labels
  (`anchorchain/privacy/range/bit/{i}`, `anchorchain/bp/{y,z,x}`,
  `anchorchain/bp/ip/{round}`, `anchorchain/privacy/membership/v1`,
  `anchorchain/privacy/conservation/v1`), encodings, generator derivation, and
  the Fiat–Shamir challenge are identical, so this library can be dropped into
  an AnchorChain port as its privacy backend. `crosscheck/run.sh` verifies this
  continuously.
- **`Scalar.random()` is unbiased** (rejection sampling), unlike
  AnchorChain's biased reduction-based `randScalar`.
- **Default generators** `generators.G`/`generators.H` are the AnchorChain ones;
  derived `H`s for bespoke protocols go through `generators.hashToPoint`.
- Proofs own their heap allocations; each module exposes a matching
  `*Deinit`.

See [`docs/PROTOCOLS.md`](docs/PROTOCOLS.md) for the full protocol
specification, [`SECURITY.md`](SECURITY.md) for the threat model and
limitations, [`docs/PRODUCTION-READINESS.md`](docs/PRODUCTION-READINESS.md) for
the honest production-readiness assessment, [`docs/COMPARISON-anchorchain.md`](docs/COMPARISON-anchorchain.md)
for the side-by-side comparison with AnchorChain, and
[`docs/ROADMAP.md`](docs/ROADMAP.md) for the remaining work.

## Dependencies

- [`bsvz`](https://github.com/b-open-io/bsvz) — secp256k1 group operations
  (pinned in `build.zig.zon`).

## License

MIT — see [`LICENSE`](LICENSE). Third-party components (AnchorChain `privacy`,
`bsvz`) remain under their own licenses; see
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
