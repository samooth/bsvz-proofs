# AGENTS.md — guide for LLM agents working on bsvz-proofs

This file is for LLM agents (e.g. opencode). It captures durable, atemporal
facts about the project so any future session can work here without re-learning
them. It does not document every function — read the source for that.

## What this project is

`bsvz-proofs` is a Zig library of zero-knowledge proof primitives over secp256k1,
built on the `bsvz` backend. Its core requirement: **byte-for-byte
compatibility with the AnchorChain `privacy` TypeScript package** — same
encodings, generators, labels, and Fiat–Shamir challenge — so proofs
cross-verify between Zig and TS. Any change that alters emitted bytes breaks
that contract unless the TS side changes too.

## Build / test / verify

- Zig required: `0.16.x` (see `LESSONS_1.md`; many 0.16 std API specifics
  below). No nightly-fragility allowed — do not upgrade APIs casually.
- `zig build` — compile the module.
- `zig build test` — run all six test suites. Also run
  `zig build test -Doptimize=ReleaseSafe`; optimized builds expose
  comptime-budget and integer-width bugs Debug tolerates.
- `./crosscheck/run.sh` — byte-compat check vs the pure-Node AnchorChain
  reference (`crosscheck/ref.js`). Must print `crosscheck OK: ...`. Requires
  `node`. Run after ANY change to transcript, generators, or challenge inputs.
- `zig build crosscheck` — prints the Zig-side vectors (debug aid).
- `zig build wasm` — build `zig-out/bin/bsvz_proofs.wasm` (wasm32-freestanding
  C-ABI shim over every protocol, see `src/wasm.zig`).
- `zig build wasm-test` — node smoke test (`wasm/run-node.mjs`): asserts the
  same AnchorChain vectors as `zig build crosscheck` and round-trips every
  exported protocol, including tamper negatives. Requires `node`. Run after
  changing `src/wasm.zig`, the export list in `build.zig`, or the crosscheck
  vectors.
- `wasm/` is a publishable npm package (`bsvz-proofs`): `npm run build` there
  builds a ReleaseSmall wasm (`zig build wasm -Doptimize=ReleaseSmall`) and
  copies it into `wasm/`; `prepack` runs it before `npm pack`/`npm publish`.
  The `.wasm` is gitignored (build product — don't commit it). The JS API in
  `wasm/index.js` wraps the shim; keep it in sync with the `export fn` list.
- Run `zig fmt` (whole tree: `src`, `tests`, `examples`, `build.zig`) before
  committing.

## Module layout

| File | Role |
| --- | --- |
| `src/root.zig` | Public API surface; exports every module + type aliases |
| `src/scalar.zig` | `Scalar`: canonical [32]u8, arith, `random()`, 256-bit helpers (`toU256`/`fromU256`/`pow2`) |
| `src/random.zig` | Process-wide ChaCha20 CSPRNG + `setRandomForTesting` (test-only, not thread-safe) |
| `src/transcript.zig` | `challenge(label, points, scalars)` + incremental `Hasher`; SHA-256d; zero→1 |
| `src/generators.zig` | `hashToPoint`/`generatorVector`, const `G`/`H`/`BP_U`; AnchorChain domains |
| `src/pedersen.zig` | `commit`/`verify` (default G/H) + `commitWithGens`/`verifyWithGens`, add/sub |
| `src/sigma.zig` | `schnorrProve/Verify`, `cdsOrProve/Verify`; **label is first arg**; verify takes no allocator |
| `src/rangeproof.zig` | `linearProve` → `LinearProveResult{proof, commitment}`, `linearVerify(commitment, proof)`, `linearProofDeinit`; bits 1..256 |
| `src/bulletproofs.zig` | `proveRangeBP` → `ProveResult`, `verifyRangeBP(allocator, commitment, proof)`, `bulletproofDeinit`; bits power-of-two |
| `src/membership.zig` | `proveMembership`/`verifyMembership`/`membershipProofDeinit`; field is `or_proof` |
| `src/conservation.zig` | `netCommitment`, `proveConservation`, `verifyConservation` |
| `src/wasm.zig` | wasm32 C-ABI export shim (pointer+len for every protocol); keep its `export fn` names in sync with `wasm_mod.export_symbol_names` in `build.zig` |
| `tests/*_test.zig` | Six suites; each re-seeds a deterministic RNG per proof |

Proof types own heap allocations; every module with proofs exports a matching
`*Deinit` — free everything (see memory notes).

## API conventions (do not break)

- **Labels are first-class.** `schnorrProve("label", base, p, x)`,
  `cdsOrProve(alloc, "label", base, statements, true_index, witness)`.
  Verifier must pass the identical label. AnchorChain uses
  `anchorchain/privacy/...` and `anchorchain/bp/...` labels — keep them.
- **Default generators** `generators.G` / `generators.H` / `generators.BP_U`
  are AnchorChain's. Standalone default-G/H APIs (`pedersen.commit`,
  `linearVerify`) bind these internally; do not pass other H's to them.
- Range proofs return the commitment alongside the proof
  (`LinearProveResult`, `ProveResult`) because verifiers need it.
- `Scalar.random()` is rejection-sampled/unbiased — preserve that; do not fall
  back to reduction-based sampling (AnchorChain's is biased; ours is
  deliberately better).

## Byte-compatibility rules (the contract)

- Challenge = `SHA-256d(label ‖ sec1(points…) ‖ scalar32…)`, zero → 1.
- `hashToPoint(domain)` = try-and-increment with counter suffix `":" + counter`,
  try `0x02` prefix before `0x03`, bound `counter < 100_000`.
- Generator domains (verbatim): `AnchorChain/pedersen/H/v1`,
  `anchorchain/bp/g/v1`, `anchorchain/bp/h/v1`, `anchorchain/bp/U/v1`;
  range bit labels `anchorchain/privacy/range/bit/{i}`; BP challenges
  `anchorchain/bp/{y,z,x}`, `anchorchain/bp/ip/{round}`;
  `anchorchain/privacy/membership/v1`, `anchorchain/privacy/conservation/v1`.
- Range blinding scheme: `r_0 = r − Σ_{i≥1} 2^i·r_i` (first bit derived last,
  no inverse), retry if a `commit(0,0)` bit-0 would result.
- Scalar encodings are 32-byte big-endian; points are 33-byte compressed SEC1.
- When adding a protocol, mirror AnchorChain `privacy` TS line-for-line and add
  it to `crosscheck/ref.js` + `examples/crosscheck.zig`.

## Zig 0.16 gotchas that WILL bite again

See `LESSONS_1.md` for the full list with examples. Highlights:
- `ArrayList(T).empty` + `append(allocator, x)` / `toOwnedSlice(allocator)`; no `init()`.
- `@setEvalBranchQuota` only inside `blk: {}` / `comptime {}` — needed for comptime `hashToPoint` consts.
- `std.Random.bytes(rng.*, out)`; `Xoshiro256.init(u64)` single seed.
- No `std.fmt.fmtSliceHexLower` — use `std.fmt.bytesToHex(&arr, .lower)`.
- `or` is a keyword (→ `or_proof`); a var named `u2` shadows the type (→ `u_sq`).
- `1 << 256` overflows `u256` — explicit `if (bits < 256)` guards.
- Compare bit tests at `u256` width: `((v.toU256() >> @intCast(i)) & 1) == 1`.
- Free every intermediate slice (`defer allocator.free`); tests catch leaks.
- **Wasm exports:** with `-fno-entry`, `export fn` symbols are dropped from the
  wasm export section in 0.16 (both lld and the self-hosted linker). The build
  API workaround is `root_module.export_symbol_names` (emits `--export=<name>`);
  keep it in sync with the `export fn` names in `src/wasm.zig`. `u64` results
  surface to JS as signed `i64`.

## bsvz API patterns

- `Point.mul([32]u8) !Point` (pass `scalar.toBytes()`), `basePointMul`, `add`,
  `negate()`; point equality via `inner.equivalent`.
- Scalar field is `bytes: [32]u8`; use `toBytes()` for `mul`.
- `bsvz` is pinned in `build.zig.zon` by URL+hash; the module import name is
  `bsvz`, and this package's module name is `bsvz-proofs`.

## Testing conventions

- Tests use `zkp.random.setRandomForTesting(&rng)` to inject
  `std.Random.Xoshiro256` for reproducible proofs; **re-seed per proof**, not
  per suite.
- Include negative cases: wrong value/blinding/bit-width/set-size, tampered
  proofs, `commit(0,0)` rejection, empty-set conservation.
- New primitives get a `tests/<name>_test.zig` registered in `build.zig`.

## Do / don't

- DO preserve AnchorChain byte-compat; verify with `crosscheck/run.sh`.
- DO keep labels exact, deinit symmetric, and all test suites green in both
  Debug and ReleaseSafe.
- DON'T add comments to code unless asked; keep style consistent with existing
  modules (`std.fmt`, no external deps beyond `bsvz`).
- DON'T commit unless explicitly asked.
- DON'T change the public API signatures documented here without updating
  README.md, docs/PROTOCOLS.md, and the crosscheck vectors together.
