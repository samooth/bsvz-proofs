# Production readiness

Current status: **solid, well-tested prototype — NOT production-ready.**

The library is a byte-for-byte port of AnchorChain's privacy primitives,
verified against a reference implementation, but nothing here has been reviewed
for security-critical deployment.

## What is in place

- All six primitives implemented and cross-checked byte-for-byte against a
  reference (`crosscheck/run.sh`)
- 53/53 unit tests passing in Debug and ReleaseSafe
- Docs: protocol spec, comparison, roadmap, security, lessons learned

## Gaps that block production use

1. **No independent audit.** The schemes are standard and publicly vetted, but
   no qualified cryptography engineer has reviewed this implementation.
   SECURITY.md makes this explicit.
2. **Untested dependency chain.** `bsvz` and the Zig standard-library crypto
   have not been validated for a deployment target. Zig std field arithmetic is
   constant-time, but that claim is not verified here.
3. **No serialization.** Proofs exist only as in-memory structs; there is no
   versioned binary format for transport or storage (Phase 2 in ROADMAP.md).
4. **CSPRNG not fork-safe.** The process-wide ChaCha20 stream would be
   duplicated between children of a forking daemon.
5. **No independent golden vectors.** Cross-checking against a single reference
   implementation would miss a bug shared by both.
6. **Constant-time not asserted.** Proof code does not branch on secrets (bit
   decomposition is index-based), but the property is not asserted on all
   optimized backends.

## When is it usable?

- **Production:** only after an independent audit and the Phase 2 hardening
  items (serialization, golden vectors, fork-safe CSPRNG, benchmarks).
- **Integration work on the frost/zkp port, research, or as an experimental
  dependency:** fine today.
