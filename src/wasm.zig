//! WebAssembly export shim (C ABI) for `bsvz-proofs`.
//!
//! Compiled only for `wasm32-freestanding` (see `zig build wasm`). Every
//! exported function speaks pointer + length pairs so it is trivially callable
//! from JS. Scalars are 32-byte big-endian; points are 33-byte compressed SEC1.
//! Proofs are written into caller-preallocated buffers (size helpers provided)
//! or into memory obtained with `zkp_alloc`.
//!
//! Entropy contract: the host MUST call `zkp_seed` with `crypto.getRandomValues`
//! bytes before any proof that samples randomness, otherwise the module traps.

const std = @import("std");
const builtin = @import("builtin");
const bsvz = @import("bsvz");
const zkp = @import("bsvz-proofs");

const Point = bsvz.crypto.Point;
const Scalar = zkp.Scalar;

comptime {
    if (!builtin.cpu.arch.isWasm()) {
        @compileError("src/wasm.zig is only compilable for a wasm32 target");
    }
    if (!builtin.single_threaded) {
        @compileError("src/wasm.zig requires single_threaded (WasmAllocator)");
    }
}

const alloc = std.heap.wasm_allocator;

pub const SCALAR_LEN: usize = 32;
pub const POINT_LEN: usize = 33;

/// Error codes returned by exported functions.
pub const E_OK: u32 = 0;
pub const E_INVALID_POINT: u32 = 1;
pub const E_INVALID_ARG: u32 = 2;
pub const E_OOM: u32 = 3;
pub const E_PROTOCOL: u32 = 4;

var last_error: [256]u8 = undefined;
var last_error_len: usize = 0;

fn setLastError(msg: []const u8) void {
    last_error_len = @min(msg.len, last_error.len);
    @memcpy(last_error[0..last_error_len], msg[0..last_error_len]);
}

fn fail(code: u32, msg: []const u8) u32 {
    setLastError(msg);
    return code;
}

fn sc(bytes: *const [32]u8) Scalar {
    return .{ .bytes = bytes.* };
}

fn readPoint(p: [*]const u8) !Point {
    return Point.fromCompressedSec1(p[0..POINT_LEN]) catch error.InvalidPoint;
}

fn writePoint(out: [*]u8, p: Point) void {
    const sec1 = p.toCompressedSec1();
    const n = @min(sec1.len, POINT_LEN);
    @memcpy(out[0..n], sec1.bytes[0..n]);
    // Identity encodes as 1 byte; pad the rest (no protocol here emits it).
    @memset(out[n..POINT_LEN], 0);
}

fn scalarLen(n: usize) usize {
    return n * SCALAR_LEN;
}

fn pointLen(n: usize) usize {
    return n * POINT_LEN;
}

/// P_k = C - s_k*G (mirrors membership.candidate, which is private).
fn membershipCandidate(commitment: Point, sk: Scalar) Point {
    if (sk.isZero()) return commitment;
    const skG = zkp.generators.G.mul(sk.toBytes()) catch unreachable;
    return commitment.add(skG.negate());
}

/// A CDS-OR proof over `n` statements serialized as three flat arrays
/// (`a` n*33, `e` n*32, `s` n*32), the layout used by all OR-proof exports.
fn orProofSize(n: usize) usize {
    return pointLen(n) + scalarLen(n) + scalarLen(n);
}

// Deterministic RNG for testing (mirrors `random.setRandomForTesting`).
var test_rng: std.Random.Xoshiro256 = undefined;
var test_random: std.Random = undefined;

export fn zkp_version() u32 {
    return 1;
}

/// Copy the last error message (UTF-8) into `buf`; returns its length.
export fn zkp_last_error(buf: [*]u8, len: usize) usize {
    const n = @min(last_error_len, len);
    @memcpy(buf[0..n], last_error[0..n]);
    return n;
}

/// Seed entropy from the host CSPRNG (e.g. `crypto.getRandomValues`). Must be
/// called before the first proof; at most 64 bytes are stored.
export fn zkp_seed(ptr: [*]const u8, len: usize) u32 {
    if (len > 64) return fail(E_INVALID_ARG, "zkp_seed: at most 64 bytes");
    zkp.random.setEntropy(ptr[0..len]);
    return E_OK;
}

/// Test-only: pin a deterministic RNG so proofs are byte-for-byte reproducible.
export fn zkp_set_rng_for_testing(seed: u64) void {
    test_rng = std.Random.Xoshiro256.init(seed);
    test_random = test_rng.random();
    zkp.random.setRandomForTesting(&test_random);
}

/// Test-only: restore the CSPRNG (requires a prior `zkp_seed`).
export fn zkp_set_rng_for_testing_off() void {
    zkp.random.setRandomForTesting(null);
}

/// Allocate `len` bytes in wasm linear memory (use `zkp_free` to release).
export fn zkp_alloc(len: usize) ?[*]u8 {
    const slice = alloc.alloc(u8, len) catch return null;
    return slice.ptr;
}

/// Free a buffer previously returned by `zkp_alloc` (same length).
export fn zkp_free(ptr: [*]u8, len: usize) void {
    alloc.free(ptr[0..len]);
}

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

export fn zkp_scalar_random(out: *[32]u8) void {
    out.* = Scalar.random().bytes;
}

/// Reduce a 256-bit big-endian value mod the secp256k1 group order.
export fn zkp_scalar_from_bytes(bytes: *const [32]u8, out: *[32]u8) void {
    out.* = Scalar.fromBytes(bytes.*).bytes;
}

export fn zkp_scalar_from_int(value: u64, out: *[32]u8) void {
    out.* = Scalar.fromInt(value).bytes;
}

export fn zkp_scalar_to_int(bytes: *const [32]u8) u64 {
    return sc(bytes).toInt();
}

export fn zkp_scalar_is_zero(bytes: *const [32]u8) u32 {
    return if (sc(bytes).isZero()) 1 else 0;
}

export fn zkp_scalar_eq(a: *const [32]u8, b: *const [32]u8) u32 {
    return if (sc(a).eq(sc(b))) 1 else 0;
}

export fn zkp_scalar_add(a: *const [32]u8, b: *const [32]u8, out: *[32]u8) void {
    out.* = sc(a).add(sc(b)).bytes;
}

export fn zkp_scalar_sub(a: *const [32]u8, b: *const [32]u8, out: *[32]u8) void {
    out.* = sc(a).sub(sc(b)).bytes;
}

export fn zkp_scalar_mul(a: *const [32]u8, b: *const [32]u8, out: *[32]u8) void {
    out.* = sc(a).mul(sc(b)).bytes;
}

export fn zkp_scalar_neg(a: *const [32]u8, out: *[32]u8) void {
    out.* = sc(a).neg().bytes;
}

export fn zkp_scalar_invert(a: *const [32]u8, out: *[32]u8) u32 {
    if (sc(a).isZero()) return fail(E_INVALID_ARG, "cannot invert zero");
    out.* = sc(a).invert().bytes;
    return E_OK;
}

// ---------------------------------------------------------------------------
// Points
// ---------------------------------------------------------------------------

export fn zkp_point_add(a: *const [33]u8, b: *const [33]u8, out: *[33]u8) u32 {
    const pa = readPoint(a.ptr) catch return fail(E_INVALID_POINT, "zkp_point_add: bad point a");
    const pb = readPoint(b.ptr) catch return fail(E_INVALID_POINT, "zkp_point_add: bad point b");
    writePoint(out.ptr, pa.add(pb));
    return E_OK;
}

export fn zkp_point_sub(a: *const [33]u8, b: *const [33]u8, out: *[33]u8) u32 {
    const pa = readPoint(a.ptr) catch return fail(E_INVALID_POINT, "zkp_point_sub: bad point a");
    const pb = readPoint(b.ptr) catch return fail(E_INVALID_POINT, "zkp_point_sub: bad point b");
    writePoint(out.ptr, pa.add(pb.negate()));
    return E_OK;
}

export fn zkp_point_negate(a: *const [33]u8, out: *[33]u8) u32 {
    const pa = readPoint(a.ptr) catch return fail(E_INVALID_POINT, "zkp_point_negate: bad point");
    writePoint(out.ptr, pa.negate());
    return E_OK;
}

export fn zkp_point_mul(point: *const [33]u8, scalar: *const [32]u8, out: *[33]u8) u32 {
    const pp = readPoint(point.ptr) catch return fail(E_INVALID_POINT, "zkp_point_mul: bad point");
    const r = pp.mul(scalar.*) catch return fail(E_PROTOCOL, "zkp_point_mul: scalar mul failed");
    writePoint(out.ptr, r);
    return E_OK;
}

export fn zkp_point_eq(a: *const [33]u8, b: *const [33]u8) u32 {
    const pa = readPoint(a.ptr) catch return 0;
    const pb = readPoint(b.ptr) catch return 0;
    return if (zkp.pedersen.pointsEq(pa, pb)) 1 else 0;
}

// ---------------------------------------------------------------------------
// Transcript / hashing
// ---------------------------------------------------------------------------

export fn zkp_sha256(data: [*]const u8, len: usize, out: *[32]u8) void {
    out.* = zkp.transcript.sha256(data[0..len]);
}

export fn zkp_sha256d(data: [*]const u8, len: usize, out: *[32]u8) void {
    out.* = zkp.transcript.sha256d(data[0..len]);
}

/// Fiat-Shamir challenge: `points` is `n_points * 33` bytes, `scalars` is
/// `n_scalars * 32` bytes.
export fn zkp_challenge(label: [*]const u8, label_len: usize, points: [*]const u8, n_points: usize, scalars: [*]const u8, n_scalars: usize, out: *[32]u8) u32 {
    var points_list = alloc.alloc(Point, n_points) catch return fail(E_OOM, "zkp_challenge: alloc");
    defer alloc.free(points_list);
    for (0..n_points) |i| {
        points_list[i] = readPoint(points + pointLen(i)) catch return fail(E_INVALID_POINT, "zkp_challenge: bad point");
    }
    const scalars_list: []const Scalar = @ptrCast(scalars[0..scalarLen(n_scalars)]);
    out.* = zkp.transcript.challenge(label[0..label_len], points_list, scalars_list).bytes;
    return E_OK;
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

export fn zkp_hash_to_point(domain: [*]const u8, len: usize, out: *[33]u8) u32 {
    writePoint(out.ptr, zkp.generators.hashToPoint(domain[0..len]));
    return E_OK;
}

/// Writes `n` derived generators as `n * 33` bytes into `out`.
export fn zkp_generator_vector(domain: [*]const u8, len: usize, n: usize, out: [*]u8) u32 {
    const vec = zkp.generators.generatorVector(domain[0..len], n, alloc) catch return fail(E_OOM, "zkp_generator_vector: alloc");
    defer alloc.free(vec);
    for (vec, 0..) |p, i| writePoint(out + pointLen(i), p);
    return E_OK;
}

export fn zkp_generator_G(out: *[33]u8) void {
    writePoint(out.ptr, zkp.generators.G);
}

export fn zkp_generator_H(out: *[33]u8) void {
    writePoint(out.ptr, zkp.generators.H);
}

export fn zkp_generator_BP_U(out: *[33]u8) void {
    writePoint(out.ptr, zkp.generators.BP_U);
}

// ---------------------------------------------------------------------------
// Pedersen
// ---------------------------------------------------------------------------

export fn zkp_commit(value: *const [32]u8, blinding: *const [32]u8, out: *[33]u8) void {
    writePoint(out.ptr, zkp.pedersen.commit(sc(value), sc(blinding)));
}

export fn zkp_commit_with_gens(value: *const [32]u8, blinding: *const [32]u8, g: *const [33]u8, h: *const [33]u8, out: *[33]u8) u32 {
    const pg = readPoint(g.ptr) catch return fail(E_INVALID_POINT, "zkp_commit_with_gens: bad G");
    const ph = readPoint(h.ptr) catch return fail(E_INVALID_POINT, "zkp_commit_with_gens: bad H");
    writePoint(out.ptr, zkp.pedersen.commitWithGens(sc(value), sc(blinding), pg, ph));
    return E_OK;
}

export fn zkp_commit_verify(commitment: *const [33]u8, value: *const [32]u8, blinding: *const [32]u8) u32 {
    const pc = readPoint(commitment.ptr) catch return 0;
    return if (zkp.pedersen.verify(pc, sc(value), sc(blinding))) 1 else 0;
}

export fn zkp_commit_add(a: *const [33]u8, b: *const [33]u8, out: *[33]u8) u32 {
    const pa = readPoint(a.ptr) catch return fail(E_INVALID_POINT, "zkp_commit_add: bad point a");
    const pb = readPoint(b.ptr) catch return fail(E_INVALID_POINT, "zkp_commit_add: bad point b");
    writePoint(out.ptr, zkp.pedersen.add(pa, pb));
    return E_OK;
}

export fn zkp_commit_sub(a: *const [33]u8, b: *const [33]u8, out: *[33]u8) u32 {
    const pa = readPoint(a.ptr) catch return fail(E_INVALID_POINT, "zkp_commit_sub: bad point a");
    const pb = readPoint(b.ptr) catch return fail(E_INVALID_POINT, "zkp_commit_sub: bad point b");
    writePoint(out.ptr, zkp.pedersen.sub(pa, pb));
    return E_OK;
}

// ---------------------------------------------------------------------------
// Schnorr
// ---------------------------------------------------------------------------

export fn zkp_schnorr_prove(label: [*]const u8, label_len: usize, base: *const [33]u8, p: *const [33]u8, x: *const [32]u8, out_a: *[33]u8, out_s: *[32]u8) u32 {
    const pb = readPoint(base.ptr) catch return fail(E_INVALID_POINT, "zkp_schnorr_prove: bad base");
    const pp = readPoint(p.ptr) catch return fail(E_INVALID_POINT, "zkp_schnorr_prove: bad p");
    const proof = zkp.sigma.schnorrProve(label[0..label_len], pb, pp, sc(x));
    writePoint(out_a.ptr, proof.a);
    out_s.* = proof.s.bytes;
    return E_OK;
}

export fn zkp_schnorr_verify(label: [*]const u8, label_len: usize, base: *const [33]u8, p: *const [33]u8, a: *const [33]u8, s: *const [32]u8) u32 {
    const pb = readPoint(base.ptr) catch return 0;
    const pp = readPoint(p.ptr) catch return 0;
    const pa = readPoint(a.ptr) catch return 0;
    const proof = zkp.sigma.SchnorrProof{ .a = pa, .s = sc(s) };
    return if (zkp.sigma.schnorrVerify(label[0..label_len], pb, pp, proof)) 1 else 0;
}

// ---------------------------------------------------------------------------
// CDS one-out-of-many (OR proof)
// ---------------------------------------------------------------------------

/// Size in bytes of a serialized CDS-OR proof over `n` statements.
export fn zkp_cds_or_size(n: usize) usize {
    return orProofSize(n);
}

/// Proves knowledge of the discrete log of statement `true_index` over `base`.
/// Writes three flat arrays: `out_a` n*33, `out_e` n*32, `out_s` n*32.
export fn zkp_cds_or_prove(label: [*]const u8, label_len: usize, base: *const [33]u8, statements: [*]const u8, n: usize, true_index: usize, witness: *const [32]u8, out_a: [*]u8, out_e: [*]u8, out_s: [*]u8) u32 {
    const pb = readPoint(base.ptr) catch return fail(E_INVALID_POINT, "zkp_cds_or_prove: bad base");
    var stmts = alloc.alloc(Point, n) catch return fail(E_OOM, "zkp_cds_or_prove: alloc");
    defer alloc.free(stmts);
    for (0..n) |i| {
        stmts[i] = readPoint(statements + pointLen(i)) catch return fail(E_INVALID_POINT, "zkp_cds_or_prove: bad statement");
    }
    const proof = zkp.sigma.cdsOrProve(alloc, label[0..label_len], pb, stmts, true_index, sc(witness)) catch
        return fail(E_PROTOCOL, "zkp_cds_or_prove: invalid statement");
    defer zkp.sigma.cdsOrProofDeinit(proof, alloc);
    for (0..n) |i| {
        writePoint(out_a + pointLen(i), proof.a_values[i]);
        (out_e + scalarLen(i))[0..32].* = proof.e_values[i].bytes;
        (out_s + scalarLen(i))[0..32].* = proof.s_values[i].bytes;
    }
    return E_OK;
}

export fn zkp_cds_or_verify(label: [*]const u8, label_len: usize, base: *const [33]u8, statements: [*]const u8, n: usize, a: [*]const u8, e: [*]const u8, s: [*]const u8) u32 {
    const pb = readPoint(base.ptr) catch return 0;
    var stmts = alloc.alloc(Point, n) catch return 0;
    defer alloc.free(stmts);
    var a_list = alloc.alloc(Point, n) catch return 0;
    defer alloc.free(a_list);
    var e_list = alloc.alloc(Scalar, n) catch return 0;
    defer alloc.free(e_list);
    var s_list = alloc.alloc(Scalar, n) catch return 0;
    defer alloc.free(s_list);
    for (0..n) |i| {
        stmts[i] = readPoint(statements + pointLen(i)) catch return 0;
        a_list[i] = readPoint(a + pointLen(i)) catch return 0;
        e_list[i] = .{ .bytes = (e + scalarLen(i))[0..32].* };
        s_list[i] = .{ .bytes = (s + scalarLen(i))[0..32].* };
    }
    const proof = zkp.sigma.CdsOrProof{ .a_values = a_list, .e_values = e_list, .s_values = s_list };
    return if (zkp.sigma.cdsOrVerify(label[0..label_len], pb, stmts, proof)) 1 else 0;
}

// ---------------------------------------------------------------------------
// Linear range proof
// ---------------------------------------------------------------------------

/// Serialized linear range proof over `bits` bits:
/// bit_commitments (bits*33) then, per bit, a CDS-OR proof over 2 statements
/// (a 2*33, e 2*32, s 2*32). The top-level commitment is returned separately.
fn linearRangeSize(bits: usize) usize {
    return pointLen(bits) + bits * orProofSize(2);
}

export fn zkp_range_size(bits: usize) usize {
    return linearRangeSize(bits);
}

export fn zkp_range_prove(value: *const [32]u8, blinding: *const [32]u8, bits: usize, out: [*]u8) u32 {
    const res = zkp.rangeproof.linearProve(alloc, sc(value), sc(blinding), bits) catch
        return fail(E_PROTOCOL, "zkp_range_prove: prove failed");
    defer zkp.rangeproof.linearProofDeinit(res.proof, alloc);

    var off: usize = 0;
    for (0..bits) |i| {
        writePoint(out + off, res.proof.bit_commitments[i]);
        off += POINT_LEN;
    }
    for (0..bits) |i| {
        const bp = res.proof.bit_proofs[i];
        for (0..2) |j| {
            writePoint(out + off, bp.a_values[j]);
            off += POINT_LEN;
        }
        for (0..2) |j| {
            (out + off)[0..32].* = bp.e_values[j].bytes;
            off += SCALAR_LEN;
        }
        for (0..2) |j| {
            (out + off)[0..32].* = bp.s_values[j].bytes;
            off += SCALAR_LEN;
        }
    }
    return E_OK;
}

/// Verifies a serialized range proof against the commitment. Returns 1/0.
export fn zkp_range_verify(commitment: *const [33]u8, proof_buf: [*]const u8, bits: usize) u32 {
    const cm = readPoint(commitment.ptr) catch return 0;
    var bit_cs = alloc.alloc(Point, bits) catch return 0;
    defer alloc.free(bit_cs);
    var a_all = alloc.alloc(Point, bits * 2) catch return 0;
    defer alloc.free(a_all);
    var e_all = alloc.alloc(Scalar, bits * 2) catch return 0;
    defer alloc.free(e_all);
    var s_all = alloc.alloc(Scalar, bits * 2) catch return 0;
    defer alloc.free(s_all);
    var bit_ps = alloc.alloc(zkp.sigma.CdsOrProof, bits) catch return 0;
    defer alloc.free(bit_ps);

    var off: usize = 0;
    for (0..bits) |i| {
        bit_cs[i] = readPoint(proof_buf + off) catch return 0;
        off += POINT_LEN;
    }
    for (0..bits) |i| {
        const a_base = a_all[i * 2 .. i * 2 + 2];
        for (0..2) |j| {
            a_base[j] = readPoint(proof_buf + off) catch return 0;
            off += POINT_LEN;
        }
        const e_base = e_all[i * 2 .. i * 2 + 2];
        for (0..2) |j| {
            e_base[j] = .{ .bytes = (proof_buf + off + scalarLen(j))[0..32].* };
        }
        off += 2 * SCALAR_LEN;
        const s_base = s_all[i * 2 .. i * 2 + 2];
        for (0..2) |j| {
            s_base[j] = .{ .bytes = (proof_buf + off + scalarLen(j))[0..32].* };
        }
        off += 2 * SCALAR_LEN;
        bit_ps[i] = .{ .a_values = a_base, .e_values = e_base, .s_values = s_base };
    }

    const proof = zkp.rangeproof.LinearRangeProof{
        .bits = bits,
        .bit_commitments = bit_cs,
        .bit_proofs = bit_ps,
    };
    return if (zkp.rangeproof.linearVerify(cm, proof)) 1 else 0;
}

// ---------------------------------------------------------------------------
// Bulletproofs (logarithmic range proof)
// ---------------------------------------------------------------------------

fn innerProductRounds(bits: usize) usize {
    var rounds: usize = 0;
    var m = bits;
    while (m > 1) : (m /= 2) rounds += 1;
    return rounds;
}

/// Serialized BP proof over `bits` bits (power of two):
/// commitment (33) A(33) S(33) T1(33) T2(33) taux(32) mu(32) tHat(32)
/// ip.a(32) ip.b(32) L(rounds*33) R(rounds*33).
fn rangeBpSize(bits: usize) usize {
    return POINT_LEN + 4 * POINT_LEN + 5 * SCALAR_LEN + 2 * innerProductRounds(bits) * POINT_LEN;
}

export fn zkp_range_bp_size(bits: usize) usize {
    return rangeBpSize(bits);
}

export fn zkp_range_bp_prove(value: *const [32]u8, blinding: *const [32]u8, bits: usize, out: [*]u8) u32 {
    const res = zkp.bulletproofs.proveRangeBP(alloc, sc(value), sc(blinding), bits) catch
        return fail(E_PROTOCOL, "zkp_range_bp_prove: prove failed");
    defer zkp.bulletproofs.bulletproofDeinit(res.proof, alloc);

    var off: usize = 0;
    writePoint(out + off, res.commitment);
    off += POINT_LEN;
    writePoint(out + off, res.proof.A);
    off += POINT_LEN;
    writePoint(out + off, res.proof.S);
    off += POINT_LEN;
    writePoint(out + off, res.proof.T1);
    off += POINT_LEN;
    writePoint(out + off, res.proof.T2);
    off += POINT_LEN;
    (out + off)[0..32].* = res.proof.taux.bytes;
    off += SCALAR_LEN;
    (out + off)[0..32].* = res.proof.mu.bytes;
    off += SCALAR_LEN;
    (out + off)[0..32].* = res.proof.tHat.bytes;
    off += SCALAR_LEN;
    (out + off)[0..32].* = res.proof.ip.a.bytes;
    off += SCALAR_LEN;
    (out + off)[0..32].* = res.proof.ip.b.bytes;
    off += SCALAR_LEN;
    for (res.proof.ip.L) |p| {
        writePoint(out + off, p);
        off += POINT_LEN;
    }
    for (res.proof.ip.R) |p| {
        writePoint(out + off, p);
        off += POINT_LEN;
    }
    return E_OK;
}

/// Verifies a serialized BP proof against the commitment. Returns 1/0.
export fn zkp_range_bp_verify(commitment: *const [33]u8, proof_buf: [*]const u8, bits: usize) u32 {
    const cm = readPoint(commitment.ptr) catch return 0;
    const rounds = innerProductRounds(bits);
    var off: usize = 0;

    const A = readPoint(proof_buf + off) catch return 0;
    off += POINT_LEN;
    const S = readPoint(proof_buf + off) catch return 0;
    off += POINT_LEN;
    const T1 = readPoint(proof_buf + off) catch return 0;
    off += POINT_LEN;
    const T2 = readPoint(proof_buf + off) catch return 0;
    off += POINT_LEN;
    const taux: Scalar = .{ .bytes = (proof_buf + off)[0..32].* };
    off += SCALAR_LEN;
    const mu: Scalar = .{ .bytes = (proof_buf + off)[0..32].* };
    off += SCALAR_LEN;
    const tHat: Scalar = .{ .bytes = (proof_buf + off)[0..32].* };
    off += SCALAR_LEN;
    const ip_a: Scalar = .{ .bytes = (proof_buf + off)[0..32].* };
    off += SCALAR_LEN;
    const ip_b: Scalar = .{ .bytes = (proof_buf + off)[0..32].* };
    off += SCALAR_LEN;

    var L = alloc.alloc(Point, rounds) catch return 0;
    defer alloc.free(L);
    var R = alloc.alloc(Point, rounds) catch return 0;
    defer alloc.free(R);
    for (0..rounds) |i| {
        L[i] = readPoint(proof_buf + off) catch return 0;
        off += POINT_LEN;
    }
    for (0..rounds) |i| {
        R[i] = readPoint(proof_buf + off) catch return 0;
        off += POINT_LEN;
    }

    const proof = zkp.bulletproofs.RangeProofBP{
        .bits = bits,
        .A = A,
        .S = S,
        .T1 = T1,
        .T2 = T2,
        .taux = taux,
        .mu = mu,
        .tHat = tHat,
        .ip = .{ .L = L, .R = R, .a = ip_a, .b = ip_b },
    };
    return if (zkp.bulletproofs.verifyRangeBP(alloc, cm, proof)) 1 else 0;
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

/// Membership proof over a public set of `n_set` scalars; serialized like a
/// CDS-OR proof: `out_a` n*33, `out_e` n*32, `out_s` n*32.
export fn zkp_membership_size(n_set: usize) usize {
    return orProofSize(n_set);
}

export fn zkp_membership_prove(commitment: *const [33]u8, blinding: *const [32]u8, set: [*]const u8, n_set: usize, value: *const [32]u8, out_a: [*]u8, out_e: [*]u8, out_s: [*]u8) u32 {
    const cm = readPoint(commitment.ptr) catch return fail(E_INVALID_POINT, "zkp_membership_prove: bad commitment");
    const set_scalars: []const Scalar = @ptrCast(set[0..scalarLen(n_set)]);
    const proof = zkp.membership.proveMembership(alloc, cm, sc(blinding), set_scalars, sc(value)) catch
        return fail(E_PROTOCOL, "zkp_membership_prove: value not in set / empty set");
    defer zkp.membership.membershipProofDeinit(proof, alloc);
    for (0..n_set) |i| {
        writePoint(out_a + pointLen(i), proof.or_proof.a_values[i]);
        (out_e + scalarLen(i))[0..32].* = proof.or_proof.e_values[i].bytes;
        (out_s + scalarLen(i))[0..32].* = proof.or_proof.s_values[i].bytes;
    }
    return E_OK;
}

export fn zkp_membership_verify(commitment: *const [33]u8, set: [*]const u8, n_set: usize, a: [*]const u8, e: [*]const u8, s: [*]const u8) u32 {
    const cm = readPoint(commitment.ptr) catch return 0;
    const set_scalars: []const Scalar = @ptrCast(set[0..scalarLen(n_set)]);
    var stmts = alloc.alloc(Point, n_set) catch return 0;
    defer alloc.free(stmts);
    var a_list = alloc.alloc(Point, n_set) catch return 0;
    defer alloc.free(a_list);
    var e_list = alloc.alloc(Scalar, n_set) catch return 0;
    defer alloc.free(e_list);
    var s_list = alloc.alloc(Scalar, n_set) catch return 0;
    defer alloc.free(s_list);
    for (0..n_set) |i| {
        stmts[i] = membershipCandidate(cm, set_scalars[i]);
        a_list[i] = readPoint(a + pointLen(i)) catch return 0;
        e_list[i] = .{ .bytes = (e + scalarLen(i))[0..32].* };
        s_list[i] = .{ .bytes = (s + scalarLen(i))[0..32].* };
    }
    const proof = zkp.membership.MembershipProof{
        .set_size = n_set,
        .or_proof = .{ .a_values = a_list, .e_values = e_list, .s_values = s_list },
    };
    return if (zkp.membership.verifyMembership(alloc, cm, set_scalars, proof)) 1 else 0;
}

// ---------------------------------------------------------------------------
// Conservation
// ---------------------------------------------------------------------------

export fn zkp_conservation_prove(inputs: [*]const u8, n_in: usize, outputs: [*]const u8, n_out: usize, excess: *const [32]u8, out_a: *[33]u8, out_s: *[32]u8) u32 {
    var ins = alloc.alloc(Point, n_in) catch return fail(E_OOM, "zkp_conservation_prove: alloc");
    defer alloc.free(ins);
    for (0..n_in) |i| {
        ins[i] = readPoint(inputs + pointLen(i)) catch return fail(E_INVALID_POINT, "zkp_conservation_prove: bad input");
    }
    var outs = alloc.alloc(Point, n_out) catch return fail(E_OOM, "zkp_conservation_prove: alloc");
    defer alloc.free(outs);
    for (0..n_out) |i| {
        outs[i] = readPoint(outputs + pointLen(i)) catch return fail(E_INVALID_POINT, "zkp_conservation_prove: bad output");
    }
    const proof = zkp.conservation.proveConservation(ins, outs, sc(excess)) orelse
        return fail(E_PROTOCOL, "zkp_conservation_prove: empty input or output side");
    writePoint(out_a.ptr, proof.a);
    out_s.* = proof.s.bytes;
    return E_OK;
}

export fn zkp_conservation_verify(inputs: [*]const u8, n_in: usize, outputs: [*]const u8, n_out: usize, a: *const [33]u8, s: *const [32]u8) u32 {
    var ins = alloc.alloc(Point, n_in) catch return 0;
    defer alloc.free(ins);
    for (0..n_in) |i| {
        ins[i] = readPoint(inputs + pointLen(i)) catch return 0;
    }
    var outs = alloc.alloc(Point, n_out) catch return 0;
    defer alloc.free(outs);
    for (0..n_out) |i| {
        outs[i] = readPoint(outputs + pointLen(i)) catch return 0;
    }
    const pa = readPoint(a.ptr) catch return 0;
    const proof = zkp.sigma.SchnorrProof{ .a = pa, .s = sc(s) };
    return if (zkp.conservation.verifyConservation(ins, outs, proof)) 1 else 0;
}
