const std = @import("std");
const bsvz = @import("bsvz");
const Scalar = @import("scalar.zig").Scalar;
const pedersen = @import("pedersen.zig");
const transcript = @import("transcript.zig");

/// Schnorr proof of knowledge of x such that p = x * base. Made non-interactive
/// by Fiat-Shamir: the challenge binds `[base, p, a]`, exactly as AnchorChain's
/// `proveDlog`.
pub const SchnorrProof = struct {
    a: bsvz.crypto.Point, // commitment k*base
    s: Scalar, // k + e*x
};

pub fn schnorrProve(label: []const u8, base: bsvz.crypto.Point, p: bsvz.crypto.Point, x: Scalar) SchnorrProof {
    const k = Scalar.random();
    const a = base.mul(k.toBytes()) catch unreachable;
    const e = transcript.challenge(label, &.{ base, p, a }, &.{});
    return .{ .a = a, .s = k.add(e.mul(x)) };
}

pub fn schnorrVerify(label: []const u8, base: bsvz.crypto.Point, p: bsvz.crypto.Point, proof: SchnorrProof) bool {
    const e = transcript.challenge(label, &.{ base, p, proof.a }, &.{});
    const sG = base.mul(proof.s.toBytes()) catch unreachable;
    const eP = p.mul(e.toBytes()) catch unreachable;
    return pedersen.pointsEq(sG, proof.a.add(eP));
}

/// CDS '94 one-out-of-many OR proof: knowledge of x with p_trueIndex = x * base
/// for SOME statement, without revealing which. Fake branches are simulated with
/// random (e, s) and the sub-challenges sum to the Fiat-Shamir challenge over
/// `[base, ...statements, ...a]`, matching AnchorChain's `proveOneOfMany`.
pub const CdsOrProof = struct {
    a_values: []bsvz.crypto.Point,
    e_values: []Scalar,
    s_values: []Scalar,
};

pub fn cdsOrProve(
    allocator: std.mem.Allocator,
    label: []const u8,
    base: bsvz.crypto.Point,
    statements: []const bsvz.crypto.Point,
    true_index: usize,
    witness: Scalar,
) !CdsOrProof {
    const n = statements.len;
    if (n == 0 or true_index >= n) return error.InvalidStatement;

    var a_values = try allocator.alloc(bsvz.crypto.Point, n);
    errdefer allocator.free(a_values);
    var e_values = try allocator.alloc(Scalar, n);
    errdefer allocator.free(e_values);
    var s_values = try allocator.alloc(Scalar, n);
    errdefer allocator.free(s_values);

    // Simulate every false branch: pick e_j, s_j, derive a_j = s_j*base - e_j*p_j.
    var fake_e_sum = Scalar.zero;
    for (0..n) |j| {
        if (j == true_index) continue;
        const e_j = Scalar.random();
        const s_j = Scalar.random();
        e_values[j] = e_j;
        s_values[j] = s_j;
        const sjG = base.mul(s_j.toBytes()) catch unreachable;
        const ejPj = statements[j].mul(e_j.toBytes()) catch unreachable;
        a_values[j] = sjG.add(ejPj.negate());
        fake_e_sum = fake_e_sum.add(e_j);
    }

    // Real branch commitment.
    const k = Scalar.random();
    a_values[true_index] = base.mul(k.toBytes()) catch unreachable;

    // Bind the whole transcript [base, ...statements, ...a], then split it.
    var h = transcript.Hasher.init(label);
    h.addPoint(base);
    h.addPoints(statements);
    h.addPoints(a_values);
    const total = h.finish();

    e_values[true_index] = total.sub(fake_e_sum);
    s_values[true_index] = k.add(e_values[true_index].mul(witness));

    return .{ .a_values = a_values, .e_values = e_values, .s_values = s_values };
}

pub fn cdsOrVerify(
    label: []const u8,
    base: bsvz.crypto.Point,
    statements: []const bsvz.crypto.Point,
    proof: CdsOrProof,
) bool {
    const n = statements.len;
    if (n == 0 or proof.a_values.len != n or proof.e_values.len != n or proof.s_values.len != n) return false;

    // The sub-challenges must sum to the Fiat-Shamir challenge over the transcript.
    var h = transcript.Hasher.init(label);
    h.addPoint(base);
    h.addPoints(statements);
    h.addPoints(proof.a_values);
    const total = h.finish();

    var e_sum = Scalar.zero;
    for (proof.e_values) |e_j| e_sum = e_sum.add(e_j);
    if (!e_sum.eq(total)) return false;

    // Every branch equation must hold: s_j*base == a_j + e_j*p_j.
    for (0..n) |j| {
        const sjG = base.mul(proof.s_values[j].toBytes()) catch unreachable;
        const ejPj = statements[j].mul(proof.e_values[j].toBytes()) catch unreachable;
        if (!pedersen.pointsEq(sjG, proof.a_values[j].add(ejPj))) return false;
    }
    return true;
}

pub fn cdsOrProofDeinit(proof: CdsOrProof, allocator: std.mem.Allocator) void {
    allocator.free(proof.a_values);
    allocator.free(proof.e_values);
    allocator.free(proof.s_values);
}
