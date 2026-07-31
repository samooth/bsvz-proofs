const std = @import("std");
const bsvz = @import("bsvz");
const Scalar = @import("scalar.zig").Scalar;
const pedersen = @import("pedersen.zig");
const sigma = @import("sigma.zig");
const generators = @import("generators.zig");

/// Linear range proof: prove that a Pedersen commitment C = v*G + r*H hides a
/// value v in [0, 2^bits), by bit decomposition. Each bit is committed as
/// C_i = b_i*G + r_i*H with a CDS-OR proof that b_i ∈ {0, 1} over base H, and
/// the verifier checks sum_i 2^i * C_i == C. Proof size is O(bits); use
/// bulletproofs.zig for the logarithmic alternative. Mirrors AnchorChain's
/// `proveRange`/`verifyRange` byte-for-byte.
///
/// The per-bit blindings are chosen so r_0 = r - sum_{i>=1} 2^i*r_i (no inverse,
/// no relabelling) and the (negligible) commit(0, 0) case for bit 0 is retried.
pub const LinearRangeProof = struct {
    bits: usize,
    bit_commitments: []bsvz.crypto.Point,
    bit_proofs: []sigma.CdsOrProof,
};

pub const LinearProveResult = struct {
    proof: LinearRangeProof,
    commitment: bsvz.crypto.Point,
};

const max_bits = 256;

fn bitLabel(buf: *[64]u8, i: usize) []const u8 {
    return std.fmt.bufPrint(buf, "anchorchain/privacy/range/bit/{d}", .{i}) catch unreachable;
}

pub fn linearProve(
    allocator: std.mem.Allocator,
    value: Scalar,
    blinding: Scalar,
    bits: usize,
) !LinearProveResult {
    if (bits == 0 or bits > max_bits) return error.InvalidRangeBits;
    const v = value;
    if (bits < 256 and v.toU256() >= (@as(u256, 1) << @intCast(bits))) return error.ValueOutOfRange;

    const commitment = pedersen.commit(v, blinding);
    const G = generators.G;
    const H = generators.H;

    while (true) {
        const r = try allocator.alloc(Scalar, bits);
        defer allocator.free(r);

        // Per-bit blindings with r_0 fixed so that sum_i 2^i * r_i == blinding.
        var weighted = Scalar.zero;
        for (1..bits) |i| {
            r[i] = Scalar.random();
            weighted = weighted.add(r[i].mul(Scalar.pow2(i)));
        }
        r[0] = blinding.sub(weighted);
        const b0 = (v.toU256() & 1) != 0;
        if (!b0 and r[0].isZero()) continue; // avoid commit(0, 0); negligible

        const bit_commitments = try allocator.alloc(bsvz.crypto.Point, bits);
        errdefer allocator.free(bit_commitments);
        const bit_proofs = try allocator.alloc(sigma.CdsOrProof, bits);
        errdefer allocator.free(bit_proofs);
        var bit_blindings = try allocator.alloc(Scalar, bits);
        defer allocator.free(bit_blindings);

        var label_buf: [64]u8 = undefined;
        for (0..bits) |i| {
            const b_i = ((v.toU256() >> @intCast(i)) & 1) != 0;
            const b_scalar = if (b_i) Scalar.one else Scalar.zero;
            bit_blindings[i] = r[i];
            const C_i = pedersen.commitWithGens(b_scalar, r[i], G, H);
            bit_commitments[i] = C_i;
            // Statements over base H: P0 = C_i opens to 0; P1 = C_i - G opens to 1.
            const statements = [_]bsvz.crypto.Point{ C_i, C_i.add(G.negate()) };
            bit_proofs[i] = try sigma.cdsOrProve(
                allocator,
                bitLabel(&label_buf, i),
                H,
                &statements,
                if (b_i) @as(usize, 1) else 0,
                r[i],
            );
        }

        return .{ .proof = .{
            .bits = bits,
            .bit_commitments = bit_commitments,
            .bit_proofs = bit_proofs,
        }, .commitment = commitment };
    }
}

pub fn linearVerify(commitment: bsvz.crypto.Point, proof: LinearRangeProof) bool {
    if (proof.bits == 0 or proof.bits > max_bits) return false;
    if (proof.bit_commitments.len != proof.bits or proof.bit_proofs.len != proof.bits) return false;

    const G = generators.G;
    const H = generators.H;

    // 1) The bits must reconstruct the committed value: sum_i 2^i * C_i == C.
    var acc = bsvz.crypto.Point.identity();
    for (0..proof.bits) |i| {
        acc = acc.add(proof.bit_commitments[i].mul(Scalar.pow2(i).toBytes()) catch unreachable);
    }
    if (!pedersen.pointsEq(acc, commitment)) return false;

    // 2) Each bit commitment must open to 0 or 1.
    var label_buf: [64]u8 = undefined;
    for (0..proof.bits) |i| {
        const C_i = proof.bit_commitments[i];
        const statements = [_]bsvz.crypto.Point{ C_i, C_i.add(G.negate()) };
        if (!sigma.cdsOrVerify(bitLabel(&label_buf, i), H, &statements, proof.bit_proofs[i])) return false;
    }
    return true;
}

pub fn linearProofDeinit(proof: LinearRangeProof, allocator: std.mem.Allocator) void {
    for (proof.bit_proofs) |bp| sigma.cdsOrProofDeinit(bp, allocator);
    allocator.free(proof.bit_commitments);
    allocator.free(proof.bit_proofs);
}
