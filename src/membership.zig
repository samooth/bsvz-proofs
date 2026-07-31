const std = @import("std");
const bsvz = @import("bsvz");
const Scalar = @import("scalar.zig").Scalar;
const sigma = @import("sigma.zig");
const generators = @import("generators.zig");

/// Zero-knowledge membership proof: a Pedersen commitment C = v*G + r*H hides a
/// value v that is one of a public set {s_0, ..., s_{m-1}}, without revealing
/// which. For each candidate s_k, form P_k = C - s_k*G; if v = s_k then
/// P_k = r*H, so the prover knows its discrete log w.r.t. H. A CDS-OR proof
/// over base H proves "I know log_H(P_k) for SOME k". Linear in |set|.
/// Mirrors AnchorChain's `membership.ts` byte-for-byte.
pub const MembershipProof = struct {
    set_size: usize,
    or_proof: sigma.CdsOrProof,
};

const LABEL = "anchorchain/privacy/membership/v1";

/// P_k = C - s_k*G (with s_k = 0 handled without a zero multiply).
fn candidate(commitment: bsvz.crypto.Point, sk: Scalar) bsvz.crypto.Point {
    if (sk.isZero()) return commitment;
    const skG = generators.G.mul(sk.toBytes()) catch unreachable;
    return commitment.add(skG.negate());
}

pub fn proveMembership(
    allocator: std.mem.Allocator,
    commitment: bsvz.crypto.Point,
    blinding: Scalar,
    set: []const Scalar,
    value: Scalar,
) !MembershipProof {
    if (set.len == 0) return error.EmptySet;
    const v = value;
    var true_index: ?usize = null;
    for (set, 0..) |s, i| {
        if (s.eq(v)) {
            true_index = i;
            break;
        }
    }
    const ti = true_index orelse return error.ValueNotInSet;

    const statements = try allocator.alloc(bsvz.crypto.Point, set.len);
    defer allocator.free(statements);
    for (set, 0..) |s, i| statements[i] = candidate(commitment, s);

    return .{
        .set_size = set.len,
        .or_proof = try sigma.cdsOrProve(allocator, LABEL, generators.H, statements, ti, blinding),
    };
}

pub fn verifyMembership(
    allocator: std.mem.Allocator,
    commitment: bsvz.crypto.Point,
    set: []const Scalar,
    proof: MembershipProof,
) bool {
    if (set.len == 0 or proof.set_size != set.len) return false;

    const statements = allocator.alloc(bsvz.crypto.Point, set.len) catch return false;
    defer allocator.free(statements);
    for (set, 0..) |s, i| statements[i] = candidate(commitment, s);

    return sigma.cdsOrVerify(LABEL, generators.H, statements, proof.or_proof);
}

pub fn membershipProofDeinit(proof: MembershipProof, allocator: std.mem.Allocator) void {
    sigma.cdsOrProofDeinit(proof.or_proof, allocator);
}
