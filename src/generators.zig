const std = @import("std");
const bsvz = @import("bsvz");
const Scalar = @import("scalar.zig").Scalar;
const transcript = @import("transcript.zig");

/// Domain strings fixed to match AnchorChain exactly.
pub const default_h_domain = "AnchorChain/pedersen/H/v1";
pub const bp_g_domain = "anchorchain/bp/g/v1";
pub const bp_h_domain = "anchorchain/bp/h/v1";
pub const bp_u_domain = "anchorchain/bp/U/v1";

/// Nothing-up-my-sleeve hash-to-curve (try-and-increment), byte-compatible
/// with AnchorChain's `hashToPoint`: for counter = 0, 1, ..., hash
/// SHA-256d(domain:counter) as the x-coordinate and try the even-y (0x02) then
/// odd-y (0x03) compressed encodings, returning the first valid secp256k1
/// point. No discrete-log relation with G, H, or the other generators is known.
pub fn hashToPoint(domain: []const u8) bsvz.crypto.Point {
    var counter: u64 = 0;
    while (counter < 100_000) : (counter += 1) {
        var buf: [64]u8 = undefined;
        const label = std.fmt.bufPrint(&buf, "{s}:{d}", .{ domain, counter }) catch unreachable;
        const x = transcript.sha256d(label);
        for ([_]u8{ 0x02, 0x03 }) |prefix| {
            var compressed: [33]u8 = undefined;
            compressed[0] = prefix;
            @memcpy(compressed[1..], &x);
            if (bsvz.crypto.Point.fromCompressedSec1(&compressed)) |p| {
                return p;
            } else |_| {}
        }
    }
    unreachable;
}

/// Derive n independent generators hashToPoint(domain + "/" + i), matching
/// AnchorChain's `generatorVector`.
pub fn generatorVector(domain: []const u8, n: usize, allocator: std.mem.Allocator) ![]bsvz.crypto.Point {
    var vec = try allocator.alloc(bsvz.crypto.Point, n);
    errdefer allocator.free(vec);
    for (0..n) |i| {
        var buf: [64]u8 = undefined;
        const label = std.fmt.bufPrint(&buf, "{s}/{d}", .{ domain, i }) catch unreachable;
        vec[i] = hashToPoint(label);
    }
    return vec;
}

/// The secp256k1 base point G.
pub const G = blk: {
    @setEvalBranchQuota(500_000);
    break :blk bsvz.crypto.Point.basePointMul(Scalar.one.toBytes()) catch unreachable;
};

/// The default Pedersen generator H = hashToPoint("AnchorChain/pedersen/H/v1"),
/// matching AnchorChain's CURVE_H.
pub const H = blk: {
    @setEvalBranchQuota(2_000_000);
    break :blk hashToPoint(default_h_domain);
};

/// The inner-product binding generator U = hashToPoint("anchorchain/bp/U/v1"),
/// matching AnchorChain's BP_U.
pub const BP_U = blk: {
    @setEvalBranchQuota(2_000_000);
    break :blk hashToPoint(bp_u_domain);
};
