const std = @import("std");
const bsvz = @import("bsvz");
const Scalar = @import("scalar.zig").Scalar;

/// SHA-256.
pub fn sha256(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(data);
    h.final(&out);
    return out;
}

/// Double-SHA-256, matching AnchorChain's `doubleSha256`.
pub fn sha256d(data: []const u8) [32]u8 {
    const first = sha256(data);
    return sha256(&first);
}

/// Fiat-Shamir transcript hasher. The challenge is the double-SHA-256 of a
/// domain label followed by the canonical (compressed SEC1) encoding of every
/// public point and scalar in the statement and the prover's commitments.
///
/// This is the byte-for-byte equivalent of AnchorChain's `challenge(label,
/// points, scalars)`: SHA-256d over the concatenation of the label bytes, the
/// compressed SEC1 encoding of each point, and the 32-byte big-endian encoding
/// of each scalar, reduced mod the group order, with a zero challenge mapped to
/// one. The incremental builder lets proofs hash `[base, ...statements,
/// ...a]` without allocating a concatenated array.
pub const Hasher = struct {
    inner: std.crypto.hash.sha2.Sha256,

    pub fn init(label: []const u8) Hasher {
        var self = Hasher{ .inner = std.crypto.hash.sha2.Sha256.init(.{}) };
        self.inner.update(label);
        return self;
    }

    pub fn addPoint(self: *Hasher, point: bsvz.crypto.Point) void {
        const sec1 = point.toCompressedSec1();
        self.inner.update(sec1.bytes[0..sec1.len]);
    }

    pub fn addPoints(self: *Hasher, points: []const bsvz.crypto.Point) void {
        for (points) |p| self.addPoint(p);
    }

    pub fn addScalar(self: *Hasher, scalar: Scalar) void {
        const bytes = scalar.toBytes();
        self.inner.update(&bytes);
    }

    pub fn addScalars(self: *Hasher, scalars: []const Scalar) void {
        for (scalars) |s| self.addScalar(s);
    }

    /// Finish the challenge: SHA-256d over the transcript, reduce mod the
    /// group order, and map a (negligible) zero result to one.
    pub fn finish(self: *Hasher) Scalar {
        var digest: [32]u8 = undefined;
        self.inner.final(&digest);
        const out = sha256(&digest);
        var c = Scalar.fromBytes(out);
        if (c.isZero()) return Scalar.one;
        return c;
    }
};

/// Fiat-Shamir challenge over a label, a list of points, and a list of scalars
/// — the direct equivalent of AnchorChain's `challenge`.
pub fn challenge(label: []const u8, points: []const bsvz.crypto.Point, scalars: []const Scalar) Scalar {
    var h = Hasher.init(label);
    h.addPoints(points);
    h.addScalars(scalars);
    return h.finish();
}
