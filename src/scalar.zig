const std = @import("std");
const scalar_field = std.crypto.ecc.Secp256k1.scalar;
const rand = @import("random.zig");

/// A canonical scalar mod the secp256k1 group order L.
/// Stored in big-endian canonical form so it can be fed directly to
/// bsvz Point multiplication and absorbed into transcripts.
pub const EncodedScalar = [32]u8;

pub const Scalar = struct {
    bytes: EncodedScalar,

    pub const zero = Scalar{ .bytes = @as([32]u8, @splat(0)) };
    pub const one = blk: {
        var b = @as([32]u8, @splat(0));
        b[31] = 1;
        break :blk Scalar{ .bytes = b };
    };

    /// Reduce a 256-bit big-endian value mod L (used for Fiat-Shamir challenges).
    pub fn fromBytes(bytes: EncodedScalar) Scalar {
        var padded = @as([48]u8, @splat(0));
        @memcpy(padded[16..], &bytes);
        return .{ .bytes = scalar_field.reduce48(padded, .big) };
    }

    pub fn toBytes(self: Scalar) EncodedScalar {
        return self.bytes;
    }

    pub fn fromInt(value: u64) Scalar {
        var b = @as([32]u8, @splat(0));
        std.mem.writeInt(u64, b[24..32], value, .big);
        return .{ .bytes = b };
    }

    pub fn toInt(self: Scalar) u64 {
        return std.mem.readInt(u64, self.bytes[24..32], .big);
    }

    /// Interpret the canonical bytes as a 256-bit big-endian integer.
    /// Valid for the full canonical range (the value is already < L).
    pub fn toU256(self: Scalar) u256 {
        return std.mem.readInt(u256, &self.bytes, .big);
    }

    /// Reduce an arbitrary 256-bit big-endian integer mod L.
    pub fn fromU256(value: u256) Scalar {
        var b: [32]u8 = undefined;
        std.mem.writeInt(u256, &b, value, .big);
        return fromBytes(b);
    }

    /// 2^exp mod L, for exp in [0, 256).
    pub fn pow2(exp: usize) Scalar {
        std.debug.assert(exp < 256);
        return fromU256(@as(u256, 1) << @intCast(exp));
    }

    /// Uniformly random scalar in [1, L) via rejection sampling.
    pub fn random() Scalar {
        var buf: [32]u8 = undefined;
        while (true) {
            rand.bytes(&buf);
            if (std.mem.readInt(u256, &buf, .big) < scalar_field.field_order) {
                return .{ .bytes = buf };
            }
        }
    }

    pub fn isZero(self: Scalar) bool {
        return std.mem.allEqual(u8, &self.bytes, 0);
    }

    pub fn eq(self: Scalar, other: Scalar) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    pub fn add(self: Scalar, other: Scalar) Scalar {
        return .{ .bytes = scalar_field.add(self.bytes, other.bytes, .big) catch unreachable };
    }

    pub fn sub(self: Scalar, other: Scalar) Scalar {
        return .{ .bytes = scalar_field.sub(self.bytes, other.bytes, .big) catch unreachable };
    }

    pub fn mul(self: Scalar, other: Scalar) Scalar {
        return .{ .bytes = scalar_field.mul(self.bytes, other.bytes, .big) catch unreachable };
    }

    pub fn neg(self: Scalar) Scalar {
        return .{ .bytes = scalar_field.neg(self.bytes, .big) catch unreachable };
    }

    pub fn invert(self: Scalar) Scalar {
        const s = scalar_field.Scalar.fromBytes(self.bytes, .big) catch unreachable;
        return .{ .bytes = s.invert().toBytes(.big) };
    }
};
