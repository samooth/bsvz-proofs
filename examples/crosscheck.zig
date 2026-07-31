const std = @import("std");
const bsvz = @import("bsvz");
const zkp = @import("bsvz-zkp");

const hex_chars = "0123456789abcdef";

fn toHexLower(out: *[2048]u8, bytes: []const u8) []const u8 {
    std.debug.assert(bytes.len * 2 <= out.len);
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0xF];
    }
    return out[0 .. bytes.len * 2];
}

fn printHex(label: []const u8, bytes: []const u8) void {
    var buf: [2048]u8 = undefined;
    std.debug.print("{s}: {s}\n", .{ label, toHexLower(&buf, bytes) });
}

pub fn main() !void {
    const G = zkp.generators.G;
    const H = zkp.generators.H;
    const U = zkp.generators.BP_U;

    const g0 = zkp.generators.hashToPoint("anchorchain/bp/g/v1/0");
    const g1 = zkp.generators.hashToPoint("anchorchain/bp/g/v1/1");
    const h0 = zkp.generators.hashToPoint("anchorchain/bp/h/v1/0");
    const h1 = zkp.generators.hashToPoint("anchorchain/bp/h/v1/1");

    var p: [33]u8 = undefined;
    @memcpy(&p, &G.toCompressedSec1().bytes[0..33].*);
    printHex("G", &p);

    const Hsec1 = H.toCompressedSec1();
    printHex("H", Hsec1.bytes[0..Hsec1.len]);
    const Usec1 = U.toCompressedSec1();
    printHex("BP_U", Usec1.bytes[0..Usec1.len]);
    const g0sec1 = g0.toCompressedSec1();
    printHex("g0", g0sec1.bytes[0..g0sec1.len]);
    const g1sec1 = g1.toCompressedSec1();
    printHex("g1", g1sec1.bytes[0..g1sec1.len]);
    const h0sec1 = h0.toCompressedSec1();
    printHex("h0", h0sec1.bytes[0..h0sec1.len]);
    const h1sec1 = h1.toCompressedSec1();
    printHex("h1", h1sec1.bytes[0..h1sec1.len]);

    // challenge over a fixed label, points [G, H], scalars [42]
    const c = zkp.transcript.challenge("crosscheck/v1", &.{ G, H }, &.{zkp.Scalar.fromInt(42)});
    printHex("challenge", &c.toBytes());

    // Pedersen commit with fixed value and blinding
    const cm = zkp.pedersen.commit(zkp.Scalar.fromInt(1234), zkp.Scalar.fromInt(5678));
    const cmsec1 = cm.toCompressedSec1();
    printHex("commit(1234,5678)", cmsec1.bytes[0..cmsec1.len]);

    // A Schnorr proof with a fixed nonce via the seeded RNG hook.
    var prng = std.Random.Xoshiro256.init(0xDEADBEEFCAFEBABE);
    var rng = prng.random();
    zkp.random.setRandomForTesting(&rng);
    const x = zkp.Scalar.fromInt(7);
    const P = G.mul(x.toBytes()) catch unreachable;
    const proof = zkp.sigma.schnorrProve("crosscheck/schnorr/v1", G, P, x);
    zkp.random.setRandomForTesting(null);
    const a_sec1 = proof.a.toCompressedSec1();
    printHex("schnorr.a", a_sec1.bytes[0..a_sec1.len]);
    printHex("schnorr.s", &proof.s.toBytes());
}
