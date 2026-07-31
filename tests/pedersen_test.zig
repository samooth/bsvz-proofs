const std = @import("std");
const zkp = @import("bsvz-zkp");

test "pedersen commit and verify" {
    const value = zkp.Scalar.fromInt(42);
    const blinding = zkp.Scalar.random();
    const c = zkp.pedersen.commit(value, blinding);
    try std.testing.expect(zkp.pedersen.verify(c, value, blinding));

    try std.testing.expect(!zkp.pedersen.verify(c, zkp.Scalar.fromInt(43), blinding));
    try std.testing.expect(!zkp.pedersen.verify(c, value, zkp.Scalar.random()));
}

test "pedersen homomorphic addition" {
    const v1 = zkp.Scalar.fromInt(10);
    const r1 = zkp.Scalar.random();
    const c1 = zkp.pedersen.commit(v1, r1);

    const v2 = zkp.Scalar.fromInt(20);
    const r2 = zkp.Scalar.random();
    const c2 = zkp.pedersen.commit(v2, r2);

    const c_sum = zkp.pedersen.add(c1, c2);
    try std.testing.expect(zkp.pedersen.verify(c_sum, v1.add(v2), r1.add(r2)));
}

test "pedersen homomorphic subtraction" {
    const v1 = zkp.Scalar.fromInt(30);
    const r1 = zkp.Scalar.random();
    const c1 = zkp.pedersen.commit(v1, r1);

    const v2 = zkp.Scalar.fromInt(12);
    const r2 = zkp.Scalar.random();
    const c2 = zkp.pedersen.commit(v2, r2);

    const c_diff = zkp.pedersen.sub(c1, c2);
    try std.testing.expect(zkp.pedersen.verify(c_diff, v1.sub(v2), r1.sub(r2)));
}

test "commit with explicit generators matches default" {
    const value = zkp.Scalar.fromInt(7);
    const blinding = zkp.Scalar.random();
    const c_default = zkp.pedersen.commit(value, blinding);
    const c_explicit = zkp.pedersen.commitWithGens(value, blinding, zkp.generators.G, zkp.generators.H);
    try std.testing.expect(zkp.pedersen.pointsEq(c_default, c_explicit));
}

test "default generators are valid curve points" {
    try std.testing.expect(zkp.generators.G.isOnCurve());
    try std.testing.expect(!zkp.generators.G.isIdentity());
    try std.testing.expect(zkp.generators.H.isOnCurve());
    try std.testing.expect(!zkp.generators.H.isIdentity());
    try std.testing.expect(zkp.generators.BP_U.isOnCurve());
    try std.testing.expect(!zkp.generators.BP_U.isIdentity());
}

test "hashToPoint is deterministic" {
    const a = zkp.generators.hashToPoint("bsvz-zkp/test/domain/v1");
    const b = zkp.generators.hashToPoint("bsvz-zkp/test/domain/v1");
    try std.testing.expect(zkp.pedersen.pointsEq(a, b));
}

test "challenge differs across labels and inputs" {
    const a = zkp.transcript.challenge("label-a", &.{}, &.{});
    const b = zkp.transcript.challenge("label-b", &.{}, &.{});
    try std.testing.expect(!a.eq(b));

    const pt = zkp.generators.H;
    const c = zkp.transcript.challenge("label-a", &.{pt}, &.{});
    try std.testing.expect(!a.eq(c));
}

test "scalar 256-bit roundtrip" {
    const v = zkp.Scalar.fromU256((@as(u256, 1) << 200) + 0xDEADBEEF);
    try std.testing.expectEqual((@as(u256, 1) << 200) + 0xDEADBEEF, v.toU256());
    try std.testing.expectEqual(@as(u256, 1), zkp.Scalar.pow2(0).toU256());
    try std.testing.expectEqual(@as(u256, 1) << 255, zkp.Scalar.pow2(255).toU256());
}
