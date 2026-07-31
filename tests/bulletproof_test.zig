const std = @import("std");
const zkp = @import("bsvz-zkp");

fn runBPTest(value: zkp.Scalar, num_bits: usize) !bool {
    const blinding = zkp.Scalar.random();
    const result = try zkp.bulletproofs.proveRangeBP(std.testing.allocator, value, blinding, num_bits);
    defer zkp.bulletproofs.bulletproofDeinit(result.proof, std.testing.allocator);
    return zkp.bulletproofs.verifyRangeBP(std.testing.allocator, result.commitment, result.proof);
}

test "bulletproof proves and verifies 8 bits" {
    try std.testing.expect(try runBPTest(zkp.Scalar.fromInt(42), 8));
}

test "bulletproof upper bound 8 bits" {
    try std.testing.expect(try runBPTest(zkp.Scalar.fromInt(255), 8));
}

test "bulletproof zero value" {
    try std.testing.expect(try runBPTest(zkp.Scalar.zero, 16));
}

test "bulletproof 32 bits" {
    try std.testing.expect(try runBPTest(zkp.Scalar.fromInt(0xFFFFFFFF), 32));
}

test "bulletproof 64 bits" {
    try std.testing.expect(try runBPTest(zkp.Scalar.fromInt(0xFFFFFFFFFFFFFFFF), 64));
}

test "bulletproof 128 bits" {
    try std.testing.expect(try runBPTest(zkp.Scalar.fromU256((@as(u256, 1) << 100) + 7), 128));
}

test "bulletproof wrong commitment fails" {
    const value = zkp.Scalar.fromInt(42);
    const blinding = zkp.Scalar.random();
    const result = try zkp.bulletproofs.proveRangeBP(std.testing.allocator, value, blinding, 8);
    defer zkp.bulletproofs.bulletproofDeinit(result.proof, std.testing.allocator);

    const other_commitment = zkp.pedersen.commit(zkp.Scalar.fromInt(43), blinding);
    try std.testing.expect(!zkp.bulletproofs.verifyRangeBP(std.testing.allocator, other_commitment, result.proof));
}

test "bulletproof tampered T1 fails" {
    const value = zkp.Scalar.fromInt(42);
    const blinding = zkp.Scalar.random();
    const result = try zkp.bulletproofs.proveRangeBP(std.testing.allocator, value, blinding, 8);
    defer zkp.bulletproofs.bulletproofDeinit(result.proof, std.testing.allocator);

    var proof = result.proof;
    proof.T1 = proof.T1.add(zkp.generators.H);
    try std.testing.expect(!zkp.bulletproofs.verifyRangeBP(std.testing.allocator, result.commitment, proof));
}

test "bulletproof tampered ip proof fails" {
    const value = zkp.Scalar.fromInt(42);
    const blinding = zkp.Scalar.random();
    const result = try zkp.bulletproofs.proveRangeBP(std.testing.allocator, value, blinding, 8);
    defer zkp.bulletproofs.bulletproofDeinit(result.proof, std.testing.allocator);

    var proof = result.proof;
    proof.ip.a = proof.ip.a.add(zkp.Scalar.one);
    try std.testing.expect(!zkp.bulletproofs.verifyRangeBP(std.testing.allocator, result.commitment, proof));
}

test "bulletproof non-pow2 bits rejected" {
    try std.testing.expectError(
        error.InvalidRangeBits,
        zkp.bulletproofs.proveRangeBP(std.testing.allocator, zkp.Scalar.fromInt(42), zkp.Scalar.random(), 12),
    );
    try std.testing.expectError(
        error.InvalidRangeBits,
        zkp.bulletproofs.proveRangeBP(std.testing.allocator, zkp.Scalar.zero, zkp.Scalar.zero, 0),
    );
    try std.testing.expectError(
        error.InvalidRangeBits,
        zkp.bulletproofs.proveRangeBP(std.testing.allocator, zkp.Scalar.zero, zkp.Scalar.zero, 512),
    );
}

test "bulletproof out of range value rejected" {
    try std.testing.expectError(
        error.ValueOutOfRange,
        zkp.bulletproofs.proveRangeBP(std.testing.allocator, zkp.Scalar.fromInt(256), zkp.Scalar.random(), 8),
    );
}

test "bulletproof verify rejects wrong round count" {
    const value = zkp.Scalar.fromInt(42);
    const blinding = zkp.Scalar.random();
    const result = try zkp.bulletproofs.proveRangeBP(std.testing.allocator, value, blinding, 8);
    defer zkp.bulletproofs.bulletproofDeinit(result.proof, std.testing.allocator);

    var proof = result.proof;
    const truncated = proof.ip.L[0 .. proof.ip.L.len - 1];
    proof.ip.L = truncated;
    proof.ip.R = proof.ip.R[0 .. proof.ip.R.len - 1];
    try std.testing.expect(!zkp.bulletproofs.verifyRangeBP(std.testing.allocator, result.commitment, proof));
}

test "bulletproof deterministic under seeded rng" {
    const value = zkp.Scalar.fromInt(12345);
    const blinding = zkp.Scalar.fromInt(6789);

    var prng1 = std.Random.Xoshiro256.init(0x1234567890ABCDEF);
    var rng1 = prng1.random();
    zkp.random.setRandomForTesting(&rng1);
    const r1 = try zkp.bulletproofs.proveRangeBP(std.testing.allocator, value, blinding, 16);
    zkp.random.setRandomForTesting(null);
    defer zkp.bulletproofs.bulletproofDeinit(r1.proof, std.testing.allocator);

    var prng2 = std.Random.Xoshiro256.init(0x1234567890ABCDEF);
    var rng2 = prng2.random();
    zkp.random.setRandomForTesting(&rng2);
    const r2 = try zkp.bulletproofs.proveRangeBP(std.testing.allocator, value, blinding, 16);
    zkp.random.setRandomForTesting(null);
    defer zkp.bulletproofs.bulletproofDeinit(r2.proof, std.testing.allocator);

    try std.testing.expect(zkp.pedersen.pointsEq(r1.proof.A, r2.proof.A));
    try std.testing.expect(r1.proof.taux.eq(r2.proof.taux));
    try std.testing.expect(r1.proof.ip.a.eq(r2.proof.ip.a));
}
