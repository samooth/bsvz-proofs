const std = @import("std");
const zkp = @import("bsvz-proofs");

fn runRangeTest(value: zkp.Scalar, num_bits: usize) !bool {
    const blinding = zkp.Scalar.random();
    const result = try zkp.rangeproof.linearProve(std.testing.allocator, value, blinding, num_bits);
    defer zkp.rangeproof.linearProofDeinit(result.proof, std.testing.allocator);
    return zkp.rangeproof.linearVerify(result.commitment, result.proof);
}

test "linear range proof proves and verifies" {
    try std.testing.expect(try runRangeTest(zkp.Scalar.fromInt(42), 8));
}

test "linear range proof at upper bound" {
    try std.testing.expect(try runRangeTest(zkp.Scalar.fromInt(255), 8));
}

test "linear range proof zero value" {
    try std.testing.expect(try runRangeTest(zkp.Scalar.zero, 16));
}

test "linear range proof large value 64 bits" {
    try std.testing.expect(try runRangeTest(zkp.Scalar.fromInt(0xFFFFFFFFFFFFFFFF), 64));
}

test "linear range proof 200-bit value" {
    try std.testing.expect(try runRangeTest(zkp.Scalar.fromU256((@as(u256, 1) << 200) + 12345), 256));
}

test "linear range proof commits match bit decomposition" {
    const value = zkp.Scalar.fromInt(42);
    const blinding = zkp.Scalar.random();
    const num_bits = 8;
    const result = try zkp.rangeproof.linearProve(std.testing.allocator, value, blinding, num_bits);
    defer zkp.rangeproof.linearProofDeinit(result.proof, std.testing.allocator);

    try std.testing.expect(zkp.rangeproof.linearVerify(result.commitment, result.proof));

    // The returned commitment must be exactly C(42, blinding).
    try std.testing.expect(zkp.pedersen.verify(result.commitment, value, blinding));
}

test "tampered bit commitment fails verification" {
    const value = zkp.Scalar.fromInt(42);
    const blinding = zkp.Scalar.random();
    const result = try zkp.rangeproof.linearProve(std.testing.allocator, value, blinding, 8);
    defer zkp.rangeproof.linearProofDeinit(result.proof, std.testing.allocator);

    var proof = result.proof;
    proof.bit_commitments[3] = proof.bit_commitments[3].add(zkp.generators.H);
    try std.testing.expect(!zkp.rangeproof.linearVerify(result.commitment, proof));
}

test "wrong commitment fails verification" {
    const value = zkp.Scalar.fromInt(42);
    const blinding = zkp.Scalar.random();
    const result = try zkp.rangeproof.linearProve(std.testing.allocator, value, blinding, 8);
    defer zkp.rangeproof.linearProofDeinit(result.proof, std.testing.allocator);

    const other_commitment = zkp.pedersen.commit(zkp.Scalar.fromInt(43), blinding);
    try std.testing.expect(!zkp.rangeproof.linearVerify(other_commitment, result.proof));
}

test "out of range value is rejected" {
    try std.testing.expectError(
        error.ValueOutOfRange,
        zkp.rangeproof.linearProve(std.testing.allocator, zkp.Scalar.fromInt(256), zkp.Scalar.random(), 8),
    );
}

test "invalid num_bits is rejected" {
    try std.testing.expectError(
        error.InvalidRangeBits,
        zkp.rangeproof.linearProve(std.testing.allocator, zkp.Scalar.zero, zkp.Scalar.zero, 0),
    );
    try std.testing.expectError(
        error.InvalidRangeBits,
        zkp.rangeproof.linearProve(std.testing.allocator, zkp.Scalar.zero, zkp.Scalar.zero, 257),
    );
}
