const std = @import("std");
const zkp = @import("bsvz-zkp");

test "membership proves membership" {
    const set = [_]zkp.Scalar{ zkp.Scalar.fromInt(1), zkp.Scalar.fromInt(42), zkp.Scalar.fromInt(999) };
    const value = zkp.Scalar.fromInt(42);
    const blinding = zkp.Scalar.random();
    const commitment = zkp.pedersen.commit(value, blinding);

    const proof = try zkp.membership.proveMembership(std.testing.allocator, commitment, blinding, &set, value);
    defer zkp.membership.membershipProofDeinit(proof, std.testing.allocator);

    try std.testing.expect(zkp.membership.verifyMembership(std.testing.allocator, commitment, &set, proof));
}

test "membership for first and last elements" {
    const set = [_]zkp.Scalar{ zkp.Scalar.fromInt(7), zkp.Scalar.fromInt(8), zkp.Scalar.fromInt(9) };
    for (0..set.len) |idx| {
        const value = set[idx];
        const blinding = zkp.Scalar.random();
        const commitment = zkp.pedersen.commit(value, blinding);
        const proof = try zkp.membership.proveMembership(std.testing.allocator, commitment, blinding, &set, value);
        defer zkp.membership.membershipProofDeinit(proof, std.testing.allocator);
        try std.testing.expect(zkp.membership.verifyMembership(std.testing.allocator, commitment, &set, proof));
    }
}

test "value not in set errors" {
    const set = [_]zkp.Scalar{ zkp.Scalar.fromInt(1), zkp.Scalar.fromInt(42), zkp.Scalar.fromInt(999) };
    const value = zkp.Scalar.fromInt(1000);
    const blinding = zkp.Scalar.random();
    const commitment = zkp.pedersen.commit(value, blinding);

    try std.testing.expectError(
        error.ValueNotInSet,
        zkp.membership.proveMembership(std.testing.allocator, commitment, blinding, &set, value),
    );
}

test "empty set errors" {
    const value = zkp.Scalar.fromInt(5);
    const blinding = zkp.Scalar.random();
    const commitment = zkp.pedersen.commit(value, blinding);
    const empty = [_]zkp.Scalar{};

    try std.testing.expectError(
        error.EmptySet,
        zkp.membership.proveMembership(std.testing.allocator, commitment, blinding, &empty, value),
    );
}

test "wrong commitment fails verification" {
    const set = [_]zkp.Scalar{ zkp.Scalar.fromInt(1), zkp.Scalar.fromInt(42), zkp.Scalar.fromInt(999) };
    const value = zkp.Scalar.fromInt(42);
    const blinding = zkp.Scalar.random();
    const commitment = zkp.pedersen.commit(value, blinding);

    const proof = try zkp.membership.proveMembership(std.testing.allocator, commitment, blinding, &set, value);
    defer zkp.membership.membershipProofDeinit(proof, std.testing.allocator);

    const wrong_commitment = zkp.pedersen.commit(zkp.Scalar.fromInt(43), blinding);
    try std.testing.expect(!zkp.membership.verifyMembership(std.testing.allocator, wrong_commitment, &set, proof));
}

test "set size mismatch fails verification" {
    const set = [_]zkp.Scalar{ zkp.Scalar.fromInt(1), zkp.Scalar.fromInt(42), zkp.Scalar.fromInt(999) };
    const value = zkp.Scalar.fromInt(42);
    const blinding = zkp.Scalar.random();
    const commitment = zkp.pedersen.commit(value, blinding);

    const proof = try zkp.membership.proveMembership(std.testing.allocator, commitment, blinding, &set, value);
    defer zkp.membership.membershipProofDeinit(proof, std.testing.allocator);

    const other_set = [_]zkp.Scalar{ zkp.Scalar.fromInt(1), zkp.Scalar.fromInt(42) };
    try std.testing.expect(!zkp.membership.verifyMembership(std.testing.allocator, commitment, &other_set, proof));
}
