const std = @import("std");
const bsvz = @import("bsvz");
const zkp = @import("bsvz-proofs");

const G = zkp.generators.G;

test "schnorr proof of knowledge" {
    const x = zkp.Scalar.random();
    const P = G.mul(x.toBytes()) catch unreachable;
    const proof = zkp.sigma.schnorrProve("bsvz-proofs/schnorr/test/v1", G, P, x);
    try std.testing.expect(zkp.sigma.schnorrVerify("bsvz-proofs/schnorr/test/v1", G, P, proof));
}

test "schnorr proof fails with wrong secret" {
    const x = zkp.Scalar.random();
    const wrong_x = zkp.Scalar.random();
    const P = G.mul(x.toBytes()) catch unreachable;
    const proof = zkp.sigma.schnorrProve("bsvz-proofs/schnorr/test/v1", G, P, wrong_x);
    try std.testing.expect(!zkp.sigma.schnorrVerify("bsvz-proofs/schnorr/test/v1", G, P, proof));
}

test "schnorr proof fails with wrong label" {
    const x = zkp.Scalar.random();
    const P = G.mul(x.toBytes()) catch unreachable;
    const proof = zkp.sigma.schnorrProve("bsvz-proofs/schnorr/test/v1", G, P, x);
    try std.testing.expect(!zkp.sigma.schnorrVerify("bsvz-proofs/schnorr/test/v2", G, P, proof));
}

test "schnorr proof fails with wrong base" {
    const x = zkp.Scalar.random();
    const P = G.mul(x.toBytes()) catch unreachable;
    const proof = zkp.sigma.schnorrProve("bsvz-proofs/schnorr/test/v1", G, P, x);
    try std.testing.expect(!zkp.sigma.schnorrVerify("bsvz-proofs/schnorr/test/v1", zkp.generators.H, P, proof));
}

test "cds-or one-of-two known index zero" {
    const x0 = zkp.Scalar.random();
    const x1 = zkp.Scalar.random();
    const P0 = G.mul(x0.toBytes()) catch unreachable;
    const P1 = G.mul(x1.toBytes()) catch unreachable;

    const statements = [_]bsvz.crypto.Point{ P0, P1 };
    const proof = try zkp.sigma.cdsOrProve(std.testing.allocator, "bsvz-proofs/cds-or/test/v1", G, &statements, 0, x0);
    defer zkp.sigma.cdsOrProofDeinit(proof, std.testing.allocator);

    try std.testing.expect(zkp.sigma.cdsOrVerify("bsvz-proofs/cds-or/test/v1", G, &statements, proof));
}

test "cds-or one-of-two known index one" {
    const x0 = zkp.Scalar.random();
    const x1 = zkp.Scalar.random();
    const P0 = G.mul(x0.toBytes()) catch unreachable;
    const P1 = G.mul(x1.toBytes()) catch unreachable;

    const statements = [_]bsvz.crypto.Point{ P0, P1 };
    const proof = try zkp.sigma.cdsOrProve(std.testing.allocator, "bsvz-proofs/cds-or/test/v1", G, &statements, 1, x1);
    defer zkp.sigma.cdsOrProofDeinit(proof, std.testing.allocator);

    try std.testing.expect(zkp.sigma.cdsOrVerify("bsvz-proofs/cds-or/test/v1", G, &statements, proof));
}

test "cds-or one-of-three" {
    const xs = [_]zkp.Scalar{ zkp.Scalar.random(), zkp.Scalar.random(), zkp.Scalar.random() };
    var statements: [3]bsvz.crypto.Point = undefined;
    for (xs, 0..) |x, i| statements[i] = G.mul(x.toBytes()) catch unreachable;

    const proof = try zkp.sigma.cdsOrProve(std.testing.allocator, "bsvz-proofs/cds-or/test/v1", G, &statements, 2, xs[2]);
    defer zkp.sigma.cdsOrProofDeinit(proof, std.testing.allocator);

    try std.testing.expect(zkp.sigma.cdsOrVerify("bsvz-proofs/cds-or/test/v1", G, &statements, proof));
}

test "cds-or fails for unknown secret" {
    const x0 = zkp.Scalar.random();
    const x1 = zkp.Scalar.random();
    const x_unknown = zkp.Scalar.random();
    const P0 = G.mul(x0.toBytes()) catch unreachable;
    const P1 = G.mul(x1.toBytes()) catch unreachable;

    const statements = [_]bsvz.crypto.Point{ P0, P1 };
    const proof = try zkp.sigma.cdsOrProve(std.testing.allocator, "bsvz-proofs/cds-or/test/v1", G, &statements, 0, x_unknown);
    defer zkp.sigma.cdsOrProofDeinit(proof, std.testing.allocator);

    try std.testing.expect(!zkp.sigma.cdsOrVerify("bsvz-proofs/cds-or/test/v1", G, &statements, proof));
}

test "cds-or fails for tampered e-values" {
    const x0 = zkp.Scalar.random();
    const x1 = zkp.Scalar.random();
    const P0 = G.mul(x0.toBytes()) catch unreachable;
    const P1 = G.mul(x1.toBytes()) catch unreachable;

    const statements = [_]bsvz.crypto.Point{ P0, P1 };
    var proof = try zkp.sigma.cdsOrProve(std.testing.allocator, "bsvz-proofs/cds-or/test/v1", G, &statements, 0, x0);
    defer zkp.sigma.cdsOrProofDeinit(proof, std.testing.allocator);

    proof.e_values[0] = proof.e_values[0].add(zkp.Scalar.one);
    try std.testing.expect(!zkp.sigma.cdsOrVerify("bsvz-proofs/cds-or/test/v1", G, &statements, proof));
}

test "cds-or rejects length mismatch" {
    const x0 = zkp.Scalar.random();
    const P0 = G.mul(x0.toBytes()) catch unreachable;

    const statements = [_]bsvz.crypto.Point{P0};
    const proof = try zkp.sigma.cdsOrProve(std.testing.allocator, "bsvz-proofs/cds-or/test/v1", G, &statements, 0, x0);
    defer zkp.sigma.cdsOrProofDeinit(proof, std.testing.allocator);

    const empty = [_]bsvz.crypto.Point{};
    try std.testing.expect(!zkp.sigma.cdsOrVerify("bsvz-proofs/cds-or/test/v1", G, &empty, proof));
}
