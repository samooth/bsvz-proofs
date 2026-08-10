const std = @import("std");
const zkp = @import("bsvz-proofs");

test "conservation proves balanced transaction" {
    const v1 = zkp.Scalar.fromInt(10);
    const r1 = zkp.Scalar.random();
    const c1 = zkp.pedersen.commit(v1, r1);

    const v2 = zkp.Scalar.fromInt(20);
    const r2 = zkp.Scalar.random();
    const c2 = zkp.pedersen.commit(v2, r2);

    const vo = zkp.Scalar.fromInt(30);
    const ro = zkp.Scalar.random();
    const co = zkp.pedersen.commit(vo, ro);

    const inputs = [_]zkp.pedersen.Commitment{ c1, c2 };
    const outputs = [_]zkp.pedersen.Commitment{co};
    const excess = r1.add(r2).sub(ro);

    const proof = zkp.conservation.proveConservation(&inputs, &outputs, excess) orelse return error.NoProof;
    try std.testing.expect(zkp.conservation.verifyConservation(&inputs, &outputs, proof));
}

test "conservation single input single output" {
    const vi = zkp.Scalar.fromInt(100);
    const ri = zkp.Scalar.random();
    const ci = zkp.pedersen.commit(vi, ri);

    const vo = zkp.Scalar.fromInt(100);
    const ro = zkp.Scalar.random();
    const co = zkp.pedersen.commit(vo, ro);

    const inputs = [_]zkp.pedersen.Commitment{ci};
    const outputs = [_]zkp.pedersen.Commitment{co};

    const proof = zkp.conservation.proveConservation(&inputs, &outputs, ri.sub(ro)) orelse return error.NoProof;
    try std.testing.expect(zkp.conservation.verifyConservation(&inputs, &outputs, proof));
}

test "unbalanced transaction fails verification" {
    const v1 = zkp.Scalar.fromInt(10);
    const r1 = zkp.Scalar.random();
    const c1 = zkp.pedersen.commit(v1, r1);

    const v2 = zkp.Scalar.fromInt(20);
    const r2 = zkp.Scalar.random();
    const c2 = zkp.pedersen.commit(v2, r2);

    // outputs sum to 31, inputs to 30: books do not balance
    const vo = zkp.Scalar.fromInt(31);
    const ro = zkp.Scalar.random();
    const co = zkp.pedersen.commit(vo, ro);

    const inputs = [_]zkp.pedersen.Commitment{ c1, c2 };
    const outputs = [_]zkp.pedersen.Commitment{co};

    // A prover who does not know log_H(D) cannot make a proof that verifies.
    const fake_excess = r1.add(r2).sub(ro);
    const proof = zkp.conservation.proveConservation(&inputs, &outputs, fake_excess) orelse return error.NoProof;
    try std.testing.expect(!zkp.conservation.verifyConservation(&inputs, &outputs, proof));
}

test "conservation wrong excess blinding fails" {
    const vi = zkp.Scalar.fromInt(50);
    const ri = zkp.Scalar.random();
    const ci = zkp.pedersen.commit(vi, ri);

    const vo = zkp.Scalar.fromInt(50);
    const ro = zkp.Scalar.random();
    const co = zkp.pedersen.commit(vo, ro);

    const inputs = [_]zkp.pedersen.Commitment{ci};
    const outputs = [_]zkp.pedersen.Commitment{co};

    const proof = zkp.conservation.proveConservation(&inputs, &outputs, zkp.Scalar.random()) orelse return error.NoProof;
    try std.testing.expect(!zkp.conservation.verifyConservation(&inputs, &outputs, proof));
}

test "netCommitment of empty transaction is null" {
    const empty = [_]zkp.pedersen.Commitment{};
    try std.testing.expect(zkp.conservation.netCommitment(&empty, &empty) == null);
    try std.testing.expect(zkp.conservation.proveConservation(&empty, &empty, zkp.Scalar.zero) == null);
    const proof = zkp.sigma.schnorrProve("x", zkp.generators.H, zkp.generators.G, zkp.Scalar.zero);
    try std.testing.expect(!zkp.conservation.verifyConservation(&empty, &empty, proof));
}

test "netCommitment is additively homomorphic" {
    const v1 = zkp.Scalar.fromInt(10);
    const r1 = zkp.Scalar.random();
    const c1 = zkp.pedersen.commit(v1, r1);
    const vo = zkp.Scalar.fromInt(10);
    const ro = zkp.Scalar.random();
    const co = zkp.pedersen.commit(vo, ro);

    const inputs = [_]zkp.pedersen.Commitment{c1};
    const outputs = [_]zkp.pedersen.Commitment{co};
    const d = zkp.conservation.netCommitment(&inputs, &outputs).?;

    // D must be exactly (r1 - ro)*H — no G component.
    const expected = zkp.generators.H.mul(r1.sub(ro).toBytes()) catch unreachable;
    try std.testing.expect(zkp.pedersen.pointsEq(d, expected));
}
