const bsvz = @import("bsvz");
const Scalar = @import("scalar.zig").Scalar;
const generators = @import("generators.zig");

/// Pedersen commitment: C(v, r) = v*G + r*H
/// Perfectly hiding, computationally binding, additively homomorphic.
///
/// By default the AnchorChain generators G and H are used, so commitments and
/// proofs are byte-compatible with AnchorChain. The identity commitment
/// commit(0, 0) is not a usable commitment (matching AnchorChain's
/// commit(0, 0) rejection); callers that may commit to a zero value with a zero
/// blinding must guard against it.
pub const Commitment = bsvz.crypto.Point;

pub fn pointsEq(a: bsvz.crypto.Point, b: bsvz.crypto.Point) bool {
    return a.inner.equivalent(b.inner);
}

/// C(v, r) = v*G + r*H with the default generators.
pub fn commit(value: Scalar, blinding: Scalar) Commitment {
    return commitWithGens(value, blinding, generators.G, generators.H);
}

/// C(v, r) = v*G + r*H with explicit generators.
pub fn commitWithGens(value: Scalar, blinding: Scalar, G: bsvz.crypto.Point, H: bsvz.crypto.Point) Commitment {
    const vG = G.mul(value.toBytes()) catch unreachable;
    const rH = H.mul(blinding.toBytes()) catch unreachable;
    return vG.add(rH);
}

pub fn verify(commitment: Commitment, value: Scalar, blinding: Scalar) bool {
    return pointsEq(commitment, commit(value, blinding));
}

pub fn verifyWithGens(commitment: Commitment, value: Scalar, blinding: Scalar, G: bsvz.crypto.Point, H: bsvz.crypto.Point) bool {
    return pointsEq(commitment, commitWithGens(value, blinding, G, H));
}

/// Homomorphic addition: C(v1,r1) + C(v2,r2) = C(v1+v2, r1+r2)
pub fn add(c1: Commitment, c2: Commitment) Commitment {
    return c1.add(c2);
}

/// Homomorphic subtraction: C(v1,r1) - C(v2,r2) = C(v1-v2, r1-r2)
pub fn sub(c1: Commitment, c2: Commitment) Commitment {
    return c1.add(c2.negate());
}
