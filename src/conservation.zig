const std = @import("std");
const bsvz = @import("bsvz");
const Scalar = @import("scalar.zig").Scalar;
const sigma = @import("sigma.zig");
const generators = @import("generators.zig");

/// Homomorphic value conservation in zero-knowledge. Given confidential input
/// and output commitments, the net commitment D = sum(inputs) - sum(outputs)
/// is public. If value is conserved the G component cancels and
/// D = (excess blinding)*H; the prover proves knowledge of log_H(D) with a
/// Schnorr proof. The verifier learns only that the books balance — never any
/// amount nor the excess blinding. Mirrors AnchorChain's `conservation.ts`.
const LABEL = "anchorchain/privacy/conservation/v1";

fn sumPoints(points: []const bsvz.crypto.Point) ?bsvz.crypto.Point {
    var acc: ?bsvz.crypto.Point = null;
    for (points) |p| {
        acc = if (acc) |a| a.add(p) else p;
    }
    return acc;
}

/// The public net commitment D = sum(inputs) - sum(outputs).
pub fn netCommitment(inputs: []const bsvz.crypto.Point, outputs: []const bsvz.crypto.Point) ?bsvz.crypto.Point {
    const in_sum = sumPoints(inputs) orelse return null;
    const out_sum = sumPoints(outputs);
    return if (out_sum) |o| in_sum.add(o.negate()) else in_sum;
}

/// Prove conservation: the prover supplies the excess blinding
/// r = sum(r_in) - sum(r_out); the proof is a Schnorr PoK that D = r*H.
/// Returns null if either side is empty.
pub fn proveConservation(
    inputs: []const bsvz.crypto.Point,
    outputs: []const bsvz.crypto.Point,
    excess_blinding: Scalar,
) ?sigma.SchnorrProof {
    const d = netCommitment(inputs, outputs) orelse return null;
    return sigma.schnorrProve(LABEL, generators.H, d, excess_blinding);
}

pub fn verifyConservation(
    inputs: []const bsvz.crypto.Point,
    outputs: []const bsvz.crypto.Point,
    proof: sigma.SchnorrProof,
) bool {
    const d = netCommitment(inputs, outputs) orelse return false;
    return sigma.schnorrVerify(LABEL, generators.H, d, proof);
}
