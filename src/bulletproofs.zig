const std = @import("std");
const bsvz = @import("bsvz");
const Scalar = @import("scalar.zig").Scalar;
const pedersen = @import("pedersen.zig");
const transcript = @import("transcript.zig");
const generators = @import("generators.zig");

/// Bulletproofs range proof: a Pedersen commitment V = v*G + r*H hides a value
/// v in [0, 2^bits) and the proof is LOGARITHMIC in bits (an inner-product
/// argument folds a 2n-length witness in log2(n) rounds). Ported from
/// AnchorChain's `bulletproofs.ts` so proofs are byte-compatible: same labels
/// (`anchorchain/bp/{y,z,x}`, `anchorchain/bp/ip/{round}`), same generator
/// vectors, same Fiat-Shamir challenges. bits must be a power of two in
/// (0, 256]; value must fit in bits. Sound and zero-knowledge under discrete
/// log in the random-oracle model; no trusted setup; no post-quantum claim.
pub const InnerProductProof = struct {
    L: []bsvz.crypto.Point,
    R: []bsvz.crypto.Point,
    a: Scalar,
    b: Scalar,
};

pub const RangeProofBP = struct {
    bits: usize,
    A: bsvz.crypto.Point,
    S: bsvz.crypto.Point,
    T1: bsvz.crypto.Point,
    T2: bsvz.crypto.Point,
    taux: Scalar,
    mu: Scalar,
    tHat: Scalar,
    ip: InnerProductProof,
};

pub const ProveResult = struct {
    proof: RangeProofBP,
    commitment: bsvz.crypto.Point,
};

fn isPow2(n: usize) bool {
    return n > 0 and (n & (n - 1)) == 0;
}

fn inner(a: []const Scalar, b: []const Scalar) Scalar {
    var acc = Scalar.zero;
    for (a, b) |x, y| acc = acc.add(x.mul(y));
    return acc;
}

fn powers(allocator: std.mem.Allocator, base: Scalar, n: usize) ![]Scalar {
    var out = try allocator.alloc(Scalar, n);
    errdefer allocator.free(out);
    out[0] = Scalar.one;
    for (1..n) |i| out[i] = out[i - 1].mul(base);
    return out;
}

fn vecAdd(allocator: std.mem.Allocator, a: []const Scalar, b: []const Scalar) ![]Scalar {
    const out = try allocator.alloc(Scalar, a.len);
    for (a, b, 0..) |x, y, i| out[i] = x.add(y);
    return out;
}

fn vecScale(allocator: std.mem.Allocator, s: Scalar, a: []const Scalar) ![]Scalar {
    const out = try allocator.alloc(Scalar, a.len);
    for (a, 0..) |x, i| out[i] = s.mul(x);
    return out;
}

fn hadamard(allocator: std.mem.Allocator, a: []const Scalar, b: []const Scalar) ![]Scalar {
    const out = try allocator.alloc(Scalar, a.len);
    for (a, b, 0..) |x, y, i| out[i] = x.mul(y);
    return out;
}

fn msm(scalars: []const Scalar, points: []const bsvz.crypto.Point) bsvz.crypto.Point {
    var acc = bsvz.crypto.Point.identity();
    for (scalars, points) |s, p| acc = acc.add(p.mul(s.toBytes()) catch unreachable);
    return acc;
}

pub fn proveRangeBP(allocator: std.mem.Allocator, value: Scalar, blinding: Scalar, bits: usize) !ProveResult {
    if (!isPow2(bits) or bits > 256) return error.InvalidRangeBits;
    const v = value;
    if (bits < 256 and v.toU256() >= (@as(u256, 1) << @intCast(bits))) return error.ValueOutOfRange;

    const n = bits;
    const gv = try generators.generatorVector(generators.bp_g_domain, n, allocator);
    defer allocator.free(gv);
    const hv = try generators.generatorVector(generators.bp_h_domain, n, allocator);
    defer allocator.free(hv);
    const U = generators.BP_U;
    const G = generators.G;
    const H = generators.H;

    const commitment = pedersen.commit(v, blinding);

    // Bit vectors: aL = bits of v, aR = aL - 1 (so aL o aR = 0).
    const aL = try allocator.alloc(Scalar, n);
    defer allocator.free(aL);
    const aR = try allocator.alloc(Scalar, n);
    defer allocator.free(aR);
    for (0..n) |i| {
        const b_i = ((v.toU256() >> @intCast(i)) & 1) == 1;
        aL[i] = if (b_i) Scalar.one else Scalar.zero;
        aR[i] = aL[i].sub(Scalar.one);
    }

    const alpha = Scalar.random();
    var A = H.mul(alpha.toBytes()) catch unreachable;
    A = A.add(msm(aL, gv));
    A = A.add(msm(aR, hv));

    const sL = try allocator.alloc(Scalar, n);
    defer allocator.free(sL);
    const sR = try allocator.alloc(Scalar, n);
    defer allocator.free(sR);
    for (0..n) |i| {
        sL[i] = Scalar.random();
        sR[i] = Scalar.random();
    }
    const rho = Scalar.random();
    var S = H.mul(rho.toBytes()) catch unreachable;
    S = S.add(msm(sL, gv));
    S = S.add(msm(sR, hv));

    const y = transcript.challenge("anchorchain/bp/y", &.{ A, S }, &.{});
    const z = transcript.challenge("anchorchain/bp/z", &.{ A, S }, &.{});
    const yN = try powers(allocator, y, n);
    defer allocator.free(yN);
    const twoN = try powers(allocator, Scalar.fromInt(2), n);
    defer allocator.free(twoN);
    const oneN = try allocator.alloc(Scalar, n);
    defer allocator.free(oneN);
    for (0..n) |i| oneN[i] = Scalar.one;
    const z2 = z.mul(z);

    // l(X) = (aL - z) + sL X ; r(X) = y^n o (aR + z) + z^2 2^n + (y^n o sR) X
    const negZ = z.neg();
    const negZ_oneN = try vecScale(allocator, negZ, oneN);
    defer allocator.free(negZ_oneN);
    const l0 = try vecAdd(allocator, aL, negZ_oneN);
    defer allocator.free(l0);
    const l1 = sL;

    const z_oneN = try vecScale(allocator, z, oneN);
    defer allocator.free(z_oneN);
    const aR_z = try vecAdd(allocator, aR, z_oneN);
    defer allocator.free(aR_z);
    const yN_aRz = try hadamard(allocator, yN, aR_z);
    defer allocator.free(yN_aRz);
    const z2_twoN = try vecScale(allocator, z2, twoN);
    defer allocator.free(z2_twoN);
    const r0 = try vecAdd(allocator, yN_aRz, z2_twoN);
    defer allocator.free(r0);
    const r1 = try hadamard(allocator, yN, sR);
    defer allocator.free(r1);

    const t1 = inner(l0, r1).add(inner(l1, r0));
    const t2 = inner(l1, r1);
    const tau1 = Scalar.random();
    const tau2 = Scalar.random();
    var T1 = G.mul(t1.toBytes()) catch unreachable;
    T1 = T1.add(H.mul(tau1.toBytes()) catch unreachable);
    var T2 = G.mul(t2.toBytes()) catch unreachable;
    T2 = T2.add(H.mul(tau2.toBytes()) catch unreachable);

    const x = transcript.challenge("anchorchain/bp/x", &.{ T1, T2 }, &.{});
    const x2 = x.mul(x);

    const x_l1 = try vecScale(allocator, x, l1);
    defer allocator.free(x_l1);
    const l = try vecAdd(allocator, l0, x_l1);
    defer allocator.free(l);
    const x_r1 = try vecScale(allocator, x, r1);
    defer allocator.free(x_r1);
    const r = try vecAdd(allocator, r0, x_r1);
    defer allocator.free(r);
    const tHat = inner(l, r);
    const taux = tau2.mul(x2).add(tau1.mul(x)).add(z2.mul(blinding));
    const mu = alpha.add(rho.mul(x));

    // h'_i = (y^{-i}) * h_i
    const yInv = y.invert();
    const yInvN = try powers(allocator, yInv, n);
    defer allocator.free(yInvN);
    const hp = try allocator.alloc(bsvz.crypto.Point, n);
    defer allocator.free(hp);
    for (0..n) |i| hp[i] = hv[i].mul(yInvN[i].toBytes()) catch unreachable;

    const ip = try proveInnerProduct(allocator, gv, hp, U, l, r);

    return .{ .proof = .{
        .bits = bits,
        .A = A,
        .S = S,
        .T1 = T1,
        .T2 = T2,
        .taux = taux,
        .mu = mu,
        .tHat = tHat,
        .ip = ip,
    }, .commitment = commitment };
}

pub fn verifyRangeBP(allocator: std.mem.Allocator, commitment: bsvz.crypto.Point, proof: RangeProofBP) bool {
    const n = proof.bits;
    if (!isPow2(n) or n > 256) return false;

    const gv = generators.generatorVector(generators.bp_g_domain, n, allocator) catch return false;
    defer allocator.free(gv);
    const hv = generators.generatorVector(generators.bp_h_domain, n, allocator) catch return false;
    defer allocator.free(hv);
    const U = generators.BP_U;
    const G = generators.G;
    const H = generators.H;

    const y = transcript.challenge("anchorchain/bp/y", &.{ proof.A, proof.S }, &.{});
    const z = transcript.challenge("anchorchain/bp/z", &.{ proof.A, proof.S }, &.{});
    const x = transcript.challenge("anchorchain/bp/x", &.{ proof.T1, proof.T2 }, &.{});
    const yN = powers(allocator, y, n) catch return false;
    defer allocator.free(yN);
    const twoN = powers(allocator, Scalar.fromInt(2), n) catch return false;
    defer allocator.free(twoN);
    const oneN = allocator.alloc(Scalar, n) catch return false;
    defer allocator.free(oneN);
    for (0..n) |i| oneN[i] = Scalar.one;
    const z2 = z.mul(z);
    const z3 = z2.mul(z);
    const x2 = x.mul(x);

    // delta(y,z) = (z - z^2)<1,y^n> - z^3 <1,2^n>
    const delta = z.sub(z2).mul(inner(oneN, yN)).sub(z3.mul(inner(oneN, twoN)));

    // Check 1: tHat*G + taux*H == z^2 V + delta*G + x T1 + x^2 T2
    var lhs1 = G.mul(proof.tHat.toBytes()) catch return false;
    lhs1 = lhs1.add(H.mul(proof.taux.toBytes()) catch return false);
    var rhs1 = commitment.mul(z2.toBytes()) catch return false;
    rhs1 = rhs1.add(G.mul(delta.toBytes()) catch return false);
    rhs1 = rhs1.add(proof.T1.mul(x.toBytes()) catch return false);
    rhs1 = rhs1.add(proof.T2.mul(x2.toBytes()) catch return false);
    if (!pedersen.pointsEq(lhs1, rhs1)) return false;

    // h'_i = (y^{-i}) * h_i
    const yInv = y.invert();
    const yInvN = powers(allocator, yInv, n) catch return false;
    defer allocator.free(yInvN);
    const hp = allocator.alloc(bsvz.crypto.Point, n) catch return false;
    defer allocator.free(hp);
    for (0..n) |i| hp[i] = hv[i].mul(yInvN[i].toBytes()) catch return false;

    // P = A + xS + sum(-z) g_i + sum(z y^i + z^2 2^i) h'_i
    const negZ = z.neg();
    var P = proof.A;
    P = P.add(proof.S.mul(x.toBytes()) catch return false);
    const gScalars = allocator.alloc(Scalar, n) catch return false;
    defer allocator.free(gScalars);
    for (0..n) |i| gScalars[i] = negZ;
    P = P.add(msm(gScalars, gv));
    const hScalars = allocator.alloc(Scalar, n) catch return false;
    defer allocator.free(hScalars);
    for (0..n) |i| hScalars[i] = z.mul(yN[i]).add(z2.mul(twoN[i]));
    P = P.add(msm(hScalars, hp));

    // P - mu*H + tHat*U is the inner-product commitment.
    var Pip = P;
    Pip = Pip.add(H.mul(proof.mu.neg().toBytes()) catch return false);
    Pip = Pip.add(U.mul(proof.tHat.toBytes()) catch return false);

    return verifyInnerProduct(allocator, gv, hp, U, Pip, proof.ip);
}

// ---- inner-product argument (logarithmic) ----
fn proveInnerProduct(
    allocator: std.mem.Allocator,
    g_in: []const bsvz.crypto.Point,
    h_in: []const bsvz.crypto.Point,
    U: bsvz.crypto.Point,
    a_in: []const Scalar,
    b_in: []const Scalar,
) !InnerProductProof {
    var g = try allocator.dupe(bsvz.crypto.Point, g_in);
    defer allocator.free(g);
    var h = try allocator.dupe(bsvz.crypto.Point, h_in);
    defer allocator.free(h);
    var a = try allocator.dupe(Scalar, a_in);
    defer allocator.free(a);
    var b = try allocator.dupe(Scalar, b_in);
    defer allocator.free(b);

    var L: std.ArrayList(bsvz.crypto.Point) = .empty;
    defer L.deinit(allocator);
    var R: std.ArrayList(bsvz.crypto.Point) = .empty;
    defer R.deinit(allocator);

    var round: usize = 0;
    var label_buf: [64]u8 = undefined;
    while (a.len > 1) {
        const nn = a.len / 2;
        const aLo = a[0..nn];
        const aHi = a[nn..];
        const bLo = b[0..nn];
        const bHi = b[nn..];
        const gLo = g[0..nn];
        const gHi = g[nn..];
        const hLo = h[0..nn];
        const hHi = h[nn..];

        const cL = inner(aLo, bHi);
        const cR = inner(aHi, bLo);
        var Lj = msm(aLo, gHi);
        Lj = Lj.add(msm(bHi, hLo));
        Lj = Lj.add(U.mul(cL.toBytes()) catch unreachable);
        var Rj = msm(aHi, gLo);
        Rj = Rj.add(msm(bLo, hHi));
        Rj = Rj.add(U.mul(cR.toBytes()) catch unreachable);
        try L.append(allocator, Lj);
        try R.append(allocator, Rj);

        const label = std.fmt.bufPrint(&label_buf, "anchorchain/bp/ip/{d}", .{round}) catch unreachable;
        const u = transcript.challenge(label, &.{ Lj, Rj }, &.{});
        const uInv = u.invert();

        const gNext = try allocator.alloc(bsvz.crypto.Point, nn);
        defer allocator.free(gNext);
        const hNext = try allocator.alloc(bsvz.crypto.Point, nn);
        defer allocator.free(hNext);
        const aNext = try allocator.alloc(Scalar, nn);
        defer allocator.free(aNext);
        const bNext = try allocator.alloc(Scalar, nn);
        defer allocator.free(bNext);
        for (0..nn) |i| {
            var gv_next = gLo[i].mul(uInv.toBytes()) catch unreachable;
            gv_next = gv_next.add(gHi[i].mul(u.toBytes()) catch unreachable);
            gNext[i] = gv_next;
            var hv_next = hLo[i].mul(u.toBytes()) catch unreachable;
            hv_next = hv_next.add(hHi[i].mul(uInv.toBytes()) catch unreachable);
            hNext[i] = hv_next;
            aNext[i] = aLo[i].mul(u).add(aHi[i].mul(uInv));
            bNext[i] = bLo[i].mul(uInv).add(bHi[i].mul(u));
        }

        const new_g = try allocator.dupe(bsvz.crypto.Point, gNext);
        errdefer allocator.free(new_g);
        const new_h = try allocator.dupe(bsvz.crypto.Point, hNext);
        errdefer allocator.free(new_h);
        const new_a = try allocator.dupe(Scalar, aNext);
        errdefer allocator.free(new_a);
        const new_b = try allocator.dupe(Scalar, bNext);
        errdefer allocator.free(new_b);
        allocator.free(g);
        allocator.free(h);
        allocator.free(a);
        allocator.free(b);
        g = new_g;
        h = new_h;
        a = new_a;
        b = new_b;
        round += 1;
    }

    return .{
        .L = try L.toOwnedSlice(allocator),
        .R = try R.toOwnedSlice(allocator),
        .a = a[0],
        .b = b[0],
    };
}

fn verifyInnerProduct(
    allocator: std.mem.Allocator,
    g_in: []const bsvz.crypto.Point,
    h_in: []const bsvz.crypto.Point,
    U: bsvz.crypto.Point,
    P_in: bsvz.crypto.Point,
    proof: InnerProductProof,
) bool {
    if (proof.L.len != proof.R.len) return false;
    if (proof.L.len > 255) return false;
    var expected: usize = 0;
    var m = g_in.len;
    while (m > 1) : (m /= 2) expected += 1;
    if (proof.L.len != expected) return false;

    var g = allocator.dupe(bsvz.crypto.Point, g_in) catch return false;
    defer allocator.free(g);
    var h = allocator.dupe(bsvz.crypto.Point, h_in) catch return false;
    defer allocator.free(h);
    var P = P_in;

    var label_buf: [64]u8 = undefined;
    for (0..proof.L.len) |round| {
        const Lj = proof.L[round];
        const Rj = proof.R[round];
        const label = std.fmt.bufPrint(&label_buf, "anchorchain/bp/ip/{d}", .{round}) catch unreachable;
        const u = transcript.challenge(label, &.{ Lj, Rj }, &.{});
        const uInv = u.invert();
        const u_sq = u.mul(u);
        const uInv_sq = uInv.mul(uInv);

        const nn = g.len / 2;
        const gLo = g[0..nn];
        const gHi = g[nn..];
        const hLo = h[0..nn];
        const hHi = h[nn..];

        const gNext = allocator.alloc(bsvz.crypto.Point, nn) catch return false;
        defer allocator.free(gNext);
        const hNext = allocator.alloc(bsvz.crypto.Point, nn) catch return false;
        defer allocator.free(hNext);
        for (0..nn) |i| {
            var gv_next = gLo[i].mul(uInv.toBytes()) catch return false;
            gv_next = gv_next.add(gHi[i].mul(u.toBytes()) catch return false);
            gNext[i] = gv_next;
            var hv_next = hLo[i].mul(u.toBytes()) catch return false;
            hv_next = hv_next.add(hHi[i].mul(uInv.toBytes()) catch return false);
            hNext[i] = hv_next;
        }

        allocator.free(g);
        allocator.free(h);
        g = allocator.dupe(bsvz.crypto.Point, gNext) catch return false;
        h = allocator.dupe(bsvz.crypto.Point, hNext) catch return false;

        // P' = u^2 L + P + u^{-2} R
        var P2 = Lj.mul(u_sq.toBytes()) catch return false;
        P2 = P2.add(P);
        P2 = P2.add(Rj.mul(uInv_sq.toBytes()) catch return false);
        P = P2;
    }

    // final: P == a g* + b h* + (a b) U
    var rhs = g[0].mul(proof.a.toBytes()) catch return false;
    rhs = rhs.add(h[0].mul(proof.b.toBytes()) catch return false);
    rhs = rhs.add(U.mul(proof.a.mul(proof.b).toBytes()) catch return false);
    return pedersen.pointsEq(P, rhs);
}

pub fn bulletproofDeinit(proof: RangeProofBP, allocator: std.mem.Allocator) void {
    allocator.free(proof.ip.L);
    allocator.free(proof.ip.R);
}
