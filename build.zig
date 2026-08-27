const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const bsvz = b.dependency("bsvz", .{
        .target = target,
        .optimize = optimize,
    });

    const mod = b.addModule("bsvz-proofs", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("bsvz", bsvz.module("bsvz"));

    const test_step = b.step("test", "Run unit tests");

    for ([_]struct { name: []const u8, file: []const u8 }{
        .{ .name = "pedersen_test", .file = "tests/pedersen_test.zig" },
        .{ .name = "sigma_test", .file = "tests/sigma_test.zig" },
        .{ .name = "rangeproof_test", .file = "tests/rangeproof_test.zig" },
        .{ .name = "bulletproof_test", .file = "tests/bulletproof_test.zig" },
        .{ .name = "membership_test", .file = "tests/membership_test.zig" },
        .{ .name = "conservation_test", .file = "tests/conservation_test.zig" },
    }) |t| {
        const test_mod = b.createModule(.{
            .root_source_file = b.path(t.file),
            .target = target,
            .optimize = optimize,
        });
        test_mod.addImport("bsvz-proofs", mod);
        test_mod.addImport("bsvz", bsvz.module("bsvz"));

        const test_exe = b.addTest(.{
            .name = t.name,
            .root_module = test_mod,
        });
        test_step.dependOn(&b.addRunArtifact(test_exe).step);
    }

    // Byte-compatibility cross-check vector (see crosscheck/ref.js).
    const crosscheck_mod = b.createModule(.{
        .root_source_file = b.path("examples/crosscheck.zig"),
        .target = target,
        .optimize = optimize,
    });
    crosscheck_mod.addImport("bsvz-proofs", mod);
    crosscheck_mod.addImport("bsvz", bsvz.module("bsvz"));

    const crosscheck_exe = b.addExecutable(.{
        .name = "crosscheck",
        .root_module = crosscheck_mod,
    });
    const crosscheck_step = b.step("crosscheck", "Print AnchorChain cross-check vectors");
    crosscheck_step.dependOn(&b.addRunArtifact(crosscheck_exe).step);

    // WebAssembly module (wasm32-freestanding, single-threaded) for web use.
    const wasm_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });
    const wasm_mod = b.createModule(.{
        .root_source_file = b.path("src/wasm.zig"),
        .target = wasm_target,
        .optimize = optimize,
        .single_threaded = true,
        .link_libc = false,
    });
    wasm_mod.addImport("bsvz-proofs", mod);
    wasm_mod.addImport("bsvz", bsvz.module("bsvz"));

    // Zig 0.16 drops `export fn` symbols from the wasm export section when the
    // entry is disabled; re-export them explicitly via `--export=` so JS can
    // call the C-ABI shim (see src/wasm.zig). Keep this list in sync with the
    // `export fn` names in src/wasm.zig.
    wasm_mod.export_symbol_names = &[_][]const u8{
        "zkp_version",
        "zkp_last_error",
        "zkp_seed",
        "zkp_set_rng_for_testing",
        "zkp_set_rng_for_testing_off",
        "zkp_alloc",
        "zkp_free",
        "zkp_scalar_random",
        "zkp_scalar_from_bytes",
        "zkp_scalar_from_int",
        "zkp_scalar_to_int",
        "zkp_scalar_is_zero",
        "zkp_scalar_eq",
        "zkp_scalar_add",
        "zkp_scalar_sub",
        "zkp_scalar_mul",
        "zkp_scalar_neg",
        "zkp_scalar_invert",
        "zkp_point_add",
        "zkp_point_sub",
        "zkp_point_negate",
        "zkp_point_mul",
        "zkp_point_eq",
        "zkp_sha256",
        "zkp_sha256d",
        "zkp_challenge",
        "zkp_hash_to_point",
        "zkp_generator_vector",
        "zkp_generator_G",
        "zkp_generator_H",
        "zkp_generator_BP_U",
        "zkp_commit",
        "zkp_commit_with_gens",
        "zkp_commit_verify",
        "zkp_commit_add",
        "zkp_commit_sub",
        "zkp_schnorr_prove",
        "zkp_schnorr_verify",
        "zkp_cds_or_size",
        "zkp_cds_or_prove",
        "zkp_cds_or_verify",
        "zkp_range_size",
        "zkp_range_prove",
        "zkp_range_verify",
        "zkp_range_bp_size",
        "zkp_range_bp_prove",
        "zkp_range_bp_verify",
        "zkp_membership_size",
        "zkp_membership_prove",
        "zkp_membership_verify",
        "zkp_conservation_prove",
        "zkp_conservation_verify",
    };

    const wasm_exe = b.addExecutable(.{
        .name = "bsvz_proofs",
        .root_module = wasm_mod,
    });
    wasm_exe.entry = .disabled;
    wasm_exe.export_memory = true;
    const wasm_step = b.step("wasm", "Build the WebAssembly module (wasm32-freestanding)");
    wasm_step.dependOn(&b.addInstallArtifact(wasm_exe, .{
        .dest_sub_path = "bsvz_proofs.wasm",
    }).step);

    // Node smoke test for the wasm module (loads .wasm, round-trips every
    // protocol, and asserts the AnchorChain byte-compat vectors).
    const node_run = b.addSystemCommand(&.{"node"});
    node_run.addArg(b.path("wasm/run-node.mjs"));
    node_run.addArtifactArg(wasm_exe);
    const wasm_test_step = b.step("wasm-test", "Run the wasm node smoke test");
    wasm_test_step.dependOn(&node_run.step);
}
