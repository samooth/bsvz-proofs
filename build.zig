const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const bsvz = b.dependency("bsvz", .{
        .target = target,
        .optimize = optimize,
    });

    const mod = b.addModule("bsvz-zkp", .{
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
        test_mod.addImport("bsvz-zkp", mod);
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
    crosscheck_mod.addImport("bsvz-zkp", mod);
    crosscheck_mod.addImport("bsvz", bsvz.module("bsvz"));

    const crosscheck_exe = b.addExecutable(.{
        .name = "crosscheck",
        .root_module = crosscheck_mod,
    });
    const crosscheck_step = b.step("crosscheck", "Print AnchorChain cross-check vectors");
    crosscheck_step.dependOn(&b.addRunArtifact(crosscheck_exe).step);
}
