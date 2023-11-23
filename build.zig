const std = @import("std");
const Builder = std.build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.option(std.builtin.Mode, "mode", "") orelse .Debug;

    _ = b.addModule("iguanaTLS", .{
        .source_file = .{ .path = "src/main.zig" },
    });

    const lib = b.addStaticLibrary(.{
        .name = "iguanaTLS",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = .{},
        .optimize = mode,
    });
    b.installArtifact(lib);

    var main_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .optimize = mode,
    });
    main_tests.main_mod_path = .{ .path = "." };

    const test_step = b.step("test", "Run library tests");
    const test_run = b.addRunArtifact(main_tests);
    test_step.dependOn(&test_run.step);
}
