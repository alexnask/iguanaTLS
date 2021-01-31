const std = @import("std");
const tls = @import("tls");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
pub fn main() !void {
    const allocator = &gpa.allocator;

    var args = std.process.args();
    std.debug.assert(args.skip());

    while (args.next(allocator)) |maybe_arg| {
        const arg = try maybe_arg;
        defer allocator.free(arg);

        std.debug.print("ARG: `{s}`\n", .{arg});
    }
}
