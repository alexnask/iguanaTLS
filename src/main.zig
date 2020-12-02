const std = @import("std");
pub const x509 = @import("x509.zig");

comptime {
    std.testing.refAllDecls(x509);
}

// @TODO Document the notion of sub-streams somewhere
// Only valid to read when one of them is alive, but
// you dont need to consume all of it to start reading
// from the next.
