const std = @import("std");
const tls = @import("tls");

pub const log_level = .debug;
const default_running_time = 2.0;

const SinkWriter = blk: {
    const S = struct {};
    break :blk std.io.Writer(S, error{}, struct {
        fn f(_: S, buffer: []const u8) !usize {
            return buffer.len;
        }
    }.f);
};

const ReplayingReaderState = struct {
    data: []const u8,
};
const ReplayingReader = std.io.Reader(*ReplayingReaderState, error{}, struct {
    fn f(self: *ReplayingReaderState, buffer: []u8) !usize {
        if (self.data.len < buffer.len)
            @panic("Not enoguh reader data!");
        std.mem.copy(u8, buffer, self.data[0..buffer.len]);
        self.data = self.data[buffer.len..];
        return buffer.len;
    }
}.f);

const ReplayingRandom = struct {
    rand: std.rand.Random = .{ .fillFn = fillFn },
    data: []const u8,

    fn fillFn(r: *std.rand.Random, buf: []u8) void {
        const self = @fieldParentPtr(ReplayingRandom, "rand", r);
        if (self.data.len < buf.len)
            @panic("Not enough random data!");
        std.mem.copy(u8, buf, self.data[0..buf.len]);
        self.data = self.data[buf.len..];
    }
};

fn benchmark_run(
    comptime ciphersuites: anytype,
    comptime curves: anytype,
    allocator: *std.mem.Allocator,
    running_time: f32,
    hostname: []const u8,
    port: u16,
    trust_anchors: tls.x509.TrustAnchorChain,
    reader_recording: []const u8,
    random_recording: []const u8,
) !void {
    {
        const warmup_time_secs = std.math.max(0.5, running_time / 20);
        std.log.info("Warming up for {d:.2} seconds...", .{warmup_time_secs});
        const warmup_time_ns = @floatToInt(i128, warmup_time_secs * std.time.ns_per_s);

        var warmup_time_passed: i128 = 0;
        var timer = try std.time.Timer.start();
        while (warmup_time_passed < warmup_time_ns) {
            var rand = ReplayingRandom{
                .data = random_recording,
            };
            var reader_state = ReplayingReaderState{
                .data = reader_recording,
            };
            const reader = ReplayingReader{ .context = &reader_state };
            const writer = SinkWriter{ .context = .{} };

            timer.reset();
            _ = try tls.client_connect(.{
                .rand = &rand.rand,
                .reader = reader,
                .writer = writer,
                .ciphersuites = ciphersuites,
                .curves = curves,
                .cert_verifier = .default,
                .temp_allocator = allocator,
                .trusted_certificates = trust_anchors.data.items,
            }, hostname);
            warmup_time_passed += timer.read();
        }
    }
    {
        std.log.info("Benchmarking for {d:.2} seconds...", .{running_time});
        var runtimes = std.ArrayList(i128).init(allocator);
        defer runtimes.deinit();
        const bench_time_ns = @floatToInt(i128, running_time * std.time.ns_per_s);

        var total_time_passed: i128 = 0;
        var iterations: usize = 0;
        var timer = try std.time.Timer.start();
        while (total_time_passed < bench_time_ns) : (iterations += 1) {
            var rand = ReplayingRandom{
                .data = random_recording,
            };
            var reader_state = ReplayingReaderState{
                .data = reader_recording,
            };
            const reader = ReplayingReader{ .context = &reader_state };
            const writer = SinkWriter{ .context = .{} };

            timer.reset();
            _ = try tls.client_connect(.{
                .rand = &rand.rand,
                .reader = reader,
                .writer = writer,
                .ciphersuites = ciphersuites,
                .curves = curves,
                .cert_verifier = .default,
                .temp_allocator = allocator,
                .trusted_certificates = trust_anchors.data.items,
            }, hostname);
            const runtime = timer.read();
            total_time_passed += runtime;
            try runtimes.append(runtime);
        }

        const total_time_secs = @intToFloat(f64, total_time_passed) / std.time.ns_per_s;
        const mean_time_ns = @divTrunc(total_time_passed, iterations);
        const mean_time_ms = @intToFloat(f64, mean_time_ns) * std.time.ms_per_s / std.time.ns_per_s;

        const std_dev_ns = blk: {
            var acc: i128 = 0;
            for (runtimes.items) |rt| {
                const dt = rt - mean_time_ns;
                acc += dt * dt;
            }
            break :blk std.math.sqrt(@divTrunc(acc, iterations));
        };
        const std_dev_ms = @intToFloat(f64, std_dev_ns) * std.time.ms_per_s / std.time.ns_per_s;

        std.log.info(
            \\Finished benchmarking.
            \\Total runtime: {d:.2} sec
            \\Iterations: {} ({d:.2} iterations/sec)
            \\Mean iteration time: {d:.2} ms
            \\Standard deviation: {d:.2} ms
        , .{
            total_time_secs,
            iterations,
            @intToFloat(f64, iterations) / total_time_secs,
            mean_time_ms,
            std_dev_ms,
        });

        // (percentile/100) * (total number n + 1)
        std.sort.sort(i128, runtimes.items, {}, comptime std.sort.asc(i128));
        const percentiles = .{ 99.0, 90.0, 75.0, 50.0 };
        inline for (percentiles) |percentile| {
            if (percentile < iterations) {
                const idx = @floatToInt(usize, @intToFloat(f64, iterations + 1) * percentile / 100.0);
                std.log.info(
                    "{d:.0}th percentile value: {d:.2} ms",
                    .{
                        percentile,
                        @intToFloat(f64, runtimes.items[idx]) * std.time.ms_per_s / std.time.ns_per_s,
                    },
                );
            }
        }
    }
}

fn benchmark_run_with_ciphersuite(
    comptime ciphersuites: anytype,
    curve_str: []const u8,
    allocator: *std.mem.Allocator,
    running_time: f32,
    hostname: []const u8,
    port: u16,
    trust_anchors: tls.x509.TrustAnchorChain,
    reader_recording: []const u8,
    random_recording: []const u8,
) !void {
    if (std.mem.eql(u8, curve_str, "all")) {
        return try benchmark_run(
            ciphersuites,
            tls.curves.all,
            allocator,
            running_time,
            hostname,
            port,
            trust_anchors,
            reader_recording,
            random_recording,
        );
    }
    inline for (tls.curves.all) |curve| {
        if (std.mem.eql(u8, curve_str, curve.name)) {
            return try benchmark_run(
                ciphersuites,
                .{curve},
                allocator,
                running_time,
                hostname,
                port,
                trust_anchors,
                reader_recording,
                random_recording,
            );
        }
    }
    return error.InvalidCurve;
}

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
pub fn main() !void {
    const allocator = &gpa.allocator;

    var args = std.process.args();
    std.debug.assert(args.skip());

    const recorded_file_path = try (args.next(allocator) orelse {
        std.log.crit("Need a recorded handshake file path as the first argument", .{});
        return error.NotEnoughArgs;
    });
    defer allocator.free(recorded_file_path);

    const running_time = blk: {
        const maybe_arg = args.next(allocator) orelse break :blk default_running_time;
        const arg = try maybe_arg;
        break :blk std.fmt.parseFloat(f32, arg) catch {
            std.log.crit("Running time is not a floating point number...", .{});
            return error.InvalidArg;
        };
    };

    const recorded_file = try std.fs.cwd().openFile(recorded_file_path, .{});
    defer recorded_file.close();

    const ciphersuite_str_len = try recorded_file.reader().readByte();
    const ciphersuite_str = try allocator.alloc(u8, ciphersuite_str_len);
    defer allocator.free(ciphersuite_str);
    try recorded_file.reader().readNoEof(ciphersuite_str);

    const curve_str_len = try recorded_file.reader().readByte();
    const curve_str = try allocator.alloc(u8, curve_str_len);
    defer allocator.free(curve_str);
    try recorded_file.reader().readNoEof(curve_str);

    const hostname_len = try recorded_file.reader().readIntLittle(usize);
    const hostname = try allocator.alloc(u8, hostname_len);
    defer allocator.free(hostname);
    try recorded_file.reader().readNoEof(hostname);

    const port = try recorded_file.reader().readIntLittle(u16);

    const trust_anchors = blk: {
        const pem_file_path_len = try recorded_file.reader().readIntLittle(usize);
        const pem_file_path = try allocator.alloc(u8, pem_file_path_len);
        defer allocator.free(pem_file_path);
        try recorded_file.reader().readNoEof(pem_file_path);

        const pem_file = try std.fs.cwd().openFile(pem_file_path, .{});
        defer pem_file.close();

        const tas = try tls.x509.TrustAnchorChain.from_pem(allocator, pem_file.reader());
        std.log.info("Read {} certificates.", .{tas.data.items.len});
        break :blk tas;
    };
    defer trust_anchors.deinit();

    const reader_recording_len = try recorded_file.reader().readIntLittle(usize);
    const reader_recording = try allocator.alloc(u8, reader_recording_len);
    defer allocator.free(reader_recording);
    try recorded_file.reader().readNoEof(reader_recording);

    const random_recording_len = try recorded_file.reader().readIntLittle(usize);
    const random_recording = try allocator.alloc(u8, random_recording_len);
    defer allocator.free(random_recording);
    try recorded_file.reader().readNoEof(random_recording);

    if (std.mem.eql(u8, ciphersuite_str, "all")) {
        return try benchmark_run_with_ciphersuite(
            tls.ciphersuites.all,
            curve_str,
            allocator,
            running_time,
            hostname,
            port,
            trust_anchors,
            reader_recording,
            random_recording,
        );
    }
    inline for (tls.ciphersuites.all) |ciphersuite| {
        if (std.mem.eql(u8, ciphersuite_str, ciphersuite.name)) {
            return try benchmark_run_with_ciphersuite(
                .{ciphersuite},
                curve_str,
                allocator,
                running_time,
                hostname,
                port,
                trust_anchors,
                reader_recording,
                random_recording,
            );
        }
    }
    return error.InvalidCiphersuite;
}
