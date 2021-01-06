const std = @import("std");
const mem = std.mem;

// TODO See stdlib, this is a modified non vectorized implementation
pub const ChaCha20Stream = struct {
    const math = std.math;
    pub const BlockVec = [16]u32;

    pub fn initContext(key: [8]u32, d: [4]u32) BlockVec {
        const c = "expand 32-byte k";
        const constant_le = comptime [4]u32{
            mem.readIntLittle(u32, c[0..4]),
            mem.readIntLittle(u32, c[4..8]),
            mem.readIntLittle(u32, c[8..12]),
            mem.readIntLittle(u32, c[12..16]),
        };
        return BlockVec{
            constant_le[0], constant_le[1], constant_le[2], constant_le[3],
            key[0],         key[1],         key[2],         key[3],
            key[4],         key[5],         key[6],         key[7],
            d[0],           d[1],           d[2],           d[3],
        };
    }

    const QuarterRound = struct {
        a: usize,
        b: usize,
        c: usize,
        d: usize,
    };

    fn Rp(a: usize, b: usize, c: usize, d: usize) QuarterRound {
        return QuarterRound{
            .a = a,
            .b = b,
            .c = c,
            .d = d,
        };
    }

    inline fn chacha20Core(x: *BlockVec, input: BlockVec) void {
        x.* = input;

        const rounds = comptime [_]QuarterRound{
            Rp(0, 4, 8, 12),
            Rp(1, 5, 9, 13),
            Rp(2, 6, 10, 14),
            Rp(3, 7, 11, 15),
            Rp(0, 5, 10, 15),
            Rp(1, 6, 11, 12),
            Rp(2, 7, 8, 13),
            Rp(3, 4, 9, 14),
        };

        comptime var j: usize = 0;
        inline while (j < 20) : (j += 2) {
            inline for (rounds) |r| {
                x[r.a] +%= x[r.b];
                x[r.d] = math.rotl(u32, x[r.d] ^ x[r.a], @as(u32, 16));
                x[r.c] +%= x[r.d];
                x[r.b] = math.rotl(u32, x[r.b] ^ x[r.c], @as(u32, 12));
                x[r.a] +%= x[r.b];
                x[r.d] = math.rotl(u32, x[r.d] ^ x[r.a], @as(u32, 8));
                x[r.c] +%= x[r.d];
                x[r.b] = math.rotl(u32, x[r.b] ^ x[r.c], @as(u32, 7));
            }
        }
    }

    inline fn hashToBytes(out: *[64]u8, x: BlockVec) void {
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            mem.writeIntLittle(u32, out[16 * i + 0 ..][0..4], x[i * 4 + 0]);
            mem.writeIntLittle(u32, out[16 * i + 4 ..][0..4], x[i * 4 + 1]);
            mem.writeIntLittle(u32, out[16 * i + 8 ..][0..4], x[i * 4 + 2]);
            mem.writeIntLittle(u32, out[16 * i + 12 ..][0..4], x[i * 4 + 3]);
        }
    }

    inline fn contextFeedback(x: *BlockVec, ctx: BlockVec) void {
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            x[i] +%= ctx[i];
        }
    }

    // TODO: Optimize this
    pub fn chacha20Xor(out: []u8, in: []const u8, key: [8]u32, ctx: *BlockVec, idx: *usize, buf: *[64]u8) void {
        var x: BlockVec = undefined;

        const start_idx = idx.*;
        var i: usize = 0;
        while (i < in.len) {
            if (idx.* % 64 == 0) {
                if (idx.* != 0) {
                    ctx.*[12] += 1;
                }
                chacha20Core(x[0..], ctx.*);
                contextFeedback(&x, ctx.*);
                hashToBytes(buf, x);
            }

            out[i] = in[i] ^ buf[idx.* % 64];

            i += 1;
            idx.* += 1;
        }
    }
};

pub fn keyToWords(key: [32]u8) [8]u32 {
    var k: [8]u32 = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        k[i] = mem.readIntLittle(u32, key[i * 4 ..][0..4]);
    }
    return k;
}
