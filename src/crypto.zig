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

// See std.crypto.core.modes.ctr
/// This mode creates a key stream by encrypting an incrementing counter using a block cipher, and adding it to the source material.
pub fn ctr(
    comptime BlockCipher: anytype,
    block_cipher: BlockCipher,
    dst: []u8,
    src: []const u8,
    counterInt: *u128,
    idx: *usize,
    endian: comptime std.builtin.Endian,
) void {
    std.debug.assert(dst.len >= src.len);
    const block_length = BlockCipher.block_length;
    var cur_idx: usize = 0;

    const offset = idx.* % block_length;
    if (offset != 0) {
        const part_len = std.math.min(block_length - offset, src.len);

        var counter: [BlockCipher.block_length]u8 = undefined;
        mem.writeInt(u128, &counter, counterInt.*, endian);
        var pad = [_]u8{0} ** block_length;
        mem.copy(u8, pad[offset..], src[0..part_len]);
        block_cipher.xor(&pad, &pad, counter);
        mem.copy(u8, dst[0..part_len], pad[offset..][0..part_len]);

        cur_idx += part_len;
        idx.* += part_len;
        if (idx.* % block_length == 0)
            counterInt.* += 1;
    }

    const start_idx = cur_idx;
    const remaining = src.len - cur_idx;
    cur_idx = 0;

    const parallel_count = BlockCipher.block.parallel.optimal_parallel_blocks;
    const wide_block_length = parallel_count * 16;
    if (remaining >= wide_block_length) {
        var counters: [parallel_count * 16]u8 = undefined;
        while (cur_idx + wide_block_length <= remaining) : (cur_idx += wide_block_length) {
            comptime var j = 0;
            inline while (j < parallel_count) : (j += 1) {
                mem.writeInt(u128, counters[j * 16 .. j * 16 + 16], counterInt.*, endian);
                counterInt.* +%= 1;
            }
            block_cipher.xorWide(parallel_count, dst[start_idx..][cur_idx .. cur_idx + wide_block_length][0..wide_block_length], src[start_idx..][cur_idx .. cur_idx + wide_block_length][0..wide_block_length], counters);
            idx.* += wide_block_length;
        }
    }
    while (cur_idx + block_length <= remaining) : (cur_idx += block_length) {
        var counter: [BlockCipher.block_length]u8 = undefined;
        mem.writeInt(u128, &counter, counterInt.*, endian);
        counterInt.* +%= 1;
        block_cipher.xor(dst[start_idx..][cur_idx .. cur_idx + block_length][0..block_length], src[start_idx..][cur_idx .. cur_idx + block_length][0..block_length], counter);
        idx.* += block_length;
    }
    if (cur_idx < remaining) {
        std.debug.assert(idx.* % block_length == 0);
        var counter: [BlockCipher.block_length]u8 = undefined;
        mem.writeInt(u128, &counter, counterInt.*, endian);

        var pad = [_]u8{0} ** block_length;
        mem.copy(u8, &pad, src[start_idx..][cur_idx..]);
        block_cipher.xor(&pad, &pad, counter);
        mem.copy(u8, dst[cur_idx..], pad[0 .. remaining - cur_idx]);

        idx.* += remaining - cur_idx;
        if (idx.* % block_length == 0)
            counterInt.* +%= 1;
    }
}
