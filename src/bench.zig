// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <https://unlicense.org>
const std = @import("std");
const zigscan = @import("zigscan.zig");

pub fn main() !void {
    const writer = std.io.getStdOut().writer();
    for (scans) |scan| {
        const seed: u64 = @bitCast(std.time.microTimestamp());
        try writer.print("\n===== {s} (seed 0x{X}) =====\n\n", .{ scan.name, seed });
        try scan.func(seed);
    }

    try writer.print("\n=============== DONE ===============\n", .{});
}

const scans = [_]Scan{
    .{
        .name = "Random bytes, fixed pattern (average case)",
        .func = randomBytesFixedPattern,
    },
    .{
        .name = "Zeroed bytes, fixed pattern (best case)",
        .func = zeroedBytesFixedPattern,
    },
    .{
        .name = "First match byte, fixed pattern (worst case)",
        .func = firstMatchFixedPattern,
    },
    .{
        .name = "First match byte, no wildcards",
        .func = firstMatchNoWildcard,
    },
};

const Scan = struct {
    name: []const u8,
    func: *const fn (seed: u64) anyerror!void,
};

const Scanners = [_]type{ Sigscan, Vecpattern };
const Sigscan = struct {
    pub const name = "scalar sigscanner";
    pub noinline fn scan(
        bytes: []align(@alignOf(zigscan.vecpattern.VecType)) const u8,
        comptime pattern_length: usize,
        comptime pattern: zigscan.maskgen.MaskAndMatch(pattern_length),
    ) ?usize {
        return zigscan.sigscan.scanMaskAndMatch(bytes, pattern_length, pattern);
    }
};

const Vecpattern = struct {
    pub const name = "vecpattern";
    pub noinline fn scan(
        bytes: []align(@alignOf(zigscan.vecpattern.VecType)) const u8,
        comptime pattern_length: usize,
        comptime pattern: zigscan.maskgen.MaskAndMatch(pattern_length),
    ) ?usize {
        return zigscan.vecpattern.scanMaskAndMatch(bytes, false, pattern_length, pattern);
    }
};

fn randomBytesFixedPattern(seed: u64) anyerror!void {
    var default_rand = std.Random.DefaultPrng.init(seed);
    const random = default_rand.random();

    const pattern = comptime zigscan.maskgen.fromIda("E8 ? ? ? ? E8 ? ? ? ? 48 85 C0 74 ? 48 89 C7 48 8B 9E");

    const max_search = 512 << 20;
    const idx = random.intRangeAtMost(usize, 512 << 10, max_search - pattern.mask.len);

    const bytes = try std.heap.page_allocator.alignedAlloc(u8, @alignOf(zigscan.vecpattern.VecType), idx + pattern.mask.len + 1024);
    defer std.heap.page_allocator.free(bytes);

    random.bytes(bytes[0..]);
    for (bytes[idx..][0..pattern.mask.len], pattern.mask[0..], pattern.match[0..]) |*set, mask, match| {
        set.* &= ~mask;
        set.* |= match;
    }

    try benchPattern(bytes, pattern.mask.len, pattern, idx, std.io.getStdOut().writer());
}

fn zeroedBytesFixedPattern(seed: u64) anyerror!void {
    var default_rand = std.Random.DefaultPrng.init(seed);
    const random = default_rand.random();

    const pattern = comptime zigscan.maskgen.fromIda("E8 ? ? ? ? E8 ? ? ? ? 48 85 C0 74 ? 48 89 C7 48 8B 9E");
    const search_size = 64 << 20;
    const idx = (search_size - pattern.mask.len) - random.intRangeAtMost(usize, 0, @sizeOf(zigscan.vecpattern.VecType) - 1);

    const bytes = try std.heap.page_allocator.alignedAlloc(u8, @alignOf(zigscan.vecpattern.VecType), search_size);
    defer std.heap.page_allocator.free(bytes);

    @memset(bytes[0..], 0);
    @memcpy(bytes[idx..][0..pattern.mask.len], pattern.match[0..]);

    try benchPattern(bytes, pattern.mask.len, pattern, idx, std.io.getStdOut().writer());
}

fn firstMatchFixedPattern(seed: u64) anyerror!void {
    var default_rand = std.Random.DefaultPrng.init(seed);
    const random = default_rand.random();

    const pattern = comptime zigscan.maskgen.fromIda("E8 ? ? ? ? E8 ? ? ? ? 48 85 C0 74 ? 48 89 C7 48 8B 9E");
    const search_size = 64 << 20;
    const idx = (search_size - pattern.mask.len) - random.intRangeAtMost(usize, 0, @sizeOf(zigscan.vecpattern.VecType) - 1);

    const bytes = try std.heap.page_allocator.alignedAlloc(u8, @alignOf(zigscan.vecpattern.VecType), search_size);
    defer std.heap.page_allocator.free(bytes);

    @memset(bytes[0..], pattern.match[0]);
    @memcpy(bytes[idx..][0..pattern.mask.len], pattern.match[0..]);

    try benchPattern(bytes, pattern.mask.len, pattern, idx, std.io.getStdOut().writer());
}

fn firstMatchNoWildcard(seed: u64) anyerror!void {
    var default_rand = std.Random.DefaultPrng.init(seed);
    const random = default_rand.random();

    const pattern = comptime zigscan.maskgen.fromIda("E8 E9 48 85 C0 74 48 89 C7 48 8B 9E");
    const search_size = 64 << 20;
    const idx = (search_size - pattern.mask.len) - random.intRangeAtMost(usize, 0, @sizeOf(zigscan.vecpattern.VecType) - 1);

    const bytes = try std.heap.page_allocator.alignedAlloc(u8, @alignOf(zigscan.vecpattern.VecType), search_size);
    defer std.heap.page_allocator.free(bytes);

    @memset(bytes[0..], pattern.match[0]);
    @memcpy(bytes[idx..][0..pattern.mask.len], pattern.match[0..]);

    try benchPattern(bytes, pattern.mask.len, pattern, idx, std.io.getStdOut().writer());
}

fn benchPattern(
    bytes: []align(@alignOf(zigscan.vecpattern.VecType)) const u8,
    comptime pattern_len: usize,
    comptime pattern: zigscan.maskgen.MaskAndMatch(pattern_len),
    idx: usize,
    writer: anytype,
) !void {
    inline for (Scanners) |Scanner| {
        var time1 = try std.time.Timer.start();
        const result = Scanner.scan(bytes, pattern_len, pattern);
        const time2 = time1.lap();

        try printResult(
            Scanner.name,
            time2,
            bytes,
            pattern.mask.len,
            pattern,
            idx,
            result,
            writer,
        );
    }
}

fn printResult(
    name: []const u8,
    time_ns: u64,
    bytes: []const u8,
    comptime pattern_len: usize,
    comptime pattern: zigscan.maskgen.MaskAndMatch(pattern_len),
    idx: usize,
    result_opt: ?usize,
    writer: anytype,
) !void {
    try writer.print("Finished {s} in {} ns: ", .{ name, time_ns });
    if (result_opt) |result| {
        if (result == idx) {
            try writer.print("successfully found idx 0x{X} (~{d:.5} GBytes/sec)\n", .{ idx, @as(f64, @floatFromInt(result)) / @as(f64, @floatFromInt(time_ns)) });
        } else {
            try writer.print("ERROR: tried to find idx 0x{X}, got 0x{X}\n", .{ idx, result });
            for (bytes[result..][0..pattern.mask.len], pattern.mask[0..], pattern.match[0..]) |cmp, mask, match| {
                if (cmp & mask != match) return;
            }
            try writer.print("ERROR: pattern was duplicated in random bytes, 0x{X} is also a valid index.\n", .{result});
            return error.BadRandFill;
        }
    } else {
        try writer.print("ERROR: could not find idx 0x{X}\n", .{idx});
    }
}
