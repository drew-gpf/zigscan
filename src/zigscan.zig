//! Fast pattern scanner
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

pub const vecpattern = @import("vecpattern.zig");
pub const sigscan = @import("sigscan.zig");
pub const maskgen = @import("maskgen.zig");

/// Look for an IDA-style byte pattern within the specified bytes.
/// For example, the pattern 58 5A ?? ?? 60 3 will look for a sequence of bytes
/// 0x58, then 0x5A, then any byte, then any byte, then 0x60, then 0x03.
/// Redundant spaces are ignored. Non-byte constants (e.g. 65A, J, etc) which aren't '??' or '?' result in compile errors.
/// Leading or trailing '??' are compile errors; for leading '??', use scanIdaUnaligned and slicing, and for trailing '??',
/// check the return value of this function that it did not exceed the number of bytes you want to trail.
/// Note that '??' is the same as '?'.
/// This function returns the index of the first incidence of the given pattern.
pub inline fn scanIda(
    bytes: []align(@alignOf(vecpattern.VecType)) const u8,
    comptime pattern: []const u8,
) ?usize {
    return scanRawMaskMatch(bytes, comptime maskgen.fromIda(pattern));
}

/// `scanIda`, but `bytes` is potentially unaligned.
pub inline fn scanIdaUnaligned(bytes: []const u8, comptime pattern: []const u8) ?usize {
    return scanRawMaskMatchUnaligned(bytes, comptime maskgen.fromIda(pattern));
}

/// `scanIdaUnaligned`, but less codegen. Has a performance penalty for large patterns that
/// start at the beginning of the byte sequence. Only use this to reduce binary sizes.
pub inline fn scanIdaUnalignedSmall(bytes: []const u8, comptime pattern: []const u8) ?usize {
    return scanRawMaskMatchUnalignedSmall(bytes, comptime maskgen.fromIda(pattern));
}

/// `mask` and `match` are human-readable strings containing a bitmask (e.g. "FF FF ff 3 0") and
/// a similarly-formatted match.
pub inline fn scanArb(
    bytes: []align(@alignOf(vecpattern.VecType)) const u8,
    comptime match: []const u8,
    comptime mask: []const u8,
) ?usize {
    return scanRawMaskMatch(bytes, comptime maskgen.fromMaskAndMatch(mask, match));
}

/// `scanArb`, but `bytes` is potentially unaligned.
pub inline fn scanArbUnaligned(
    bytes: []const u8,
    comptime match: []const u8,
    comptime mask: []const u8,
) ?usize {
    return scanRawMaskMatchUnaligned(bytes, comptime maskgen.fromMaskAndMatch(mask, match));
}

/// `scanArbUnaligned`, but less codegen. Has a performance penalty for large patterns that
/// start at the beginning of the byte sequence. Only use this to reduce binary sizes.
pub inline fn scanArbUnalignedSmall(
    bytes: []const u8,
    comptime match: []const u8,
    comptime mask: []const u8,
) ?usize {
    return scanRawMaskMatchUnalignedSmall(bytes, comptime maskgen.fromMaskAndMatch(mask, match));
}

inline fn scanRawMaskMatch(
    bytes: []align(@alignOf(vecpattern.VecType)) const u8,
    comptime mask_match: anytype,
) ?usize {
    return vecpattern.scanMaskAndMatch(bytes, false, mask_match.mask.len, mask_match);
}

fn scanRawMaskMatchUnaligned(bytes: []const u8, comptime mask_match: anytype) ?usize {
    const base_ptr = @intFromPtr(bytes.ptr);
    const backward = std.mem.alignBackward(usize, base_ptr, @alignOf(vecpattern.VecType));
    const diff = base_ptr - backward;

    return switch (diff) {
        inline 1...(@alignOf(vecpattern.VecType) - 1) => |off| blk: {
            // Start scanning at `backward` but insert null masks according to
            // how many bytes we want to skip from the start. Only do this for the first vector word.
            const new_mask = ([_]u8{0x00} ** off) ++ mask_match.mask;
            const new_match = ([_]u8{0x00} ** off) ++ mask_match.match;
            if (vecpattern.scanMaskAndMatch(
                @alignCast(@as([*]const u8, @ptrFromInt(backward))[0 .. bytes.len + off]),
                true,
                new_mask.len,
                maskgen.MaskAndMatch(new_mask.len){ .mask = new_mask, .match = new_match },
            )) |result| break :blk result;

            // If the pattern did not start within the first vector word, we need to check subsequent (aligned) vector words.
            const off_to_next_word = @sizeOf(vecpattern.VecType) - off;
            if (bytes.len <= off_to_next_word) break :blk null;

            const result = vecpattern.scanMaskAndMatch(
                @alignCast(bytes[off_to_next_word..]),
                false,
                mask_match.mask.len,
                mask_match,
            ) orelse break :blk null;
            break :blk result + off_to_next_word;
        },
        0 => scanRawMaskMatch(@alignCast(bytes), mask_match),
        else => unreachable,
    };
}

fn scanRawMaskMatchUnalignedSmall(bytes: []const u8, comptime mask_match: anytype) ?usize {
    const base_ptr = @intFromPtr(bytes.ptr);
    const forward = std.mem.alignForward(usize, base_ptr, @alignOf(vecpattern.VecType));
    const diff = forward - base_ptr;

    if (diff > 0) {
        // Scan within unaligned bytes
        if (sigscan.scanMaskAndMatch(bytes[0..@min(bytes.len, mask_match.mask.len + diff)], mask_match.mask.len, mask_match)) |result| return result;

        // Scan the rest
        if (bytes.len <= diff) return null;
        const result = vecpattern.scanMaskAndMatch(
            @alignCast(bytes[diff..]),
            false,
            mask_match.mask.len,
            mask_match,
        ) orelse return null;
        return result + diff;
    } else {
        return scanRawMaskMatch(@alignCast(bytes), mask_match);
    }
}

test "unaligned sigscans" {
    const template = [_]u8{ 0x13, 0x37, 0x13, 0x00, 0x12, 0x34, 0x56, 0x78, 0xAA };
    for (0..@sizeOf(vecpattern.VecType)) |offs| {
        var bytes align(@alignOf(vecpattern.VecType)) = std.mem.zeroes([@sizeOf(vecpattern.VecType) + template.len - 1]u8);
        @memcpy(bytes[offs..][0..template.len], template[0..]);
        try testScanIda(bytes[offs..], scanIdaUnaligned);
        try testScanIda(bytes[offs..], scanIdaUnalignedSmall);
        try testScanMaskMatch(bytes[offs..], scanArbUnaligned);
        try testScanMaskMatch(bytes[offs..], scanArbUnalignedSmall);
    }
}

test "zero" {
    const buf align(@alignOf(vecpattern.VecType)) = std.mem.zeroes([@sizeOf(vecpattern.VecType)]u8);
    for (0..@sizeOf(vecpattern.VecType)) |offs| {
        try std.testing.expectEqual(null, scanIdaUnaligned(buf[offs..][0..0], "00"));
        try std.testing.expectEqual(null, scanIdaUnalignedSmall(buf[offs..][0..0], "00"));

        try std.testing.expectEqual(null, scanIdaUnaligned(buf[offs..][0..1], "00 00"));
        try std.testing.expectEqual(null, scanIdaUnalignedSmall(buf[offs..][0..1], "00 00"));
    }

    try std.testing.expectEqual(0, scanIda(buf[0..], "00 " ** @sizeOf(vecpattern.VecType)));
    try std.testing.expectEqual(null, scanIda(buf[0 .. buf.len / 2], "00 " ** @sizeOf(vecpattern.VecType)));
}

test "bench tests" {
    _ = @import("bench.zig");
}

fn testScanIda(bytes: []const u8, comptime scanner: anytype) !void {
    try std.testing.expectEqual(0, scanner(bytes, "13"));
    try std.testing.expectEqual(0, scanner(bytes, "13 37 13"));
    try std.testing.expectEqual(8, scanner(bytes, "AA"));
    try std.testing.expectEqual(4, scanner(bytes, "12 34 56 ?? AA"));
    try std.testing.expectEqual(2, scanner(bytes, "13 ?? 12"));
}

fn testScanMaskMatch(bytes: []const u8, comptime scanner: anytype) !void {
    try std.testing.expectEqual(0, scanner(bytes, "13", "FF"));
    try std.testing.expectEqual(0, scanner(bytes, "13 37 13", "FF FF FF"));
    try std.testing.expectEqual(8, scanner(bytes, "AA", "FF"));
    try std.testing.expectEqual(4, scanner(bytes, "12 34 56 00 AA", "FF FF FF 00 FF"));
    try std.testing.expectEqual(2, scanner(bytes, "13 00 12", "FF 00 FF"));
    try std.testing.expectEqual(7, scanner(bytes, "08", "08"));
}
