//! Fast vectorized pattern scanner
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
const maskgen = @import("maskgen.zig");

pub const VecType = @Vector(std.simd.suggestVectorLength(u8).?, u8);
comptime {
    std.debug.assert(@alignOf(VecType) == @sizeOf(VecType));
}

/// If `only_first` is true, only the first word is checked. This is used for quickly
/// filtering the unaligned portion of a byte array.
pub fn scanMaskAndMatch(
    bytes: []align(@alignOf(VecType)) const u8,
    comptime only_first: bool,
    comptime num_mask_bytes: usize,
    comptime mask_match: maskgen.MaskAndMatch(num_mask_bytes),
) ?usize {
    const S = struct {
        const mask align(@alignOf(VecType)) = extendBytePattern(mask_match.mask);
        const match align(@alignOf(VecType)) = extendBytePattern(mask_match.match);
    };

    comptime {
        @setEvalBranchQuota(1000000);

        std.debug.assert(num_mask_bytes > 0);
        if (S.mask[0] == 0x00 and !only_first) {
            @compileError("Invalid multi-word pattern begins with null mask (use slicing and scanUnaligned instead)");
        }

        if (mask_match.mask[num_mask_bytes - 1] == 0x00) {
            @compileError("Invalid mask ends with a null byte");
        }

        for (mask_match.mask[0..], mask_match.match[0..], 0..) |mask, match, i| {
            if (mask == 0 and match != 0) {
                @compileLog("Invalid match byte is nonzero when mask is zero (invalid wildcard, pattern will never match)", mask, match, i);
            }
        }
    }

    const result = @call(.always_inline, scanRaw, .{
        S.mask.len,
        num_mask_bytes,
        only_first,
        bytes,
        &S.mask,
        &S.match,
    });

    if (!std.mem.isAligned(bytes.len, @sizeOf(VecType))) {
        // Make sure that the scan did not go out-of-bounds
        if (result) |val| {
            if (val + num_mask_bytes > bytes.len) return null;
        }
    }

    return result;
}

/// `mask_len` must be a multiple of @sizeOf(VecType); you must fill unused bytes with zeroes.
/// `actual_mask_len` describes the number of mask bytes that may not be zero.
/// For performance reasons, you should generally make sure that the byte at (actual_mask_len-1) is nonzero.
/// This function may return an "impossible" scan result that goes out-of-bounds of the
/// bytes to scan. Because the buffer you give must be aligned, however, this function cannot
/// cause a page fault from an out-of-bounds read.
///
/// Note that this function will assume that zeroed mask bytes have corresponding
/// zeroed match bytes; in other words, it only checks that the mask byte is zero
/// to determine if a pattern byte is a wildcard or not.
pub fn scanRaw(
    comptime mask_len: comptime_int,
    comptime actual_mask_len: comptime_int,
    /// If true, only check the first word for a start bit.
    /// This is an optimization intended for unaligned pattern scanners
    /// where we want to check only some part of the first word using an appended mask
    /// which is otherwise inefficient for the rest of the scan.
    comptime only_first: bool,
    bytes: []align(@alignOf(VecType)) const u8,
    mask_bytes: *align(@alignOf(VecType)) const [mask_len]u8,
    match_bytes: *align(@alignOf(VecType)) const [mask_len]u8,
) ?usize {
    comptime std.debug.assert(mask_len > 0 and actual_mask_len > 0 and std.mem.isAligned(mask_len, @sizeOf(VecType)) and actual_mask_len <= mask_len);

    // This behaviour is equivalent, but we can include an optimization here.
    // It is equivalent because scanMaskAndMatch makes sure that the pattern does not
    // go outside of the memory specified by `bytes`.
    if (bytes.len < actual_mask_len) return null;

    @setRuntimeSafety(false);
    var i: usize = 0;

    const first_mask = @as(*const VecType, @ptrCast(mask_bytes)).*;
    const first_match = @as(*const VecType, @ptrCast(match_bytes)).*;
    const end: usize = if (only_first) @min(@sizeOf(VecType), bytes.len) else bytes.len;

    outer: while (i < end) : (i += @sizeOf(VecType)) {
        // This read is out-of-bounds but can't cause a page fault because of alignment.
        const word = @as(*const VecType, @alignCast(@ptrCast(&bytes[i]))).*;

        // Exclude this check for the last byte in the vector since it can be done below with offs == 0.
        // This block doesn't check order and just acts as a filter to make sure that the checks below
        // could ever pass.
        const PredInt = std.meta.Int(.unsigned, @sizeOf(VecType));
        const first_predicate: PredInt = @bitCast((word & @as(VecType, @splat(mask_bytes[0]))) == @as(VecType, @splat(match_bytes[0])));
        const lowest_possible_start: usize = inline for (0..@min(@sizeOf(VecType) - 1, actual_mask_len)) |offs| {
            if (mask_bytes[offs] != 0) {
                switch (offs) {
                    0 => {
                        // Byte 0 can exist anywhere in the vector
                        if (first_predicate == 0) {
                            continue :outer;
                        }
                    },
                    else => {
                        // Check if this byte exists in the vector. Additionally, mask off
                        // locations where the byte could not exist.
                        const pred_mask: PredInt = @truncate(std.math.maxInt(PredInt) << offs);
                        const predicate: PredInt = @bitCast((word & @as(VecType, @splat(mask_bytes[offs]))) == @as(VecType, @splat(match_bytes[offs])));

                        if (predicate & pred_mask == 0) {
                            // If the nth byte does not exist in the vector, it must be because the first byte
                            // is shifted somehow. Construct a mask consisting of possible first byte positions;
                            // if the first byte exists in any of them, we must do the slower scan, else,
                            // we know that the pattern cannot start in this word.
                            const first_pred_mask: PredInt = @truncate(std.math.maxInt(PredInt) << (@sizeOf(VecType) - offs));
                            if (first_predicate & first_pred_mask == 0) {
                                continue :outer;
                            }

                            // We've reached the end of the vector.
                            break @sizeOf(VecType) - offs;
                        }
                    },
                }
            }
        } else 0;

        inline for (0..@sizeOf(VecType)) |offs| {
            // Skip ANDing the predicate if we know that the pattern doesn't match there
            if (offs >= lowest_possible_start and (first_predicate & (@as(PredInt, 1) << offs)) != 0) {
                const mask = std.simd.shiftElementsRight(first_mask, offs, 0);
                const match = std.simd.shiftElementsRight(first_match, offs, 0);

                if (@reduce(.And, word & mask == match)) {
                    const first_bytes_matched = @sizeOf(VecType) - offs;
                    if (first_bytes_matched >= actual_mask_len) {
                        // may be larger if the actual mask length is less than the mask length,
                        // because we're technically matching more bytes than actual_mask_len.
                        // (this check only happens at comptime and has no runtime cost.)
                        return i + offs;
                    }

                    var new_mask: VecType = undefined;
                    var new_match: VecType = undefined;

                    if (offs != 0) {
                        new_mask = std.simd.shiftElementsLeft(first_mask, first_bytes_matched, 0);
                        new_match = std.simd.shiftElementsLeft(first_match, first_bytes_matched, 0);
                    } else {
                        new_mask = @as(*const VecType, @alignCast(@ptrCast(&mask_bytes[first_bytes_matched]))).*;
                        new_match = @as(*const VecType, @alignCast(@ptrCast(&match_bytes[first_bytes_matched]))).*;
                    }

                    var j: usize = i + @sizeOf(VecType);

                    while (j < bytes.len) : (j += @sizeOf(VecType)) {
                        const new_word = @as(*const VecType, @alignCast(@ptrCast(&bytes[j]))).*;
                        if (!@reduce(.And, new_word & new_mask == new_match)) break;

                        const extra_vecs = j - (i + @sizeOf(VecType));
                        const bytes_matched_this_iter = if (offs == 0) @sizeOf(VecType) else offs;
                        const total_bytes_matched = extra_vecs + first_bytes_matched + bytes_matched_this_iter;
                        if (total_bytes_matched >= actual_mask_len) {
                            return i + offs;
                        }

                        if (offs == 0) {
                            new_mask = @as(*const VecType, @alignCast(@ptrCast(&mask_bytes[(j - i) + first_bytes_matched]))).*;
                            new_match = @as(*const VecType, @alignCast(@ptrCast(&match_bytes[(j - i) + first_bytes_matched]))).*;
                        } else {
                            const mask_mem = @as(*const VecType, @alignCast(@ptrCast(&mask_bytes[j - i]))).*;
                            const match_mem = @as(*const VecType, @alignCast(@ptrCast(&match_bytes[j - i]))).*;

                            new_mask = std.simd.shiftElementsRight(mask_mem, offs, 0);
                            new_match = std.simd.shiftElementsRight(match_mem, offs, 0);

                            if (!@reduce(.And, new_word & new_mask == new_match)) break;
                            if (total_bytes_matched + first_bytes_matched >= actual_mask_len) {
                                return i + offs;
                            }

                            new_mask = std.simd.shiftElementsLeft(mask_mem, first_bytes_matched, 0);
                            new_match = std.simd.shiftElementsLeft(match_mem, first_bytes_matched, 0);
                        }
                    }
                }
            }
        }
    }

    return null;
}

fn extendBytePattern(comptime byte_pattern: anytype) [std.mem.alignForward(usize, byte_pattern.len, @sizeOf(VecType))]u8 {
    @setEvalBranchQuota(100000);
    var ret = std.mem.zeroes([std.mem.alignForward(usize, byte_pattern.len, @sizeOf(VecType))]u8);

    for (ret[0..byte_pattern.len], byte_pattern) |*set, byte| {
        set.* = byte;
    }

    return ret;
}
