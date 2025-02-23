//! pattern helpers
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

pub fn MaskAndMatch(comptime num_bytes: comptime_int) type {
    return struct {
        mask: [num_bytes]u8,
        match: [num_bytes]u8,
    };
}

pub fn fromMaskAndMatch(comptime mask: []const u8, comptime match: []const u8) MaskAndMatch(countPatternBytes(mask)) {
    const mask_len = countPatternBytes(mask);
    std.debug.assert(mask_len == countPatternBytes(match));

    const ret = MaskAndMatch(countPatternBytes(mask)){
        .mask = toMaskOrMatch(mask),
        .match = toMaskOrMatch(match),
    };

    for (ret.mask, ret.match, 0..) |mask_b, match_b, i| {
        if (mask_b & match_b != match_b) @compileLog("Bad match byte for mask", mask_b, match_b, i);
    }

    return ret;
}

pub fn fromIda(comptime pattern: []const u8) MaskAndMatch(countPatternBytes(pattern)) {
    const byte_pattern = toBytePattern(pattern);
    var ret: MaskAndMatch(countPatternBytes(pattern)) = undefined;

    for (byte_pattern, 0..) |byte, i| {
        if (byte) |val| {
            ret.mask[i] = 0xFF;
            ret.match[i] = val;
        } else {
            ret.mask[i] = 0;
            ret.match[i] = 0;
        }
    }

    return ret;
}

fn toMaskOrMatch(comptime pattern: []const u8) [countPatternBytes(pattern)]u8 {
    @setEvalBranchQuota(100000);

    var ret: [countPatternBytes(pattern)]u8 = undefined;
    var tokens = std.mem.tokenizeAny(u8, pattern, " \t");
    var i = 0;

    while (tokens.next()) |token| : (i += 1) {
        // Validate this token. Because we ran countPatternBytes() on the pattern,
        // we know that all tokens are a normal length.
        for (token) |char| {
            const is_hex_digit = std.ascii.isHex(char);

            if (!is_hex_digit) {
                @compileLog("Invalid token in pattern", char, token, pattern);
            }
        }

        ret[i] = std.fmt.parseUnsigned(u8, token, 16) catch unreachable;
    }

    return ret;
}

fn toBytePattern(comptime pattern: []const u8) [countPatternBytes(pattern)]?u8 {
    @setEvalBranchQuota(100000);

    var ret: [countPatternBytes(pattern)]?u8 = undefined;
    var tokens = std.mem.tokenizeAny(u8, pattern, " \t");
    var i = 0;

    while (tokens.next()) |token| : (i += 1) {
        // Validate this token. Because we ran countPatternBytes() on the pattern,
        // we know that all tokens are a normal length.
        var was_opt = false;

        for (token, 0..) |char, idx| {
            const is_opt = char == '?';
            const is_hex_digit = std.ascii.isHex(char);

            if (is_hex_digit) {
                if (was_opt) @compileLog("Invalid token in pattern after optional indicator", char, token, pattern);
            } else {
                if (!is_opt or (idx > 0 and !was_opt)) @compileLog("Invalid token in pattern", char, token, pattern);
            }

            was_opt = is_opt;
        }

        if (was_opt) {
            ret[i] = null;
        } else {
            ret[i] = std.fmt.parseUnsigned(u8, token, 16) catch unreachable;
        }
    }

    return ret;
}

/// Count the number of bytes specified by a pattern.
fn countPatternBytes(comptime pattern: []const u8) usize {
    @setEvalBranchQuota(100000);

    var tokens = std.mem.tokenizeAny(u8, pattern, " \t");
    var idx = 0;

    while (tokens.next()) |token| : (idx += 1) {
        if (token.len > 2) @compileLog("Invalid pattern token; must be 1 or 2 chars wide.", pattern, token);
    }

    comptime std.debug.assert(idx > 0); // no pattern?
    return idx;
}
