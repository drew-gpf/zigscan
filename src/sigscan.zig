//! Slow naive pattern scanner
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

pub inline fn scanMaskAndMatch(
    bytes: []const u8,
    comptime num_mask_bytes: usize,
    comptime mask_match: maskgen.MaskAndMatch(num_mask_bytes),
) ?usize {
    comptime {
        @setEvalBranchQuota(1000000);

        std.debug.assert(num_mask_bytes > 0);
        if (mask_match.mask[0] == 0x00) {
            @compileError("Invalid pattern begins with null mask (just slice into `bytes`)");
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

    if (bytes.len < num_mask_bytes) return null;
    const max_len = (bytes.len - (num_mask_bytes - 1));
    var i: usize = 0;

    loop: while (i < max_len) : (i += 1) {
        // Look through pattern bytes starting here; if a mismatch occurs we iterate again,
        // or if all bytes pass we return the initial starting index.
        inline for (mask_match.mask[0..], mask_match.match[0..], 0..) |mask, match, j| {
            if (bytes[i + j] & mask != match) continue :loop;
        }

        return i;
    }

    return null;
}
