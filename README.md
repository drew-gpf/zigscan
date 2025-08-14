``zigscan`` is an architecture-agnostic vectorized pattern scanner that supports IDA-style patterns as well as arbitrary mask and match patterns, allowing one to match individual bits within bytes.
It works with buffers of arbitrary length and alignment.

To use, direct ``build.zig.zon`` to download a commit archive and have your build script import a module called ``zigscan``. Then:

```zig
const std = @import("std");
const zigscan = @import("zigscan");

pub fn main() !void {
    var bytes: [16]u8 = undefined;
    @memset(bytes[0..], 0xEE);
    bytes[13] = std.crypto.random.int(u8);
    bytes[14] = 0xFF;
    bytes[15] = 0xFF;

    std.debug.print("0x{X}\n", .{zigscan.scanIdaUnaligned(bytes[0..], "EE ?? FF FF").?});
}
```

```cmd
C:\test> .\test.exe
0xC
```

To get an idea of performance, you can run synthetic benchmarks using ``zig build run -Doptimize=ReleaseFast``.
The following is sample output on a Core i9-10900K w/ 3200MT/s DDR4, benchmarked against a naive pattern scanner in ``src/sigscan.zig``:

```
===== Random bytes, fixed pattern (average case) (seed 0x6117907BE017A) =====

Finished scalar sigscanner in 69644000 ns: successfully found idx 0xC88F5B6 (~3.01968 GBytes/sec)
Finished vecpattern in 14954000 ns: successfully found idx 0xC88F5B6 (~14.06329 GBytes/sec)

===== Zeroed bytes, fixed pattern (best case) (seed 0x6117907C00902) =====

Finished scalar sigscanner in 21565100 ns: successfully found idx 0x3FFFFE6 (~3.11192 GBytes/sec)
Finished vecpattern in 2868700 ns: successfully found idx 0x3FFFFE6 (~23.39347 GBytes/sec)

===== First match byte, fixed pattern (worst case) (seed 0x6117907C09D73) =====

Finished scalar sigscanner in 42737200 ns: successfully found idx 0x3FFFFE0 (~1.57027 GBytes/sec)
Finished vecpattern in 20581900 ns: successfully found idx 0x3FFFFE0 (~3.26058 GBytes/sec)

===== First match byte, no wildcards (seed 0x6117907C1CA3A) =====

Finished scalar sigscanner in 28539600 ns: successfully found idx 0x3FFFFE7 (~2.35143 GBytes/sec)
Finished vecpattern in 4347900 ns: successfully found idx 0x3FFFFE7 (~15.43477 GBytes/sec)

=============== DONE ===============
```
