#!/usr/bin/env python3
"""
png_inspect.py -- print a PNG's chunk table, tolerantly.

Parses any file (valid or malformed) and prints an offset/length/type/CRC table
plus decoded IHDR fields and warnings. It NEVER crashes on bad input, so it
doubles as a triage tool for the crashing files the fuzzer saves. It makes the
"trust a declared length -> downstream desync" failure visible directly.

Run:
    python3 src/png_inspect.py corpus/seed.png
    python3 src/png_inspect.py crashes/001_heap-buffer-overflow.png
"""
from __future__ import annotations

import struct
import sys
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

_COLOUR_TYPES = {
    0: "grayscale", 2: "truecolour (RGB)", 3: "indexed",
    4: "grayscale+alpha", 6: "truecolour+alpha (RGBA)",
}


def _ascii(b: bytes) -> str:
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


def inspect(path: str) -> int:
    with open(path, "rb") as f:
        buf = f.read()

    print(f"file: {path}  ({len(buf)} bytes)")

    # --- signature ---------------------------------------------------------
    sig = buf[:8]
    if sig == PNG_SIGNATURE:
        print("signature: OK (\\x89PNG\\r\\n\\x1a\\n)")
        pos = 8
    else:
        print(f"signature: BAD (got {sig.hex(' ')}) -- parsing chunks from offset 0")
        pos = 0

    warnings: list[str] = []
    n = len(buf)
    saw_iend = False
    idx = 0

    print()
    print(f"{'#':>2}  {'offset':>7}  {'len(decl)':>9}  {'type':<6}  {'crc':<10}  notes")
    print("-" * 72)

    while pos + 8 <= n:
        declared_len = struct.unpack(">I", buf[pos:pos + 4])[0]
        ctype = buf[pos + 4:pos + 8]
        data_off = pos + 8
        crc_off = data_off + declared_len

        # Type sanity: PNG chunk types are 4 ASCII letters.
        type_str = _ascii(ctype)
        if not all(65 <= c <= 90 or 97 <= c <= 122 for c in ctype):
            warnings.append(f"chunk#{idx}: non-ASCII chunk type {ctype.hex(' ')}")

        # Does the declared length run past the end of the file?
        note = ""
        if crc_off + 4 > n:
            note = "LENGTH RUNS PAST EOF"
            warnings.append(
                f"chunk#{idx} {type_str}: declared length {declared_len} "
                f"runs past EOF (only {max(0, n - data_off)} data bytes present)"
            )
            crc_status = "n/a"
        else:
            stored_crc = struct.unpack(">I", buf[crc_off:crc_off + 4])[0]
            calc_crc = zlib.crc32(ctype + buf[data_off:crc_off]) & 0xFFFFFFFF
            if stored_crc == calc_crc:
                crc_status = "OK"
            else:
                crc_status = "MISMATCH"
                warnings.append(
                    f"chunk#{idx} {type_str}: CRC mismatch "
                    f"(stored 0x{stored_crc:08x}, computed 0x{calc_crc:08x})"
                )

        print(f"{idx:>2}  {pos:>7}  {declared_len:>9}  {type_str:<6}  "
              f"{crc_status:<10}  {note}")

        # Decode IHDR fields when present and long enough.
        if ctype == b"IHDR" and data_off + 13 <= n:
            w, h, bd, ct, comp, filt, inter = struct.unpack(
                ">IIBBBBB", buf[data_off:data_off + 13])
            ctname = _COLOUR_TYPES.get(ct, f"UNKNOWN({ct})")
            print(f"      IHDR: {w}x{h}  bit_depth={bd}  colour_type={ct} "
                  f"[{ctname}]  compression={comp}  filter={filt}  interlace={inter}")
            if ct not in _COLOUR_TYPES:
                warnings.append(f"chunk#{idx} IHDR: invalid colour_type {ct}")
            if bd not in (1, 2, 4, 8, 16):
                warnings.append(f"chunk#{idx} IHDR: invalid bit_depth {bd}")

        if ctype == b"IEND":
            saw_iend = True

        # Advance using bytes that actually exist, so a lie cannot loop us.
        step = 8 + min(declared_len, n) + 4
        pos += step
        idx += 1
        if ctype == b"IEND":
            break

    if pos < n and pos + 8 > n:
        trailing = n - pos
        if trailing > 0 and not saw_iend:
            warnings.append(f"{trailing} trailing byte(s) after last full chunk")

    if not saw_iend:
        warnings.append("no IEND chunk found")

    print()
    if warnings:
        print(f"warnings ({len(warnings)}):")
        for w in warnings:
            print(f"  ! {w}")
    else:
        print("no warnings: file looks structurally valid")
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: png_inspect.py <file>", file=sys.stderr)
        return 2
    try:
        return inspect(sys.argv[1])
    except FileNotFoundError:
        print(f"no such file: {sys.argv[1]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
