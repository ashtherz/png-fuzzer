#!/usr/bin/env python3
"""
make_seed.py -- build a *valid* PNG file byte-by-byte, with no imaging library.

Every byte is constructed and understood here: the 8-byte signature, the IHDR
header chunk, one IDAT chunk of zlib-compressed pixel data, and the IEND marker.
Because we build it ourselves, the seed is fully controllable and we know exactly
what a "correct" file looks like -- which is the baseline the mutator corrupts.

Only the Python standard library is used. `zlib` is a compression library, not an
imaging library: it does DEFLATE, exactly the compression PNG's IDAT requires.

Run:
    python3 make_seed.py            # writes ./seed.png (8x8 RGB gradient)
    python3 make_seed.py out.png    # custom output path
"""
import os
import struct
import sys
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Serialize one PNG chunk: length(4) | type(4) | data | crc(4).

    The CRC is computed over type+data, exactly as the PNG spec requires.
    """
    assert len(chunk_type) == 4, "chunk type must be 4 ASCII bytes"
    length = struct.pack(">I", len(data))
    crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    return length + chunk_type + data + crc


def build_png(width: int = 8, height: int = 8) -> bytes:
    """Construct a minimal valid truecolour (RGB, 8-bit) PNG."""
    bit_depth = 8
    colour_type = 2          # 2 = truecolour (RGB), 3 channels
    compression = 0          # 0 = DEFLATE (the only value PNG allows)
    filter_method = 0        # 0 = adaptive filtering
    interlace = 0            # 0 = no interlacing

    ihdr = struct.pack(
        ">IIBBBBB",
        width, height, bit_depth, colour_type, compression, filter_method, interlace,
    )

    # Build raw scanlines: each row is one filter byte (0 = None) followed by
    # width * 3 bytes of RGB. We paint a simple gradient so the compressed data
    # is non-trivial (a few dozen bytes), not just a run of zeros.
    raw = bytearray()
    for y in range(height):
        raw.append(0)                       # filter type: None
        for x in range(width):
            raw.append((x * 32) & 0xFF)     # R
            raw.append((y * 32) & 0xFF)     # G
            raw.append(((x + y) * 16) & 0xFF)  # B

    idat = zlib.compress(bytes(raw), level=9)

    return (
        PNG_SIGNATURE
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", idat)
        + chunk(b"IEND", b"")
    )


def main() -> None:
    # Default output goes next to this script (the corpus/ directory), so the
    # seed lands in the same place regardless of the current working directory
    # -- e.g. `python3 corpus/make_seed.py` and `cd corpus && python3 make_seed.py`
    # both write corpus/seed.png, which is where the fuzzer looks for seeds.
    default_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seed.png")
    out = sys.argv[1] if len(sys.argv) > 1 else default_out
    png = build_png()
    with open(out, "wb") as f:
        f.write(png)
    print(f"wrote {out} ({len(png)} bytes): valid 8x8 RGB PNG")


if __name__ == "__main__":
    main()
