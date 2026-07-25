#!/usr/bin/env python3
"""
mutator.py -- the mutation engine.

A mutation takes valid (or already-broken) PNG bytes and returns corrupted bytes
plus a short, human-readable description of *exactly* what it changed. Because
every mutation is named and self-describing, any crash the fuzzer finds can be
traced back to the byte-level change that caused it.

Two families of strategy:

  Dumb (format-agnostic):        bit_flip, byte_flip, truncate
  Structure-aware (PNG-aware):   lie_length, dup_chunk, remove_chunk,
                                 ihdr_field, corrupt_crc

The dispatcher weights effort toward the structure-aware strategies -- they reach
bugs that random bit-flipping almost never does. `havoc` stacks several mutations
onto one input. All randomness flows through a seeded RNG so a run is reproducible.

This module has no third-party dependencies and does not import the C target; it
only ever manipulates bytes.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


# --------------------------------------------------------------------------- #
# A tiny, tolerant PNG chunk parser (shared shape with png_inspect.py).
# --------------------------------------------------------------------------- #
@dataclass
class Chunk:
    index: int          # 0-based position in the chunk stream
    len_off: int        # offset of the 4-byte length field
    declared_len: int   # length value read from the file (may be a lie)
    ctype: bytes        # 4 type bytes
    data_off: int       # offset where data begins
    crc_off: int        # offset of the 4-byte CRC (may be past EOF if truncated)
    end_off: int        # offset just past this chunk (clamped to len(buf))


def parse_chunks(buf: bytes) -> List[Chunk]:
    """Walk the chunk stream as far as the bytes allow. Never raises."""
    chunks: List[Chunk] = []
    pos = 8 if buf[:8] == PNG_SIGNATURE else 0
    i = 0
    n = len(buf)
    while pos + 8 <= n:
        declared_len = struct.unpack(">I", buf[pos:pos + 4])[0]
        ctype = buf[pos + 4:pos + 8]
        data_off = pos + 8
        crc_off = data_off + declared_len
        end_off = min(crc_off + 4, n)
        chunks.append(Chunk(i, pos, declared_len, ctype, data_off, crc_off, end_off))
        # Advance using the *physically present* bytes so a lie can't trap us in
        # a loop: cap the step to what actually exists.
        step = 8 + min(declared_len, n) + 4
        if step <= 0:
            break
        pos += step
        i += 1
        if ctype == b"IEND":
            break
    return chunks


# --------------------------------------------------------------------------- #
# Mutation result type
# --------------------------------------------------------------------------- #
@dataclass
class MutationResult:
    data: bytes
    description: str


# Each strategy has the signature: (rng, data, chunks) -> Optional[MutationResult]
# Returning None means "not applicable to this input" (e.g. no chunks present);
# the dispatcher then falls back to a dumb strategy.
Strategy = Callable[["object", bytes, List[Chunk]], Optional[MutationResult]]


# --------------------------------------------------------------------------- #
# Dumb strategies
# --------------------------------------------------------------------------- #
def m_bit_flip(rng, data: bytes, chunks) -> Optional[MutationResult]:
    if not data:
        return None
    b = bytearray(data)
    pos = rng.randrange(len(b))
    bit = rng.randrange(8)
    b[pos] ^= (1 << bit)
    return MutationResult(bytes(b), f"bit_flip: byte {pos}, bit {bit}")


def m_byte_flip(rng, data: bytes, chunks) -> Optional[MutationResult]:
    if not data:
        return None
    b = bytearray(data)
    pos = rng.randrange(len(b))
    old = b[pos]
    new = rng.randrange(256)
    b[pos] = new
    return MutationResult(bytes(b), f"byte_flip: byte {pos}, 0x{old:02x}->0x{new:02x}")


def m_truncate(rng, data: bytes, chunks) -> Optional[MutationResult]:
    if len(data) < 2:
        return None
    keep = rng.randrange(1, len(data))
    return MutationResult(data[:keep], f"truncate: {len(data)} -> {keep} bytes")


# --------------------------------------------------------------------------- #
# Structure-aware strategies
# --------------------------------------------------------------------------- #
# Interesting boundary values for IHDR integer fields. 0x10000 (and multiples)
# are chosen to defeat the decoder's 16-bit narrowing (their low 16 bits are 0).
_WIDTH_VALUES = [0, 1, 64, 65, 100, 255, 256, 1000, 4096, 65535,
                 0x10000, 0x20000, 0x30000, 0x7FFFFFFF, 0xFFFFFFFF]
_COLOURTYPE_VALUES = [0, 2, 3, 4, 6, 7, 8, 16, 64, 100, 200, 255]
_BITDEPTH_VALUES = [0, 1, 2, 4, 8, 16, 24, 32, 255]

# Named 4-byte / 1-byte fields inside the IHDR data area.
_IHDR_FIELDS = [
    ("width",  0, 4, _WIDTH_VALUES),
    ("height", 4, 4, _WIDTH_VALUES),
    ("bitdepth", 8, 1, _BITDEPTH_VALUES),
    ("colourtype", 9, 1, _COLOURTYPE_VALUES),
]


def m_lie_length(rng, data: bytes, chunks) -> Optional[MutationResult]:
    """Rewrite a chunk's declared length so it disagrees with the bytes present."""
    if not chunks:
        return None
    c = rng.choice(chunks)
    kind = rng.choice(["huge", "plus", "minus", "zero", "max"])
    if kind == "huge":
        new_len = rng.choice([100_000, 1_000_000, 0x00FFFFFF])
    elif kind == "plus":
        new_len = c.declared_len + rng.randint(1, 500)
    elif kind == "minus":
        new_len = max(0, c.declared_len - rng.randint(1, max(1, c.declared_len)))
    elif kind == "zero":
        new_len = 0
    else:  # max
        new_len = 0xFFFFFFFF
    b = bytearray(data)
    b[c.len_off:c.len_off + 4] = struct.pack(">I", new_len & 0xFFFFFFFF)
    return MutationResult(
        bytes(b),
        f"lie_length: chunk#{c.index} {c.ctype.decode('latin1')} "
        f"len {c.declared_len} -> {new_len}",
    )


def m_ihdr_field(rng, data: bytes, chunks) -> Optional[MutationResult]:
    """Overwrite one IHDR field with an interesting boundary value."""
    ihdr = next((c for c in chunks if c.ctype == b"IHDR"), None)
    if ihdr is None or ihdr.data_off + 13 > len(data):
        return None
    name, off, size, values = rng.choice(_IHDR_FIELDS)
    value = rng.choice(values)
    b = bytearray(data)
    field_off = ihdr.data_off + off
    if size == 4:
        b[field_off:field_off + 4] = struct.pack(">I", value & 0xFFFFFFFF)
    else:
        b[field_off] = value & 0xFF
    return MutationResult(
        bytes(b),
        f"ihdr_field: {name} = {value} (0x{value:x})",
    )


def m_dup_chunk(rng, data: bytes, chunks) -> Optional[MutationResult]:
    """Duplicate a whole chunk (inserted right after the original)."""
    if not chunks:
        return None
    c = rng.choice(chunks)
    raw = data[c.len_off:c.end_off]
    b = data[:c.end_off] + raw + data[c.end_off:]
    return MutationResult(
        b, f"dup_chunk: chunk#{c.index} {c.ctype.decode('latin1')} duplicated"
    )


def m_remove_chunk(rng, data: bytes, chunks) -> Optional[MutationResult]:
    """Delete a whole chunk from the stream."""
    if len(chunks) < 2:  # keep at least something after the signature
        return None
    c = rng.choice(chunks)
    b = data[:c.len_off] + data[c.end_off:]
    return MutationResult(
        b, f"remove_chunk: chunk#{c.index} {c.ctype.decode('latin1')} removed"
    )


def m_corrupt_crc(rng, data: bytes, chunks) -> Optional[MutationResult]:
    """Flip the CRC bytes of a chunk (integrity check, not a security control)."""
    candidates = [c for c in chunks if c.crc_off + 4 <= len(data)]
    if not candidates:
        return None
    c = rng.choice(candidates)
    b = bytearray(data)
    for i in range(4):
        b[c.crc_off + i] ^= rng.randrange(1, 256)
    return MutationResult(
        bytes(b), f"corrupt_crc: chunk#{c.index} {c.ctype.decode('latin1')} CRC flipped"
    )


# --------------------------------------------------------------------------- #
# Dispatch table (name -> (function, weight)). Higher weight = chosen more often.
# --------------------------------------------------------------------------- #
_STRATEGIES: dict[str, Tuple[Strategy, int]] = {
    # dumb
    "bit_flip":     (m_bit_flip, 2),
    "byte_flip":    (m_byte_flip, 2),
    "truncate":     (m_truncate, 2),
    # structure-aware (weighted higher -- they reach the planted bugs)
    "lie_length":   (m_lie_length, 6),
    "ihdr_field":   (m_ihdr_field, 6),
    "dup_chunk":    (m_dup_chunk, 3),
    "remove_chunk": (m_remove_chunk, 3),
    "corrupt_crc":  (m_corrupt_crc, 3),
}

STRATEGY_NAMES = list(_STRATEGIES.keys())
_DUMB_FALLBACKS = [m_bit_flip, m_byte_flip]


def _weighted_pick(rng) -> Tuple[str, Strategy]:
    names = list(_STRATEGIES.keys())
    weights = [_STRATEGIES[n][1] for n in names]
    name = rng.choices(names, weights=weights, k=1)[0]
    return name, _STRATEGIES[name][0]


def apply_one(rng, data: bytes, force: Optional[str] = None) -> MutationResult:
    """Apply a single mutation. If `force` names a strategy, use only that one.

    Falls back to a dumb strategy if the chosen structure-aware strategy did not
    apply (e.g. the input has no parseable chunks)."""
    chunks = parse_chunks(data)
    if force is not None:
        if force not in _STRATEGIES:
            raise ValueError(f"unknown strategy: {force!r} "
                             f"(choices: {', '.join(STRATEGY_NAMES)})")
        result = _STRATEGIES[force][0](rng, data, chunks)
        if result is not None:
            return result
        # Forced strategy was not applicable; report a no-op so the caller can skip.
        return MutationResult(data, f"{force}: (not applicable)")

    name, fn = _weighted_pick(rng)
    result = fn(rng, data, chunks)
    if result is None:
        fallback = rng.choice(_DUMB_FALLBACKS)
        result = fallback(rng, data, chunks)
        if result is None:
            result = MutationResult(data, "noop")
    return result


def havoc(rng, data: bytes, max_stack: int = 5,
          force: Optional[str] = None) -> MutationResult:
    """Stack 2..max_stack mutations onto one input in a single pass."""
    n = rng.randint(2, max_stack)
    cur = data
    parts: List[str] = []
    for _ in range(n):
        res = apply_one(rng, cur, force=force)
        cur = res.data
        parts.append(res.description)
    return MutationResult(cur, "havoc[" + " | ".join(parts) + "]")


# --------------------------------------------------------------------------- #
# CLI: quick manual inspection of what a mutation does.
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import argparse
    import random

    ap = argparse.ArgumentParser(description="Apply one mutation and report it.")
    ap.add_argument("seed", help="path to a PNG to mutate")
    ap.add_argument("--seed-rng", type=int, default=0, help="RNG seed")
    ap.add_argument("--strategy", help=f"force a strategy: {', '.join(STRATEGY_NAMES)}")
    ap.add_argument("--havoc", action="store_true", help="stack several mutations")
    ap.add_argument("--out", help="write mutated bytes here")
    args = ap.parse_args()

    with open(args.seed, "rb") as f:
        original = f.read()
    rng = random.Random(args.seed_rng)
    result = (havoc(rng, original, force=args.strategy) if args.havoc
              else apply_one(rng, original, force=args.strategy))
    print(result.description)
    print(f"{len(original)} bytes -> {len(result.data)} bytes")
    if args.out:
        with open(args.out, "wb") as f:
            f.write(result.data)
        print(f"wrote {args.out}")
