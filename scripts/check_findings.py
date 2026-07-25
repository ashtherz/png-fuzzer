#!/usr/bin/env python3
"""
check_findings.py -- assert a fuzzing campaign found the expected bugs.

Reads a crashes/SUMMARY.md produced by `fuzz.py fuzz` and verifies that every
expected crash-site function is present. Used by CI so a broken pipeline (e.g. a
mutation that stops reaching a bug, or a dedup regression) fails the build.

Usage:
    python3 scripts/check_findings.py [crashes/SUMMARY.md]

Exit code 0 if all expected bugs are present, 1 otherwise.
"""
from __future__ import annotations

import sys
from pathlib import Path

# The four planted bugs, by the function each crash lands in.
EXPECTED = {
    "chunk_checksum":      "heap over-read (CWE-125)",
    "fill_row_scratch":    "stack overflow (CWE-121/787)",
    "ihdr_channel_lookup": "OOB index read (CWE-125/129)",
    "ihdr_alloc_and_fill": "integer narrowing -> heap write (CWE-190->787)",
}


def main() -> int:
    summary_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("crashes/SUMMARY.md")
    if not summary_path.exists():
        print(f"FAIL: no summary at {summary_path} -- did the campaign run?")
        return 1

    text = summary_path.read_text()
    missing = [fn for fn in EXPECTED if fn not in text]

    print(f"checking {summary_path} for {len(EXPECTED)} expected bugs:")
    for fn, desc in EXPECTED.items():
        mark = "MISSING" if fn in missing else "found"
        print(f"  [{'x' if fn not in missing else ' '}] {fn:<22} {desc}  ({mark})")

    if missing:
        print(f"\nFAIL: {len(missing)} expected bug(s) not found: {', '.join(missing)}")
        return 1

    print(f"\nOK: all {len(EXPECTED)} planted bugs were discovered and deduplicated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
