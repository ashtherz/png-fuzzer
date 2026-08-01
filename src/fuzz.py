#!/usr/bin/env python3
"""
fuzz.py -- the fuzzing harness (the driver loop).

    mutate -> execute the target on the mutated file -> detect a crash ->
    deduplicate by crash site -> save the input, notes and a running summary.

A run counts as a crash when the target is killed by a signal OR prints a
sanitizer report. An optional per-run timeout records hangs as potential
denial-of-service findings.

Deduplication is by CRASH SITE -- the source location the sanitizer blames
(file:line inside the target). An earlier, naive approach keyed on the full
sanitizer message, but that text embeds the faulting memory *address*, which
changes every run (ASLR), so identical bugs looked unique. Keying on the stable
crash site is the correct signature.

Subcommands:
    fuzz     run a campaign
    repro    re-run the target on a saved crash file and print the full report
"""
from __future__ import annotations

import argparse
import os
import random
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Make sibling modules importable no matter where we are invoked from.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutator  # noqa: E402

# --------------------------------------------------------------------------- #
# Locations (relative to the project root, which is this file's parent's parent).
# --------------------------------------------------------------------------- #
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = ROOT / "target" / "naive_decoder"
DEFAULT_SEEDS = ROOT / "corpus"
DEFAULT_OUT = ROOT / "crashes"

# Sanitizers must abort (so the process dies by signal) and print a stack trace.
SAN_ENV = {
    "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=1",
    "UBSAN_OPTIONS": "abort_on_error=1:print_stacktrace=1",
}

# --------------------------------------------------------------------------- #
# Parsing sanitizer reports
# --------------------------------------------------------------------------- #
# SUMMARY line examples:
#   SUMMARY: AddressSanitizer: heap-buffer-overflow naive_decoder.c:103 in chunk_checksum
#   SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior naive_decoder.c:48:12
_SUMMARY_RE = re.compile(
    r"SUMMARY:\s+(\w+Sanitizer):\s+(\S+)\s+([\w./-]+):(\d+)(?::\d+)?(?:\s+in\s+(\w+))?"
)
# A stack frame that references our target source, used to recover the function
# name (and as a fallback site) when the SUMMARY line lacks "in <func>".
_FRAME_RE = re.compile(r"#\d+\s+.*?\bin\s+(\w+)\s+([\w./-]+):(\d+)")
# UBSan's precise message, e.g. "runtime error: index 255 out of bounds ...".
_RUNTIME_ERR_RE = re.compile(r"runtime error:\s*(.+)")


@dataclass
class CrashInfo:
    site: str            # dedup key, e.g. "naive_decoder.c:103"
    bug_type: str        # short slug, e.g. "heap-buffer-overflow"
    function: str        # e.g. "chunk_checksum"
    sanitizer: str       # "AddressSanitizer" / "UndefinedBehaviorSanitizer"
    detail: str          # one-line human detail
    report: str          # the full captured stderr


def classify(stderr: str, returncode: int, timed_out: bool) -> Optional[CrashInfo]:
    """Return CrashInfo if this run is a crash/hang, else None."""
    if timed_out:
        return CrashInfo("hang", "timeout-hang", "-", "timeout",
                         "target exceeded the per-run timeout (possible DoS)", stderr)

    m = _SUMMARY_RE.search(stderr)
    if m:
        sanitizer, kind, fname, line, func_in_summary = m.groups()
        site = f"{fname}:{line}"
        # Recover the function name and refine the bug type for UBSan.
        function = func_in_summary or "-"
        if function == "-":
            fm = _FRAME_RE.search(stderr)
            if fm:
                function = fm.group(1)
        bug_type = kind
        rt = _RUNTIME_ERR_RE.search(stderr)
        detail = rt.group(1).strip() if rt else kind
        if kind == "undefined-behavior" and rt:
            # Give the file a more descriptive slug than "undefined-behavior".
            low = rt.group(1).lower()
            if "out of bounds" in low or "index" in low:
                bug_type = "oob-index"
            elif "overflow" in low:
                bug_type = "int-overflow"
            else:
                bug_type = "undefined-behavior"
        return CrashInfo(site, bug_type, function, sanitizer, detail, stderr)

    # No sanitizer summary, but killed by a signal -> still a crash (e.g. raw SEGV).
    if returncode is not None and returncode < 0:
        signum = -returncode
        # Try to recover a site from any target frame in the output.
        fm = _FRAME_RE.search(stderr)
        if fm:
            site = f"{fm.group(2)}:{fm.group(3)}"
            function = fm.group(1)
        else:
            site = f"signal:{signum}"
            function = "-"
        return CrashInfo(site, f"signal-{signum}", function, "signal",
                         f"killed by signal {signum}", stderr)

    return None


# --------------------------------------------------------------------------- #
# Root-cause notes, keyed by the function the crash lands in.
# --------------------------------------------------------------------------- #
ROOT_CAUSE = {
    "chunk_checksum":      ("CWE-125", "Trusts a chunk length from the file when reading data."),
    "fill_row_scratch":    ("CWE-121/787", "File-controlled count writes into a fixed 64-byte stack buffer."),
    "ihdr_channel_lookup": ("CWE-125/129", "Unvalidated colour-type byte used directly as an array index."),
    "ihdr_alloc_and_fill": ("CWE-190->787", "32-bit width narrowed to 16-bit when sizing the pixel buffer."),
}


def root_cause_for(info: CrashInfo) -> tuple[str, str]:
    return ROOT_CAUSE.get(info.function, ("-", "(see sanitizer report)"))


# --------------------------------------------------------------------------- #
# Running the target
# --------------------------------------------------------------------------- #
def run_target(target: Path, png_path: Path, timeout: Optional[float]) -> tuple[str, int, bool]:
    env = {**os.environ, **SAN_ENV}
    try:
        p = subprocess.run(
            [str(target), str(png_path)],
            capture_output=True, text=True, env=env, timeout=timeout,
        )
        return p.stderr + p.stdout, p.returncode, False
    except subprocess.TimeoutExpired as e:
        # text=True, so stdout/stderr are str or None.
        return (e.stderr or "") + (e.stdout or ""), 0, True


# --------------------------------------------------------------------------- #
# Campaign state
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    number: int
    info: CrashInfo
    mutation: str
    png_name: str
    times_hit: int = 1


@dataclass
class Campaign:
    out_dir: Path
    findings: dict[str, Finding] = field(default_factory=dict)  # site -> Finding
    total_crashes: int = 0
    next_number: int = 1

    def record(self, info: CrashInfo, png_bytes: bytes, mutation: str,
               repro_cmd: str) -> Optional[Finding]:
        self.total_crashes += 1
        existing = self.findings.get(info.site)
        if existing is not None:
            existing.times_hit += 1
            return None  # duplicate crash site -> nothing new to save

        n = self.next_number
        self.next_number += 1
        slug = re.sub(r"[^A-Za-z0-9._-]", "-", info.bug_type)
        base = f"{n:03d}_{slug}"
        png_name = f"{base}.png"
        (self.out_dir / png_name).write_bytes(png_bytes)

        cwe, cause = ROOT_CAUSE.get(info.function, ("-", "(see report)"))
        notes = (
            f"Finding #{n:03d}\n"
            f"{'=' * 60}\n"
            f"crash site : {info.site}\n"
            f"function   : {info.function}\n"
            f"bug type   : {info.bug_type}\n"
            f"sanitizer  : {info.sanitizer}\n"
            f"cwe        : {cwe}\n"
            f"root cause : {cause}\n"
            f"detail     : {info.detail}\n\n"
            f"mutation that produced this input:\n  {mutation}\n\n"
            f"reproduce:\n  {repro_cmd}\n\n"
            f"{'-' * 60}\nfull sanitizer report:\n{'-' * 60}\n"
            f"{info.report}\n"
        )
        (self.out_dir / f"{base}.txt").write_text(notes)

        finding = Finding(n, info, mutation, png_name)
        self.findings[info.site] = finding
        return finding

    def write_summary(self) -> None:
        lines = [
            "# Fuzzing campaign summary",
            "",
            f"- total crashing runs: {self.total_crashes}",
            f"- distinct crash sites (unique bugs): {len(self.findings)}",
            "",
            "| # | crash site | function | bug type | CWE | times hit | root cause |",
            "|---|------------|----------|----------|-----|-----------|------------|",
        ]
        for f in sorted(self.findings.values(), key=lambda x: x.number):
            cwe, cause = root_cause_for(f.info)
            lines.append(
                f"| {f.number:03d} | `{f.info.site}` | `{f.info.function}` | "
                f"{f.info.bug_type} | {cwe} | {f.times_hit} | {cause} |"
            )
        lines.append("")
        (self.out_dir / "SUMMARY.md").write_text("\n".join(lines))


# --------------------------------------------------------------------------- #
# fuzz subcommand
# --------------------------------------------------------------------------- #
def load_seeds(seeds_dir: Path) -> list[bytes]:
    seeds = []
    for p in sorted(seeds_dir.glob("*.png")):
        seeds.append(p.read_bytes())
    return seeds


def cmd_fuzz(args) -> int:
    target = Path(args.target).resolve()
    seeds_dir = Path(args.seeds).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not target.exists():
        print(f"error: target not built: {target}\n"
              f"build it with:  cd target && make", file=sys.stderr)
        return 2

    seeds = load_seeds(seeds_dir)
    if not seeds:
        print(f"error: no *.png seeds in {seeds_dir}\n"
              f"generate one with:  cd corpus && python3 make_seed.py", file=sys.stderr)
        return 2

    rng = random.Random(args.seed)
    campaign = Campaign(out_dir=out_dir)
    scratch = out_dir / ".cur.png"

    print(f"target   : {target}")
    print(f"seeds    : {len(seeds)} file(s) from {seeds_dir}")
    print(f"iters    : {args.iters}   rng seed: {args.seed}   "
          f"strategy: {args.strategy or 'weighted-mix'}   "
          f"timeout: {args.timeout or 'off'}")
    print(f"out      : {out_dir}")
    print("-" * 60)

    start = time.time()
    done = 0
    interrupted = False
    try:
        for i in range(1, args.iters + 1):
            done = i
            base = rng.choice(seeds)
            # ~35% of iterations use havoc (stacked mutations).
            if rng.random() < 0.35:
                res = mutator.havoc(rng, base, force=args.strategy)
            else:
                res = mutator.apply_one(rng, base, force=args.strategy)

            scratch.write_bytes(res.data)
            stderr, rc, timed_out = run_target(target, scratch, args.timeout)
            info = classify(stderr, rc, timed_out)

            if info is not None:
                repro_cmd = f"python3 src/fuzz.py repro crashes/{campaign.next_number:03d}_*.png"
                finding = campaign.record(info, res.data, res.description, repro_cmd)
                if finding is not None:
                    print(f"[{i:>6}] NEW  #{finding.number:03d}  {info.bug_type:<20} "
                          f"{info.site:<24} via {res.description[:60]}")
                    campaign.write_summary()

            if i % max(1, args.iters // 20) == 0 or i == args.iters:
                elapsed = time.time() - start
                rate = i / elapsed if elapsed else 0
                print(f"[{i:>6}/{args.iters}] crashes={campaign.total_crashes} "
                      f"unique={len(campaign.findings)} "
                      f"({rate:.0f} exec/s)")
    except KeyboardInterrupt:
        # Ctrl+C: stop cleanly and keep everything found so far.
        interrupted = True
        print("\ninterrupted — wrapping up with what was found so far...")

    if scratch.exists():
        scratch.unlink()
    campaign.write_summary()

    elapsed = time.time() - start
    print("-" * 60)
    print(f"{'stopped' if interrupted else 'done'} after {done} iters, "
          f"{elapsed:.1f}s   crashing runs: {campaign.total_crashes}   "
          f"unique bugs: {len(campaign.findings)}")
    print(f"artifacts in: {out_dir}  (see SUMMARY.md)")
    return 0


# --------------------------------------------------------------------------- #
# repro subcommand
# --------------------------------------------------------------------------- #
def cmd_repro(args) -> int:
    target = Path(args.target).resolve()
    png = Path(args.file)
    if not png.exists():
        # allow a glob (repro command in notes uses one)
        matches = sorted(png.parent.glob(png.name))
        if not matches:
            print(f"no such file: {args.file}", file=sys.stderr)
            return 2
        png = matches[0]
    if not target.exists():
        print(f"error: target not built: {target}", file=sys.stderr)
        return 2

    print(f"reproducing: {png}")
    stderr, rc, timed_out = run_target(target, png, args.timeout)
    info = classify(stderr, rc, timed_out)
    print(stderr)
    print("-" * 60)
    if info is None:
        print(f"NO CRASH (return code {rc}). "
              f"The input did not trigger a sanitizer error.")
        return 1
    cwe, cause = root_cause_for(info)
    print(f"CRASH: {info.bug_type} at {info.site} in {info.function}  "
          f"[{cwe}]  {cause}")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="fuzz.py", description="Mutation-based PNG fuzzing harness.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fuzz", help="run a fuzzing campaign")
    f.add_argument("--iters", type=int, default=6000, help="mutate-and-run iterations")
    f.add_argument("--seed", type=int, default=0, help="RNG seed (fixes the mutation sequence)")
    f.add_argument("--strategy", default=None,
                   help=f"force one strategy: {', '.join(mutator.STRATEGY_NAMES)}")
    f.add_argument("--timeout", type=float, default=None, help="per-run timeout in seconds")
    f.add_argument("--seeds", default=str(DEFAULT_SEEDS), help="seed-corpus directory")
    f.add_argument("--out", default=str(DEFAULT_OUT), help="output dir for crashes")
    f.add_argument("--target", default=str(DEFAULT_TARGET), help="path to the built target")
    f.set_defaults(func=cmd_fuzz)

    r = sub.add_parser("repro", help="re-run the target on a saved crash file")
    r.add_argument("file", help="path to a crashing .png (glob allowed)")
    r.add_argument("--timeout", type=float, default=None, help="per-run timeout in seconds")
    r.add_argument("--target", default=str(DEFAULT_TARGET), help="path to the built target")
    r.set_defaults(func=cmd_repro)
    return ap


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
