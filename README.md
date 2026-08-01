<p align="center">
  <img src=".github/banner.svg" alt="PNG Mutation Fuzzer" width="100%">
</p>

<p align="center">
  <a href="https://github.com/ashtherz/png-fuzzer/actions/workflows/ci.yml">
    <img src="https://github.com/ashtherz/png-fuzzer/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/dependencies-none-brightgreen.svg" alt="No dependencies">
  <img src="https://img.shields.io/badge/python-3.x-3776ab.svg" alt="Python 3">
  <img src="https://img.shields.io/badge/sanitizers-ASan%20%2B%20UBSan-orange.svg" alt="ASan + UBSan">
</p>

# PNG Mutation Fuzzer

A small, readable **black-box mutation fuzzer** for PNG image decoders — in the
spirit of AFL++ / libFuzzer, but stripped to its essentials so you can read every
line. It mutates PNGs, feeds them to a decoder built under **AddressSanitizer /
UBSan**, and **detects, locates, deduplicates, and records** the memory-safety
bugs they trigger.

<p align="center">
  <img src=".github/demo.gif" alt="A fuzzing campaign discovering all four planted bugs from a single seed" width="92%">
</p>

> **Scope.** The target (`target/naive_decoder.c`) is a deliberately vulnerable
> decoder written for this project, modelling real [CWE](https://cwe.mitre.org/)
> classes — it demonstrates bug *discovery*, not a scan of production libpng. For
> education and authorized security testing only.

📖 **Want the full tour?** The illustrated **[walkthrough](docs/GUIDE.md)** explains
every stage step by step. There's also a **[project site](https://ashtherz.github.io/png-fuzzer/)**.

---

## Quick start

```bash
git clone https://github.com/ashtherz/png-fuzzer.git && cd png-fuzzer
make build        # compile the sanitized decoder
make seed         # write corpus/seed.png
make fuzz         # run a campaign, then print crashes/SUMMARY.md
```

No dependencies beyond a C compiler (`gcc`/`clang`; macOS's `cc` works) and
Python 3 (standard library only). `make help` lists every shortcut; the raw
`python3 …` commands are in the [CLI reference](#command-line-reference).

## How it works

```
seed.png ─▶ mutate ─▶ malformed.png ─▶ naive_decoder (ASan/UBSan) ─▶ crash?
              ▲                                                         │
              └──────────────── loop ──────────────┐                   ▼
                                                    └── dedup + save (input · notes · SUMMARY.md)
```

Five single-responsibility components:

| Component | File | Job |
|-----------|------|-----|
| Seed generator | [`corpus/make_seed.py`](corpus/make_seed.py) | Builds a valid PNG byte-by-byte (no imaging library). |
| Structure inspector | [`src/png_inspect.py`](src/png_inspect.py) | Prints a PNG's chunk table; tolerant of malformed input, so it also triages crash files. |
| Mutation engine | [`src/mutator.py`](src/mutator.py) | Named corruption strategies + a `havoc` mode, all from a seeded RNG. |
| Vulnerable target | [`target/naive_decoder.c`](target/naive_decoder.c) | Naive decoder with four planted bugs, built under sanitizers. |
| Fuzzing harness | [`src/fuzz.py`](src/fuzz.py) | The loop: mutate → run → detect → dedup by crash site → save. |

The full data-flow diagram and a stage-by-stage tour are in
**[docs/GUIDE.md](docs/GUIDE.md)**.

## The four planted bugs

Each lives in its own function, so a sanitizer report blames exactly one weakness.

| Function | Weakness | Root cause |
|----------|----------|------------|
| `chunk_checksum` | heap over-read (CWE-125) | Trusts a chunk `length` from the file when reading. |
| `fill_row_scratch` | stack overflow (CWE-121/787) | File-controlled count writes into a fixed 64-byte stack buffer. |
| `ihdr_channel_lookup` | OOB index read (CWE-125/129) | Unvalidated colour-type used directly as a table index. |
| `ihdr_alloc_and_fill` | narrowing → heap write (CWE-190→787) | 32-bit width truncated to 16-bit when sizing the buffer. |

The common thread: a value taken from the file and **trusted** as a length, an
index, or a size, with no bounds check — the most common shape of real
memory-safety bugs.

## Results

A deterministic run (`--seed 0`, 1500 iterations) produced **692 crashing runs →
4 unique bugs**. The dedup key is the **crash site** (`file:line`), *not* the
sanitizer's full message — that message embeds the faulting address, which
changes every run (ASLR), so identical bugs would otherwise look unique. That
692 → 4 collapse is the whole reason deduplication exists.

Findings land in `crashes/`: per unique bug, a `NNN_<bugtype>.png` (the exact
input, reproducible forever) and a `.txt` (the mutation that caused it, the full
sanitizer report, and a reproduce command), plus a rolling `SUMMARY.md`. A fixed
`--seed` replays the exact mutation sequence on any machine.

## Command-line reference

```bash
python3 src/fuzz.py fuzz  [options]      # run a campaign
python3 src/fuzz.py repro <crash.png>    # replay a saved crash, print the report
python3 src/png_inspect.py <file>        # chunk table for any file (valid or broken)
```

`fuzz` options:

| Flag | Meaning |
|------|---------|
| `--iters N` | Mutate-and-run iterations (default 6000). |
| `--seed N` | RNG seed; fixes the exact mutation sequence. |
| `--strategy NAME` | Force one strategy instead of the weighted mix. |
| `--timeout SECS` | Per-run timeout; hangs are recorded as possible DoS findings. |
| `--seeds DIR` | Seed-corpus directory (default `corpus/`). |
| `--out DIR` | Output directory for crashes (default `crashes/`). |

Strategies: `bit_flip`, `byte_flip`, `truncate`, `lie_length`, `ihdr_field`,
`dup_chunk`, `remove_chunk`, `corrupt_crc`.

Everything is also available through `make` — `make help` lists `build`, `release`,
`seed`, `inspect FILE=…`, `fuzz`, `repro FILE=…`, `check`, and `clean`.

## Seeds & AutoCorpus

The fuzzer is **seed-agnostic** — point it at any corpus:

```bash
make fuzz SEEDS=path/to/corpus            # or: python3 src/fuzz.py fuzz --seeds path/to/corpus
```

More diverse seeds reach more code, so growing the corpus is the biggest lever on
a black-box fuzzer. To auto-generate one,
[**AutoCorpus**](https://github.com/user1342/AutoCorpus) (an LLM-backed seed
generator) pairs well — it *makes* seeds, this fuzzer *mutates* them:

```bash
make fuzz SEEDS=autocorpus_out
```

`scripts/run_campaign.sh` (which `make fuzz` calls) reports how many files
actually carry a PNG signature. AutoCorpus shines on text formats (JSON/XML);
PNG is binary, so treat its output as raw starting material and let
`png_inspect.py` tell you what parses.

## Limitations

Black-box (no coverage feedback), reachability bounded by seed diversity,
self-authored target (a demonstration, not an audit of a real decoder), and no
test-case minimization. Longer discussion in the [guide](docs/GUIDE.md).

## More

- **[Walkthrough / guide](docs/GUIDE.md)** — the illustrated deep dive.
- **[Project site](https://ashtherz.github.io/png-fuzzer/)** — GitHub Pages.
- **[Contributing](CONTRIBUTING.md)** — setup, the checks CI runs, and how to add
  a strategy or a bug.
- **Continuous integration** — every push builds the target and asserts all four
  bugs are still found ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Acknowledgements

[AutoCorpus](https://github.com/user1342/AutoCorpus) (GPL-3.0, by
[@user1342](https://github.com/user1342)) — the complementary seed generator, *referenced
and interoperated with, not bundled*, so this repository stays MIT-licensed.
Detection is built on [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)
+ UBSan; the design is inspired by AFL++ and libFuzzer (kept black-box here for clarity).

## License

[MIT](LICENSE) — free for everyone to use, study, modify, and share.
