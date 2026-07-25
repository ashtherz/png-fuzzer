# Contributing

Thanks for your interest! This is a small, deliberately-readable educational
project, so the bar for contributions is simple: **keep it clear.** A newcomer
should be able to read any file top-to-bottom and understand it.

## Ground rules

- **No third-party runtime dependencies.** The fuzzer runs on the Python standard
  library and a C compiler, nothing else. A contribution that adds a `pip`
  dependency to the core loop will be declined.
- **Readability over cleverness.** Match the surrounding style, comment the *why*,
  and keep functions short and single-purpose.
- **Every bug must be reproducible.** Any planted vulnerability or fix must be
  demonstrable with a saved input and a sanitizer report.
- **This is for education and authorized security testing only.** Don't add
  anything designed to target real third-party software.

## Getting set up

```bash
git clone https://github.com/ashtherz/png-fuzzer.git && cd png-fuzzer
cd target && make && cd ..        # sanitized decoder
python3 corpus/make_seed.py       # corpus/seed.png
python3 src/fuzz.py fuzz --iters 1500 --seed 0
```

## Run the same checks CI runs

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) builds the target,
runs a deterministic `--seed 0` campaign, and asserts all four planted bugs are
found. Reproduce it locally before opening a PR:

```bash
make -C target CC=clang
python3 corpus/make_seed.py
python3 src/png_inspect.py corpus/seed.png
python3 src/fuzz.py fuzz --iters 1500 --seed 0
python3 scripts/check_findings.py crashes/SUMMARY.md   # must print "OK: all 4 ..."
python3 -m py_compile src/*.py corpus/*.py scripts/*.py
```

If you change anything about crash detection, dedup, or the target, the
`check_findings.py` step is your safety net.

## How to add a mutation strategy

1. Write a function in [`src/mutator.py`](src/mutator.py) with the signature
   `def m_yourname(rng, data, chunks) -> Optional[MutationResult]`. Return `None`
   if it doesn't apply to the given input.
2. Always return a **descriptive** `MutationResult` — the description is what makes
   a crash traceable, so say exactly what changed.
3. Register it in the `_STRATEGIES` dispatch table with a weight.
4. Test it in isolation: `python3 src/mutator.py corpus/seed.png --strategy yourname`.

## How to add a planted bug

1. Add a **new function** in [`target/naive_decoder.c`](target/naive_decoder.c)
   (own function = clean, dedup-able crash site) with a comment naming the CWE and
   the root cause. Mark it `__attribute__((noinline))`.
2. Make sure the **valid seed still decodes cleanly** — the bug must only fire on
   mutated input.
3. Add its function name + CWE + root cause to `ROOT_CAUSE` in
   [`src/fuzz.py`](src/fuzz.py) and to `EXPECTED` in
   [`scripts/check_findings.py`](scripts/check_findings.py).
4. Confirm a campaign discovers it and that it lands at its own crash site.

## Commit & PR

- Small, focused commits with a clear message (imperative mood).
- Note how you verified the change (the `check_findings.py` output is ideal).
- One idea per PR keeps review easy.

## Reporting issues

Open a GitHub issue with: your OS and compiler (`cc --version`), the exact
command, and the output. For a crash the fuzzer found, attach the `crashes/NNN_*`
files — they reproduce the bug independently of the RNG.
