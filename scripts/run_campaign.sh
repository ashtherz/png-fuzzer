#!/usr/bin/env bash
#
# run_campaign.sh -- one command: build (if needed), sanity-check the seeds,
# then run a fuzzing campaign. Handy for handing a folder of externally-generated
# seeds (e.g. from AutoCorpus, https://github.com/user1342/AutoCorpus) straight
# to the fuzzer.
#
# Usage:
#   scripts/run_campaign.sh [SEEDS_DIR] [ITERS] [RNG_SEED]
#
#   SEEDS_DIR   folder of *.png seeds        (default: corpus/)
#   ITERS       mutate-and-run iterations    (default: 6000)
#   RNG_SEED    RNG seed for reproducibility (default: 0)
#
# Examples:
#   scripts/run_campaign.sh                          # default corpus, 6000 iters
#   scripts/run_campaign.sh autocorpus_out           # seeds from AutoCorpus
#   scripts/run_campaign.sh autocorpus_out 10000 7   # + custom iters and RNG seed
#
set -euo pipefail

# Resolve the repo root from this script's location, so it works from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

SEEDS_DIR="${1:-corpus}"
ITERS="${2:-6000}"
RNG_SEED="${3:-0}"
TARGET="target/naive_decoder"

echo "==> project : $ROOT"
echo "==> seeds   : $SEEDS_DIR"
echo "==> iters   : $ITERS   rng seed: $RNG_SEED"
echo

# 1. Build the sanitized target if it isn't there yet.
if [[ ! -x "$TARGET" ]]; then
  echo "==> target not built; running 'make -C target'..."
  make -C target
  echo
fi

# 2. If using the default corpus and it's empty, generate the seed for the user.
if [[ "$SEEDS_DIR" == "corpus" && -z "$(find corpus -maxdepth 1 -name '*.png' -print -quit 2>/dev/null)" ]]; then
  echo "==> no seed in corpus/; generating one..."
  python3 corpus/make_seed.py
  echo
fi

# 3. Sanity-check the seed folder. Files that don't start with the PNG signature
#    won't decode as PNG -- useful when the seeds came from a generic generator.
if [[ ! -d "$SEEDS_DIR" ]]; then
  echo "error: seed directory not found: $SEEDS_DIR" >&2
  exit 2
fi

python3 - "$SEEDS_DIR" <<'PY'
import sys, glob, os
d = sys.argv[1]
pngs = sorted(glob.glob(os.path.join(d, "*.png")))
sig = b"\x89PNG\r\n\x1a\n"
valid = 0
for p in pngs:
    with open(p, "rb") as f:
        if f.read(8) == sig:
            valid += 1
total = len(pngs)
print(f"==> seed check: {total} *.png file(s), {valid} with a valid PNG signature")
if total == 0:
    print(f"error: no *.png seeds in {d}", file=sys.stderr)
    print("       (point this at a folder of .png seeds, or run make_seed.py)", file=sys.stderr)
    sys.exit(2)
if valid < total:
    print(f"    note: {total - valid} file(s) are not PNG-signed; the decoder is "
          f"lenient and will still try them, but inspect with:")
    print(f"          python3 src/png_inspect.py {d}/<file>")
PY
echo

# 4. Run the campaign.
echo "==> starting campaign..."
python3 src/fuzz.py fuzz --seeds "$SEEDS_DIR" --iters "$ITERS" --seed "$RNG_SEED"

# 5. Show the summary if any bugs were found.
echo
if [[ -f crashes/SUMMARY.md ]]; then
  echo "==> crashes/SUMMARY.md:"
  cat crashes/SUMMARY.md
fi
