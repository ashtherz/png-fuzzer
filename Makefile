# Convenience wrapper for the whole project. Run `make` (or `make help`) to list
# targets. Variables can be overridden on the command line, e.g.:
#
#   make fuzz SEEDS=autocorpus_out ITERS=10000 SEED=7
#   make inspect FILE=crashes/001_heap-buffer-overflow.png
#
# (The C build itself lives in target/Makefile; this just drives everything.)

# SEEDS  seed-corpus directory        ITERS  mutate-and-run iterations
# SEED   RNG seed (fixes the sequence) FILE   path used by inspect / repro
SEEDS ?= corpus
ITERS ?= 6000
SEED  ?= 0
FILE  ?=

PYTHON ?= python3

.DEFAULT_GOAL := help
.PHONY: help build release seed inspect fuzz repro check clean

help: ## Show this help
	@echo "PNG mutation fuzzer -- make targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n",$$1,$$2}'
	@echo
	@echo "Variables: SEEDS=$(SEEDS)  ITERS=$(ITERS)  SEED=$(SEED)"
	@echo "Example:   make fuzz SEEDS=autocorpus_out ITERS=10000 SEED=7"

build: ## Build the sanitized target (ASan + UBSan)
	$(MAKE) -C target

release: ## Build the optimized, non-sanitized target
	$(MAKE) -C target release

seed: ## Generate the valid seed PNG (corpus/seed.png)
	$(PYTHON) corpus/make_seed.py

inspect: ## Inspect a file's chunk structure (FILE=path)
	@test -n "$(FILE)" || { echo "usage: make inspect FILE=<path>"; exit 2; }
	$(PYTHON) src/png_inspect.py $(FILE)

fuzz: ## Build + seed-check + run a campaign (SEEDS=, ITERS=, SEED=)
	scripts/run_campaign.sh $(SEEDS) $(ITERS) $(SEED)

repro: ## Replay a saved crash and print the report (FILE=path)
	@test -n "$(FILE)" || { echo "usage: make repro FILE=<path/to/crash.png>"; exit 2; }
	$(PYTHON) src/fuzz.py repro $(FILE)

check: ## Assert a campaign found all planted bugs (CI check)
	$(PYTHON) scripts/check_findings.py crashes/SUMMARY.md

clean: ## Remove built binaries, the generated seed, and crash artifacts
	$(MAKE) -C target clean
	rm -f corpus/seed.png
	find crashes -type f ! -name '.gitkeep' -delete 2>/dev/null || true
	find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
