# Asupersync convenience targets.
#
# This Makefile wraps common cargo commands and demo workflows.
# All cargo invocations go through rch with an isolated target directory.

.PHONY: test check clippy fmt demo-record demo-delta-debug demo-benchmark clean

RCH ?= rch exec --
RCH_TARGET_DIR ?= $${TMPDIR:-/tmp}/rch_target_asupersync_makefile
RCH_CARGO = $(RCH) env CARGO_TARGET_DIR=$(RCH_TARGET_DIR) cargo

# Default: run full test suite.
test:
	$(RCH_CARGO) test --all-features

# Type-check without codegen.
check:
	$(RCH_CARGO) check --all-features

# Lint check (deny warnings).
clippy:
	$(RCH_CARGO) clippy --all-features -- -D warnings

# Format check.
fmt:
	$(RCH_CARGO) fmt -- --check

# Record a nondeterministic failure demo trace.
#
# Sweeps seeds to find a cancel/obligation race condition, then records the
# failing execution to an .ftrace file for deterministic replay.
#
# Environment variables:
#   DEMO_SEED_START  - First seed to try (default: 0)
#   DEMO_SEED_COUNT  - Number of seeds to sweep (default: 10_000)
#   DEMO_TRACE_DIR   - Output directory for .ftrace files (default: .)
demo-record:
	$(RCH_CARGO) run --example demo_record_nondeterministic --features test-internals

# Hierarchical delta debugging demo.
#
# Finds a failing seed, extracts scenario elements, and minimizes
# to the smallest subset that reproduces the obligation leak.
#
# Environment variables:
#   DEMO_SEED_START  - First seed to try (default: 0)
#   DEMO_SEED_COUNT  - Number of seeds to sweep (default: 50_000)
#   DEMO_NARRATIVE   - Output path for narrative .md (default: narrative.md)
demo-delta-debug:
	$(RCH_CARGO) run --example demo_delta_debug --features test-internals

# Reproducible benchmark harness for the full time-travel demo pipeline.
#
# Runs record -> delta-debug -> checksum validation and compares all
# outputs against golden checksums in artifacts/demo_golden_checksums.json.
#
# Environment variables:
#   GOLDEN_UPDATE   - Set to "1" to regenerate golden checksums
#   DEMO_TRACE_DIR  - Output directory for artifacts (default: tempdir)
demo-benchmark:
	$(RCH_CARGO) run --example demo_benchmark --features test-internals

clean:
	$(RCH_CARGO) clean
