# Asupersync convenience targets.
#
# This Makefile wraps common cargo commands and demo workflows.
# All heavy lifting is done by Cargo; these are shortcuts.

.PHONY: test check clippy fmt demo-record clean

# Default: run full test suite.
test:
	cargo test --all-features

# Type-check without codegen.
check:
	cargo check --all-features

# Lint check (deny warnings).
clippy:
	cargo clippy --all-features -- -D warnings

# Format check.
fmt:
	cargo fmt -- --check

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
	cargo run --example demo_record_nondeterministic --features test-internals

clean:
	cargo clean
