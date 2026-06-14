#!/usr/bin/env bash
# Deterministic memory-residency replay E2E lane
# (asupersync-memory-residency-control-ho2itz.4).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/memory_residency_replay_e2e"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_ID="${MEMORY_RESIDENCY_REPLAY_RUN_ID:-${TIMESTAMP}}"
CONTRACT="${PROJECT_ROOT}/artifacts/memory_residency_replay_e2e_contract_v1.json"
HELPER="${SCRIPT_DIR}/memory_residency_replay_e2e.py"
PROOF_COMMAND="RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=\${TMPDIR:-/tmp}/rch_target_memory_residency_replay_e2e_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test memory_residency_replay_e2e_contract -- --nocapture"

export TEST_SEED="${TEST_SEED:-memory-residency-replay-fixture-v1}"

if [[ ! -f "$CONTRACT" ]]; then
    echo "FATAL: missing input scenario contract: $CONTRACT" >&2
    echo "copy-paste RCH command: $PROOF_COMMAND" >&2
    exit 1
fi

if [[ ! -x "$HELPER" ]]; then
    echo "FATAL: missing executable helper: $HELPER" >&2
    echo "copy-paste RCH command: $PROOF_COMMAND" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

python3 "$HELPER" \
    --contract "$CONTRACT" \
    --output-root "$OUTPUT_DIR" \
    --run-id "$RUN_ID" \
    --generated-at "$GENERATED_AT"
