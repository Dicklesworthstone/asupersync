#!/usr/bin/env bash
set -euo pipefail

if [[ "${RCH_REQUIRE_REMOTE:-}" != "1" ]]; then
  echo "RCH_REQUIRE_REMOTE=1 is required; local Cargo fallback is not valid proof." >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

jq empty \
  artifacts/validation_frontier_inventory_v1.json \
  artifacts/rch_stale_progress_receipt_contract_v1.json \
  artifacts/downstream_consumer_proof_v1.json \
  artifacts/validation_frontier_graph_budgets_v1.json \
  artifacts/validation_frontier_signoff_v1.json \
  artifacts/proof_lane_manifest_v1.json \
  artifacts/proof_status_snapshot_v1.json

RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_validation_frontier_inventory CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test validation_frontier_inventory_contract -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_rch_stale_progress_receipt CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test rch_stale_progress_receipt_contract -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_downstream_consumer_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test downstream_consumer_proof_contract -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_validation_frontier_graph_budgets CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test validation_frontier_graph_budgets_contract -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_validation_frontier_signoff CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test validation_frontier_signoff_contract -- --nocapture
