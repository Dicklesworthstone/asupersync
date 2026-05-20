#!/bin/bash
# ATP TransferActor E2E contract runner.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_atp_transfer_actor" \
  cargo test --test atp_transfer_actor -- --nocapture
