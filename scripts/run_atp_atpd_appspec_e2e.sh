#!/bin/bash
# ATP atpd AppSpec supervision contract runner.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_atpd_appspec" \
  cargo test --test atp_atpd_appspec -- --nocapture
