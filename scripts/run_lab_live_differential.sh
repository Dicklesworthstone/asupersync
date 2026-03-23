#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_BIN="${ROOT_DIR}/target/debug/asupersync"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

if [[ -x "${LOCAL_BIN}" ]]; then
  exec "${LOCAL_BIN}" lab differential "$@"
fi

cd "${ROOT_DIR}"
if [[ -x "${RCH_BIN}" ]]; then
  exec "${RCH_BIN}" exec -- cargo run --features cli --bin asupersync -- lab differential "$@"
fi

exec cargo run --features cli --bin asupersync -- lab differential "$@"
