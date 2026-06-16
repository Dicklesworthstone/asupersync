#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_ID="${RUN_ID:-a7-quic-application-data-loopback}"
TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_${RUN_ID}}"

echo "ATP_QUIC_TRACE=${ATP_QUIC_TRACE:-1}"
echo "CARGO_TARGET_DIR=${TARGET_DIR}"

RCH_REQUIRE_REMOTE=1 rch exec -- env \
  ATP_QUIC_TRACE="${ATP_QUIC_TRACE:-1}" \
  CARGO_TARGET_DIR="${TARGET_DIR}" \
  CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features test-internals,tls \
    --test quic_application_data_udp_loopback -- --nocapture
