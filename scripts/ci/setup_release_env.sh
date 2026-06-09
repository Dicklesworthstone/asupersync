#!/bin/bash
# ATP-N7: release-lane environment bootstrap.

set -euo pipefail

mkdir -p artifacts/release proof test-results logs

export ATP_RELEASE_MODE="${ATP_RELEASE_MODE:-1}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

echo "ATP release environment ready"
echo "ATP_RELEASE_MODE=$ATP_RELEASE_MODE"
echo "CARGO_INCREMENTAL=$CARGO_INCREMENTAL"
