#!/bin/bash
# ATP-N7: deterministic local test-vector manifest for CI proof lanes.

set -euo pipefail

OUT_DIR="${ATP_TEST_VECTOR_DIR:-artifacts/test-vectors}"
mkdir -p "$OUT_DIR"

cat > "${OUT_DIR}/manifest.json" <<'JSON'
{
  "schema_version": "atp-test-vector-manifest-v1",
  "source": "repository-local",
  "network_required": false,
  "vectors": [
    {
      "id": "quic-frame-roundtrip-basic",
      "lane": "atp_conformance",
      "description": "Built-in QUIC frame roundtrip fixtures compiled from tests/atp/quic/conformance.rs"
    },
    {
      "id": "raptorq-hard-regime-basic",
      "lane": "atp_packet_lab",
      "description": "Built-in RaptorQ/packet-lab fixtures compiled from repository tests"
    }
  ]
}
JSON

echo "ATP test-vector manifest written to ${OUT_DIR}/manifest.json"
