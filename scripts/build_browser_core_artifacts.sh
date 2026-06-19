#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

PROFILE="${1:-prod}"
CRATE_DIR="${REPO_ROOT}/asupersync-browser-core"
STAGING_DIR="${REPO_ROOT}/pkg/browser-core/${PROFILE}"
PACKAGE_DIR="${REPO_ROOT}/packages/browser-core"
ABI_FILE="${REPO_ROOT}/src/types/wasm_abi.rs"
JS_MAP_FILE="asupersync.js.map"
WASM_MAP_FILE="asupersync_bg.wasm.map"
RCH_BIN="${RCH_BIN:-rch}"
WRAPPER_ROOT="${REPO_ROOT}/target/browser-core-build"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "error: wasm-pack is required (https://rustwasm.github.io/wasm-pack/)" >&2
  exit 1
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "error: rg is required to extract ABI constants" >&2
  exit 1
fi

if ! command -v "${RCH_BIN}" >/dev/null 2>&1; then
  echo "error: ${RCH_BIN} is required to offload cargo-backed wasm builds" >&2
  exit 1
fi

case "${PROFILE}" in
  minimal)
    BUILD_ARGS=(--release -- --no-default-features --features minimal)
    RCH_CARGO_ARGS=(build -p asupersync-browser-core --target wasm32-unknown-unknown --release --no-default-features --features minimal)
    ;;
  dev)
    BUILD_ARGS=(--dev -- --no-default-features --features dev)
    RCH_CARGO_ARGS=(build -p asupersync-browser-core --target wasm32-unknown-unknown --no-default-features --features dev)
    ;;
  prod)
    BUILD_ARGS=(--release -- --no-default-features --features prod)
    RCH_CARGO_ARGS=(build -p asupersync-browser-core --target wasm32-unknown-unknown --release --no-default-features --features prod)
    ;;
  deterministic)
    BUILD_ARGS=(--release -- --no-default-features --features deterministic)
    RCH_CARGO_ARGS=(build -p asupersync-browser-core --target wasm32-unknown-unknown --release --no-default-features --features deterministic)
    ;;
  *)
    cat >&2 <<'USAGE'
error: invalid profile
usage: scripts/build_browser_core_artifacts.sh [minimal|dev|prod|deterministic]
USAGE
    exit 2
    ;;
esac

mkdir -p "${STAGING_DIR}" "${PACKAGE_DIR}" "${WRAPPER_ROOT}"
WORK_DIR="$(mktemp -d "${WRAPPER_ROOT}/${PROFILE}.XXXXXX")"
TARGET_DIR="${WORK_DIR}/target"
LOCAL_TARGET_DIR="${WORK_DIR}/wasm-pack-target"
PREFLIGHT_LOG="${WORK_DIR}/rch-preflight-build.log"
BUILD_LOG="${WORK_DIR}/wasm-pack-build.log"

reject_rch_local_fallback_log() {
  local log_path="$1"
  if grep -Eq '^\[RCH\] local \(|falling back to local' "${log_path}" 2>/dev/null; then
    echo "error: rch local fallback detected; refusing local cargo execution" >&2
    echo "rch local fallback detected; refusing local cargo execution" > "${WORK_DIR}/rch_local_fallback.txt"
    exit 86
  fi
}

echo "==> Preflighting asupersync-browser-core (${PROFILE}) through RCH"
if RCH_REQUIRE_REMOTE=1 "${RCH_BIN}" exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo "${RCH_CARGO_ARGS[@]}" 2>&1 | tee "${PREFLIGHT_LOG}"; then
  reject_rch_local_fallback_log "${PREFLIGHT_LOG}"
else
  reject_rch_local_fallback_log "${PREFLIGHT_LOG}"
  exit 1
fi

echo "==> Packaging asupersync-browser-core (${PROFILE})"
if CARGO_TARGET_DIR="${LOCAL_TARGET_DIR}" wasm-pack build "${CRATE_DIR}" \
  --target web \
  --out-dir "${STAGING_DIR}" \
  --out-name asupersync \
  "${BUILD_ARGS[@]}" 2>&1 | tee "${BUILD_LOG}"; then
  :
else
  exit 1
fi

major="$(rg -No 'WASM_ABI_MAJOR_VERSION[^=]*= ([0-9_]+);' "${ABI_FILE}" -r '$1' -m1 | tr -d '_')"
minor="$(rg -No 'WASM_ABI_MINOR_VERSION[^=]*= ([0-9_]+);' "${ABI_FILE}" -r '$1' -m1 | tr -d '_')"
fingerprint="$(rg -No 'WASM_ABI_SIGNATURE_FINGERPRINT_V1[^=]*= ([0-9_]+);' "${ABI_FILE}" -r '$1' -m1 | tr -d '_')"

cat > "${STAGING_DIR}/abi-metadata.json" <<EOF
{
  "abi_version": {
    "major": ${major},
    "minor": ${minor}
  },
  "abi_signature_fingerprint_v1": ${fingerprint},
  "profile": "${PROFILE}"
}
EOF

js_map_present=false
if [[ -f "${STAGING_DIR}/${JS_MAP_FILE}" ]]; then
  js_map_present=true
fi

wasm_map_present=false
if [[ -f "${STAGING_DIR}/${WASM_MAP_FILE}" ]]; then
  wasm_map_present=true
fi

cat > "${STAGING_DIR}/debug-metadata.json" <<EOF
{
  "artifact_set": "asupersync-browser-core",
  "profile": "${PROFILE}",
  "abi_version": {
    "major": ${major},
    "minor": ${minor}
  },
  "abi_signature_fingerprint_v1": ${fingerprint},
  "symbols": [
    "runtime_create",
    "runtime_close",
    "scope_enter",
    "scope_close",
    "task_spawn",
    "task_join",
    "task_cancel",
    "fetch_request",
    "websocket_open",
    "websocket_send",
    "websocket_recv",
    "websocket_close",
    "websocket_cancel",
    "abi_version",
    "abi_fingerprint"
  ],
  "source_maps": {
    "js": {
      "file": "${JS_MAP_FILE}",
      "present": ${js_map_present}
    },
    "wasm": {
      "file": "${WASM_MAP_FILE}",
      "present": ${wasm_map_present}
    }
  }
}
EOF

echo "==> Syncing staged artifacts into packages/browser-core/"
for artifact in \
  asupersync.js \
  asupersync.d.ts \
  asupersync_bg.wasm \
  asupersync_bg.wasm.d.ts \
  abi-metadata.json \
  debug-metadata.json
do
  if [[ -f "${STAGING_DIR}/${artifact}" ]]; then
    cp "${STAGING_DIR}/${artifact}" "${PACKAGE_DIR}/${artifact}"
  else
    echo "warning: missing staged artifact ${artifact}" >&2
  fi
done

for optional_map in "${JS_MAP_FILE}" "${WASM_MAP_FILE}"; do
  if [[ -f "${STAGING_DIR}/${optional_map}" ]]; then
    cp "${STAGING_DIR}/${optional_map}" "${PACKAGE_DIR}/${optional_map}"
  fi
done

echo "==> Done"
echo "Staging: ${STAGING_DIR}"
echo "Package: ${PACKAGE_DIR}"
