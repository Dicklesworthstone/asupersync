#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ERRORS=0

check_file() {
  local path="$1"
  local label="$2"
  if [[ ! -f "${path}" ]]; then
    echo "FAIL: missing ${label} (${path})" >&2
    ERRORS=$((ERRORS + 1))
  else
    echo "  ok: ${label}"
  fi
}

check_json_key() {
  local path="$1"
  local key="$2"
  local label="$3"
  if ! python3 -c "import json,sys; d=json.load(open('${path}')); assert ${key} in d" 2>/dev/null; then
    echo "FAIL: ${label} — key ${key} missing in ${path}" >&2
    ERRORS=$((ERRORS + 1))
  fi
}

echo "=== Package Build Validation ==="
echo ""

# 1. browser-core artifacts
echo "[browser-core]"
BC="${REPO_ROOT}/packages/browser-core"
check_file "${BC}/asupersync.js"      "JS entry"
check_file "${BC}/asupersync.d.ts"    "TS declarations"
check_file "${BC}/asupersync_bg.wasm" "WASM binary"
check_file "${BC}/abi-metadata.json"  "ABI metadata"
check_file "${BC}/debug-metadata.json" "Debug metadata"
check_file "${BC}/package.json"       "package.json"

if [[ -f "${BC}/abi-metadata.json" ]]; then
  check_json_key "${BC}/abi-metadata.json" "'abi_version'" "ABI version key"
  check_json_key "${BC}/abi-metadata.json" "'abi_signature_fingerprint_v1'" "ABI fingerprint key"
fi
echo ""

# 2. Higher-level packages
for pkg in browser react next; do
  echo "[@asupersync/${pkg}]"
  PKG="${REPO_ROOT}/packages/${pkg}"
  check_file "${PKG}/package.json"    "package.json"
  check_file "${PKG}/src/index.ts"    "source entry"
  check_file "${PKG}/tsconfig.json"   "tsconfig.json"

  # dist is only present after build
  if [[ -d "${PKG}/dist" ]]; then
    check_file "${PKG}/dist/index.js"   "compiled JS"
    check_file "${PKG}/dist/index.d.ts" "compiled declarations"
  else
    echo "  skip: dist/ not built yet"
  fi
  echo ""
done

# 3. Workspace config
echo "[workspace]"
check_file "${REPO_ROOT}/package.json"        "root package.json"
check_file "${REPO_ROOT}/pnpm-workspace.yaml" "pnpm workspace config"
check_file "${REPO_ROOT}/tsconfig.base.json"  "shared tsconfig"
echo ""

# 4. Dependency graph validation
echo "[dependency graph]"
for pkg in browser react next; do
  PKG_JSON="${REPO_ROOT}/packages/${pkg}/package.json"
  if python3 -c "
import json, sys
d = json.load(open('${PKG_JSON}'))
deps = d.get('dependencies', {})
exp = d.get('exports', {})
has_type = d.get('type') == 'module'
has_main = 'main' in d
has_types = 'types' in d
if not has_type: sys.exit(1)
if not has_main: sys.exit(1)
if not has_types: sys.exit(1)
" 2>/dev/null; then
    echo "  ok: @asupersync/${pkg} has type/main/types fields"
  else
    echo "FAIL: @asupersync/${pkg} missing required package.json fields" >&2
    ERRORS=$((ERRORS + 1))
  fi
done
echo ""

# Summary
if [[ "${ERRORS}" -gt 0 ]]; then
  echo "VALIDATION FAILED: ${ERRORS} error(s)" >&2
  exit 1
else
  echo "VALIDATION PASSED"
fi
