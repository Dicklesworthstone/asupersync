#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Cleaning package build artifacts"

# Clean staging area
rm -rf "${REPO_ROOT}/pkg/browser-core"

# Clean higher-level package dist dirs
for pkg in browser react next; do
  rm -rf "${REPO_ROOT}/packages/${pkg}/dist"
  rm -f "${REPO_ROOT}/packages/${pkg}/tsconfig.tsbuildinfo"
done

# Clean browser-core generated artifacts (leave package.json and tsconfig.json)
for artifact in \
  asupersync.js \
  asupersync.d.ts \
  asupersync.js.map \
  asupersync_bg.wasm \
  asupersync_bg.wasm.d.ts \
  asupersync_bg.wasm.map \
  abi-metadata.json \
  debug-metadata.json \
  tsconfig.tsbuildinfo
do
  rm -f "${REPO_ROOT}/packages/browser-core/${artifact}"
done

echo "==> Clean complete"
