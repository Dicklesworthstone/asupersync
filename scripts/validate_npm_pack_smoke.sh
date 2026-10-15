#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ERRORS=0
WARNINGS=0

err() {
  echo "FAIL: $1" >&2
  ERRORS=$((ERRORS + 1))
}

warn() {
  echo "WARN: $1" >&2
  WARNINGS=$((WARNINGS + 1))
}

ok() {
  echo "  ok: $1"
}

check_json() {
  local file="$1"
  local query="$2"
  local label="$3"
  if ! python3 -c "import json,sys; d=json.load(open('$file')); exec('$query')" 2>/dev/null; then
    err "$label"
    return 1
  else
    ok "$label"
    return 0
  fi
}

echo "=== npm Pack/Install Smoke Validation ==="
echo ""

# ── Phase 0: Workspace Manager and Resolver Contract ─────────────────

echo "[Phase 0: Workspace Manager and Resolver Contract]"

ROOT_MANIFEST="${REPO_ROOT}/package.json"
BASE_TSCONFIG="${REPO_ROOT}/tsconfig.base.json"
WORKSPACE_YAML="${REPO_ROOT}/pnpm-workspace.yaml"
NPMRC="${REPO_ROOT}/.npmrc"

if [[ -f "$ROOT_MANIFEST" ]]; then
  ok "root package.json present"
else
  err "root package.json missing"
fi

if python3 -c "import json; d=json.load(open('$ROOT_MANIFEST')); assert d.get('packageManager','').startswith('pnpm@')" 2>/dev/null; then
  ok "root packageManager pins pnpm"
else
  err "root packageManager must pin pnpm"
fi

if python3 -c "import json; d=json.load(open('$ROOT_MANIFEST')); assert 'node' in d.get('engines',{}) and 'pnpm' in d.get('engines',{})" 2>/dev/null; then
  ok "root engines declare node and pnpm"
else
  err "root package.json must declare node and pnpm engines"
fi

if python3 -c "import json; d=json.load(open('$ROOT_MANIFEST')); s=d.get('scripts',{}); assert 'pnpm' in s.get('build:packages','') and 'pnpm' in s.get('build','') and 'pnpm' in s.get('typecheck','')" 2>/dev/null; then
  ok "workspace build scripts use pnpm"
else
  err "workspace build scripts must use pnpm"
fi

if [[ -f "$WORKSPACE_YAML" ]] && grep -q 'packages/\*' "$WORKSPACE_YAML"; then
  ok "pnpm-workspace.yaml enumerates packages/*"
else
  err "pnpm-workspace.yaml missing or incomplete"
fi

if [[ -f "$NPMRC" ]] && grep -q 'enable-pre-post-scripts=true' "$NPMRC"; then
  ok ".npmrc present with deterministic script policy"
else
  err ".npmrc missing deterministic script policy"
fi

if python3 -c "import json; d=json.load(open('$BASE_TSCONFIG')); c=d.get('compilerOptions',{}); assert c.get('moduleResolution')=='bundler' and c.get('module')=='ES2020'" 2>/dev/null; then
  ok "tsconfig.base.json pins moduleResolution=bundler and module=ES2020"
else
  err "tsconfig.base.json must pin moduleResolution=bundler and module=ES2020"
fi
echo ""

# ── Phase 1: Manifest Integrity ──────────────────────────────────────

echo "[Phase 1: Manifest Integrity]"

REQUIRED_PACKAGES=(
  "@asupersync/browser-core:browser-core"
  "@asupersync/browser:browser"
  "@asupersync/react:react"
  "@asupersync/next:next"
)

for entry in "${REQUIRED_PACKAGES[@]}"; do
  IFS=: read -r pkg_name pkg_dir <<< "$entry"
  manifest="${REPO_ROOT}/packages/${pkg_dir}/package.json"

  if [[ ! -f "$manifest" ]]; then
    err "${pkg_name}: package.json missing"
    continue
  fi

  # Name matches
  actual_name=$(python3 -c "import json; print(json.load(open('$manifest'))['name'])")
  if [[ "$actual_name" != "$pkg_name" ]]; then
    err "${pkg_name}: name mismatch (got ${actual_name})"
  else
    ok "${pkg_name}: name"
  fi

  # Required fields
  for field in version type main types exports files publishConfig sideEffects; do
    if python3 -c "import json; d=json.load(open('$manifest')); assert '$field' in d" 2>/dev/null; then
      ok "${pkg_name}: has ${field}"
    else
      # Some fields are optional for browser-core (no build scripts)
      if [[ "$field" == "scripts" && "$pkg_dir" == "browser-core" ]]; then
        continue
      fi
      err "${pkg_name}: missing field ${field}"
    fi
  done

  # ESM module type
  if python3 -c "import json; assert json.load(open('$manifest'))['type']=='module'" 2>/dev/null; then
    ok "${pkg_name}: ESM module"
  else
    err "${pkg_name}: not ESM module"
  fi

  # sideEffects: false
  if python3 -c "import json; assert json.load(open('$manifest'))['sideEffects']==False" 2>/dev/null; then
    ok "${pkg_name}: sideEffects=false"
  else
    err "${pkg_name}: sideEffects not false"
  fi

  # publishConfig.access = public
  if python3 -c "import json; assert json.load(open('$manifest'))['publishConfig']['access']=='public'" 2>/dev/null; then
    ok "${pkg_name}: public access"
  else
    err "${pkg_name}: publishConfig.access not public"
  fi

  # Exports map has root entry
  if python3 -c "import json; assert '.' in json.load(open('$manifest'))['exports']" 2>/dev/null; then
    ok "${pkg_name}: exports has root entry"
  else
    err "${pkg_name}: exports missing root entry"
  fi

  if python3 -c "import json; root=json.load(open('$manifest'))['exports']['.']; assert isinstance(root, dict) and 'types' in root and ('import' in root or 'default' in root)" 2>/dev/null; then
    ok "${pkg_name}: exports root carries types and import/default"
  else
    err "${pkg_name}: exports root must carry types and import/default"
  fi

  echo ""
done

# ── Phase 2: Dependency Graph ────────────────────────────────────────

echo "[Phase 2: Dependency Graph]"

# Check dependency exists (handles workspace:* protocol)
check_dep() {
  local pkg_path="$1"
  local dep_name="$2"
  local label="$3"
  if python3 -c "
import json
d=json.load(open('${pkg_path}'))
deps=dict(list(d.get('dependencies',{}).items()) + list(d.get('devDependencies',{}).items()))
assert '${dep_name}' in deps, f'missing ${dep_name}'
" 2>/dev/null; then
    ok "$label"
  else
    err "$label"
  fi
}

check_dep "${REPO_ROOT}/packages/browser/package.json" \
  "@asupersync/browser-core" \
  "@asupersync/browser -> @asupersync/browser-core"

check_dep "${REPO_ROOT}/packages/react/package.json" \
  "@asupersync/browser" \
  "@asupersync/react -> @asupersync/browser"

check_dep "${REPO_ROOT}/packages/next/package.json" \
  "@asupersync/browser" \
  "@asupersync/next -> @asupersync/browser"

# browser-core has no @asupersync deps
if python3 -c "
import json
d=json.load(open('${REPO_ROOT}/packages/browser-core/package.json'))
deps=d.get('dependencies',{})
asup=[k for k in deps if k.startswith('@asupersync/')]
assert len(asup)==0, f'browser-core depends on {asup}'
" 2>/dev/null; then
  ok "@asupersync/browser-core: no @asupersync dependencies"
else
  err "@asupersync/browser-core: has unexpected @asupersync dependencies"
fi
echo ""

# ── Phase 3: browser-core Artifact Readiness ─────────────────────────

echo "[Phase 3: browser-core Artifact Readiness]"

BC="${REPO_ROOT}/packages/browser-core"
ARTIFACTS=(
  "asupersync.js:JS entry"
  "asupersync.d.ts:TS declarations (wasm-bindgen)"
  "asupersync_bg.wasm:WASM binary"
  "abi-metadata.json:ABI metadata"
  "debug-metadata.json:Debug metadata"
)

bc_files=$(python3 -c "import json; print('\n'.join(json.load(open('${BC}/package.json'))['files']))")

for entry in "${ARTIFACTS[@]}"; do
  IFS=: read -r artifact label <<< "$entry"
  if echo "$bc_files" | grep -qF "$artifact"; then
    ok "files array includes ${artifact} (${label})"
  else
    err "files array missing ${artifact} (${label})"
  fi

  if [[ -f "${BC}/${artifact}" ]]; then
    ok "artifact present: ${artifact}"
  else
    warn "artifact not built yet: ${artifact} (run build:wasm first)"
  fi
done

while IFS= read -r rel; do
  [[ -n "$rel" ]] || continue
  if [[ -e "${BC}/${rel}" ]]; then
    ok "files array artifact exists on disk: ${rel}"
  else
    err "files array advertises missing artifact: ${rel}"
  fi
done <<< "$bc_files"
echo ""

# ── Phase 4: Higher-Level Package Source ──────────────────────────────

echo "[Phase 4: Higher-Level Package Source]"

for pkg_dir in browser react next; do
  src="${REPO_ROOT}/packages/${pkg_dir}/src/index.ts"
  if [[ -f "$src" ]]; then
    ok "@asupersync/${pkg_dir}: src/index.ts exists"
  else
    err "@asupersync/${pkg_dir}: src/index.ts missing"
  fi

  tsconfig="${REPO_ROOT}/packages/${pkg_dir}/tsconfig.json"
  if [[ -f "$tsconfig" ]]; then
    ok "@asupersync/${pkg_dir}: tsconfig.json exists"
  else
    err "@asupersync/${pkg_dir}: tsconfig.json missing"
  fi
done
echo ""

# ── Phase 5: Package Resolver Contract ───────────────────────────────

echo "[Phase 5: Package Resolver Contract]"

for pkg_dir in browser react next; do
  tsconfig="${REPO_ROOT}/packages/${pkg_dir}/tsconfig.json"

  if python3 -c "import json; d=json.load(open('$tsconfig')); assert d.get('extends')=='../../tsconfig.base.json'" 2>/dev/null; then
    ok "@asupersync/${pkg_dir}: extends root tsconfig baseline"
  else
    err "@asupersync/${pkg_dir}: must extend ../../tsconfig.base.json"
  fi

  if python3 -c "import json; d=json.load(open('$tsconfig')); assert 'moduleResolution' not in d.get('compilerOptions',{})" 2>/dev/null; then
    ok "@asupersync/${pkg_dir}: does not override moduleResolution"
  else
    err "@asupersync/${pkg_dir}: must not override moduleResolution"
  fi
done
echo ""

# ── Phase 6: npm pack Dry Run (if npm available) ─────────────────────

echo "[Phase 6: npm pack Dry Run]"

if command -v npm >/dev/null 2>&1; then
  for pkg_dir in browser-core browser react next; do
    pkg_path="${REPO_ROOT}/packages/${pkg_dir}"
    echo "  packing @asupersync/${pkg_dir}..."
    if npm pack --dry-run --pack-destination /tmp "${pkg_path}" >/dev/null 2>&1; then
      ok "@asupersync/${pkg_dir}: npm pack --dry-run succeeded"
    else
      err "@asupersync/${pkg_dir}: npm pack --dry-run failed"
    fi
  done
else
  echo "  skip: npm not installed (install to enable pack validation)"
fi
echo ""

# ── Phase 7: Optional Consumer Manager Presence ───────────────────────

echo "[Phase 7: Optional Consumer Manager Presence]"

for manager in npm pnpm yarn bun; do
  if command -v "$manager" >/dev/null 2>&1; then
    ok "${manager}: available for downstream compatibility checks"
  else
    warn "${manager}: not installed (consumer-matrix execution skipped)"
  fi
done
echo ""

# ── Summary ──────────────────────────────────────────────────────────

echo "=== Summary ==="
echo "  Errors:   ${ERRORS}"
echo "  Warnings: ${WARNINGS}"

if [[ "${ERRORS}" -gt 0 ]]; then
  echo ""
  echo "VALIDATION FAILED: ${ERRORS} error(s)" >&2
  exit 1
else
  echo ""
  echo "VALIDATION PASSED"
fi
