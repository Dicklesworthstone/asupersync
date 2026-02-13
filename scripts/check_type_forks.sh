#!/usr/bin/env bash
# check_type_forks.sh — Enforce franken_kernel type uniqueness (bd-1usdh.3).
#
# Scans all Rust source files for competing definitions of canonical types
# that must only be defined in franken_kernel. Exits non-zero if forks found.
#
# Usage: scripts/check_type_forks.sh [--json]
#
# Exit codes:
#   0 — no forks detected
#   1 — type forks detected
#   2 — usage error

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Canonical types that MUST only be defined in franken_kernel.
CANONICAL_TYPES=(
    "TraceId"
    "DecisionId"
    "PolicyId"
    "SchemaVersion"
    "Budget"
    "NoCaps"
)

# Also check Cx but it needs special handling (common word in other contexts).
CX_PATTERN="^pub struct Cx"

# The one crate allowed to define these types.
ALLOWED_CRATE="franken_kernel"

JSON_MODE=false
if [[ "${1:-}" == "--json" ]]; then
    JSON_MODE=true
fi

fork_count=0
crates_scanned=0
forks=()

# Find all Rust source files, excluding franken_kernel and target dirs.
while IFS= read -r src_file; do
    # Determine which crate this file belongs to.
    rel_path="${src_file#"$REPO_ROOT/"}"
    crate_dir="${rel_path%%/*}"

    # Skip the allowed crate.
    if [[ "$crate_dir" == "$ALLOWED_CRATE" ]]; then
        continue
    fi

    # Skip target directories and hidden directories.
    if [[ "$rel_path" == target/* ]] || [[ "$rel_path" == .* ]]; then
        continue
    fi

    crates_scanned=$((crates_scanned + 1))

    # Check for struct/enum/type alias definitions of canonical types.
    for type_name in "${CANONICAL_TYPES[@]}"; do
        # Match: pub struct TypeName, struct TypeName, pub enum TypeName,
        #        pub type TypeName, type TypeName
        pattern="^[[:space:]]*(pub[[:space:]]+)?(struct|enum|type)[[:space:]]+${type_name}[^a-zA-Z0-9_]"

        if grep -nE "$pattern" "$src_file" 2>/dev/null | grep -v "^[[:space:]]*//" | grep -v "^[[:space:]]*\*" > /dev/null; then
            line_info=$(grep -nE "$pattern" "$src_file" 2>/dev/null | grep -v "^[[:space:]]*//" | grep -v "^[[:space:]]*\*" | head -1)
            line_num="${line_info%%:*}"
            fork_count=$((fork_count + 1))
            forks+=("${rel_path}:${line_num}:${type_name}")

            if [[ "$JSON_MODE" == false ]]; then
                echo "ERROR: type fork detected — ${type_name} defined in ${rel_path}:${line_num}"
                echo "       Should use: use franken_kernel::${type_name};"
            fi
        fi
    done

    # Special check for Cx.
    if grep -nE "$CX_PATTERN" "$src_file" 2>/dev/null | grep -v "^[[:space:]]*//" > /dev/null; then
        line_info=$(grep -nE "$CX_PATTERN" "$src_file" 2>/dev/null | grep -v "^[[:space:]]*//" | head -1)
        line_num="${line_info%%:*}"
        fork_count=$((fork_count + 1))
        forks+=("${rel_path}:${line_num}:Cx")

        if [[ "$JSON_MODE" == false ]]; then
            echo "ERROR: type fork detected — Cx defined in ${rel_path}:${line_num}"
            echo "       Should use: use franken_kernel::Cx;"
        fi
    fi
done < <(find "$REPO_ROOT" -name "*.rs" -not -path "*/target/*" -not -path "*/.git/*" -type f 2>/dev/null)

if [[ "$JSON_MODE" == true ]]; then
    # Output structured JSON.
    forks_json="["
    for i in "${!forks[@]}"; do
        IFS=: read -r file line type_name <<< "${forks[$i]}"
        if [[ $i -gt 0 ]]; then forks_json+=","; fi
        forks_json+="{\"file\":\"${file}\",\"line\":${line},\"type\":\"${type_name}\"}"
    done
    forks_json+="]"

    cat <<EOJSON
{
  "type_fork_count": ${fork_count},
  "crates_scanned": ${crates_scanned},
  "forks": ${forks_json},
  "status": "$([ "$fork_count" -eq 0 ] && echo "pass" || echo "fail")"
}
EOJSON
else
    echo ""
    if [[ "$fork_count" -eq 0 ]]; then
        echo "INFO: type uniqueness check passed — scanned ${crates_scanned} files, found 0 forks."
    else
        echo "FAIL: found ${fork_count} type fork(s) across ${crates_scanned} files."
        echo "      All canonical types must be imported from franken_kernel."
        exit 1
    fi
fi
