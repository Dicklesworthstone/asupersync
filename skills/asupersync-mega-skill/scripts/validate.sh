#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VALIDATOR="$SCRIPT_DIR/../../sw/scripts/validate-skill.py"
FALLBACK_VALIDATOR="/home/ubuntu/.codex/skills/sw/scripts/validate-skill.py"

if [[ ! -f "$VALIDATOR" && -f "$FALLBACK_VALIDATOR" ]]; then
  VALIDATOR="$FALLBACK_VALIDATOR"
fi

if [[ ! -f "$VALIDATOR" ]]; then
  echo "error: validator not found: $VALIDATOR" >&2
  exit 1
fi

exec python3 "$VALIDATOR" "$SKILL_DIR" "$@"
