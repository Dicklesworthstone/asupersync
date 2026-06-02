#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "exec" ]]; then
    echo "usage: $0 exec [--] <command> [args...]" >&2
    exit 64
fi

shift
if [[ "${1:-}" == "--" ]]; then
    shift
fi

if [[ "$#" -eq 0 ]]; then
    echo "rch-ci-fallback: missing command" >&2
    exit 64
fi

echo "[rch-ci-fallback] executing locally: $*" >&2
exec "$@"
