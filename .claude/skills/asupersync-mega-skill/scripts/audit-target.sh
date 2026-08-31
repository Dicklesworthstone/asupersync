#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ADOPTION_LANES="$SKILL_DIR/references/ADOPTION-LANES.md"
TOKIO_SOURCE_PATTERN='\b(tokio_util|tokio_stream|tokio_postgres|tokio_rustls|tower_http|tonic_web|hyper_util|async_std|sea_orm|mysql_async|tokio|hyper|axum|reqwest|tower|tonic|sqlx|mongodb|deadpool|bb8|quinn|h3|smol)\b'

if [[ $# -eq 1 && "$1" == "--self-test" ]]; then
  for rust_path in \
    'tokio_util::codec' \
    'tokio_stream::wrappers' \
    'tokio_postgres::Client' \
    'tokio_rustls::TlsConnector' \
    'tower_http::trace' \
    'tonic_web::GrpcWebLayer' \
    'hyper_util::client' \
    'sea_orm::Database' \
    'mongodb::Client' \
    'async_std::task'
  do
    if ! printf '%s\n' "$rust_path" | rg -q "$TOKIO_SOURCE_PATTERN"; then
      echo "error: source inventory misses Rust path: $rust_path" >&2
      exit 1
    fi
  done
  for non_match in \
    'my_tokio_helper::spawn' \
    'tokioish::runtime' \
    'hyperactive::Client' \
    'towering::Service'
  do
    if printf '%s\n' "$non_match" | rg -q "$TOKIO_SOURCE_PATTERN"; then
      echo "error: source inventory false-positive for: $non_match" >&2
      exit 1
    fi
  done
  echo "source inventory pattern self-test passed"
  exit 0
fi

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /path/to/rust-project | --self-test" >&2
  exit 1
fi

target="$1"
max_lines="${ASUPERSYNC_AUDIT_MAX_LINES:-200}"

if [[ ! "$max_lines" =~ ^[1-9][0-9]*$ ]]; then
  echo "error: ASUPERSYNC_AUDIT_MAX_LINES must be a positive integer" >&2
  exit 1
fi

if [[ ! -d "$target" ]]; then
  echo "error: target directory does not exist: $target" >&2
  exit 1
fi

echo "== Asupersync Migration Inventory =="
echo "target: $target"
echo
echo "note: this helper is for downstream migration inventory. It is not an"
echo "Asupersync repo proof lane; repo-internal Cargo proof still follows"
echo "live AGENTS.md / proof-lane manifests and RCH_REQUIRE_REMOTE=1."
echo "classification: heuristic_inventory_not_completeness_proof"
echo "The source scan can match comments and names; the optional Cargo probe"
echo "covers only the root manifest's locked normal-edge inverse-Tokio graph."
echo "Static match sections show at most $max_lines lines by default."
echo "Set ASUPERSYNC_AUDIT_FULL=1 for complete matching-source output."
echo

scan_matches() {
  local file_glob="$1"
  shift

  if [[ "${ASUPERSYNC_AUDIT_FULL:-0}" == "1" ]]; then
    local status
    if rg -n --glob '!**/target/**' --glob '!*.lock' --glob "$file_glob" "$@"; then
      return 0
    else
      status=$?
    fi
    if [[ "$status" -eq 1 ]]; then
      return 0
    fi
    return "$status"
  fi

  local -a pipeline_status
  set +e
  # awk consumes the complete stream, so an intentional display cap never
  # creates an early-closing-pipe error. Preserve real rg/awk failures instead
  # of laundering them into an apparently complete inventory.
  rg -n --glob '!**/target/**' --glob '!*.lock' --glob "$file_glob" "$@" \
    | awk -v limit="$max_lines" '
        NR <= limit { print }
        END {
          if (NR > limit) {
            printf "... %d additional matches omitted; set ASUPERSYNC_AUDIT_FULL=1 to show all ...\n", NR - limit
          }
        }
      '
  pipeline_status=("${PIPESTATUS[@]}")
  set -e

  if [[ "${pipeline_status[0]}" -gt 1 ]]; then
    return "${pipeline_status[0]}"
  fi
  if [[ "${pipeline_status[1]}" -ne 0 ]]; then
    return "${pipeline_status[1]}"
  fi
  return 0
}

scan_source() {
  scan_matches '*.rs' "$@"
}

echo "== Cargo manifests =="
find "$target" \
  -path '*/target' -prune -o \
  -path '*/.git' -prune -o \
  -name Cargo.toml -type f -print \
  | sort
echo

echo "== Direct source references to Tokio ecosystem =="
scan_source \
  "$TOKIO_SOURCE_PATTERN" \
  "$target"
echo

echo "== Dependency declarations in Cargo.toml files =="
scan_matches 'Cargo.toml' \
  '^[[:space:]]*"?(tokio|hyper|hyper-util|axum|reqwest|tower|tower-http|tonic|tonic-web|tokio-util|tokio-stream|tokio-postgres|tokio-rustls|sqlx|sea-orm|mongodb|mysql_async|deadpool|bb8|quinn|h3|async-std|smol)"?[[:space:]]*=|package[[:space:]]*=[[:space:]]*"(tokio|hyper|hyper-util|axum|reqwest|tower|tower-http|tonic|tonic-web|tokio-util|tokio-stream|tokio-postgres|tokio-rustls|sqlx|sea-orm|mongodb|mysql_async|deadpool|bb8|quinn|h3|async-std|smol)"' \
  "$target"
echo

if [[ -f "$target/Cargo.toml" ]]; then
  if [[ "${ASUPERSYNC_AUDIT_CARGO_TREE:-0}" == "1" ]]; then
    echo "== cargo tree -i tokio (explicit opt-in; may resolve/download) =="
    if [[ ! -f "$target/Cargo.lock" ]]; then
      echo "error: refusing Cargo graph probe without Cargo.lock" >&2
      exit 2
    fi
    (
      cd "$target"
      cargo tree --locked -e normal -i tokio
    )
    echo
  else
    echo "== Cargo graph probe skipped =="
    echo "Set ASUPERSYNC_AUDIT_CARGO_TREE=1 to run cargo tree --locked."
    echo "That opt-in can resolve/download dependencies and is not static inspection."
    echo
  fi
fi

echo "== Common migration hotspots =="
echo "-- spawn and task ownership --"
scan_source 'tokio::spawn|spawn_blocking|JoinSet|select!' "$target"
echo
echo "-- sync and channels --"
scan_source 'tokio::sync|mpsc::|oneshot::|broadcast::|watch::|Mutex|RwLock|Semaphore|Notify|Barrier|OnceCell' "$target"
echo
echo "-- time and cancellation --"
scan_source 'tokio::time|sleep\(|timeout\(|interval\(|CancellationToken|abort' "$target"
echo
echo "-- web, grpc, db --"
scan_source 'Router|axum|tonic|reqwest|sqlx|tokio-postgres|mysql_async|deadpool|bb8' "$target"
echo

echo "== Suggested next step =="
echo "Pick a lane with $ADOPTION_LANES"
