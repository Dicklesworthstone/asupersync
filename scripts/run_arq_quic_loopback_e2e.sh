#!/usr/bin/env bash
# Run a retained, self-validating ATP metadata-fidelity loopback artifact pack.
#
# Normal mode builds or uses the standalone `atp` binary, runs a real receiver
# plus sender over the selected RQ or QUIC transport, and writes:
#   - events.ndjson: ordered script-stage events
#   - summary.json: machine-readable transfer summary
#   - sender.json / receiver.json: raw atp JSON reports
#   - source.integrity.before.json / source.integrity.after.json: exact
#     transport manifest roots bracketing the live send
#   - received.integrity.json: exact roots recomputed from committed output
#   - sender.time.txt: /usr/bin/time -v sender metrics
#   - receiver.time.txt: /usr/bin/time -v receiver metrics
#
# Offline mode (`--from-output DIR`) validates a retained output directory
# without rerunning the transfer. This is the negative-test hook for corrupted
# artifacts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_DIR="${ARQ_QUIC_OUTPUT_DIR:-$PROJECT_ROOT/artifacts/arq_quic_e2e/$TIMESTAMP}"
ATP_BIN="${ATP_BIN:-}"
ATP_TRANSPORT="${ATP_TRANSPORT:-quic}"
AUTH_KEY_HEX="${ARQ_QUIC_AUTH_KEY_HEX:-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}"
PAYLOAD_BYTES="${ARQ_QUIC_PAYLOAD_BYTES:-8192}"
SERVER_NAME="${ARQ_QUIC_SERVER_NAME:-localhost}"
FROM_OUTPUT=""

usage() {
    cat >&2 <<USAGE
Usage:
  $0 [--output-dir DIR]
  $0 --from-output DIR

Environment:
  ATP_BIN                  Existing atp binary. If unset, cargo builds one.
  ATP_TRANSPORT            Transport to exercise: quic (default) or rq.
  CARGO_TARGET_DIR         Target dir for the optional cargo build.
  ARQ_QUIC_OUTPUT_DIR      Artifact output dir (default artifacts/arq_quic_e2e/<UTC timestamp>).
  ARQ_QUIC_PAYLOAD_BYTES   Deterministic payload size (default 8192).
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            OUTPUT_DIR="${2:?--output-dir requires a path}"
            shift 2
            ;;
        --from-output)
            FROM_OUTPUT="${2:?--from-output requires a path}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

case "$ATP_TRANSPORT" in
    quic|rq) ;;
    *)
        echo "unsupported ATP_TRANSPORT: $ATP_TRANSPORT (expected quic or rq)" >&2
        exit 2
        ;;
esac

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required command: $1" >&2
        exit 127
    }
}

require_cmd jq
require_cmd python3
if [[ -z "$FROM_OUTPUT" && "$ATP_TRANSPORT" == "quic" ]]; then
    require_cmd openssl
fi
require_cmd sha256sum
require_cmd awk
require_cmd cmp
require_cmd find
require_cmd grep
require_cmd mkfifo
require_cmd readlink
require_cmd sed
require_cmd stat
require_cmd touch

emit_event() {
    local stage="$1"
    local status="$2"
    local message="$3"
    local details="${4:-}"
    mkdir -p "$OUTPUT_DIR"
    jq -cn \
        --arg schema_version "arq-quic-e2e-event-v1" \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg stage "$stage" \
        --arg status "$status" \
        --arg message "$message" \
        --arg details "$details" \
        '($details | fromjson? // {}) as $details_obj |
        {
          schema_version:$schema_version,
          ts:$ts,
          stage:$stage,
          status:$status,
          message:$message
        } + (if $details_obj == {} then {} else {details:$details_obj} end)' \
        >> "$OUTPUT_DIR/events.ndjson"
}

emit_summary_event() {
    mkdir -p "$OUTPUT_DIR"
    jq -c \
        --arg schema_version "arq-quic-e2e-event-v1" \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
          schema_version:$schema_version,
          ts:$ts,
          stage:"summary",
          status:"passed",
          message:"captured final transfer metrics and counter availability",
          details:{
            bytes_sent:.bytes_sent,
            bytes_received:.bytes_received,
            sha256_match:.sha256_match,
            metadata_fidelity:.metadata_fidelity,
            integrity_roots:.integrity_roots,
            metrics:.metrics,
            transport_counters:.transport_counters
          }
        }' "$OUTPUT_DIR/summary.json" \
        >> "$OUTPUT_DIR/events.ndjson"
}

extract_max_rss_kb() {
    local time_file="$1"
    local value
    value="$(
        awk -F: '/Maximum resident set size/ { gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2 }' "$time_file" \
            | tail -n1
    )"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$value"
    else
        printf '0\n'
    fi
}

extract_elapsed_raw() {
    local time_file="$1"
    sed -n 's/^[[:space:]]*Elapsed (wall clock) time (h:mm:ss or m:ss):[[:space:]]*//p' "$time_file" \
        | tail -n1
}

elapsed_to_seconds() {
    local raw="$1"
    python3 - "$raw" <<'PY'
import sys

raw = sys.argv[1].strip()
if not raw:
    print("0")
    raise SystemExit

parts = raw.split(":")
try:
    if len(parts) == 3:
        seconds = int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
    elif len(parts) == 2:
        seconds = int(parts[0]) * 60 + float(parts[1])
    else:
        seconds = float(parts[0])
except ValueError:
    seconds = 0.0

if seconds < 0:
    seconds = 0.0
print(f"{seconds:.6f}")
PY
}

verify_sparse_file() {
    local source="$1"
    local received="$2"
    local label="$3"
    local source_size source_blocks received_size received_blocks

    cmp -s "$source" "$received" || {
        echo "$label content differs" >&2
        return 1
    }
    source_size="$(stat -c '%s' "$source")"
    source_blocks="$(stat -c '%b' "$source")"
    received_size="$(stat -c '%s' "$received")"
    received_blocks="$(stat -c '%b' "$received")"
    (( source_blocks * 512 < source_size / 2 )) || {
        echo "$label source fixture is not sparse" >&2
        return 1
    }
    (( received_blocks * 512 < received_size / 2 )) || {
        echo "$label received file lost sparse allocation" >&2
        return 1
    }
}

verify_metadata_fidelity() {
    local source_root="$1"
    local received_root="$2"
    local xattr_supported="$3"

    cmp -s "$source_root/payload.bin" "$received_root/payload.bin" || {
        echo "metadata payload differs" >&2
        return 1
    }
    [[ "$(stat -c '%a' "$received_root/payload.bin")" == "640" ]] || {
        echo "metadata payload mode differs" >&2
        return 1
    }
    [[ "$(stat -c '%Y' "$received_root/payload.bin")" == "1600000123" ]] || {
        echo "metadata payload mtime differs" >&2
        return 1
    }
    [[ -d "$received_root/empty-dir" ]] || {
        echo "empty directory missing" >&2
        return 1
    }
    [[ "$(stat -c '%a' "$received_root/empty-dir")" == "750" ]] || {
        echo "empty directory mode differs" >&2
        return 1
    }
    [[ -z "$(find "$received_root/empty-dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
        echo "empty directory is not empty" >&2
        return 1
    }
    [[ -L "$received_root/relative-link" ]] || {
        echo "relative symlink missing" >&2
        return 1
    }
    [[ "$(readlink "$received_root/relative-link")" == "payload.bin" ]] || {
        echo "relative symlink target differs" >&2
        return 1
    }
    [[ -L "$received_root/dangling-link" ]] || {
        echo "dangling symlink missing" >&2
        return 1
    }
    [[ "$(readlink "$received_root/dangling-link")" == "missing-target" ]] || {
        echo "dangling symlink target differs" >&2
        return 1
    }
    [[ ! -e "$received_root/dangling-link" ]] || {
        echo "dangling symlink unexpectedly resolves" >&2
        return 1
    }
    cmp -s "$source_root/hardlink-a.txt" "$received_root/hardlink-a.txt" || {
        echo "hardlink payload differs" >&2
        return 1
    }
    cmp -s "$received_root/hardlink-a.txt" "$received_root/hardlink-b.txt" || {
        echo "hardlink contents differ" >&2
        return 1
    }
    [[ "$(stat -c '%d:%i' "$received_root/hardlink-a.txt")" == "$(stat -c '%d:%i' "$received_root/hardlink-b.txt")" ]] || {
        echo "hardlink inode identity differs" >&2
        return 1
    }
    [[ -p "$received_root/events.fifo" ]] || {
        echo "FIFO was not recreated" >&2
        return 1
    }
    [[ "$(stat -c '%a' "$received_root/events.fifo")" == "620" ]] || {
        echo "FIFO mode differs" >&2
        return 1
    }
    [[ "$(stat -c '%Y' "$received_root/events.fifo")" == "1600000789" ]] || {
        echo "FIFO mtime differs" >&2
        return 1
    }
    verify_sparse_file "$source_root/packed-sparse.bin" "$received_root/packed-sparse.bin" "packed sparse file" || return 1
    verify_sparse_file "$source_root/regular-sparse.bin" "$received_root/regular-sparse.bin" "regular sparse file" || return 1
    if [[ "$xattr_supported" == "true" ]]; then
        if ! python3 - "$received_root/payload.bin" <<'PY'
import os
import sys

value = os.getxattr(sys.argv[1], "user.asupersync.quic-metadata-e2e")
if value != b"metadata-value\0with-binary":
    raise SystemExit("received xattr differs")
PY
        then
            echo "received xattr differs" >&2
            return 1
        fi
    fi
    [[ -z "$(find "$(dirname "$received_root")" -maxdepth 1 -name '.atp-*-staging-*' -print -quit)" ]] || {
        echo "ATP staging residue remains" >&2
        return 1
    }
}

capture_transport_integrity() {
    local root="$1"
    local output="$2"

    "$ATP_BIN" send "$root" 127.0.0.1:1 \
        --dry-run \
        --transport "$ATP_TRANSPORT" \
        --preserve-xattrs \
        --allow-special-files \
        --rq-auth-key-hex "$AUTH_KEY_HEX" \
        > "$output"
}

validate_output() {
    local dir="$1"
    local summary="$dir/summary.json"
    local events="$dir/events.ndjson"
    local source_before="$dir/source.integrity.before.json"
    local source_after="$dir/source.integrity.after.json"
    local received_integrity="$dir/received.integrity.json"
    local summary_schema

    [[ -s "$summary" ]] || { echo "missing summary.json in $dir" >&2; return 1; }
    [[ -s "$events" ]] || { echo "missing events.ndjson in $dir" >&2; return 1; }
    summary_schema="$(jq -r '.schema_version // empty' "$summary")"
    case "$summary_schema" in
        arq-quic-loopback-e2e-summary-v1) ;;
        arq-quic-loopback-e2e-summary-v2)
            [[ -s "$source_before" ]] || { echo "missing source.integrity.before.json in $dir" >&2; return 1; }
            [[ -s "$source_after" ]] || { echo "missing source.integrity.after.json in $dir" >&2; return 1; }
            [[ -s "$received_integrity" ]] || { echo "missing received.integrity.json in $dir" >&2; return 1; }
            ;;
        *)
            echo "unsupported summary schema in $summary" >&2
            return 1
            ;;
    esac

    jq -e '
      (.schema_version == "arq-quic-loopback-e2e-summary-v1" or
        .schema_version == "arq-quic-loopback-e2e-summary-v2") and
      .status == "passed" and
      (.transport == "quic" or .transport == "rq") and
      .sha256_match == true and
      (.bytes_sent | type == "number") and
      (.bytes_received | type == "number") and
      .bytes_sent == .bytes_received and
      .bytes_sent > 0 and
      .sender.event == "atp_send" and
      .sender.transport == .transport and
      .sender.committed == true and
      .receiver.event == "atp_receive" and
      .receiver.transport == .transport and
      .receiver.committed == true and
      .metadata_fidelity.status == "passed" and
      .metadata_fidelity.entries_verified == 9 and
      .metadata_fidelity.payload_bytes_match == true and
      .metadata_fidelity.payload_mode == "640" and
      .metadata_fidelity.payload_mtime_epoch == 1600000123 and
      (.metadata_fidelity.xattr_supported | type == "boolean") and
      (.metadata_fidelity.xattr_match | type == "boolean") and
      .metadata_fidelity.xattr_match == .metadata_fidelity.xattr_supported and
      .metadata_fidelity.empty_directory == true and
      .metadata_fidelity.empty_directory_mode == "750" and
      .metadata_fidelity.relative_symlink_target == "payload.bin" and
      .metadata_fidelity.dangling_symlink_target == "missing-target" and
      .metadata_fidelity.hardlink_identity == true and
      .metadata_fidelity.fifo == true and
      .metadata_fidelity.fifo_mode == "620" and
      .metadata_fidelity.packed_sparse_content == true and
      .metadata_fidelity.packed_sparse_allocation == true and
      .metadata_fidelity.regular_sparse_content == true and
      .metadata_fidelity.regular_sparse_allocation == true and
      .metadata_fidelity.staging_clean == true and
      (.metadata_fidelity.no_claim | type == "string" and length > 0) and
      (if .schema_version == "arq-quic-loopback-e2e-summary-v2" then
        .sender.merkle_ok == true and
        (.metadata_fidelity.entries | length) == 9 and
        ([.metadata_fidelity.entries[].rel_path] | unique | length) == 9 and
        all(.metadata_fidelity.entries[];
          .status == "passed" and (.checks | type == "object")) and
        ([.metadata_fidelity.entries[].rel_path] | sort) ==
          (["payload.bin","empty-dir","relative-link","dangling-link","hardlink-a.txt","hardlink-b.txt","events.fifo","packed-sparse.bin","regular-sparse.bin"] | sort) and
        .metadata_fidelity.fifo_mtime_epoch == 1600000789 and
        (.integrity_roots as $r |
          $r.status == "passed" and
          $r.transport == .transport and
          $r.source_before.transport == .transport and
          $r.source_after.transport == .transport and
          $r.received.transport == .transport and
          ($r.source_before.flat_merkle_root_hex | test("^[0-9a-f]{64}$")) and
          ($r.source_before.metadata_commitment_hex | test("^[0-9a-f]{64}$")) and
          ($r.source_after.flat_merkle_root_hex | test("^[0-9a-f]{64}$")) and
          ($r.source_after.metadata_commitment_hex | test("^[0-9a-f]{64}$")) and
          ($r.received.flat_merkle_root_hex | test("^[0-9a-f]{64}$")) and
          ($r.received.metadata_commitment_hex | test("^[0-9a-f]{64}$")) and
          $r.source_before.flat_merkle_root_hex == $r.source_after.flat_merkle_root_hex and
          $r.source_before.flat_merkle_root_hex == $r.received.flat_merkle_root_hex and
          $r.source_before.metadata_commitment_hex == $r.source_after.metadata_commitment_hex and
          $r.source_before.metadata_commitment_hex == $r.received.metadata_commitment_hex and
          .sender.merkle_root == $r.source_before.flat_merkle_root_hex and
          $r.source_stable == true and
          $r.destination_match == true and
          $r.live_sender_merkle_match == true and
          $r.receiver_merkle_commit_gate_observed == true and
          $r.metadata_commitment_match == true and
          ($r.no_claim | type == "string" and length > 0)) and
        (.artifacts.source_integrity_before | type == "string" and length > 0) and
        (.artifacts.source_integrity_after | type == "string" and length > 0) and
        (.artifacts.received_integrity | type == "string" and length > 0)
      else true end) and
      (.metrics.sender_max_rss_kb | type == "number") and
      (.metrics.receiver_max_rss_kb | type == "number") and
      (.metrics.peak_max_rss_kb | type == "number") and
      .metrics.peak_max_rss_kb >= .metrics.sender_max_rss_kb and
      .metrics.peak_max_rss_kb >= .metrics.receiver_max_rss_kb and
      (.metrics.sender_elapsed_seconds | type == "number" and . >= 0) and
      (.metrics.receiver_elapsed_seconds | type == "number" and . >= 0) and
      (.metrics.transfer_elapsed_seconds | type == "number" and . >= 0) and
      (.metrics.goodput_bytes_per_second | type == "number" and . >= 0) and
      (.metrics.goodput_bits_per_second | type == "number" and . >= 0) and
      (.metrics.feedback_rounds_total | type == "number" and . >= 0) and
      (if .transport == "quic" then
        (.metrics.decode_time_per_block_micros | type == "number" and . >= 0)
      else
        .metrics.decode_time_per_block_micros == null
      end) and
      (.transport_counters as $c |
        $c.symbols_sent_available == true and
        ($c.symbols_sent | type == "number" and . >= 0) and
        $c.symbols_accepted_available == true and
        ($c.symbols_accepted | type == "number" and . >= 0) and
        ((($c.symbols_sent == 0) and ($c.symbols_accepted == 0)) or
          (($c.symbols_sent > 0) and ($c.symbols_accepted > 0) and
            ($c.symbols_accepted <= $c.symbols_sent))) and
        (if $c.symbols_sent > 0 then
          .metrics.symbol_loss_rate_available == true and
          .metrics.symbol_loss_rate_mode == "observed-raptorq-symbols" and
          (.metrics.symbol_loss_rate | type == "number" and . >= 0 and . <= 1) and
          .metrics.symbol_loss_rate == (($c.symbols_sent - $c.symbols_accepted) / $c.symbols_sent)
        else
          .metrics.symbol_loss_rate_available == false and
          .metrics.symbol_loss_rate_mode == "not-applicable-no-symbols" and
          .metrics.symbol_loss_rate == null
        end)) and
      .transport_counters.feedback_rounds_available == true and
      (.transport_counters.feedback_rounds_sender | type == "number" and . >= 0) and
      (.transport_counters.feedback_rounds_receiver | type == "number" and . >= 0) and
      (if .transport == "quic" then
        .transport_counters.decode_count_available == true and
        (.transport_counters.decode_count | type == "number" and . >= 0) and
        .transport_counters.decode_micros_available == true and
        (.transport_counters.decode_micros | type == "number" and . >= 0)
      else
        .transport_counters.decode_count_available == false and
        .transport_counters.decode_count == null and
        .transport_counters.decode_micros_available == false and
        .transport_counters.decode_micros == null
      end) and
      (.transport_counters.no_claim | type == "string") and
      (.artifacts.events_ndjson | type == "string")
    ' "$summary" >/dev/null

    if [[ "$summary_schema" == "arq-quic-loopback-e2e-summary-v2" ]]; then
        jq -e -n \
            --slurpfile summary "$summary" \
            --slurpfile before "$source_before" \
            --slurpfile after "$source_after" \
            --slurpfile received "$received_integrity" '
          ($summary | length) == 1 and
          ($before | length) == 1 and
          ($after | length) == 1 and
          ($received | length) == 1 and
          $before[0].transport_integrity == $summary[0].integrity_roots.source_before and
          $after[0].transport_integrity == $summary[0].integrity_roots.source_after and
          $received[0].transport_integrity == $summary[0].integrity_roots.received
        ' >/dev/null
    fi

    jq -e -s \
        --arg summary_schema "$summary_schema" \
        --slurpfile summary "$summary" '
      length >= 6 and
      all(.[]; .schema_version == "arq-quic-e2e-event-v1" and
        (.stage | type == "string" and length > 0) and
        (.status as $s | ["started","passed","failed"] | index($s) != null)) and
      any(.[]; .stage == "receiver_ready" and .status == "passed") and
      any(.[]; .stage == "sender_transfer" and .status == "passed") and
      any(.[]; .stage == "sha256_verify" and .status == "passed") and
      any(.[]; .stage == "metadata_fidelity" and .status == "passed" and .details.status == "passed") and
      (if $summary_schema == "arq-quic-loopback-e2e-summary-v2" then
        ([.[] | select(.stage == "metadata_entry" and .status == "passed") | .details] | sort_by(.rel_path)) ==
          ($summary[0].metadata_fidelity.entries | sort_by(.rel_path)) and
        all(.[] | select(.stage == "metadata_entry" and .status == "passed");
          .details.status == "passed" and (.details.checks | type == "object")) and
        ([.[] | select(.stage == "integrity_roots" and .status == "passed")] | length) == 1 and
        ([.[] | select(.stage == "integrity_roots" and .status == "passed")][0].details ==
          $summary[0].integrity_roots)
      else true end) and
      any(.[]; .stage == "summary" and .status == "passed" and (.details.transport_counters.no_claim | type == "string"))
    ' "$events" >/dev/null
}

if [[ -n "$FROM_OUTPUT" ]]; then
    validate_output "$FROM_OUTPUT"
    echo "validated ARQ/QUIC loopback output: $FROM_OUTPUT"
    exit 0
fi

mkdir -p "$OUTPUT_DIR/source" "$OUTPUT_DIR/dest" "$OUTPUT_DIR/tls"
: > "$OUTPUT_DIR/events.ndjson"
emit_event "setup" "started" "preparing retained loopback artifacts"

if [[ -z "$ATP_BIN" ]]; then
    emit_event "build_atp" "started" "building standalone atp binary with atp-cli,tls"
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_arq_quic_loopback_atp}"
    export CARGO_TARGET_DIR
    # Routed through rch with an explicit target dir (AGENTS.md). rch retrieves
    # the target directory, so $CARGO_TARGET_DIR/debug/atp is present locally
    # afterwards -- the same build-then-use-the-local-path pattern AGENTS.md
    # documents for the ATP bench binary.
    (
        cd "$PROJECT_ROOT"
        RCH_REQUIRE_REMOTE=1 "${RCH_BIN:-rch}" exec -- env CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
            cargo build --locked -j 1 -p asupersync --bin atp --features atp-cli,tls
    )
    ATP_BIN="$CARGO_TARGET_DIR/debug/atp"
fi
[[ -x "$ATP_BIN" ]] || { emit_event "build_atp" "failed" "atp binary missing or not executable"; echo "atp binary missing: $ATP_BIN" >&2; exit 1; }
emit_event "build_atp" "passed" "using atp binary $ATP_BIN"

if [[ "$ATP_TRANSPORT" == "quic" ]]; then
    "$SCRIPT_DIR/atp_bench_gen_certs.sh" "$OUTPUT_DIR/tls" 127.0.0.1 > "$OUTPUT_DIR/certs.log" 2>&1
fi

SOURCE_TREE="$OUTPUT_DIR/source/metadata-tree"
PAYLOAD="$SOURCE_TREE/payload.bin"
PACKED_SPARSE="$SOURCE_TREE/packed-sparse.bin"
REGULAR_SPARSE="$SOURCE_TREE/regular-sparse.bin"
mkdir -p "$SOURCE_TREE/empty-dir"
SOURCE_XATTR_SUPPORTED="$(python3 - "$PAYLOAD" "$PAYLOAD_BYTES" "$PACKED_SPARSE" "$REGULAR_SPARSE" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
size = int(sys.argv[2])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_bytes(bytes((i * 17) % 251 for i in range(size)))
os.chmod(path, 0o640)
os.utime(path, (1_600_000_123, 1_600_000_123))

for sparse_path, sparse_size, marker in [
    (pathlib.Path(sys.argv[3]), 512 * 1024, b"packed-sparse"),
    (pathlib.Path(sys.argv[4]), 2 * 1024 * 1024, b"regular-sparse"),
]:
    with sparse_path.open("wb") as handle:
        handle.write(marker)
        handle.seek(sparse_size - len(marker))
        handle.write(marker)

try:
    os.setxattr(path, "user.asupersync.quic-metadata-e2e", b"metadata-value\0with-binary")
except OSError:
    print("false")
else:
    print("true")
PY
)"
chmod 750 "$SOURCE_TREE/empty-dir"
ln -s "payload.bin" "$SOURCE_TREE/relative-link"
ln -s "missing-target" "$SOURCE_TREE/dangling-link"
printf 'shared hardlink content\n' > "$SOURCE_TREE/hardlink-a.txt"
ln "$SOURCE_TREE/hardlink-a.txt" "$SOURCE_TREE/hardlink-b.txt"
mkfifo "$SOURCE_TREE/events.fifo"
chmod 620 "$SOURCE_TREE/events.fifo"
touch -m -d @1600000789 "$SOURCE_TREE/events.fifo"
verify_sparse_file "$PACKED_SPARSE" "$PACKED_SPARSE" "packed sparse source fixture"
verify_sparse_file "$REGULAR_SPARSE" "$REGULAR_SPARSE" "regular sparse source fixture"
emit_event "payload" "passed" "wrote heterogeneous metadata-fidelity tree" "$(jq -cn \
    --argjson xattr_supported "$SOURCE_XATTR_SUPPORTED" \
    '{entries:9,xattr_supported:$xattr_supported,packed_sparse_bytes:524288,regular_sparse_bytes:2097152}')"

SOURCE_INTEGRITY_BEFORE="$OUTPUT_DIR/source.integrity.before.json"
SOURCE_INTEGRITY_AFTER="$OUTPUT_DIR/source.integrity.after.json"
RECEIVED_INTEGRITY="$OUTPUT_DIR/received.integrity.json"
if capture_transport_integrity "$SOURCE_TREE" "$SOURCE_INTEGRITY_BEFORE"; then
    emit_event "source_integrity_before" "passed" "captured exact $ATP_TRANSPORT source roots before transfer"
else
    emit_event "source_integrity_before" "failed" "failed to capture source roots before transfer"
    exit 1
fi

RECEIVER_JSON="$OUTPUT_DIR/receiver.json"
RECEIVER_STDERR="$OUTPUT_DIR/receiver.stderr"
RECEIVER_TIME="$OUTPUT_DIR/receiver.time.txt"
SENDER_JSON="$OUTPUT_DIR/sender.json"
SENDER_STDERR="$OUTPUT_DIR/sender.stderr"
SENDER_TIME="$OUTPUT_DIR/sender.time.txt"

RECEIVER_ARGS=(
    recv "$OUTPUT_DIR/dest"
    --listen 127.0.0.1:0
    --transport "$ATP_TRANSPORT"
    --once
    --preserve-xattrs
    --allow-special-files
    --sparse-files
    --rq-auth-key-hex "$AUTH_KEY_HEX"
)
if [[ "$ATP_TRANSPORT" == "quic" ]]; then
    RECEIVER_ARGS+=(
        --server-cert "$OUTPUT_DIR/tls/leaf.pem"
        --server-key "$OUTPUT_DIR/tls/leaf.key"
    )
fi
/usr/bin/time -v -o "$RECEIVER_TIME" "$ATP_BIN" "${RECEIVER_ARGS[@]}" \
    > "$RECEIVER_JSON" 2> "$RECEIVER_STDERR" &
RECEIVER_PID=$!

LISTEN_ADDR=""
if [[ "$ATP_TRANSPORT" == "quic" ]]; then
    READY_PATTERN="atp: quic listening on "
else
    READY_PATTERN="atp: rq control listening on "
fi
for _ in $(seq 1 100); do
    if ! kill -0 "$RECEIVER_PID" 2>/dev/null; then
        emit_event "receiver_ready" "failed" "receiver exited before readiness"
        cat "$RECEIVER_STDERR" >&2 || true
        exit 1
    fi
    if grep -Fq "$READY_PATTERN" "$RECEIVER_STDERR" 2>/dev/null; then
        if [[ "$ATP_TRANSPORT" == "quic" ]]; then
            LISTEN_ADDR="$(
                sed -n 's/^atp: quic listening on \([^,]*\), dest .*/\1/p' "$RECEIVER_STDERR" \
                    | tail -n1
            )"
        else
            LISTEN_ADDR="$(
                sed -n 's/^atp: rq control listening on \([^ ]*\) (udp on .*/\1/p' "$RECEIVER_STDERR" \
                    | tail -n1
            )"
        fi
        break
    fi
    sleep 0.1
done
[[ -n "$LISTEN_ADDR" ]] || { emit_event "receiver_ready" "failed" "receiver did not print readiness"; cat "$RECEIVER_STDERR" >&2 || true; exit 1; }
emit_event "receiver_ready" "passed" "receiver listening on $LISTEN_ADDR"

SENDER_ARGS=(
    send "$SOURCE_TREE" "$LISTEN_ADDR"
    --transport "$ATP_TRANSPORT"
    --preserve-xattrs
    --allow-special-files
    --rq-auth-key-hex "$AUTH_KEY_HEX"
)
if [[ "$ATP_TRANSPORT" == "quic" ]]; then
    SENDER_ARGS+=(
        --ca "$OUTPUT_DIR/tls/ca.pem"
        --server-name "$SERVER_NAME"
    )
else
    SENDER_ARGS+=(--streams 4)
fi
emit_event "sender_transfer" "started" "running atp send --transport $ATP_TRANSPORT"
if /usr/bin/time -v -o "$SENDER_TIME" "$ATP_BIN" "${SENDER_ARGS[@]}" \
    > "$SENDER_JSON" 2> "$SENDER_STDERR"; then
    emit_event "sender_transfer" "passed" "sender completed"
else
    emit_event "sender_transfer" "failed" "sender failed"
    cat "$SENDER_STDERR" >&2 || true
    kill "$RECEIVER_PID" 2>/dev/null || true
    wait "$RECEIVER_PID" 2>/dev/null || true
    exit 1
fi

wait "$RECEIVER_PID"
emit_event "receiver_transfer" "passed" "receiver exited after one transfer"

SOURCE_SHA="$(sha256sum "$PAYLOAD" | awk '{print $1}')"
DEST_TREE="$OUTPUT_DIR/dest/metadata-tree"
RECEIVED="$DEST_TREE/payload.bin"
[[ -f "$RECEIVED" ]] || { emit_event "sha256_verify" "failed" "received payload missing"; exit 1; }
RECEIVED_SHA="$(sha256sum "$RECEIVED" | awk '{print $1}')"
if [[ "$SOURCE_SHA" != "$RECEIVED_SHA" ]]; then
    emit_event "sha256_verify" "failed" "source and received sha256 differ"
    exit 1
fi
emit_event "sha256_verify" "passed" "source and received sha256 match" "$(jq -cn \
    --arg source_sha "$SOURCE_SHA" \
    --arg received_sha "$RECEIVED_SHA" \
    '{source_sha256:$source_sha,received_sha256:$received_sha,match:true}')"

if ! METADATA_ERROR="$(verify_metadata_fidelity "$SOURCE_TREE" "$DEST_TREE" "$SOURCE_XATTR_SUPPORTED" 2>&1)"; then
    emit_event "metadata_fidelity" "failed" "metadata-fidelity verification failed" "$(jq -cn \
        --arg error "$METADATA_ERROR" \
        '{error:$error}')"
    printf '%s\n' "$METADATA_ERROR" >&2
    exit 1
fi
PAYLOAD_MODE="$(stat -c '%a' "$DEST_TREE/payload.bin")"
PAYLOAD_MTIME="$(stat -c '%Y' "$DEST_TREE/payload.bin")"
EMPTY_DIR_MODE="$(stat -c '%a' "$DEST_TREE/empty-dir")"
RELATIVE_LINK_TARGET="$(readlink "$DEST_TREE/relative-link")"
DANGLING_LINK_TARGET="$(readlink "$DEST_TREE/dangling-link")"
HARDLINK_INODE="$(stat -c '%d:%i' "$DEST_TREE/hardlink-a.txt")"
FIFO_MODE="$(stat -c '%a' "$DEST_TREE/events.fifo")"
FIFO_MTIME="$(stat -c '%Y' "$DEST_TREE/events.fifo")"
PACKED_SPARSE_SIZE="$(stat -c '%s' "$DEST_TREE/packed-sparse.bin")"
PACKED_SPARSE_BLOCKS="$(stat -c '%b' "$DEST_TREE/packed-sparse.bin")"
REGULAR_SPARSE_SIZE="$(stat -c '%s' "$DEST_TREE/regular-sparse.bin")"
REGULAR_SPARSE_BLOCKS="$(stat -c '%b' "$DEST_TREE/regular-sparse.bin")"
METADATA_ENTRIES_JSON="$(jq -cn \
    --arg source_sha "$SOURCE_SHA" \
    --arg received_sha "$RECEIVED_SHA" \
    --arg payload_mode "$PAYLOAD_MODE" \
    --argjson payload_mtime "$PAYLOAD_MTIME" \
    --argjson xattr_supported "$SOURCE_XATTR_SUPPORTED" \
    --arg empty_dir_mode "$EMPTY_DIR_MODE" \
    --arg relative_link_target "$RELATIVE_LINK_TARGET" \
    --arg dangling_link_target "$DANGLING_LINK_TARGET" \
    --arg hardlink_inode "$HARDLINK_INODE" \
    --arg fifo_mode "$FIFO_MODE" \
    --argjson fifo_mtime "$FIFO_MTIME" \
    --argjson packed_sparse_size "$PACKED_SPARSE_SIZE" \
    --argjson packed_sparse_blocks "$PACKED_SPARSE_BLOCKS" \
    --argjson regular_sparse_size "$REGULAR_SPARSE_SIZE" \
    --argjson regular_sparse_blocks "$REGULAR_SPARSE_BLOCKS" \
    '[
      {rel_path:"payload.bin",kind:"regular",status:"passed",checks:{source_sha256:$source_sha,received_sha256:$received_sha,bytes_match:true,mode:$payload_mode,mtime_epoch:$payload_mtime,xattr:{supported:$xattr_supported,match:$xattr_supported}}},
      {rel_path:"empty-dir",kind:"directory",status:"passed",checks:{present:true,empty:true,mode:$empty_dir_mode}},
      {rel_path:"relative-link",kind:"symlink",status:"passed",checks:{present:true,target:$relative_link_target}},
      {rel_path:"dangling-link",kind:"symlink",status:"passed",checks:{present:true,target:$dangling_link_target,resolves:false}},
      {rel_path:"hardlink-a.txt",kind:"regular",status:"passed",checks:{content_match:true,inode_identity:$hardlink_inode}},
      {rel_path:"hardlink-b.txt",kind:"hardlink",status:"passed",checks:{content_match:true,inode_identity:$hardlink_inode,relinked:true}},
      {rel_path:"events.fifo",kind:"fifo",status:"passed",checks:{present:true,mode:$fifo_mode,mtime_epoch:$fifo_mtime}},
      {rel_path:"packed-sparse.bin",kind:"regular",status:"passed",checks:{content_match:true,sparse_allocation:true,size_bytes:$packed_sparse_size,allocated_blocks_512:$packed_sparse_blocks}},
      {rel_path:"regular-sparse.bin",kind:"regular",status:"passed",checks:{content_match:true,sparse_allocation:true,size_bytes:$regular_sparse_size,allocated_blocks_512:$regular_sparse_blocks}}
    ]')"
while IFS= read -r metadata_entry; do
    METADATA_ENTRY_PATH="$(jq -r '.rel_path' <<<"$metadata_entry")"
    emit_event "metadata_entry" "passed" "verified metadata entry $METADATA_ENTRY_PATH" "$metadata_entry"
done < <(jq -c '.[]' <<<"$METADATA_ENTRIES_JSON")
METADATA_NO_CLAIM="This real-binary loopback result proves only the retained $ATP_TRANSPORT metadata-fidelity fixture on this Unix filesystem. A single-transport receipt does not prove cross-transport parity, cross-host behavior, exact hole extents, privileged uid/gid restoration, broad workspace health, performance, or release readiness."
METADATA_FIDELITY_JSON="$(jq -cn \
    --arg source_tree "$SOURCE_TREE" \
    --arg received_tree "$DEST_TREE" \
    --argjson xattr_supported "$SOURCE_XATTR_SUPPORTED" \
    --argjson entries "$METADATA_ENTRIES_JSON" \
    --arg no_claim "$METADATA_NO_CLAIM" \
    '{
      status:"passed",
      source_tree:$source_tree,
      received_tree:$received_tree,
      entries_verified:9,
      entries:$entries,
      payload_bytes_match:true,
      payload_mode:"640",
      payload_mtime_epoch:1600000123,
      xattr_supported:$xattr_supported,
      xattr_match:$xattr_supported,
      empty_directory:true,
      empty_directory_mode:"750",
      relative_symlink_target:"payload.bin",
      dangling_symlink_target:"missing-target",
      hardlink_identity:true,
      fifo:true,
      fifo_mode:"620",
      fifo_mtime_epoch:1600000789,
      packed_sparse_content:true,
      packed_sparse_allocation:true,
      regular_sparse_content:true,
      regular_sparse_allocation:true,
      staging_clean:true,
      no_claim:$no_claim
    }')"
emit_event "metadata_fidelity" "passed" "heterogeneous metadata tree committed faithfully" "$METADATA_FIDELITY_JSON"

if ! capture_transport_integrity "$SOURCE_TREE" "$SOURCE_INTEGRITY_AFTER"; then
    emit_event "integrity_roots" "failed" "failed to capture source roots after transfer"
    exit 1
fi
if ! capture_transport_integrity "$DEST_TREE" "$RECEIVED_INTEGRITY"; then
    emit_event "integrity_roots" "failed" "failed to capture committed destination roots"
    exit 1
fi
INTEGRITY_NO_CLAIM="These point-in-time roots prove only that the selected transport's source preparation was stable before/after this loopback and reproduced by the committed destination. The live sender Merkle root and commit receipt are cross-checked; there is no atomic filesystem snapshot or cross-host, cross-filesystem, cross-version, performance, broad-workspace, or release-readiness claim."
INTEGRITY_ROOTS_JSON="$(jq -cn \
    --slurpfile before "$SOURCE_INTEGRITY_BEFORE" \
    --slurpfile after "$SOURCE_INTEGRITY_AFTER" \
    --slurpfile received "$RECEIVED_INTEGRITY" \
    --slurpfile sender "$SENDER_JSON" \
    --slurpfile receiver "$RECEIVER_JSON" \
    --arg transport "$ATP_TRANSPORT" \
    --arg no_claim "$INTEGRITY_NO_CLAIM" \
    '($before[0].transport_integrity) as $b |
    ($after[0].transport_integrity) as $a |
    ($received[0].transport_integrity) as $r |
    {
      status:"passed",
      transport:$transport,
      source_before:$b,
      source_after:$a,
      received:$r,
      source_stable:(($b.flat_merkle_root_hex == $a.flat_merkle_root_hex) and ($b.metadata_commitment_hex == $a.metadata_commitment_hex)),
      destination_match:(($b.flat_merkle_root_hex == $r.flat_merkle_root_hex) and ($b.metadata_commitment_hex == $r.metadata_commitment_hex)),
      live_sender_merkle_match:($sender[0].merkle_root == $b.flat_merkle_root_hex),
      receiver_merkle_commit_gate_observed:(($sender[0].merkle_ok == true) and ($sender[0].committed == true) and ($receiver[0].committed == true)),
      metadata_commitment_match:($b.metadata_commitment_hex == $r.metadata_commitment_hex),
      no_claim:$no_claim
    }')"
if ! jq -e '
    .status == "passed" and
    (.source_before.flat_merkle_root_hex | test("^[0-9a-f]{64}$")) and
    (.source_before.metadata_commitment_hex | test("^[0-9a-f]{64}$")) and
    .source_stable == true and
    .destination_match == true and
    .live_sender_merkle_match == true and
    .receiver_merkle_commit_gate_observed == true and
    .metadata_commitment_match == true
  ' <<<"$INTEGRITY_ROOTS_JSON" >/dev/null; then
    emit_event "integrity_roots" "failed" "transport integrity roots did not agree" "$INTEGRITY_ROOTS_JSON"
    exit 1
fi
emit_event "integrity_roots" "passed" "transport Merkle and metadata commitments agree" "$INTEGRITY_ROOTS_JSON"

SENDER_MAX_RSS_KB="$(extract_max_rss_kb "$SENDER_TIME")"
RECEIVER_MAX_RSS_KB="$(extract_max_rss_kb "$RECEIVER_TIME")"
if (( SENDER_MAX_RSS_KB >= RECEIVER_MAX_RSS_KB )); then
    PEAK_MAX_RSS_KB="$SENDER_MAX_RSS_KB"
else
    PEAK_MAX_RSS_KB="$RECEIVER_MAX_RSS_KB"
fi
SENDER_ELAPSED_RAW="$(extract_elapsed_raw "$SENDER_TIME")"
RECEIVER_ELAPSED_RAW="$(extract_elapsed_raw "$RECEIVER_TIME")"
SENDER_ELAPSED_SECONDS="$(elapsed_to_seconds "$SENDER_ELAPSED_RAW")"
RECEIVER_ELAPSED_SECONDS="$(elapsed_to_seconds "$RECEIVER_ELAPSED_RAW")"

jq -n \
    --slurpfile sender "$SENDER_JSON" \
    --slurpfile receiver "$RECEIVER_JSON" \
    --arg output_dir "$OUTPUT_DIR" \
    --arg payload "$PAYLOAD" \
    --arg received "$RECEIVED" \
    --arg source_sha "$SOURCE_SHA" \
    --arg received_sha "$RECEIVED_SHA" \
    --arg events "$OUTPUT_DIR/events.ndjson" \
    --arg sender_json "$SENDER_JSON" \
    --arg receiver_json "$RECEIVER_JSON" \
    --arg sender_stderr "$SENDER_STDERR" \
    --arg receiver_stderr "$RECEIVER_STDERR" \
    --arg sender_time "$SENDER_TIME" \
    --arg receiver_time "$RECEIVER_TIME" \
    --arg source_integrity_before "$SOURCE_INTEGRITY_BEFORE" \
    --arg source_integrity_after "$SOURCE_INTEGRITY_AFTER" \
    --arg received_integrity "$RECEIVED_INTEGRITY" \
    --arg transport "$ATP_TRANSPORT" \
    --arg sender_elapsed_raw "$SENDER_ELAPSED_RAW" \
    --arg receiver_elapsed_raw "$RECEIVER_ELAPSED_RAW" \
    --argjson sender_elapsed_seconds "$SENDER_ELAPSED_SECONDS" \
    --argjson receiver_elapsed_seconds "$RECEIVER_ELAPSED_SECONDS" \
    --argjson sender_max_rss_kb "$SENDER_MAX_RSS_KB" \
    --argjson receiver_max_rss_kb "$RECEIVER_MAX_RSS_KB" \
    --argjson peak_max_rss_kb "$PEAK_MAX_RSS_KB" \
    --argjson metadata_fidelity "$METADATA_FIDELITY_JSON" \
    --argjson integrity_roots "$INTEGRITY_ROOTS_JSON" \
    '($sender[0].symbols_sent // null) as $symbols_sent |
    ($receiver[0].symbols_accepted // null) as $symbols_accepted |
    ($sender[0].feedback_rounds // null) as $feedback_rounds_sender |
    ($receiver[0].feedback_rounds // null) as $feedback_rounds_receiver |
    ($receiver[0].decode_count // null) as $decode_count |
    ($receiver[0].decode_micros // null) as $decode_micros |
    ($receiver[0].bytes_received // 0) as $bytes_received |
    (if $sender_elapsed_seconds > 0 then $sender_elapsed_seconds else $receiver_elapsed_seconds end) as $transfer_elapsed_seconds |
    {
      schema_version: "arq-quic-loopback-e2e-summary-v2",
      status: "passed",
      transport: $transport,
      output_dir: $output_dir,
      payload_path: $payload,
      received_path: $received,
      bytes_sent: ($sender[0].bytes_sent // 0),
      bytes_received: ($receiver[0].bytes_received // 0),
      sender: $sender[0],
      receiver: $receiver[0],
      sha256: {source: $source_sha, received: $received_sha, match: ($source_sha == $received_sha)},
      sha256_match: ($source_sha == $received_sha),
      metadata_fidelity: $metadata_fidelity,
      integrity_roots: $integrity_roots,
      metrics: {
        sender_max_rss_kb: $sender_max_rss_kb,
        receiver_max_rss_kb: $receiver_max_rss_kb,
        peak_max_rss_kb: $peak_max_rss_kb,
        sender_elapsed_raw: $sender_elapsed_raw,
        receiver_elapsed_raw: $receiver_elapsed_raw,
        sender_elapsed_seconds: $sender_elapsed_seconds,
        receiver_elapsed_seconds: $receiver_elapsed_seconds,
        transfer_elapsed_seconds: $transfer_elapsed_seconds,
        goodput_bytes_per_second: (if $transfer_elapsed_seconds > 0 then ($bytes_received / $transfer_elapsed_seconds) else 0 end),
        goodput_bits_per_second: (if $transfer_elapsed_seconds > 0 then (($bytes_received * 8) / $transfer_elapsed_seconds) else 0 end),
        symbol_loss_rate: (
          if (($symbols_sent | type) == "number" and $symbols_sent > 0 and (($symbols_accepted | type) == "number"))
          then (([($symbols_sent - $symbols_accepted), 0] | max) / $symbols_sent)
          else null
          end
        ),
        symbol_loss_rate_available: (
          (($symbols_sent | type) == "number") and
          ($symbols_sent > 0) and
          (($symbols_accepted | type) == "number")
        ),
        symbol_loss_rate_mode: (
          if (($symbols_sent | type) == "number") and ($symbols_sent > 0)
          then "observed-raptorq-symbols"
          else "not-applicable-no-symbols"
          end
        ),
        feedback_rounds_total: (
          (if (($feedback_rounds_sender | type) == "number") then $feedback_rounds_sender else 0 end) +
          (if (($feedback_rounds_receiver | type) == "number") then $feedback_rounds_receiver else 0 end)
        ),
        decode_time_per_block_micros: (
          if (($decode_count | type) == "number")
          then (if ($decode_count > 0 and (($decode_micros | type) == "number"))
            then ($decode_micros / $decode_count)
            else 0
            end)
          else null
          end
        )
      },
      transport_counters: {
        source: "atp-cli-json",
        symbols_sent: $symbols_sent,
        symbols_accepted: $symbols_accepted,
        feedback_rounds_sender: $feedback_rounds_sender,
        feedback_rounds_receiver: $feedback_rounds_receiver,
        decode_count: $decode_count,
        decode_micros: $decode_micros,
        symbols_sent_available: (($symbols_sent | type) == "number"),
        symbols_accepted_available: (($symbols_accepted | type) == "number"),
        feedback_rounds_available: ((($feedback_rounds_sender | type) == "number") and (($feedback_rounds_receiver | type) == "number")),
        decode_count_available: (($decode_count | type) == "number"),
        decode_micros_available: (($decode_micros | type) == "number"),
        no_claim: "Loopback summary derives goodput from retained time/CLI artifacts and exposes sender/receiver peak RSS. Receiver decode block count/time are retained only when the selected transport CLI emits them; unavailable counters remain null with explicit false availability. Symbol loss is numeric only when RaptorQ symbols were attempted; zero-symbol source-stream transfers report it as null and not applicable. Any numeric loss rate remains a loopback artifact metric, not a fleet/network-loss proof. H2 still does not claim metrics-provider emission, fanout/per-path stats, avg RSS, optional-metrics off-overhead, or fleet proof."
      },
      artifacts: {
        events_ndjson: $events,
        sender_json: $sender_json,
        receiver_json: $receiver_json,
        sender_stderr: $sender_stderr,
        receiver_stderr: $receiver_stderr,
        sender_time: $sender_time,
        receiver_time: $receiver_time,
        source_integrity_before: $source_integrity_before,
        source_integrity_after: $source_integrity_after,
        received_integrity: $received_integrity
      }
    }' > "$OUTPUT_DIR/summary.json"

emit_summary_event
if ! VALIDATION_ERROR="$(validate_output "$OUTPUT_DIR" 2>&1)"; then
    emit_event "offline_validation" "failed" "summary and events failed validation" "$(
        jq -cn --arg error "$VALIDATION_ERROR" '{error:$error}'
    )"
    printf '%s\n' "$VALIDATION_ERROR" >&2
    exit 1
fi
emit_event "offline_validation" "passed" "summary and events validate"

echo "ARQ/QUIC loopback E2E artifacts: $OUTPUT_DIR"
