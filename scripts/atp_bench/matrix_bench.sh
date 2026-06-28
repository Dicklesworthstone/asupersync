#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${REPO_ROOT}/artifacts/atp_bench_matrix/${RUN_ID}"
WORK_DIR="${OUT_DIR}/workloads"
RESULTS_JSONL="${OUT_DIR}/results.jsonl"
PLAN_JSONL="${OUT_DIR}/plan.jsonl"
REPORT_MD="${OUT_DIR}/scorecard.md"
REPS_DEFAULT=3
DRY_RUN=1
APPLY_NETEM=0
GENERATE_WORKLOADS=0
RUN_CELL_CMD=""
WORKLOADS="500K,5M,50M,500M,5G,tree_small,tree_big"
REGIMES="perfect,good,bad,broken"
TIERS="nocrypto,auth,encrypted"
STREAMS_SWEEP="1"
METHODS_FILTER=""
FAIL_ON_MISMATCH=0

usage() {
  cat <<'USAGE'
Usage: matrix_bench.sh [options]

Plans or runs the ATP-vs-optimally-tuned-rsync benchmark matrix from
docs/atp_bench_matrix_spec.md. The default is dry-run planning only.

Options:
  --execute                 run cells instead of printing the resumable plan
  --apply-netem             permit symmetric tc/netem setup for each regime
  --generate-workloads      create deterministic payloads under --work-dir
  --run-cell-command CMD    command invoked once per method/rep with env vars
  --out DIR                 output directory
  --work-dir DIR            workload directory
  --results PATH            result JSONL path
  --workloads CSV           workload list
  --regimes CSV             regime list
  --tiers CSV               crypto tier list
  --methods CSV             method allowlist after tier expansion
  --streams CSV             ATP-RQ stream counts to sweep (default: 1)
  --reps N                  default reps per method/cell
  --fail-on-mismatch        exit non-zero if score_matrix finds any failed row
  --help                    show this help

Execution env for --run-cell-command:
  ATP_MATRIX_WORKLOAD, ATP_MATRIX_WORKLOAD_PATH, ATP_MATRIX_REGIME,
  ATP_MATRIX_TIER, ATP_MATRIX_METHOD, ATP_MATRIX_REP, ATP_MATRIX_RESULTS,
  ATP_MATRIX_STREAMS, ATP_MATRIX_NETEM_JSON, ATP_MATRIX_RUN_ID,
  ATP_MATRIX_GIT_HEAD.
USAGE
}

die() {
  printf 'matrix_bench.sh: %s\n' "$*" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --execute)
      DRY_RUN=0
      shift
      ;;
    --apply-netem)
      APPLY_NETEM=1
      shift
      ;;
    --generate-workloads)
      GENERATE_WORKLOADS=1
      shift
      ;;
    --run-cell-command)
      RUN_CELL_CMD="${2:?missing command}"
      shift 2
      ;;
    --out)
      OUT_DIR="${2:?missing directory}"
      WORK_DIR="${OUT_DIR}/workloads"
      RESULTS_JSONL="${OUT_DIR}/results.jsonl"
      PLAN_JSONL="${OUT_DIR}/plan.jsonl"
      REPORT_MD="${OUT_DIR}/scorecard.md"
      shift 2
      ;;
    --work-dir)
      WORK_DIR="${2:?missing directory}"
      shift 2
      ;;
    --results)
      RESULTS_JSONL="${2:?missing path}"
      shift 2
      ;;
    --workloads)
      WORKLOADS="${2:?missing CSV}"
      shift 2
      ;;
    --regimes)
      REGIMES="${2:?missing CSV}"
      shift 2
      ;;
    --tiers)
      TIERS="${2:?missing CSV}"
      shift 2
      ;;
    --methods)
      METHODS_FILTER="${2:?missing CSV}"
      shift 2
      ;;
    --streams)
      STREAMS_SWEEP="${2:?missing CSV}"
      shift 2
      ;;
    --reps)
      REPS_DEFAULT="${2:?missing reps}"
      shift 2
      ;;
    --fail-on-mismatch)
      FAIL_ON_MISMATCH=1
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ "${REPS_DEFAULT}" =~ ^[0-9]+$ ]] || die "--reps must be an integer"
[[ "${REPS_DEFAULT}" -ge 1 ]] || die "--reps must be >= 1"

method_uses_stream_sweep() {
  [[ "$1" == atp-rq-* ]]
}

validate_streams() {
  local -n streams_ref="$1"
  local stream
  for stream in "${streams_ref[@]}"; do
    [[ "${stream}" =~ ^[0-9]+$ ]] || die "--streams values must be integers"
    [[ "${stream}" -ge 1 ]] || die "--streams values must be >= 1"
  done
}

split_csv() {
  local value="$1"
  local -n out_ref="$2"
  IFS=',' read -r -a out_ref <<<"${value}"
}

method_allowed() {
  local method="$1"
  [[ -n "${METHODS_FILTER}" ]] || return 0
  local allowed_methods
  split_csv "${METHODS_FILTER}" allowed_methods
  local allowed
  for allowed in "${allowed_methods[@]}"; do
    [[ "${method}" == "${allowed}" ]] && return 0
  done
  return 1
}

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

git_head() {
  git -C "${REPO_ROOT}" rev-parse HEAD
}

netem_json() {
  local regime="$1"
  case "${regime}" in
    perfect)
      printf '{"rate":"1gbit","delay_ms":2,"jitter_ms":0,"loss_pct":0,"reorder_pct":0,"duplicate_pct":0}'
      ;;
    good)
      printf '{"rate":"200mbit","delay_ms":25,"jitter_ms":0,"loss_pct":0.1,"reorder_pct":0,"duplicate_pct":0}'
      ;;
    bad)
      printf '{"rate":"50mbit","delay_ms":80,"jitter_ms":20,"loss_pct":2,"reorder_pct":0,"duplicate_pct":0}'
      ;;
    broken)
      printf '{"rate":"10mbit","delay_ms":200,"jitter_ms":50,"loss_pct":10,"reorder_pct":5,"duplicate_pct":1}'
      ;;
    highbdp)
      # Clean fat + long pipe (1gbit @ 200ms RTT => BDP ~33k pkts) to ISOLATE
      # multi-stream fan-out: a single ATP-RQ stream is capped by per-stream
      # pacing while N fanned-out streams fill the pipe, and single-TCP rsync is
      # slow-start-ramp limited. Loss is intentionally 0 here — loss-resilience
      # is already measured by the */bad cells; mixing 0.1% loss with 200ms RTT
      # would collapse single-TCP via Mathis (~1.8Mbit/s) and conflate levers.
      # Large limit avoids netem tail-drop (default 1000 pkts << BDP). Pair with
      # --streams 1,2,4,8.
      printf '{"rate":"1gbit","delay_ms":200,"jitter_ms":10,"loss_pct":0,"reorder_pct":0,"duplicate_pct":0,"limit":200000}'
      ;;
    *)
      die "unknown regime: ${regime}"
      ;;
  esac
}

methods_for_tier() {
  local tier="$1"
  case "${tier}" in
    nocrypto)
      printf '%s\n' "atp-rq-lab" "rsyncd"
      ;;
    auth)
      printf '%s\n' "atp-rq-auth" "rsync-ssh-aes128gcm"
      ;;
    encrypted)
      printf '%s\n' "atp-quic-tls13" "rsync-ssh-aes128gcm"
      ;;
    *)
      die "unknown crypto tier: ${tier}"
      ;;
  esac
}

reps_for_cell() {
  local workload="$1"
  local regime="$2"
  if [[ "${workload}" == "5G" && "${regime}" == "broken" ]]; then
    printf '1'
  elif [[ "${workload}" == "500K" || "${workload}" == "tree_small" ]]; then
    if [[ "${REPS_DEFAULT}" -lt 5 ]]; then
      printf '5'
    else
      printf '%s' "${REPS_DEFAULT}"
    fi
  else
    printf '%s' "${REPS_DEFAULT}"
  fi
}

workload_path() {
  local workload="$1"
  case "${workload}" in
    500K|5M|50M|500M|5G)
      printf '%s/%s.bin' "${WORK_DIR}" "${workload}"
      ;;
    tree_small|tree_big)
      printf '%s/%s' "${WORK_DIR}" "${workload}"
      ;;
    *)
      die "unknown workload: ${workload}"
      ;;
  esac
}

workload_size_bytes() {
  case "$1" in
    500K) printf '512000' ;;
    5M) printf '5242880' ;;
    50M) printf '52428800' ;;
    500M) printf '524288000' ;;
    5G) printf '5368709120' ;;
    *) die "not a flat-file workload: $1" ;;
  esac
}

generate_flat_payload() {
  local workload="$1"
  local path
  local size
  path="$(workload_path "${workload}")"
  size="$(workload_size_bytes "${workload}")"
  if [[ -e "${path}" ]]; then
    [[ -f "${path}" ]] || die "existing workload path is not a file: ${path}"
    local actual
    actual="$(wc -c <"${path}" | tr -d ' ')"
    [[ "${actual}" == "${size}" ]] || die "payload size mismatch for ${path}: have ${actual}, want ${size}"
    return
  fi
  mkdir -p "$(dirname "${path}")"
  python3 - "$path" "$size" "$workload" <<'PY'
import hashlib
import random
import sys

path = sys.argv[1]
size = int(sys.argv[2])
label = sys.argv[3]
rng = random.Random("atp-bench-matrix:" + label)
remaining = size
chunk_size = 1024 * 1024
digest = hashlib.sha256()
with open(path, "xb") as fh:
    while remaining:
        chunk = rng.randbytes(min(chunk_size, remaining))
        fh.write(chunk)
        digest.update(chunk)
        remaining -= len(chunk)
print(digest.hexdigest())
PY
}

generate_workload() {
  local workload="$1"
  case "${workload}" in
    500K|5M|50M|500M|5G)
      generate_flat_payload "${workload}" >/dev/null
      ;;
    tree_small|tree_big)
      local root
      root="$(workload_path "${workload}")"
      if [[ -e "${root}.manifest.jsonl" ]]; then
        die "manifest already exists; refusing to append or overwrite: ${root}.manifest.jsonl"
      fi
      python3 "${SCRIPT_DIR}/gen_tree.py" --kind "${workload}" --root "${root}" --seed 1093842 >/dev/null
      ;;
  esac
}

cell_done() {
  local workload="$1" regime="$2" tier="$3" method="$4" rep="$5" streams="$6"
  [[ -f "${RESULTS_JSONL}" ]] || return 1
  python3 - "$RESULTS_JSONL" "$workload" "$regime" "$tier" "$method" "$rep" "$streams" <<'PY'
import json
import sys

path, workload, regime, tier, method, rep, streams = sys.argv[1:8]
requires_stream_match = method.startswith("atp-rq-")
with open(path, encoding="utf-8") as fh:
    for line in fh:
        if not line.strip():
            continue
        row = json.loads(line)
        row_streams = row.get("atp_rq_streams", row.get("stream_count"))
        stream_match = not requires_stream_match or (
            row_streams is not None and str(row_streams) == streams
        )
        if (
            str(row.get("workload")) == workload
            and str(row.get("regime")) == regime
            and str(row.get("crypto_tier", row.get("tier"))) == tier
            and str(row.get("method")) == method
            and str(row.get("rep")) == rep
            and stream_match
            and str(row.get("status", "ok")).lower() == "ok"
        ):
            raise SystemExit(0)
raise SystemExit(1)
PY
}

write_plan_row() {
  local workload="$1" regime="$2" tier="$3" method="$4" rep="$5" path="$6" git="$7" streams="$8"
  local netem
  netem="$(netem_json "${regime}")"
  local atp_streams_json="null"
  if method_uses_stream_sweep "${method}"; then
    atp_streams_json="${streams}"
  fi
  printf '{"schema":"atp-bench-matrix-plan-v1","run_id":%s,"git_head":%s,"workload":%s,"workload_path":%s,"regime":%s,"crypto_tier":%s,"method":%s,"rep":%s,"stream_count":%s,"atp_rq_streams":%s,"netem":%s}\n' \
    "$(json_escape "${RUN_ID}")" \
    "$(json_escape "${git}")" \
    "$(json_escape "${workload}")" \
    "$(json_escape "${path}")" \
    "$(json_escape "${regime}")" \
    "$(json_escape "${tier}")" \
    "$(json_escape "${method}")" \
    "${rep}" \
    "${streams}" \
    "${atp_streams_json}" \
    "${netem}"
}

apply_netem_for_regime() {
  local regime="$1"
  [[ "${APPLY_NETEM}" -eq 1 ]] || return 0
  [[ -n "${ATP_MATRIX_IFACE_A:-}" && -n "${ATP_MATRIX_IFACE_B:-}" ]] || die "--apply-netem requires ATP_MATRIX_IFACE_A and ATP_MATRIX_IFACE_B"
  local netem
  netem="$(netem_json "${regime}")"
  python3 - "$netem" "${ATP_MATRIX_IFACE_A}" "${ATP_MATRIX_IFACE_B}" <<'PY'
import json
import subprocess
import sys

cfg = json.loads(sys.argv[1])
ifaces = sys.argv[2:]
for iface in ifaces:
    cmd = [
        "tc", "qdisc", "replace", "dev", iface, "root", "netem",
        "rate", cfg["rate"],
        "delay", f"{cfg['delay_ms']}ms", f"{cfg['jitter_ms']}ms",
        "loss", f"{cfg['loss_pct']}%",
        "reorder", f"{cfg['reorder_pct']}%",
        "duplicate", f"{cfg['duplicate_pct']}%",
    ]
    subprocess.run(cmd, check=True)
PY
}

run_cell() {
  local workload="$1" regime="$2" tier="$3" method="$4" rep="$5" path="$6" git="$7" streams="$8"
  if cell_done "${workload}" "${regime}" "${tier}" "${method}" "${rep}" "${streams}"; then
    printf 'skip existing %s %s %s %s streams=%s rep=%s\n' "${workload}" "${regime}" "${tier}" "${method}" "${streams}" "${rep}" >&2
    return
  fi
  [[ -n "${RUN_CELL_CMD}" ]] || die "--execute requires --run-cell-command"
  export ATP_MATRIX_WORKLOAD="${workload}"
  export ATP_MATRIX_WORKLOAD_PATH="${path}"
  export ATP_MATRIX_REGIME="${regime}"
  export ATP_MATRIX_TIER="${tier}"
  export ATP_MATRIX_METHOD="${method}"
  export ATP_MATRIX_REP="${rep}"
  export ATP_MATRIX_STREAMS="${streams}"
  export ATP_MATRIX_RESULTS="${RESULTS_JSONL}"
  export ATP_MATRIX_NETEM_JSON
  ATP_MATRIX_NETEM_JSON="$(netem_json "${regime}")"
  export ATP_MATRIX_RUN_ID="${RUN_ID}"
  export ATP_MATRIX_GIT_HEAD="${git}"
  bash -c "${RUN_CELL_CMD}"
}

main() {
  local workloads regimes tiers streams
  split_csv "${WORKLOADS}" workloads
  split_csv "${REGIMES}" regimes
  split_csv "${TIERS}" tiers
  split_csv "${STREAMS_SWEEP}" streams
  validate_streams streams

  mkdir -p "${OUT_DIR}"
  : >"${PLAN_JSONL}"
  local git
  git="$(git_head)"

  for workload in "${workloads[@]}"; do
    local path
    path="$(workload_path "${workload}")"
    if [[ "${GENERATE_WORKLOADS}" -eq 1 && "${DRY_RUN}" -eq 0 ]]; then
      generate_workload "${workload}"
    fi
    for regime in "${regimes[@]}"; do
      apply_netem_for_regime "${regime}"
      for tier in "${tiers[@]}"; do
        mapfile -t methods < <(methods_for_tier "${tier}")
        local reps
        reps="$(reps_for_cell "${workload}" "${regime}")"
        for method in "${methods[@]}"; do
          if ! method_allowed "${method}"; then
            continue
          fi
          local method_streams=("${streams[@]}")
          if ! method_uses_stream_sweep "${method}"; then
            method_streams=(1)
          fi
          local rep
          local stream_count
          for stream_count in "${method_streams[@]}"; do
            for ((rep = 1; rep <= reps; rep++)); do
              write_plan_row "${workload}" "${regime}" "${tier}" "${method}" "${rep}" "${path}" "${git}" "${stream_count}" >>"${PLAN_JSONL}"
              if [[ "${DRY_RUN}" -eq 0 ]]; then
                run_cell "${workload}" "${regime}" "${tier}" "${method}" "${rep}" "${path}" "${git}" "${stream_count}"
              fi
            done
          done
        done
      done
    done
  done

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    cat "${PLAN_JSONL}"
  elif [[ -f "${RESULTS_JSONL}" ]]; then
    python3 "${SCRIPT_DIR}/score_matrix.py" "${RESULTS_JSONL}" --out-md "${REPORT_MD}"
    if [[ "${FAIL_ON_MISMATCH}" -eq 1 ]]; then
      python3 "${SCRIPT_DIR}/score_matrix.py" "${RESULTS_JSONL}" --fail-on-mismatch
    fi
  fi
}

main "$@"
