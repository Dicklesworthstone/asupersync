#!/usr/bin/env bash
set -euo pipefail

if [[ ${ATP_RQ_AUTH_KEY_HEX+x} ]]; then
  set +x
  unset ATP_RQ_AUTH_KEY_HEX RQ_AUTH_SECRET
  echo "ATP_RQ_AUTH_KEY_HEX is forbidden; authenticated cells generate protected per-cell keys" >&2
  exit 2
fi
if [[ ${RQ_AUTH_KEY_HEX+x} ]]; then
  set +x
  unset RQ_AUTH_KEY_HEX RQ_AUTH_SECRET
  echo "RQ_AUTH_KEY_HEX is forbidden; authenticated cells generate protected per-cell keys" >&2
  exit 2
fi
unset RQ_AUTH_SECRET
unset ATP_MATRIX_VERIFIED_BINARY_SHA256 ATP_MATRIX_VERIFIED_ARCHIVE_SHA256
unset ATP_MATRIX_VERIFIED_WORKFLOW_RUN_ID ATP_MATRIX_VERIFIED_WORKFLOW_RUN_ATTEMPT

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
CELL_PROFILE="whole-object-scorecard-v1"
WORK_DIR_EXPLICIT=0
RESULTS_EXPLICIT=0
REPS_EXPLICIT=0

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
  --cell-profile PROFILE    whole-object-scorecard-v1 (default) or
                            authenticated-delta-unchanged-v1
  --streams CSV             ATP-RQ stream counts to sweep (default: 1)
  --reps N                  default reps per method/cell
  --fail-on-mismatch        exit non-zero if score_matrix finds any failed row
  --help                    show this help

Execution env for --run-cell-command:
  ATP_MATRIX_WORKLOAD, ATP_MATRIX_WORKLOAD_PATH, ATP_MATRIX_REGIME,
  ATP_MATRIX_TIER, ATP_MATRIX_METHOD, ATP_MATRIX_REP, ATP_MATRIX_RESULTS,
  ATP_MATRIX_STREAMS, ATP_MATRIX_NETEM_JSON, ATP_MATRIX_RUN_ID,
  ATP_MATRIX_GIT_HEAD, ATP_MATRIX_CELL_PROFILE, ATP_MATRIX_CASE_ID.

Authenticated-delta execute mode also requires a commit-bound binary packet:
  BIN, ATP_MATRIX_BINARY_ARCHIVE, ATP_MATRIX_BINARY_ARCHIVE_SHA256,
  ATP_MATRIX_BINARY_PROVENANCE, ATP_MATRIX_BINARY_ATTESTATION_BUNDLE.
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
      if [[ "${WORK_DIR_EXPLICIT}" -eq 0 ]]; then
        WORK_DIR="${OUT_DIR}/workloads"
      fi
      if [[ "${RESULTS_EXPLICIT}" -eq 0 ]]; then
        RESULTS_JSONL="${OUT_DIR}/results.jsonl"
      fi
      PLAN_JSONL="${OUT_DIR}/plan.jsonl"
      REPORT_MD="${OUT_DIR}/scorecard.md"
      shift 2
      ;;
    --work-dir)
      WORK_DIR="${2:?missing directory}"
      WORK_DIR_EXPLICIT=1
      shift 2
      ;;
    --results)
      RESULTS_JSONL="${2:?missing path}"
      RESULTS_EXPLICIT=1
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
    --cell-profile)
      CELL_PROFILE="${2:?missing profile}"
      shift 2
      ;;
    --streams)
      STREAMS_SWEEP="${2:?missing CSV}"
      shift 2
      ;;
    --reps)
      REPS_DEFAULT="${2:?missing reps}"
      REPS_EXPLICIT=1
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
case "${CELL_PROFILE}" in
  whole-object-scorecard-v1|authenticated-delta-unchanged-v1) ;;
  *) die "unknown --cell-profile: ${CELL_PROFILE}" ;;
esac
if [[ "${CELL_PROFILE}" == "authenticated-delta-unchanged-v1" ]]; then
  if [[ "${REPS_EXPLICIT}" -eq 0 ]]; then
    REPS_DEFAULT=1
  fi
  if [[ "${RESULTS_EXPLICIT}" -eq 0 ]]; then
    RESULTS_JSONL="${OUT_DIR}/authenticated_delta_unchanged_results.jsonl"
  fi
  PLAN_JSONL="${OUT_DIR}/authenticated_delta_unchanged_plan.jsonl"
  REPORT_MD="${OUT_DIR}/authenticated_delta_unchanged_acceptance.md"
fi

method_uses_stream_sweep() {
  [[ "$1" == atp-rq-* ]]
}

cell_case_id() {
  local workload="$1" regime="$2" tier="$3" method="$4" rep="$5" streams="$6"
  printf '%s:%s:%s:%s:%s:s%s:r%s' \
    "${CELL_PROFILE}" "${workload}" "${regime}" "${tier}" "${method}" "${streams}" "${rep}"
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
  # ShellCheck cannot see that the nameref writes into the caller's array.
  # shellcheck disable=SC2034
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
  /usr/bin/git -C "${REPO_ROOT}" rev-parse HEAD
}

verify_commit_bound_atp_binary() {
  local git="$1"
  local archive="${ATP_MATRIX_BINARY_ARCHIVE:-}"
  local archive_sha256="${ATP_MATRIX_BINARY_ARCHIVE_SHA256:-}"
  local provenance="${ATP_MATRIX_BINARY_PROVENANCE:-}"
  local attestation_bundle="${ATP_MATRIX_BINARY_ATTESTATION_BUNDLE:-}"
  local binary="${BIN:-}"

  [[ -n "${binary}" ]] || die "${CELL_PROFILE} execute mode requires BIN"
  [[ -n "${archive}" ]] || die "${CELL_PROFILE} execute mode requires ATP_MATRIX_BINARY_ARCHIVE"
  [[ -n "${archive_sha256}" ]] || die "${CELL_PROFILE} execute mode requires ATP_MATRIX_BINARY_ARCHIVE_SHA256"
  [[ -n "${provenance}" ]] || die "${CELL_PROFILE} execute mode requires ATP_MATRIX_BINARY_PROVENANCE"
  [[ -n "${attestation_bundle}" ]] || die "${CELL_PROFILE} execute mode requires ATP_MATRIX_BINARY_ATTESTATION_BUNDLE"

  local label path
  for label in BIN archive archive-sha256 provenance attestation-bundle; do
    case "${label}" in
      BIN) path="${binary}" ;;
      archive) path="${archive}" ;;
      archive-sha256) path="${archive_sha256}" ;;
      provenance) path="${provenance}" ;;
      attestation-bundle) path="${attestation_bundle}" ;;
    esac
    [[ -f "${path}" && ! -L "${path}" ]] || die "commit-bound ATP ${label} must be a regular non-symlink file: ${path}"
  done
  [[ -x "${binary}" ]] || die "commit-bound ATP BIN is not executable: ${binary}"
  [[ -s "${attestation_bundle}" ]] || die "commit-bound ATP attestation bundle is empty"
  [[ -x /usr/bin/gh ]] || die "commit-bound ATP verification requires /usr/bin/gh"
  [[ -x /usr/bin/python3 ]] || die "commit-bound ATP verification requires /usr/bin/python3"
  [[ -x /usr/bin/git ]] || die "commit-bound ATP verification requires /usr/bin/git"
  [[ "${RUN_CELL_CMD}" == "bash scripts/atp_bench/run_matrix_cell.sh" ]] \
    || die "${CELL_PROFILE} requires the canonical run_matrix_cell.sh command"
  /usr/bin/git -C "${REPO_ROOT}" diff --quiet "${git}" -- \
    scripts/atp_bench/matrix_bench.sh scripts/atp_bench/run_matrix_cell.sh \
    || die "${CELL_PROFILE} requires checked-in, unmodified matrix runner scripts"

  /usr/bin/gh attestation verify "${archive}" \
    --bundle "${attestation_bundle}" \
    --repo Dicklesworthstone/asupersync \
    --signer-workflow Dicklesworthstone/asupersync/.github/workflows/atp-proof-lanes.yml \
    --source-digest "${git}" \
    --source-ref refs/heads/main \
    --predicate-type https://slsa.dev/provenance/v1 \
    --deny-self-hosted-runners >/dev/null \
    || die "commit-bound ATP archive attestation verification failed"

  local tree verified_identity expected_version actual_version
  local verified_binary_sha256 verified_archive_sha256
  local verified_workflow_run_id verified_workflow_run_attempt
  tree="$(/usr/bin/git -C "${REPO_ROOT}" rev-parse "${git}^{tree}")"
  verified_identity="$(/usr/bin/python3 - \
    "${archive}" "${archive_sha256}" "${provenance}" "${attestation_bundle}" \
    "${binary}" "${REPO_ROOT}" "${git}" "${tree}" <<'PY'
import hashlib
import json
import pathlib
import stat
import subprocess
import sys
import tarfile

(
    archive_arg,
    archive_sha256_arg,
    provenance_arg,
    attestation_bundle_arg,
    binary_arg,
    repo_arg,
    git_sha,
    git_tree,
) = sys.argv[1:9]
archive = pathlib.Path(archive_arg)
archive_sha256 = pathlib.Path(archive_sha256_arg)
provenance_path = pathlib.Path(provenance_arg)
attestation_bundle = pathlib.Path(attestation_bundle_arg)
binary_path = pathlib.Path(binary_arg)
repo = pathlib.Path(repo_arg)


def fail(message):
    raise SystemExit(f"commit-bound ATP artifact verification failed: {message}")


def require(condition, message):
    if not condition:
        fail(message)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate provenance key: {key}")
        result[key] = value
    return result


archive_digest = sha256_bytes(archive.read_bytes())
require(
    archive_sha256.name == f"{archive.name}.sha256",
    "outer checksum filename does not match archive",
)
require(
    archive_sha256.read_text(encoding="ascii")
    == f"{archive_digest}  {archive.name}\n",
    "outer archive checksum line or digest mismatch",
)

expected_members = ["atp-linux-x86_64", "provenance.json", "SHA256SUMS"]
with tarfile.open(archive, mode="r:gz") as bundle:
    members = bundle.getmembers()
    require(
        [member.name for member in members] == expected_members,
        "archive members are not the exact canonical ordered set",
    )
    require(all(member.isfile() for member in members), "archive contains a non-regular member")
    require(stat.S_IMODE(members[0].mode) == 0o755, "archived ATP binary mode is not 0755")
    archived_binary_file = bundle.extractfile(members[0])
    embedded_provenance_file = bundle.extractfile(members[1])
    inner_checksums_file = bundle.extractfile(members[2])
    require(archived_binary_file is not None, "archived ATP binary is unreadable")
    require(embedded_provenance_file is not None, "embedded provenance is unreadable")
    require(inner_checksums_file is not None, "inner checksum file is unreadable")
    archived_binary = archived_binary_file.read()
    embedded_provenance = embedded_provenance_file.read()
    inner_checksums = inner_checksums_file.read()

external_provenance = provenance_path.read_bytes()
require(
    external_provenance == embedded_provenance,
    "standalone provenance differs from attested embedded provenance",
)
try:
    manifest = json.loads(
        embedded_provenance.decode("utf-8"), object_pairs_hook=reject_duplicate_keys
    )
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"invalid provenance JSON: {error}")

require(manifest.get("schema") == "asupersync-commit-bound-atp-binary-v1", "wrong provenance schema")
source = manifest.get("source", {})
require(source.get("repository") == "Dicklesworthstone/asupersync", "wrong source repository")
require(source.get("git_sha") == git_sha, "source SHA does not match checkout HEAD")
require(source.get("git_tree") == git_tree, "source tree does not match checkout HEAD")
require(source.get("git_ref") == "refs/heads/main", "source ref is not main")
require(source.get("clean_checkout_verified") is True, "producer did not verify a clean checkout")

build = manifest.get("build", {})
expected_command = (
    "cargo build --locked --release --target x86_64-unknown-linux-gnu "
    "--bin atp --features atp-cli"
)
expected_workflow_ref = (
    "Dicklesworthstone/asupersync/.github/workflows/atp-proof-lanes.yml@refs/heads/main"
)
require(build.get("command") == expected_command, "unexpected producer build command")
require(build.get("target") == "x86_64-unknown-linux-gnu", "unexpected producer target")
require(build.get("runner_os") == "Linux", "producer runner OS is not Linux")
require(build.get("runner_arch") == "X64", "producer runner architecture is not X64")
require(build.get("workflow_ref") == expected_workflow_ref, "unexpected producer workflow ref")
require(build.get("workflow_sha") == git_sha, "producer workflow SHA does not match source SHA")
require(str(build.get("workflow_run_id", "")).isdigit(), "invalid producer workflow run ID")
require(
    isinstance(build.get("workflow_run_attempt"), int)
    and build["workflow_run_attempt"] >= 1,
    "invalid producer workflow run attempt",
)
require(
    isinstance(build.get("runner_image_os"), str) and build["runner_image_os"],
    "missing producer runner image OS",
)
require(
    isinstance(build.get("runner_image_version"), str)
    and build["runner_image_version"],
    "missing producer runner image version",
)
require(
    "host: x86_64-unknown-linux-gnu" in str(build.get("rustc", "")),
    "producer rustc host is not x86_64-unknown-linux-gnu",
)
lockfile = subprocess.check_output(
    ["/usr/bin/git", "-C", str(repo), "show", f"{git_sha}:Cargo.lock"]
)
require(
    build.get("cargo_lock_sha256") == sha256_bytes(lockfile),
    "Cargo.lock digest does not match source commit",
)

abi = manifest.get("abi", {})
file_description = str(abi.get("file_description", ""))
require("ELF 64-bit LSB" in file_description, "producer file metadata is not ELF64 LSB")
require("x86-64" in file_description, "producer file metadata is not x86-64")
require(abi.get("machine") == "x86_64", "producer machine is not x86_64")
require(
    str(abi.get("build_host_glibc", "")).startswith("glibc "),
    "missing producer glibc metadata",
)

artifact = manifest.get("artifact", {})
run_id = str(build["workflow_run_id"])
run_attempt = str(build["workflow_run_attempt"])
expected_archive_name = f"atp-linux-x86_64-{git_sha}-{run_id}-{run_attempt}.tar.gz"
expected_bundle_name = f"attestation-bundle-{git_sha}-{run_id}-{run_attempt}.jsonl"
require(archive.name == expected_archive_name, "archive basename is not commit/run bound")
require(artifact.get("archive_name") == archive.name, "provenance archive name mismatch")
require(artifact.get("archive_attestation_required") is True, "archive attestation is not required")
require(attestation_bundle.name == expected_bundle_name, "attestation bundle name is not commit/run bound")

verification = manifest.get("verification", {})
require(verification.get("archive_attestation_required") is True, "verification omits archive attestation")
require(
    verification.get("attestation_bundle") == attestation_bundle.name,
    "wrong attestation bundle contract",
)
require(
    verification.get("attestation_predicate_type") == "https://slsa.dev/provenance/v1",
    "wrong attestation predicate contract",
)
require(verification.get("embedded_provenance_authoritative") is True, "embedded provenance is not authoritative")
require(
    verification.get("required_signer_workflow")
    == "Dicklesworthstone/asupersync/.github/workflows/atp-proof-lanes.yml",
    "wrong signer-workflow contract",
)
require(verification.get("required_source_ref") == "refs/heads/main", "wrong source-ref contract")

archived_binary_digest = sha256_bytes(archived_binary)
require(
    inner_checksums.decode("ascii")
    == f"{archived_binary_digest}  atp-linux-x86_64\n",
    "inner binary checksum line or digest mismatch",
)
require(
    len(archived_binary) >= 20
    and archived_binary[:4] == b"\x7fELF"
    and archived_binary[4] == 2
    and archived_binary[5] == 1
    and int.from_bytes(archived_binary[18:20], "little") == 62,
    "archived payload is not little-endian ELF64 EM_X86_64",
)
binary = manifest.get("binary", {})
require(binary.get("name") == "atp-linux-x86_64", "wrong binary name in provenance")
require(binary.get("sha256") == archived_binary_digest, "archived binary digest mismatch")
require(binary.get("size_bytes") == len(archived_binary), "archived binary size mismatch")
require(binary_path.name == "atp-linux-x86_64", "BIN basename is not canonical")
disk_binary = binary_path.read_bytes()
require(sha256_bytes(disk_binary) == archived_binary_digest, "BIN digest differs from archive")
require(len(disk_binary) == len(archived_binary), "BIN size differs from archive")
require(binary_path.stat().st_mode & 0o022 == 0, "BIN is group- or world-writable")

claims = manifest.get("claims", {})
for claim in (
    "performance",
    "matrix_execution",
    "broad_workspace_health",
    "consumer_verification",
    "privileged_execution_safety",
    "release_readiness",
    "reproducible_build",
    "runtime_correctness",
):
    require(claims.get(claim) is False, f"producer no-claim {claim} is not false")

version_output = binary.get("version_output")
require(isinstance(version_output, str) and version_output, "missing binary version output")
print(
    "\t".join(
        (
            version_output,
            archived_binary_digest,
            archive_digest,
            run_id,
            run_attempt,
        )
    )
)
PY
  )" || die "commit-bound ATP archive/provenance verification failed"

  IFS=$'\t' read -r expected_version verified_binary_sha256 \
    verified_archive_sha256 verified_workflow_run_id verified_workflow_run_attempt \
    <<<"${verified_identity}"
  [[ "${verified_binary_sha256}" =~ ^[0-9a-f]{64}$ ]] \
    || die "verified ATP binary identity is malformed"
  [[ "${verified_archive_sha256}" =~ ^[0-9a-f]{64}$ ]] \
    || die "verified ATP archive identity is malformed"
  [[ "${verified_workflow_run_id}" =~ ^[0-9]+$ ]] \
    || die "verified ATP workflow run ID is malformed"
  [[ "${verified_workflow_run_attempt}" =~ ^[0-9]+$ ]] \
    || die "verified ATP workflow run attempt is malformed"

  actual_version="$("${binary}" --version)" \
    || die "verified commit-bound ATP binary failed its version probe"
  [[ "${actual_version}" == "${expected_version}" ]] \
    || die "verified commit-bound ATP binary version output differs from provenance"
  export BIN="${binary}"
  export ATP_MATRIX_VERIFIED_BINARY_SHA256="${verified_binary_sha256}"
  export ATP_MATRIX_VERIFIED_ARCHIVE_SHA256="${verified_archive_sha256}"
  export ATP_MATRIX_VERIFIED_WORKFLOW_RUN_ID="${verified_workflow_run_id}"
  export ATP_MATRIX_VERIFIED_WORKFLOW_RUN_ATTEMPT="${verified_workflow_run_attempt}"
  printf 'verified commit-bound ATP binary %s for %s\n' "${actual_version}" "${git}" >&2
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
  if [[ "${CELL_PROFILE}" == "authenticated-delta-unchanged-v1" ]]; then
    case "${tier}" in
      auth)      printf '%s\n' "atp-rq-auth" ;;
      encrypted) printf '%s\n' "atp-quic-tls13" ;;
      *) die "${CELL_PROFILE} supports only auth and encrypted tiers" ;;
    esac
    return
  fi
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

auth_posture_for_method() {
  case "$1" in
    atp-rq-lab)             printf '%s' 'rq-lab-unauthenticated-v1' ;;
    atp-rq-auth)            printf '%s' 'rq-symbol-hmac-v1' ;;
    atp-quic-tls13)         printf '%s' 'quic-tls13-transport-aead-v1' ;;
    rsyncd)                 printf '%s' 'rsyncd-plaintext-v1' ;;
    rsync-ssh-aes128gcm)    printf '%s' 'ssh-aes128-gcm-v1' ;;
    *)                      die "unknown method for auth posture: $1" ;;
  esac
}

delta_control_auth_posture_for_method() {
  if [[ "${CELL_PROFILE}" != "authenticated-delta-unchanged-v1" ]]; then
    printf '%s' 'none'
    return
  fi
  case "$1" in
    atp-rq-auth)    printf '%s' 'rq-framed-control-hmac-sha256-v1' ;;
    atp-quic-tls13) printf '%s' 'quic-tls13-session-bound-manifest-hmac-sha256-v1' ;;
    *) die "method $1 is not admitted by ${CELL_PROFILE}" ;;
  esac
}

reps_for_cell() {
  local workload="$1"
  local regime="$2"
  if [[ "${CELL_PROFILE}" == "authenticated-delta-unchanged-v1" ]]; then
    printf '%s' "${REPS_DEFAULT}"
  elif [[ "${workload}" == "5G" && "${regime}" == "broken" ]]; then
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

validate_profile_dimensions() {
  local -n workloads_ref="$1"
  local -n tiers_ref="$2"
  [[ "${CELL_PROFILE}" == "authenticated-delta-unchanged-v1" ]] || return 0

  local value
  for value in "${workloads_ref[@]}"; do
    case "${value}" in
      500K|5M|50M|500M) ;;
      *) die "${CELL_PROFILE} requires a nonempty flat-file workload, not ${value}" ;;
    esac
  done
  for value in "${tiers_ref[@]}"; do
    case "${value}" in
      auth|encrypted) ;;
      *) die "${CELL_PROFILE} supports only auth and encrypted tiers, not ${value}" ;;
    esac
  done
  if [[ -n "${METHODS_FILTER}" ]]; then
    local filtered_methods
    split_csv "${METHODS_FILTER}" filtered_methods
    for value in "${filtered_methods[@]}"; do
      case "${value}" in
        atp-rq-auth|atp-quic-tls13) ;;
        *) die "${CELL_PROFILE} does not admit method ${value}" ;;
      esac
    done
  fi
}

validate_results_profile() {
  [[ -f "${RESULTS_JSONL}" ]] || return 0
  python3 - "${RESULTS_JSONL}" "${CELL_PROFILE}" <<'PY'
import json
import sys

path, expected = sys.argv[1:3]
with open(path, encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, 1):
        if not line.strip():
            continue
        row = json.loads(line)
        actual = row.get("cell_profile")
        if actual != expected:
            raise SystemExit(
                f"{path}:{line_number}: cell_profile {actual!r} does not match {expected!r}"
            )
PY
}

cell_done() {
  local workload="$1" regime="$2" tier="$3" method="$4" rep="$5" streams="$6" case_id="$7" git="$8"
  [[ -f "${RESULTS_JSONL}" ]] || return 1
  local expected_auth_posture
  expected_auth_posture="$(auth_posture_for_method "${method}")"
  local expected_delta_control_auth_posture
  expected_delta_control_auth_posture="$(delta_control_auth_posture_for_method "${method}")"
  local expected_binary_sha256="${ATP_MATRIX_VERIFIED_BINARY_SHA256:-}"
  local expected_archive_sha256="${ATP_MATRIX_VERIFIED_ARCHIVE_SHA256:-}"
  local expected_workflow_run_id="${ATP_MATRIX_VERIFIED_WORKFLOW_RUN_ID:-}"
  local expected_workflow_run_attempt="${ATP_MATRIX_VERIFIED_WORKFLOW_RUN_ATTEMPT:-}"
  python3 - "$RESULTS_JSONL" "$workload" "$regime" "$tier" "$method" "$rep" "$streams" \
    "${CELL_PROFILE}" "${expected_auth_posture}" "${expected_delta_control_auth_posture}" \
    "$case_id" "$git" "${expected_binary_sha256}" "${expected_archive_sha256}" \
    "${expected_workflow_run_id}" "${expected_workflow_run_attempt}" <<'PY'
import json
import sys

(
    path,
    workload,
    regime,
    tier,
    method,
    rep,
    streams,
    profile,
    expected_auth_posture,
    expected_delta_control_auth_posture,
    case_id,
    git,
    expected_binary_sha256,
    expected_archive_sha256,
    expected_workflow_run_id,
    expected_workflow_run_attempt,
) = sys.argv[1:17]
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
        acceptance_match = profile != "authenticated-delta-unchanged-v1" or (
            row.get("artifact_binary_sha256") == expected_binary_sha256
            and row.get("artifact_archive_sha256") == expected_archive_sha256
            and row.get("artifact_workflow_run_id") == expected_workflow_run_id
            and row.get("artifact_workflow_run_attempt") == expected_workflow_run_attempt
            and row.get("delta_acceptance_ok") is True
            and row.get("delta_mode_observed") == "already_in_sync"
            and row.get("delta_control_auth_posture") == expected_delta_control_auth_posture
            and row.get("performance_claim") is False
            and row.get("status_code") == 0
            and row.get("timed_out") is False
            and row.get("sender_payload_bytes") == 0
            and row.get("sender_symbols") == 0
            and row.get("receiver_payload_bytes") == 0
            and row.get("receiver_symbols") == 0
            and row.get("feedback_rounds") == 0
            and row.get("payload_file_identity_unchanged") is True
            and 0 < int(row.get("control_wire_bytes", 0)) < int(row.get("size_bytes", 0))
        )
        if (
            row.get("cell_profile") == profile
            and row.get("case_id") == case_id
            and row.get("git_head") == git
            and str(row.get("workload")) == workload
            and row.get("sha_ok") is True
            and str(row.get("regime")) == regime
            and str(row.get("crypto_tier", row.get("tier"))) == tier
            and str(row.get("method")) == method
            and str(row.get("rep")) == rep
            and stream_match
            and row.get("auth_posture") == expected_auth_posture
            and acceptance_match
            and str(row.get("status", "ok")).lower() == "ok"
        ):
            raise SystemExit(0)
raise SystemExit(1)
PY
}

write_plan_row() {
  local workload="$1" regime="$2" tier="$3" method="$4" rep="$5" path="$6" git="$7" streams="$8" case_id="$9"
  local netem
  netem="$(netem_json "${regime}")"
  local auth_posture
  auth_posture="$(auth_posture_for_method "${method}")"
  local delta_control_auth_posture
  delta_control_auth_posture="$(delta_control_auth_posture_for_method "${method}")"
  local atp_streams_json="null"
  if method_uses_stream_sweep "${method}"; then
    atp_streams_json="${streams}"
  fi
  local artifact_binary_sha256_json="null"
  local artifact_archive_sha256_json="null"
  local artifact_workflow_run_id_json="null"
  local artifact_workflow_run_attempt_json="null"
  if [[ "${CELL_PROFILE}" == "authenticated-delta-unchanged-v1" \
    && -n "${ATP_MATRIX_VERIFIED_BINARY_SHA256:-}" ]]; then
    artifact_binary_sha256_json="$(json_escape "${ATP_MATRIX_VERIFIED_BINARY_SHA256}")"
    artifact_archive_sha256_json="$(json_escape "${ATP_MATRIX_VERIFIED_ARCHIVE_SHA256}")"
    artifact_workflow_run_id_json="$(json_escape "${ATP_MATRIX_VERIFIED_WORKFLOW_RUN_ID}")"
    artifact_workflow_run_attempt_json="$(json_escape "${ATP_MATRIX_VERIFIED_WORKFLOW_RUN_ATTEMPT}")"
  fi
  printf '{"schema":"atp-bench-matrix-plan-v1","cell_profile":%s,"case_id":%s,"run_id":%s,"git_head":%s,"artifact_binary_sha256":%s,"artifact_archive_sha256":%s,"artifact_workflow_run_id":%s,"artifact_workflow_run_attempt":%s,"workload":%s,"workload_path":%s,"regime":%s,"crypto_tier":%s,"method":%s,"auth_posture":%s,"delta_control_auth_posture":%s,"delta_mode_expected":%s,"performance_claim":%s,"rep":%s,"stream_count":%s,"atp_rq_streams":%s,"netem":%s}\n' \
    "$(json_escape "${CELL_PROFILE}")" \
    "$(json_escape "${case_id}")" \
    "$(json_escape "${RUN_ID}")" \
    "$(json_escape "${git}")" \
    "${artifact_binary_sha256_json}" \
    "${artifact_archive_sha256_json}" \
    "${artifact_workflow_run_id_json}" \
    "${artifact_workflow_run_attempt_json}" \
    "$(json_escape "${workload}")" \
    "$(json_escape "${path}")" \
    "$(json_escape "${regime}")" \
    "$(json_escape "${tier}")" \
    "$(json_escape "${method}")" \
    "$(json_escape "${auth_posture}")" \
    "$(json_escape "${delta_control_auth_posture}")" \
    "$(json_escape "$([[ "${CELL_PROFILE}" == "authenticated-delta-unchanged-v1" ]] && printf already_in_sync || printf disabled)")" \
    "$([[ "${CELL_PROFILE}" == "whole-object-scorecard-v1" ]] && printf true || printf false)" \
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
  local workload="$1" regime="$2" tier="$3" method="$4" rep="$5" path="$6" git="$7" streams="$8" case_id="$9"
  if cell_done "${workload}" "${regime}" "${tier}" "${method}" "${rep}" "${streams}" "${case_id}" "${git}"; then
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
  export ATP_MATRIX_CELL_PROFILE="${CELL_PROFILE}"
  export ATP_MATRIX_CASE_ID="${case_id}"
  bash -c "${RUN_CELL_CMD}"
}

write_authenticated_delta_report() {
  python3 - "${PLAN_JSONL}" "${RESULTS_JSONL}" "${REPORT_MD}" "${CELL_PROFILE}" <<'PY'
import json
import sys
from pathlib import Path

plan_path, results_path, report_path, profile = sys.argv[1:5]

def rows(path):
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]

def plan_key(row):
    return (
        row.get("case_id"),
        row.get("git_head"),
        row.get("artifact_binary_sha256"),
        row.get("artifact_archive_sha256"),
        row.get("artifact_workflow_run_id"),
        row.get("artifact_workflow_run_attempt"),
    )

def display_key(row):
    method = str(row.get("method"))
    streams = row.get("atp_rq_streams", row.get("stream_count", 1))
    if not method.startswith("atp-rq-"):
        streams = 1
    return (
        str(row.get("workload")),
        str(row.get("regime")),
        str(row.get("crypto_tier")),
        method,
        int(row.get("rep", 0)),
        int(streams),
    )

planned = rows(plan_path)
results = rows(results_path)
if not planned:
    raise SystemExit("authenticated delta acceptance plan is empty")
planned_keys = [plan_key(row) for row in planned]
if any(any(not value for value in identity) for identity in planned_keys):
    raise SystemExit("authenticated delta plan contains an empty case/git/artifact identity")
if len(set(planned_keys)) != len(planned_keys):
    raise SystemExit("authenticated delta plan contains duplicate case/git/artifact identities")
artifact_identities = {identity[2:] for identity in planned_keys}
if len(artifact_identities) != 1:
    raise SystemExit("authenticated delta plan mixes commit-bound ATP artifacts")
artifact_binary_sha256, artifact_archive_sha256, workflow_run_id, workflow_run_attempt = next(
    iter(artifact_identities)
)

expected_posture = {
    "atp-rq-auth": "rq-symbol-hmac-v1",
    "atp-quic-tls13": "quic-tls13-transport-aead-v1",
}
expected_delta_posture = {
    "atp-rq-auth": "rq-framed-control-hmac-sha256-v1",
    "atp-quic-tls13": "quic-tls13-session-bound-manifest-hmac-sha256-v1",
}
accepted_rows = []
for planned_row in planned:
    identity = plan_key(planned_row)
    candidates = [row for row in results if plan_key(row) == identity]
    accepted = []
    for row in candidates:
        method = row.get("method")
        try:
            control_wire_ok = (
                0 < int(row.get("control_wire_bytes", 0)) < int(row.get("size_bytes", 0))
            )
        except (TypeError, ValueError):
            control_wire_ok = False
        checks = {
            "cell_profile": row.get("cell_profile") == profile,
            "workload": row.get("workload") == planned_row.get("workload"),
            "regime": row.get("regime") == planned_row.get("regime"),
            "crypto_tier": row.get("crypto_tier") == planned_row.get("crypto_tier"),
            "method": method == planned_row.get("method") and method in expected_posture,
            "rep": row.get("rep") == planned_row.get("rep"),
            "stream_count": display_key(row) == display_key(planned_row),
            "auth_posture": row.get("auth_posture") == expected_posture.get(method),
            "delta_control_auth_posture": row.get("delta_control_auth_posture") == expected_delta_posture.get(method),
            "status": row.get("status") == "ok",
            "status_code": row.get("status_code") == 0,
            "timed_out": row.get("timed_out") is False,
            "sha_ok": row.get("sha_ok") is True,
            "delta_acceptance_ok": row.get("delta_acceptance_ok") is True,
            "delta_mode_observed": row.get("delta_mode_observed") == "already_in_sync",
            "sender_payload_bytes": row.get("sender_payload_bytes") == 0,
            "sender_symbols": row.get("sender_symbols") == 0,
            "receiver_payload_bytes": row.get("receiver_payload_bytes") == 0,
            "receiver_symbols": row.get("receiver_symbols") == 0,
            "feedback_rounds": row.get("feedback_rounds") == 0,
            "payload_file_identity_unchanged": row.get("payload_file_identity_unchanged") is True,
            "performance_claim": row.get("performance_claim") is False,
            "control_wire_bytes": control_wire_ok,
        }
        failed = [name for name, passed in checks.items() if not passed]
        if not failed:
            accepted.append(row)
        elif row.get("status") == "ok":
            raise SystemExit(
                f"authenticated delta cell {identity!r} has malformed ok row: {', '.join(failed)}"
            )
    if len(accepted) != 1:
        raise SystemExit(
            f"authenticated delta cell {identity!r} requires exactly one accepted row; "
            f"found {len(accepted)} among {len(candidates)} attempts"
        )
    accepted_rows.append(accepted[0])

lines = [
    "# Authenticated delta unchanged acceptance",
    "",
    "Functional protocol evidence only. This report makes no throughput or ATP-vs-rsync claim.",
    "",
    f"Verified ATP binary SHA-256: `{artifact_binary_sha256}`",
    f"Attested archive SHA-256: `{artifact_archive_sha256}`",
    f"Producer workflow run/attempt: `{workflow_run_id}/{workflow_run_attempt}`",
    "",
    "| workload | regime | tier | method | control wire bytes | accepted |",
    "|---|---|---|---|---:|---|",
]
for row in sorted(accepted_rows, key=display_key):
    lines.append(
        f"| {row['workload']} | {row['regime']} | {row['crypto_tier']} | "
        f"{row['method']} | {row['control_wire_bytes']} | yes |"
    )
lines.extend([
    "",
    "No-claim: this packet does not prove changed-chunk delivery, throughput improvement,",
    "broad workspace health, release readiness, or live RCH fleet availability.",
])
Path(report_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
}

main() {
  local workloads regimes tiers streams
  split_csv "${WORKLOADS}" workloads
  split_csv "${REGIMES}" regimes
  split_csv "${TIERS}" tiers
  split_csv "${STREAMS_SWEEP}" streams
  validate_streams streams
  validate_profile_dimensions workloads tiers

  local git
  git="$(git_head)"
  if [[ "${DRY_RUN}" -eq 0 ]]; then
    [[ -n "${RUN_CELL_CMD}" ]] || die "--execute requires --run-cell-command"
    validate_results_profile
    if [[ "${CELL_PROFILE}" == "authenticated-delta-unchanged-v1" ]]; then
      verify_commit_bound_atp_binary "${git}"
    fi
  fi

  mkdir -p "${OUT_DIR}"
  : >"${PLAN_JSONL}"
  local planned_cells=0

  for workload in "${workloads[@]}"; do
    local path
    path="$(workload_path "${workload}")"
    if [[ "${GENERATE_WORKLOADS}" -eq 1 && "${DRY_RUN}" -eq 0 ]]; then
      generate_workload "${workload}"
    fi
    for regime in "${regimes[@]}"; do
      if [[ "${DRY_RUN}" -eq 0 ]]; then
        apply_netem_for_regime "${regime}"
      fi
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
              local case_id
              case_id="$(cell_case_id "${workload}" "${regime}" "${tier}" "${method}" "${rep}" "${stream_count}")"
              planned_cells=$((planned_cells + 1))
              write_plan_row "${workload}" "${regime}" "${tier}" "${method}" "${rep}" \
                "${path}" "${git}" "${stream_count}" "${case_id}" >>"${PLAN_JSONL}"
              if [[ "${DRY_RUN}" -eq 0 ]]; then
                run_cell "${workload}" "${regime}" "${tier}" "${method}" "${rep}" \
                  "${path}" "${git}" "${stream_count}" "${case_id}"
              fi
            done
          done
        done
      done
    done
  done

  [[ "${planned_cells}" -gt 0 ]] || die "selection produced no matrix cells"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    cat "${PLAN_JSONL}"
  else
    [[ -s "${RESULTS_JSONL}" ]] \
      || die "--execute produced no result rows: ${RESULTS_JSONL}"
    if [[ "${CELL_PROFILE}" == "authenticated-delta-unchanged-v1" ]]; then
      write_authenticated_delta_report
    else
      python3 "${SCRIPT_DIR}/score_matrix.py" "${RESULTS_JSONL}" --out-md "${REPORT_MD}"
      if [[ "${FAIL_ON_MISMATCH}" -eq 1 ]]; then
        python3 "${SCRIPT_DIR}/score_matrix.py" "${RESULTS_JSONL}" --fail-on-mismatch
      fi
    fi
  fi
}

main "$@"
